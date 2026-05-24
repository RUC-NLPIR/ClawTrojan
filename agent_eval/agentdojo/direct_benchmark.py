"""Direct AgentDojo runner for OpenAI-compatible providers.

The official AgentDojo CLI constrains ``--model`` to its built-in enum. This
module bypasses only that CLI limitation while still using AgentDojo's public
suite, attack, pipeline, tool execution, and scorer implementations.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict

from dotenv import load_dotenv


def main() -> None:
    parser = argparse.ArgumentParser(description="Run AgentDojo with a custom OpenAI-compatible model")
    parser.add_argument("--model", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--api-key-env", required=True)
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--logdir", type=Path, required=True)
    parser.add_argument("--attack", default=None)
    parser.add_argument("--defense", default=None)
    parser.add_argument("--suite", "-s", action="append", default=[])
    parser.add_argument("--user-task", "-ut", action="append", default=[])
    parser.add_argument("--injection-task", "-it", action="append", default=[])
    parser.add_argument(
        "--skip-injection-task-utility",
        action="store_true",
        help="Skip the AgentDojo precheck that runs each injection task as a user task.",
    )
    parser.add_argument("--force-rerun", action="store_true")
    args = parser.parse_args()

    load_dotenv()
    api_key = os.environ.get(args.api_key_env)
    if not api_key:
        raise RuntimeError(f"Missing API key environment variable: {args.api_key_env}")

    import openai
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig, load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    import agentdojo.agent_pipeline.llms.openai_llm as openai_llm_mod
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
    from agentdojo.logging import OutputLogger
    from agentdojo.task_suite.load_suites import get_suite, get_suites
    from agentdojo import benchmark as benchmark_mod
    from agentdojo import types as agentdojo_types

    # AgentDojo 0.1.35 leaves TaskResults forward refs unresolved under
    # recent Pydantic v2 releases. Rebuilding here keeps cached/new trace
    # loading working without patching site-packages.
    benchmark_mod.TaskResults.model_rebuild(_types_namespace=vars(agentdojo_types))

    suites = args.suite or list(get_suites(args.benchmark_version).keys())
    results_by_suite: Dict[str, Any] = {}
    for suite_name in suites:
        suite = get_suite(args.benchmark_version, suite_name)
        print(f"Running benchmark for suite: '{suite.name}'")
        print(f"Using model: '{args.model}'")
        if args.attack:
            print(f"Using attack: '{args.attack}'")
        if args.defense:
            print(f"Using defense: '{args.defense}'")
        if args.user_task:
            print(f"Using user tasks: {', '.join(args.user_task)}")

        if args.api_key_env == "SILICONFLOW_API_KEY":
            _patch_system_role_for_siliconflow(openai_llm_mod)

        client = openai.OpenAI(api_key=api_key, base_url=args.base_url)
        llm = OpenAILLM(client, args.model)
        # AgentDojo's ImportantInstructionsAttack extracts the model family
        # from pipeline.name; keep a recognized family while the API model
        # remains the OpenAI-compatible provider model above.
        llm.name = "gpt-4o-mini-2024-07-18"
        pipeline = _build_pipeline(llm, defense=args.defense, system_message=load_system_message(None))

        suite_logdir = args.logdir / suite_name
        with OutputLogger(str(suite_logdir)):
            if args.attack:
                attack = load_attack(args.attack, suite, pipeline)
                if args.skip_injection_task_utility:
                    results = _benchmark_suite_with_injections_no_precheck(
                        pipeline,
                        suite,
                        attack,
                        user_tasks=tuple(args.user_task) or None,
                        injection_tasks=tuple(args.injection_task) or None,
                        logdir=suite_logdir,
                        force_rerun=args.force_rerun,
                        benchmark_version=args.benchmark_version,
                    )
                else:
                    results = benchmark_suite_with_injections(
                        pipeline,
                        suite,
                        attack,
                        user_tasks=tuple(args.user_task) or None,
                        injection_tasks=tuple(args.injection_task) or None,
                        logdir=suite_logdir,
                        force_rerun=args.force_rerun,
                        benchmark_version=args.benchmark_version,
                    )
            else:
                results = benchmark_suite_without_injections(
                    pipeline,
                    suite,
                    user_tasks=tuple(args.user_task) or None,
                    logdir=suite_logdir,
                    force_rerun=args.force_rerun,
                    benchmark_version=args.benchmark_version,
                )
        results_by_suite[suite_name] = _summarize_suite_results(results, show_security=bool(args.attack))
        _print_suite_summary(suite_name, results_by_suite[suite_name], show_security=bool(args.attack))

    print("AGENTDOJO_DIRECT_SUMMARY_JSON=" + json.dumps(results_by_suite, sort_keys=True))


def _summarize_suite_results(results: Dict[str, Any], *, show_security: bool) -> Dict[str, Any]:
    utility_values = list(results["utility_results"].values())
    summary: Dict[str, Any] = {
        "average_utility": sum(utility_values) / len(utility_values) if utility_values else 0.0,
        "utility_count": len(utility_values),
    }
    if show_security:
        security_values = list(results["security_results"].values())
        injection_values = list(results["injection_tasks_utility_results"].values())
        summary.update({
            "average_security": sum(security_values) / len(security_values) if security_values else 0.0,
            "security_count": len(security_values),
            "passed_injection_tasks_as_user_tasks": sum(1 for value in injection_values if value),
            "total_injection_tasks_as_user_tasks": len(injection_values),
        })
    return summary


def _benchmark_suite_with_injections_no_precheck(
    agent_pipeline: Any,
    suite: Any,
    attack: Any,
    *,
    logdir: Path,
    force_rerun: bool,
    user_tasks: tuple[str, ...] | None,
    injection_tasks: tuple[str, ...] | None,
    benchmark_version: str,
) -> Dict[str, Any]:
    from agentdojo.benchmark import run_task_with_injection_tasks

    if user_tasks is not None:
        user_tasks_to_run = [suite.get_user_task_by_id(user_task_id) for user_task_id in user_tasks]
    else:
        user_tasks_to_run = list(suite.user_tasks.values())

    utility_results: Dict[tuple[str, str], bool] = {}
    security_results: Dict[tuple[str, str], bool] = {}
    for user_task in user_tasks_to_run:
        utility, security = run_task_with_injection_tasks(
            suite,
            agent_pipeline,
            user_task,
            attack,
            logdir,
            force_rerun,
            injection_tasks,
            benchmark_version,
        )
        utility_results.update(utility)
        security_results.update(security)

    injection_task_ids = injection_tasks or tuple(suite.injection_tasks.keys())
    return {
        "utility_results": utility_results,
        "security_results": security_results,
        "injection_tasks_utility_results": {injection_task_id: True for injection_task_id in injection_task_ids},
    }


def _build_pipeline(llm: Any, *, defense: str | None, system_message: str) -> Any:
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor

    from agent_eval.agentdojo.pipeline_adapters import AgentDojoDasGuardPIDetector, AgentDojoDasGuardToolsExecutor

    if defense == "dasguard":
        tools_loop = ToolsExecutionLoop([AgentDojoDasGuardToolsExecutor(), AgentDojoDasGuardPIDetector(), llm])
        pipeline = AgentPipeline([SystemMessage(system_message), InitQuery(), llm, tools_loop])
        pipeline.name = f"{llm.name}-dasguard"
        return pipeline
    return AgentPipeline.from_config(
        PipelineConfig(
            llm=llm,
            model_id=None,
            defense=defense,
            system_message_name=None,
            system_message=system_message,
        )
    )


def _patch_system_role_for_siliconflow(openai_llm_mod: Any) -> None:
    original_message_to_openai = openai_llm_mod._message_to_openai

    def message_to_openai(message: Any, model_name: str) -> Any:
        if message["role"] == "system":
            return {
                "role": "system",
                "content": openai_llm_mod._content_blocks_to_openai_content_blocks(message),
            }
        return original_message_to_openai(message, model_name)

    openai_llm_mod._message_to_openai = message_to_openai


def _print_suite_summary(suite_name: str, summary: Dict[str, Any], *, show_security: bool) -> None:
    print(f"Results for suite {suite_name}")
    print(f"Average utility: {summary['average_utility'] * 100:.2f}%")
    if show_security:
        print(
            "\nPassed injection tasks as user tasks: "
            f"{summary['passed_injection_tasks_as_user_tasks']}/"
            f"{summary['total_injection_tasks_as_user_tasks']}"
        )
        print(f"Average security: {summary['average_security'] * 100:.2f}%")


if __name__ == "__main__":
    main()
