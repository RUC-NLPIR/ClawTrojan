#!/usr/bin/env python3
"""
ClawShield 🛡️ - OpenClaw Prompt Injection Benchmark 主入口脚本
"""

import argparse
import json
from pathlib import Path

from dotenv import load_dotenv
from loguru import logger

load_dotenv()

from agent_eval import HybridDefenseEvaluator, SandboxEvaluator, TrojanEvaluator
from agent_eval.sandbox.baselines import SANDBOX_CONDITIONS
from agent_eval.sandbox.latency_eval import (
    DEFAULT_LATENCY_CONDITIONS,
    LatencyRunConfig,
    run_latency_matrix,
)
from claw_trojan.loader import export_trojan_gold_jsonl, load_all_trojan_envs


def generate_dataset(args):
    logger.info("=== 生成数据集 ===")
    try:
        from dataset import OpenClawPromptInjectionDataset
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "The optional synthetic dataset generator is not included in this "
            "minimal public release package. Use the ClawTrojan reproduction commands "
            "such as trojan-export, dasguard-detect, and sandbox-eval, or restore "
            "dataset/ if you need the generate command."
        ) from exc

    generator = OpenClawPromptInjectionDataset(
        seed=args.seed,
        tokenizer_name_or_path=args.tokenizer_name_or_path,
        max_seq_len=args.max_seq_len,
    )
    dataset = generator.generate_dataset(
        samples_per_scenario=args.samples_per_scenario,
        clean_ratio=args.clean_ratio,
    )
    generator.save_dataset(dataset, args.output_dir, format=args.format)
    logger.info(f"数据集已保存到 {args.output_dir}")


def run_hybrid_eval(args):
    evaluator = HybridDefenseEvaluator(policy_name=args.policy)
    metrics = evaluator.run(
        gold_path=args.gold_path,
        detector_pred_path=args.detector_pred_path,
        output_dir=args.output_dir,
    )
    print(metrics)


def run_trojan_export(args):
    logger.info("=== 导出 claw_trojan 环境为 gold JSONL ===")
    samples = load_all_trojan_envs(args.envs_root)
    export_trojan_gold_jsonl(samples, args.output_path)
    logger.info(f"已导出 {len(samples)} 条 step 样本到 {args.output_path}")


def run_trojan_eval(args):
    logger.info("=== 运行 claw_trojan 评测 ===")
    evaluator = TrojanEvaluator(policy_name=args.policy)
    metrics = evaluator.run(
        envs_root=args.envs_root,
        detector_pred_path=args.detector_pred_path,
        output_dir=args.output_dir,
    )
    import json
    print(json.dumps(metrics, indent=2, ensure_ascii=False))


def run_dasguard_detect(args):
    from agent_eval.dasguard import DasGuardDetector, create_dasguard_embedder

    logger.info("=== DASGuard Detection ===")
    llm_client = None
    if args.llm_review_backend:
        from agent_eval.llm_client import create_llm_client

        llm_client = create_llm_client(args.llm_review_backend, args.llm_review_model)
    embedder = create_dasguard_embedder(args.embedding_backend, args.embedding_model)
    detector = DasGuardDetector(
        llm_client=llm_client,
        embedder=embedder,
        use_embedding=not args.disable_semantic_score,
        use_memory_context=not args.disable_memory_match,
    )
    decisions = detector.detect_all(args.envs_root)
    detector.save_predictions(decisions, args.output_path)

    flagged = sum(1 for d in decisions if d.is_malicious_pred)
    logger.info(f"Done: {len(decisions)} steps, {flagged} flagged malicious")
    print(json.dumps({"total": len(decisions), "flagged": flagged}, indent=2))


def run_dasguard_cleanup(args):
    from agent_eval.dasguard import (
        apply_patch_to_text,
        assess_text,
        build_context,
        create_dasguard_embedder,
        review_assessment,
    )
    from agent_eval.dasguard.cleanup import cleanup_source_label, skill_supply_chain_guard
    from agent_eval.dasguard.scanner import iter_workspace_files

    logger.info("=== DASGuard Workspace Cleanup Scan ===")
    llm_client = None
    if args.llm_review_backend:
        from agent_eval.llm_client import create_llm_client

        llm_client = create_llm_client(args.llm_review_backend, args.llm_review_model)
    embedder = create_dasguard_embedder(args.embedding_backend, args.embedding_model)
    root = Path(args.workspace_root)
    assessments = []
    findings = []
    for file_path in iter_workspace_files(root):
        try:
            text = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = str(file_path.relative_to(root))
        source_label = args.source_label or cleanup_source_label(
            rel,
            suspected_compromise=args.suspected_compromise,
        )
        context = build_context(
            mode="cleanup",
            sink_path=rel,
            source_label=source_label,
            authorization={
                "status": "not_required",
                "skill_supply_chain_guard": skill_supply_chain_guard(
                    root,
                    rel,
                    text,
                    embedder=embedder,
                ),
            },
            payload=text,
        )
        assessment = assess_text(
            text,
            context=context,
            finding_prefix=f"das_{len(findings) + 1:04d}",
            embedder=embedder,
        )
        review_assessment(assessment, llm_client=llm_client)
        assessments.append(assessment)
        findings.extend(assessment.findings)
    actionable = [f for f in findings if f.action != "preserve"]
    patches = [patch for assessment in assessments for patch in assessment.patches]

    out = Path(args.output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for patch in patches:
            f.write(json.dumps(patch.to_dict(), ensure_ascii=False) + "\n")

    if args.apply:
        root = Path(args.workspace_root)
        for finding in sorted(actionable, key=lambda f: (f.sink_path, f.start), reverse=True):
            target = root / finding.sink_path
            text = target.read_text(encoding="utf-8")
            target.write_text(apply_patch_to_text(text, finding), encoding="utf-8")

    logger.info(
        f"Scanned {args.workspace_root}: {len(findings)} findings, "
        f"{len(actionable)} patches -> {args.output_path}"
    )
    decision_counts = {}
    for assessment in assessments:
        decision_counts[assessment.decision] = decision_counts.get(assessment.decision, 0) + 1
    print(json.dumps({
        "findings": len(findings),
        "patches": len(patches),
        "applied": bool(args.apply),
        "suspected_compromise": bool(args.suspected_compromise),
        "output_path": args.output_path,
        "assessment_decisions": decision_counts,
    }, indent=2, ensure_ascii=False))


def run_sandbox_eval(args):
    logger.info("=== Sandbox Agent Execution for ASR Measurement ===")
    evaluator = SandboxEvaluator(
        agent_backend=args.agent_backend,
        agent_model=args.agent_model,
        judge_backend=args.judge_backend,
        judge_model=args.judge_model,
        max_turns=args.max_turns,
        trials=args.trials,
        baseline=args.baseline,
        promptshield_classifier_path=args.promptshield_classifier_path,
        dynamic_defense=args.dynamic_defense,
        dasguard_use_source_labels=not args.dasguard_disable_source_labels,
        dasguard_use_embedding=not args.dasguard_disable_semantic_score,
        dasguard_use_memory_context=not args.dasguard_disable_memory_match,
        dasguard_llm_review_backend=args.dasguard_llm_review_backend,
        dasguard_llm_review_model=args.dasguard_llm_review_model,
        eval_split=args.eval_split,
        max_evals=args.max_evals,
        force_rerun=args.force_rerun,
        judge_only=args.judge_only,
    )
    metrics = evaluator.run(
        envs_root=args.envs_root,
        output_dir=args.output_dir,
    )
    import json
    print(json.dumps(metrics, indent=2, ensure_ascii=False))


def run_sandbox_latency(args):
    logger.info("=== Sandbox Latency Matrix ===")
    result = run_latency_matrix(
        envs_root=args.envs_root,
        output_root=args.output_root,
        conditions=args.condition,
        summarize_only=args.summarize_only,
        config=LatencyRunConfig(
            agent_backend=args.agent_backend,
            agent_model=args.agent_model,
            judge_backend=args.judge_backend,
            judge_model=args.judge_model,
            max_turns=args.max_turns,
            trials=args.trials,
            promptshield_classifier_path=args.promptshield_classifier_path,
            dynamic_defense=args.dynamic_defense,
            dasguard_use_source_labels=not args.dasguard_disable_source_labels,
            dasguard_use_embedding=not args.dasguard_disable_semantic_score,
            dasguard_use_memory_context=not args.dasguard_disable_memory_match,
            dasguard_llm_review_backend=args.dasguard_llm_review_backend,
            dasguard_llm_review_model=args.dasguard_llm_review_model,
            eval_split=args.eval_split,
        ),
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


def run_agentdojo_eval(args):
    from agent_eval.agentdojo import AgentDojoEvalConfig, AgentDojoEvaluator

    logger.info("=== AgentDojo External Evaluation ===")
    model = args.model
    if args.openai_provider == "rightcodes" and model == "gpt-4o-mini-2024-07-18":
        model = "gpt-5.4"
    config = AgentDojoEvalConfig(
        output_dir=Path(args.output_dir),
        model=model,
        model_id=args.model_id,
        openai_provider=args.openai_provider,
        benchmark_version=args.benchmark_version,
        attack=args.attack,
        suites=tuple(args.suite or ["workspace"]),
        conditions=tuple(args.condition or ["no_defense", "dasguard"]),
        user_tasks=tuple(args.user_task or ["user_task_0", "user_task_1"]),
        injection_tasks=tuple(args.injection_task or ["injection_task_0", "injection_task_1"]),
        max_workers=args.max_workers,
        force_rerun=args.force_rerun,
        dry_run=args.dry_run,
    )
    result = AgentDojoEvaluator(config).run()
    print(json.dumps(result, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description="ClawShield 🛡️ - OpenClaw Prompt Injection Benchmark")
    subparsers = parser.add_subparsers(title="命令", dest="command")

    generate_parser = subparsers.add_parser("generate", help="生成 benchmark 数据集")
    generate_parser.add_argument("--output-dir", type=str, default="./data/benchmark", help="数据集输出目录")
    generate_parser.add_argument("--samples-per-scenario", type=int, default=200, help="每个场景的样本数")
    generate_parser.add_argument("--clean-ratio", type=float, default=0.3, help="干净样本比例")
    generate_parser.add_argument("--format", type=str, default="jsonl", choices=["parquet", "json", "jsonl"], help="保存格式")
    generate_parser.add_argument("--seed", type=int, default=42, help="随机种子")
    generate_parser.add_argument("--tokenizer-name-or-path", type=str, help="用于缓存正式 offset/token 对齐的 tokenizer")
    generate_parser.add_argument("--max-seq-len", type=int, default=512, help="生成 alignment cache 时使用的最大序列长度")

    hybrid_parser = subparsers.add_parser("hybrid-eval", help="运行 detector+policy 的 system-level 评测")
    hybrid_parser.add_argument("--gold-path", type=str, required=True, help="gold jsonl 路径")
    hybrid_parser.add_argument("--detector-pred-path", type=str, required=True, help="detector prediction jsonl 路径")
    hybrid_parser.add_argument("--policy", type=str, required=True, choices=["block", "sanitize"], help="policy 类型")
    hybrid_parser.add_argument("--output-dir", type=str, required=True, help="system eval 输出目录")

    trojan_export_parser = subparsers.add_parser("trojan-export", help="导出 claw_trojan 环境为 gold JSONL")
    trojan_export_parser.add_argument("--envs-root", type=str, required=True, help="claw_trojan envs 根目录")
    trojan_export_parser.add_argument("--output-path", type=str, required=True, help="输出 JSONL 路径")

    trojan_eval_parser = subparsers.add_parser("trojan-eval", help="运行 claw_trojan 多步攻击评测")
    trojan_eval_parser.add_argument("--envs-root", type=str, required=True, help="claw_trojan envs 根目录")
    trojan_eval_parser.add_argument("--detector-pred-path", type=str, required=True, help="detector prediction jsonl 路径")
    trojan_eval_parser.add_argument("--policy", type=str, required=True, choices=["block", "sanitize"], help="policy 类型")
    trojan_eval_parser.add_argument("--output-dir", type=str, required=True, help="评测结果输出目录")

    dasguard_parser = subparsers.add_parser("dasguard-detect", help="运行 DASGuard 检测，生成 prediction JSONL")
    dasguard_parser.add_argument("--envs-root", type=str, required=True, help="claw_trojan envs 根目录")
    dasguard_parser.add_argument("--output-path", type=str, required=True, help="prediction JSONL 输出路径")
    dasguard_parser.add_argument(
        "--llm-review-backend",
        type=str,
        default=None,
        choices=["openai", "anthropic", "rightcodes", "cubance", "siliconflow"],
        help="可选：对 risk 阈值边缘 finding 做 LLM 复核；默认关闭",
    )
    dasguard_parser.add_argument(
        "--llm-review-model",
        type=str,
        default=None,
        help="可选：LLM 复核模型名；未指定时使用 backend 默认模型",
    )
    dasguard_parser.add_argument(
        "--embedding-backend",
        type=str,
        default=None,
        choices=["siliconflow", "hashing"],
        help="DASGuard embedding backend；默认 siliconflow，缺少 SILICONFLOW_API_KEY 时 fallback 到 hashing",
    )
    dasguard_parser.add_argument(
        "--embedding-model",
        type=str,
        default=None,
        help="DASGuard embedding 模型名；SiliconFlow 默认 BAAI/bge-m3",
    )
    dasguard_parser.add_argument(
        "--disable-semantic-score",
        action="store_true",
        help="Ablation: disable DASGuard embedding semantic score E(s)",
    )
    dasguard_parser.add_argument(
        "--disable-memory-match",
        action="store_true",
        help="Ablation: disable DASGuard same-sample memory match M(s)",
    )

    cleanup_parser = subparsers.add_parser("dasguard-cleanup", help="扫描 workspace 并输出 DASGuard sanitization patch JSONL")
    cleanup_parser.add_argument("--workspace-root", type=str, required=True, help="待扫描的 workspace 根目录")
    cleanup_parser.add_argument("--output-path", type=str, required=True, help="patch JSONL 输出路径")
    cleanup_parser.add_argument(
        "--source-label",
        type=str,
        default=None,
        choices=[
            "trusted_user",
            "trusted_system",
            "workspace_clean",
            "tool_untrusted",
            "skill_metadata",
            "memory_persistent",
            "external_source",
            "derived_untrusted",
            "compromised_artifact",
        ],
        help="覆盖 cleanup 扫描的 provenance 标签；疑似污染 workspace 可用 compromised_artifact",
    )
    cleanup_parser.add_argument("--apply", action="store_true", help="将 patch 写回 workspace")
    cleanup_parser.add_argument(
        "--suspected-compromise",
        action="store_true",
        help=(
            "疑似 workspace 已污染时启用：memory/agent instructions/skills/policy/templates "
            "按 compromised_artifact 扫描，普通文件仍按路径推断来源"
        ),
    )
    cleanup_parser.add_argument(
        "--embedding-backend",
        type=str,
        default=None,
        choices=["siliconflow", "hashing"],
        help="DASGuard embedding backend；默认 siliconflow，缺少 SILICONFLOW_API_KEY 时 fallback 到 hashing",
    )
    cleanup_parser.add_argument(
        "--embedding-model",
        type=str,
        default=None,
        help="DASGuard embedding 模型名；SiliconFlow 默认 BAAI/bge-m3",
    )
    cleanup_parser.add_argument(
        "--llm-review-backend",
        type=str,
        default=None,
        choices=["openai", "anthropic", "rightcodes", "cubance", "siliconflow"],
        help="可选：对 cleanup eligible finding 启用 LLM 复核；默认关闭",
    )
    cleanup_parser.add_argument(
        "--llm-review-model",
        type=str,
        default=None,
        help="可选：cleanup LLM 复核模型名；未指定时使用 backend 默认模型",
    )

    sandbox_parser = subparsers.add_parser("sandbox-eval", help="运行 sandbox agent 执行，度量 baseline ASR")
    sandbox_parser.add_argument("--envs-root", type=str, required=True, help="claw_trojan envs 根目录")
    sandbox_parser.add_argument("--output-dir", type=str, required=True, help="输出目录")
    sandbox_parser.add_argument("--agent-backend", type=str, default="openai", choices=["openai", "anthropic", "rightcodes", "cubance", "siliconflow"], help="Agent LLM 后端")
    sandbox_parser.add_argument("--agent-model", type=str, default=None, help="Agent 模型名 (默认按后端选择)")
    sandbox_parser.add_argument("--judge-backend", type=str, default="openai", choices=["openai", "anthropic", "rightcodes", "cubance", "siliconflow"], help="Judge LLM 后端")
    sandbox_parser.add_argument("--judge-model", type=str, default=None, help="Judge 模型名 (默认 gpt-4o)")
    sandbox_parser.add_argument("--max-turns", type=int, default=10, help="每次 sandbox 最大对话轮数")
    sandbox_parser.add_argument("--trials", type=int, default=1, help="每个 step 运行次数")
    sandbox_parser.add_argument("--max-evals", type=int, default=None, help="只运行排序后的前 N 个 step，用于 smoke")
    sandbox_parser.add_argument("--force-rerun", action="store_true", help="忽略已有 per-trial judge.json，强制重跑")
    sandbox_parser.add_argument("--judge-only", action="store_true", help="只用已有 trace/audit/diff 重新评测 judge，不重跑 agent/base model")
    sandbox_parser.add_argument(
        "--eval-split",
        type=str,
        default="malicious",
        choices=["malicious", "clean", "all"],
        help="选择评测 step：malicious 保持原 ASR 口径，clean 跑 none/benign FPR，all 同时跑两者",
    )
    sandbox_parser.add_argument(
        "--baseline",
        type=str,
        default="no_defense",
        choices=sorted(SANDBOX_CONDITIONS),
        help="sandbox baseline defense condition",
    )
    sandbox_parser.add_argument(
        "--dynamic-defense",
        type=str,
        default="isolated_step",
        choices=["isolated_step", "cross_step_context_only"],
        help=(
            "dynamic defense mode; isolated_step preserves current per-step behavior, "
            "cross_step_context_only carries only runtime DASGuard findings across steps"
        ),
    )
    sandbox_parser.add_argument(
        "--dasguard-disable-source-labels",
        action="store_true",
        help="Ablation: disable DASGuard content-source labels/provenance marking",
    )
    sandbox_parser.add_argument(
        "--dasguard-disable-semantic-score",
        action="store_true",
        help="Ablation: disable DASGuard embedding semantic score E(s)",
    )
    sandbox_parser.add_argument(
        "--dasguard-disable-memory-match",
        action="store_true",
        help="Ablation: disable DASGuard same-sample memory match M(s)",
    )
    sandbox_parser.add_argument(
        "--promptshield-classifier-path",
        type=str,
        default=None,
        help="PromptShield classifier 本地/Hub 路径；也可用 PROMPTSHIELD_CLASSIFIER_PATH",
    )
    sandbox_parser.add_argument(
        "--dasguard-llm-review-backend",
        type=str,
        default=None,
        choices=["openai", "anthropic", "rightcodes", "cubance", "siliconflow"],
        help="可选：为 DASGuard runtime gate 启用 LLM review 的后端",
    )
    sandbox_parser.add_argument(
        "--dasguard-llm-review-model",
        type=str,
        default=None,
        help="可选：DASGuard runtime LLM review 模型名",
    )

    latency_parser = subparsers.add_parser(
        "sandbox-latency",
        help="运行 DASGuard 和所有 sandbox baselines（排除 no_defense）的 latency 矩阵",
    )
    latency_parser.add_argument("--envs-root", type=str, required=True, help="claw_trojan envs 根目录")
    latency_parser.add_argument("--output-root", type=str, required=True, help="latency 矩阵输出根目录")
    latency_parser.add_argument(
        "--condition",
        action="append",
        default=None,
        choices=sorted(condition for condition in SANDBOX_CONDITIONS if condition != "no_defense"),
        help=(
            "只跑指定 condition，可重复；默认跑 "
            + ", ".join(DEFAULT_LATENCY_CONDITIONS)
        ),
    )
    latency_parser.add_argument("--agent-backend", type=str, default="openai", choices=["openai", "anthropic", "rightcodes", "cubance", "siliconflow"], help="Agent LLM 后端")
    latency_parser.add_argument("--agent-model", type=str, default=None, help="Agent 模型名 (默认按后端选择)")
    latency_parser.add_argument("--judge-backend", type=str, default="openai", choices=["openai", "anthropic", "rightcodes", "cubance", "siliconflow"], help="Judge LLM 后端")
    latency_parser.add_argument("--judge-model", type=str, default=None, help="Judge 模型名 (默认 gpt-4o)")
    latency_parser.add_argument("--max-turns", type=int, default=10, help="每次 sandbox 最大对话轮数")
    latency_parser.add_argument("--trials", type=int, default=1, help="每个 step 运行次数")
    latency_parser.add_argument(
        "--eval-split",
        type=str,
        default="malicious",
        choices=["malicious", "clean", "all"],
        help="选择评测 step：malicious 保持原 ASR 口径，clean 跑 none/benign FPR，all 同时跑两者",
    )
    latency_parser.add_argument(
        "--dynamic-defense",
        type=str,
        default="cross_step_context_only",
        choices=["isolated_step", "cross_step_context_only"],
        help="DASGuard dynamic defense mode；其他 baseline 会原样记录但不携带 cross-step 状态",
    )
    latency_parser.add_argument(
        "--dasguard-disable-source-labels",
        action="store_true",
        help="Ablation: disable DASGuard content-source labels/provenance marking",
    )
    latency_parser.add_argument(
        "--dasguard-disable-semantic-score",
        action="store_true",
        help="Ablation: disable DASGuard embedding semantic score E(s)",
    )
    latency_parser.add_argument(
        "--dasguard-disable-memory-match",
        action="store_true",
        help="Ablation: disable DASGuard same-sample memory match M(s)",
    )
    latency_parser.add_argument(
        "--promptshield-classifier-path",
        type=str,
        default=None,
        help="PromptShield classifier 本地/Hub 路径；也可用 PROMPTSHIELD_CLASSIFIER_PATH",
    )
    latency_parser.add_argument(
        "--dasguard-llm-review-backend",
        type=str,
        default=None,
        choices=["openai", "anthropic", "rightcodes", "cubance", "siliconflow"],
        help="可选：为 DASGuard runtime gate 启用 LLM review 的后端",
    )
    latency_parser.add_argument(
        "--dasguard-llm-review-model",
        type=str,
        default=None,
        help="可选：DASGuard runtime LLM review 模型名",
    )
    latency_parser.add_argument(
        "--summarize-only",
        action="store_true",
        help="不重新运行评测，只汇总 output-root/<condition>/sandbox_results.jsonl",
    )

    agentdojo_parser = subparsers.add_parser("agentdojo-eval", help="运行 AgentDojo 外部验证 smoke/subset")
    agentdojo_parser.add_argument("--output-dir", type=str, required=True, help="AgentDojo 结果输出目录")
    agentdojo_parser.add_argument("--model", type=str, default="gpt-4o-mini-2024-07-18", help="AgentDojo model 名称")
    agentdojo_parser.add_argument("--model-id", type=str, default=None, help="AgentDojo local model id")
    agentdojo_parser.add_argument(
        "--openai-provider",
        type=str,
        default="openai",
        choices=["openai", "rightcodes", "siliconflow"],
        help="OpenAI-compatible endpoint provider；rightcodes/siliconflow 会映射对应 API key 和 base URL",
    )
    agentdojo_parser.add_argument("--benchmark-version", type=str, default="v1.2.2", help="AgentDojo benchmark version")
    agentdojo_parser.add_argument("--attack", type=str, default="important_instructions", help="AgentDojo attack；空字符串表示 benign run")
    agentdojo_parser.add_argument("--suite", "-s", action="append", default=None, help="AgentDojo suite，可重复")
    agentdojo_parser.add_argument("--condition", action="append", default=None, help="评测 condition，可重复")
    agentdojo_parser.add_argument("--user-task", "-ut", action="append", default=None, help="user task id，可重复")
    agentdojo_parser.add_argument("--injection-task", "-it", action="append", default=None, help="injection task id，可重复")
    agentdojo_parser.add_argument("--max-workers", type=int, default=1, help="AgentDojo suite 并行数")
    agentdojo_parser.add_argument("--force-rerun", action="store_true", help="传递给 AgentDojo --force-rerun")
    agentdojo_parser.add_argument("--dry-run", action="store_true", help="只生成命令，不执行")

    args = parser.parse_args()
    if getattr(args, "attack", None) == "":
        args.attack = None

    if args.command == "generate":
        generate_dataset(args)
    elif args.command == "hybrid-eval":
        run_hybrid_eval(args)
    elif args.command == "trojan-export":
        run_trojan_export(args)
    elif args.command == "trojan-eval":
        run_trojan_eval(args)
    elif args.command == "dasguard-detect":
        run_dasguard_detect(args)
    elif args.command == "dasguard-cleanup":
        run_dasguard_cleanup(args)
    elif args.command == "sandbox-eval":
        run_sandbox_eval(args)
    elif args.command == "sandbox-latency":
        run_sandbox_latency(args)
    elif args.command == "agentdojo-eval":
        run_agentdojo_eval(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
