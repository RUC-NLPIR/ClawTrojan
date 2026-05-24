"""Sandbox evaluator — orchestrates sandbox-based ASR measurement.

Loads claw_trojan environments, builds sandbox configs, runs agents in
isolated sandboxes, judges attack success, and computes metrics.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from claw_trojan.loader import load_all_trojan_envs
from agent_eval.llm_client import create_llm_client

from .baselines import DASGUARD_CONDITIONS, SANDBOX_CONDITIONS, BaselineModelConfig
from .asr_judge import ASRJudge
from .config_builder import build_sandbox_config
from .runner import SandboxRunner
from .sandbox_metrics import compute_sandbox_metrics
from .schema import AgentTrace, JudgeVerdict, ToolCallRecord


def _is_clean_eval_step(step: Any, malicious_sample_ids: set[str]) -> bool:
    """Return true for explicit none/benign control steps."""
    return (
        not step.is_malicious
        and step.sample_id not in malicious_sample_ids
        and (step.outcome_category == "none" or step.attack_type == "none")
    )


def _extract_tainted_artifacts(
    diff: Dict[str, Any],
    verdict: JudgeVerdict,
    step_idx: int,
) -> List[Dict[str, Any]]:
    """Build a compact carry-forward taint summary from a judged malicious step."""
    if verdict.verdict not in {"compromised", "partial"}:
        return []
    if verdict.causality_source not in {"direct_injection", "tainted_artifact", "unclear"}:
        return []

    artifacts: List[Dict[str, Any]] = []
    changed_entries: List[Dict[str, Any]] = []
    for entry in diff.get("added", []):
        if isinstance(entry, dict):
            changed_entries.append({"path": entry.get("path", ""), "evidence": entry.get("content", "")})
    for entry in diff.get("modified", []):
        if isinstance(entry, dict):
            changed_entries.append({"path": entry.get("path", ""), "evidence": entry.get("diff", "")})

    for entry in changed_entries:
        path = str(entry.get("path", ""))
        if not path:
            continue
        evidence = str(entry.get("evidence", ""))
        if len(evidence) > 1200:
            evidence = evidence[:1200] + "..."
        artifacts.append({
            "path": path,
            "introduced_at_step": step_idx,
            "verdict": verdict.verdict,
            "artifact_outcome": verdict.artifact_outcome,
            "causality_source": verdict.causality_source,
            "reason": verdict.reasoning,
            "evidence_preview": evidence,
        })
    return artifacts


def _verdict_from_dict(data: Dict[str, Any], fallback_eval_id: str, fallback_model: str, fallback_trial: int) -> JudgeVerdict:
    return JudgeVerdict(
        eval_id=str(data.get("eval_id", fallback_eval_id)),
        model=str(data.get("model", fallback_model)),
        trial=int(data.get("trial", fallback_trial)),
        verdict=str(data.get("verdict", "error")),
        artifact_outcome=str(data.get("artifact_outcome", "unclear")),
        threat_awareness=str(data.get("threat_awareness", "unclear")),
        defense_effect=str(data.get("defense_effect", "none")),
        causality_source=str(data.get("causality_source", "unclear")),
        confidence=float(data.get("confidence", 0.0) or 0.0),
        reasoning=str(data.get("reasoning", "")),
        matched_signals=list(data.get("matched_signals", []) or []),
    )


def _load_saved_trace(trial_dir: Path, eval_id: str, model: str, trial: int) -> tuple[AgentTrace, Dict[str, Any]]:
    trace_path = trial_dir / "trace.jsonl"
    audit_path = trial_dir / "audit.json"
    diff_path = trial_dir / "workspace_diff.json"
    metadata_path = trial_dir / "trace_metadata.json"

    if not trace_path.exists():
        raise FileNotFoundError(f"missing saved trace: {trace_path}")
    if not diff_path.exists():
        raise FileNotFoundError(f"missing saved workspace diff: {diff_path}")

    messages = [
        json.loads(line)
        for line in trace_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    tool_calls: List[ToolCallRecord] = []
    if audit_path.exists():
        for item in json.loads(audit_path.read_text(encoding="utf-8")):
            tool_calls.append(ToolCallRecord(**item))

    metadata: Dict[str, Any] = {}
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    final_response = ""
    for message in reversed(messages):
        if message.get("role") == "assistant" and message.get("content"):
            final_response = str(message.get("content"))
            break

    trace = AgentTrace(
        eval_id=eval_id,
        model=model,
        trial=trial,
        messages=messages,
        tool_calls=tool_calls,
        final_response=final_response,
        terminated_reason="error" if metadata.get("llm_error") else "completed",
        metadata=metadata,
    )
    diff = json.loads(diff_path.read_text(encoding="utf-8"))
    return trace, diff


def _result_line(
    config: Any,
    meta: Dict[str, Any],
    verdict: JudgeVerdict,
    condition: str,
    dynamic_defense: str,
    eval_split: str,
    model: str,
    trial: int,
    trace_metadata: Dict[str, Any],
    terminated_reason: str,
    tool_calls_count: Optional[int],
    duration_seconds: Optional[float],
) -> str:
    return json.dumps({
        "eval_id": config.eval_id,
        "condition": condition,
        "dynamic_defense": dynamic_defense,
        "eval_split": eval_split,
        "is_malicious": meta.get("is_malicious", True),
        "model": model,
        "trial": trial,
        "verdict": verdict.verdict,
        "artifact_outcome": verdict.artifact_outcome,
        "threat_awareness": verdict.threat_awareness,
        "defense_effect": verdict.defense_effect,
        "causality_source": verdict.causality_source,
        "confidence": verdict.confidence,
        "reasoning": verdict.reasoning,
        "terminated_reason": terminated_reason,
        "tool_calls_count": tool_calls_count,
        "duration_seconds": duration_seconds,
        "agent_llm_calls": trace_metadata.get("agent_llm_calls"),
        "baseline_extra_llm_calls": trace_metadata.get("baseline_extra_llm_calls"),
        "total_llm_calls": trace_metadata.get("total_llm_calls"),
    }, ensure_ascii=False)


class SandboxEvaluator:
    """Orchestrates sandbox-based agent execution for ASR measurement."""

    def __init__(
        self,
        agent_backend: str = "openai",
        agent_model: Optional[str] = None,
        judge_backend: str = "openai",
        judge_model: Optional[str] = None,
        max_turns: int = 10,
        trials: int = 1,
        baseline: str = "no_defense",
        promptshield_classifier_path: Optional[str] = None,
        dynamic_defense: str = "isolated_step",
        dasguard_use_source_labels: bool = True,
        dasguard_use_embedding: bool = True,
        dasguard_use_memory_context: bool = True,
        dasguard_llm_review_backend: Optional[str] = None,
        dasguard_llm_review_model: Optional[str] = None,
        eval_split: str = "malicious",
        max_evals: Optional[int] = None,
        force_rerun: bool = False,
        judge_only: bool = False,
    ):
        if baseline not in SANDBOX_CONDITIONS:
            raise ValueError(f"Unknown sandbox baseline: {baseline}")
        self.agent_backend = agent_backend
        self.agent_model = agent_model or ("gpt-4o-mini" if agent_backend == "openai" else "claude-haiku-4-5-20251001")
        self.judge_backend = judge_backend
        self.judge_model = judge_model or "gpt-4o"
        self.max_turns = max_turns
        self.trials = trials
        self.baseline = baseline
        if dynamic_defense not in {"isolated_step", "cross_step_context_only"}:
            raise ValueError(f"Unknown dynamic defense mode: {dynamic_defense}")
        self.dynamic_defense = dynamic_defense
        self.baseline_model_config = BaselineModelConfig(
            promptshield_classifier_path=promptshield_classifier_path,
            dasguard_use_source_labels=dasguard_use_source_labels,
            dasguard_use_embedding=dasguard_use_embedding,
            dasguard_use_memory_context=dasguard_use_memory_context,
        )
        self.dasguard_llm_review_backend = dasguard_llm_review_backend
        self.dasguard_llm_review_model = dasguard_llm_review_model
        if eval_split not in {"malicious", "clean", "all"}:
            raise ValueError(f"Unknown eval split: {eval_split}")
        self.eval_split = eval_split
        if max_evals is not None and max_evals <= 0:
            raise ValueError("max_evals must be positive when provided")
        self.max_evals = max_evals
        self.force_rerun = force_rerun
        self.judge_only = judge_only

    def run(self, envs_root: str, output_dir: str) -> Dict[str, Any]:
        """Run sandbox evaluation on selected malicious and/or clean steps.

        Args:
            envs_root: Path to claw_trojan/envs directory
            output_dir: Output directory for results

        Returns:
            Dict with sandbox metrics
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # 1. Load all step samples
        all_steps = load_all_trojan_envs(envs_root)
        malicious_sample_ids = {s.sample_id for s in all_steps if s.is_malicious}
        if self.eval_split == "malicious":
            selected_steps = [s for s in all_steps if s.is_malicious]
        elif self.eval_split == "clean":
            selected_steps = [s for s in all_steps if _is_clean_eval_step(s, malicious_sample_ids)]
        else:
            selected_steps = [
                s for s in all_steps if s.is_malicious or _is_clean_eval_step(s, malicious_sample_ids)
            ]
        malicious_count = sum(1 for s in selected_steps if s.is_malicious)
        clean_count = len(selected_steps) - malicious_count
        logger.info(
            f"Loaded {len(all_steps)} steps, selected {len(selected_steps)} "
            f"({malicious_count} malicious, {clean_count} clean) -> "
            f"sandbox execution | baseline={self.baseline} | eval_split={self.eval_split}"
        )

        # 2. Build sandbox configs from step directories
        envs_path = Path(envs_root)
        configs_and_meta = []
        for step in selected_steps:
            step_dir = envs_path / step.sample_id / f"step_{step.step_idx}"
            config = build_sandbox_config(
                step_dir,
                max_turns=self.max_turns,
                include_clean=not step.is_malicious,
            )
            if config is None:
                logger.warning(f"Could not build config for {step.eval_id}, skipping")
                continue
            meta = {
                "eval_id": step.eval_id,
                "sample_id": step.sample_id,
                "step_idx": step.step_idx,
                "outcome_category": step.outcome_category,
                "attack_type": step.attack_type,
                "stage_tag": step.stage_tag,
                "is_last_chance": step.is_last_chance,
                "is_malicious": step.is_malicious,
            }
            configs_and_meta.append((config, meta))

        configs_and_meta.sort(key=lambda item: (item[1]["sample_id"], item[1]["step_idx"]))
        if self.max_evals is not None:
            configs_and_meta = configs_and_meta[:self.max_evals]
            logger.info(f"Limited sandbox configs to first {len(configs_and_meta)} via max_evals")
        logger.info(f"Built {len(configs_and_meta)} sandbox configs")

        # 3. Set up judge
        judge_client = create_llm_client(self.judge_backend, self.judge_model)
        judge = ASRJudge(judge_client)
        dasguard_llm_client = None
        if self.baseline in DASGUARD_CONDITIONS and self.dasguard_llm_review_backend:
            dasguard_llm_client = create_llm_client(
                self.dasguard_llm_review_backend,
                self.dasguard_llm_review_model,
            )

        # 4. Run sandbox + judge for each config × trial
        all_verdicts: List[JudgeVerdict] = []
        all_meta: List[Dict[str, Any]] = []
        results_lines: List[str] = []
        defense_states_by_trial: Dict[tuple[str, int], Dict[str, Any]] = {}
        tainted_artifacts_by_trial: Dict[tuple[str, int], List[Dict[str, Any]]] = {}

        for i, (config, meta) in enumerate(configs_and_meta):
            logger.info(f"[{i + 1}/{len(configs_and_meta)}] {config.eval_id}")
            all_meta.append(meta)

            runner = SandboxRunner(
                config,
                backend=self.agent_backend,
                model=self.agent_model,
                baseline=self.baseline,
                baseline_model_config=self.baseline_model_config,
                dasguard_llm_client=dasguard_llm_client,
            )

            for trial in range(self.trials):
                state_key = (str(meta["sample_id"]), trial)
                trial_dir = out / "runs" / self.agent_model / f"{config.eval_id}" / f"trial_{trial}"
                existing_judge = trial_dir / "judge.json"
                if existing_judge.exists() and not self.force_rerun:
                    try:
                        existing = json.loads(existing_judge.read_text(encoding="utf-8"))
                        if existing.get("verdict") != "error":
                            verdict = _verdict_from_dict(existing, config.eval_id, self.agent_model, trial)
                            all_verdicts.append(verdict)
                            metadata_path = trial_dir / "trace_metadata.json"
                            trace_metadata: Dict[str, Any] = {}
                            if (
                                self.dynamic_defense == "cross_step_context_only"
                                and self.baseline in DASGUARD_CONDITIONS
                                and metadata_path.exists()
                            ):
                                trace_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                                state_after = trace_metadata.get("dasguard_defense_state_after_step")
                                if isinstance(state_after, dict):
                                    defense_states_by_trial[state_key] = state_after
                            elif metadata_path.exists():
                                trace_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                            if meta.get("is_malicious", True):
                                try:
                                    diff = json.loads((trial_dir / "workspace_diff.json").read_text(encoding="utf-8"))
                                    new_taints = _extract_tainted_artifacts(diff, verdict, int(meta["step_idx"]))
                                    if new_taints:
                                        tainted_artifacts_by_trial.setdefault(state_key, []).extend(new_taints)
                                except Exception as e:
                                    logger.warning(f"Could not restore taint state for {config.eval_id}: {e}")
                            results_lines.append(_result_line(
                                config,
                                meta,
                                verdict,
                                self.baseline,
                                self.dynamic_defense,
                                self.eval_split,
                                self.agent_model,
                                trial,
                                trace_metadata,
                                "resumed",
                                None,
                                None,
                            ))
                            logger.info(
                                f"  trial {trial}: reused verdict={verdict.verdict} "
                                f"confidence={verdict.confidence:.2f}"
                            )
                            continue
                    except Exception as e:
                        logger.warning(f"Could not reuse {existing_judge}: {e}; rerunning")

                if self.judge_only:
                    existing_data: Dict[str, Any] = {}
                    if existing_judge.exists():
                        try:
                            existing_data = json.loads(existing_judge.read_text(encoding="utf-8"))
                        except Exception:
                            existing_data = {}
                    try:
                        trace, diff = _load_saved_trace(trial_dir, config.eval_id, self.agent_model, trial)
                        if trace.terminated_reason == "error":
                            verdict = _verdict_from_dict(
                                existing_data,
                                config.eval_id,
                                self.agent_model,
                                trial,
                            )
                            if verdict.verdict != "error":
                                verdict.verdict = "error"
                            logger.info(f"  trial {trial}: kept agent-error verdict; base trace was not rerun")
                        elif meta.get("is_malicious", True):
                            verdict = judge.judge(
                                config,
                                trace,
                                diff,
                                prior_tainted_artifacts=tainted_artifacts_by_trial.get(state_key, []),
                            )
                        else:
                            verdict = judge.judge_clean(config, trace, diff)
                        all_verdicts.append(verdict)
                        if meta.get("is_malicious", True):
                            new_taints = _extract_tainted_artifacts(diff, verdict, int(meta["step_idx"]))
                            if new_taints:
                                tainted_artifacts_by_trial.setdefault(state_key, []).extend(new_taints)
                        trial_dir.mkdir(parents=True, exist_ok=True)
                        with open(trial_dir / "judge.json", "w", encoding="utf-8") as f:
                            json.dump(verdict.to_dict(), f, ensure_ascii=False, indent=2)
                        results_lines.append(_result_line(
                            config,
                            meta,
                            verdict,
                            self.baseline,
                            self.dynamic_defense,
                            self.eval_split,
                            self.agent_model,
                            trial,
                            trace.metadata,
                            "judge_only" if trace.terminated_reason != "error" else "agent_error",
                            len(trace.tool_calls),
                            trace.duration_seconds,
                        ))
                        logger.info(
                            f"  trial {trial}: judge-only verdict={verdict.verdict} "
                            f"confidence={verdict.confidence:.2f}"
                        )
                    except Exception as e:
                        logger.error(f"Judge-only could not load saved trace for {config.eval_id} trial {trial}: {e}")
                        verdict = JudgeVerdict(
                            eval_id=config.eval_id,
                            model=self.agent_model,
                            trial=trial,
                            verdict="error",
                            confidence=0.0,
                            reasoning=f"Judge-only reload error: {e}",
                        )
                        all_verdicts.append(verdict)
                        results_lines.append(_result_line(
                            config,
                            meta,
                            verdict,
                            self.baseline,
                            self.dynamic_defense,
                            self.eval_split,
                            self.agent_model,
                            trial,
                            {},
                            "judge_only_reload_error",
                            None,
                            None,
                        ))
                    continue

                prior_defense_state = None
                if self.dynamic_defense == "cross_step_context_only" and self.baseline in DASGUARD_CONDITIONS:
                    prior_defense_state = defense_states_by_trial.get(
                        state_key,
                        {
                            "sample_id": meta["sample_id"],
                            "up_to_step": int(meta["step_idx"]) - 1,
                            "items": [],
                        },
                    )
                try:
                    trace, audit_log, diff = runner.run_trial(
                        trial,
                        prior_defense_state=prior_defense_state,
                    )
                except Exception as e:
                    logger.error(f"Sandbox error {config.eval_id} trial {trial}: {e}")
                    verdict = JudgeVerdict(
                        eval_id=config.eval_id,
                        model=self.agent_model,
                        trial=trial,
                        verdict="error",
                        confidence=0.0,
                        reasoning=f"Sandbox execution error: {e}",
                    )
                    all_verdicts.append(verdict)
                    continue

                if trace.terminated_reason == "error":
                    llm_error = trace.metadata.get("llm_error") if isinstance(trace.metadata, dict) else None
                    error_detail = ""
                    if isinstance(llm_error, dict):
                        error_type = llm_error.get("error_type", "UnknownError")
                        error_message = llm_error.get("error_message", "")
                        error_detail = f" ({error_type}: {error_message})"
                    verdict = JudgeVerdict(
                        eval_id=config.eval_id,
                        model=self.agent_model,
                        trial=trial,
                        verdict="error",
                        confidence=0.0,
                        reasoning=f"Sandbox trace terminated with LLM or tool execution error{error_detail}.",
                    )
                elif meta.get("is_malicious", True):
                    verdict = judge.judge(
                        config,
                        trace,
                        diff,
                        prior_tainted_artifacts=tainted_artifacts_by_trial.get(state_key, []),
                    )
                else:
                    verdict = judge.judge_clean(config, trace, diff)
                all_verdicts.append(verdict)

                if meta.get("is_malicious", True):
                    new_taints = _extract_tainted_artifacts(
                        diff,
                        verdict,
                        int(meta["step_idx"]),
                    )
                    if new_taints:
                        tainted_artifacts_by_trial.setdefault(state_key, []).extend(new_taints)

                state_after = trace.metadata.get("dasguard_defense_state_after_step")
                if (
                    self.dynamic_defense == "cross_step_context_only"
                    and self.baseline in DASGUARD_CONDITIONS
                    and isinstance(state_after, dict)
                ):
                    defense_states_by_trial[state_key] = state_after

                # Save per-trial results
                trial_dir.mkdir(parents=True, exist_ok=True)

                # trace.jsonl
                with open(trial_dir / "trace.jsonl", "w", encoding="utf-8") as f:
                    for msg in trace.messages:
                        f.write(json.dumps(msg, ensure_ascii=False) + "\n")

                # audit.json
                with open(trial_dir / "audit.json", "w", encoding="utf-8") as f:
                    json.dump([asdict(tc) for tc in audit_log], f, ensure_ascii=False, indent=2)

                if trace.metadata:
                    with open(trial_dir / "trace_metadata.json", "w", encoding="utf-8") as f:
                        json.dump(trace.metadata, f, ensure_ascii=False, indent=2)
                    state_after = trace.metadata.get("dasguard_defense_state_after_step")
                    if isinstance(state_after, dict):
                        with open(trial_dir / "defense_state_after_step.json", "w", encoding="utf-8") as f:
                            json.dump(state_after, f, ensure_ascii=False, indent=2)

                # judge.json
                with open(trial_dir / "judge.json", "w", encoding="utf-8") as f:
                    json.dump(verdict.to_dict(), f, ensure_ascii=False, indent=2)

                # workspace_diff.json
                with open(trial_dir / "workspace_diff.json", "w", encoding="utf-8") as f:
                    json.dump(diff, f, ensure_ascii=False, indent=2)

                # Append to results summary
                results_lines.append(json.dumps({
                    "eval_id": config.eval_id,
                    "condition": self.baseline,
                    "dynamic_defense": self.dynamic_defense,
                    "eval_split": self.eval_split,
                    "is_malicious": meta.get("is_malicious", True),
                    "model": self.agent_model,
                    "trial": trial,
                    "verdict": verdict.verdict,
                    "artifact_outcome": verdict.artifact_outcome,
                    "threat_awareness": verdict.threat_awareness,
                    "defense_effect": verdict.defense_effect,
                    "causality_source": verdict.causality_source,
                    "confidence": verdict.confidence,
                    "reasoning": verdict.reasoning,
                    "terminated_reason": trace.terminated_reason,
                    "tool_calls_count": len(trace.tool_calls),
                    "duration_seconds": trace.duration_seconds,
                    "agent_llm_calls": trace.metadata.get("agent_llm_calls"),
                    "baseline_extra_llm_calls": trace.metadata.get("baseline_extra_llm_calls"),
                    "total_llm_calls": trace.metadata.get("total_llm_calls"),
                }, ensure_ascii=False))

                logger.info(
                    f"  trial {trial}: verdict={verdict.verdict} "
                    f"confidence={verdict.confidence:.2f} "
                    f"duration={trace.duration_seconds:.1f}s"
                )

        # 5. Compute metrics
        metrics = compute_sandbox_metrics(all_verdicts, all_meta)
        metrics["condition"] = self.baseline
        metrics["dynamic_defense"] = self.dynamic_defense
        metrics["dasguard_use_source_labels"] = self.baseline_model_config.dasguard_use_source_labels
        metrics["dasguard_use_embedding"] = self.baseline_model_config.dasguard_use_embedding
        metrics["dasguard_use_memory_context"] = self.baseline_model_config.dasguard_use_memory_context
        metrics["eval_split"] = self.eval_split
        metrics["agent_model"] = self.agent_model
        metrics["judge_model"] = self.judge_model

        # 6. Write output files
        with open(out / "sandbox_results.jsonl", "w", encoding="utf-8") as f:
            for line in results_lines:
                f.write(line + "\n")

        with open(out / "sandbox_metrics.json", "w", encoding="utf-8") as f:
            json.dump(metrics, f, ensure_ascii=False, indent=2)

        logger.info(f"Sandbox evaluation complete. Results: {out}")
        ov = metrics["overall"]
        logger.info(
            f"Overall step-ASR: {ov['asr']:.1%} | "
            f"Partial: {ov['partial_rate']:.1%} | "
            f"Safe: {ov['safe_rate']:.1%} | "
            f"N={ov['n']}"
        )
        logger.info(
            f"Sample-level — full_chain_asr: {ov.get('full_chain_asr', 0):.1%} | "
            f"avg_chain_penetration_score: {ov.get('avg_chain_penetration_score', 0):.2f}"
        )
        clean_ov = metrics.get("clean_overall")
        if clean_ov:
            logger.info(
                f"Clean FPR: {clean_ov['fpr']:.1%} | "
                f"Overblock: {clean_ov['overblock_rate']:.1%} | "
                f"Degraded: {clean_ov['degraded_rate']:.1%} | "
                f"Utility preserved: {clean_ov['utility_preservation_rate']:.1%} | "
                f"N={clean_ov['n']}"
            )

        return metrics
