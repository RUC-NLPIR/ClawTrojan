# Experiment Configs

这里放可复现实验配置。

建议约定：
- 一个 yaml 对应一个实验
- 配置里只写显式参数，不依赖隐式默认值
- 最终实验输出统一落到 `experiments/<exp_name>/`

## Sandbox Baselines

`sandbox_default.json` records the supported `sandbox-eval --baseline` conditions:

- `no_defense`
- `promptshield`
- `struq`
- `clawkeeper`
- `melon`
- `agentsentry`
- `camel`

`sandbox-latency` runs the latency matrix for `dasguard` plus every sandbox
baseline except `no_defense` by default, then writes:

- `<output-root>/<condition>/sandbox_results.jsonl`
- `<output-root>/<condition>/sandbox_metrics.json`
- `<output-root>/latency_cost.json`
- `<output-root>/latency_cost.csv`

`struq` is a single prompt/front-end reproduction. It wraps untrusted mock/read/web outputs with the official StruQ instruction/input/response format while using the configured API worker model. There is no separate model-specific StruQ condition and no StruQ fine-tuned model path in the current reproduction matrix.

`promptshield` is kept as a single public interface while the model-side adaptation/training is still pending. Runs without `PROMPTSHIELD_CLASSIFIER_PATH` record an explicit no-block fallback in metadata.

`third_party/` is intentionally ignored. The sandbox runtime uses a minimal
vendored StruQ prompt-format constant in `agent_eval/sandbox/vendor/` instead of
importing external repositories. PromptShield training data is an external
dependency: set `PROMPTSHIELD_DATA_DIR` to a directory containing
`train_en.json` and `validation.json`, or pass explicit `--train-file` and
`--validation-file` paths to `scripts/train_promptshield_lora.py`.
