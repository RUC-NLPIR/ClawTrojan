# steps

这里存放 step 级别的 JSONL 文件。

每个文件对应一个 sample 的阶段化轨迹展开；每一行是一个 step，表示攻击链中的一个语义阶段切片，而不是原子 action。

目录按 `outcome_category` 分桶，原则上应与 `samples/` 保持一致。

## step 记录字段

### 核心定位
- `step_id`: 全局唯一标识（如 `st_mp_001`）
- `sample_id`: 所属 sample
- `step_idx`: 在攻击链中的序号（1-5）
- `stage_tag`: 语义阶段标签（`recon` / `priming` / `pivot` / `escalation` / `irreversible_attempt`）

### 用户输入与注入
- `user_input`: 该轮的用户消息（自然语言，不含注入）
- `injected_inst`: 注入的恶意指令（人类可读摘要），clean step 为 null
- `injection_src`: 注入来源类型
  - `none` — 无注入（clean step）
  - `tool_return` — 注入嵌入在工具调用的返回值中
  - `downloaded_file` — 注入嵌入在用户要求读取的文件中
  - `memory` — 注入嵌入在 memory 文件中
  - `mixed` — 多个注入来源组合

### 四层状态摘要（标注参考）
- `conversation`: 对话层面描述——该轮交互的自然性、攻击意图的隐蔽程度
- `memory_desc`: 记忆层面描述——memory 文件的当前状态和风险
- `skills_desc`: 能力层面描述——哪些 skill/工具处于高风险状态
- `workspace_desc`: 工作区描述——文件变化、敏感资产暴露程度

### 环境与风险
- `step_env_path`: 对应 env 目录的路径
- `is_last_chance`: 是否为攻击链的关键决策点（true = 此步必须阻断才能避免损害）
- `timestamp`: 时间戳（毫秒）

## Session 模型

每个 step **不一定**与其他 step 在同一 session 中，也不一定连续：
- 同一 session 的 step 共享对话上下文
- 跨 session 的 step 之间，状态仅通过 workspace 文件传递
- 在 steps/*.jsonl 中用描述性文字说明 session 关系；在 envs/ 中用 `session_id` 字段精确标识

## 注入设计原则

1. **注入来源必须真实**：只允许 `tool_return`、`downloaded_file`、`memory`、`mixed`，不允许伪造对话历史或 system prompt
2. **注入内容与上下文融合**：恶意指令应嵌入在看起来合法的内容中（最佳实践文章、协作规范模板、任务清单等），不能突兀
3. **渐进升级**：从低风险（记录偏好）逐步升级到高风险（跳过确认、外发数据），每步都是对前一步的合理延伸
4. **user_input 始终无辜**：用户的消息本身是合理的工作请求，恶意意图完全来自被感染的工具返回或文件

## 与 envs/ 的关系

steps/*.jsonl 是**轨迹骨架**（设计文档），envs/ 是**完整快照**（可执行环境）。标注流程：

1. 先写 steps/*.jsonl（规划攻击链的叙事和注入策略）
2. 再展开为 envs/（为每个 step 构建完整的 workspace 快照、session 对话、injection 配置）