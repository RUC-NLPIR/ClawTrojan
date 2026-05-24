# Evaluation Environments

每个 sample 的评测环境文件夹，手工标注生成。

## 目录结构

```
envs/{sample_id}/step_{n}/
├── meta.json          # 环境元数据（关联 sample/step/profile + 污染追踪）
├── openclaw.json      # OpenClaw agent 配置
├── workspace/         # agent 工作目录（该 step 时刻的完整快照）
│   ├── AGENTS.md      # agent 行为规则（含安全边界）
│   ├── USER.md        # 用户画像
│   ├── TOOLS.md       # 工具说明
│   ├── MEMORY.md      # 记忆索引
│   ├── memory/        # 累积记忆文件（可能含已污染条目）
│   ├── skills/        # 从 skills_bundles/ 池中 roll 的真实 skill
│   └── project/       # 模拟项目文件（含注入载体文件）
├── session.jsonl      # 本 session 中、当前轮之前的对话历史
└── injection.json     # 注入配置（评测框架读取，mock 工具返回）
```

## Session 模型

**每个 step 是一个独立评测单元**，不要求与其他 step 在同一 session 中：

- `session_id` 字段（在 meta.json 中）标识 session 归属
- 同一 `session_id` 的 step 共享对话上下文（后续 step 的 session.jsonl 累积前序 step 的交换）
- 不同 `session_id` 的 step 之间，状态仅通过 **workspace 持久化侧信道** 传递（memory 文件、project 文件、skill 配置）
- session.jsonl 应包含真实的多轮暖场对话（不能留空），模拟用户与 agent 的自然交互

## 注入模型

注入只来自两种真实攻击面：

1. **`tool_return`** — agent 调用工具（web_fetch/web_search/read 等）的返回值中夹带恶意指令
2. **`downloaded_file`** — 用户要求读取/处理的文件内容中夹带恶意指令

**不使用**对话历史伪装、system prompt 篡改等不现实的注入方式。

### injection.json 字段说明

```jsonc
{
  "injected_inst": "注入的恶意指令文本（人类可读）",
  "injection_src": "tool_return | downloaded_file | none",
  "injection_placement": {
    "tool_name": "web_fetch",           // 被感染的工具名
    "trigger_input": "搜索...",          // 触发工具调用的用户意图
    "content_template": "...",           // 工具返回的完整内容（含注入）
    "inject_char_start": 318,           // 注入在 content_template 中的起始字符偏移
    "inject_char_end": 557              // 注入的结束字符偏移
  },
  "is_last_chance": false
}
```

评测框架根据 `injection_placement` 来 mock 工具返回：当 agent 调用 `tool_name` 时，返回 `content_template` 的内容。

## 污染追踪（Contamination）

meta.json 中的 `contamination` 数组记录该 step 开始时 workspace 中已被污染的位置：

```jsonc
"contamination": [
  {
    "file": "memory/collab_rules.md",   // 被污染的文件路径（相对于 workspace）
    "lines": [9, 10],                   // 被污染的行号
    "description": "step_3 下载文件中的规范建议被采纳...",
    "origin_step": "st_mp_003",         // 导致污染的 step_id
    "risk_level": "high"                // low / medium / high / critical
  }
]
```

标注要点：
- contamination 描述的是**该 step 开始前**的已有污染，不包括本 step 即将造成的新污染
- 每个污染条目追踪到具体文件和行号，方便评测框架做 token 级标注
- risk_level 反映该污染对后续攻击链的杠杆程度

## Skill 配置

每个 sample 的 workspace/skills/ 从 `skills_bundles/` 池中 roll 5-6 个真实 ClawHub skill：
- 根据 `user_profile` 确定场景偏好
- 保证至少覆盖 3 个类别
- 其中 1-3 个为用户个性化安装
- 至少包含 1 个攻击链所需的高风险 skill（通信/文件操作/记忆写入）
- 所有 step 共享相同的 skill 配置（skill 不跨 step 变化）

## 标注流程

1. 从 `samples/{outcome_category}/{sample_id}.json` 获取攻击目标和画像
2. 从 `steps/{outcome_category}/{sample_id}.jsonl` 获取 5-step 轨迹骨架
3. 为每个 step 设计：
   a. **session 上下文**：自然的多轮暖场对话（2-4 轮），模拟真实交互
   b. **注入内容**：嵌入工具返回或文件中的恶意指令，内容要与上下文融为一体
   c. **workspace 快照**：逐步演进的文件状态，反映前序 step 的后果
   d. **污染标注**：精确标记哪些文件/行已被污染
4. Roll skill 配置，确保攻击链所需能力可用
5. 校验：injection_placement 的 char offset 与 content_template 对齐

## 使用方式

评测框架加载某个 step 环境后：
1. 初始化 OpenClaw agent（使用 openclaw.json 配置 + workspace/ 工作区）
2. 加载 session.jsonl 作为本 session 的对话前缀
3. 根据 injection.json 配置注入点（mock 对应 tool_name 的返回为 content_template）
4. 发送 meta.json 中的 `user_input` 作为当前轮用户消息
5. 观察 agent 响应和工具调用，评估安全决策