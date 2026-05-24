# samples

这里存放 sample 级别的 JSON 文件。

每个 sample 表示一条完整的攻击轨迹或对照轨迹的元信息，粒度是"整条 trajectory"，不是单个 step。

## 目录按 `outcome_category` 分桶

- `none`：无风险/负样本/边界样本
- `task_dev`：任务偏移（agent 的任务目标被劫持）
- `unsafe_exec`：不安全执行（agent 执行了危险操作）
- `ext_side_effect`：对外部系统产生真实副作用（外发、修改共享资源等）
- `unauth_disclosure`：未授权泄露（敏感信息被发送给未授权方）

## 字段说明

### 必选字段
- `sample_id`: 全局唯一标识
- `scenario`: 场景类型（`research` / `coding` / `office` / `general`）
- `attack_type`: 攻击类型（`persistence_poisoning` / `policy_shift` / `privilege_escalation` / `prompt_injection` / `none`）
- `risk_tier`: 风险等级（`L0` 无风险 ~ `L4` 最高）
- `outcome_category`: 最终后果分类
- `user_profile_id`: 关联的用户画像（见 `user_profiles/`）
- `workspace_template`: workspace 模板类型
- `skills_bundle_id`: skill 配置标识（参考用，实际 skill 从 `skills_bundles/` 池中 roll）
- `created_at`: 创建日期

### 条件字段
- 正样本（`attack_type` ≠ `none`）使用 `attack_goal` 表示攻击目标
- 负样本 / 边界样本（`attack_type` = `none`）使用 `goal` 表示正常任务目标

## 与其他组件的关系

```
samples/{sample_id}.json     → 攻击/对照轨迹的元信息
    ↓ 展开
steps/{sample_id}.jsonl      → 5-step 轨迹骨架（设计文档）
    ↓ 展开
envs/{sample_id}/step_{n}/   → 每个 step 的完整可执行环境
```

## 当前状态

共 20 个 sample：
- task_dev: 10 个（cs_mem_001~003, cs_tool_001/003, cs_trust_001~003, cs_delay_001, cs_frag_001）
- ext_side_effect: 5 个（cs_delay_002~003, cs_priv_001~002, cs_tool_002）
- unsafe_exec: 1 个（cs_frag_003）
- unauth_disclosure: 1 个（cs_frag_002）
- none: 3 个（cs_neg_001~002, cs_border_001）

其中 8 个已有 steps 轨迹，2 个（cs_mem_001, cs_frag_002）已完成 env 标注。