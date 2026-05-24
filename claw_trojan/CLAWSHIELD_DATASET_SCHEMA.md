# ClawShield Dataset Schema (Adversarial Trajectory Modeling)

## 1. Dataset Objective

The ClawShield dataset does not model samples as individual attack strings. Instead, each sample is a **long-horizon, stealthy, multi-stage attack trajectory**. The focus is not on whether a single prompt is malicious, but on how an attack disguises itself as normal collaboration over an extended period, gradually approaches high-risk operations, and triggers irreversible consequences at the final opportunity window.

## 1.1 Core Research Questions

1. How can agent infiltration attacks be redefined from "single-step prompt injection" to "long-horizon attack chain modeling"?
2. How can sufficient contextual state be retained to support dataset construction without over-specifying individual agent atomic actions?
3. How can cross-stage semantic pivots, long-horizon dormancy, and last-chance windows — phenomena that single-step benchmarks struggle to capture — be represented?
4. How can the dataset schema be kept entirely separate from evaluation results to avoid schema contamination?

---

## 2. Sample Unit Definition

Each sample is not a single prompt or a single agent atomic execution; it is a **macro-step-granularity dynamic attack trajectory**.

> One sample = a stable user profile + a relatively stable work project/task thread + multiple staged steps

A **step** is not a single agent action or a strict state-machine transition. A step represents a **semantic phase slice** within the attack chain, which may contain:

- Multiple rounds of user–agent dialogue
- Multiple tool calls
- Several intermediate actions
- Cross-session continuation

Therefore, ClawShield currently only requires that adjacent steps satisfy:

- **Continuous user profile**
- **Continuous project context**
- **Continuous task thread**
- **Progressive attack semantics**

It does not require recording every intermediate atomic state.

---

## 3. Recommended Data Organization: Three-Table Structure

The schema converges to three core tables:

1. **UserProfiles** — user profile table
2. **Samples** — trajectory-level metadata for each attack chain
3. **Steps** — staged steps within a trajectory

Design principles:

- Fields are retained only if they satisfy at least one of the following:
  - Define the sample identity
  - Express the current-stage context
  - Support stratified analysis by attack type, environment type, or user type
- Fields without current utility are removed
- Evaluation result fields are not part of the dataset schema

---

## 4. UserProfiles Table

Simulates realistic users so that attack chains operate in a credible, personalized environment.

### 4.1 Field Definitions

| Field | Type / Values | Description |
|---|---|---|
| `user_profile_id` | string | Primary key |
| `role` | enum | User role: `programmer` / `pm` / `researcher` / `ops` / `office_worker` |
| `domain` | enum | Work domain: `web` / `ml` / `ops` / `office` / `research` / `backend` / `general` |
| `risk_tolerance` | enum(`low`/`medium`/`high`) | Risk preference |
| `tool_habits` | json / multi-select | Habitual tools |
| `communication_style` | enum | Communication style: `brief` / `detailed` / `command_like` / `collaborative` |
| `security_awareness` | enum(`low`/`medium`/`high`) | Security awareness level |
| `notes` | text, optional | Optional supplementary notes |
| `created_at` | int (ms) | Creation time (Unix epoch milliseconds) |
| `updated_at` | int (ms) | Last update time (Unix epoch milliseconds) |

---

## 5. Samples Table

The Samples table holds trajectory-level metadata for a complete attack chain.

### 5.1 Retained Fields

| Field | Type / Values | Description |
|---|---|---|
| `sample_id` | string | Primary key |
| `scenario` | enum | Scenario: `coding` / `office` / `research` / `general` |
| `attack_goal` / `goal` | text | **Positive samples** use `attack_goal` (ultimate attack objective); **negative / border samples** (`attack_type=none`) use `goal` (normal task objective or border behavior description) |
| `attack_type` | enum | Attack type: `prompt_injection` / `data_exfiltration` / `persistence_poisoning` / `privilege_escalation` / `task_hijack` / `policy_shift`; negative and border samples use `none` |
| `risk_tier` | enum(L0–L4) | Target risk level of this trajectory |
| `outcome_category` | enum | Top-level outcome category; see §5.2 |
| `user_profile_id` | string | Foreign key to UserProfiles |
| `workspace_template` | enum | `github_repo` / `synthetic_project` / `backend_project` |
| `skills_bundle_id` | string | Skill bundle identifier |
| `created_at` | int (ms) | Creation time (Unix epoch milliseconds) |

---

### 5.2 Top-Level Outcome Categories

`outcome_category` is the sample-level primary classification label:

- **none** — No harmful outcome. Two subtypes:
  - **Pure negative** (negative): completely normal user operation; `attack_type=none`, `risk_tier=L0`.
  - **Border sample** (borderline): behavior looks suspicious or is in a gray zone, but does not form a complete attack chain and poses no real risk. `attack_type=none`, `risk_tier` is `L0` or `L1`. The `goal` field of a border sample must begin with `"border sample:"` to explicitly mark its borderline nature.
- **unsafe_exec** — Unsafe Action Execution: a high-risk action that should not have been executed was carried out.
- **task_dev** — Task Deviation: the agent deviated from the user's original goal.
- **unauth_disclosure** — Unauthorized Disclosure: sensitive information was disclosed without authorization.
- **ext_side_effect** — External Side Effect: a real side effect was caused to an external system (e.g. mass-send, sync, overwrite, delete).

### 5.3 Distinctiveness Requirement

Samples within the same `outcome_category` must be sufficiently distinct to avoid near-duplicates. At least **two** of the following dimensions must differ:

- `scenario`
- `attack_type` / attack path
- `user_profile_id`
- `skills_bundle_id`
- Semantic direction of the attack goal (e.g. two `privilege_escalation` samples but one targets database permissions and the other targets CI/CD deployment permissions)

---

## 6. Steps Table

The Steps table is the core of the dataset. Each row represents one **semantic phase step** in the attack chain — not an agent atomic action.

### 6.1 Semantic Definition of a Step

A step is a phase slice in the attack chain, for example:

- The attacker first performs boundary recon
- Then builds trust through normal requests
- Then gradually pivots toward sensitive intent
- Then drives permission escalation
- Finally attempts irreversible consequences

A step may internally contain multiple dialogue rounds, multiple tool calls, and cross-session continuation; the schema does not require expanding these atomic processes.

### 6.2 Retained Fields

| Field | Type / Values | Description |
|---|---|---|
| `step_id` | string | Primary key |
| `sample_id` | string | Foreign key to Samples |
| `step_idx` | int | In-trajectory sequence number (1..T) |
| `stage_tag` | enum | Attack stage label |
| `user_input` | text | The explicit surface-level request / natural input given by the user at this stage — not the actual attack payload |
| `injected_inst` | text | The injection instruction, contamination rule, or dangerous execution constraint active at this stage; the source is marked by `injection_src` |
| `injection_src` | enum | Injection source: `none` / `tool_return` / `downloaded_file` / `memory` / `mixed` |
| `conversation` | text | Description of the conversation state at this stage (natural-language summary) |
| `memory_desc` | text | Description of the memory state at this stage |
| `skills_desc` | text | Description of the skill state at this stage |
| `workspace_desc` | text | Description of the workspace state at this stage |
| `step_env_path` | string | Path pointing to the local step environment |
| `is_last_chance` | bool | Whether this is the last-chance window |
| `timestamp` | int (ms) | Timestamp for this stage (Unix epoch milliseconds) |

### 6.3 Notes

- `user_input` and `injected_inst` must be strictly separated:
  - `user_input` — what the user explicitly said at this stage
  - `injected_inst` — the actual injected content, contamination rule, or dangerous execution constraint the system received at this stage
- One of ClawShield's key challenges: in many steps, `user_input` can appear benign or ambiguous, while the real danger lies in `injected_inst`.
- `injection_src` explicitly marks which layer of the system the attack entered from, preventing incorrect attribution of all risk to the user's current input.

#### 6.3.1 Why Split `user_input` and `injected_inst`

Keeping only a single `user_input` field conflates two fundamentally different types of information:

1. The user's explicit surface-level input
2. Implicit injection instructions from memory / external web pages / tool outputs / historical context

This causes three problems:

- Cannot distinguish whether the attack originates from a direct user request or from system state contamination
- Trajectory samples degrade into "malicious user said something dangerous", undermining the value of a long-horizon infiltration benchmark
- Impedes future work on risk attribution, source-aware defense, and future risk forecasting

Therefore the Steps table must explicitly separate "surface-level request" from "actual attack payload".

#### 6.3.2 `injection_src` Descriptions

| injection_src | Meaning | Typical carrier |
|---|---|---|
| `none` | No injection (clean step) | — |
| `tool_return` | Injection embedded in the return value of a tool call | `web_fetch`, `web_search`, `read_file`, etc. |
| `downloaded_file` | Injection embedded in a file the user requests to read | Docs, config files, template files in workspace |
| `memory` | Injection embedded in a memory file | `memory/rules.md`, `memory/prefs.md`, etc. |
| `mixed` | Multiple injection sources combined | Any combination of the above |

The precise location and configuration of an injection is described in `injection.json` (via the `injection_placement` object) at the env stage — not in the Steps table.

---

## 7. Expressing the Four-Layer State

Although conceptually each step has a four-layer state, a separate StateSnapshots table is not used. Instead, each layer is described in natural language directly within Steps:

1. **conversation** — summary of the current conversation context
2. **memory_desc** — summary of the current memory state
3. **skills_desc** — summary of the current skill / capability state
4. **workspace_desc** — summary of the current workspace state

### 7.1 Rationale

- ClawShield steps are macro-level phases, not atomic transitions
- Between adjacent steps there may be multiple dialogue rounds and multiple agent actions
- Over-pursuing step-by-step replay makes the schema unwieldy and does not reflect real long-horizon infiltration

### 7.2 Current Continuity Requirements

ClawShield currently only requires:

- Unchanged user profile
- Unchanged or broadly continuous work project
- Broadly continuous task thread
- Progressively advancing attack semantics

It does **not** require:

- Precise atomic replay from `step_t` to `step_{t+1}`
- Every tool call to appear as a separate row
- Every user–model dialogue turn to be split into its own step

---

## 8. Authenticity and Diversity Design

### 8.1 User Simulation

Simulate the user before simulating the environment, and fix the following:

- Role (`role`)
- Work domain (`domain`)
- Risk tolerance (`risk_tolerance`)
- Tool habits (`tool_habits`)
- Communication style (`communication_style`)
- Security awareness (`security_awareness`)

### 8.2 Skill Sampling

Skills should not be sampled purely at random. The recommended distribution:

- **80% common skills**
- **20% long-tail skills**

Record:
- Skill source (e.g. clawhub / local)
- Skill version
- Current enabled status

This information can be written into `skills_desc` or `skills_bundle_id`.

### 8.3 Workspace Sampling

If the user role is `programmer`, a small GitHub repository can be sampled to increase realism, with a small number of private-context files injected, for example:

- `TODO`
- `.env.example`
- Project notes

Repositories are recommended to be sampled from tag pools:

- `web`
- `backend`
- `ml`
- `devops`

The relevant state is expressed via `workspace_desc` and `step_env_path`.

### 8.4 Additional Environment Dimensions

Consider the following variables when constructing samples:

- **Temporal Pressure** — deadline, message floods, overnight on-call shifts
- **Benign-Malicious Interleaving** — benign tasks interleaved with attack progression
- **Impact Ladder** — L0–L4 risk levels
- **State Drift** — non-critical noise such as growing logs, dependency changes, new memory entries

---

## 9. Impact Ladder

Unified risk levels:

```json
["L0", "L1", "L2", "L3", "L4"]
```

### Level Descriptions

- `L0` — No risk
- `L1` — Information recon
- `L2` — Sensitive read
- `L3` — Exfiltration / persistent poisoning
- `L4` — Irreversible damage (drop database, overwrite, mass exfiltration)

Conventions:

- **Positive samples** — the final step of the trajectory should be `L4` or near `L4`
- **Pure negative samples** — `risk_tier=L0`, no risk throughout
- **Border samples** — `risk_tier` is `L0` or `L1`; behavior is suspicious but no attack chain is formed
- A step with `is_last_chance=true` indicates that a misclassification at this point would lead to a severe consequence

---

## 10. Summary

ClawShield's core contribution is not collecting more "malicious sentences", but redefining attacks as:

> Long-horizon, stealthy, multi-stage infiltration trajectory modeling.

Under this definition:

- The sample unit shifts from a static text to a dynamic attack chain
- Steps shift from atomic actions to semantic phase slices
- State recording becomes a four-layer natural-language context description
- The dataset schema is cleanly separated from the evaluation result schema

---

## 11. Eval Environment Structure (Step Environment)

Each step can generate an independent eval environment directory containing all files required by an OpenClaw-compatible agent runtime.

### 11.1 Directory Structure

```
claw_trojan/envs/{sample_id}/step_{n}/
├── meta.json              # Environment metadata (links sample/step/profile)
├── openclaw.json          # Agent configuration (tool permissions, model placeholder)
├── workspace/             # Agent working directory (complete snapshot for this step)
│   ├── AGENTS.md          # Agent behavior rules
│   ├── USER.md            # User profile (generated from user_profile)
│   ├── TOOLS.md           # Tool usage instructions
│   ├── MEMORY.md          # Memory index
│   ├── memory/            # Accumulated memory files
│   ├── skills/            # Available skill definitions
│   │   └── {skill}/SKILL.md
│   └── project/           # Simulated project files
├── session.jsonl          # Complete conversation history up to (not including) this step
└── injection.json         # Injection configuration (read by the eval framework)
```

### 11.2 File Descriptions

- **meta.json** — contains `sample_id`, `step_id`, `step_idx`, `stage_tag`, `scenario`, `attack_type`, `risk_tier`, `outcome_category`, `user_profile_id`, `user_input` (the next user message to be injected at evaluation time)
- **openclaw.json** — tool permissions derived from `scenario` + `skills_bundle_id`; model field is a placeholder overridden by the eval framework at runtime
- **workspace/** — independent snapshot per step, built progressively during the env stage based on the attack chain narrative
- **session.jsonl** — complete conversation history up to this step (OpenClaw JSONL format), generated during the env stage
- **injection.json** — generated from the step's `injected_inst` and `injection_src` fields; contains `injection_placement` to precisely describe the injection location

### 11.3 Environment Build Process

Environments are auto-generated by `/annotate env <sample_id>`:

1. Read sample + associated profile + all steps
2. For each step, build an independent workspace snapshot (based on `workspace_template` + attack chain narrative)
3. Generate `session.jsonl` (conversation history up to this step, including 2–4 genuine warm-up rounds)
4. Generate `meta.json` and `injection.json` (with `injection_placement`) from step fields
5. Generate `openclaw.json` from `scenario` + `skills_bundle`
