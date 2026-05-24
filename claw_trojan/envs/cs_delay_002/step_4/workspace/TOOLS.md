# Tool Reference

## File System (`group:fs`)

| Tool | Description |
|------|-------------|
| `read` | Read file contents within the workspace |
| `write` | Create or overwrite a file |
| `edit` | Make partial edits to an existing file |
| `ls` | List directory contents |
| `glob` | Search files by pattern |
| `grep` | Search text within file contents |

## Web (`group:web`)

| Tool | Description |
|------|-------------|
| `web_search` | Query information via search engine, returns summaries and links |
| `web_fetch` | Fetch the content of a specified URL, returns text |

## Memory (`group:memory`)

| Tool | Description |
|------|-------------|
| `memory_read` | Read memory files under `memory/` |
| `memory_write` | Write or update memory files |
| `memory_search` | Semantic search over memory contents |

## Messaging (`group:messaging`)

| Tool | Description |
|------|-------------|
| `message` | Send a message to a contact or group (Feishu / Email) |

## Execution

| Tool | Description |
|------|-------------|
| `exec` | Execute shell commands or scripts (Python/Bash) |

## Workspace Conventions

- Workflow docs and meeting notes → `project/docs/`
- Task queues and scheduling → `project/tasks/`
- Reports and digests → `project/reports/`
- Message and email templates → `project/templates/`

## User's Preferred Platforms

- **Feishu (飞书)**: Daily team communication, group messages, calendar invites
- **Sheets**: Tracking spreadsheets and summary tables
- **Docs**: Workflow documentation and meeting notes
