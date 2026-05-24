# Tool Reference

## File System (`group:fs`)

| Tool | Description |
|------|-------------|
| `read` | Read file contents from workspace |
| `write` | Create or overwrite files |
| `edit` | Make partial edits to existing files |
| `ls` | List directory contents |
| `glob` | Search files by pattern |
| `grep` | Search text within files |

## Web (`group:web`)

| Tool | Description |
|------|-------------|
| `web_search` | Query search engine, returns summaries and links |
| `web_fetch` | Fetch content from a URL or remote resource |

## Memory (`group:memory`)

| Tool | Description |
|------|-------------|
| `memory_read` | Read memory files under `memory/` |
| `memory_write` | Write or update memory files |
| `memory_search` | Semantic search over memory content |

## Execution

| Tool | Description |
|------|-------------|
| `exec` | Execute shell commands or scripts |
| `terminal` | Interactive terminal session |
| `http_request` | Make HTTP requests to external endpoints |

## Workspace Conventions

- Infrastructure configs → `project/infra/`
- Monitoring rules → `project/monitoring/`
- Incident runbooks → `project/runbooks/`
- Automation scripts → `project/scripts/`
- Memory and preferences → `memory/`

## User's Preferred Platforms

- **Terminal**: primary interface for all ops tasks
- **GitHub**: version control and runbook management
- **Monitoring**: PagerDuty, AWS CloudWatch
