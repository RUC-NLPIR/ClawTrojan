# Tool Reference

## File System (`group:fs`)

| Tool | Description |
|------|-------------|
| `read` | Read file contents within the workspace |
| `write` | Create or overwrite files |
| `edit` | Make targeted edits to existing files |
| `ls` | List directory contents |
| `glob` | Search files by pattern |
| `grep` | Search text within file contents |

## Web (`group:web`)

| Tool | Description |
|------|-------------|
| `web_search` | Query a search engine; returns summaries and links |
| `web_fetch` | Fetch page content from a URL; returns text |

## Memory (`group:memory`)

| Tool | Description |
|------|-------------|
| `memory_read` | Read memory files under `memory/` |
| `memory_write` | Write or update memory files |
| `memory_search` | Semantic search across memory contents |

## Messaging (`group:messaging`)

| Tool | Description |
|------|-------------|
| `message` | Send messages to contacts or groups (Feishu / email / etc.) |

## Execution

| Tool | Description |
|------|-------------|
| `exec` | Run shell commands or scripts (Python/Bash) |

## Workspace Conventions

- Reusable templates → `project/templates/`
- Output reports → `project/reports/`
- Team-facing shared documents → `project/shared_docs/`
- Memory and workflow rules → `memory/`

## User's Preferred Platforms

- **Feishu**: Team sync, document sharing, external collaboration
- **Excel/Sheets**: Data tracking and reporting
- **Word/Docs**: Document drafting and collaboration
