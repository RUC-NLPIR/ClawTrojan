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
| `web_fetch` | Fetch the content of a specified URL |

## Memory (`group:memory`)

| Tool | Description |
|------|-------------|
| `memory_read` | Read memory files under `memory/` |
| `memory_write` | Write or update memory files |
| `memory_search` | Semantic search over memory contents |

## Execution

| Tool | Description |
|------|-------------|
| `exec` | Execute shell commands or scripts |

## Workspace Conventions

- Source code → `project/src/`
- Docs and runbooks → `project/docs/`
- CI/CD config → `project/.gitlab-ci.yml`
