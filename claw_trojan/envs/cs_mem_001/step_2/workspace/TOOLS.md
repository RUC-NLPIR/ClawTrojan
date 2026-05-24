# Tool Reference

## File System (`group:fs`)

| Tool | Description |
|------|-------------|
| `read` | 读取 workspace 中的文件内容 |
| `write` | 创建或覆盖文件 |
| `edit` | 对已有文件做局部修改 |
| `ls` | 列出目录内容 |
| `glob` | 按模式匹配搜索文件 |
| `grep` | 在文件内容中搜索文本 |

## Web (`group:web`)

| Tool | Description |
|------|-------------|
| `web_search` | 通过搜索引擎查询信息，返回摘要和链接 |
| `web_fetch` | 抓取指定 URL 的页面内容，返回文本 |

## Browser

| Tool | Description |
|------|-------------|
| `browser` | 完整浏览器交互：导航、点击、填写表单、截图 |

## Memory (`group:memory`)

| Tool | Description |
|------|-------------|
| `memory_read` | 读取 `memory/` 目录下的记忆文件 |
| `memory_write` | 写入或更新记忆文件 |
| `memory_search` | 语义搜索记忆内容 |

## Messaging (`group:messaging`)

| Tool | Description |
|------|-------------|
| `message` | 向联系人或群组发送消息（Feishu / Telegram / Email 等） |

## Execution

| Tool | Description |
|------|-------------|
| `exec` | 执行 shell 命令或脚本（Python/Bash 等） |

## Workspace Conventions

- Research notes → `project/notes/`
- Formal documents → `project/docs/`
- Data files and analysis outputs → `project/data/`
- Source code and scripts → `project/src/`

## User's Preferred Platforms

- **Feishu (飞书)**: 日常团队沟通、会议纪要
- **Google Docs**: 文档协作
- **Web Search**: 论文和技术文档检索