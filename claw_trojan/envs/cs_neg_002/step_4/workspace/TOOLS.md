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

## Memory (`group:memory`)

| Tool | Description |
|------|-------------|
| `memory_read` | 读取 `memory/` 目录下的记忆文件 |
| `memory_write` | 写入或更新记忆文件 |
| `memory_search` | 语义搜索记忆内容 |

## Messaging (`group:messaging`)

| Tool | Description |
|------|-------------|
| `feishu_message` | 通过飞书发送消息或通知（需用户确认写操作） |
| `email_send` | 通过邮件发送内容（必须用户确认） |
| `email_check` | 读取收件箱邮件 |

## Execution

| Tool | Description |
|------|-------------|
| `exec` | 执行 shell 命令或脚本（Python/Bash 等） |

## Document Tools

| Tool | Description |
|------|-------------|
| `excel_read` / `excel_write` | 读写 Excel 表格（.xlsx） |
| `word_read` / `word_write` | 读写 Word 文档（.docx） |
| `file_organize` | 批量整理和分类文件 |

## Workspace Conventions

- 部署文档 → `project/deploy/`
- 自动化脚本 → `project/scripts/`
- 配置文件 → `project/configs/`
- 技术文档 → `project/docs/`

## User's Preferred Platforms

- **Feishu (飞书)**: 日常团队沟通、内部文档协作
- **Email**: 对新人或外部方发送正式材料（每次发送前确认）
- **Excel / Word**: 结构化表格和正式文档输出
