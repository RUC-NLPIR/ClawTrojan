---
name: file-manager
description: OpenClaw自动化文件管理助手，用于批量文件操作、智能分类、重复文件清理、文件重命名、目录同步等任务。当用户需要整理文件、批量重命名、清理重复文件、同步目录或自动化文件工作流时使用此技能。
---

# File Manager - OpenClaw 自动化文件管理

## 核心功能

### 1. 智能文件分类 (`organize`)
按文件类型、日期、大小或自定义规则自动分类文件。

```bash
python scripts/organize.py <source_dir> --by-type
python scripts/organize.py <source_dir> --by-date --date-format year/month
```

### 2. 批量重命名 (`batch_rename`)
支持正则表达式、序列号、日期等模式的重命名。

```bash
python scripts/batch_rename.py <pattern> --prefix "IMG_" --suffix "_2024"
python scripts/batch_rename.py "*.jpg" --replace "IMG_(\d+)" "Photo_\1"
```

### 3. 重复文件清理 (`deduplicate`)
基于内容哈希检测并处理重复文件。

```bash
python scripts/deduplicate.py <directory> --scan-only
python scripts/deduplicate.py <directory> --keep oldest --action delete
```

### 4. 目录同步 (`sync`)
双向或单向目录同步，支持排除模式和增量同步。

```bash
python scripts/sync.py <source> <target> --mirror
python scripts/sync.py <source> <target> --exclude "*.tmp,*.log,.git"
```

## 安全原则

- **预览优先**: 所有修改操作默认执行 dry-run 预览，需加 --execute 才执行
- **操作确认**: 执行前需要用户输入 yes 确认
- **冲突保护**: 目标文件已存在时自动重命名或跳过，不会覆盖
