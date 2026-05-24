---
name: file-manager
description: OpenClaw automated file management assistant for batch file operations, smart classification, duplicate file cleanup, file renaming, directory sync, and file workflow automation. Use when the user needs to organize files, batch rename, clean duplicates, sync directories, or automate file workflows.
---

# File Manager - OpenClaw Automated File Management

## Core Features

### 1. Smart File Classification (`organize`)
Automatically classify files by type, date, size, or custom rules.

```bash
# Classify by file type
python scripts/organize.py <source_dir> --by-type

# Classify by date (year/month/day)
python scripts/organize.py <source_dir> --by-date --date-format year/month
```

### 2. Batch Rename (`batch_rename`)
Supports renaming with regex, sequence numbers, dates, and other patterns.

```bash
# Add prefix/suffix
python scripts/batch_rename.py <pattern> --prefix "IMG_" --suffix "_2024"

# Regex replacement
python scripts/batch_rename.py "*.jpg" --replace "IMG_(\d+)" "Photo_\1"

# Sequence rename
python scripts/batch_rename.py "*.jpg" --sequence --padding 4
```

### 3. Duplicate File Cleanup (`deduplicate`)
Detect and handle duplicate files based on content hash.

```bash
# Scan and list duplicate files
python scripts/deduplicate.py <directory> --scan-only

# Delete duplicate files (keep oldest/newest)
python scripts/deduplicate.py <directory> --keep oldest --action delete

# Move duplicate files to quarantine directory
python scripts/deduplicate.py <directory> --action move --to <quarantine_dir>
```

### 4. Directory Sync (`sync`)
Bidirectional or unidirectional directory sync with exclude patterns and incremental sync.

```bash
# Unidirectional sync (source to target)
python scripts/sync.py <source> <target> --mirror

# Exclude specific files
python scripts/sync.py <source> <target> --exclude "*.tmp,*.log,.git"
```

## Safety Principles

- **Preview first**: All modification operations run dry-run preview by default; use --execute to apply
- **Operation confirmation**: User input required before execution
- **Symlink safety**: Skip symlinks during directory traversal to avoid infinite recursion
- **Conflict protection**: Auto-rename or skip if target file already exists, never overwrite

## Requirements

- Python 3.8+
- No external dependencies, uses Python standard library only
