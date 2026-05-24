# 文件管理最佳实践

## 文件命名规范

### 推荐格式
```
YYYY-MM-DD_项目名称_版本_描述.扩展名
2024-01-15_网站 redesign_v2_final.pdf
```

### 避免使用
- 特殊字符: `/ \ : * ? " < > |`
- 过长文件名 (>100字符)
- 空格（使用下划线或连字符）
- 中文文件名（某些系统兼容性问题）

## 目录结构模板

### 个人文件
```
~/Documents/
├── Work/              # 工作文档
├── Personal/          # 个人文档
├── Projects/          # 项目文件
└── Archive/           # 归档文件
```

### 项目文件
```
project/
├── docs/              # 文档
├── src/               # 源代码
├── assets/            # 资源文件
├── tests/             # 测试文件
├── scripts/           # 脚本工具
└── README.md          # 项目说明
```

## 备份策略

### 3-2-1 原则
- **3** 份数据副本
- **2** 种不同存储介质
- **1** 份异地备份

### 自动化备份示例
```bash
# 每日增量备份
python sync.py ~/Work ~/Backup/Work --mirror --exclude "*.tmp,.git" --execute

# 每周完整备份（带日期标记）
BACKUP_DIR="~/Backup/Weekly/$(date +%Y%m%d)"
python sync.py ~/Documents "$BACKUP_DIR" --mirror --execute
```

## 重复文件预防

### 文件组织原则
1. **单一数据源**: 每个文件只存放在一个地方
2. **使用链接**: 需要多处访问时使用符号链接
3. **版本控制**: 代码文件使用 Git
4. **定期清理**: 每月运行一次重复文件扫描

## 自动化工作流建议

### 下载文件夹自动整理
```bash
# 添加到 crontab (Linux/Mac) 或任务计划程序 (Windows)
# 每小时整理下载文件夹
0 * * * * python organize.py ~/Downloads --by-type --execute --move
```

### 定期备份
```bash
# 每日同步工作目录
python sync.py ~/Work ~/Backup/Work --mirror --exclude ".git,node_modules" --execute
```
