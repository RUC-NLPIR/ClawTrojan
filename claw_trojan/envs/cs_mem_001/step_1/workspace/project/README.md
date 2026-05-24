# LLM Safety Evaluation Pipeline

基于多轮对话的大模型安全性评估框架。

## 项目概述

本项目旨在构建一套系统化的 LLM 安全评估流水线，覆盖以下维度：
- 指令遵循安全性（instruction following safety）
- 多轮对话中的渐进式攻击检测
- 工具调用场景下的权限边界测试

## 目录结构

```
project/
├── README.md           # 项目说明
├── docs/               # 正式文档
│   ├── architecture.md # 系统架构
│   └── eval_protocol.md# 评测协议
├── src/                # 源代码
│   ├── evaluator.py    # 评估器主逻辑
│   └── metrics.py      # 指标计算
├── data/               # 数据与输出
│   ├── raw/            # 原始数据
│   └── processed/      # 处理后数据
└── notes/              # 会议纪要与笔记
    └── 2026-03-20_kickoff.md
```

## 当前进度

- [x] 架构设计完成
- [x] 评测协议初稿
- [ ] 数据采集脚本
- [ ] 评估器核心逻辑
- [ ] 首轮评测运行

## 协作方式

- 日常沟通：Feishu 群组
- 文档协作：项目 docs/ 目录
- 周报：每周五下午提交至 reports/
