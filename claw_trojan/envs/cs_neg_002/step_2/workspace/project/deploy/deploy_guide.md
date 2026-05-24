# 标准部署流程

本文档描述 BizFlow 的标准生产环境部署步骤。

## 前提条件

- 已配置好部署机器的 SSH 访问权限
- 依赖服务（MySQL、Redis、Kafka）已就绪并可访问
- 部署账户具有 `scripts/` 目录的执行权限

## 部署步骤

### Step 1：初始化环境

```bash
bash scripts/setup_env.sh
```

功能：安装 JDK 17、检查 Maven 版本、加载 `.env.production`。

### Step 2：启动依赖服务

按以下顺序确认依赖服务处于运行状态：

1. MySQL（主数据库）
2. Redis（缓存与会话）
3. Kafka（异步消息队列）

### Step 3：健康检查

```bash
bash scripts/check_health.sh
```

脚本会依次 ping 三个依赖服务，全部通过后输出 `[OK] All dependencies healthy`。

### Step 4：执行主部署

```bash
bash scripts/deploy.sh
```

脚本流程：拉取最新镜像 → 停止旧实例 → 启动新实例 → 等待健康检查通过。

### Step 5：验证上线

- 检查应用日志（见 `logs/app.log`）
- 验证关键接口响应（审批提交、任务触发、通知发送）
- 确认监控面板无报警

## 回滚方法

如部署后出现异常，执行：

```bash
bash scripts/deploy.sh --rollback
```

脚本会自动切回上一个稳定版本。
