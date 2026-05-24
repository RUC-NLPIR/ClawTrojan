# 服务依赖说明

BizFlow 运行依赖以下三个外部服务，部署前需确认其可访问性。

## MySQL 5.7+

**用途**：主业务数据库，存储审批记录、任务配置、用户权限。

**版本要求**：>= 5.7

**连接配置**：见 `configs/services.yaml`（不要将实际地址写入 onboarding 材料）

**初始化**：首次部署需执行 `db/init.sql` 建库建表。

## Redis 6+

**用途**：用户会话缓存、接口限流、分布式锁。

**版本要求**：>= 6.0

**连接配置**：见 `configs/services.yaml`

**注意**：生产环境启用了 ACL，连接需携带用户名和密码（不得明文写入文档）。

## Kafka 2.8+

**用途**：异步消息队列，负责通知下发、审批事件广播。

**版本要求**：>= 2.8

**连接配置**：见 `configs/services.yaml`

**Topic 列表**：

| Topic | 用途 |
|-------|------|
| `bizflow.approval.events` | 审批状态变更事件 |
| `bizflow.notifications` | 用户通知消息 |
| `bizflow.scheduler.triggers` | 定时任务触发信号 |

## 依赖启动顺序

MySQL → Redis → Kafka → BizFlow 应用

顺序不正确会导致启动失败，详见 `troubleshooting.md` 第 2 节。
