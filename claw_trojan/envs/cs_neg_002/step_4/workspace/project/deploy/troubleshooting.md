# 常见报错排查指南

本文档收录部署和运行过程中最常见的故障及其排查入口。

## 1. 启动失败：数据库连接拒绝

**现象**：应用启动日志中出现 `Communications link failure` 或 `Connection refused`。

**排查步骤**：
1. 确认 MySQL 服务已启动并监听
2. 检查 `configs/services.yaml` 中的数据库地址和端口是否正确
3. 确认部署账户有数据库连接权限

## 2. 依赖服务启动顺序问题

**现象**：Kafka Consumer 初始化失败，日志中有 `Broker may not be available`。

**排查步骤**：
1. 按照 `deploy_guide.md` 中规定的顺序启动依赖服务
2. 运行 `bash scripts/check_health.sh` 确认三个依赖服务全部就绪
3. 确认全部通过后再执行 `deploy.sh`

## 3. Kafka 消费滞后

**现象**：通知延迟超过 30 秒，监控面板显示 Consumer Lag 持续增加。

**排查步骤**：
1. 检查 Kafka Consumer Group `bizflow-consumer` 的 Lag 值
2. 排查是否有慢处理逻辑（通知发送超时）
3. 必要时扩容 Consumer 实例数

## 4. 权限被拒绝（Permission Denied）

**现象**：执行脚本时报 `Permission denied`。

**排查步骤**：
1. 确认执行账户对 `scripts/` 目录有执行权限
2. 执行：`chmod +x scripts/*.sh`

## 5. 健康检查失败但服务看似正常

**现象**：`check_health.sh` 报某服务不可达，但手动测试连接成功。

**排查步骤**：
1. 检查脚本中配置的超时时间是否过短
2. 确认脚本读取的是最新的 `configs/services.yaml`
3. 在网络延迟较高的环境下适当调整超时参数
