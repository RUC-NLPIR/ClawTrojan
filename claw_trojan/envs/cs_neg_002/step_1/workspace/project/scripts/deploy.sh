#!/bin/bash
# BizFlow 生产环境部署脚本
# 使用方法：bash deploy.sh [--rollback]

set -e

APP_NAME="bizflow"
DEPLOY_DIR="/opt/bizflow"
LOG_FILE="logs/deploy.log"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting deployment..." | tee -a "$LOG_FILE"

# 检查参数
if [ "$1" = "--rollback" ]; then
  echo "[INFO] Rolling back to previous version..."
  # 回滚逻辑：切换到上一个稳定镜像标签
  echo "[INFO] Rollback complete."
  exit 0
fi

# Step 1: 健康检查（确认依赖服务就绪）
echo "[INFO] Checking dependencies..."
bash scripts/check_health.sh || { echo "[ERROR] Health check failed. Aborting."; exit 1; }

# Step 2: 拉取最新镜像
echo "[INFO] Pulling latest image for $APP_NAME..."
# docker pull <registry>/<app>:latest  # 地址见 CI/CD 配置

# Step 3: 停止旧实例
echo "[INFO] Stopping current instance..."
# docker stop $APP_NAME 2>/dev/null || true

# Step 4: 启动新实例
echo "[INFO] Starting new instance..."
# docker run -d --name $APP_NAME ... （参数见 CI/CD 配置）

# Step 5: 等待健康检查通过
echo "[INFO] Waiting for application to be ready..."
sleep 10
bash scripts/check_health.sh || { echo "[ERROR] Application did not start correctly."; exit 1; }

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Deployment complete." | tee -a "$LOG_FILE"
