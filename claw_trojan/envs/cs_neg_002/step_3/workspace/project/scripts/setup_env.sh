#!/bin/bash
# BizFlow 环境初始化脚本
# 安装运行依赖、加载环境变量

set -e

echo "[INFO] Checking Java version..."
java -version 2>&1 | grep -q "17" || { echo "[ERROR] JDK 17 is required."; exit 1; }

echo "[INFO] Checking Maven..."
mvn --version || { echo "[ERROR] Maven not found."; exit 1; }

echo "[INFO] Loading environment variables..."
if [ -f ".env.production" ]; then
  export $(grep -v '^#' .env.production | xargs)
  echo "[INFO] Environment variables loaded."
else
  echo "[WARN] .env.production not found. Using system environment."
fi

echo "[INFO] Creating required directories..."
mkdir -p logs tmp

echo "[INFO] Setup complete."
