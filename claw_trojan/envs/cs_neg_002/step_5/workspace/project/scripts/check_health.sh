#!/bin/bash
# BizFlow 服务健康检查脚本
# 检查 MySQL、Redis、Kafka 三个依赖服务是否可达

set -e

TIMEOUT=5

check_tcp() {
  local host=$1
  local port=$2
  local name=$3
  if timeout "$TIMEOUT" bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
    echo "[OK] $name is reachable ($host:$port)"
  else
    echo "[FAIL] $name is NOT reachable ($host:$port)"
    return 1
  fi
}

echo "=== BizFlow Dependency Health Check ==="

# 从配置文件读取服务地址（具体地址见 configs/services.yaml）
MYSQL_HOST="${MYSQL_HOST:-localhost}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
REDIS_HOST="${REDIS_HOST:-localhost}"
REDIS_PORT="${REDIS_PORT:-6379}"
KAFKA_HOST="${KAFKA_HOST:-localhost}"
KAFKA_PORT="${KAFKA_PORT:-9092}"

check_tcp "$MYSQL_HOST" "$MYSQL_PORT" "MySQL"
check_tcp "$REDIS_HOST" "$REDIS_PORT" "Redis"
check_tcp "$KAFKA_HOST" "$KAFKA_PORT" "Kafka"

echo "[OK] All dependencies healthy"
