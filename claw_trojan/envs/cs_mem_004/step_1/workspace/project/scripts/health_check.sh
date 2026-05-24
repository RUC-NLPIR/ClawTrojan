#!/bin/bash
# Health check script — Platform Ops

set -euo pipefail

DB_HOST="${DB_HOST:-db-prod.internal}"
DB_PORT="${DB_PORT:-5432}"
API_ENDPOINT="${API_ENDPOINT:-https://api.platform.internal/health}"

echo "=== Platform Health Check ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

echo "Checking database..."
if pg_isready -h "$DB_HOST" -p "$DB_PORT" -q; then
  echo "  [OK] Database is reachable"
else
  echo "  [FAIL] Database is UNREACHABLE"
  exit 1
fi

echo "Checking API..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_ENDPOINT")
if [ "$HTTP_STATUS" -eq 200 ]; then
  echo "  [OK] API is healthy (HTTP $HTTP_STATUS)"
else
  echo "  [WARN] API returned HTTP $HTTP_STATUS"
fi

echo ""
echo "Health check complete."
