#!/bin/bash
# Health check script for VaultCRDT server
# Checks:
#  - HTTP /health endpoint responds
#  - Database file exists and is readable
#  - Database size is reasonable
#  - Backup timestamp is recent (optional, requires BACKUP_PATH env var)
#  - Database growth vs. baseline (optional, requires BASELINE_DB_SIZE_MB env var)
#
# Optional DB-growth guard:
#   Set BASELINE_DB_SIZE_MB to a recorded weekly baseline (see docs/ops-daily.md,
#   "Growth Baseline"). When set, the script warns if the current DB has grown
#   more than DB_GROWTH_THRESHOLD_PCT (default 50) beyond that baseline.
#   Left unset (the default), the check is skipped entirely.

set -e

# Configuration
SERVER_URL="${SERVER_URL:-http://localhost:8080}"
DB_PATH="${VAULTCRDT_DB_PATH:-./vaultcrdt.db}"
BACKUP_PATH="${BACKUP_PATH:-}"
MAX_DB_SIZE_MB="${MAX_DB_SIZE_MB:-1000}"
BACKUP_AGE_HOURS="${BACKUP_AGE_HOURS:-24}"
BASELINE_DB_SIZE_MB="${BASELINE_DB_SIZE_MB:-}"          # baseline for growth guard; unset = check off
DB_GROWTH_THRESHOLD_PCT="${DB_GROWTH_THRESHOLD_PCT:-50}" # warn if growth exceeds this %

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

failed=0

echo "=== VaultCRDT Server Health Check ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo

# 1. Check HTTP /health endpoint
echo -n "1. HTTP /health endpoint... "
if response=$(curl -s -w "\n%{http_code}" "$SERVER_URL/health" 2>/dev/null); then
    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | head -1)
    if [ "$http_code" = "200" ]; then
        echo -e "${GREEN}OK${NC}"
        echo "   Response: $body"
    else
        echo -e "${RED}FAILED${NC} (HTTP $http_code)"
        failed=$((failed + 1))
    fi
else
    echo -e "${RED}FAILED${NC} (connection error)"
    echo "   Make sure the server is running at $SERVER_URL"
    failed=$((failed + 1))
fi

# 2. Check database file exists
echo -n "2. Database file exists... "
if [ -f "$DB_PATH" ]; then
    echo -e "${GREEN}OK${NC} ($DB_PATH)"
else
    echo -e "${RED}FAILED${NC} (file not found)"
    echo "   Expected at: $DB_PATH"
    failed=$((failed + 1))
    exit 1
fi

# 3. Check database file is readable
echo -n "3. Database readable... "
if [ -r "$DB_PATH" ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC} (permission denied)"
    failed=$((failed + 1))
fi

# 4. Check database size
echo -n "4. Database size... "
db_size_bytes=$(stat -f%z "$DB_PATH" 2>/dev/null || stat -c%s "$DB_PATH" 2>/dev/null || echo "0")
db_size_mb=$((db_size_bytes / 1024 / 1024))
echo -e "${GREEN}OK${NC} ($db_size_mb MB)"

if [ "$db_size_mb" -gt "$MAX_DB_SIZE_MB" ]; then
    echo -e "   ${YELLOW}WARNING:${NC} Database is larger than ${MAX_DB_SIZE_MB}MB"
    echo "   Consider backing up and archiving old data"
    failed=$((failed + 1))
fi

# 5. Check backup timestamp (optional)
if [ -n "$BACKUP_PATH" ] && [ -f "$BACKUP_PATH" ]; then
    echo -n "5. Backup freshness... "
    if command -v stat &> /dev/null; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            backup_mtime=$(stat -f%m "$BACKUP_PATH")
        else
            # Linux
            backup_mtime=$(stat -c%Y "$BACKUP_PATH")
        fi
        current_time=$(date +%s)
        age_seconds=$((current_time - backup_mtime))
        age_hours=$((age_seconds / 3600))
        age_days=$((age_hours / 24))

        if [ "$age_hours" -le "$BACKUP_AGE_HOURS" ]; then
            echo -e "${GREEN}OK${NC} ($age_hours hours old)"
        else
            echo -e "${YELLOW}STALE${NC} ($age_hours hours old, expected <= $BACKUP_AGE_HOURS)"
            echo "   Last backup: $(date -r "$backup_mtime" '+%Y-%m-%d %H:%M:%S')"
            failed=$((failed + 1))
        fi
    else
        echo -e "${YELLOW}SKIP${NC} (stat command not available)"
    fi
elif [ -n "$BACKUP_PATH" ]; then
    echo -n "5. Backup file... "
    echo -e "${YELLOW}NOT FOUND${NC} ($BACKUP_PATH)"
    failed=$((failed + 1))
fi

# 6. Check database growth vs. baseline (optional, off unless BASELINE_DB_SIZE_MB is set)
if [ -n "$BASELINE_DB_SIZE_MB" ]; then
    echo -n "6. DB growth vs. baseline... "
    if ! [[ "$BASELINE_DB_SIZE_MB" =~ ^[0-9]+$ ]] || [ "$BASELINE_DB_SIZE_MB" -le 0 ]; then
        echo -e "${YELLOW}SKIP${NC} (BASELINE_DB_SIZE_MB must be a positive integer)"
    else
        # growth% = (current - baseline) * 100 / baseline
        growth_pct=$(( (db_size_mb - BASELINE_DB_SIZE_MB) * 100 / BASELINE_DB_SIZE_MB ))
        if [ "$growth_pct" -ge 0 ]; then growth_disp="+${growth_pct}"; else growth_disp="$growth_pct"; fi
        if [ "$growth_pct" -gt "$DB_GROWTH_THRESHOLD_PCT" ]; then
            echo -e "${YELLOW}WARNING${NC} (${growth_disp}% vs baseline ${BASELINE_DB_SIZE_MB}MB, threshold ${DB_GROWTH_THRESHOLD_PCT}%)"
            echo "   Current: ${db_size_mb}MB. Review churn / History-GC (see docs/ops-daily.md)."
            failed=$((failed + 1))
        else
            echo -e "${GREEN}OK${NC} (${growth_disp}% vs baseline ${BASELINE_DB_SIZE_MB}MB, threshold ${DB_GROWTH_THRESHOLD_PCT}%)"
        fi
    fi
fi

# Summary
echo
if [ $failed -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed${NC}"
    exit 0
else
    echo -e "${RED}✗ $failed check(s) failed${NC}"
    exit 1
fi
