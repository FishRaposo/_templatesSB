#!/bin/bash
#
# Self-Review System for OpenClaw
# Runs every 4 hours to analyze system health and update self-review.md
#

set -e

# Configuration
WORKSPACE_DIR="/root/.openclaw/workspace"
MEMORY_DIR="$WORKSPACE_DIR/memory"
LOG_DIR="/var/log/openclaw"
REVIEW_FILE="$MEMORY_DIR/self-review.md"
METRICS_FILE="$MEMORY_DIR/metrics.json"
ALERT_LOG="$LOG_DIR/alerts.log"
REVIEW_LOG="$LOG_DIR/self-review.log"

# Time windows (in hours)
WINDOW_4H=4
WINDOW_24H=24
WINDOW_7D=168

# Ensure directories exist
mkdir -p "$MEMORY_DIR" "$LOG_DIR"

# Timestamp
TIMESTAMP=$(date '+%Y-%m-%d %H:%M')
TIMESTAMP_ISO=$(date -Iseconds)
CURRENT_HOUR=$(date +%H)

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$REVIEW_LOG"
}

# Alert function
alert() {
    local severity="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$severity] $message" | tee -a "$ALERT_LOG"
}

# Helper function to count successes in time window
count_success() {
    local category="$1"
    local since="$2"
    jq -r ".$category[] | select(.timestamp >= \"$since\") | .status" "$METRICS_FILE" 2>/dev/null | grep -c 'success' || echo 0
}

# Helper function to count total in time window
count_total() {
    local category="$1"
    local since="$2"
    jq -r ".$category[] | select(.timestamp >= \"$since\") | .status" "$METRICS_FILE" 2>/dev/null | wc -l
}

log "Starting self-review at $TIMESTAMP"

# ============================================================================
# METRICS COLLECTION
# ============================================================================

# Initialize metrics JSON if it doesn't exist
if [[ ! -f "$METRICS_FILE" ]]; then
    cat > "$METRICS_FILE" << 'EOF'
{
  "deploys": [],
  "builds": [],
  "subagent_tasks": [],
  "sessions": [],
  "errors": [],
  "security_scans": [],
  "last_updated": ""
}
EOF
fi

# Function to add metric
add_metric() {
    local category="$1"
    local status="$2"
    local duration="${3:-0}"
    local details="${4:-{}}"
    
    local entry=$(jq -n \
        --arg timestamp "$TIMESTAMP_ISO" \
        --arg status "$status" \
        --argjson duration "$duration" \
        --argjson details "$details" \
        '{timestamp: $timestamp, status: $status, duration: $duration, details: $details}')
    
    jq --argjson entry "$entry" ".$category += [$entry]" "$METRICS_FILE" > "$METRICS_FILE.tmp" && mv "$METRICS_FILE.tmp" "$METRICS_FILE"
}

# ============================================================================
# SECURITY & PRIVACY LEAK DETECTION
# ============================================================================

log "Running security scan..."

# Patterns to detect
PATTERNS=(
    'api[_-]?key["\047]?\s*[:=]\s*["\047]?[a-zA-Z0-9]{16,}'
    'apikey["\047]?\s*[:=]\s*["\047]?[a-zA-Z0-9]{16,}'
    'token["\047]?\s*[:=]\s*["\047]?[a-zA-Z0-9]{16,}'
    'secret["\047]?\s*[:=]\s*["\047]?[a-zA-Z0-9]{16,}'
    'password["\047]?\s*[:=]\s*["\047][^"\047]{4,}'
    'passwd["\047]?\s*[:=]\s*["\047][^"\047]{4,}'
    'bearer\s+[a-zA-Z0-9_\-\.]{20,}'
    'sk-[a-zA-Z0-9]{20,}'
    'sk_live_[a-zA-Z0-9]{20,}'
    'sk_test_[a-zA-Z0-9]{20,}'
    'ghp_[a-zA-Z0-9]{36}'
    'gho_[a-zA-Z0-9]{36}'
    'github[_-]?token'
    'BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY'
    'BEGIN\s+PGP\s+PRIVATE\s+KEY'
    '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    '\+?[1-9]\d{1,2}[\s\-\.]?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}'
    'mongodb(\+srv)?://[^:]+:[^@]+@'
    'postgres(ql)?://[^:]+:[^@]+@'
    'mysql://[^:]+:[^@]+@'
    'redis://:[^@]+@'
    'AKIA[0-9A-Z]{16}'
    'aws[_-]?secret[_-]?access[_-]?key'
)

# Files to scan
SCAN_DIRS=(
    "$WORKSPACE_DIR/memory"
    "$WORKSPACE_DIR"
)

EXCLUDE_ARGS="--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next --exclude-dir=dist --exclude-dir=build --exclude=*.log --exclude=*.lock --exclude=*.png --exclude=*.jpg --exclude=*.jpeg --exclude=*.gif --exclude=*.ico --exclude=*.svg --exclude=*.woff --exclude=*.woff2 --exclude=*.ttf --exclude=*.eot"

# Run security scan
SECURITY_ISSUES=""
for pattern in "${PATTERNS[@]}"; do
    matches=$(grep -r -n -i -E "$pattern" $EXCLUDE_ARGS "${SCAN_DIRS[@]}" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
        filtered=$(echo "$matches" | grep -v -E 'example\.(com|org)|test\.(com|org)|localhost|127\.0\.0\.1|0\.0\.0\.0|::1|@example\.|user@example|noreply@|no-reply@' || true)
        if [[ -n "$filtered" ]]; then
            SECURITY_ISSUES="$SECURITY_ISSUES
$filtered"
        fi
    fi
done

# Count issues by type - ensure single numeric output
API_KEY_COUNT=$(echo "$SECURITY_ISSUES" | grep -c -iE 'api[_-]?key|token|secret|bearer|sk-|ghp_|gho_' 2>/dev/null | tr -d '\n' || echo 0)
EMAIL_COUNT=$(echo "$SECURITY_ISSUES" | grep -c '@' 2>/dev/null | tr -d '\n' || echo 0)
PHONE_COUNT=$(echo "$SECURITY_ISSUES" | grep -c -E '\+?[0-9]{3}[-.\s]?[0-9]{3}' 2>/dev/null | tr -d '\n' || echo 0)
IP_COUNT=$(echo "$SECURITY_ISSUES" | grep -c -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' 2>/dev/null | tr -d '\n' || echo 0)
KEY_COUNT=$(echo "$SECURITY_ISSUES" | grep -c -i 'PRIVATE KEY' 2>/dev/null | tr -d '\n' || echo 0)
URL_PASS_COUNT=$(echo "$SECURITY_ISSUES" | grep -c -E '://[^:]+:[^@]+@' 2>/dev/null | tr -d '\n' || echo 0)

# Clean up any non-numeric characters and ensure defaults
API_KEY_COUNT=$(echo "${API_KEY_COUNT:-0}" | grep -oE '^[0-9]+' || echo 0)
EMAIL_COUNT=$(echo "${EMAIL_COUNT:-0}" | grep -oE '^[0-9]+' || echo 0)
PHONE_COUNT=$(echo "${PHONE_COUNT:-0}" | grep -oE '^[0-9]+' || echo 0)
IP_COUNT=$(echo "${IP_COUNT:-0}" | grep -oE '^[0-9]+' || echo 0)
KEY_COUNT=$(echo "${KEY_COUNT:-0}" | grep -oE '^[0-9]+' || echo 0)
URL_PASS_COUNT=$(echo "${URL_PASS_COUNT:-0}" | grep -oE '^[0-9]+' || echo 0)

TOTAL_ISSUES=$((API_KEY_COUNT + EMAIL_COUNT + PHONE_COUNT + IP_COUNT + KEY_COUNT + URL_PASS_COUNT))

log "Security scan complete. Found $TOTAL_ISSUES potential issues."

# Alert on security issues
if [[ $TOTAL_ISSUES -gt 0 ]]; then
    alert "CRITICAL" "Security scan detected $TOTAL_ISSUES potential leaks! Check self-review.md for details."
fi

# ============================================================================
# ANALYZE RECENT ACTIVITY
# ============================================================================

log "Analyzing recent activity..."

# Find recent memory files (last 4 hours)
RECENT_FILES=$(find "$MEMORY_DIR" -name "*.md" -mtime -0.1667 2>/dev/null || true)

# Count decisions, blockers, errors from recent files
DECISION_COUNT=0
BLOCKER_COUNT=0
ERROR_COUNT=0
TIMEOUT_COUNT=0
BUILD_FAIL_COUNT=0

if [[ -n "$RECENT_FILES" ]]; then
    DECISION_COUNT=$(grep -h '\[decision\]' $RECENT_FILES 2>/dev/null | wc -l || echo 0)
    BLOCKER_COUNT=$(grep -h '\[blocker\]' $RECENT_FILES 2>/dev/null | wc -l || echo 0)
    ERROR_COUNT=$(grep -h -i 'error\|fail\|exception' $RECENT_FILES 2>/dev/null | wc -l || echo 0)
    TIMEOUT_COUNT=$(grep -h -i 'timeout\|timed out' $RECENT_FILES 2>/dev/null | wc -l || echo 0)
    BUILD_FAIL_COUNT=$(grep -h -i 'build fail\|build error\|compilation error' $RECENT_FILES 2>/dev/null | wc -l || echo 0)
fi

log "Recent activity: $DECISION_COUNT decisions, $BLOCKER_COUNT blockers, $ERROR_COUNT errors"

# ============================================================================
# CALCULATE METRICS
# ============================================================================

DEPLOY_RATE_4H="-"

# Read existing metrics for trend calculation
if [[ -f "$METRICS_FILE" ]]; then
    NOW=$(date +%s)
    FOUR_HOURS_AGO=$((NOW - 14400))
    FOUR_HOURS_AGO_ISO=$(date -u +%Y-%m-%dT%H:%M:%S -d @$FOUR_HOURS_AGO 2>/dev/null || date -u -v-4H +%Y-%m-%dT%H:%M:%S 2>/dev/null || echo "")
    
    if [[ -n "$FOUR_HOURS_AGO_ISO" ]]; then
        DEPLOY_SUCCESS_4H=$(count_success "deploys" "$FOUR_HOURS_AGO_ISO")
        DEPLOY_TOTAL_4H=$(count_total "deploys" "$FOUR_HOURS_AGO_ISO")
        
        if [[ $DEPLOY_TOTAL_4H -gt 0 ]]; then
            DEPLOY_RATE_4H=$((DEPLOY_SUCCESS_4H * 100 / DEPLOY_TOTAL_4H))
        fi
    fi
fi

# ============================================================================
# UPDATE SELF-REVIEW.MD
# ============================================================================

log "Updating self-review.md..."

# Determine status indicators
if [[ $TOTAL_ISSUES -eq 0 ]]; then
    SECURITY_STATUS="✅ Clean"
else
    SECURITY_STATUS="❌ $TOTAL_ISSUES issues"
fi

if [[ $TOTAL_ISSUES -eq 0 ]]; then
    SECURITY_SCAN_STATUS="✅ No leaks detected"
else
    SECURITY_SCAN_STATUS="❌ $TOTAL_ISSUES potential leaks detected"
fi

if [[ $TOTAL_ISSUES -eq 0 ]]; then
    SECURITY_GOAL="✅"
else
    SECURITY_GOAL="❌"
fi

if [[ $TOTAL_ISSUES -eq 0 ]]; then
    SECURITY_SCORE="PASS"
else
    SECURITY_SCORE="FAIL"
fi

if [[ $ERROR_COUNT -eq 0 && $TOTAL_ISSUES -eq 0 ]]; then
    WEEKLY_SUMMARY="System healthy. No critical issues detected."
else
    WEEKLY_SUMMARY="Attention needed: $ERROR_COUNT errors, $TOTAL_ISSUES security issues."
fi

CRITICAL_COUNT=0
if [[ $TOTAL_ISSUES -gt 0 ]]; then
    CRITICAL_COUNT=1
fi
if [[ $BUILD_FAIL_COUNT -gt 2 ]]; then
    CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
fi
if [[ $BLOCKER_COUNT -gt 0 ]]; then
    CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
fi

# Build active issues table
ACTIVE_ISSUES=""
if [[ $BUILD_FAIL_COUNT -gt 0 ]]; then
    ACTIVE_ISSUES="${ACTIVE_ISSUES}| BUILD-$(date +%s) | $TIMESTAMP | Build failures detected ($BUILD_FAIL_COUNT) | high | investigating | Check build logs for details |\n"
fi
if [[ $TIMEOUT_COUNT -gt 0 ]]; then
    ACTIVE_ISSUES="${ACTIVE_ISSUES}| TOUT-$(date +%s) | $TIMESTAMP | Timeout issues ($TIMEOUT_COUNT) | medium | monitoring | Review timeout thresholds |\n"
fi
if [[ $BLOCKER_COUNT -gt 0 ]]; then
    ACTIVE_ISSUES="${ACTIVE_ISSUES}| BLK-$(date +%s) | $TIMESTAMP | Active blockers ($BLOCKER_COUNT) | high | in-progress | See CURRENT.md for details |\n"
fi
if [[ -z "$ACTIVE_ISSUES" ]]; then
    ACTIVE_ISSUES="| - | - | No active issues | - | - | - |\n"
fi

# Build recurring patterns table
RECURRING_PATTERNS=""
if [[ $BUILD_FAIL_COUNT -gt 1 ]]; then
    RECURRING_PATTERNS="${RECURRING_PATTERNS}| Build failures | $BUILD_FAIL_COUNT | $TIMESTAMP | Pre-flight checks |\n"
fi
if [[ $TIMEOUT_COUNT -gt 1 ]]; then
    RECURRING_PATTERNS="${RECURRING_PATTERNS}| Timeouts | $TIMEOUT_COUNT | $TIMESTAMP | Increase thresholds |\n"
fi
if [[ -z "$RECURRING_PATTERNS" ]]; then
    RECURRING_PATTERNS="| - | - | - | - |\n"
fi

# Severity indicators
if [[ $API_KEY_COUNT -gt 0 ]]; then
    API_SEVERITY="CRITICAL"
else
    API_SEVERITY="-"
fi
if [[ $EMAIL_COUNT -gt 0 ]]; then
    EMAIL_SEVERITY="HIGH"
else
    EMAIL_SEVERITY="-"
fi
if [[ $PHONE_COUNT -gt 0 ]]; then
    PHONE_SEVERITY="MEDIUM"
else
    PHONE_SEVERITY="-"
fi
if [[ $IP_COUNT -gt 0 ]]; then
    IP_SEVERITY="LOW"
else
    IP_SEVERITY="-"
fi
if [[ $KEY_COUNT -gt 0 ]]; then
    KEY_SEVERITY="CRITICAL"
else
    KEY_SEVERITY="-"
fi
if [[ $URL_PASS_COUNT -gt 0 ]]; then
    URL_SEVERITY="CRITICAL"
else
    URL_SEVERITY="-"
fi

# Create the updated content
cat > "$REVIEW_FILE" << EOF
# Self-Review System

> **Last Updated:** $TIMESTAMP  
> **Next Review:** $(date -d '+4 hours' '+%Y-%m-%d %H:%M' 2>/dev/null || date -v+4H '+%Y-%m-%d %H:%M' 2>/dev/null || echo "Next cycle")  
> **Review Interval:** Every 4 hours

---

## Overview

This document tracks system health, failure patterns, and success metrics for OpenClaw operations. It serves as both a diagnostic tool and a learning system for continuous improvement.

---

## Quick Status

| Metric | Status |
|--------|--------|
| Security Scan | $SECURITY_STATUS |
| Recent Errors | $ERROR_COUNT in last 4h |
| Active Blockers | $BLOCKER_COUNT |
| Recent Decisions | $DECISION_COUNT in last 4h |

---

## MISS/FIX Pattern Tracking

> **MISS:** What went wrong  
> **FIX:** Proposed or implemented fix  
> **Severity:** critical | high | medium | low

### Active Issues

| ID | Timestamp | MISS | Severity | FIX Status | FIX Description |
|----|-----------|------|----------|------------|-----------------|
$ACTIVE_ISSUES
### Resolved Issues (Last 7 Days)

| ID | Timestamp | MISS | Severity | Resolution | Date Resolved |
|----|-----------|------|----------|------------|---------------|
| - | - | No resolved issues | - | - | - |

### Recurring Patterns

| Pattern | Frequency | Last Occurrence | Mitigation |
|---------|-----------|-----------------|------------|
$RECURRING_PATTERNS
---

## Success Rate Metrics

### Deployment Metrics

| Metric | Last 4h | Last 24h | Last 7d | Goal | Trend |
|--------|---------|----------|---------|------|-------|
| Deploy Success Rate | $DEPLOY_RATE_4H | - | - | >90% | - |
| Build Success Rate | - | - | - | >95% | - |
| Rollback Rate | - | - | - | <5% | - |
| Avg Deploy Time | - | - | - | <5min | - |

### Sub-Agent Metrics

| Metric | Last 4h | Last 24h | Last 7d | Goal | Trend |
|--------|---------|----------|---------|------|-------|
| Task Completion Rate | - | - | - | >85% | - |
| Validation Pass Rate | - | - | - | >90% | - |
| Avg Task Duration | - | - | - | <10min | - |
| Timeout Rate | $TIMEOUT_COUNT | - | - | <5% | - |

### Session Health

| Metric | Last 4h | Last 24h | Last 7d | Goal | Trend |
|--------|---------|----------|---------|------|-------|
| Session Success Rate | - | - | - | >95% | - |
| Error Rate | $ERROR_COUNT | - | - | <2% | - |
| Recovery Rate | - | - | - | >80% | - |

---

## Security & Privacy Leak Detection

### Sensitive Pattern Scan Results

**Last Scan:** $TIMESTAMP  
**Status:** $SECURITY_SCAN_STATUS

| Pattern Type | Count | Locations | Severity |
|--------------|-------|-----------|----------|
| API Keys/Tokens | $API_KEY_COUNT | - | $API_SEVERITY |
| Email Addresses | $EMAIL_COUNT | - | $EMAIL_SEVERITY |
| Phone Numbers | $PHONE_COUNT | - | $PHONE_SEVERITY |
| IP Addresses | $IP_COUNT | - | $IP_SEVERITY |
| Private Keys | $KEY_COUNT | - | $KEY_SEVERITY |
| Passwords in URLs | $URL_PASS_COUNT | - | $URL_SEVERITY |

### Leak History

| Date | Pattern Found | Location | Action Taken |
|------|---------------|----------|--------------|
| - | - | - | - |

---

## Common Failure Modes

### Build Failures

| Type | Count (7d) | Last Occurrence | Root Cause | Prevention |
|------|------------|-----------------|------------|------------|
| Dependency resolution | 0 | - | - | - |
| Type errors | 0 | - | - | - |
| Missing env vars | 0 | - | - | - |
| Network timeouts | 0 | - | - | - |
| Build failures | $BUILD_FAIL_COUNT | $TIMESTAMP | TBD | Pre-flight checks |

### Timeout Patterns

| Type | Count (7d) | Last Occurrence | Avg Duration | Threshold |
|------|------------|-----------------|--------------|-----------|
| Sub-agent tasks | $TIMEOUT_COUNT | $TIMESTAMP | - | 10min |
| Deployments | 0 | - | - | 5min |
| External API calls | 0 | - | - | 30s |

### Authentication Issues

| Type | Count (7d) | Last Occurrence | Resolution |
|------|------------|-----------------|------------|
| Token expiry | 0 | - | - |
| Permission denied | 0 | - | - |
| Invalid credentials | 0 | - | - |

---

## Weekly Trend Analysis

### Week of $(date +%Y-W%V)

**Summary:** $WEEKLY_SUMMARY

#### Success Rate Trends
\`\`\`
Deploy Success:  []
Build Success:   []
Task Completion: []
\`\`\`

#### Error Frequency
\`\`\`
Critical: $(if [[ $TOTAL_ISSUES -gt 0 ]]; then echo "1"; else echo "0"; fi)
High:     $BUILD_FAIL_COUNT
Medium:   $TIMEOUT_COUNT
Low:      $ERROR_COUNT
\`\`\`

#### Fix Effectiveness
\`\`\`
Fixes Applied:   0
Fixes Verified:  0
Success Rate:    -
\`\`\`

---

## Goals & Targets

### Current Sprint Goals

| Goal | Target | Current | Status |
|------|--------|---------|--------|
| Deploy Success Rate | >90% | - | ⏳ |
| Build Success Rate | >95% | - | ⏳ |
| Task Completion Rate | >85% | - | ⏳ |
| Validation Pass Rate | >90% | - | ⏳ |
| Security Leak Count | 0 | $TOTAL_ISSUES | $SECURITY_GOAL |
| Avg Deploy Time | <5min | - | ⏳ |

### Historical Goal Progress

| Week | Deploy Success | Build Success | Task Completion | Security Score |
|------|----------------|---------------|-----------------|----------------|
| $(date +%Y-W%V) | - | - | - | $SECURITY_SCORE |

---

## Alert Thresholds

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| Deploy Success Rate | <85% | <75% | Review deploy pipeline |
| Build Success Rate | <90% | <80% | Check dependencies |
| Security Leak Detected | Any | - | Immediate review |
| Error Rate | >5% | >10% | Investigate logs |
| Timeout Rate | >10% | >20% | Adjust thresholds |

---

## Review Log

| Timestamp | Reviewer | Summary | Critical Issues |
|-----------|----------|---------|-----------------|
| $TIMESTAMP | system | Auto-review completed | $TOTAL_ISSUES |

---

## Notes

- This file is auto-updated every 4 hours by \`/root/.openclaw/workspace/scripts/self-review.sh\`
- Critical issues trigger immediate alerts
- Weekly trends are computed every Sunday at 02:00
- All timestamps are in Asia/Shanghai timezone unless noted
EOF

# Update metrics file timestamp
jq --arg timestamp "$TIMESTAMP_ISO" '.last_updated = $timestamp' "$METRICS_FILE" > "$METRICS_FILE.tmp" && mv "$METRICS_FILE.tmp" "$METRICS_FILE"

# ============================================================================
# CRITICAL ISSUE ALERTS
# ============================================================================

# Check for critical conditions
if [[ $TOTAL_ISSUES -gt 0 ]]; then
    alert "CRITICAL" "Security scan found $TOTAL_ISSUES potential data leaks"
fi

if [[ $BUILD_FAIL_COUNT -gt 2 ]]; then
    alert "HIGH" "Multiple build failures detected ($BUILD_FAIL_COUNT in last 4h)"
fi

if [[ $BLOCKER_COUNT -gt 0 ]]; then
    alert "HIGH" "Active blockers require attention ($BLOCKER_COUNT)"
fi

# ============================================================================
# SUMMARY
# ============================================================================

log "Self-review complete at $(date '+%Y-%m-%d %H:%M:%S')"
log "Summary: $ERROR_COUNT errors, $TOTAL_ISSUES security issues, $CRITICAL_COUNT critical alerts"

if [[ $CRITICAL_COUNT -gt 0 ]]; then
    log "⚠️  $CRITICAL_COUNT critical issues require attention"
    exit 1
else
    log "✅ All systems nominal"
    exit 0
fi
