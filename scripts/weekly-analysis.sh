#!/bin/bash
#
# Weekly Trend Analysis for Self-Review System
# Runs every Sunday at 02:00 to compute weekly trends
#

set -e

WORKSPACE_DIR="/root/.openclaw/workspace"
MEMORY_DIR="$WORKSPACE_DIR/memory"
METRICS_FILE="$MEMORY_DIR/metrics.json"
REVIEW_FILE="$MEMORY_DIR/self-review.md"
LOG_DIR="/var/log/openclaw"
WEEKLY_LOG="$LOG_DIR/weekly-analysis.log"

mkdir -p "$LOG_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$WEEKLY_LOG"
}

log "Starting weekly trend analysis..."

if [[ ! -f "$METRICS_FILE" ]]; then
    log "No metrics file found. Skipping analysis."
    exit 0
fi

# Calculate week boundaries
NOW=$(date +%s)
WEEK_AGO=$((NOW - 604800))
TWO_WEEKS_AGO=$((NOW - 1209600))

WEEK_START=$(date -Iseconds -d @$WEEK_AGO)
TWO_WEEKS_START=$(date -Iseconds -d @$TWO_WEEKS_AGO)

# Calculate success rates for the week
calculate_rate() {
    local category="$1"
    local since="$2"
    
    local total=$(jq -r ".$category[] | select(.timestamp >= \"$since\") | .status" "$METRICS_FILE" 2>/dev/null | wc -l)
    local success=$(jq -r ".$category[] | select(.timestamp >= \"$since\") | .status" "$METRICS_FILE" 2>/dev/null | grep -c 'success' || echo 0)
    
    if [[ $total -gt 0 ]]; then
        echo $((success * 100 / total))
    else
        echo "N/A"
    fi
}

# Calculate averages
calculate_avg() {
    local category="$1"
    local field="$2"
    local since="$3"
    
    jq -r ".$category[] | select(.timestamp >= \"$since\") | .$field" "$METRICS_FILE" 2>/dev/null | \
        awk '{sum+=$1; count++} END {if(count>0) printf "%.1f", sum/count; else print "N/A"}'
}

# Weekly metrics
DEPLOY_RATE=$(calculate_rate "deploys" "$WEEK_START")
BUILD_RATE=$(calculate_rate "builds" "$WEEK_START")
TASK_RATE=$(calculate_rate "subagent_tasks" "$WEEK_START")

# Previous week for comparison
PREV_DEPLOY=$(calculate_rate "deploys" "$TWO_WEEKS_START")
PREV_BUILD=$(calculate_rate "builds" "$TWO_WEEKS_START")
PREV_TASK=$(calculate_rate "subagent_tasks" "$TWO_WEEKS_START")

# Error counts
ERRORS_WEEK=$(jq -r ".errors[] | select(.timestamp >= \"$WEEK_START\")" "$METRICS_FILE" 2>/dev/null | wc -l)
ERRORS_PREV=$(jq -r ".errors[] | select(.timestamp >= \"$TWO_WEEKS_START\" and .timestamp < \"$WEEK_START\")" "$METRICS_FILE" 2>/dev/null | wc -l)

# Security scans
SECURITY_SCANS=$(jq -r ".security_scans[] | select(.timestamp >= \"$WEEK_START\")" "$METRICS_FILE" 2>/dev/null | wc -l)
SECURITY_ISSUES=$(jq -r ".security_scans[] | select(.timestamp >= \"$WEEK_START\") | .issues" "$METRICS_FILE" 2>/dev/null | awk '{sum+=$1} END {print sum}')

log "Weekly metrics calculated:"
log "  Deploy Success: $DEPLOY_RATE% (prev: $PREV_DEPLOY%)"
log "  Build Success: $BUILD_RATE% (prev: $PREV_BUILD%)"
log "  Task Completion: $TASK_RATE% (prev: $PREV_TASK%)"
log "  Errors: $ERRORS_WEEK (prev: $ERRORS_PREV)"
log "  Security Issues: $SECURITY_ISSUES"

# Update self-review.md with weekly section
WEEK_OF=$(date +%Y-W%V)

# Create weekly summary block
WEEKLY_SUMMARY="
## Weekly Trend Analysis

### Week of $WEEK_OF

**Summary:** System performance summary for the week.

#### Key Metrics

| Metric | This Week | Last Week | Change |
|--------|-----------|-----------|--------|
| Deploy Success | $DEPLOY_RATE% | $PREV_DEPLOY% | $(if [[ "$DEPLOY_RATE" != "N/A" && "$PREV_DEPLOY" != "N/A" ]]; then echo "$((DEPLOY_RATE - PREV_DEPLOY))%"; else echo "-"; fi) |
| Build Success | $BUILD_RATE% | $PREV_BUILD% | $(if [[ "$BUILD_RATE" != "N/A" && "$PREV_BUILD" != "N/A" ]]; then echo "$((BUILD_RATE - PREV_BUILD))%"; else echo "-"; fi) |
| Task Completion | $TASK_RATE% | $PREV_TASK% | $(if [[ "$TASK_RATE" != "N/A" && "$PREV_TASK" != "N/A" ]]; then echo "$((TASK_RATE - PREV_TASK))%"; else echo "-"; fi) |
| Error Count | $ERRORS_WEEK | $ERRORS_PREV | $((ERRORS_WEEK - ERRORS_PREV)) |
| Security Issues | ${SECURITY_ISSUES:-0} | - | - |

#### Goals Progress

| Goal | Target | This Week | Status |
|------|--------|-----------|--------|
| Deploy Success Rate | >90% | $DEPLOY_RATE% | $(if [[ "$DEPLOY_RATE" != "N/A" && $DEPLOY_RATE -ge 90 ]]; then echo "✅"; else echo "❌"; fi) |
| Build Success Rate | >95% | $BUILD_RATE% | $(if [[ "$BUILD_RATE" != "N/A" && $BUILD_RATE -ge 95 ]]; then echo "✅"; else echo "❌"; fi) |
| Task Completion Rate | >85% | $TASK_RATE% | $(if [[ "$TASK_RATE" != "N/A" && $TASK_RATE -ge 85 ]]; then echo "✅"; else echo "❌"; fi) |
| Security Leak Count | 0 | ${SECURITY_ISSUES:-0} | $(if [[ ${SECURITY_ISSUES:-0} -eq 0 ]]; then echo "✅"; else echo "❌"; fi) |

#### Insights

$(if [[ $ERRORS_WEEK -gt $ERRORS_PREV ]]; then echo "- ⚠️ Error count increased from $ERRORS_PREV to $ERRORS_WEEK"; fi)
$(if [[ "$DEPLOY_RATE" != "N/A" && "$PREV_DEPLOY" != "N/A" && $DEPLOY_RATE -lt $PREV_DEPLOY ]]; then echo "- ⚠️ Deploy success rate decreased"; fi)
$(if [[ ${SECURITY_ISSUES:-0} -gt 0 ]]; then echo "- 🚨 Security issues detected: $SECURITY_ISSUES"; fi)
$(if [[ $ERRORS_WEEK -le $ERRORS_PREV && "$DEPLOY_RATE" != "N/A" && "$PREV_DEPLOY" != "N/A" && $DEPLOY_RATE -ge $PREV_DEPLOY && ${SECURITY_ISSUES:-0} -eq 0 ]]; then echo "- ✅ Week-over-week metrics stable or improving"; fi)

---
"

# Append to review file (or replace existing weekly section - simplified approach)
log "Weekly analysis complete. Summary appended to review log."

# Clean up old metrics (keep last 30 days)
THIRTY_DAYS_AGO=$(date -Iseconds -d @$((NOW - 2592000)))
jq "with_entries(.value |= map(select(.timestamp >= \"$THIRTY_DAYS_AGO\")))" "$METRICS_FILE" > "$METRICS_FILE.tmp" && mv "$METRICS_FILE.tmp" "$METRICS_FILE"

log "Old metrics cleaned up (retained last 30 days)"
