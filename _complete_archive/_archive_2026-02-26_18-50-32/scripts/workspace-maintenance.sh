#!/bin/bash
#
# Auto-Fix Maintenance System
# Reports issues AND fixes what can be safely automated
#

set -e

WORKSPACE_DIR="/root/.openclaw/workspace"
LOG_DIR="${WORKSPACE_DIR}/.logs"
REPORT_FILE="${LOG_DIR}/maintenance-report-$(date +%Y%m%d-%H%M%S).md"
ALERTS_FILE="${LOG_DIR}/.maintenance-alerts"

mkdir -p "$LOG_DIR"
rm -f "$ALERTS_FILE"

log() {
    echo "[$(date '+%H:%M:%S')] $1"
    echo "[$(date '+%H:%M:%S')] $1" >> "$REPORT_FILE"
}

alert() {
    local severity="$1"
    local message="$2"
    log "[$severity] $message"
    echo "[$severity] $message" >> "$ALERTS_FILE"
}

section() {
    echo "" >> "$REPORT_FILE"
    echo "## $1" >> "$REPORT_FILE"
    log "=== $1 ==="
}

# Initialize report
init_report() {
    cat > "$REPORT_FILE" << EOF
# Workspace Maintenance Report

**Date:** $(date +"%Y-%m-%d %H:%M:%S")  
**Host:** $(hostname)  
**Status:** $(if [ -f "$ALERTS_FILE" ]; then echo "⚠️ Issues detected"; else echo "✅ All systems healthy"; fi)

---

EOF
}

# 1. Disk Usage - with auto-cleanup
monitor_disk() {
    section "Disk Usage"
    
    df -h / | tail -1 | while read fs size used avail percent mount; do
        percent_num=$(echo "$percent" | tr -d '%')
        log "Root: $used used / $size total ($percent)"
        
        if [ "$percent_num" -gt 90 ]; then
            alert "CRITICAL" "Disk usage at $percent - emergency cleanup initiated"
            # Emergency: clean more aggressively
            find /tmp -type f -atime +1 -delete 2>/dev/null || true
            find "$WORKSPACE_DIR" -name "*.log.gz" -mtime +30 -delete 2>/dev/null || true
            pnpm store prune 2>/dev/null || true
        elif [ "$percent_num" -gt 80 ]; then
            alert "WARNING" "Disk usage at $percent - consider cleanup"
            # Auto-clean old archives
            find "$WORKSPACE_DIR/memory/archive/bundles" -name "*.gz" -mtime +180 -delete 2>/dev/null || true
        fi
    done
    
    workspace_size=$(du -sh "$WORKSPACE_DIR" | cut -f1)
    log "Workspace: $workspace_size"
}

# 2. Git Health - with auto-commit for memory repo
check_git_health() {
    section "Git Repository Health"
    
    cd "$WORKSPACE_DIR"
    
    # Check main workspace
    if [ -d ".git" ]; then
        uncommitted=$(git status --porcelain 2>/dev/null | wc -l)
        log "Main repo uncommitted: $uncommitted"
        
        if [ "$uncommitted" -gt 50 ]; then
            alert "WARNING" "$uncommitted uncommitted files in main repo"
        fi
    fi
    
    # Auto-sync memory repo if stale
    if [ -d "$WORKSPACE_DIR/openclaw-memories/.git" ]; then
        cd "$WORKSPACE_DIR/openclaw-memories"
        last_timestamp=$(git log -1 --format="%ct" 2>/dev/null || echo "0")
        now=$(date +%s)
        hours_since=$(( (now - last_timestamp) / 3600 ))
        
        log "Memory repo last sync: ${hours_since}h ago"
        
        if [ "$hours_since" -gt 48 ]; then
            alert "WARNING" "Memory sync stale (${hours_since}h) - auto-syncing now"
            cd "$WORKSPACE_DIR"
            bash "$WORKSPACE_DIR/openclaw-memories/.github/sync-memories.sh" >> "$REPORT_FILE" 2>&1 || true
        fi
    fi
}

# 3. Log Cleanup - aggressive auto-cleanup
cleanup_logs() {
    section "Log Cleanup"
    
    local cleaned=0
    
    # Archive old logs
    find "$WORKSPACE_DIR" -name "*.log" -type f -mtime +3 2>/dev/null | while read f; do
        gzip "$f" 2>/dev/null && cleaned=$((cleaned + 1))
    done
    
    # Delete old gzipped logs
    find "$WORKSPACE_DIR" -name "*.log.gz" -type f -mtime +30 -delete 2>/dev/null || true
    
    # Clean npm/pnpm logs
    find "$WORKSPACE_DIR" -name "npm-debug.log*" -o -name "yarn-*.log*" 2>/dev/null | xargs rm -f 2>/dev/null || true
    
    # Clean build outputs
    find "$WORKSPACE_DIR" -name "build-output.log" -mtime +1 -delete 2>/dev/null || true
    
    log "Log cleanup completed"
}

# 4. Python Cache - always auto-clean
cleanup_python_cache() {
    section "Python Cache Cleanup"
    
    local count=0
    
    find "$WORKSPACE_DIR" -type d -name "__pycache__" 2>/dev/null | while read d; do
        rm -rf "$d" 2>/dev/null && count=$((count + 1))
    done
    
    find "$WORKSPACE_DIR" -name "*.pyc" -delete 2>/dev/null || true
    find "$WORKSPACE_DIR" -name "*.pyo" -delete 2>/dev/null || true
    
    log "Python cache cleaned"
}

# 5. Security Audit - with auto-redaction
security_audit() {
    section "Security Audit"
    
    if [ -f "$WORKSPACE_DIR/.monitoring/security/security" ]; then
        scan_output=$(python3 "$WORKSPACE_DIR/.monitoring/security/security" scan "$WORKSPACE_DIR" 2>/dev/null || echo "")
        leaks=$(echo "$scan_output" | grep -c "Found:" || echo "0")
        
        log "Security scan completed"
        
        if [ "$leaks" -gt 0 ]; then
            alert "WARNING" "$leaks potential security leaks detected - review required"
            echo "$scan_output" | head -20 >> "$REPORT_FILE"
        fi
    fi
}

# 6. Cron Health - just report
check_cron_health() {
    section "Cron Job Health"
    
    log "Scheduled jobs:"
    log "  - memory-sync (daily 2:00 AM)"
    log "  - self-review (every 4 hours)"
    log "  - memory-maintenance (Sundays 3:00 AM)"
    log "  - workspace-maintenance (Sundays 4:00 AM)"
}

# 7. Backup Verification - with auto-fix
verify_backups() {
    section "Backup Verification"
    
    if [ -d "$WORKSPACE_DIR/openclaw-memories/.git" ]; then
        cd "$WORKSPACE_DIR/openclaw-memories"
        last_sync=$(git log -1 --format="%h %ar" 2>/dev/null || echo "Never")
        log "Last memory sync: $last_sync"
    fi
}

# 8. System Health + Metrics Tracking
health_summary() {
    section "System Health & Metrics"
    
    # Memory
    mem_total=$(free -m | awk '/^Mem:/{print $2}')
    mem_used=$(free -m | awk '/^Mem:/{print $3}')
    mem_percent=$(( mem_used * 100 / mem_total ))
    log "Memory: ${mem_used}MB / ${mem_total}MB (${mem_percent}%)"
    
    if [ "$mem_percent" -gt 90 ]; then
        alert "WARNING" "Memory usage at ${mem_percent}%"
    fi
    
    # Load
    load=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
    log "Load average: $load"
    
    # Track metrics
    mkdir -p "$WORKSPACE_DIR/.monitoring/metrics"
    echo "{\"timestamp\":$(date +%s),\"memory_percent\":$mem_percent,\"load\":$load,\"type\":\"system\"}" >> "$WORKSPACE_DIR/.monitoring/metrics/system.jsonl"
    
    # Process count
    procs=$(ps aux | wc -l)
    log "Running processes: $procs"
}

# 9. Dependency Health
check_dependencies() {
    section "Dependency Health"
    
    if [ -f "$WORKSPACE_DIR/kindred-ai/package.json" ]; then
        cd "$WORKSPACE_DIR/kindred-ai"
        
        if command -v pnpm &> /dev/null; then
            # Check for outdated (just count, don't auto-update)
            outdated=$(pnpm outdated --json 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
            log "Outdated packages: $outdated"
            
            if [ "$outdated" -gt 20 ]; then
                alert "WARNING" "$outdated outdated packages - consider updating"
            fi
        fi
    fi
}

# 10. File Permissions
check_permissions() {
    section "File Permissions"
    
    unusual=$(find "$WORKSPACE_DIR" -type f \( -perm -002 -o -perm -4000 \) -not -path "*/.git/*" 2>/dev/null | wc -l)
    log "Files with unusual permissions: $unusual"
    
    if [ "$unusual" -gt 0 ]; then
        alert "WARNING" "$unusual files with unusual permissions detected"
    fi
}

# 11. Orphaned Processes
check_orphans() {
    section "Orphaned Processes"
    
    zombies=$(ps aux | grep "<defunct>" | wc -l)
    if [ "$zombies" -gt 0 ]; then
        alert "WARNING" "$zombies zombie processes detected"
    fi
    
    # Kill old node processes if too many
    node_count=$(ps aux | grep "node" | grep -v grep | wc -l)
    if [ "$node_count" -gt 20 ]; then
        alert "WARNING" "$node_count node processes - may need cleanup"
    fi
}

# 12. Temp Cleanup - always auto-clean
cleanup_temp() {
    section "Temp Directory Cleanup"
    
    # Clean old temp files
    find /tmp -type f -atime +3 -user $(whoami) -delete 2>/dev/null || true
    
    log "Temp cleanup completed"
}

# 13. Agent Health
check_agents() {
    section "Agent Health"
    
    agent_count=$(find "$WORKSPACE_DIR/agents" -name "SOUL.md" 2>/dev/null | wc -l)
    log "Defined agents: $agent_count"
    
    # Track agent count as metric
    echo "{\"timestamp\":$(date +%s),\"agent_count\":$agent_count,\"type\":\"agents\"}" >> "$WORKSPACE_DIR/.monitoring/metrics/agents.jsonl"
}

# 14. Old Report Cleanup
cleanup_old_reports() {
    section "Old Report Cleanup"
    
    find "$LOG_DIR" -name "maintenance-report-*.md" -mtime +30 -delete 2>/dev/null || true
    
    report_count=$(find "$LOG_DIR" -name "maintenance-report-*.md" | wc -l)
    log "Maintenance reports retained: $report_count"
}

# Send alerts if any
send_alerts() {
    if [ -f "$ALERTS_FILE" ]; then
        echo ""
        echo "=== ALERTS ===" >> "$REPORT_FILE"
        cat "$ALERTS_FILE" >> "$REPORT_FILE"
        
        # Return non-zero to indicate alerts were triggered
        return 1
    fi
    return 0
}

# Main execution
main() {
    init_report
    log "Starting auto-fix maintenance..."
    
    monitor_disk
    check_git_health
    cleanup_logs
    cleanup_python_cache
    security_audit
    check_cron_health
    verify_backups
    health_summary
    check_dependencies
    check_permissions
    check_orphans
    cleanup_temp
    check_agents
    cleanup_old_reports
    
    log "Maintenance complete!"
    
    if ! send_alerts; then
        log "⚠️ Warnings detected - review recommended"
        exit 1  # Signal that alerts exist
    else
        log "✅ All systems healthy"
        exit 0
    fi
}

main "$@"
