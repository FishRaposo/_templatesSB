#!/bin/bash
#
# Memory Maintenance System
# Manages tiered memory: active → archive → reference
#
# Tiers:
# - active/     - Current session context (7 days)
# - working/    - Recent work memory (30 days)
# - archive/    - Long-term storage (consultable, searchable)
# - reference/  - Permanent knowledge (decisions, patterns, lessons)
#

set -e

WORKSPACE_DIR="/root/.openclaw/workspace"
MEMORY_DIR="${WORKSPACE_DIR}/memory"
ARCHIVE_DIR="${MEMORY_DIR}/archive"
REFERENCE_DIR="${MEMORY_DIR}/reference"
ACTIVE_DIR="${MEMORY_DIR}/active"
WORKING_DIR="${MEMORY_DIR}/working"

TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
TODAY=$(date +"%Y-%m-%d")

# Retention policies (in days)
ACTIVE_DAYS=7
WORKING_DAYS=30
ARCHIVE_DAYS=365

log() { echo "[$(date '+%H:%M:%S')] $1"; }

# Ensure directory structure exists
init_structure() {
    mkdir -p "${ACTIVE_DIR}" "${WORKING_DIR}" "${ARCHIVE_DIR}"/"{daily,projects,summaries}" "${REFERENCE_DIR}"/"{decisions,patterns,lessons,projects}"
    log "Memory structure initialized"
}

# Move daily notes from root to appropriate tier
organize_daily_notes() {
    log "Organizing daily notes..."
    
    for file in "${MEMORY_DIR}"/*.md; do
        [ -f "$file" ] || continue
        filename=$(basename "$file")
        
        # Skip special files
        [[ "$filename" =~ ^(CURRENT|DECISIONS|SELF_REVIEW_SYSTEM|security-system|self-review)\.md$ ]] && continue
        
        # Extract date from filename (YYYY-MM-DD.md format)
        if [[ "$filename" =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})\.md$ ]]; then
            file_date="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]}"
            days_old=$(( ( $(date -d "$TODAY" +%s) - $(date -d "$file_date" +%s) ) / 86400 ))
            
            if [ $days_old -le $ACTIVE_DAYS ]; then
                # Keep in root (active)
                log "  $filename - active (day $days_old)"
            elif [ $days_old -le $WORKING_DAYS ]; then
                # Move to working/
                mv "$file" "${WORKING_DIR}/"
                log "  $filename → working/ (day $days_old)"
            else
                # Move to archive/daily/
                mv "$file" "${ARCHIVE_DIR}/daily/"
                log "  $filename → archive/daily/ (day $days_old)"
            fi
        fi
    done
}

# Summarize working memory into reference knowledge
summarize_working_memory() {
    log "Summarizing working memory..."
    
    # This would ideally use an LLM, but for now we'll create a placeholder
    # that can be enhanced later
    
    summary_file="${REFERENCE_DIR}/summaries/weekly-${TODAY}.md"
    
    cat > "$summary_file" << EOF
# Weekly Summary - ${TODAY}

**Generated:** ${TIMESTAMP}
**Period:** Last ${WORKING_DAYS} days

## Key Activities

EOF
    
    # List files in working directory
    if [ -d "${WORKING_DIR}" ] && [ "$(ls -A ${WORKING_DIR})" ]; then
        echo "### Working Memory Files" >> "$summary_file"
        ls -1 "${WORKING_DIR}"/*.md 2>/dev/null | while read f; do
            echo "- $(basename $f)" >> "$summary_file"
        done
        echo "" >> "$summary_file"
    fi
    
    log "  Summary created: $summary_file"
}

# Extract decisions and patterns to reference
extract_knowledge() {
    log "Extracting knowledge to reference..."
    
    # Copy DECISIONS.md to reference if it exists
    if [ -f "${MEMORY_DIR}/DECISIONS.md" ]; then
        cp "${MEMORY_DIR}/DECISIONS.md" "${REFERENCE_DIR}/decisions/all-decisions.md"
        log "  Decisions archived"
    fi
    
    # Copy project memories
    if [ -d "${MEMORY_DIR}/projects" ]; then
        cp -r "${MEMORY_DIR}/projects/"* "${REFERENCE_DIR}/projects/" 2>/dev/null || true
        log "  Projects archived"
    fi
}

# Clean up old archive files (keep summaries)
archive_cleanup() {
    log "Cleaning up old archives..."
    
    # Find files older than ARCHIVE_DAYS in archive/daily/
    find "${ARCHIVE_DIR}/daily" -name "*.md" -type f -mtime +${ARCHIVE_DAYS} 2>/dev/null | while read file; do
        # Instead of deleting, compress into yearly bundles
        year=$(basename "$file" | cut -d'-' -f1)
        mkdir -p "${ARCHIVE_DIR}/bundles/${year}"
        gzip -c "$file" > "${ARCHIVE_DIR}/bundles/${year}/$(basename $file).gz"
        rm "$file"
        log "  $(basename $file) → compressed bundle ${year}"
    done
}

# Generate maintenance report
generate_report() {
    report_file="${MEMORY_DIR}/.maintenance-report"
    
    cat > "$report_file" << EOF
# Memory Maintenance Report
**Run:** ${TIMESTAMP}

## Current State

| Tier | Location | Retention | File Count |
|------|----------|-----------|------------|
| Active | memory/ | ${ACTIVE_DAYS} days | $(ls -1 ${MEMORY_DIR}/*.md 2>/dev/null | wc -l) |
| Working | memory/working/ | ${WORKING_DAYS} days | $(ls -1 ${WORKING_DIR}/*.md 2>/dev/null | wc -l) |
| Archive | memory/archive/ | ${ARCHIVE_DAYS} days | $(find ${ARCHIVE_DIR} -name "*.md" 2>/dev/null | wc -l) |
| Reference | memory/reference/ | Permanent | $(find ${REFERENCE_DIR} -name "*.md" 2>/dev/null | wc -l) |

## Quick Stats

- Total daily notes: $(find ${MEMORY_DIR} -name "[0-9]*-[0-9]*-[0-9]*.md" 2>/dev/null | wc -l)
- Archive bundles: $(ls -1 ${ARCHIVE_DIR}/bundles 2>/dev/null | wc -l) years
- Reference summaries: $(ls -1 ${REFERENCE_DIR}/summaries 2>/dev/null | wc -l)

## Next Maintenance

Scheduled: $(date -d "+1 week" "+%Y-%m-%d")

EOF
    
    log "Report generated: $report_file"
}

# Main execution
main() {
    log "Starting memory maintenance..."
    
    init_structure
    organize_daily_notes
    summarize_working_memory
    extract_knowledge
    archive_cleanup
    generate_report
    
    log "Memory maintenance complete!"
}

# Run if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
