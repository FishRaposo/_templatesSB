# Session-End.ps1 — End session helper for unified memory system (PowerShell)
# Usage: .\scripts\Session-End.ps1 "Description of work completed"

param(
    [string]$Description = "Session work"
)

$ErrorActionPreference = "Stop"

$TIMESTAMP = Get-Date -Format "yyyy-MM-dd HH:mm"
$DATE = Get-Date -Format "yyyy-MM-dd"
$PROJECT_NAME = Split-Path (git rev-parse --show-toplevel 2>$null) -Leaf
if (-not $PROJECT_NAME) { $PROJECT_NAME = "unknown" }

Write-Host "🦀 Ending session in $PROJECT_NAME"
Write-Host "Description: $Description"
Write-Host ""

# 1. Update CHANGELOG.md (L1)
Write-Host "📝 Updating CHANGELOG.md..."

$CHANGELOG_ENTRY = @"

## $TIMESTAMP — $Description

**Type:** session
**Scope:** agent

### What
$Description

### Changes
- Work completed during session

### Next Steps
- Continue as needed

---
"@

if (Test-Path CHANGELOG.md) {
    # Read current content
    $content = Get-Content CHANGELOG.md -Raw
    # Find first "---" and insert after it
    $parts = $content -split "(^---\r?\n)", 2, "RegexMatch"
    if ($parts.Count -ge 2) {
        $newContent = $parts[0] + $parts[1] + $CHANGELOG_ENTRY + ($parts[2] -replace "^---\r?\n", "")
        $newContent | Set-Content CHANGELOG.md -NoNewline
    }
}

Write-Host "✅ CHANGELOG.md updated"

# 2. Update graph.md timestamp (L2)
Write-Host "🔄 Updating .memory/graph.md..."
if (Test-Path .memory/graph.md) {
    (Get-Content .memory/graph.md) -replace "Last Updated:.*", "Last Updated: $TIMESTAMP" | Set-Content .memory/graph.md
}
Write-Host "✅ graph.md updated"

# 3. Regenerate context.md (L3)
Write-Host "🔄 Regenerating .memory/context.md..."

$RECENT_EVENTS = ""
if (Test-Path CHANGELOG.md) {
    $RECENT_EVENTS = (Get-Content CHANGELOG.md | Select-String "^## " | Select-Object -First 5 | ForEach-Object { "- " + $_ }) -join "`n"
}

$PENDING_TASKS = "0"
if (Test-Path "agents/crabby/task-queue/queue.json") {
    $queue = Get-Content "agents/crabby/task-queue/queue.json" | ConvertFrom-Json
    $PENDING_TASKS = $queue.queue.Count
}

$CONTEXT_CONTENT = @"
# Current Context

_Immediate trajectory and active work_

**Last Updated:** $TIMESTAMP
**Session:** $Description

## Session Summary

$Description

## Active Work

- [ ] Pending tasks: $PENDING_TASKS
- [ ] Last session completed

## Recent Events (from CHANGELOG)

$RECENT_EVENTS

## Blockers

None currently.

## Next Actions

1. Review recent changes
2. Continue with pending work
3. Update lessons/ if patterns learned

---

*Regenerate: Every session*
"@

$CONTEXT_CONTENT | Set-Content .memory/context.md
Write-Host "✅ context.md regenerated"

# 4. Update daily log if exists
$DAILY_LOG = "memory/$DATE.md"
if (Test-Path $DAILY_LOG) {
    Add-Content $DAILY_LOG ""
    Add-Content $DAILY_LOG "## $TIMESTAMP"
    Add-Content $DAILY_LOG ""
    Add-Content $DAILY_LOG $Description
    Write-Host "✅ Daily log updated: $DAILY_LOG"
}

# 5. Git add and suggest commit
Write-Host ""
Write-Host "📦 Staging changes..."
git add -A
git status --short

Write-Host ""
Write-Host "💡 Suggested commit message:"
Write-Host "  git commit -m `"Session: $Description`""
Write-Host ""
Write-Host "🦀 Session end complete!"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Review staged changes"
Write-Host "  2. Commit: git commit -m `"Session: $Description`""
Write-Host "  3. Push: git push origin main"
