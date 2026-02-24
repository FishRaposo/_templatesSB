# Memory-Check.ps1 — Validate memory system health (PowerShell)
# Usage: .\scripts\Memory-Check.ps1

Write-Host "🦀 Memory System Health Check"
Write-Host "=============================="
Write-Host ""

$ERRORS = 0
$WARNINGS = 0

# Check L0: AGENTS.md
Write-Host "📋 Checking L0 (AGENTS.md)..."
if (Test-Path AGENTS.md) {
    Write-Host "  ✅ AGENTS.md exists"
    if (Select-String -Path AGENTS.md -Pattern "Three Pillars" -Quiet) {
        Write-Host "  ✅ Three Pillars section found"
    } else {
        Write-Host "  ⚠️  Three Pillars section missing"
        $WARNINGS++
    }
} else {
    Write-Host "  ❌ AGENTS.md missing!"
    $ERRORS++
}
Write-Host ""

# Check L1: CHANGELOG.md
Write-Host "📜 Checking L1 (CHANGELOG.md)..."
if (Test-Path CHANGELOG.md) {
    Write-Host "  ✅ CHANGELOG.md exists"
    $RECENT = Select-String -Path CHANGELOG.md -Pattern (Get-Date -Format "yyyy-MM-dd") -Quiet
    if ($RECENT) {
        Write-Host "  ✅ Recent entries found"
    } else {
        Write-Host "  ⚠️  No recent entries (stale?)"
        $WARNINGS++
    }
} else {
    Write-Host "  ❌ CHANGELOG.md missing!"
    $ERRORS++
}
Write-Host ""

# Check L2: graph.md
Write-Host "🕸️  Checking L2 (.memory/graph.md)..."
if (Test-Path .memory/graph.md) {
    Write-Host "  ✅ graph.md exists"
    if (Select-String -Path .memory/graph.md -Pattern "Last Updated:" -Quiet) {
        Write-Host "  ✅ Has timestamp"
    } else {
        Write-Host "  ⚠️  No timestamp found"
        $WARNINGS++
    }
} else {
    Write-Host "  ❌ .memory/graph.md missing!"
    $ERRORS++
}
Write-Host ""

# Check L3: context.md
Write-Host "📍 Checking L3 (.memory/context.md)..."
if (Test-Path .memory/context.md) {
    Write-Host "  ✅ context.md exists"
    $MTIME = (Get-Item .memory/context.md).LastWriteTime
    $AGE = ((Get-Date) - $MTIME).Days
    if ($AGE -lt 7) {
        Write-Host "  ✅ Recently updated ($AGE days ago)"
    } else {
        Write-Host "  ⚠️  Stale (last updated $AGE days ago)"
        $WARNINGS++
    }
} else {
    Write-Host "  ❌ .memory/context.md missing!"
    $ERRORS++
}
Write-Host ""

# Check L4: lessons/
Write-Host "📚 Checking L4 (lessons/)..."
if (Test-Path lessons) {
    $LESSON_COUNT = (Get-ChildItem lessons/*.md -ErrorAction SilentlyContinue).Count
    Write-Host "  ✅ lessons/ directory exists ($LESSON_COUNT lessons)"
    if ($LESSON_COUNT -eq 0) {
        Write-Host "  ⚠️  No lessons yet (write-only?)"
        $WARNINGS++
    }
} else {
    Write-Host "  ⚠️  lessons/ directory missing (optional)"
}
Write-Host ""

# Check .gitignore
Write-Host "🛡️  Checking .gitignore..."
if (Test-Path .gitignore) {
    if (Select-String -Path .gitignore -Pattern "\.env" -Quiet) {
        Write-Host "  ✅ .env files ignored"
    } else {
        Write-Host "  ⚠️  .env not in .gitignore"
        $WARNINGS++
    }
} else {
    Write-Host "  ⚠️  .gitignore missing"
    $WARNINGS++
}
Write-Host ""

# Summary
Write-Host "=============================="
Write-Host "📊 Summary"
Write-Host "=============================="
if ($ERRORS -eq 0 -and $WARNINGS -eq 0) {
    Write-Host "✅ All checks passed! Memory system is healthy."
} elseif ($ERRORS -eq 0) {
    Write-Host "⚠️  $WARNINGS warning(s). System functional but could be improved."
} else {
    Write-Host "❌ $ERRORS error(s), $WARNINGS warning(s). System needs attention!"
}
Write-Host ""

if ($ERRORS -gt 0 -or $WARNINGS -gt 0) {
    Write-Host "💡 Recommendations:"
    if (-not (Test-Path CHANGELOG.md)) {
        Write-Host "  - Create CHANGELOG.md: New-Item CHANGELOG.md"
    }
    if (-not (Test-Path .memory)) {
        Write-Host "  - Create .memory/: New-Item -ItemType Directory .memory"
    }
    Write-Host "  - Run Session-End.ps1 after each session"
    Write-Host "  - Review stale files and regenerate"
}

Write-Host ""
Write-Host "🦀 Memory check complete!"
