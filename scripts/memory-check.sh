#!/bin/bash
# memory-check.sh — Validate memory system health
# Usage: ./scripts/memory-check.sh

echo "🦀 Memory System Health Check"
echo "=============================="
echo ""

ERRORS=0
WARNINGS=0

# Check L0: AGENTS.md
echo "📋 Checking L0 (AGENTS.md)..."
if [ -f AGENTS.md ]; then
    echo "  ✅ AGENTS.md exists"
    # Check for key sections
    if grep -q "Three Pillars" AGENTS.md; then
        echo "  ✅ Three Pillars section found"
    else
        echo "  ⚠️  Three Pillars section missing"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "  ❌ AGENTS.md missing!"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# Check L1: CHANGELOG.md
echo "📜 Checking L1 (CHANGELOG.md)..."
if [ -f CHANGELOG.md ]; then
    echo "  ✅ CHANGELOG.md exists"
    # Check for recent entries (within 7 days)
    RECENT=$(grep -c "$(date '+%Y-%m-%d' -d '7 days ago')\|$(date '+%Y-%m-%d' -d '6 days ago')\|$(date '+%Y-%m-%d' -d '5 days ago')\|$(date '+%Y-%m-%d' -d '4 days ago')\|$(date '+%Y-%m-%d' -d '3 days ago')\|$(date '+%Y-%m-%d' -d '2 days ago')\|$(date '+%Y-%m-%d' -d '1 day ago')\|$(date '+%Y-%m-%d')" CHANGELOG.md 2>/dev/null || echo "0")
    if [ "$RECENT" -gt 0 ]; then
        echo "  ✅ Recent entries found (within 7 days)"
    else
        echo "  ⚠️  No recent entries (stale?)"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "  ❌ CHANGELOG.md missing!"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# Check L2: .memory/graph.md
echo "🕸️  Checking L2 (.memory/graph.md)..."
if [ -f .memory/graph.md ]; then
    echo "  ✅ graph.md exists"
    # Check timestamp
    if grep -q "Last Updated:" .memory/graph.md; then
        echo "  ✅ Has timestamp"
    else
        echo "  ⚠️  No timestamp found"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "  ❌ .memory/graph.md missing!"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# Check L3: .memory/context.md
echo "📍 Checking L3 (.memory/context.md)..."
if [ -f .memory/context.md ]; then
    echo "  ✅ context.md exists"
    # Check if stale (older than 7 days)
    if [ -f .memory/context.md ]; then
        MTIME=$(stat -c %Y .memory/context.md 2>/dev/null || stat -f %m .memory/context.md 2>/dev/null || echo "0")
        NOW=$(date +%s)
        AGE=$(( (NOW - MTIME) / 86400 ))
        if [ $AGE -lt 7 ]; then
            echo "  ✅ Recently updated ($AGE days ago)"
        else
            echo "  ⚠️  Stale (last updated $AGE days ago)"
            WARNINGS=$((WARNINGS + 1))
        fi
    fi
else
    echo "  ❌ .memory/context.md missing!"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# Check L4: lessons/
echo "📚 Checking L4 (lessons/)..."
if [ -d lessons ]; then
    LESSON_COUNT=$(ls -1 lessons/*.md 2>/dev/null | wc -l)
    echo "  ✅ lessons/ directory exists ($LESSON_COUNT lessons)"
    if [ $LESSON_COUNT -eq 0 ]; then
        echo "  ⚠️  No lessons yet (write-only?)")
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "  ⚠️  lessons/ directory missing (optional)"
fi
echo ""

# Check .gitignore
echo "🛡️  Checking .gitignore..."
if [ -f .gitignore ]; then
    if grep -q "\.env" .gitignore; then
        echo "  ✅ .env files ignored"
    else
        echo "  ⚠️  .env not in .gitignore"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo "  ⚠️  .gitignore missing"
    WARNINGS=$((WARNINGS + 1))
fi
echo ""

# Summary
echo "=============================="
echo "📊 Summary"
echo "=============================="
if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo "✅ All checks passed! Memory system is healthy."
elif [ $ERRORS -eq 0 ]; then
    echo "⚠️  $WARNINGS warning(s). System functional but could be improved."
else
    echo "❌ $ERRORS error(s), $WARNINGS warning(s). System needs attention!"
fi
echo ""

if [ $ERRORS -gt 0 ] || [ $WARNINGS -gt 0 ]; then
    echo "💡 Recommendations:"
    if [ ! -f CHANGELOG.md ]; then
        echo "  - Create CHANGELOG.md: touch CHANGELOG.md"
    fi
    if [ ! -d .memory ]; then
        echo "  - Create .memory/: mkdir -p .memory"
    fi
    echo "  - Run session-end.sh after each session"
    echo "  - Review stale files and regenerate"
fi

echo ""
echo "🦀 Memory check complete!"
