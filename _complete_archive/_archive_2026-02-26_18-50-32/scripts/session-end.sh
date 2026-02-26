#!/bin/bash
# session-end.sh — End session helper for unified memory system
# Usage: ./scripts/session-end.sh "Description of work completed"

set -e

DESCRIPTION="${1:-Session work}"
PROJECT_NAME=$(basename $(git rev-parse --show-toplevel 2>/dev/null || echo "unknown"))
TIMESTAMP=$(date '+%Y-%m-%d %H:%M')
DATE=$(date '+%Y-%m-%d')

echo "🦀 Ending session in $PROJECT_NAME"
echo "Description: $DESCRIPTION"
echo ""

# 1. Update CHANGELOG.md (L1)
echo "📝 Updating CHANGELOG.md..."

CHANGELOG_ENTRY="
## $TIMESTAMP — $DESCRIPTION

**Type:** session
**Scope:** agent

### What
$DESCRIPTION

### Changes
- Work completed during session

### Next Steps
- Continue as needed
"

# Prepend to CHANGELOG.md (after format section)
if [ -f CHANGELOG.md ]; then
    # Add entry after the first "---"
    sed -i '0,/---/{/---/a\
&CHANGELOG_ENTRY
}' CHANGELOG.md
fi

echo "✅ CHANGELOG.md updated"

# 2. Regenerate graph.md (L2)
echo "🔄 Regenerating .memory/graph.md..."

# Simple regeneration - scan current state
# (Projects can customize this)
if [ -f .memory/graph.md ]; then
    # Update timestamp
    sed -i "s/Last Updated:.*/Last Updated: $TIMESTAMP/" .memory/graph.md
fi

echo "✅ graph.md regenerated"

# 3. Regenerate context.md (L3)
echo "🔄 Regenerating .memory/context.md..."

# Get last 3 changelog entries for recent events
RECENT_EVENTS=$(grep "^## " CHANGELOG.md | head -5 | sed 's/^## /- /')

# Count pending tasks if task-queue exists
PENDING_TASKS="0"
if [ -d "agents/crabby/task-queue" ] && [ -f "agents/crabby/task-queue/queue.json" ]; then
    PENDING_TASKS=$(grep -c '"id"' agents/crabby/task-queue/queue.json 2>/dev/null || echo "0")
fi

cat > .memory/context.md << EOF
# Current Context

_Immediate trajectory and active work_

**Last Updated:** $TIMESTAMP
**Session:** $DESCRIPTION

## Session Summary

$DESCRIPTION

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
EOF

echo "✅ context.md regenerated"

# 4. Update daily log if exists
if [ -d "memory" ]; then
    DAILY_LOG="memory/$DATE.md"
    if [ -f "$DAILY_LOG" ]; then
        echo "" >> "$DAILY_LOG"
        echo "## $TIMESTAMP" >> "$DAILY_LOG"
        echo "" >> "$DAILY_LOG"
        echo "$DESCRIPTION" >> "$DAILY_LOG"
        echo "✅ Daily log updated: $DAILY_LOG"
    fi
fi

# 5. Git add and suggest commit
echo ""
echo "📦 Staging changes..."
git add -A
git status --short

echo ""
echo "💡 Suggested commit message:"
echo "  git commit -m \"Session: $DESCRIPTION\""
echo ""
echo "🦀 Session end complete!"
echo ""
echo "Next steps:"
echo "  1. Review staged changes"
echo "  2. Commit: git commit -m \"Session: $DESCRIPTION\""
echo "  3. Push: git push origin main"
