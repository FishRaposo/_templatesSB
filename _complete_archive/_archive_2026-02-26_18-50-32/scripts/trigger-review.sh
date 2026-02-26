#!/bin/bash
#
# Manual trigger for self-review system
# Usage: ./trigger-review.sh [full|security|activity]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-full}"

case "$MODE" in
    full)
        echo "Running full self-review..."
        "$SCRIPT_DIR/self-review.sh"
        ;;
    security)
        echo "Running security scan only..."
        # Source the security scanning portion
        WORKSPACE_DIR="/root/.openclaw/workspace"
        MEMORY_DIR="$WORKSPACE_DIR/memory"
        
        # Run just the security patterns
        PATTERNS=(
            'api[_-]?key["\047]?\s*[:=]\s*["\047]?[a-zA-Z0-9]{16,}'
            'token["\047]?\s*[:=]\s*["\047]?[a-zA-Z0-9]{16,}'
            'secret["\047]?\s*[:=]\s*["\047]?[a-zA-Z0-9]{16,}'
            'BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY'
            'sk_live_[a-zA-Z0-9]{20,}'
            'AKIA[0-9A-Z]{16}'
        )
        
        EXCLUDE_ARGS="--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next --exclude-dir=dist --exclude-dir=build"
        
        echo "Scanning for sensitive patterns..."
        for pattern in "${PATTERNS[@]}"; do
            echo "Pattern: $pattern"
            grep -r -n -i -E "$pattern" $EXCLUDE_ARGS "$WORKSPACE_DIR" 2>/dev/null | head -5 || echo "  No matches"
        done
        ;;
    activity)
        echo "Showing recent activity summary..."
        MEMORY_DIR="/root/.openclaw/workspace/memory"
        RECENT_FILES=$(find "$MEMORY_DIR" -name "*.md" -mtime -0.1667 2>/dev/null || true)
        
        if [[ -n "$RECENT_FILES" ]]; then
            echo "Recent files (last 4h):"
            echo "$RECENT_FILES" | while read -r file; do
                echo "  - $file"
            done
            
            echo ""
            echo "Decisions: $(grep -h '\[decision\]' $RECENT_FILES 2>/dev/null | wc -l || echo 0)"
            echo "Blockers: $(grep -h '\[blocker\]' $RECENT_FILES 2>/dev/null | wc -l || echo 0)"
            echo "Errors: $(grep -h -i 'error\|fail\|exception' $RECENT_FILES 2>/dev/null | wc -l || echo 0)"
        else
            echo "No recent activity found."
        fi
        ;;
    *)
        echo "Usage: $0 [full|security|activity]"
        echo ""
        echo "Modes:"
        echo "  full     - Run complete self-review (default)"
        echo "  security - Run security scan only"
        echo "  activity - Show recent activity summary"
        exit 1
        ;;
esac
