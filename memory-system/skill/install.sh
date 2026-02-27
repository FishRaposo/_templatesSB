#!/bin/bash

# Memory System Skill Installer
# Usage: ./install.sh [destination]

DEST="${1:-memory-system-skill}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing Memory System Skill to $DEST..."

# Copy skill folder
cp -r "$SCRIPT_DIR" "$DEST"

echo "✅ Memory System Skill installed to $DEST/"
echo ""
echo "Next steps:"
echo "1. Point your AI agent at $DEST/SKILL.md"
echo "2. Say: 'Set up a memory system for this project'"
echo ""
echo "Skill includes:"
echo "- SKILL.md: Complete deployment instructions"
echo "- memory-system/templates/: All deployable files"
echo "- memory-system/_examples/: Worked example"
echo "- config.json: Skill triggers and configuration"
