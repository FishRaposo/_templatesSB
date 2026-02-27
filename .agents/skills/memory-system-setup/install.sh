#!/bin/bash

# Memory System Setup Skill Installer
# Usage: ./install.sh [destination]

DEST="${1:-memory-system-setup}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing Memory System Setup Skill to $DEST..."

# Copy skill folder
cp -r "$SCRIPT_DIR" "$DEST"

echo "OK Memory System Setup Skill installed to $DEST/"
echo ""
echo "Next steps:"
echo "1. Point your AI agent at $DEST/SKILL.md"
echo "2. Say: 'Set up the memory system for this project'"
echo ""
echo "Skill includes:"
echo "- SKILL.md: Complete deployment instructions"
echo "- memory-system-setup/templates/: All deployable files"
echo "- memory-system-setup/_examples/: Worked example"
echo "- config.json: Skill triggers and configuration"
