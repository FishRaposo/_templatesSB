# Memory System Setup Skill Installer (PowerShell)
# Usage: .\install.ps1 [destination]

param(
    [string]$Destination = "memory-system-setup"
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Installing Memory System Setup Skill to $Destination..."

# Copy skill folder
Copy-Item -Path "$ScriptDir\*" -Destination "$Destination\" -Recurse -Force

Write-Host "OK Memory System Setup Skill installed to $Destination\"
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Point your AI agent at $Destination\SKILL.md"
Write-Host "2. Say: 'Set up the memory system for this project'"
Write-Host ""
Write-Host "Skill includes:"
Write-Host "- SKILL.md: Complete deployment instructions"
Write-Host "- memory-system-setup/templates/: All deployable files"
Write-Host "- memory-system-setup/_examples/: Worked example"
Write-Host "- config.json: Skill triggers and configuration"
