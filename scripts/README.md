# Scripts

_Automation helpers for the unified memory system_

## Available Scripts

### Session End

**Purpose:** Automate the session-end workflow (L1-L3 updates)

**Bash:**
```bash
./scripts/session-end.sh "Description of work completed"
```

**PowerShell:**
```powershell
.\scripts\Session-End.ps1 "Description of work completed"
```

**What it does:**
1. Appends entry to CHANGELOG.md (L1)
2. Updates timestamp in graph.md (L2)
3. Regenerates context.md (L3)
4. Updates daily log if exists
5. Stages changes with git add

**After running:**
```bash
git commit -m "Session: Description of work"
git push origin main
```

---

### Memory Check

**Purpose:** Validate memory system health

**Bash:**
```bash
./scripts/memory-check.sh
```

**PowerShell:**
```powershell
.\scripts\Memory-Check.ps1
```

**What it checks:**
- L0: AGENTS.md exists and has key sections
- L1: CHANGELOG.md exists and has recent entries
- L2: graph.md exists and has timestamp
- L3: context.md exists and isn't stale
- L4: lessons/ directory exists
- .gitignore properly configured

**Output:**
- ✅ Pass / ⚠️ Warning / ❌ Error
- Summary with recommendations

**Run this:**
- Before starting a new session
- After a long break
- When something feels "off"

---

## Installation

Make scripts executable (Bash only):

```bash
chmod +x scripts/session-end.sh
chmod +x scripts/memory-check.sh
```

PowerShell scripts don't need special permissions.

---

## Integration

### Option 1: Manual (Recommended)

Run `session-end.sh` manually after each session.

### Option 2: Alias

Add to your shell config:

**Bash (.bashrc/.zshrc):**
```bash
alias end-session='~/openclaw-memories/scripts/session-end.sh'
alias check-memory='~/openclaw-memories/scripts/memory-check.sh'
```

**PowerShell ($PROFILE):**
```powershell
Set-Alias end-session "~\openclaw-memories\scripts\Session-End.ps1"
Set-Alias check-memory "~\openclaw-memories\scripts\Memory-Check.ps1"
```

### Option 3: Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
./scripts/memory-check.sh || exit 1
```

---

## Customization

Scripts are templates. Customize for your project:

- **session-end.sh**: Add project-specific steps
- **memory-check.sh**: Add project-specific validations
- Change paths, add checks, modify output format

---

## Troubleshooting

### "Permission denied" (Bash)

```bash
chmod +x scripts/*.sh
```

### "Execution Policy" (PowerShell)

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Script not found

Run from project root:
```bash
cd ~/openclaw-memories
./scripts/session-end.sh "..."
```

---

## Cross-Project

These scripts work across all three projects:
- openclaw-memories
- _templates
- kindred-ai

Copy scripts/ folder to each project and customize as needed.

---

*Automate the pain points, keep the system healthy* 🦀
