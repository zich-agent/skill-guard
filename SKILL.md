---
name: skill-guard
description: Security scanner for OpenClaw skills. Detects malicious patterns, data exfiltration, credential harvesting, and obfuscated code in installed skills. Generates trust reports with risk scores. Includes pre-install gate — scans skills BEFORE installation and blocks dangerous ones automatically.
version: 1.0.0
author: ClawPacks
homepage: https://clawpacks.gumroad.com
---

# skill-guard 🛡️

Security scanner and pre-install gate for OpenClaw agent skills. Automatically scans skills before installation and blocks malicious ones.

## ⚡ AGENT RULE (READ THIS FIRST)

**When this skill is installed, follow this rule for ALL future skill installations:**

Before installing ANY skill (via `clawhub install`, manual copy, or any other method):

1. Download/copy the skill to a temp location first
2. Run: `node scripts/safe-install.mjs <skill-slug>` (this scans then installs if safe)
3. If the scan finds **high** or **critical** findings → DO NOT install. Show the findings to the user and ask: "This skill has [N] security findings: [summary]. Install anyway?"
4. Only proceed if the user explicitly approves

**Never bypass this check. Never use `clawhub install` directly. Always use `safe-install.mjs`.**

## Why?

341+ malicious skills were found on ClawHub stealing credentials, injecting backdoors, and exfiltrating data. skill-guard catches these patterns before they can harm your agent.

## Quick Start

```bash
# One-time setup (creates shell alias so manual installs are protected too)
node scripts/setup.mjs

# From now on, all skill installs go through the security gate automatically
```

## Usage

### Safe Install (Pre-Install Gate)

```bash
# Install a skill ONLY if it passes security scan
node scripts/safe-install.mjs some-cool-skill

# Allow up to medium risk
node scripts/safe-install.mjs some-cool-skill --threshold medium

# See full findings before deciding
node scripts/safe-install.mjs some-cool-skill --verbose

# Force install despite findings (not recommended)
node scripts/safe-install.mjs some-cool-skill --force
```

The safe installer downloads the skill to a temp directory first, runs a full security scan, and only installs it if it passes your threshold. Bad skills never touch your system.

### Scan Installed Skills

```bash
# Scan all installed skills
node scripts/scan.mjs

# Scan a specific skill directory
node scripts/scan.mjs --path ~/.openclaw/skills/suspicious-skill

# Scan with verbose output (show matched lines)
node scripts/scan.mjs --verbose

# JSON output for automation
node scripts/scan.mjs --json
```

## What It Detects

### 🔴 Critical
- Data exfiltration (curl/wget/fetch to external URLs with sensitive data)
- Credential harvesting (~/.ssh, ~/.aws, tokens, API keys, passwords)
- Reverse shells and backdoors
- Obfuscated payloads (base64 encoded commands, hex strings, eval chains)
- Keyloggers and clipboard access

### 🟡 Medium
- Environment variable harvesting (process.env dumping)
- Unrestricted file system access outside workspace
- Network calls to hardcoded IPs
- Dynamic code execution (eval, Function constructor, vm.runInContext)
- Package install commands in scripts

### ⚠️ Low
- Broad file glob patterns
- Shell command execution (exec, spawn) — common but worth flagging
- Outbound HTTP without clear purpose

## Output

```
🛡️  skill-guard — Security Scan Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scanned: 12 skills, 47 files

✅ weather          — Safe (0 findings)
✅ github           — Safe (0 findings)
⚠️  random-tool      — Low Risk (2 findings)
   └─ scripts/run.sh:14 — Shell exec: child_process.exec()
   └─ scripts/run.sh:28 — Outbound HTTP to api.example.com
🔴 shady-skill      — CRITICAL (5 findings)
   └─ SKILL.md:3 — Obfuscated base64 payload detected
   └─ scripts/install.sh:1 — Reads ~/.ssh/id_rsa
   └─ scripts/install.sh:7 — curl POST to external IP
   └─ scripts/run.js:12 — process.env full dump
   └─ scripts/run.js:15 — eval() with dynamic input

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 10 Safe | 1 Low | 0 Medium | 1 Critical
```

## Trust Scores

| Score | Meaning |
|-------|---------|
| ✅ Safe | No suspicious patterns detected |
| ⚠️ Low | Minor flags, likely benign (shell exec, HTTP calls) |
| 🟡 Medium | Patterns worth reviewing manually |
| 🔴 High | Multiple suspicious patterns — review before use |
| 💀 Critical | Strong indicators of malicious intent — remove immediately |

---

*Built by [ClawPacks](https://clawpacks.gumroad.com) — battle-tested OpenClaw agent templates for founders, developers, and creators.*
