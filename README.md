# 🛡️ skill-guard

**Security scanner & pre-install gate for OpenClaw skills**

Stop malicious skills before they touch your system.

[![OpenClaw](https://img.shields.io/badge/OpenClaw-skill-blue)](https://openclaw.ai)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## The Problem

Not every skill on ClawHub is safe. Some contain:

- 🔓 Credential harvesting (`~/.ssh`, `~/.aws`, API keys)
- 📡 Data exfiltration (sending your secrets to external servers)
- 🚪 Reverse shells and backdoors
- 🎭 Obfuscated payloads (base64-encoded commands, eval chains)

**skill-guard** scans skills _before_ installation and blocks anything suspicious.

---

## Quick Start

```bash
# Install skill-guard
clawhub install skill-guard

# Set up the automatic gate (one-time)
node skills/skill-guard/scripts/setup.mjs

# Done. Every future install is now protected.
```

---

## How It Works

```
  clawhub install foo
         │
         ▼
  ┌──────────────┐
  │ Download to  │
  │  temp dir    │
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐
  │  Scan for    │
  │ 50+ patterns │
  └──────┬───────┘
         │
         ▼
      Safe?
      /    \
    Yes     No
     │       │
     ▼       ▼
  Install   Block +
  to        show
  skills/   findings
```

The skill never reaches your system unless it passes.

---

## Usage

### Safe Install (recommended)

```bash
# Install only if the skill passes security scan
node skills/skill-guard/scripts/safe-install.mjs weather
```

**Example output — safe skill:**

```
🛡️  skill-guard — Pre-Install Security Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📦 Downloading weather to temp directory...
🔍 Scanning for malicious patterns...

✅ weather — Safe (0 findings)

📥 Installing weather...
Done! Skill installed safely.
```

### Blocking a dangerous skill

```bash
node skills/skill-guard/scripts/safe-install.mjs shady-skill
```

**Example output — blocked skill:**

```
🛡️  skill-guard — Pre-Install Security Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📦 Downloading shady-skill to temp directory...
🔍 Scanning for malicious patterns...

💀 shady-skill — CRITICAL (5 findings)

   scripts/install.sh:1  — Reads ~/.ssh/id_rsa
   scripts/install.sh:7  — curl POST to external IP
   scripts/run.js:12     — process.env full dump
   scripts/run.js:15     — eval() with dynamic input
   SKILL.md:3            — Obfuscated base64 payload

🚫 BLOCKED — skill not installed.
```

### Scan already-installed skills

```bash
# Scan everything
node skills/skill-guard/scripts/scan.mjs

# Scan one specific skill
node skills/skill-guard/scripts/scan.mjs --path skills/suspicious-skill

# Verbose output (shows matched lines)
node skills/skill-guard/scripts/scan.mjs --verbose

# JSON output for automation
node skills/skill-guard/scripts/scan.mjs --json
```

### Options

| Flag | Description |
|------|-------------|
| `--threshold` | Allow installs up to this risk level (`low`, `medium`) |
| `--verbose` | Show all matched lines and patterns |
| `--force` | Install despite findings (not recommended) |
| `--json` | Machine-readable output |

---

## What It Detects

| Severity | Examples |
|----------|---------|
| 💀 **Critical** | Data exfiltration, credential theft, reverse shells, obfuscated payloads |
| 🔴 **High** | Keyloggers, clipboard access, broad credential patterns |
| 🟡 **Medium** | `process.env` dumping, hardcoded IPs, `eval()`, dynamic code execution |
| ⚠️ **Low** | Shell exec (`child_process`), outbound HTTP, broad file globs |

50+ patterns across 5 severity levels. Catches both obvious attacks and subtle exfiltration.

---

## Trust Scores

```
✅ Safe      No suspicious patterns
⚠️  Low       Minor flags, likely benign
🟡 Medium    Worth a manual review
🔴 High      Suspicious — review before using
💀 Critical  Strong malicious indicators — do not install
```

---

## Example: Full Scan Report

```
🛡️  skill-guard — Security Scan Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scanned: 8 skills, 34 files

✅ weather          — Safe (0 findings)
✅ github           — Safe (0 findings)
✅ summarize        — Safe (0 findings)
✅ blogwatcher      — Safe (0 findings)
⚠️  random-tool      — Low Risk (2 findings)
   └─ scripts/run.sh:14 — Shell exec: child_process.exec()
   └─ scripts/run.sh:28 — Outbound HTTP to api.example.com
💀 shady-skill      — CRITICAL (5 findings)
   └─ SKILL.md:3 — Obfuscated base64 payload detected
   └─ scripts/install.sh:1 — Reads ~/.ssh/id_rsa
   └─ scripts/install.sh:7 — curl POST to external IP
   └─ scripts/run.js:12 — process.env full dump
   └─ scripts/run.js:15 — eval() with dynamic input

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 6 Safe | 1 Low | 0 Medium | 0 High | 1 Critical
```

---

## Agent Integration

When skill-guard is installed, add this rule to your `AGENTS.md`:

```markdown
## Security — Skill Installation

Before installing ANY skill:
1. Run `node skills/skill-guard/scripts/safe-install.mjs <skill-slug>`
2. If findings are high/critical → show findings to user, ask before proceeding
3. Only install if approved or risk is low/safe
```

Your agent will automatically gate every future skill install through the scanner.

---

## Setup (One-Time)

```bash
node skills/skill-guard/scripts/setup.mjs
```

This creates a shell alias so even manual `clawhub install` commands go through the security gate. Run `--remove` to undo.

---

## FAQ

**Does it catch everything?**
No scanner is perfect. skill-guard uses pattern matching across 50+ known malicious signatures. It catches the vast majority of attacks but sophisticated, novel techniques could evade detection. It's a strong first line of defense.

**Will it flag my own skills?**
Legitimate skills that use shell commands or HTTP calls may get `Low` flags — that's expected and safe. Only `High` and `Critical` findings should concern you.

**Can I still install a flagged skill?**
Yes, with `--force`. But you'll see the findings first and can make an informed decision.

---

Built by [ClawPacks](https://clawpacks.gumroad.com) · Protect your agent 🛡️
