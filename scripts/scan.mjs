#!/usr/bin/env node

/**
 * skill-guard — Security scanner for OpenClaw skills
 * Detects malicious patterns in installed skills and generates trust reports.
 *
 * Usage:
 *   node scan.mjs                    # Scan all installed skills
 *   node scan.mjs --path <dir>       # Scan specific skill directory
 *   node scan.mjs --verbose          # Show matched lines
 *   node scan.mjs --json             # JSON output
 */

import { readdir, readFile, stat } from "fs/promises";
import { join, basename, extname, relative } from "path";
import { homedir } from "os";

// ============================================================================
// Pattern definitions
// ============================================================================

const PATTERNS = {
  critical: [
    {
      id: "exfil-curl",
      name: "Data exfiltration via curl/wget",
      regex:
        /\b(curl|wget)\b.*(-d|--data|--data-raw|--data-binary|-X\s*POST).*\b(ssh|key|token|password|secret|cred|aws|env)\b/gi,
      desc: "Sends sensitive data to external endpoint",
    },
    {
      id: "exfil-fetch",
      name: "Data exfiltration via fetch/axios",
      regex:
        /\b(fetch|axios)\s*\(.*\b(token|password|secret|credential|api.?key|ssh)\b/gi,
      desc: "Sends sensitive data via HTTP client",
    },
    {
      id: "read-ssh",
      name: "SSH key access",
      regex: /[~$]?(HOME|home|\/Users\/|\/root\/).*\.ssh\/(id_rsa|id_ed25519|known_hosts|authorized_keys|config)/g,
      desc: "Reads SSH keys or config",
    },
    {
      id: "read-ssh-tilde",
      name: "SSH key access (~/.ssh)",
      regex: /~\/\.ssh\//g,
      desc: "Accesses ~/.ssh directory",
    },
    {
      id: "read-aws",
      name: "AWS credential access",
      regex: /~\/\.aws\/(credentials|config)|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID/g,
      desc: "Reads AWS credentials",
    },
    {
      id: "read-env-file",
      name: "Environment file access",
      regex: /\b(cat|read|readFile|readFileSync)\b.*\.(env|env\.local|env\.production)/g,
      desc: "Reads .env files containing secrets",
    },
    {
      id: "reverse-shell",
      name: "Reverse shell",
      regex:
        /\b(nc|ncat|netcat)\s+(-e|--exec|-c)|\bbash\s+-i\s+>&?\s*\/dev\/tcp|\/bin\/sh\s+-i|python.*socket.*connect/gi,
      desc: "Reverse shell or backdoor connection",
    },
    {
      id: "base64-exec",
      name: "Obfuscated base64 execution",
      regex:
        /\b(echo|printf)\s+['"]?[A-Za-z0-9+\/=]{40,}['"]?\s*\|\s*(base64\s+-d|b64decode)\s*\|\s*(sh|bash|eval|node|python)/g,
      desc: "Decodes and executes base64 payload",
    },
    {
      id: "base64-atob-exec",
      name: "JS base64 decode + eval",
      regex: /\b(atob|Buffer\.from)\s*\([^)]*\).*\b(eval|Function|exec)\b/g,
      desc: "Decodes base64 in JS and executes",
    },
    {
      id: "keylogger",
      name: "Keylogger pattern",
      regex: /\b(keylog|key.?log|keyboard.?listen|input.?capture|keystroke)/gi,
      desc: "Potential keylogger or keyboard listener",
    },
    {
      id: "clipboard-exfil",
      name: "Clipboard exfiltration",
      regex: /\b(pbcopy|pbpaste|xclip|xsel|clipboard)\b.*\b(curl|wget|fetch|http|send|post)\b/gi,
      desc: "Reads clipboard and sends externally",
    },
    {
      id: "curl-external-ip",
      name: "Data POST to hardcoded IP",
      regex: /\b(curl|wget|fetch|axios)\b.*https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
      desc: "Sends data to hardcoded IP address",
    },
    {
      id: "steal-browser-cookies",
      name: "Browser cookie theft",
      regex: /(Cookies\.binarycookies|chrome.*cookies|firefox.*cookies\.sqlite|\.cookie-jar|ChromiumCookies)/gi,
      desc: "Accesses browser cookie stores",
    },
    {
      id: "steal-keychain",
      name: "Keychain/credential store access",
      regex: /\b(security\s+find-(generic|internet)-password|keychain|credential.?store|kwallet|gnome-keyring)/gi,
      desc: "Accesses system keychain or credential store",
    },
    {
      id: "openclaw-creds",
      name: "OpenClaw credential access",
      regex: /\.openclaw\/(credentials|openclaw\.json|config)|\bOPENCLAW_.*KEY\b|\bANTHROPIC_API_KEY\b|\bOPENAI_API_KEY\b/g,
      desc: "Reads OpenClaw credentials or API keys",
    },
  ],

  high: [
    {
      id: "env-dump",
      name: "Full environment variable dump",
      regex: /\bprocess\.env\b(?!\.[A-Z_]+)|JSON\.stringify\(.*process\.env|Object\.keys\(.*process\.env|env\s*=\s*process\.env\b/g,
      desc: "Dumps all environment variables (may contain secrets)",
    },
    {
      id: "eval-dynamic",
      name: "Dynamic code execution",
      regex: /\beval\s*\((?!['"][^'"]*['"])|new\s+Function\s*\(|vm\.runIn(New|This)?Context/g,
      desc: "Executes dynamic/untrusted code",
    },
    {
      id: "hex-payload",
      name: "Hex-encoded payload",
      regex: /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){10,}/gi,
      desc: "Long hex-encoded string (possible obfuscation)",
    },
    {
      id: "fs-sensitive-paths",
      name: "Access to sensitive system paths",
      regex: /\/(etc\/(passwd|shadow|hosts)|proc\/self|dev\/(tcp|udp))/g,
      desc: "Reads sensitive system files",
    },
    {
      id: "npm-install-runtime",
      name: "Runtime package installation",
      regex: /\b(npm|npx|yarn|pnpm|pip|pip3)\s+(install|add|exec)\b/g,
      desc: "Installs packages at runtime (supply chain risk)",
    },
    {
      id: "download-execute",
      name: "Download and execute",
      regex: /\b(curl|wget)\b.*\|\s*(sh|bash|node|python)|>\s*\/tmp\/[^\s]+\s*&&\s*(sh|bash|chmod)/g,
      desc: "Downloads and immediately executes remote code",
    },
    {
      id: "crypto-mining",
      name: "Cryptocurrency mining",
      regex: /\b(xmrig|minerd|cryptonight|stratum\+tcp|coinhive|monero|mining.?pool)/gi,
      desc: "Potential cryptocurrency mining activity",
    },
    {
      id: "telegram-exfil",
      name: "Telegram bot exfiltration",
      regex: /api\.telegram\.org\/bot.*send(Message|Document)/g,
      desc: "Sends data via Telegram bot",
    },
    {
      id: "discord-webhook-exfil",
      name: "Discord webhook exfiltration",
      regex: /discord(app)?\.com\/api\/webhooks\/\d+\//g,
      desc: "Sends data via Discord webhook",
    },
  ],

  medium: [
    {
      id: "exec-spawn",
      name: "Shell command execution",
      regex: /\b(child_process|exec|execSync|spawn|spawnSync|execFile)\b/g,
      desc: "Executes shell commands",
    },
    {
      id: "network-hardcoded-ip",
      name: "Hardcoded IP address",
      regex: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?/g,
      desc: "Network call to hardcoded IP",
    },
    {
      id: "broad-file-read",
      name: "Broad home directory access",
      regex: /\b(readdir|glob|walk)\b.*~\/|homedir\(\)/g,
      desc: "Scans home directory broadly",
    },
    {
      id: "write-cron",
      name: "Cron/scheduled task modification",
      regex: /\bcrontab\b|\/(etc\/cron|var\/spool\/cron)|launchctl\s+(load|submit)/g,
      desc: "Modifies scheduled tasks or cron jobs",
    },
    {
      id: "permission-change",
      name: "Permission modification",
      regex: /\bchmod\s+[0-7]{3,4}\b|\bchown\b/g,
      desc: "Changes file permissions or ownership",
    },
    {
      id: "dns-exfil",
      name: "DNS-based data exfiltration",
      regex: /\b(dig|nslookup|host)\s+.*\$|\bdns.*exfil/gi,
      desc: "Potential DNS-based data exfiltration",
    },
  ],

  low: [
    {
      id: "outbound-http",
      name: "Outbound HTTP request",
      regex: /\b(fetch|axios|http\.request|https\.request|got|node-fetch|request)\s*\(/g,
      desc: "Makes outbound HTTP requests",
    },
    {
      id: "file-write",
      name: "File write operation",
      regex: /\b(writeFile|writeFileSync|appendFile|createWriteStream)\b/g,
      desc: "Writes to file system",
    },
    {
      id: "broad-glob",
      name: "Broad glob pattern",
      regex: /\*\*\/\*\.|\bglob\b.*\*\*/g,
      desc: "Uses broad file glob patterns",
    },
  ],
};

// Self-exclusion: skip our own pattern definition file to avoid false positives
const SELF_SKIP_FILES = new Set(["scan.mjs", "scan.js", "scan.ts", "safe-install.mjs", "safe-install.js"]);

// File extensions to scan
const SCAN_EXTENSIONS = new Set([
  ".md", ".js", ".mjs", ".cjs", ".ts", ".mts",
  ".py", ".sh", ".bash", ".zsh", ".fish",
  ".json", ".json5", ".yaml", ".yml", ".toml",
  ".rb", ".pl", ".lua", ".go", ".rs",
  ".ps1", ".bat", ".cmd",
]);

// Files to always skip
const SKIP_FILES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  ".DS_Store",
  "node_modules",
]);

// Max file size to scan (512KB)
const MAX_FILE_SIZE = 512 * 1024;

// ============================================================================
// Scanner
// ============================================================================

async function getSkillDirs(customPath) {
  if (customPath) {
    return [{ name: basename(customPath), path: customPath }];
  }

  const dirs = [];
  const home = homedir();
  const searchPaths = [
    join(home, ".openclaw", "skills"),
    join(home, ".openclaw", "extensions"),
    "skills",
  ];

  for (const searchPath of searchPaths) {
    try {
      const entries = await readdir(searchPath, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory() && !SKIP_FILES.has(entry.name)) {
          dirs.push({
            name: entry.name,
            path: join(searchPath, entry.name),
          });
        }
      }
    } catch {
      // Directory doesn't exist, skip
    }
  }

  return dirs;
}

async function getFilesRecursive(dir, base = dir) {
  const files = [];
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (SKIP_FILES.has(entry.name)) continue;
      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git") continue;
        files.push(...(await getFilesRecursive(fullPath, base)));
      } else if (entry.isFile()) {
        // Skip our own scanner files to avoid false positives from pattern definitions
        if (SELF_SKIP_FILES.has(entry.name)) continue;
        const ext = extname(entry.name).toLowerCase();
        if (SCAN_EXTENSIONS.has(ext) || entry.name === "Makefile" || entry.name === "Dockerfile") {
          const s = await stat(fullPath);
          if (s.size <= MAX_FILE_SIZE) {
            files.push({ path: fullPath, rel: relative(base, fullPath) });
          }
        }
      }
    }
  } catch {
    // Permission denied or similar
  }
  return files;
}

function scanContent(content, filePath) {
  const findings = [];
  const lines = content.split("\n");

  // Skip skill-guard's own SKILL.md (contains example output with fake findings)
  if (filePath === "SKILL.md" || filePath.endsWith("/SKILL.md")) {
    const isSkillGuard = content.includes("skill-guard") && content.includes("Security scanner");
    if (isSkillGuard) return findings;
  }

  for (const [severity, patterns] of Object.entries(PATTERNS)) {
    for (const pattern of patterns) {
      // Reset regex state
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Skip comment-only lines in markdown that are just documentation
        if (filePath.endsWith(".md") && /^#{1,6}\s/.test(line)) continue;

        if (regex.test(line)) {
          findings.push({
            severity,
            id: pattern.id,
            name: pattern.name,
            desc: pattern.desc,
            file: filePath,
            line: i + 1,
            content: line.trim().substring(0, 120),
          });
          // Reset regex for next test
          regex.lastIndex = 0;
        }
      }
    }
  }

  return findings;
}

function getRiskLevel(findings) {
  if (findings.some((f) => f.severity === "critical")) return "critical";
  if (findings.some((f) => f.severity === "high")) return "high";
  if (findings.some((f) => f.severity === "medium")) return "medium";
  if (findings.some((f) => f.severity === "low")) return "low";
  return "safe";
}

const RISK_ICONS = {
  safe: "✅",
  low: "⚠️",
  medium: "🟡",
  high: "🔴",
  critical: "💀",
};

const RISK_LABELS = {
  safe: "Safe",
  low: "Low Risk",
  medium: "Medium Risk",
  high: "High Risk",
  critical: "CRITICAL",
};

// ============================================================================
// Main
// ============================================================================

async function main() {
  const args = process.argv.slice(2);
  const verbose = args.includes("--verbose") || args.includes("-v");
  const jsonOutput = args.includes("--json");
  const pathIdx = args.indexOf("--path");
  const customPath = pathIdx >= 0 ? args[pathIdx + 1] : null;

  const skills = await getSkillDirs(customPath);

  if (skills.length === 0) {
    console.log("No skills found to scan.");
    process.exit(0);
  }

  const results = [];
  let totalFiles = 0;

  for (const skill of skills) {
    const files = await getFilesRecursive(skill.path);
    const allFindings = [];

    for (const file of files) {
      try {
        const content = await readFile(file.path, "utf-8");
        const findings = scanContent(content, file.rel);
        allFindings.push(...findings);
      } catch {
        // Can't read file, skip
      }
    }

    totalFiles += files.length;

    // Deduplicate findings by id+file+line
    const seen = new Set();
    const uniqueFindings = allFindings.filter((f) => {
      const key = `${f.id}:${f.file}:${f.line}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    results.push({
      name: skill.name,
      path: skill.path,
      filesScanned: files.length,
      risk: getRiskLevel(uniqueFindings),
      findings: uniqueFindings,
    });
  }

  // Sort: critical first, then high, medium, low, safe
  const order = { critical: 0, high: 1, medium: 2, low: 3, safe: 4 };
  results.sort((a, b) => order[a.risk] - order[b.risk]);

  if (jsonOutput) {
    console.log(JSON.stringify({ skills: results, totalFiles, totalSkills: skills.length }, null, 2));
    return;
  }

  // Pretty output
  console.log();
  console.log("🛡️  skill-guard — Security Scan Report");
  console.log("━".repeat(50));
  console.log();
  console.log(`Scanned: ${skills.length} skills, ${totalFiles} files`);
  console.log();

  const counts = { safe: 0, low: 0, medium: 0, high: 0, critical: 0 };

  for (const result of results) {
    counts[result.risk]++;
    const icon = RISK_ICONS[result.risk];
    const label = RISK_LABELS[result.risk];
    const findingCount = result.findings.length;

    console.log(
      `${icon} ${result.name.padEnd(25)} — ${label} (${findingCount} finding${findingCount !== 1 ? "s" : ""})`
    );

    if (result.findings.length > 0 && (verbose || result.risk === "critical" || result.risk === "high")) {
      for (const f of result.findings) {
        const sevIcon =
          f.severity === "critical"
            ? "💀"
            : f.severity === "high"
              ? "🔴"
              : f.severity === "medium"
                ? "🟡"
                : "⚠️";
        console.log(`   └─ ${f.file}:${f.line} — ${sevIcon} ${f.name}`);
        if (verbose) {
          console.log(`      ${f.desc}`);
          console.log(`      > ${f.content}`);
        }
      }
    }
  }

  console.log();
  console.log("━".repeat(50));
  console.log(
    `Summary: ${counts.safe} Safe | ${counts.low} Low | ${counts.medium} Medium | ${counts.high} High | ${counts.critical} Critical`
  );

  if (counts.critical > 0 || counts.high > 0) {
    console.log();
    console.log(
      "⚠️  ATTENTION: Skills with High/Critical findings should be reviewed or removed immediately."
    );
    console.log(
      "   Run with --verbose for full details including matched line content."
    );
  }

  console.log();
  console.log(
    "Built by ClawPacks — https://clawpacks.gumroad.com"
  );
}

main().catch((e) => {
  console.error("Scan failed:", e.message);
  process.exit(1);
});
