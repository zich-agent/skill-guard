#!/usr/bin/env node

/**
 * safe-install — Pre-install security gate for OpenClaw skills
 *
 * Downloads a skill to a temp directory, runs skill-guard scan,
 * and only installs if it passes the security threshold.
 *
 * Usage:
 *   node safe-install.mjs <skill-slug>                    # Install if safe
 *   node safe-install.mjs <skill-slug> --threshold medium # Allow up to medium risk
 *   node safe-install.mjs <skill-slug> --force            # Install anyway (with warning)
 *   node safe-install.mjs <skill-slug> --verbose          # Show all findings
 */

import { execSync } from "child_process";
import { mkdtempSync, rmSync, existsSync, cpSync } from "fs";
import { join, dirname } from "path";
import { tmpdir, homedir } from "os";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SCANNER = join(__dirname, "scan.mjs");

const RISK_ORDER = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };

function parseArgs() {
  const args = process.argv.slice(2);
  const slug = args.find((a) => !a.startsWith("--"));
  const force = args.includes("--force");
  const verbose = args.includes("--verbose");
  const thresholdIdx = args.indexOf("--threshold");
  const threshold = thresholdIdx >= 0 ? args[thresholdIdx + 1] : "low";
  const versionIdx = args.indexOf("--version");
  const version = versionIdx >= 0 ? args[versionIdx + 1] : null;

  if (!slug) {
    console.error("Usage: safe-install <skill-slug> [--threshold low|medium|high] [--force] [--verbose]");
    console.error("");
    console.error("Thresholds:");
    console.error("  low     — Block medium, high, and critical (default — most strict)");
    console.error("  medium  — Block high and critical");
    console.error("  high    — Block only critical");
    process.exit(1);
  }

  return { slug, force, verbose, threshold, version };
}

function downloadToTemp(slug, version) {
  const tempDir = mkdtempSync(join(tmpdir(), "skill-guard-"));
  const skillDir = join(tempDir, "skills");

  console.log(`📦 Downloading ${slug}${version ? `@${version}` : ""} to temp directory...`);

  try {
    const versionFlag = version ? ` --version ${version}` : "";
    execSync(`clawhub install ${slug}${versionFlag} --dir ${skillDir}`, {
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 30000,
    });
  } catch (e) {
    const stderr = e.stderr?.toString() || "";
    const stdout = e.stdout?.toString() || "";
    console.error(`❌ Failed to download ${slug}: ${stderr || stdout || e.message}`);
    rmSync(tempDir, { recursive: true, force: true });
    process.exit(1);
  }

  return { tempDir, skillDir };
}

function runScan(skillDir, slug, verbose) {
  console.log(`🔍 Scanning ${slug} for security issues...`);
  console.log("");

  try {
    const jsonOutput = execSync(`node ${SCANNER} --path ${join(skillDir, slug)} --json`, {
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 30000,
    });

    return JSON.parse(jsonOutput.toString());
  } catch (e) {
    // Scanner might exit non-zero but still output valid JSON
    const stdout = e.stdout?.toString();
    if (stdout) {
      try {
        return JSON.parse(stdout);
      } catch {}
    }
    console.error(`❌ Scan failed: ${e.message}`);
    return null;
  }
}

function displayResults(scanResult, verbose) {
  if (!scanResult?.skills?.length) {
    console.log("⚠️  No files found to scan");
    return "safe";
  }

  const skill = scanResult.skills[0];
  const ICONS = { safe: "✅", low: "⚠️", medium: "🟡", high: "🔴", critical: "💀" };
  const LABELS = { safe: "Safe", low: "Low Risk", medium: "Medium Risk", high: "High Risk", critical: "CRITICAL" };

  console.log("🛡️  skill-guard — Pre-Install Security Report");
  console.log("━".repeat(50));
  console.log("");
  console.log(
    `${ICONS[skill.risk]} ${skill.name} — ${LABELS[skill.risk]} (${skill.findings.length} finding${skill.findings.length !== 1 ? "s" : ""})`
  );

  if (skill.findings.length > 0) {
    console.log("");

    // Group by severity
    const bySeverity = {};
    for (const f of skill.findings) {
      if (!bySeverity[f.severity]) bySeverity[f.severity] = [];
      bySeverity[f.severity].push(f);
    }

    for (const sev of ["critical", "high", "medium", "low"]) {
      if (!bySeverity[sev]) continue;
      const sevIcon = sev === "critical" ? "💀" : sev === "high" ? "🔴" : sev === "medium" ? "🟡" : "⚠️";

      for (const f of bySeverity[sev]) {
        console.log(`   ${sevIcon} ${f.file}:${f.line} — ${f.name}`);
        if (verbose) {
          console.log(`      ${f.desc}`);
          if (f.content) console.log(`      > ${f.content}`);
        }
      }
    }
  }

  console.log("");
  console.log("━".repeat(50));

  return skill.risk;
}

function installForReal(slug, version) {
  console.log(`📥 Installing ${slug} to workspace...`);

  try {
    const versionFlag = version ? ` --version ${version}` : "";
    execSync(`clawhub install ${slug}${versionFlag}`, {
      stdio: "inherit",
      timeout: 30000,
    });
    return true;
  } catch (e) {
    console.error(`❌ Installation failed: ${e.message}`);
    return false;
  }
}

async function main() {
  const { slug, force, verbose, threshold, version } = parseArgs();

  // Step 1: Download to temp
  const { tempDir, skillDir } = downloadToTemp(slug, version);

  try {
    // Step 2: Scan
    const scanResult = runScan(skillDir, slug, verbose);

    if (!scanResult) {
      console.log("⚠️  Could not complete scan. Aborting installation.");
      process.exit(1);
    }

    // Step 3: Display results
    const risk = displayResults(scanResult, verbose);

    // Step 4: Decision
    const blocked = RISK_ORDER[risk] > RISK_ORDER[threshold];

    if (blocked && !force) {
      console.log(`🚫 BLOCKED — ${slug} has ${risk}-level findings (threshold: ${threshold})`);
      console.log("");
      console.log("Options:");
      console.log(`  --threshold ${risk}    Allow this risk level`);
      console.log(`  --force              Install anyway (not recommended)`);
      console.log(`  --verbose            See full findings with line content`);
      process.exit(1);
    }

    if (blocked && force) {
      console.log(`⚠️  WARNING: Installing ${slug} despite ${risk}-level findings (--force used)`);
      console.log("");
    }

    if (!blocked) {
      console.log(`✅ ${slug} passed security check (risk: ${risk}, threshold: ${threshold})`);
      console.log("");
    }

    // Step 5: Install for real
    const success = installForReal(slug, version);

    if (success) {
      console.log("");
      console.log(`✅ ${slug} installed successfully.`);
    }
  } finally {
    // Cleanup temp
    rmSync(tempDir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error("Error:", e.message);
  process.exit(1);
});
