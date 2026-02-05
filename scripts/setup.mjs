#!/usr/bin/env node

/**
 * skill-guard setup — Creates shell wrapper so all skill installs go through security gate.
 *
 * What it does:
 * 1. Creates a `clawhub-safe` wrapper script in ~/.local/bin/
 * 2. Adds shell alias: clawhub install → clawhub-safe
 * 3. Prints confirmation
 *
 * Usage:
 *   node scripts/setup.mjs           # Install wrapper + alias
 *   node scripts/setup.mjs --remove  # Remove wrapper + alias
 */

import { writeFileSync, readFileSync, existsSync, mkdirSync, unlinkSync } from "fs";
import { join, dirname } from "path";
import { homedir } from "os";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SAFE_INSTALL = join(__dirname, "safe-install.mjs");

const home = homedir();
const binDir = join(home, ".local", "bin");
const wrapperPath = join(binDir, "clawhub-safe");

// Detect shell config file
function getShellConfig() {
  const shell = process.env.SHELL || "/bin/zsh";
  if (shell.includes("zsh")) return join(home, ".zshrc");
  if (shell.includes("bash")) return join(home, ".bashrc");
  if (shell.includes("fish")) return join(home, ".config", "fish", "config.fish");
  return join(home, ".zshrc"); // default
}

const ALIAS_MARKER = "# skill-guard: safe install alias";
const ALIAS_LINE_ZSH = `clawhub() { if [[ "$1" == "install" ]]; then shift; node "${SAFE_INSTALL}" "$@"; else command clawhub "$@"; fi }`;
const ALIAS_LINE_FISH = `function clawhub; if test "$argv[1]" = "install"; node "${SAFE_INSTALL}" $argv[2..]; else command clawhub $argv; end; end`;

function install() {
  const shellConfig = getShellConfig();
  const isFish = shellConfig.includes("fish");
  const aliasLine = isFish ? ALIAS_LINE_FISH : ALIAS_LINE_ZSH;

  // Check if already installed
  if (existsSync(shellConfig)) {
    const content = readFileSync(shellConfig, "utf-8");
    if (content.includes(ALIAS_MARKER)) {
      console.log("✅ skill-guard is already set up.");
      console.log(`   Config: ${shellConfig}`);
      return;
    }
  }

  // Add alias to shell config
  const block = `\n${ALIAS_MARKER}\n${aliasLine}\n`;

  try {
    const existing = existsSync(shellConfig) ? readFileSync(shellConfig, "utf-8") : "";
    writeFileSync(shellConfig, existing + block);
    console.log("✅ skill-guard is now active!");
    console.log("");
    console.log("What changed:");
    console.log(`   Added safe-install wrapper to ${shellConfig}`);
    console.log("");
    console.log("How it works:");
    console.log("   Every 'clawhub install' now runs a security scan first.");
    console.log("   Dangerous skills are blocked before they touch your system.");
    console.log("");
    console.log("   ✅ Safe skills → installed normally");
    console.log("   🚫 Dangerous skills → blocked with findings report");
    console.log("");
    console.log("To apply now, run:");
    console.log(`   source ${shellConfig}`);
    console.log("");
    console.log("To remove later:");
    console.log("   node scripts/setup.mjs --remove");
  } catch (e) {
    console.error(`❌ Failed to write ${shellConfig}: ${e.message}`);
    process.exit(1);
  }
}

function remove() {
  const shellConfig = getShellConfig();

  if (!existsSync(shellConfig)) {
    console.log("Nothing to remove.");
    return;
  }

  const content = readFileSync(shellConfig, "utf-8");
  if (!content.includes(ALIAS_MARKER)) {
    console.log("skill-guard alias not found. Nothing to remove.");
    return;
  }

  // Remove the alias block
  const lines = content.split("\n");
  const filtered = [];
  let skipping = false;

  for (const line of lines) {
    if (line.trim() === ALIAS_MARKER) {
      skipping = true;
      continue;
    }
    if (skipping) {
      skipping = false; // Skip the alias line too
      continue;
    }
    filtered.push(line);
  }

  writeFileSync(shellConfig, filtered.join("\n"));
  console.log("✅ skill-guard alias removed.");
  console.log(`   Updated: ${shellConfig}`);
  console.log(`   Run: source ${shellConfig}`);
}

const args = process.argv.slice(2);
if (args.includes("--remove")) {
  remove();
} else {
  install();
}
