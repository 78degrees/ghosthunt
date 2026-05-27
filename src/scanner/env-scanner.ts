/**
 * env-scanner.ts — Recursively find .env files and extract secrets.
 *
 * Walks the filesystem from the user's home directory, skipping
 * heavy directories (node_modules, .git, Library, etc.).
 * Parses key=value pairs and matches values against the pattern library.
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { join, basename } from "node:path";
import { homedir } from "node:os";
import type { SecretFinding } from "../types.js";
import { SECRET_PATTERNS, requiresKeyHint } from "./patterns.js";

/** Directories to skip during recursive walk */
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".svn",
  ".hg",
  "Library",
  "Applications",
  ".Trash",
  ".cache",
  ".npm",
  ".yarn",
  "vendor",
  "venv",
  ".venv",
  "__pycache__",
  "dist",
  "build",
  ".next",
  ".nuxt",
  "coverage",
  ".tox",
  "egg-info",
]);

/** File patterns that indicate an env file */
const ENV_FILE_PATTERNS = [
  /^\.env$/,
  /^\.env\..+$/,           // .env.local, .env.production, .env.staging
  /^\.env\.[^.]+\.local$/,  // .env.production.local
  /^env\.example$/i,
  /^\.env\.example$/,
  /^\.env\.sample$/,
  /^\.env\.template$/,
];

function isEnvFile(filename: string): boolean {
  return ENV_FILE_PATTERNS.some(p => p.test(filename));
}

/** Parse a .env file into key-value pairs with line numbers */
function parseEnvFile(content: string): Array<{ key: string; value: string; lineNumber: number }> {
  const pairs: Array<{ key: string; value: string; lineNumber: number }> = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    // Skip comments and empty lines
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;

    // Match KEY=VALUE (with optional quotes)
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (match) {
      const key = match[1];
      let value = match[2].trim();

      // Strip surrounding quotes
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }

      // Skip empty values and obvious placeholders
      if (!value || value === "your-key-here" || value === "xxx" ||
          value === "CHANGE_ME" || value === "TODO" || value.startsWith("<")) {
        continue;
      }

      pairs.push({ key, value, lineNumber: i + 1 });
    }
  }

  return pairs;
}

/** Redact a secret value, showing only first 4 and last 4 chars */
export function redactValue(value: string): string {
  if (value.length <= 10) return "****";
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 8, 20))}${value.slice(-4)}`;
}

/** Recursively find all .env files under a directory */
async function findEnvFiles(dir: string, maxDepth: number = 6, depth: number = 0): Promise<string[]> {
  if (depth > maxDepth) return [];

  const results: string[] = [];

  try {
    const entries = await readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith(".") && entry.name !== ".env") {
          // Skip hidden dirs except we still want to look at top-level dots
          if (depth > 0 && entry.name.startsWith(".")) continue;
          if (SKIP_DIRS.has(entry.name)) continue;
        }
        const subResults = await findEnvFiles(join(dir, entry.name), maxDepth, depth + 1);
        results.push(...subResults);
      } else if (entry.isFile() && isEnvFile(entry.name)) {
        results.push(join(dir, entry.name));
      }
    }
  } catch {
    // Permission denied or other FS errors — skip silently
  }

  return results;
}

/** Scan all .env files and return findings */
export async function scanEnvFiles(): Promise<{ findings: SecretFinding[]; filesScanned: number }> {
  const home = homedir();
  const envFiles = await findEnvFiles(home);
  const findings: SecretFinding[] = [];

  for (const filePath of envFiles) {
    try {
      const fstat = await stat(filePath);
      // Skip files larger than 1MB (not a real .env file)
      if (fstat.size > 1_000_000) continue;

      const content = await readFile(filePath, "utf-8");
      const pairs = parseEnvFile(content);

      for (const { key, value, lineNumber } of pairs) {
        for (const pattern of SECRET_PATTERNS) {
          // If pattern requires a key hint, check the key name first
          if (requiresKeyHint(pattern)) {
            if (!pattern.keyHint || !pattern.keyHint.test(key)) continue;
          }

          if (pattern.regex.test(value)) {
            findings.push({
              type: pattern.name,
              severity: pattern.severity,
              source: "env_file",
              filePath,
              lineNumber,
              context: key,
              redactedValue: redactValue(value),
            });
            break; // One match per key-value pair is enough
          }
        }
      }
    } catch {
      // Can't read file — skip
    }
  }

  return { findings, filesScanned: envFiles.length };
}
