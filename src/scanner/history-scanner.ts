/**
 * history-scanner.ts — Scan shell history files for leaked secrets.
 *
 * Reads ~/.bash_history, ~/.zsh_history, and ~/.fish_history (which uses
 * a different format). Matches each command line against the pattern
 * library, focusing on commands that contain inline secrets:
 *
 *   curl -H "Authorization: Bearer sk_live_xxxx" ...
 *   export STRIPE_SECRET_KEY=sk_live_xxxx
 *   AWS_ACCESS_KEY_ID=AKIAXXXX aws s3 ls
 *   mysql -u root -pMyPassword123
 */

import { readFile, access } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import type { SecretFinding } from "../types.js";
import { SECRET_PATTERNS, requiresKeyHint } from "./patterns.js";
import { redactValue } from "./env-scanner.js";

/** Max lines to scan from each history file (most recent) */
const MAX_HISTORY_LINES = 10_000;

/** Max file size to read (50MB — history files can get huge) */
const MAX_FILE_SIZE = 50_000_000;

/** History files to check */
const HISTORY_FILES = [
  ".bash_history",
  ".zsh_history",
  ".fish_history",
  ".sh_history",
];

/** Patterns specifically for command-line contexts */
const CLI_PATTERNS = [
  {
    name: "Inline Password (mysql/psql)",
    regex: /(?:mysql|psql|mysqldump|pg_dump|mariadb)\s+.*(?:-p(?=[^\s\-])['"]?([^\s'"]{8,})['"]?|--password[= ]['"]?([^\s'"]{8,})['"]?)/,
    severity: "high" as const,
  },
  {
    name: "Inline Password (curl Basic Auth)",
    regex: /curl\s+.*-u\s+\w+:([^\s'"]{8,})/,
    severity: "high" as const,
  },
  {
    name: "Bearer Token in Header",
    regex: /[Bb]earer\s+([A-Za-z0-9_\-.]{20,})/,
    severity: "high" as const,
  },
  {
    name: "Authorization Header Value",
    regex: /[Aa]uthorization:\s*(?:Basic|Token|Bearer)\s+([A-Za-z0-9_\-./+=]{20,})/,
    severity: "high" as const,
  },
];

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/** Parse fish history (uses a different format: "- cmd: <command>") */
function parseFishHistory(content: string): string[] {
  const commands: string[] = [];
  const lines = content.split("\n");

  for (const line of lines) {
    const match = line.match(/^- cmd:\s*(.+)/);
    if (match) {
      commands.push(match[1]);
    }
  }

  return commands;
}

/** Scan a single history file */
async function scanHistoryFile(filePath: string): Promise<SecretFinding[]> {
  const findings: SecretFinding[] = [];

  try {
    const content = await readFile(filePath, "utf-8");

    // Get the last N lines (most recent commands)
    let lines: string[];

    if (filePath.endsWith(".fish_history")) {
      lines = parseFishHistory(content);
    } else {
      // Zsh history may have timestamps prefixed with ": 1234567890:0;"
      lines = content
        .split("\n")
        .map((line: string) => line.replace(/^:\s*\d+:\d+;/, "").trim())
        .filter(Boolean);
    }

    // Take the most recent N lines
    const recentLines = lines.slice(-MAX_HISTORY_LINES);

    for (let i = 0; i < recentLines.length; i++) {
      const line = recentLines[i];

      // Skip very short lines (unlikely to contain secrets)
      if (line.length < 15) continue;

      // Check CLI-specific patterns first
      for (const pattern of CLI_PATTERNS) {
        if (pattern.regex.test(line)) {
          const match = line.match(pattern.regex);
          findings.push({
            type: pattern.name,
            severity: pattern.severity,
            source: "shell_history",
            filePath,
            lineNumber: lines.length - recentLines.length + i + 1,
            context: line.slice(0, 60) + (line.length > 60 ? "..." : ""),
            redactedValue: match?.[1] ? redactValue(match[1]) : "****",
          });
          break;
        }
      }

      // Check standard secret patterns
      for (const pattern of SECRET_PATTERNS) {
        // Skip patterns that need key hints (too noisy in history)
        if (requiresKeyHint(pattern)) continue;

        if (pattern.regex.test(line)) {
          const match = line.match(pattern.regex);
          if (match) {
            // Avoid duplicate if CLI pattern already matched
            const alreadyFound = findings.some(
              f => f.source === "shell_history" && f.lineNumber === (lines.length - recentLines.length + i + 1)
            );
            if (alreadyFound) continue;

            findings.push({
              type: pattern.name,
              severity: pattern.severity,
              source: "shell_history",
              filePath,
              lineNumber: lines.length - recentLines.length + i + 1,
              context: line.slice(0, 60) + (line.length > 60 ? "..." : ""),
              redactedValue: redactValue(match[0]),
            });
            break;
          }
        }
      }
    }
  } catch {
    // Can't read history file — skip
  }

  return findings;
}

/** Scan all shell history files */
export async function scanShellHistory(): Promise<{ findings: SecretFinding[]; filesScanned: number }> {
  const home = homedir();
  const allFindings: SecretFinding[] = [];
  let filesScanned = 0;

  for (const histFile of HISTORY_FILES) {
    const filePath = join(home, histFile);
    if (await fileExists(filePath)) {
      filesScanned++;
      const findings = await scanHistoryFile(filePath);
      allFindings.push(...findings);
    }
  }

  return { findings: allFindings, filesScanned };
}
