/**
 * server.ts — MCP server for GhostHunt.
 *
 * Registers two tools:
 *   - scan_secrets:  Full machine scan with detailed findings
 *   - scan_summary:  Quick count + severity breakdown + health score
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { scanEnvFiles } from "./scanner/env-scanner.js";
import { scanConfigFiles } from "./scanner/config-scanner.js";
import { scanShellHistory } from "./scanner/history-scanner.js";
import type { ScanResult, ScanSummary, SecretFinding, Severity } from "./types.js";

/** Run a full scan across all sources */
async function runFullScan(): Promise<ScanResult> {
  const start = Date.now();

  // Run all scanners in parallel
  const [envResult, configResult, historyResult] = await Promise.all([
    scanEnvFiles(),
    scanConfigFiles(),
    scanShellHistory(),
  ]);

  const allFindings: SecretFinding[] = [
    ...envResult.findings,
    ...configResult.findings,
    ...historyResult.findings,
  ];

  // Deduplicate: same secret value in the same file = one finding
  const seen = new Set<string>();
  const dedupedFindings = allFindings.filter(f => {
    const key = `${f.filePath}:${f.redactedValue}:${f.type}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Sort by severity (critical first)
  const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  dedupedFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Build summary
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const bySource: Record<string, number> = {};

  for (const f of dedupedFindings) {
    bySeverity[f.severity]++;
    bySource[f.source] = (bySource[f.source] || 0) + 1;
  }

  // Health score: 100 = clean, 0 = disaster
  // Each critical = -15, high = -8, medium = -3, low = -1
  const rawPenalty =
    bySeverity.critical * 15 +
    bySeverity.high * 8 +
    bySeverity.medium * 3 +
    bySeverity.low * 1;
  const healthScore = Math.max(0, 100 - rawPenalty);

  const summary: ScanSummary = {
    totalSecrets: dedupedFindings.length,
    bySeverity,
    bySource,
    filesScanned: envResult.filesScanned + historyResult.filesScanned,
    locationsChecked: configResult.locationsChecked + envResult.filesScanned + historyResult.filesScanned,
    scanDurationMs: Date.now() - start,
    healthScore,
  };

  return { summary, findings: dedupedFindings };
}

/** Format findings for display */
function formatFindings(result: ScanResult): string {
  const { summary, findings } = result;
  const lines: string[] = [];

  // Header
  lines.push("# GhostHunt Scan Report");
  lines.push("");
  lines.push(`**Health Score: ${summary.healthScore}/100** ${summary.healthScore >= 80 ? "(Good)" : summary.healthScore >= 50 ? "(Needs Attention)" : "(Critical)"}`);
  lines.push("");
  lines.push(`- Secrets found: **${summary.totalSecrets}**`);
  lines.push(`- Critical: ${summary.bySeverity.critical} | High: ${summary.bySeverity.high} | Medium: ${summary.bySeverity.medium} | Low: ${summary.bySeverity.low}`);
  lines.push(`- Locations scanned: ${summary.locationsChecked}`);
  lines.push(`- Scan time: ${summary.scanDurationMs}ms`);
  lines.push("");

  if (findings.length === 0) {
    lines.push("No secrets found. Your machine is clean.");
    return lines.join("\n");
  }

  // Group by source
  const grouped = new Map<string, SecretFinding[]>();
  for (const f of findings) {
    const group = grouped.get(f.source) || [];
    group.push(f);
    grouped.set(f.source, group);
  }

  const sourceLabels: Record<string, string> = {
    env_file: "Environment Files (.env)",
    aws_credentials: "AWS Credentials",
    ssh_key: "SSH Keys",
    docker_config: "Docker Config",
    npm_config: "npm Config (.npmrc)",
    pypi_config: "PyPI Config (.pypirc)",
    netrc: "Netrc File",
    git_config: "Git Config",
    gh_cli: "GitHub CLI",
    shell_history: "Shell History",
    kube_config: "Kubernetes Config",
    gcloud_config: "Google Cloud Config",
    azure_config: "Azure Config",
  };

  for (const [source, sourceFindings] of grouped) {
    lines.push(`## ${sourceLabels[source] || source}`);
    lines.push("");

    for (const f of sourceFindings) {
      const severity = f.severity.toUpperCase();
      const location = f.lineNumber ? `${f.filePath}:${f.lineNumber}` : f.filePath;
      lines.push(`- **[${severity}]** ${f.type}`);
      lines.push(`  - File: \`${location}\``);
      lines.push(`  - Context: \`${f.context}\``);
      lines.push(`  - Value: \`${f.redactedValue}\``);
      lines.push("");
    }
  }

  // Recommendations
  lines.push("## Recommendations");
  lines.push("");

  if (summary.bySeverity.critical > 0) {
    lines.push("1. **Rotate critical secrets immediately.** Any API key or credential marked CRITICAL should be revoked and regenerated from the provider's dashboard.");
  }
  if (grouped.has("shell_history")) {
    lines.push("2. **Clear your shell history** of sensitive commands: `history -c` (bash) or run `truncate -s 0 ~/.zsh_history` (zsh). Consider using environment variables instead of inline secrets.");
  }
  if (grouped.has("env_file")) {
    lines.push("3. **Audit your .env files.** Ensure they are in .gitignore. Consider using a secrets manager (1Password CLI, Doppler, Vault) instead of plain-text .env files.");
  }
  if (grouped.has("ssh_key")) {
    lines.push("4. **Protect SSH keys** with passphrases. Consider using ssh-agent to avoid storing unencrypted keys.");
  }

  lines.push("");
  lines.push("---");
  lines.push("*GhostHunt scans your local machine only. No data leaves your computer.*");

  return lines.join("\n");
}

/** Format summary only (no detailed findings) */
function formatSummary(summary: ScanSummary): string {
  const lines: string[] = [];

  lines.push("# GhostHunt Quick Scan");
  lines.push("");
  lines.push(`**Health Score: ${summary.healthScore}/100** ${summary.healthScore >= 80 ? "(Good)" : summary.healthScore >= 50 ? "(Needs Attention)" : "(Critical)"}`);
  lines.push("");
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Critical | ${summary.bySeverity.critical} |`);
  lines.push(`| High | ${summary.bySeverity.high} |`);
  lines.push(`| Medium | ${summary.bySeverity.medium} |`);
  lines.push(`| Low | ${summary.bySeverity.low} |`);
  lines.push(`| **Total** | **${summary.totalSecrets}** |`);
  lines.push("");
  lines.push(`Scanned ${summary.locationsChecked} locations in ${summary.scanDurationMs}ms.`);
  lines.push("");

  if (summary.totalSecrets > 0) {
    lines.push("Run `scan_secrets` for the full detailed report with file paths and recommendations.");
  } else {
    lines.push("Your machine is clean. No secrets found.");
  }

  lines.push("");
  lines.push("---");
  lines.push("*All scanning happens locally. Nothing leaves your machine.*");

  return lines.join("\n");
}

/** Create and configure the MCP server */
export function createServer(): McpServer {
  const server = new McpServer({
    name: "ghosthunt",
    version: "1.0.0",
  });

  // ── Tool: scan_secrets (full detailed scan) ──────────────────────────────
  server.tool(
    "scan_secrets",
    "Scan your entire machine for leaked API keys, tokens, and credentials. " +
    "Checks .env files, AWS/SSH/Docker/npm configs, shell history, and more. " +
    "Returns a detailed report with file paths, line numbers, and remediation steps. " +
    "Everything runs locally — no data leaves your machine.",
    {
      include_low_severity: z
        .boolean()
        .optional()
        .default(true)
        .describe("Include low-severity findings (test keys, etc). Default: true."),
    },
    async ({ include_low_severity }) => {
      const result = await runFullScan();

      if (!include_low_severity) {
        result.findings = result.findings.filter(f => f.severity !== "low");
        result.summary.totalSecrets = result.findings.length;
      }

      return {
        content: [{ type: "text", text: formatFindings(result) }],
      };
    },
  );

  // ── Tool: scan_summary (quick count only) ────────────────────────────────
  server.tool(
    "scan_summary",
    "Quick health check — counts how many secrets are on your machine and gives " +
    "you a health score (0-100). Faster than a full scan. Run scan_secrets for details.",
    {},
    async () => {
      const result = await runFullScan();

      return {
        content: [{ type: "text", text: formatSummary(result.summary) }],
      };
    },
  );

  return server;
}
