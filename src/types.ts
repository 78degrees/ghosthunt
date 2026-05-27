/**
 * types.ts — Core types for GhostHunt secret scanner.
 */

/** Severity levels for discovered secrets */
export type Severity = "critical" | "high" | "medium" | "low";

/** Where the secret was found */
export type SecretSource =
  | "env_file"
  | "aws_credentials"
  | "ssh_key"
  | "docker_config"
  | "npm_config"
  | "pypi_config"
  | "netrc"
  | "git_config"
  | "gh_cli"
  | "shell_history"
  | "kube_config"
  | "gcloud_config"
  | "azure_config";

/** A single discovered secret */
export interface SecretFinding {
  /** What type of secret (e.g., "AWS Access Key", "Stripe Live Key") */
  type: string;
  /** Severity classification */
  severity: Severity;
  /** Where it was found */
  source: SecretSource;
  /** File path where the secret lives */
  filePath: string;
  /** Line number (if applicable) */
  lineNumber?: number;
  /** The variable name or context (e.g., "STRIPE_SECRET_KEY") */
  context: string;
  /** Redacted preview of the secret (first 4 + last 4 chars) */
  redactedValue: string;
}

/** Summary of a scan */
export interface ScanSummary {
  /** Total secrets found */
  totalSecrets: number;
  /** Breakdown by severity */
  bySeverity: Record<Severity, number>;
  /** Breakdown by source type */
  bySource: Record<string, number>;
  /** Number of files scanned */
  filesScanned: number;
  /** Number of locations checked */
  locationsChecked: number;
  /** Time taken in milliseconds */
  scanDurationMs: number;
  /** Machine health score (0-100, lower = more secrets = worse) */
  healthScore: number;
}

/** Full scan result */
export interface ScanResult {
  summary: ScanSummary;
  findings: SecretFinding[];
}
