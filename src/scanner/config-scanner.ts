/**
 * config-scanner.ts — Scan well-known credential file locations.
 *
 * Checks ~/.aws/credentials, ~/.ssh/*, ~/.docker/config.json, ~/.npmrc,
 * ~/.pypirc, ~/.netrc, ~/.config/gh/hosts.yml, ~/.kube/config, etc.
 */

import { readFile, readdir, access } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import type { SecretFinding, SecretSource } from "../types.js";
import { SECRET_PATTERNS, requiresKeyHint } from "./patterns.js";
import { redactValue } from "./env-scanner.js";

interface ConfigTarget {
  path: string;
  source: SecretSource;
  parser: (content: string, filePath: string) => SecretFinding[];
}

/** Check if a file exists and is readable */
async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/** Generic line-by-line secret scanner for config files */
function scanLines(
  content: string,
  filePath: string,
  source: SecretSource,
): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;

    for (const pattern of SECRET_PATTERNS) {
      if (requiresKeyHint(pattern)) {
        // For key-hint patterns, check if the line contains a relevant key
        if (!pattern.keyHint || !pattern.keyHint.test(line)) continue;
      }

      const match = line.match(pattern.regex);
      if (match) {
        findings.push({
          type: pattern.name,
          severity: pattern.severity,
          source,
          filePath,
          lineNumber: i + 1,
          context: line.split("=")[0]?.split(":")[0]?.trim().slice(0, 40) || "config value",
          redactedValue: redactValue(match[0]),
        });
        break;
      }
    }
  }

  return findings;
}

/** Parse AWS credentials file */
function parseAwsCredentials(content: string, filePath: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    const keyMatch = line.match(/^aws_access_key_id\s*=\s*(.+)/i);
    if (keyMatch && /^AKIA[0-9A-Z]{16}$/.test(keyMatch[1].trim())) {
      findings.push({
        type: "AWS Access Key ID",
        severity: "critical",
        source: "aws_credentials",
        filePath,
        lineNumber: i + 1,
        context: "aws_access_key_id",
        redactedValue: redactValue(keyMatch[1].trim()),
      });
    }

    const secretMatch = line.match(/^aws_secret_access_key\s*=\s*(.+)/i);
    if (secretMatch && secretMatch[1].trim().length >= 30) {
      findings.push({
        type: "AWS Secret Access Key",
        severity: "critical",
        source: "aws_credentials",
        filePath,
        lineNumber: i + 1,
        context: "aws_secret_access_key",
        redactedValue: redactValue(secretMatch[1].trim()),
      });
    }

    const sessionMatch = line.match(/^aws_session_token\s*=\s*(.+)/i);
    if (sessionMatch && sessionMatch[1].trim().length >= 20) {
      findings.push({
        type: "AWS Session Token",
        severity: "high",
        source: "aws_credentials",
        filePath,
        lineNumber: i + 1,
        context: "aws_session_token",
        redactedValue: redactValue(sessionMatch[1].trim()),
      });
    }
  }

  return findings;
}

/** Parse Docker config for auth tokens */
function parseDockerConfig(content: string, filePath: string): SecretFinding[] {
  const findings: SecretFinding[] = [];

  try {
    const config = JSON.parse(content);
    if (config.auths) {
      for (const [registry, authData] of Object.entries(config.auths)) {
        const data = authData as Record<string, unknown>;
        if (data.auth && typeof data.auth === "string" && data.auth.length > 10) {
          findings.push({
            type: "Docker Registry Auth Token",
            severity: "high",
            source: "docker_config",
            filePath,
            context: `registry: ${registry}`,
            redactedValue: redactValue(data.auth),
          });
        }
      }
    }

    if (config.credsStore) {
      // Not a leak per se, but useful to note
    }
  } catch {
    // Invalid JSON — scan as plain text
    return scanLines(content, filePath, "docker_config");
  }

  return findings;
}

/** Parse .npmrc for auth tokens */
function parseNpmrc(content: string, filePath: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // _authToken=npm_xxxxx
    if (line.includes("_authToken=") || line.includes("_auth=")) {
      const value = line.split("=").slice(1).join("=").trim();
      if (value && value.length > 5 && !value.startsWith("${")) {
        findings.push({
          type: "npm Auth Token",
          severity: "critical",
          source: "npm_config",
          filePath,
          lineNumber: i + 1,
          context: line.split("=")[0].trim(),
          redactedValue: redactValue(value),
        });
      }
    }
  }

  return findings;
}

/** Parse .netrc for machine credentials */
function parseNetrc(content: string, filePath: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = content.split("\n");
  let currentMachine = "";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const machineMatch = line.match(/^machine\s+(.+)/);
    if (machineMatch) {
      currentMachine = machineMatch[1];
    }

    const passMatch = line.match(/^password\s+(.+)/);
    if (passMatch && passMatch[1].trim().length > 3) {
      findings.push({
        type: "Netrc Password",
        severity: "high",
        source: "netrc",
        filePath,
        lineNumber: i + 1,
        context: `machine: ${currentMachine}`,
        redactedValue: redactValue(passMatch[1].trim()),
      });
    }
  }

  return findings;
}

/** Parse GitHub CLI hosts.yml */
function parseGhHosts(content: string, filePath: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const tokenMatch = line.match(/oauth_token:\s*(.+)/);
    if (tokenMatch && tokenMatch[1].trim().length > 10) {
      findings.push({
        type: "GitHub CLI OAuth Token",
        severity: "critical",
        source: "gh_cli",
        filePath,
        lineNumber: i + 1,
        context: "oauth_token",
        redactedValue: redactValue(tokenMatch[1].trim()),
      });
    }
  }

  return findings;
}

/** Scan SSH directory for private keys */
async function scanSshDir(): Promise<SecretFinding[]> {
  const sshDir = join(homedir(), ".ssh");
  const findings: SecretFinding[] = [];

  if (!(await fileExists(sshDir))) return findings;

  try {
    const entries = await readdir(sshDir);

    for (const entry of entries) {
      // Skip known non-key files
      if (entry.endsWith(".pub") || entry === "known_hosts" || entry === "config" ||
          entry === "authorized_keys" || entry === "known_hosts.old") {
        continue;
      }

      const filePath = join(sshDir, entry);
      try {
        const content = await readFile(filePath, "utf-8");

        if (content.includes("-----BEGIN") && content.includes("PRIVATE KEY")) {
          findings.push({
            type: "SSH Private Key",
            severity: "critical",
            source: "ssh_key",
            filePath,
            context: entry,
            redactedValue: "-----BEGIN **** PRIVATE KEY-----",
          });
        }
      } catch {
        // Can't read — skip
      }
    }
  } catch {
    // Can't read .ssh dir
  }

  return findings;
}

/** Main config scanner — checks all known credential locations */
export async function scanConfigFiles(): Promise<{ findings: SecretFinding[]; locationsChecked: number }> {
  const home = homedir();
  const allFindings: SecretFinding[] = [];
  let locationsChecked = 0;

  const targets: ConfigTarget[] = [
    {
      path: join(home, ".aws", "credentials"),
      source: "aws_credentials",
      parser: parseAwsCredentials,
    },
    {
      path: join(home, ".docker", "config.json"),
      source: "docker_config",
      parser: parseDockerConfig,
    },
    {
      path: join(home, ".npmrc"),
      source: "npm_config",
      parser: parseNpmrc,
    },
    {
      path: join(home, ".pypirc"),
      source: "pypi_config",
      parser: (content, fp) => scanLines(content, fp, "pypi_config"),
    },
    {
      path: join(home, ".netrc"),
      source: "netrc",
      parser: parseNetrc,
    },
    {
      path: join(home, ".config", "gh", "hosts.yml"),
      source: "gh_cli",
      parser: parseGhHosts,
    },
    {
      path: join(home, ".kube", "config"),
      source: "kube_config",
      parser: (content, fp) => scanLines(content, fp, "kube_config"),
    },
    {
      path: join(home, ".config", "gcloud", "application_default_credentials.json"),
      source: "gcloud_config",
      parser: (content, fp) => scanLines(content, fp, "gcloud_config"),
    },
  ];

  // Scan each config file
  for (const target of targets) {
    locationsChecked++;
    if (await fileExists(target.path)) {
      try {
        const content = await readFile(target.path, "utf-8");
        const findings = target.parser(content, target.path);
        allFindings.push(...findings);
      } catch {
        // Can't read — skip
      }
    }
  }

  // Scan SSH directory separately
  locationsChecked++;
  const sshFindings = await scanSshDir();
  allFindings.push(...sshFindings);

  return { findings: allFindings, locationsChecked };
}
