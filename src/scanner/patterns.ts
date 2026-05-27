/**
 * patterns.ts — Regex patterns for detecting API keys, tokens, and credentials.
 *
 * Each pattern includes:
 *   - name: Human-readable label for the secret type
 *   - regex: Pattern to match against values (not keys)
 *   - severity: How dangerous this secret is if leaked
 *   - keyHint: Optional regex to match against the variable/key name
 *              (boosts confidence when both key name and value match)
 */

import type { Severity } from "../types.js";

export interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  keyHint?: RegExp;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  // ── AWS ──────────────────────────────────────────────────────────────────
  {
    name: "AWS Access Key ID",
    regex: /\bAKIA[0-9A-Z]{16}\b/,
    severity: "critical",
    keyHint: /aws.?access.?key|aws.?key.?id/i,
  },
  {
    name: "AWS Secret Access Key",
    regex: /\b[A-Za-z0-9/+=]{40}\b/,
    severity: "critical",
    keyHint: /aws.?secret|aws.?secret.?access/i,
  },

  // ── Stripe ───────────────────────────────────────────────────────────────
  {
    name: "Stripe Live Secret Key",
    regex: /\bsk_live_[A-Za-z0-9]{24,}\b/,
    severity: "critical",
  },
  {
    name: "Stripe Live Publishable Key",
    regex: /\bpk_live_[A-Za-z0-9]{24,}\b/,
    severity: "medium",
  },
  {
    name: "Stripe Test Secret Key",
    regex: /\bsk_test_[A-Za-z0-9]{24,}\b/,
    severity: "low",
  },
  {
    name: "Stripe Restricted Key",
    regex: /\brk_live_[A-Za-z0-9]{24,}\b/,
    severity: "critical",
  },

  // ── GitHub ───────────────────────────────────────────────────────────────
  {
    name: "GitHub Personal Access Token (classic)",
    regex: /\bghp_[A-Za-z0-9]{36,}\b/,
    severity: "critical",
  },
  {
    name: "GitHub Fine-Grained Token",
    regex: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/,
    severity: "critical",
  },
  {
    name: "GitHub OAuth Access Token",
    regex: /\bgho_[A-Za-z0-9]{36,}\b/,
    severity: "high",
  },
  {
    name: "GitHub App Installation Token",
    regex: /\bghs_[A-Za-z0-9]{36,}\b/,
    severity: "high",
  },

  // ── GitLab ───────────────────────────────────────────────────────────────
  {
    name: "GitLab Personal Access Token",
    regex: /\bglpat-[A-Za-z0-9\-_]{20,}\b/,
    severity: "critical",
  },

  // ── OpenAI ───────────────────────────────────────────────────────────────
  {
    name: "OpenAI API Key",
    regex: /\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b/,
    severity: "critical",
  },
  {
    name: "OpenAI API Key (proj)",
    regex: /\bsk-proj-[A-Za-z0-9\-_]{40,}\b/,
    severity: "critical",
  },

  // ── Anthropic ────────────────────────────────────────────────────────────
  {
    name: "Anthropic API Key",
    regex: /\bsk-ant-[A-Za-z0-9\-_]{40,}\b/,
    severity: "critical",
  },

  // ── Google ───────────────────────────────────────────────────────────────
  {
    name: "Google API Key",
    regex: /\bAIza[A-Za-z0-9_\-]{35}\b/,
    severity: "high",
  },
  {
    name: "Google OAuth Client Secret",
    regex: /\bGOCSPX-[A-Za-z0-9_\-]{28,}\b/,
    severity: "high",
  },

  // ── Slack ────────────────────────────────────────────────────────────────
  {
    name: "Slack Bot Token",
    regex: /\bxoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}\b/,
    severity: "critical",
  },
  {
    name: "Slack User Token",
    regex: /\bxoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}\b/,
    severity: "critical",
  },
  {
    name: "Slack Webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
    severity: "high",
  },

  // ── Twilio ───────────────────────────────────────────────────────────────
  {
    name: "Twilio Auth Token",
    regex: /\b[a-f0-9]{32}\b/,
    severity: "high",
    keyHint: /twilio.?auth|twilio.?token/i,
  },
  {
    name: "Twilio Account SID",
    regex: /\bAC[a-f0-9]{32}\b/,
    severity: "medium",
  },

  // ── SendGrid ─────────────────────────────────────────────────────────────
  {
    name: "SendGrid API Key",
    regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/,
    severity: "critical",
  },

  // ── Mailgun ──────────────────────────────────────────────────────────────
  {
    name: "Mailgun API Key",
    regex: /\bkey-[A-Za-z0-9]{32}\b/,
    severity: "high",
    keyHint: /mailgun/i,
  },

  // ── npm ──────────────────────────────────────────────────────────────────
  {
    name: "npm Access Token",
    regex: /\bnpm_[A-Za-z0-9]{36}\b/,
    severity: "critical",
  },

  // ── PyPI ─────────────────────────────────────────────────────────────────
  {
    name: "PyPI API Token",
    regex: /\bpypi-[A-Za-z0-9_\-]{50,}\b/,
    severity: "critical",
  },

  // ── Heroku ───────────────────────────────────────────────────────────────
  {
    name: "Heroku API Key",
    regex: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/,
    severity: "high",
    keyHint: /heroku.?api|heroku.?key/i,
  },

  // ── DigitalOcean ─────────────────────────────────────────────────────────
  {
    name: "DigitalOcean Token",
    regex: /\bdop_v1_[a-f0-9]{64}\b/,
    severity: "critical",
  },

  // ── Supabase ─────────────────────────────────────────────────────────────
  {
    name: "Supabase Service Role Key",
    regex: /\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/,
    severity: "critical",
    keyHint: /supabase.?service|service.?role/i,
  },

  // ── Vercel ───────────────────────────────────────────────────────────────
  {
    name: "Vercel Token",
    regex: /\b[A-Za-z0-9]{24}\b/,
    severity: "high",
    keyHint: /vercel.?token|vercel.?api/i,
  },

  // ── Database connection strings ──────────────────────────────────────────
  {
    name: "Database Connection String (with password)",
    regex: /\b(?:postgres|mysql|mongodb|redis|amqp):\/\/[^:]+:[^@]+@[^\s"']+/i,
    severity: "critical",
  },

  // ── Private keys ─────────────────────────────────────────────────────────
  {
    name: "RSA Private Key",
    regex: /-----BEGIN RSA PRIVATE KEY-----/,
    severity: "critical",
  },
  {
    name: "OpenSSH Private Key",
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/,
    severity: "critical",
  },
  {
    name: "EC Private Key",
    regex: /-----BEGIN EC PRIVATE KEY-----/,
    severity: "critical",
  },
  {
    name: "PGP Private Key",
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    severity: "critical",
  },

  // ── Generic high-entropy patterns (matched only with key hints) ──────────
  {
    name: "Generic API Key",
    regex: /\b[A-Za-z0-9]{32,64}\b/,
    severity: "medium",
    keyHint: /api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret/i,
  },
  {
    name: "Generic Password",
    regex: /\b.{8,}\b/,
    severity: "high",
    keyHint: /^(?:password|passwd|pass|pwd|db_pass|database_password|mysql_pwd|pg_password|redis_password|admin_pass)$/i,
  },
];

/**
 * Patterns that require BOTH a key name hint AND a value match.
 * These patterns are too broad to use on values alone (would produce
 * false positives), so they only fire when the key/variable name also matches.
 */
export function requiresKeyHint(pattern: SecretPattern): boolean {
  return pattern.name.startsWith("Generic") ||
    pattern.name === "AWS Secret Access Key" ||
    pattern.name === "Twilio Auth Token" ||
    pattern.name === "Heroku API Key" ||
    pattern.name === "Vercel Token";
}
