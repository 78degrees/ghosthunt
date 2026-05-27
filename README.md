# GhostHunt

Find every leaked secret on your machine.

GhostHunt is an MCP server that scans your development machine for API keys, tokens, and credentials hiding in places you forgot to check: `.env` files scattered across projects, shell history, AWS/SSH/Docker configs, and more.

**Everything runs locally. No data leaves your machine.**

## What It Scans

- **Environment files** — recursively finds every `.env`, `.env.local`, `.env.production`, etc. under your home directory
- **AWS credentials** — `~/.aws/credentials` and session tokens
- **SSH keys** — unprotected private keys in `~/.ssh/`
- **Docker config** — registry auth tokens in `~/.docker/config.json`
- **npm/PyPI tokens** — `~/.npmrc`, `~/.pypirc` auth tokens
- **GitHub CLI** — OAuth tokens in `~/.config/gh/hosts.yml`
- **Shell history** — API keys pasted into `bash`, `zsh`, or `fish` commands
- **Kubernetes** — `~/.kube/config` credentials
- **Netrc** — `~/.netrc` passwords
- **35+ secret patterns** — AWS, Stripe, GitHub, OpenAI, Anthropic, Google, Slack, Twilio, SendGrid, database connection strings, private keys, and more

## Install

### Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "ghosthunt": {
      "command": "npx",
      "args": ["-y", "ghosthunt"]
    }
  }
}
```

Restart Claude Desktop. Then ask Claude: **"Scan my machine for leaked secrets"**

### Direct Usage

```bash
npx ghosthunt
```

## Tools

### `scan_secrets`

Full detailed scan. Returns every finding with file paths, line numbers, severity ratings, and remediation steps.

**Example prompt:** "Run a full GhostHunt scan and show me everything"

### `scan_summary`

Quick health check. Returns your health score (0-100) and a count by severity. Run this first to see if you have a problem.

**Example prompt:** "Give me a quick GhostHunt health check"

## Example Output

```
# GhostHunt Scan Report

**Health Score: 37/100** (Critical)

- Secrets found: **12**
- Critical: 3 | High: 5 | Medium: 2 | Low: 2
- Locations scanned: 47
- Scan time: 142ms

## Environment Files (.env)

- **[CRITICAL]** Stripe Live Secret Key
  - File: `/Users/you/project-a/.env:4`
  - Context: `STRIPE_SECRET_KEY`
  - Value: `sk_l****_8xQ`

- **[CRITICAL]** OpenAI API Key
  - File: `/Users/you/side-project/.env.local:12`
  - Context: `OPENAI_API_KEY`
  - Value: `sk-p****kFJ9`

## Shell History

- **[HIGH]** Bearer Token in Header
  - File: `/Users/you/.zsh_history:8847`
  - Context: `curl -H "Authorization: Bearer sk_live_...`
  - Value: `sk_l****_m3K`

## Recommendations

1. **Rotate critical secrets immediately.** Any API key marked CRITICAL
   should be revoked and regenerated from the provider's dashboard.
2. **Clear your shell history** of sensitive commands.
3. **Audit your .env files.** Ensure they are in .gitignore.
```

## Health Score

Your score starts at 100 and drops based on what GhostHunt finds:

| Finding | Penalty |
|---------|---------|
| Critical secret | -15 |
| High severity | -8 |
| Medium severity | -3 |
| Low severity | -1 |

A score below 50 means you have secrets that need immediate attention.

## Privacy

GhostHunt runs entirely on your local machine. It does not:

- Send any data to any server
- Phone home or track usage
- Store scan results anywhere
- Access the internet

Your secrets stay on your machine. The scan results stay in your Claude conversation.

## License

MIT
