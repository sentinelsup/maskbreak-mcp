# Maskbreak MCP Server

Look up limited public IP intelligence — cloud-hosting ranges and Tor exit nodes — from Claude, Cursor, or another MCP client. Powered by the [Maskbreak](https://maskbreak.com) fraud detection API. Requires Node.js 18+ for the local server.

## Tools

| Tool | What it does |
|------|--------------|
| `lookup_ip` | Public IPv4/IPv6 lookup: `known`, `allow` / `review` / `block`, risk score, and nullable signal/network metadata. Public-feed coverage is limited to cloud hosting and Tor. |
| `service_status` | Maskbreak API health, uptime, and latency |

## Setup

Grab a free API key at [maskbreak.com/signup](https://maskbreak.com/signup) (1,000 lookups/hour, shared with evaluations, no card). Keyless mode uses the free web-tool endpoint, limited to 12 lookups/minute and 80/day per caller IP. Additional endpoint and abuse-protection limits can apply.

Neither mode performs a browser visit. VPN/proxy and device evidence require a browser-SDK-backed `/v1/evaluate` request outside these tools; service names are available only when known. Unknown IPs, false signals and `allow` verdicts are not proof of safety.

### Claude Code

```bash
claude mcp add sentinel -e SENTINEL_API_KEY=sk_live_your_key -- npx -y @sentinelsup/mcp
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "npx",
      "args": ["-y", "@sentinelsup/mcp"],
      "env": { "SENTINEL_API_KEY": "sk_live_your_key" }
    }
  }
}
```

### Cursor / other MCP clients

Any client that speaks stdio MCP works the same way: command `npx`, args `["-y", "@sentinelsup/mcp"]`, env `SENTINEL_API_KEY`.

### Hosted endpoint (no install)

Prefer a remote server? The same tools are hosted at **`https://maskbreak.com/mcp`** (Streamable HTTP). Point any URL-based MCP client at it; pass your API key as an `Authorization: Bearer` header for full quota.

## Example

> "What public-feed evidence is available for this IP?"

Illustrative unknown-IP response, not a live lookup:

```json
{
  "ip": "192.0.2.1",
  "known": false,
  "verdict": "allow",
  "risk_score": 0,
  "signals": null,
  "network": null
}
```

## Environment

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `SENTINEL_API_KEY` | recommended | — | API key from your [dashboard](https://maskbreak.com/dashboard); unlocks 1,000 lookups/hour |
| `SENTINEL_BASE_URL` | no | `https://maskbreak.com` | Override for testing |

## Failures and local checks

Both tools return MCP `isError: true` for HTTP failures, malformed responses or requests that exceed the five-second timeout (including body reads). An unavailable lookup is not an allow decision.

```bash
npm ci --ignore-scripts
npm test
npm pack --dry-run --ignore-scripts
npm audit
```

Tests use a real stdio MCP client with loopback HTTP fixtures, without production keys. CI checks Node.js 18, 22 and 24. No package is published by these checks.

## Links

- [API docs](https://maskbreak.com/api)
- [Node SDK](https://github.com/sentinelsup/maskbreak-node) · [Python SDK](https://pypi.org/project/sentinelsup/)
- [Status](https://maskbreak.com/status)

MIT © Sentinel Edge Networks LTD
