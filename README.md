# Maskbreak MCP Server

Check any IP address for fraud signals — VPN, proxy, Tor, datacenter hosting, anonymity — straight from Claude, Cursor, or any MCP client. Powered by the [Maskbreak](https://maskbreak.com) fraud detection API.

## Tools

| Tool | What it does |
|------|--------------|
| `lookup_ip` | Verdict for any public IPv4/IPv6: `allow` / `review` / `block`, 0–100 risk score, VPN/proxy/Tor/datacenter/anonymity signals, ASN + org + country |
| `service_status` | Maskbreak API health, uptime, and latency |

## Setup

Grab a free API key at [maskbreak.com/signup](https://maskbreak.com/signup) (1,000 lookups/hour, no card). The server also works without a key for a few lookups per minute — enough to try it.

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

> "Is 185.220.101.34 safe to allow through signup?"

```json
{
  "ip": "185.220.101.34",
  "known": true,
  "verdict": "block",
  "risk_score": 90,
  "signals": { "vpn": false, "proxied": false, "tor": true, "dch": true, "anon": true },
  "network": { "asn": 205100, "org": "F3 Netze e.V.", "country": "DE" }
}
```

## Environment

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `SENTINEL_API_KEY` | recommended | — | API key from your [dashboard](https://maskbreak.com/dashboard); unlocks 1,000 lookups/hour |
| `SENTINEL_BASE_URL` | no | `https://maskbreak.com` | Override for testing |

## Links

- [API docs](https://maskbreak.com/api)
- [Node SDK](https://github.com/sentinelsup/maskbreak-node) · [Python SDK](https://pypi.org/project/sentinelsup/)
- [Status](https://maskbreak.com/status)

MIT © Sentinel Edge Networks LTD
