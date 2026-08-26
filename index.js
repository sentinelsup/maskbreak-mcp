#!/usr/bin/env node
// Maskbreak MCP server — IP fraud intelligence for MCP clients (Claude Code,
// Claude Desktop, Cursor, ...). One stdio server, two tools.
//
// With SENTINEL_API_KEY set, lookups go through the authenticated API
// (GET /v1/lookup/{ip}, 1,000 req/hr on the free tier). Without a key they
// fall back to the free web-tool endpoint, which is fine for trying it out
// but rate-limited to a handful of lookups per minute.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { readFileSync } from 'node:fs';

// Read the version rather than hardcoding it — it had drifted to 0.1.0 while
// the package was 0.1.2, so every client saw the wrong version.
const { version: VERSION } = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf8')
);

const BASE = process.env.SENTINEL_BASE_URL || 'https://maskbreak.com';
const API_KEY = process.env.SENTINEL_API_KEY || '';

async function lookupIp(ip) {
  const opts = { headers: { 'Accept': 'application/json' } };
  let res;
  if (API_KEY) {
    res = await fetch(`${BASE}/v1/lookup/${encodeURIComponent(ip)}`, {
      ...opts,
      headers: { ...opts.headers, 'Authorization': `Bearer ${API_KEY}` }
    });
  } else {
    res = await fetch(`${BASE}/api/lookup`, {
      method: 'POST',
      headers: { ...opts.headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const hint = !API_KEY && res.status === 429
      ? ' (keyless mode is tightly rate-limited — set SENTINEL_API_KEY for 1,000 lookups/hour; free key at https://maskbreak.com/signup)'
      : '';
    throw new Error(`${data.error || `HTTP ${res.status}`}${hint}`);
  }
  return data;
}

function text(obj) {
  return { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
}

const server = new McpServer({ name: 'maskbreak', version: VERSION });

server.tool(
  'lookup_ip',
  'Check an IP address for fraud signals: VPN, proxy, Tor exit node, datacenter hosting, and anonymity. Returns an allow/review/block verdict, a 0-100 risk score, the individual signals, and network info (ASN, organization, country).',
  { ip: z.string().describe('Public IPv4 or IPv6 address to check, e.g. "185.220.101.34"') },
  async ({ ip }) => {
    try {
      return text(await lookupIp(ip.trim()));
    } catch (e) {
      return { ...text({ error: e.message }), isError: true };
    }
  }
);

server.tool(
  'service_status',
  'Current operational status of the Sentinel API: uptime, per-service health, and average latency.',
  {},
  async () => {
    try {
      const res = await fetch(`${BASE}/api/status`, { headers: { 'Accept': 'application/json' } });
      return text(await res.json());
    } catch (e) {
      return { ...text({ error: e.message }), isError: true };
    }
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
