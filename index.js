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

const BASE = (process.env.SENTINEL_BASE_URL || 'https://maskbreak.com').replace(/\/+$/, '');
const API_KEY = process.env.SENTINEL_API_KEY || '';
const TIMEOUT_MS = 5000;

async function requestJson(path, init = {}, keylessLookup = false) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${BASE}${path}`, {
      ...init,
      headers: { 'Accept': 'application/json', ...init.headers },
      signal: controller.signal
    });
    let data;
    try {
      data = await res.json();
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      data = null;
    }
    if (!res.ok) {
      const hint = keylessLookup && res.status === 429
        ? ' (keyless mode is tightly rate-limited — set SENTINEL_API_KEY for 1,000 lookups/hour; free key at https://maskbreak.com/signup)'
        : '';
      throw new Error(`${data?.error || `HTTP ${res.status}`}${hint}`);
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error('Invalid JSON response from Maskbreak API');
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error(`Maskbreak request timed out after ${TIMEOUT_MS}ms`);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function lookupIp(ip) {
  if (API_KEY) {
    return requestJson(`/v1/lookup/${encodeURIComponent(ip)}`, {
      headers: { 'Authorization': `Bearer ${API_KEY}` }
    });
  }
  return requestJson('/api/lookup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip })
  }, true);
}

function text(obj) {
  return { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
}

const server = new McpServer({ name: 'maskbreak', version: VERSION });

server.tool(
  'lookup_ip',
  'Look up limited public IP intelligence: cloud-hosting ranges and Tor exit nodes. Returns known, an allow/review/block verdict, a 0-100 risk score, and nullable signals/network metadata. Unknown or false signals do not establish safety. VPN/proxy and device evidence require a browser-SDK-backed visit via /v1/evaluate, which this tool does not perform.',
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
      return text(await requestJson('/api/status'));
    } catch (e) {
      return { ...text({ error: e.message }), isError: true };
    }
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
