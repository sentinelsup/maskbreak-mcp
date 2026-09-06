import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const packageInfo = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
const lookup = { ip: '192.0.2.1', known: false, verdict: 'allow', risk_score: 0, signals: null, network: null };

// Real stdio MCP exchange, but HTTP stays on a loopback fixture. No live keys.
async function fixture(t, handler, { apiKey = '', trailingSlash = false } = {}) {
    const server = http.createServer(handler);
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });
    const transport = new StdioClientTransport({
        command: process.execPath,
        args: [fileURLToPath(new URL('./index.js', import.meta.url))],
        env: {
            SENTINEL_BASE_URL: `http://127.0.0.1:${server.address().port}${trailingSlash ? '/' : ''}`,
            SENTINEL_API_KEY: apiKey
        },
        stderr: 'pipe'
    });
    const client = new Client({ name: 'maskbreak-test', version: '1.0.0' });
    t.after(async () => {
        await client.close();
        server.closeAllConnections();
        await new Promise(resolve => server.close(resolve));
    });
    await client.connect(transport);
    return client;
}

function json(res, body, status = 200) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
}

test('stdio handshake, tool listing, and keyless lookup work', async t => {
    let request;
    const client = await fixture(t, (req, res) => {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            request = { method: req.method, url: req.url, auth: req.headers.authorization, body: JSON.parse(body) };
            json(res, lookup);
        });
    });
    assert.equal(client.getServerVersion().version, packageInfo.version);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map(tool => tool.name).sort(), ['lookup_ip', 'service_status']);
    assert.match(tools.find(tool => tool.name === 'lookup_ip').description, /Unknown or false signals do not establish safety/);
    const result = await client.callTool({ name: 'lookup_ip', arguments: { ip: ' 192.0.2.1 ' } });
    assert.notEqual(result.isError, true);
    assert.deepEqual(JSON.parse(result.content[0].text), lookup);
    assert.deepEqual(request, { method: 'POST', url: '/api/lookup', auth: undefined, body: { ip: '192.0.2.1' } });
});

test('keyed lookup uses bearer auth and accepts a trailing base URL slash', async t => {
    let request;
    const client = await fixture(t, (req, res) => {
        request = { method: req.method, url: req.url, auth: req.headers.authorization };
        json(res, lookup);
    }, { apiKey: 'local-fixture-key', trailingSlash: true });
    const result = await client.callTool({ name: 'lookup_ip', arguments: { ip: '192.0.2.1' } });
    assert.notEqual(result.isError, true);
    assert.deepEqual(request, { method: 'GET', url: '/v1/lookup/192.0.2.1', auth: 'Bearer local-fixture-key' });
});

test('service_status preserves the status response without forwarding credentials', async t => {
    const status = { status: 'operational', services: [], uptime: {} };
    let request;
    const client = await fixture(t, (req, res) => {
        request = { url: req.url, auth: req.headers.authorization };
        json(res, status);
    }, { apiKey: 'local-fixture-key' });
    const result = await client.callTool({ name: 'service_status', arguments: {} });
    assert.notEqual(result.isError, true);
    assert.deepEqual(JSON.parse(result.content[0].text), status);
    assert.deepEqual(request, { url: '/api/status', auth: undefined });
});

test('HTTP failures are MCP tool errors for both tools', async t => {
    for (const name of ['lookup_ip', 'service_status']) {
        await t.test(name, async t => {
            const client = await fixture(t, (_req, res) => json(res, { error: 'Temporarily unavailable' }, 503));
            const result = await client.callTool({ name, arguments: name === 'lookup_ip' ? { ip: '192.0.2.1' } : {} });
            assert.equal(result.isError, true);
            assert.match(JSON.parse(result.content[0].text).error, /Temporarily unavailable/);
        });
    }
});

test('keyless quota errors retain the API-key setup hint', async t => {
    const client = await fixture(t, (_req, res) => json(res, { error: 'Too many lookups' }, 429));
    const result = await client.callTool({ name: 'lookup_ip', arguments: { ip: '192.0.2.1' } });
    assert.equal(result.isError, true);
    assert.match(JSON.parse(result.content[0].text).error, /SENTINEL_API_KEY/);
});

test('malformed and non-object successful responses are tool errors', async t => {
    for (const name of ['lookup_ip', 'service_status']) {
        for (const body of ['<html>Unavailable</html>', 'null', '[]']) {
            await t.test(`${name}: ${body}`, async t => {
                const client = await fixture(t, (_req, res) => res.end(body));
                const result = await client.callTool({ name, arguments: name === 'lookup_ip' ? { ip: '192.0.2.1' } : {} });
                assert.equal(result.isError, true);
                assert.match(JSON.parse(result.content[0].text).error, /invalid JSON response/i);
            });
        }
    }
});

test('stalled headers and bodies produce bounded tool errors', { concurrency: true, timeout: 12000 }, async t => {
    await Promise.all(['lookup_ip', 'service_status'].map(name => t.test(name, async t => {
        const client = await fixture(t, (_req, res) => {
            if (name === 'service_status') {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.write('{');
            }
            // Leave either headers or body pending until the client's timeout.
        });
        const result = await client.callTool({ name, arguments: name === 'lookup_ip' ? { ip: '192.0.2.1' } : {} });
        assert.equal(result.isError, true);
        assert.match(JSON.parse(result.content[0].text).error, /timed out after 5000ms/);
    })));
});
