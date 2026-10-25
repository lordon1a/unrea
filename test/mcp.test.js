import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

import { fake, makeTemp, writeAt } from './helpers.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(root, 'bin', 'unrea.js');
const packageVersion = JSON.parse(
  readFileSync(path.join(root, 'package.json'), 'utf8'),
).version;

async function connect(t) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [cli, 'mcp'],
    cwd: root,
    stderr: 'pipe',
    env: { ...process.env },
  });
  let stderr = '';
  transport.stderr?.on('data', (chunk) => {
    stderr += chunk.toString();
  });

  const client = new Client(
    { name: 'unrea-test-client', version: '1.0.0' },
    { capabilities: {} },
  );
  t.after(async () => {
    await client.close().catch(() => {});
  });

  try {
    await client.connect(transport);
  } catch (error) {
    throw new Error(`MCP connection failed: ${error.message}\n${stderr}`);
  }
  return client;
}

function toolText(result, { allowError = false } = {}) {
  if (!allowError) {
    assert.ok(!result.isError, `tool returned an error: ${JSON.stringify(result)}`);
  }
  const item = result.content.find((entry) => entry.type === 'text');
  assert.ok(item, 'tool result has no text content');
  return item.text;
}

test('MCP lists tools, scans, caps and keeps secrets masked', { timeout: 30000 }, async (t) => {
  const dir = await makeTemp('unrea-mcp-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  const secret = fake.openai();
  await writeAt(dir, '.env', `OPENAI_API_KEY=${secret}\n`);

  const client = await connect(t);
  const server = client.getServerVersion();
  assert.equal(server.name, 'unrea');
  assert.equal(server.version, packageVersion);

  const { tools } = await client.listTools();
  assert.deepEqual(
    tools.map((tool) => tool.name).sort(),
    ['unrea_explain', 'unrea_fix_plan', 'unrea_scan'],
  );

  const scanResult = await client.callTool({
    name: 'unrea_scan',
    arguments: { path: dir },
  });
  const text = toolText(scanResult);
  const payload = JSON.parse(text);
  assert.equal(payload.grade, 'F');
  assert.equal(payload.mode, 'build');
  assert.equal(payload.scanned, 1);
  assert.equal(payload.summary.critical, 2); // env.file + secret.openai
  assert.equal(payload.truncated, false);
  assert.ok(Array.isArray(payload.top_fixes));
  assert.ok(payload.findings.some((finding) => finding.id === 'secret.openai'));
  assert.ok(!text.includes(secret), 'MCP scan response leaked the full secret');

  const cappedResult = await client.callTool({
    name: 'unrea_scan',
    arguments: { path: dir, min_severity: 'info', max_findings: 1 },
  });
  const capped = JSON.parse(toolText(cappedResult));
  assert.equal(capped.findings.length, 1);
  assert.equal(capped.truncated, true);
  assert.equal(capped.grade, 'F');

  const zeroResult = await client.callTool({
    name: 'unrea_scan',
    arguments: { path: dir, min_severity: 'info', max_findings: 0 },
  });
  const zero = JSON.parse(toolText(zeroResult));
  assert.equal(zero.findings.length, 0);
  assert.equal(zero.truncated, true);

  const highOnly = await client.callTool({
    name: 'unrea_scan',
    arguments: { path: dir, min_severity: 'critical' },
  });
  const critical = JSON.parse(toolText(highOnly));
  assert.equal(critical.findings.length, 2);
  assert.ok(critical.findings.every((finding) => finding.severity === 'critical'));
});

test('MCP explains known ids and lists known ids for unknown ones', { timeout: 30000 }, async (t) => {
  const client = await connect(t);

  const known = toolText(
    await client.callTool({ name: 'unrea_explain', arguments: { id: 'secret.openai' } }),
  );
  assert.match(known, /secret\.openai/);
  assert.match(known, /How an agent finds it:/);
  assert.match(known, /asar/i);
  assert.match(known, /Real risk:/);
  assert.match(known, /How to fix:/);

  const family = toolText(
    await client.callTool({ name: 'unrea_explain', arguments: { id: 'electron.fuses.*' } }),
  );
  assert.match(family, /Weak Electron fuses/);

  const alias = toolText(
    await client.callTool({ name: 'unrea_explain', arguments: { id: 'electron.fuses' } }),
  );
  assert.match(alias, /Weak Electron fuses/);

  const unknown = toolText(
    await client.callTool({ name: 'unrea_explain', arguments: { id: 'not.a.check' } }),
  );
  assert.match(unknown, /Unknown check id/);
  assert.match(unknown, /secret\.openai/);
  assert.match(unknown, /tests\.shipped/);
});

test('MCP fix plan detects electron-builder and returns apply-ready text', { timeout: 30000 }, async (t) => {
  const dir = await makeTemp('unrea-mcp-plan-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'package.json', JSON.stringify({ build: { appId: 'com.example.app' } }, null, 2));

  const client = await connect(t);

  const testsPlan = toolText(
    await client.callTool({
      name: 'unrea_fix_plan',
      arguments: { path: dir, id: 'tests.shipped' },
    }),
  );
  assert.match(testsPlan, /Detected electron-builder config/);
  assert.match(testsPlan, /!test\/\*\*/);
  assert.match(testsPlan, /!\*\*\/\*\.test\.\*/);
  assert.match(testsPlan, /!e2e\/\*\*/);
  assert.match(testsPlan, /\.npmignore/);

  const fusePlan = toolText(
    await client.callTool({
      name: 'unrea_fix_plan',
      arguments: { path: dir, id: 'electron.fuses.run_as_node' },
    }),
  );
  assert.match(fusePlan, /flipFuses/);
  assert.match(fusePlan, /afterPack/);
  assert.match(fusePlan, /RunAsNode/);
  assert.match(fusePlan, /@electron\/fuses/);

  const mapPlan = toolText(
    await client.callTool({
      name: 'unrea_fix_plan',
      arguments: { path: dir, id: 'sourcemap.file' },
    }),
  );
  assert.match(mapPlan, /sourcemap=false/);
  assert.match(mapPlan, /!\*\*\/\*\.map/);

  const unknown = await client.callTool({
    name: 'unrea_fix_plan',
    arguments: { path: dir, id: 'nope' },
  });
  assert.equal(unknown.isError, true);
  assert.match(toolText(unknown, { allowError: true }), /Known ids:/);
});
