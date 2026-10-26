import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { loadAcceptConfig } from '../src/core/accept.js';
import { buildResult, failsThreshold, formatText } from '../src/report.js';
import { scan } from '../src/scan.js';
import { fake, makeTemp, writeAt } from './helpers.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(root, 'bin', 'unrea.js');

test('an accepted finding stays in JSON but leaves grade and fail-on', async (t) => {
  const dir = await makeTemp('unrea-accept-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'app.js.map', '{"version":3}\n');
  await writeAt(
    dir,
    '.unrea.json',
    JSON.stringify({
      accept: [
        { id: 'sourcemap.file', reason: 'source maps are published on purpose', path: '*.map' },
      ],
    }),
  );

  const scanned = await scan(dir);
  const result = buildResult(scanned);
  const finding = result.findings.find((entry) => entry.id === 'sourcemap.file');

  assert.ok(finding);
  assert.equal(finding.accepted, true);
  assert.equal(finding.reason, 'source maps are published on purpose');
  assert.equal(result.grade, 'A');
  assert.equal(failsThreshold(scanned.findings, 'high'), false);
  assert.equal(scanned.accept.accepted, 1);

  const text = formatText(result, { target: dir });
  assert.match(text, /ACCEPTED \(1\)/);
  assert.match(
    text,
    /sourcemap\.file\s+app\.js\.map:1\s+reason: source maps are published on purpose/,
  );
  assert.doesNotMatch(text, /HIGH \(\d+\)/);
  assert.match(text, /critical: 0, high: 0, medium: 0, info: 0/);

  const run = spawnSync(process.execPath, [cli, 'scan', dir, '--json'], { encoding: 'utf8' });
  assert.equal(run.status, 0, 'an accepted high finding must not trip --fail-on high');
  const parsed = JSON.parse(run.stdout);
  assert.equal(parsed.grade, 'A');
  assert.equal(parsed.findings.find((entry) => entry.id === 'sourcemap.file').accepted, true);
});

test('an accept entry without a reason is a clear usage error', async (t) => {
  const dir = await makeTemp('unrea-accept-noreason-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'app.js.map', '{"version":3}\n');
  await writeAt(dir, '.unrea.json', JSON.stringify({ accept: [{ id: 'sourcemap.file' }] }));

  await assert.rejects(() => scan(dir), /needs a non-empty "reason"/);

  const run = spawnSync(process.execPath, [cli, 'scan', dir, '--json'], { encoding: 'utf8' });
  assert.equal(run.status, 2);
  assert.match(run.stderr, /accept\[0\] \(sourcemap\.file\) needs a non-empty "reason"/);
  assert.match(run.stderr, /conscious decision/);
});

test('config validation explains invalid JSON, bad shapes and missing files', async (t) => {
  const dir = await makeTemp('unrea-accept-invalid-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  await writeAt(dir, 'broken.json', '{"accept": [');
  await assert.rejects(
    () => loadAcceptConfig({ target: dir, configPath: 'broken.json', cwd: dir }),
    /invalid JSON/,
  );

  await writeAt(dir, 'shape.json', '{"accept":"nope"}');
  await assert.rejects(
    () => loadAcceptConfig({ target: dir, configPath: 'shape.json', cwd: dir }),
    /"accept" must be an array/,
  );

  await writeAt(dir, 'empty-path.json', '{"accept":[{"id":"x.y","reason":"why","path":""}]}');
  await assert.rejects(
    () => loadAcceptConfig({ target: dir, configPath: 'empty-path.json', cwd: dir }),
    /"path" must be a non-empty glob string/,
  );

  await assert.rejects(
    () => loadAcceptConfig({ target: dir, configPath: 'missing.json', cwd: dir }),
    /config file not found/,
  );
});

test('critical secrets can never be accepted', async (t) => {
  const dir = await makeTemp('unrea-accept-secret-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  const secret = fake.openai();
  await writeAt(dir, '.env', `OPENAI_API_KEY=${secret}\n`);
  await writeAt(
    dir,
    '.unrea.json',
    JSON.stringify({ accept: [{ id: 'secret.*', reason: 'this is only a fixture' }] }),
  );

  const scanned = await scan(dir);
  const finding = scanned.findings.find((entry) => entry.id === 'secret.openai');

  assert.ok(finding);
  assert.equal(finding.severity, 'critical');
  assert.ok(!('accepted' in finding), 'a critical secret must stay counted');
  assert.equal(scanned.accept.accepted, 0);
  assert.match(scanned.accept.warnings[0], /cannot accept secret\.openai/);
  assert.match(scanned.accept.warnings[0], /must be rotated, not accepted/);
  assert.equal(buildResult(scanned).grade, 'F');
  assert.equal(failsThreshold(scanned.findings, 'critical'), true);

  const run = spawnSync(process.execPath, [cli, 'scan', dir, '--json'], { encoding: 'utf8' });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /warning: cannot accept secret\.openai/);
  assert.ok(!run.stdout.includes(secret), 'JSON output leaked the full secret');
  const parsed = JSON.parse(run.stdout);
  assert.ok(!parsed.findings.find((entry) => entry.id === 'secret.openai').accepted);
});

test('--config can scope an accept entry to one path', async (t) => {
  const dir = await makeTemp('unrea-accept-path-');
  const configDir = await makeTemp('unrea-accept-config-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  t.after(() => rm(configDir, { recursive: true, force: true }));

  await writeAt(dir, 'dist/a.js.map', '{"version":3}\n');
  await writeAt(dir, 'dist/b.js.map', '{"version":3}\n');
  const config = await writeAt(
    configDir,
    'accept.json',
    JSON.stringify({
      accept: [{ id: 'sourcemap.file', reason: 'only a is public', path: 'dist/a.js.map' }],
    }),
  );

  const scanned = await scan(dir, { config });
  const a = scanned.findings.find((entry) => entry.file === 'dist/a.js.map');
  const b = scanned.findings.find((entry) => entry.file === 'dist/b.js.map');

  assert.equal(a.accepted, true);
  assert.ok(!('accepted' in b), 'the path glob must not accept the other file');
  assert.equal(buildResult(scanned).grade, 'D');

  const run = spawnSync(process.execPath, [cli, 'scan', dir, '--config', config, '--json'], {
    encoding: 'utf8',
  });
  assert.equal(run.status, 1);
  const parsed = JSON.parse(run.stdout);
  assert.equal(parsed.findings.find((entry) => entry.file === 'dist/a.js.map').accepted, true);
  assert.ok(!('accepted' in parsed.findings.find((entry) => entry.file === 'dist/b.js.map')));
});

test('a .unrea.json in the current directory is used when the target has none', async (t) => {
  const cwd = await makeTemp('unrea-accept-cwd-');
  const target = await makeTemp('unrea-accept-cwd-target-');
  t.after(() => rm(cwd, { recursive: true, force: true }));
  t.after(() => rm(target, { recursive: true, force: true }));

  await writeAt(target, 'app.js.map', '{"version":3}\n');
  await writeAt(
    cwd,
    '.unrea.json',
    JSON.stringify({ accept: [{ id: 'sourcemap.file', reason: 'maps are public' }] }),
  );

  const run = spawnSync(process.execPath, [cli, 'scan', target, '--json'], {
    cwd,
    encoding: 'utf8',
  });
  assert.equal(run.status, 0);
  const parsed = JSON.parse(run.stdout);
  assert.equal(parsed.grade, 'A');
  assert.equal(parsed.findings.find((entry) => entry.id === 'sourcemap.file').accepted, true);
});
