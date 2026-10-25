import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { scan } from '../src/scan.js';
import { buildResult, formatText } from '../src/report.js';
import { fake, makeTemp, writeAt } from './helpers.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(root, 'bin', 'unrea.js');

async function makeSourceRepo() {
  const dir = await makeTemp('unrea-source-');
  await writeAt(dir, 'package.json', '{"name":"fixture-source"}\n');
  await writeAt(dir, 'src/main.js', 'export const ok = true;\n');
  await writeAt(dir, 'test/unit.test.js', `const awsFixture = "${fake.aws()}";\n`);
  await writeAt(dir, 'node_modules/pkg/index.js', `const key = "${fake.openai()}";\n`);
  return dir;
}

test('auto-detects a source repo, skips node_modules and tests.shipped', async (t) => {
  const dir = await makeSourceRepo();
  t.after(() => rm(dir, { recursive: true, force: true }));

  const result = await scan(dir);
  assert.equal(result.mode, 'source');
  assert.equal(result.scanned, 3); // package.json, src/main.js, test/unit.test.js
  assert.equal(result.findings.filter((f) => f.file.includes('node_modules')).length, 0);
  assert.equal(result.findings.filter((f) => f.id === 'tests.shipped').length, 0);

  const testSecret = result.findings.find((f) => f.id === 'secret.aws');
  assert.equal(testSecret.severity, 'info');
  assert.match(testSecret.snippet, /^\[test file, likely fixture\] /);

  const publicResult = buildResult(result);
  assert.equal(publicResult.mode, 'source');
  const text = formatText(publicResult, { target: dir });
  assert.match(text, /WARNING: this looks like a source folder/);
});

test('--build forces normal mode and restores vendor scanning', async (t) => {
  const dir = await makeSourceRepo();
  t.after(() => rm(dir, { recursive: true, force: true }));

  const result = await scan(dir, { mode: 'build' });
  assert.equal(result.mode, 'build');
  assert.ok(result.scanned > 3);
  assert.equal(result.findings.filter((f) => f.id === 'tests.shipped').length, 1);
  const vendorSecret = result.findings.find(
    (f) => f.id === 'secret.openai' && f.file === 'node_modules/pkg/index.js',
  );
  assert.ok(vendorSecret);
  assert.equal(vendorSecret.severity, 'info');
  assert.match(vendorSecret.snippet, /^\[vendor code\] /);
});

test('a root build artifact makes auto mode build; --source forces source', async (t) => {
  const dir = await makeTemp('unrea-source-build-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'package.json', '{"name":"fixture-with-exe"}\n');
  await writeAt(dir, 'src/main.js', 'export const ok = true;\n');
  await writeAt(dir, 'app.exe', Buffer.from('not an electron binary'));

  const auto = await scan(dir);
  assert.equal(auto.mode, 'build');

  const forced = await scan(dir, { mode: 'source' });
  assert.equal(forced.mode, 'source');
  assert.equal(forced.findings.filter((f) => f.id === 'tests.shipped').length, 0);
});

test('source markers and build markers at the root', async (t) => {
  const gitOnly = await makeTemp('unrea-source-git-');
  const win = await makeTemp('unrea-source-win-');
  const asar = await makeTemp('unrea-source-asar-');
  t.after(() => rm(gitOnly, { recursive: true, force: true }));
  t.after(() => rm(win, { recursive: true, force: true }));
  t.after(() => rm(asar, { recursive: true, force: true }));

  await writeAt(gitOnly, 'package.json', '{"name":"git-only"}\n');
  await writeAt(gitOnly, '.git/HEAD', 'ref: refs/heads/main\n');
  assert.equal((await scan(gitOnly)).mode, 'source');

  await writeAt(win, 'package.json', '{"name":"win"}\n');
  await writeAt(win, 'src/main.js', 'export const ok = true;\n');
  await writeAt(win, 'win-unpacked/placeholder.txt', 'build output\n');
  assert.equal((await scan(win)).mode, 'build');

  await writeAt(asar, 'package.json', '{"name":"asar"}\n');
  await writeAt(asar, 'src/main.js', 'export const ok = true;\n');
  await writeAt(asar, 'app.asar', Buffer.from('not a real asar'));
  assert.equal((await scan(asar)).mode, 'build');
});

test('CLI exposes mode, source warning and the force flags', async (t) => {
  const dir = await makeSourceRepo();
  t.after(() => rm(dir, { recursive: true, force: true }));

  const jsonRun = spawnSync(process.execPath, [cli, 'scan', dir, '--json'], {
    encoding: 'utf8',
  });
  assert.equal(jsonRun.status, 0);
  assert.equal(JSON.parse(jsonRun.stdout).mode, 'source');

  const textRun = spawnSync(process.execPath, [cli, 'scan', dir], { encoding: 'utf8' });
  assert.match(textRun.stdout, /WARNING: this looks like a source folder/);

  const buildRun = spawnSync(process.execPath, [cli, 'scan', dir, '--build', '--json'], {
    encoding: 'utf8',
  });
  assert.equal(JSON.parse(buildRun.stdout).mode, 'build');

  const sourceRun = spawnSync(process.execPath, [cli, 'scan', dir, '--source', '--json'], {
    encoding: 'utf8',
  });
  assert.equal(JSON.parse(sourceRun.stdout).mode, 'source');

  const conflict = spawnSync(process.execPath, [cli, 'scan', dir, '--source', '--build'], {
    encoding: 'utf8',
  });
  assert.equal(conflict.status, 2);
  assert.match(conflict.stderr, /only one of --source or --build/);
});
