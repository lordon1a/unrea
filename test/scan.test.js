import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createPackage } from '@electron/asar';

import { scan } from '../src/scan.js';
import { grade } from '../src/report.js';
import { fake, fakeFuseBinary, makeTemp, writeAt } from './helpers.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(root, 'bin', 'unrea.js');

async function buildFixture() {
  const dir = await makeTemp('unrea-build-');

  const appSrc = path.join(dir, 'app-src');
  await writeAt(appSrc, 'main.js', `const key = "${fake.openai()}";\n`);
  await writeAt(appSrc, 'package.json', '{"name":"fixture","version":"1.0.0"}\n');
  await writeAt(appSrc, 'app.js.map', '{"version":3,"sources":["app.js"]}\n');
  await writeAt(appSrc, 'node_modules/vendor/index.js', `const aws = "${fake.aws()}";\n`);
  await writeAt(appSrc, 'test/asar.test.mjs', `const awsFixture = "${fake.aws()}";\n`);

  await mkdir(path.join(dir, 'resources'), { recursive: true });
  await createPackage(appSrc, path.join(dir, 'resources', 'app.asar'));
  await rm(appSrc, { recursive: true, force: true });

  await writeAt(
    dir,
    'app.exe',
    // RunAsNode ENABLE, cookie off, NodeOptions ENABLE, NodeCli ENABLE,
    // asar integrity DISABLE, OnlyLoadAppFromAsar DISABLE.
    fakeFuseBinary([true, false, true, true, false, false, false, false]),
  );
  await writeAt(dir, 'junk.exe', Buffer.from('not an electron binary'));

  await writeAt(dir, 'dist/app.js', '//# sourceMappingURL=app.js.map\nconsole.log(1);\n');
  await writeAt(dir, 'dist/app.js.map', '{"version":3}\n');
  await writeAt(dir, 'endpoints.js', [
    "fetch('http://localhost:3000/api');",
    "fetch('https://dev.example.com/secret');",
    "fetch('https://api.example.com/v1');",
    '',
  ].join('\n'));

  const licenseLines = Array.from({ length: 7 }, (_, i) => `if (isPro && checkLicense(${i})) {}`).join('\n');
  await writeAt(dir, 'license.js', `${licenseLines}\n`);

  const bigLine = `const a = 1; // ${'x'.repeat(100)}\n`;
  await writeAt(dir, 'big.js', bigLine.repeat(201));

  await writeAt(dir, 'node_modules/pkg/index.js', `const token = "${fake.githubClassic()}";\n`);
  await writeAt(dir, 'test/loose.test.js', `const key = "${fake.openai()}";\n`);
  await writeAt(dir, 'node_modules/pkg/test/vendor.test.js', `const aws = "${fake.aws()}";\n`);

  return dir;
}

test('scans a built app directory including asar contents', async (t) => {
  const dir = await buildFixture();
  t.after(() => rm(dir, { recursive: true, force: true }));

  const result = await scan(dir);
  const byId = (id) => result.findings.filter((f) => f.id === id);

  assert.deepEqual(result.surfaces, ['electron', 'generic']);
  assert.ok(result.scanned >= 8, `expected several files scanned, got ${result.scanned}`);
  assert.equal(byId('asar.plain').length, 1);
  assert.equal(byId('asar.plain')[0].severity, 'info');

  const asarMain = result.findings.find(
    (f) => f.id === 'secret.openai' && f.file === 'resources/app.asar!/main.js',
  );
  assert.ok(asarMain, 'asar entry should use the app.asar!/path display form');
  assert.equal(asarMain.severity, 'critical');
  assert.ok(!asarMain.snippet.includes(fake.openai()));

  const vendor = result.findings.find(
    (f) => f.id === 'secret.aws' && f.file === 'resources/app.asar!/node_modules/vendor/index.js',
  );
  assert.ok(vendor);
  assert.equal(vendor.severity, 'info', 'vendor provider keys are informational');
  assert.match(vendor.snippet, /^\[vendor code\] /);

  const diskVendor = result.findings.find(
    (f) => f.id === 'secret.github' && f.file === 'node_modules/pkg/index.js',
  );
  assert.ok(diskVendor);
  assert.equal(diskVendor.severity, 'info', 'vendor provider keys are informational');
  assert.match(diskVendor.snippet, /^\[vendor code\] /);

  const shipped = byId('tests.shipped');
  assert.equal(shipped.length, 2, 'one tests.shipped per root and per asar');
  const rootShipped = shipped.find((f) => f.file === path.basename(dir));
  assert.ok(rootShipped, 'the scan root gets its own tests.shipped finding');
  assert.equal(rootShipped.severity, 'high');
  assert.match(rootShipped.snippet, /^1 test file ships in the build \(e\.g\. test\/loose\.test\.js\)$/);
  assert.equal(rootShipped.fix, 'exclude test folders from the package (electron-builder `files` / .npmignore)');
  const asarShipped = shipped.find((f) => f.file === 'resources/app.asar');
  assert.ok(asarShipped, 'the asar gets its own tests.shipped finding');
  assert.match(asarShipped.snippet, /app\.asar!\/test\/asar\.test\.mjs/);

  const asarTestSecret = result.findings.find(
    (f) => f.id === 'secret.aws' && f.file === 'resources/app.asar!/test/asar.test.mjs',
  );
  assert.ok(asarTestSecret);
  assert.equal(asarTestSecret.severity, 'info');
  assert.match(asarTestSecret.snippet, /^\[test file, likely fixture\] AWS access key: /);

  const looseTestSecret = result.findings.find(
    (f) => f.id === 'secret.openai' && f.file === 'test/loose.test.js',
  );
  assert.ok(looseTestSecret);
  assert.equal(looseTestSecret.severity, 'info');
  assert.match(looseTestSecret.snippet, /^\[test file, likely fixture\] OpenAI key: /);

  const vendorTestSecret = result.findings.find(
    (f) => f.id === 'secret.aws' && f.file === 'node_modules/pkg/test/vendor.test.js',
  );
  assert.ok(vendorTestSecret);
  assert.equal(vendorTestSecret.severity, 'info', 'node_modules test dirs are vendor, not test code');
  assert.match(vendorTestSecret.snippet, /^\[vendor code\] /);
  assert.ok(!vendorTestSecret.snippet.startsWith('[test file'));

  const fuses = result.findings.filter((f) => f.id.startsWith('electron.fuses.'));
  assert.deepEqual(
    fuses.map((f) => f.id).sort(),
    [
      'electron.fuses.asar_integrity',
      'electron.fuses.node_cli_inspect',
      'electron.fuses.node_options',
      'electron.fuses.only_load_app_from_asar',
      'electron.fuses.run_as_node',
    ],
  );
  assert.equal(fuses.find((f) => f.id === 'electron.fuses.run_as_node').severity, 'high');
  assert.equal(fuses.find((f) => f.id === 'electron.fuses.only_load_app_from_asar').severity, 'medium');

  assert.equal(byId('sourcemap.file').length, 2); // dist/app.js.map and inside the asar
  assert.equal(byId('sourcemap.comment').length, 1);
  assert.equal(byId('code.readable').length, 1);
  assert.equal(byId('license.client').length, 5, 'license findings are capped at 5 per file');
  assert.equal(byId('endpoint.internal').length, 2);

  const serialized = JSON.stringify(result);
  for (const secret of [fake.openai(), fake.aws(), fake.githubClassic()]) {
    assert.ok(!serialized.includes(secret), 'JSON output leaked a full secret');
  }
});

test('detects every test-path convention once per root, excluding node_modules', async (t) => {
  const dir = await makeTemp('unrea-tests-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'tests/a.js', 'export const a = 1;\n');
  await writeAt(dir, '__tests__/b.js', 'export const b = 1;\n');
  await writeAt(dir, 'e2e/c.js', 'export const c = 1;\n');
  await writeAt(dir, 'spec/d.js', 'export const d = 1;\n');
  await writeAt(dir, 'src/e.spec.ts', 'export const e = 1;\n');
  await writeAt(dir, 'src/f.test.mjs', 'export const f = 1;\n');
  await writeAt(dir, 'src/g.js', 'export const g = 1;\n');
  await writeAt(dir, 'test/fixture.bin', Buffer.from([0, 1, 2, 3]));
  await writeAt(dir, 'node_modules/pkg/test/vendor.test.js', 'export const v = 1;\n');

  const result = await scan(dir);
  const shipped = result.findings.filter((f) => f.id === 'tests.shipped');
  assert.equal(shipped.length, 1);
  assert.equal(shipped[0].file, path.basename(dir));
  assert.equal(shipped[0].severity, 'high');
  assert.match(shipped[0].snippet, /^7 test files ship in the build \(e\.g\. /);
  assert.equal(
    shipped[0].fix,
    'exclude test folders from the package (electron-builder `files` / .npmignore)',
  );
});

test('secret findings in test files are info and do not drive the grade', async (t) => {
  const dir = await makeTemp('unrea-test-secret-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'test/only.test.js', `const awsFixture = "${fake.aws()}";\n`);
  await writeAt(dir, 'src/main.js', 'export const ok = true;\n');

  const result = await scan(dir);
  const secret = result.findings.find((f) => f.id === 'secret.aws');
  assert.ok(secret);
  assert.equal(secret.id, 'secret.aws', 'id suffix is unchanged');
  assert.equal(secret.severity, 'info');
  assert.equal(secret.line, 1);
  assert.match(secret.snippet, /^\[test file, likely fixture\] /);

  const shipped = result.findings.find((f) => f.id === 'tests.shipped');
  assert.equal(shipped.severity, 'high');
  assert.equal(grade(result.findings.filter((f) => f.id !== 'tests.shipped')), 'A');
  assert.equal(grade(result.findings), 'D', 'tests.shipped is high, the fixture key is not critical');
});

test('test-looking paths inside node_modules stay vendor code', async (t) => {
  const dir = await makeTemp('unrea-vendor-tests-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'node_modules/pkg/test/vendor.test.js', `const aws = "${fake.aws()}";\n`);

  const result = await scan(dir);
  assert.equal(result.findings.filter((f) => f.id === 'tests.shipped').length, 0);
  const secret = result.findings.find((f) => f.id === 'secret.aws');
  assert.equal(secret.severity, 'info', 'vendor provider keys are informational');
  assert.match(secret.snippet, /^\[vendor code\] /);
  assert.ok(!secret.snippet.startsWith('[test file'));
});

test('accepts a single .asar file as the scan target', async (t) => {
  const dir = await makeTemp('unrea-single-asar-');
  const src = path.join(dir, 'src');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(src, 'main.js', `const ok = true;\n`);
  await writeAt(src, 'license.js', 'if (isPro) { open(); }\n');
  const archive = path.join(dir, 'app.asar');
  await createPackage(src, archive);
  await rm(src, { recursive: true, force: true });

  const result = await scan(archive);
  assert.ok(result.findings.some((f) => f.id === 'asar.plain' && f.file === 'app.asar'));
  assert.ok(
    result.findings.some((f) => f.id === 'license.client' && f.file === 'app.asar!/license.js'),
    'asar entries should be addressed as app.asar!/path',
  );
  assert.equal(result.scanned, 2);
});

test('CLI prints a graded report, JSON, and honors fail-on', async (t) => {
  const dir = await makeTemp('unrea-cli-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, '.env', `OPENAI_API_KEY=${fake.openai()}\n`);

  const textRun = spawnSync(process.execPath, [cli, 'scan', dir], { encoding: 'utf8' });
  assert.equal(textRun.status, 1);
  assert.match(textRun.stdout, /grade: F/);
  assert.match(textRun.stdout, /CRITICAL/);
  assert.ok(!textRun.stdout.includes(fake.openai()), 'text output leaked a full secret');

  const jsonRun = spawnSync(process.execPath, [cli, 'scan', dir, '--json'], { encoding: 'utf8' });
  assert.equal(jsonRun.status, 1);
  const parsed = JSON.parse(jsonRun.stdout);
  assert.deepEqual(Object.keys(parsed), [
    'grade',
    'scanned',
    'durationMs',
    'findings',
    'mode',
    'surfaces',
  ]);
  assert.equal(parsed.grade, 'F');
  assert.equal(parsed.mode, 'build');
  assert.deepEqual(parsed.surfaces, ['generic']);
  assert.ok(parsed.scanned >= 1);
  assert.ok(!jsonRun.stdout.includes(fake.openai()), 'JSON output leaked a full secret');

  const noneRun = spawnSync(process.execPath, [cli, 'scan', dir, '--json', '--fail-on', 'none'], {
    encoding: 'utf8',
  });
  assert.equal(noneRun.status, 0);

  const strictRun = spawnSync(process.execPath, [cli, 'scan', dir, '--fail-on', 'critical'], {
    encoding: 'utf8',
  });
  assert.equal(strictRun.status, 1, 'critical findings still fail the critical threshold');
});

test('CLI --verbose expands info rows while JSON stays complete', async (t) => {
  const dir = await makeTemp('unrea-cli-verbose-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'endpoints.js', [
    "fetch('http://localhost:3000/a');",
    "fetch('https://staging.example.com/b');",
    '',
  ].join('\n'));

  const plain = spawnSync(process.execPath, [cli, 'scan', dir], { encoding: 'utf8' });
  assert.equal(plain.status, 0);
  assert.match(plain.stdout, /endpoint\.internal x2 \(e\.g\. endpoints\.js:1\)/);
  assert.ok(!plain.stdout.includes('endpoints.js:2'), 'collapsed info hides later rows');

  const verbose = spawnSync(process.execPath, [cli, 'scan', dir, '--verbose'], { encoding: 'utf8' });
  assert.equal(verbose.status, 0);
  assert.ok(!verbose.stdout.includes('endpoint.internal x2'));
  assert.ok(verbose.stdout.includes('endpoints.js:2'));
  assert.match(verbose.stdout, /INFO\s+endpoints\.js:1/);

  const json = spawnSync(process.execPath, [cli, 'scan', dir, '--json'], { encoding: 'utf8' });
  const parsed = JSON.parse(json.stdout);
  assert.equal(parsed.findings.filter((f) => f.id === 'endpoint.internal').length, 2);
});

test('CLI rejects unknown flags and missing paths', () => {
  const badFlag = spawnSync(process.execPath, [cli, 'scan', '.', '--nope'], { encoding: 'utf8' });
  assert.equal(badFlag.status, 2);
  assert.match(badFlag.stderr, /unknown option/);

  const noPath = spawnSync(process.execPath, [cli, 'scan'], { encoding: 'utf8' });
  assert.equal(noPath.status, 2);

  const badFailOn = spawnSync(process.execPath, [cli, 'scan', '.', '--fail-on', 'info'], {
    encoding: 'utf8',
  });
  assert.equal(badFailOn.status, 2);
});
