import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import test from 'node:test';

import { scan } from '../src/scan.js';
import { fakeFuseBinary, makeTemp, writeAt } from './helpers.mjs';

const STATES = [true, false, true, true, false, false, false, false];

function fuseIds(result, file) {
  return result.findings
    .filter((finding) => finding.id.startsWith('electron.fuses.') && finding.file === file)
    .map((finding) => finding.id)
    .sort();
}

const EXPECTED = [
  'electron.fuses.asar_integrity',
  'electron.fuses.node_cli_inspect',
  'electron.fuses.node_options',
  'electron.fuses.only_load_app_from_asar',
  'electron.fuses.run_as_node',
];

test('finds a macOS Contents/MacOS binary with a local fuse wire', async (t) => {
  const dir = await makeTemp('unrea-fuse-mac-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  const binary = 'MyApp.app/Contents/MacOS/MyApp';
  await writeAt(dir, binary, fakeFuseBinary(STATES));

  const result = await scan(dir);
  assert.deepEqual(fuseIds(result, binary), EXPECTED);
});

test('finds a Linux extensionless binary next to resources/app.asar', async (t) => {
  const dir = await makeTemp('unrea-fuse-linux-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'linux/MyApp', fakeFuseBinary(STATES));
  await writeAt(dir, 'linux/resources/app.asar', Buffer.from('not a real asar'));

  const result = await scan(dir);
  assert.deepEqual(fuseIds(result, 'linux/MyApp'), EXPECTED);
});
