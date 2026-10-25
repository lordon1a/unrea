import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import test from 'node:test';

import { createScanContext } from '../src/core/walk.js';
import { makeTemp, writeAt } from './helpers.mjs';

test('ctx exposes a shared lazy file view, rootFiles, has and readBytes', async (t) => {
  const dir = await makeTemp('unrea-context-');
  await writeAt(dir, 'src/main.js', 'export const ok = true;\n');
  await writeAt(dir, 'assets/blob.bin', Buffer.from([1, 2, 3, 4]));

  const { context, cleanup } = await createScanContext(dir);
  t.after(async () => {
    await cleanup();
    await rm(dir, { recursive: true, force: true });
  });

  assert.equal(Array.isArray(context.files), false);
  assert.equal(typeof context.files[Symbol.iterator], 'function');
  const files = [...context.files];
  const main = files.find((file) => file.displayPath === 'src/main.js');
  assert.ok(main);
  assert.equal(main.kind, 'text');
  assert.equal(main.text, 'export const ok = true;\n');
  assert.equal(main.inVendor, false);
  assert.equal(main.inTest, false);
  assert.equal(context.fileByPath.get('src/main.js'), main);

  assert.deepEqual(context.rootFiles, ['assets', 'src']);
  assert.equal(context.has('**/*.js'), true);
  assert.equal(context.has('assets/*.bin'), true);
  assert.equal(context.has('**/*.asar'), false);

  const bytes = await context.readBytes(main.absPath, 1, 4);
  assert.equal(bytes.toString('utf8'), 'xpor');
});
