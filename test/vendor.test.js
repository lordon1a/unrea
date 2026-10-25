import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import test from 'node:test';

import { scan } from '../src/scan.js';
import { fake, makeTemp, writeAt } from './helpers.mjs';

async function buildVendorFixture() {
  const dir = await makeTemp('unrea-vendor-');
  await writeAt(dir, 'src/main.js', `const key = "${fake.openai()}";\n`);
  await writeAt(
    dir,
    'app/vendor/lib.js',
    `const aws = "${fake.aws()}";\n//# sourceMappingURL=lib.js.map\n`,
  );
  await writeAt(
    dir,
    'node_modules/jose/key.js',
    '-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n',
  );
  await writeAt(
    dir,
    'node_modules/pkg/index.js',
    `const google = "${fake.google()}";\n`,
  );
  await writeAt(dir, 'dist/app.js', '//# sourceMappingURL=app.js.map\nconsole.log(1);\n');

  const bigLine = `const a = 1; // ${'x'.repeat(100)}\n`;
  await writeAt(dir, 'app/vendor/large.js', bigLine.repeat(201));
  await writeAt(dir, 'app/vendor/large.js.map', '{"version":3}\n');

  return dir;
}

test('vendor provider keys and PEM become info with a vendor prefix', async (t) => {
  const dir = await buildVendorFixture();
  t.after(() => rm(dir, { recursive: true, force: true }));

  const result = await scan(dir);
  const byFile = (file, id) => result.findings.find((f) => f.file === file && f.id === id);

  const normal = byFile('src/main.js', 'secret.openai');
  assert.equal(normal.severity, 'critical', 'non-vendor secrets keep their real severity');

  const vendorAws = byFile('app/vendor/lib.js', 'secret.aws');
  assert.equal(vendorAws.severity, 'info');
  assert.match(vendorAws.snippet, /^\[vendor code\] /);
  assert.ok(!vendorAws.snippet.includes(fake.aws()));

  const vendorPem = byFile('node_modules/jose/key.js', 'secret.private_key');
  assert.equal(vendorPem.severity, 'info');
  assert.match(vendorPem.snippet, /^\[vendor code\] /);

  const vendorGoogle = byFile('node_modules/pkg/index.js', 'secret.google');
  assert.equal(vendorGoogle.severity, 'info');
  assert.match(vendorGoogle.snippet, /^\[vendor code\] /);
});

test('vendor paths skip readable-code and downgrade source map comments', async (t) => {
  const dir = await buildVendorFixture();
  t.after(() => rm(dir, { recursive: true, force: true }));

  const result = await scan(dir);
  const readable = result.findings.filter((f) => f.id === 'code.readable');
  assert.equal(readable.length, 0, 'vendor files must not produce code.readable');

  const vendorComment = result.findings.find(
    (f) => f.id === 'sourcemap.comment' && f.file === 'app/vendor/lib.js',
  );
  assert.equal(vendorComment.severity, 'info');

  const appComment = result.findings.find(
    (f) => f.id === 'sourcemap.comment' && f.file === 'dist/app.js',
  );
  assert.equal(appComment.severity, 'medium', 'non-vendor source map comments stay medium');

  const vendorMap = result.findings.find(
    (f) => f.id === 'sourcemap.file' && f.file === 'app/vendor/large.js.map',
  );
  assert.equal(vendorMap.severity, 'high', 'only sourcemap.comment is vendor-downgraded');
});
