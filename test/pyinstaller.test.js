import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import test from 'node:test';

import { scan } from '../src/scan.js';
import { explain } from '../src/explain.js';
import { buildFixPlan } from '../src/fix-plan.js';
import { makeTemp, writeAt } from './helpers.mjs';

const ALL_IDS = [
  'pyinstaller.bytecode',
  'pyinstaller.source_shipped',
  'pyinstaller.spec_shipped',
  'pyinstaller.python_version',
];

function byId(findings, id) {
  return findings.filter((finding) => finding.id === id);
}

async function onedirFixture() {
  const dir = await makeTemp('unrea-pyinstaller-onedir-');
  await writeAt(dir, 'MyApp.exe', Buffer.alloc(128, 0x90));
  await writeAt(dir, '_internal/base_library.zip', Buffer.from('PK\u0003\u0004'));
  await writeAt(dir, '_internal/python311.dll', Buffer.alloc(16, 0));
  await writeAt(dir, '_internal/app.py', 'print("hello")\n');
  await writeAt(dir, '_internal/helpers/util.py', 'def helper():\n    return 1\n');
  await writeAt(dir, '_internal/numpy/__init__.py', '');
  await writeAt(dir, '_internal/numpy/core.py', '');
  await writeAt(dir, '_internal/site-packages/requests/api.py', '');
  await writeAt(dir, 'MyApp.spec', '# -*- mode: python -*-\n');
  return dir;
}

test('detects an onedir build and reports bytecode, loose source, spec and version', async (t) => {
  const dir = await onedirFixture();
  t.after(() => rm(dir, { recursive: true, force: true }));

  const result = await scan(dir);
  assert.ok(result.surfaces.includes('pyinstaller'));

  const bytecode = byId(result.findings, 'pyinstaller.bytecode');
  assert.equal(bytecode.length, 1);
  assert.equal(bytecode[0].severity, 'high');
  assert.equal(bytecode[0].file, 'MyApp.exe');
  assert.match(bytecode[0].snippet, /PyInstaller build found/);
  assert.match(bytecode[0].snippet, /_internal\/base_library\.zip/);

  const source = byId(result.findings, 'pyinstaller.source_shipped');
  assert.deepEqual(
    source.map((finding) => finding.file).sort(),
    ['_internal/app.py', '_internal/helpers/util.py'],
  );
  assert.ok(source.every((finding) => finding.severity === 'medium'));
  // Third-party package folders and site-packages are not app source.
  assert.ok(!source.some((finding) => finding.file.includes('numpy')));
  assert.ok(!source.some((finding) => finding.file.includes('site-packages')));

  const spec = byId(result.findings, 'pyinstaller.spec_shipped');
  assert.equal(spec.length, 1);
  assert.equal(spec[0].severity, 'medium');
  assert.equal(spec[0].file, 'MyApp.spec');

  const version = byId(result.findings, 'pyinstaller.python_version');
  assert.equal(version.length, 1);
  assert.equal(version[0].severity, 'info');
  assert.equal(version[0].file, '_internal/python311.dll');
  assert.match(version[0].snippet, /Python 3\.11/);
  assert.match(version[0].snippet, /end of life 2027-10-24/);
});

test('an end-of-life bundled runtime is medium severity', async (t) => {
  const dir = await makeTemp('unrea-pyinstaller-eol-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  await writeAt(dir, 'legacy/Tool.exe', Buffer.alloc(64, 0x90));
  await writeAt(dir, 'legacy/_internal/base_library.zip', Buffer.alloc(8));
  await writeAt(dir, 'legacy/_internal/python39.dll', Buffer.alloc(16, 0));

  const result = await scan(dir);
  const version = byId(result.findings, 'pyinstaller.python_version');
  assert.equal(version.length, 1);
  assert.equal(version[0].severity, 'medium');
  assert.equal(version[0].file, 'legacy/_internal/python39.dll');
  assert.match(version[0].snippet, /past end of life \(2025-10-31\)/);
  assert.match(version[0].snippet, /no longer receives security fixes/);
});

test('a shipped .pyz alone is detected, with no version or source guess', async (t) => {
  const dir = await makeTemp('unrea-pyinstaller-pyz-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  await writeAt(dir, 'bundle/tool.pyz', Buffer.from('PYZ\0payload'));

  const result = await scan(dir);
  assert.ok(result.surfaces.includes('pyinstaller'));

  const bytecode = byId(result.findings, 'pyinstaller.bytecode');
  assert.equal(bytecode.length, 1);
  assert.equal(bytecode[0].severity, 'high');
  assert.equal(bytecode[0].file, 'bundle/tool.pyz');
  assert.equal(byId(result.findings, 'pyinstaller.python_version').length, 0);
  assert.equal(byId(result.findings, 'pyinstaller.source_shipped').length, 0);
  assert.equal(byId(result.findings, 'pyinstaller.spec_shipped').length, 0);
});

test('an exe alone or a python DLL without an exe is not a PyInstaller build', async (t) => {
  const exeOnly = await makeTemp('unrea-pyinstaller-exe-');
  t.after(() => rm(exeOnly, { recursive: true, force: true }));
  await writeAt(exeOnly, 'launcher.exe', Buffer.alloc(64, 0x90));

  const exeResult = await scan(exeOnly);
  assert.ok(!exeResult.surfaces.includes('pyinstaller'));
  assert.equal(byId(exeResult.findings, 'pyinstaller.bytecode').length, 0);

  const dllOnly = await makeTemp('unrea-pyinstaller-dll-');
  t.after(() => rm(dllOnly, { recursive: true, force: true }));
  await writeAt(dllOnly, 'python311.dll', Buffer.alloc(16, 0));
  await writeAt(dllOnly, '_internal/readme.txt', 'not a build\n');

  const dllResult = await scan(dllOnly);
  assert.ok(!dllResult.surfaces.includes('pyinstaller'));
});

test('every pyinstaller id has explain text and a fix plan', async () => {
  for (const id of ALL_IDS) {
    const text = explain(id);
    assert.match(text, new RegExp(id.replace('.', '\\.')));
    assert.doesNotMatch(text, /Unknown check id/);

    const plan = await buildFixPlan(id, '.', { id });
    assert.equal(plan.ok, true, `${id} should resolve`);
    assert.match(plan.text, /Fix plan/);
  }

  const bytecodePlan = await buildFixPlan('pyinstaller.bytecode', '.', { id: 'pyinstaller.bytecode' });
  assert.match(bytecodePlan.text, /Nuitka/);
  assert.match(bytecodePlan.text, /Cython/);
  assert.match(bytecodePlan.text, /server/);
  assert.match(bytecodePlan.text, /removed the old bytecode encryption option/);
});
