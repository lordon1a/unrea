import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import test from 'node:test';

import { scan } from '../src/scan.js';
import { buildResult, formatText } from '../src/report.js';
import { explain } from '../src/explain.js';
import { buildFixPlan } from '../src/fix-plan.js';
import { makeTemp, writeAt } from './helpers.mjs';

const ALL_IDS = [
  'godot.config_shipped',
  'godot.encryption_unknown',
  'godot.encryption_off',
  'godot.directory_unencrypted',
  'godot.script_text',
  'godot.key_in_repo',
];

function byId(findings, id) {
  return findings.filter((finding) => finding.id === id);
}

async function projectFixture() {
  const dir = await makeTemp('unrea-godot-project-');
  await writeAt(dir, 'project.godot', 'config_version=5\n\n[application]\nconfig/name="Fixture"\n');
  await writeAt(
    dir,
    'export_presets.cfg',
    [
      '[preset.0]',
      '',
      'name="Windows Desktop"',
      'platform="Windows Desktop"',
      'runnable=true',
      'encrypt_pck=false',
      'encrypt_directory=false',
      '',
      '[preset.0.options]',
      '',
      'binary_format/embed_pck=false',
      'script_export_mode=2',
      '',
      '[preset.1]',
      '',
      'name="Linux"',
      'encrypt_pck=true',
      'encrypt_directory=false',
      '',
      '[preset.1.options]',
      '',
      'script_export_mode=0',
      '',
      '[preset.2]',
      '',
      'name="Web"',
      '',
      '[preset.2.options]',
      '',
      'script_export_mode=2',
      '',
    ].join('\n'),
  );
  return dir;
}

test('reads export_presets.cfg per preset and reports encryption gaps', async (t) => {
  const dir = await projectFixture();
  t.after(() => rm(dir, { recursive: true, force: true }));

  const result = await scan(dir);
  assert.ok(result.surfaces.includes('godot'));

  const off = byId(result.findings, 'godot.encryption_off');
  assert.equal(off.length, 2); // preset.0 has encrypt_pck=false, preset.2 does not set it
  assert.ok(off.every((finding) => finding.severity === 'high'));
  assert.ok(off.every((finding) => finding.file === 'export_presets.cfg'));
  assert.match(off[0].snippet, /"Windows Desktop"/);
  assert.match(off[0].snippet, /encrypt_pck=false/);
  assert.equal(off[0].line, 6);
  assert.match(off[1].snippet, /"Web"/);
  assert.match(off[1].snippet, /not set/);

  const directory = byId(result.findings, 'godot.directory_unencrypted');
  assert.equal(directory.length, 1);
  assert.equal(directory[0].severity, 'medium');
  assert.match(directory[0].snippet, /"Linux"/);
  assert.match(directory[0].snippet, /encrypt_directory=false/);
  assert.equal(directory[0].line, 18);

  const text = byId(result.findings, 'godot.script_text');
  assert.equal(text.length, 1);
  assert.equal(text[0].severity, 'medium');
  assert.match(text[0].snippet, /"Linux"/);
  assert.equal(text[0].line, 22);

  // No build artifact next to the project files, so nothing "shipped".
  assert.equal(byId(result.findings, 'godot.config_shipped').length, 0);
  assert.equal(byId(result.findings, 'godot.encryption_unknown').length, 0);
});

test('flags project config and GDScript left in a build folder, never opens the PCK', async (t) => {
  const dir = await makeTemp('unrea-godot-build-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  const buriedKey = 'SCRIPT_AES256_ENCRYPTION_KEY=' + 'ab'.repeat(32);
  await writeAt(dir, 'game/Game.exe', Buffer.alloc(64, 0x90));
  await writeAt(dir, 'game/game.pck', Buffer.concat([Buffer.from(buriedKey), Buffer.alloc(8)]));
  await writeAt(dir, 'game/project.godot', 'config_version=5\n');
  await writeAt(
    dir,
    'game/export_presets.cfg',
    [
      '[preset.0]',
      'name="Windows Desktop"',
      'encrypt_pck=true',
      'encrypt_directory=true',
      '',
      '[preset.0.options]',
      'script_export_mode=2',
      '',
    ].join('\n'),
  );
  await writeAt(dir, 'game/.godot/uid_cache.bin', Buffer.from([0, 1, 2]));
  await writeAt(dir, 'game/scripts/player.gd', 'extends Node\n');

  const result = await scan(dir);

  const shipped = byId(result.findings, 'godot.config_shipped');
  assert.equal(shipped.length, 1);
  assert.equal(shipped[0].severity, 'high');
  assert.equal(shipped[0].file, 'game');
  assert.match(shipped[0].snippet, /export_presets\.cfg/);
  assert.match(shipped[0].snippet, /project\.godot/);
  assert.match(shipped[0].snippet, /\.godot\//);
  assert.match(shipped[0].snippet, /1 \*\.gd source file/);

  const unknown = byId(result.findings, 'godot.encryption_unknown');
  assert.equal(unknown.length, 1);
  assert.equal(unknown[0].severity, 'info');
  assert.equal(unknown[0].file, 'game/game.pck');

  // The PCK is metadata only: its contents must never be parsed for secrets.
  assert.equal(byId(result.findings, 'godot.key_in_repo').length, 0);
  assert.ok(!JSON.stringify(result.findings).includes('ab'.repeat(32)));
});

test('critical when a 64-hex encryption key is committed, and the value is masked', async (t) => {
  const dir = await makeTemp('unrea-godot-key-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  const key = '0123456789abcdef'.repeat(4);
  const masked = `${key.slice(0, 4)}\u2026${key.slice(-2)}`;
  await writeAt(
    dir,
    'project.godot',
    ['config_version=5', '', '[application]', 'config/name="Key leak"', `${'SCRIPT_AES256_ENCRYPTION_KEY'}="${key}"`, ''].join('\n'),
  );
  await writeAt(
    dir,
    '.github/workflows/build.yml',
    ['name: build', 'on: push', 'env:', `  SCRIPT_AES256_ENCRYPTION_KEY: ${key}`, 'jobs: {}', ''].join('\n'),
  );

  const result = await scan(dir);
  const leaks = byId(result.findings, 'godot.key_in_repo');
  assert.equal(leaks.length, 2);
  assert.ok(leaks.every((finding) => finding.severity === 'critical'));
  assert.deepEqual(leaks.map((finding) => finding.file).sort(), [
    '.github/workflows/build.yml',
    'project.godot',
  ]);
  assert.ok(leaks.every((finding) => finding.snippet.includes(masked)));

  const json = JSON.stringify(result.findings);
  assert.ok(!json.includes(key));
  const text = formatText(buildResult(result), { target: dir });
  assert.ok(!text.includes(key));
  assert.ok(text.includes(masked));
});

test('a properly configured project stays clean', async (t) => {
  const dir = await makeTemp('unrea-godot-clean-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  await writeAt(dir, 'project.godot', 'config_version=5\n');
  await writeAt(
    dir,
    'export_presets.cfg',
    [
      '[preset.0]',
      'name="Windows Desktop"',
      'encrypt_pck=true',
      'encrypt_directory=true',
      '',
      '[preset.0.options]',
      'script_export_mode=2',
      '',
    ].join('\n'),
  );

  const result = await scan(dir);
  assert.ok(result.surfaces.includes('godot'));
  assert.deepEqual(result.findings.filter((finding) => finding.id.startsWith('godot.')), []);
});

test('detect stays off for non-Godot targets', async (t) => {
  const dir = await makeTemp('unrea-godot-none-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'notes.txt', 'hello\n');

  const result = await scan(dir);
  assert.ok(!result.surfaces.includes('godot'));
});

test('every godot id has explain text and a fix plan', async () => {
  for (const id of ALL_IDS) {
    const text = explain(id);
    assert.match(text, new RegExp(id.replace('.', '\\.')));
    const plan = await buildFixPlan(id, '.', { id });
    assert.equal(plan.ok, true, `${id} should resolve`);
    assert.match(plan.text, /Fix plan/);
  }
});
