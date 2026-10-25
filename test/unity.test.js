import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import test from 'node:test';

import { createScanContext } from '../src/core/walk.js';
import { buildFixPlan } from '../src/fix-plan.js';
import { scan } from '../src/scan.js';
import { engineInfo } from '../src/surfaces/unity/index.js';
import { makeTemp, writeAt } from './helpers.mjs';

// Ordinary game identifiers: readable, and several of them own economy/score.
const READABLE_NAMES = [
  'Gold',
  'AddScore',
  'Health',
  'Damage',
  'PlayerController',
  'PurchaseLimit',
  'Scoreboard',
  'WalletBalance',
  'UnlockState',
  'ReceiptValidator',
];

// No vowels, no CamelCase words: what a rename pass leaves behind.
const OBFUSCATED_NAMES = ['qzx', 'vbn', 'jkd', 'plm', 'wrt'];

/**
 * Minimal PE32 + CLI + BSJB metadata image with a single #Strings stream.
 * Built in memory (no binary is committed) and shaped like the repository's
 * buildSyntheticPE() helper so the shared parsePE() reads it.
 *
 * @param {string[]} strings
 * @returns {Buffer}
 */
function buildDotnetPE(strings) {
  const buffer = Buffer.alloc(0x1000);
  const peOffset = 0x80;
  const optionalStart = peOffset + 24;
  const optionalSize = 0xe0;
  const sectionTable = optionalStart + optionalSize;
  const rawBase = 0x400;
  const sectionRva = 0x1000;
  const dataDirectoryStart = optionalStart + 96;

  const u16 = (offset, value) => buffer.writeUInt16LE(value, offset);
  const u32 = (offset, value) => buffer.writeUInt32LE(value, offset);

  buffer.write('MZ', 0, 'ascii');
  u32(0x3c, peOffset);
  buffer.write('PE\0\0', peOffset, 'binary');
  u16(peOffset + 4, 0x8664);
  u16(peOffset + 6, 1);
  u16(peOffset + 20, optionalSize);
  u16(peOffset + 22, 0x0102);

  u16(optionalStart, 0x10b); // PE32
  u32(optionalStart + 16, sectionRva);
  u32(optionalStart + 28, 0x400000);
  u32(optionalStart + 60, 0x400);
  u16(optionalStart + 68, 3);
  u32(optionalStart + 92, 16);

  buffer.write('.text', sectionTable, 'ascii');
  u32(sectionTable + 8, 0x800);
  u32(sectionTable + 12, sectionRva);
  u32(sectionTable + 16, 0x800);
  u32(sectionTable + 20, rawBase);
  u32(sectionTable + 36, 0x60000020);

  // Import table + DLL name.
  u32(rawBase + 12, sectionRva + 0x20);
  buffer.write('KERNEL32.dll\0', rawBase + 0x20, 'ascii');

  // CLI header at RVA 0x1100, metadata root at RVA 0x1200.
  u32(rawBase + 0x100, 0x48);
  u32(rawBase + 0x108, sectionRva + 0x200);
  u32(rawBase + 0x10c, 0x200);

  const metadataRaw = rawBase + 0x200;
  u32(metadataRaw, 0x424a5342); // BSJB
  u16(metadataRaw + 4, 1);
  u16(metadataRaw + 6, 1);
  const version = 'v4.0.30319\0\0';
  u32(metadataRaw + 12, version.length);
  buffer.write(version, metadataRaw + 16, 'ascii');

  const streamHeader = (metadataRaw + 16 + version.length + 3) & ~3;
  u16(streamHeader, 0);
  u16(streamHeader + 2, 1);
  u32(streamHeader + 4, 0x100); // #Strings offset, relative to metadata root
  u32(streamHeader + 8, 0x100);
  buffer.write('#Strings', streamHeader + 12, 'ascii');

  const heap = `${strings.map((name) => `${name}\0`).join('')}`;
  assert.ok(Buffer.byteLength(heap, 'utf8') <= 0x100, 'test identifier heap must fit 0x100 bytes');
  buffer.write(heap, metadataRaw + 0x100, 'utf8');

  u32(dataDirectoryStart + 1 * 8, sectionRva);
  u32(dataDirectoryStart + 1 * 8 + 4, 40);
  u32(dataDirectoryStart + 4 * 8, 0xc00);
  u32(dataDirectoryStart + 4 * 8 + 4, 0x10);
  u32(dataDirectoryStart + 14 * 8, sectionRva + 0x100);
  u32(dataDirectoryStart + 14 * 8 + 4, 0x48);

  buffer.write('CERT', 0xc00, 'ascii');
  return buffer;
}

/**
 * Windows-shaped Unity Mono player folder.
 *
 * @param {{identifiers?: string[], debug?: boolean}} [options]
 * @returns {Promise<string>}
 */
async function monoFixture(options = {}) {
  const { identifiers = READABLE_NAMES, debug = true } = options;
  const dir = await makeTemp('unrea-unity-mono-');

  await writeAt(dir, 'Game.exe', 'fake Unity player');
  await writeAt(dir, 'Game_Data/globalgamemanagers', 'unity marker');
  await writeAt(dir, 'Game_Data/Managed/Assembly-CSharp.dll', buildDotnetPE(identifiers));
  await writeAt(dir, 'Game_Data/Managed/System.Core.dll', buildDotnetPE(['Enumerable']));
  await writeAt(dir, 'Game_Data/Plugins/x86_64/native.dll', 'MZ native');
  await writeAt(dir, 'Game_Data/Plugins/audio.dll', 'MZ audio');
  await writeAt(
    dir,
    'Game_Data/StreamingAssets/config.json',
    '{"api":"https://localhost:8080/api"}\n',
  );

  if (debug) {
    await writeAt(
      dir,
      'Game_BurstDebugInformation_DoNotShip/Data/Plugins/lib_burst_generated.txt',
      'burst',
    );
    await writeAt(dir, 'Game_Data/Managed/Assembly-CSharp.pdb', 'pdb');
    await writeAt(dir, 'Game_Data/Managed/Other.pdb', 'pdb');
    await writeAt(dir, 'Game_Data/Managed/Assembly-CSharp.dll.mdb', 'mdb');
    await writeAt(dir, 'Game_Data/Managed/Other.dll.mdb', 'mdb');
  }

  return dir;
}

test('a Unity Mono build reports mono, readable names, client authority and debug data', async (t) => {
  const dir = await monoFixture();
  t.after(() => rm(dir, { recursive: true, force: true }));

  const result = await scan(dir);
  const byId = (id) => result.findings.filter((finding) => finding.id === id);

  assert.ok(result.surfaces.includes('unity'), 'unity surface is detected');

  const mono = byId('unity.mono');
  assert.equal(mono.length, 1);
  assert.equal(mono[0].severity, 'high');
  assert.match(mono[0].file, /Game_Data\/Managed\/Assembly-CSharp\.dll$/);

  const names = byId('unity.names');
  assert.equal(names.length, 1);
  assert.equal(names[0].severity, 'medium');
  assert.match(names[0].snippet, /names are readable/);

  const authority = byId('unity.client_authority');
  assert.equal(authority.length, 1);
  assert.equal(authority[0].severity, 'medium');
  assert.match(authority[0].snippet, /Gold/);
  assert.match(authority[0].snippet, /AddScore/);

  const saves = byId('unity.saves');
  assert.equal(saves.length, 1);
  assert.equal(saves[0].severity, 'info');

  const plugins = byId('unity.plugins');
  assert.equal(plugins.length, 1);
  assert.equal(plugins[0].severity, 'info');
  assert.match(plugins[0].snippet, /2 native plugin DLL\(s\)/);

  const debug = byId('unity.debug_shipped');
  assert.equal(debug.length, 3, 'one finding per debug kind');
  assert.ok(debug.every((finding) => finding.severity === 'high'));
  assert.ok(debug.some((finding) => /Burst debug information folder shipped \(1\)/.test(finding.snippet)));
  assert.ok(debug.some((finding) => /^2 PDB debug symbol/.test(finding.snippet)));
  assert.ok(debug.some((finding) => /^2 Mono debug symbol/.test(finding.snippet)));

  // Generic text checks still run on StreamingAssets/.
  assert.equal(byId('endpoint.internal').length, 1);
});

test('IL2CPP metadata magic is reported and the backend is exposed to the core', async (t) => {
  const dir = await makeTemp('unrea-unity-il2cpp-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  await writeAt(dir, 'Game.exe', 'fake Unity player');
  await writeAt(dir, 'Game_Data/globalgamemanagers', 'unity marker');
  await writeAt(
    dir,
    'Game_Data/il2cpp_data/Metadata/global-metadata.dat',
    Buffer.from([0xaf, 0x1b, 0xb1, 0xfa, 0, 0, 0, 0]),
  );

  const result = await scan(dir);
  const byId = (id) => result.findings.filter((finding) => finding.id === id);

  const metadata = byId('unity.il2cpp.metadata');
  assert.equal(metadata.length, 1);
  assert.equal(metadata[0].severity, 'medium');
  assert.match(metadata[0].file, /global-metadata\.dat$/);
  assert.equal(byId('unity.mono').length, 0);
  assert.equal(byId('unity.names').length, 0);

  const { context, cleanup } = await createScanContext(dir);
  t.after(cleanup);
  assert.deepEqual(engineInfo(context), {
    engine: 'unity',
    backend: 'il2cpp',
    builds: [{ path: '.', backend: 'il2cpp' }],
  });
});

test('an encrypted global-metadata.dat is not flagged', async (t) => {
  const dir = await makeTemp('unrea-unity-il2cpp-enc-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  await writeAt(dir, 'Game.exe', 'fake Unity player');
  await writeAt(dir, 'Game_Data/globalgamemanagers', 'unity marker');
  await writeAt(
    dir,
    'Game_Data/il2cpp_data/Metadata/global-metadata.dat',
    Buffer.from([0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]),
  );

  const result = await scan(dir);
  assert.equal(result.findings.filter((finding) => finding.id === 'unity.il2cpp.metadata').length, 0);
});

test('obfuscated names do not raise unity.names or client authority findings', async (t) => {
  const dir = await monoFixture({ identifiers: OBFUSCATED_NAMES, debug: false });
  t.after(() => rm(dir, { recursive: true, force: true }));

  const result = await scan(dir);
  const byId = (id) => result.findings.filter((finding) => finding.id === id);

  assert.equal(byId('unity.mono').length, 1);
  assert.equal(byId('unity.names').length, 0);
  assert.equal(byId('unity.client_authority').length, 0);
  assert.equal(byId('unity.debug_shipped').length, 0);
});

test('a macOS .app player is detected at Contents/Resources/Data', async (t) => {
  const dir = await makeTemp('unrea-unity-mac-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  await writeAt(dir, 'Game.app/Contents/MacOS/Game', 'fake Unity player');
  await writeAt(dir, 'Game.app/Contents/Resources/Data/globalgamemanagers', 'unity marker');
  await writeAt(
    dir,
    'Game.app/Contents/Resources/Data/Managed/Assembly-CSharp.dll',
    buildDotnetPE(READABLE_NAMES),
  );

  const result = await scan(dir);
  const mono = result.findings.filter((finding) => finding.id === 'unity.mono');
  assert.equal(mono.length, 1);
  assert.match(mono[0].file, /Game\.app\/Contents\/Resources\/Data\/Managed\/Assembly-CSharp\.dll$/);
  assert.equal(result.findings.filter((finding) => finding.id === 'unity.names').length, 1);
});

test('a non-Unity folder does not pull the unity surface in', async (t) => {
  const dir = await makeTemp('unrea-not-unity-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  await writeAt(dir, 'app.exe', 'not a player');
  await writeAt(dir, 'readme.txt', 'hello');

  const result = await scan(dir);
  assert.deepEqual(result.surfaces, ['electron', 'generic']);
  assert.equal(result.findings.filter((finding) => finding.id.startsWith('unity.')).length, 0);
});

test('fix plans carry the real Unity steps and the post-build symbol stripper', async () => {
  const mono = await buildFixPlan('unity.mono', '.');
  assert.equal(mono.ok, true);
  assert.match(mono.text, /Edit > Project Settings > Player > Other Settings/);
  assert.match(mono.text, /Managed Stripping Level to High/);
  assert.match(mono.text, /Standalone: 1/);

  const debug = await buildFixPlan('unity.debug_shipped', '.');
  assert.equal(debug.ok, true);
  assert.match(debug.text, /IPostprocessBuildWithReport/);
  assert.match(debug.text, /_BurstDebugInformation_DoNotShip/);
  assert.match(debug.text, /\*\.pdb/);

  const authority = await buildFixPlan('unity.client_authority', '.');
  assert.equal(authority.ok, true);
  assert.match(authority.text, /server/i);
});
