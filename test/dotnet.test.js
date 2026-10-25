import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import test from 'node:test';

import { explain } from '../src/explain.js';
import { buildFixPlan } from '../src/fix-plan.js';
import { scan } from '../src/scan.js';
import { makeTemp, writeAt } from './helpers.mjs';

// Ordinary application identifiers: a decompiler shows near-source C#.
const APP_NAMES = [
  'PlayerAccount',
  'MainWindow',
  'SaveManager',
  'LicenseManager',
  'TrialExpired',
  'PurchaseService',
  'ApiKeyStore',
  'SecretVault',
  'SerialNumber',
  'PremiumFeature',
];

const EXE_NAMES = ['Program', 'Startup', 'MainWindow'];

// What a rename pass leaves behind.
const OBFUSCATED_NAMES = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];

/**
 * Minimal PE32 + CLI + BSJB metadata image with a single #Strings stream.
 * Built in memory (no binary is committed) and shaped like the shared
 * parsePE() reader expects.
 *
 * @param {string[]} strings
 * @param {{certificate?: boolean, cli?: boolean}} [options]
 * @returns {Buffer}
 */
function buildDotnetPE(strings, options = {}) {
  const { certificate = true, cli = true } = options;
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
  u32(optionalStart + 16, sectionRva); // entry point
  u32(optionalStart + 28, 0x400000); // image base
  u32(optionalStart + 60, 0x400); // size of headers
  u16(optionalStart + 68, 3); // console
  u32(optionalStart + 92, 16); // data directories

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
  u32(rawBase + 0x108, sectionRva + 0x200); // metadata RVA
  u32(rawBase + 0x10c, 0x200); // metadata size

  const metadataRaw = rawBase + 0x200;
  u32(metadataRaw, 0x424a5342); // BSJB
  u16(metadataRaw + 4, 1);
  u16(metadataRaw + 6, 1);
  const version = 'v4.0.30319\0\0';
  u32(metadataRaw + 12, version.length);
  buffer.write(version, metadataRaw + 16, 'ascii');

  const streamHeader = (metadataRaw + 16 + version.length + 3) & ~3;
  u16(streamHeader, 0); // flags
  u16(streamHeader + 2, 1); // one stream
  u32(streamHeader + 4, 0x100); // #Strings offset, relative to metadata root
  u32(streamHeader + 8, 0x100); // #Strings size
  buffer.write('#Strings', streamHeader + 12, 'ascii');

  const heap = strings.map((name) => `${name}\0`).join('');
  assert.ok(Buffer.byteLength(heap, 'utf8') <= 0x100, 'test identifier heap must fit 0x100 bytes');
  buffer.write(heap, metadataRaw + 0x100, 'utf8');

  // Import directory.
  u32(dataDirectoryStart + 1 * 8, sectionRva);
  u32(dataDirectoryStart + 1 * 8 + 4, 40);
  // Authenticode certificate directory (index 4).
  if (certificate) {
    u32(dataDirectoryStart + 4 * 8, 0xc00);
    u32(dataDirectoryStart + 4 * 8 + 4, 0x10);
    buffer.write('CERT', 0xc00, 'ascii');
  }
  // CLI header directory (index 14).
  if (cli) {
    u32(dataDirectoryStart + 14 * 8, sectionRva + 0x100);
    u32(dataDirectoryStart + 14 * 8 + 4, 0x48);
  }

  return buffer;
}

async function appFixture(options = {}) {
  const { certificate = true, identifiers = APP_NAMES } = options;
  const dir = await makeTemp('unrea-dotnet-');
  await writeAt(dir, 'App.exe', buildDotnetPE(EXE_NAMES, { certificate }));
  await writeAt(dir, 'App.dll', buildDotnetPE(identifiers, { certificate }));
  return dir;
}

test('a .NET app reports readable code, licensing names, PDBs and development settings', async (t) => {
  const dir = await appFixture();
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'App.pdb', 'fake pdb');
  await writeAt(dir, 'appsettings.Development.json', '{"Logging":{"LogLevel":"Debug"}}\n');
  await writeAt(dir, 'System.Runtime.dll', buildDotnetPE(['Object', 'String', 'Enumerable']));
  await writeAt(dir, 'Game_Data/Managed/Assembly-CSharp.dll', buildDotnetPE(['Gold', 'Wallet']));
  await writeAt(dir, 'node_modules/lib/Vendor.dll', buildDotnetPE(['VendorThing']));

  const result = await scan(dir);
  const byId = (id) => result.findings.filter((finding) => finding.id === id);

  assert.ok(result.surfaces.includes('dotnet'), 'dotnet surface is detected');
  assert.equal(byId('dotnet.unsigned').length, 0, 'signed exe is not flagged');

  const readable = byId('dotnet.readable');
  assert.equal(readable.length, 1, 'only the application assembly is reported');
  assert.equal(readable[0].severity, 'medium');
  assert.match(readable[0].file, /^App\.dll$/);
  assert.match(readable[0].snippet, /readable words/);

  const sensitive = byId('dotnet.sensitive_names');
  assert.equal(sensitive.length, 1);
  assert.equal(sensitive[0].severity, 'medium');
  assert.match(sensitive[0].snippet, /LicenseManager/);
  assert.match(sensitive[0].snippet, /TrialExpired/);
  assert.match(sensitive[0].snippet, /PurchaseService/);
  assert.match(sensitive[0].snippet, /ApiKeyStore/);
  assert.match(sensitive[0].snippet, /SecretVault/);

  const pdb = byId('dotnet.pdb_shipped');
  assert.equal(pdb.length, 1);
  assert.equal(pdb[0].severity, 'medium');
  assert.match(pdb[0].snippet, /1 PDB symbol file/);

  const settings = byId('dotnet.appsettings_shipped');
  assert.equal(settings.length, 1);
  assert.equal(settings[0].severity, 'info');
  assert.match(settings[0].file, /appsettings\.Development\.json$/);

  assert.equal(byId('dotnet.obfuscated').length, 0);
});

test('an unsigned main executable is reported', async (t) => {
  const dir = await appFixture({ certificate: false });
  t.after(() => rm(dir, { recursive: true, force: true }));

  const result = await scan(dir);
  const unsigned = result.findings.filter((finding) => finding.id === 'dotnet.unsigned');

  assert.equal(unsigned.length, 1);
  assert.equal(unsigned[0].severity, 'medium');
  assert.equal(unsigned[0].file, 'App.exe');
  assert.match(unsigned[0].snippet, /no Authenticode signature/);
});

test('obfuscated names become an informational finding, not readable code', async (t) => {
  const dir = await makeTemp('unrea-dotnet-obf-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'Tool.dll', buildDotnetPE(OBFUSCATED_NAMES));

  const result = await scan(dir);
  const byId = (id) => result.findings.filter((finding) => finding.id === id);

  const obfuscated = byId('dotnet.obfuscated');
  assert.equal(obfuscated.length, 1);
  assert.equal(obfuscated[0].severity, 'info');
  assert.match(obfuscated[0].snippet, /names look obfuscated/);
  assert.equal(byId('dotnet.readable').length, 0);
  assert.equal(byId('dotnet.sensitive_names').length, 0);
});

test('framework assemblies do not raise readable-code findings', async (t) => {
  const dir = await makeTemp('unrea-dotnet-framework-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'System.Runtime.dll', buildDotnetPE(['PlayerAccount', 'SaveManager']));
  await writeAt(dir, 'Microsoft.Extensions.Logging.dll', buildDotnetPE(['LoggerFactory']));
  await writeAt(dir, 'Newtonsoft.Json.dll', buildDotnetPE(['JsonSerializer']));

  const result = await scan(dir);
  assert.ok(result.surfaces.includes('dotnet'), 'the surface still detects managed assemblies');
  assert.equal(
    result.findings.filter((finding) => finding.id === 'dotnet.readable').length,
    0,
  );
});

test('Unity managed assemblies stay with the unity surface', async (t) => {
  const dir = await makeTemp('unrea-dotnet-unity-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'Game.exe', 'fake Unity player');
  await writeAt(dir, 'Game_Data/globalgamemanagers', 'unity marker');
  await writeAt(dir, 'Game_Data/Managed/Assembly-CSharp.dll', buildDotnetPE(APP_NAMES));
  await writeAt(dir, 'MonoBleedingEdge/EmbedRuntime/mono.dll', buildDotnetPE(['MonoThing']));

  const result = await scan(dir);
  const dotnetFindings = result.findings.filter((finding) => finding.id.startsWith('dotnet.'));

  assert.ok(result.surfaces.includes('unity'));
  assert.equal(result.surfaces.includes('dotnet'), false);
  assert.equal(dotnetFindings.length, 0);
});

test('a native executable does not pull the dotnet surface in', async (t) => {
  const dir = await makeTemp('unrea-dotnet-native-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'Native.exe', buildDotnetPE([], { cli: false }));
  await writeAt(dir, 'readme.txt', 'hello');

  const result = await scan(dir);
  assert.equal(result.surfaces.includes('dotnet'), false);
  assert.equal(
    result.findings.filter((finding) => finding.id.startsWith('dotnet.')).length,
    0,
  );
});

test('fix plans carry release, obfuscation, symbol and signing steps', async () => {
  const readable = await buildFixPlan('dotnet.readable', '.');
  assert.equal(readable.ok, true);
  assert.match(readable.text, /dotnet publish -c Release/);
  assert.match(readable.text, /ConfuserEx2/);
  assert.match(readable.text, /Obfuscar\.Console\.exe/);
  assert.match(readable.text, /PublishAot/);

  const pdb = await buildFixPlan('dotnet.pdb_shipped', '.');
  assert.equal(pdb.ok, true);
  assert.match(pdb.text, /<DebugType>none<\/DebugType>/);
  assert.match(pdb.text, /\*\.pdb/);

  const unsigned = await buildFixPlan('dotnet.unsigned', '.');
  assert.equal(unsigned.ok, true);
  assert.match(unsigned.text, /signtool sign/);
  assert.match(unsigned.text, /timestamp/);

  const sensitive = await buildFixPlan('dotnet.sensitive_names', '.');
  assert.equal(sensitive.ok, true);
  assert.match(sensitive.text, /server-side|server/i);

  const family = await buildFixPlan('dotnet.*', '.');
  assert.equal(family.ok, true);
  assert.match(family.text, /dotnet publish -c Release/);
  assert.match(family.text, /<DebugType>none<\/DebugType>/);
  assert.match(family.text, /signtool|Trusted Signing/);

  const text = explain('dotnet.readable');
  assert.match(text, /How an agent finds it:/);
  assert.match(text, /ILSpy/);
});
