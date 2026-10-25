import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { buildFixPlan } from '../src/fix-plan.js';
import { explain } from '../src/explain.js';
import { scan } from '../src/scan.js';
import { buildSyntheticPE, fake, makeTemp, writeAt } from './helpers.mjs';

const TEXT_RVA = 0x1000;
const TEXT_RAW = 0x400;
const TEXT_RAW_SIZE = 0x800;
const DEBUG_DIR_RAW = 0x500;
const CODEVIEW_RAW = 0x580;
const STRINGS_RAW = 0x600;

/**
 * Small PE32 image with a .text section, optional extra sections, an optional
 * CodeView debug record and an optional certificate directory. Everything is
 * built in code; no binary is committed.
 */
function buildNativePE(options = {}) {
  const dllCharacteristics = options.dllCharacteristics ?? 0x0140;
  const signed = Boolean(options.signed);
  const pdbPath = options.pdbPath || null;
  const strings = options.strings || '';
  const extraSections = options.extraSections || [];

  const extras = extraSections.map((section) => ({
    ...section,
    rawSize: Math.max(0x200, Math.ceil(section.data.length / 0x200) * 0x200),
    rawPointer: 0,
  }));
  let cursor = 0xc00;
  for (const section of extras) {
    section.rawPointer = cursor;
    cursor += section.rawSize;
  }
  const certificateOffset = cursor;
  const buffer = Buffer.alloc(cursor + (signed ? 0x40 : 0));

  const u16 = (offset, value) => buffer.writeUInt16LE(value, offset);
  const u32 = (offset, value) => buffer.writeUInt32LE(value, offset);

  buffer.write('MZ', 0, 'ascii');
  u32(0x3c, 0x80);
  buffer.write('PE\0\0', 0x80, 'binary');
  u16(0x84, 0x8664); // x64
  u16(0x86, 1 + extras.length);
  u16(0x94, 0xe0); // optional header size
  u16(0x96, 0x0022); // executable image | large address aware

  const optional = 0x80 + 24;
  u16(optional, 0x10b); // PE32
  u32(optional + 16, TEXT_RVA); // entry point
  u32(optional + 28, 0x400000); // image base
  u32(optional + 32, 0x1000); // section alignment
  u32(optional + 36, 0x200); // file alignment
  u32(optional + 56, 0x4000); // size of image
  u32(optional + 60, 0x400); // size of headers
  u16(optional + 68, 3); // console subsystem
  u16(optional + 70, dllCharacteristics);
  u32(optional + 92, 16); // data directories

  const sectionTable = optional + 0xe0;
  const writeSection = (index, name, virtualSize, rva, rawSize, rawPointer, characteristics) => {
    const at = sectionTable + index * 40;
    buffer.write(name, at, 'ascii');
    u32(at + 8, virtualSize);
    u32(at + 12, rva);
    u32(at + 16, rawSize);
    u32(at + 20, rawPointer);
    u32(at + 36, characteristics);
  };

  writeSection(0, '.text', 0x900, TEXT_RVA, TEXT_RAW_SIZE, TEXT_RAW, 0x60000020);
  extras.forEach((section, index) => {
    writeSection(
      1 + index,
      section.name,
      section.data.length,
      0x2000 + index * 0x1000,
      section.rawSize,
      section.rawPointer,
      0x40000040,
    );
    section.data.copy(buffer, section.rawPointer);
  });

  const dataDirectories = optional + 96;

  if (pdbPath) {
    const record = Buffer.concat([
      Buffer.from('RSDS', 'ascii'),
      Buffer.alloc(16, 0x11),
      Buffer.from([1, 0, 0, 0]),
      Buffer.from(`${pdbPath}\0`, 'latin1'),
    ]);
    u32(DEBUG_DIR_RAW + 12, 2); // IMAGE_DEBUG_TYPE_CODEVIEW
    u32(DEBUG_DIR_RAW + 16, record.length);
    u32(DEBUG_DIR_RAW + 20, TEXT_RVA + (CODEVIEW_RAW - TEXT_RAW));
    u32(DEBUG_DIR_RAW + 24, CODEVIEW_RAW);
    record.copy(buffer, CODEVIEW_RAW);

    u32(dataDirectories + 6 * 8, TEXT_RVA + (DEBUG_DIR_RAW - TEXT_RAW));
    u32(dataDirectories + 6 * 8 + 4, 28);
  }

  if (strings) buffer.write(strings, STRINGS_RAW, 'latin1');

  if (signed) {
    u32(dataDirectories + 4 * 8, certificateOffset);
    u32(dataDirectories + 4 * 8 + 4, 0x20);
    buffer.write('CERT', certificateOffset, 'ascii');
  }

  return buffer;
}

function byNative(result, file) {
  return result.findings
    .filter((finding) => finding.file === file && finding.id.startsWith('pe-native.'))
    .map((finding) => finding.id)
    .sort();
}

test('pe-native: unsigned file and unset ASLR/DEP/CFG flags with a PDB path', async (t) => {
  const dir = await makeTemp('unrea-pe-native-flags-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  await writeAt(
    dir,
    'app.exe',
    buildNativePE({
      dllCharacteristics: 0,
      pdbPath: 'C:\\builds\\acme-secret-project\\app.pdb',
    }),
  );
  // Fully hardened, signed, no debug path: nothing to report.
  await writeAt(
    dir,
    'helper.dll',
    buildNativePE({ dllCharacteristics: 0x4140, signed: true }),
  );
  await writeAt(dir, 'junk.exe', Buffer.from('MZ this is not a PE image'));

  const result = await scan(dir);
  assert.ok(result.surfaces.includes('pe-native'));

  assert.deepEqual(byNative(result, 'app.exe'), [
    'pe-native.debug_info',
    'pe-native.no_aslr',
    'pe-native.no_cfg',
    'pe-native.no_dep',
    'pe-native.unsigned',
  ]);

  const severity = (id) => result.findings.find((f) => f.file === 'app.exe' && f.id === id).severity;
  assert.equal(severity('pe-native.unsigned'), 'medium');
  assert.equal(severity('pe-native.no_aslr'), 'medium');
  assert.equal(severity('pe-native.no_dep'), 'medium');
  assert.equal(severity('pe-native.no_cfg'), 'info');
  assert.equal(severity('pe-native.debug_info'), 'medium');

  const debug = result.findings.find((f) => f.id === 'pe-native.debug_info');
  assert.match(debug.snippet, /app\.pdb/);
  assert.match(debug.snippet, /debug directory references PDB path/);

  assert.deepEqual(byNative(result, 'helper.dll'), [], 'hardened signed DLL stays clean');
  assert.deepEqual(byNative(result, 'junk.exe'), [], 'a file that is not a PE is skipped');
});

test('pe-native: a shipped .pdb next to the binary raises debug_info to high', async (t) => {
  const dir = await makeTemp('unrea-pe-native-pdb-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  await writeAt(dir, 'app.exe', buildNativePE({ dllCharacteristics: 0x4140, signed: true, pdbPath: 'app.pdb' }));
  await writeAt(dir, 'app.pdb', 'fake symbols, never shipped in a real release');

  const result = await scan(dir);
  const debug = result.findings.find((f) => f.id === 'pe-native.debug_info');
  assert.ok(debug, 'debug_info should be reported');
  assert.equal(debug.severity, 'high');
  assert.match(debug.snippet, /ships next to the binary/);
  assert.equal(result.findings.some((f) => f.id === 'pe-native.debug_info' && f.severity === 'medium'), false);
});

test('pe-native: Go build info, Rust build paths and secrets from binary strings', async (t) => {
  const dir = await makeTemp('unrea-pe-native-info-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  const goBuildInfo = Buffer.concat([
    Buffer.from([0xff]),
    Buffer.from(' Go buildinf:', 'latin1'),
    Buffer.from([0x08, 0x08]),
    Buffer.from(
      '\npath\tgithub.com/acme/app\nmod\tgithub.com/acme/app\t(devel)\nmod\tgithub.com/acme/dep\tv1.2.3\n',
      'latin1',
    ),
  ]);
  await writeAt(
    dir,
    'goapp.exe',
    buildNativePE({
      dllCharacteristics: 0x4140,
      signed: true,
      extraSections: [{ name: '.go.buildinfo', data: goBuildInfo }],
    }),
  );

  const rustStrings = [
    'C:\\Users\\dev\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\serde-1.0.0\\src\\lib.rs',
    'C:\\Users\\dev\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\tokio-1.38.0\\src\\runtime.rs',
    'C:\\Users\\dev\\.cargo\\registry\\cache\\index.crates.io-6f17d22bba15001f\\anyhow-1.0.86.crate',
    'C:\\Users\\dev\\.rustup\\toolchains\\stable-x86_64-pc-windows-msvc\\lib\\rustlib\\src\\rust\\library\\std\\src\\io.rs',
  ].join('\n');
  await writeAt(
    dir,
    'rustapp.exe',
    buildNativePE({ dllCharacteristics: 0x4140, signed: true, strings: rustStrings }),
  );

  const secret = fake.openai();
  await writeAt(
    dir,
    'leaky.exe',
    buildNativePE({
      dllCharacteristics: 0x4140,
      signed: true,
      strings: `const OPENAI_API_KEY=${secret}\n`,
    }),
  );

  const result = await scan(dir);

  const go = result.findings.find((f) => f.id === 'pe-native.go_buildinfo');
  assert.ok(go, 'go_buildinfo should be reported');
  assert.equal(go.file, 'goapp.exe');
  assert.equal(go.severity, 'medium');
  assert.match(go.snippet, /\.go\.buildinfo section exposes module github\.com\/acme\/app/);

  const rust = result.findings.find((f) => f.id === 'pe-native.rust_paths');
  assert.ok(rust, 'rust_paths should be reported');
  assert.equal(rust.file, 'rustapp.exe');
  assert.equal(rust.severity, 'info');
  assert.match(rust.snippet, /4 cargo\/rustc build paths/);

  assert.deepEqual(byNative(result, 'goapp.exe'), ['pe-native.go_buildinfo']);
  assert.deepEqual(byNative(result, 'rustapp.exe'), ['pe-native.rust_paths']);

  const leaked = result.findings.find((f) => f.id === 'secret.openai');
  assert.ok(leaked, 'the key embedded in the binary should be reported');
  assert.equal(leaked.file, 'leaky.exe');
  assert.equal(leaked.severity, 'critical');
  assert.match(leaked.snippet, /^binary strings: OpenAI key: /);
  assert.ok(!leaked.snippet.includes(secret), 'snippet must stay masked');
  assert.ok(!JSON.stringify(result.findings).includes(secret), 'no finding may contain the full secret');
});

test('pe-native: .NET, vendor runtimes, Unity and node_modules files are out of scope', async (t) => {
  const dir = await makeTemp('unrea-pe-native-scope-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  // Would produce five findings if the scope rules did not apply.
  const unhardened = () => buildNativePE({ dllCharacteristics: 0 });

  await writeAt(dir, 'managed.dll', buildSyntheticPE()); // .NET assembly
  await writeAt(dir, 'ffmpeg.dll', unhardened());
  await writeAt(dir, 'vcruntime140.dll', unhardened());
  await writeAt(dir, 'UnityCrashHandler64.exe', unhardened());
  await writeAt(dir, 'Unity/Game.exe', unhardened());
  await writeAt(dir, 'node_modules/native/app.exe', unhardened());
  await writeAt(dir, 'resources/app.exe', unhardened());

  const result = await scan(dir);

  assert.equal(byNative(result, 'resources/app.exe').length, 4, 'own binary is still analysed');
  for (const file of [
    'managed.dll',
    'ffmpeg.dll',
    'vcruntime140.dll',
    'UnityCrashHandler64.exe',
    'Unity/Game.exe',
    'node_modules/native/app.exe',
  ]) {
    assert.deepEqual(byNative(result, file), [], `${file} must be skipped`);
  }
});

test('pe-native: single executable target, detection gate and fix plans', async (t) => {
  const dir = await makeTemp('unrea-pe-native-single-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  const exePath = await writeAt(dir, 'app.exe', buildNativePE({ dllCharacteristics: 0 }));

  const single = await scan(exePath);
  assert.deepEqual(single.surfaces, ['electron', 'generic', 'pe-native']);
  assert.ok(single.findings.some((f) => f.id === 'pe-native.no_aslr' && f.file === 'app.exe'));

  const fakeExe = await makeTemp('unrea-pe-native-fake-');
  t.after(() => rm(fakeExe, { recursive: true, force: true }));
  await writeAt(fakeExe, 'app.exe', Buffer.alloc(64, 0x90));
  const fakeResult = await scan(fakeExe);
  assert.ok(!fakeResult.surfaces.includes('pe-native'), 'extension alone must not trigger the surface');

  assert.match(explain('pe-native.no_aslr'), /What it is:/);
  assert.doesNotMatch(explain('pe-native.no_aslr'), /Unknown check id/);

  const plans = await Promise.all([
    buildFixPlan('pe-native.unsigned', dir, { file: 'app.exe' }),
    buildFixPlan('pe-native.no_aslr', dir, { file: 'app.exe' }),
    buildFixPlan('pe-native.debug_info', dir, { file: 'app.exe' }),
    buildFixPlan('pe-native.go_buildinfo', dir, { file: 'app.exe' }),
    buildFixPlan('pe-native.rust_paths', dir, { file: 'app.exe' }),
  ]);
  for (const plan of plans) assert.equal(plan.ok, true, plan.text);
  const text = plans.map((plan) => plan.text).join('\n');
  assert.match(text, /signtool sign/);
  assert.match(text, /\/DYNAMICBASE/);
  assert.match(text, /\/PDBALTPATH/);
  assert.match(text, /-trimpath/);
  assert.match(text, /--remap-path-prefix/);

  const cfgPlan = await buildFixPlan('pe-native.no_cfg', dir, { file: 'app.exe' });
  assert.equal(cfgPlan.ok, true);
  assert.match(cfgPlan.text, /\/guard:cf/);
});

test('pe-native: repeated identical secrets collapse to one finding per file', async (t) => {
  const dir = await makeTemp('unrea-pe-native-dupe-');
  t.after(() => rm(dir, { recursive: true, force: true }));

  const secret = fake.aws();
  await writeAt(
    dir,
    'app.exe',
    buildNativePE({
      dllCharacteristics: 0x4140,
      signed: true,
      strings: `key_one=${secret}\nkey_two=${secret}\n`,
    }),
  );

  const result = await scan(dir);
  const aws = result.findings.filter((f) => f.id === 'secret.aws');
  assert.equal(aws.length, 1, 'the same value is reported once');
  assert.ok(!aws[0].snippet.includes(secret));
  assert.match(aws[0].snippet, /AWS access key: /);
  assert.equal(aws[0].file, path.basename(path.join(dir, 'app.exe')));
});
