import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import test from 'node:test';

import { parsePE, readPE } from '../src/parse/pe.js';
import { buildSyntheticPE, makeTemp, writeAt } from './helpers.mjs';

test('parses PE headers, sections, directories and imports', () => {
  const pe = parsePE(buildSyntheticPE());
  assert.equal(pe.valid, true);
  assert.equal(pe.dos.e_lfanew, 0x80);
  assert.equal(pe.coff.machine, 0x14c);
  assert.equal(pe.coff.machineName, 'x86');
  assert.equal(pe.coff.numberOfSections, 1);
  assert.equal(pe.optional.magic, 0x10b);
  assert.equal(pe.optional.pe32Plus, false);
  assert.equal(pe.optional.entryPoint, 0x1000);
  assert.equal(pe.sections[0].name, '.text');
  assert.equal(pe.sections[0].virtualAddress, 0x1000);
  assert.equal(pe.directories[1].name, 'import');
  assert.equal(pe.directories[1].virtualAddress, 0x1000);
  assert.equal(pe.directories[4].name, 'certificate');
  assert.equal(pe.directories[14].name, 'clr-runtime');
  assert.deepEqual(pe.imports, ['KERNEL32.dll']);
  assert.equal(pe.hasCertificate, true);
  assert.equal(pe.certificate.size, 0x10);
});

test('parses CLI header and .NET metadata #Strings identifiers', () => {
  const pe = parsePE(buildSyntheticPE());
  assert.equal(pe.hasCLIHeader, true);
  assert.equal(pe.isDotNet, true);
  assert.equal(pe.metadata.rva, 0x1200);
  assert.equal(pe.dotnet.signature, 'BSJB');
  assert.equal(pe.dotnet.version, 'v4.0.30319');
  assert.deepEqual(pe.dotnet.strings, ['Main', 'Program', '<Module>']);
  assert.deepEqual(pe.dotnet.streams['#Strings'], { offset: 0x80, size: 0x80 });
});

test('readPE reads a file and malformed input stays non-throwing', async (t) => {
  const dir = await makeTemp('unrea-pe-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  const pePath = await writeAt(dir, 'sample.exe', buildSyntheticPE());

  const pe = await readPE(pePath);
  assert.equal(pe.valid, true);
  assert.deepEqual(pe.imports, ['KERNEL32.dll']);

  const bad = parsePE(Buffer.from('MZ'));
  assert.equal(bad.valid, false);
  assert.match(bad.error, /smaller|PE/);
});
