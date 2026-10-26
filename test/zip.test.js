import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import test from 'node:test';

import { parseZip } from '../src/parse/zip.js';

// Build a tiny zip in memory: one stored entry and one deflated entry.
function buildZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const { name, data, deflate } of files) {
    const nameBuf = Buffer.from(name);
    const body = deflate ? deflateRawSync(data) : data;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(deflate ? 8 : 0, 8);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    locals.push(local, nameBuf, body);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(deflate ? 8 : 0, 10);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBuf);
    offset += 30 + nameBuf.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

test('parseZip lists entries and reads stored and deflated data', () => {
  const zip = parseZip(
    buildZip([
      { name: 'AndroidManifest.xml', data: Buffer.from('stored body') },
      { name: 'assets/config.json', data: Buffer.from('{"a":1}'.repeat(50)), deflate: true },
    ]),
  );
  assert.equal(zip.valid, true);
  assert.deepEqual(zip.entries.map((e) => e.name), ['AndroidManifest.xml', 'assets/config.json']);
  assert.equal(zip.read('AndroidManifest.xml').toString(), 'stored body');
  assert.equal(zip.read('assets/config.json').toString(), '{"a":1}'.repeat(50));
  assert.equal(zip.read('missing'), null);
});

test('parseZip does not throw on garbage', () => {
  assert.equal(parseZip(Buffer.from('not a zip at all, definitely not')).valid, false);
  assert.equal(parseZip(Buffer.alloc(3)).valid, false);
});
