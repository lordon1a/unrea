import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export async function makeTemp(prefix = 'unrea-test-') {
  return mkdtemp(path.join(os.tmpdir(), prefix));
}

export async function writeAt(root, relative, content) {
  const target = path.join(root, relative);
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, content, 'utf8');
  return target;
}

/**
 * Fake credentials, always assembled from pieces so no complete key-shaped
 * literal lives in the repository.
 */
export const fake = {
  aws: () => 'AKIA' + 'X'.repeat(16),
  openai: () => 'sk-' + 'proj-' + 'aB3xK9mP2qR7sT5vW8yZ4nC6',
  anthropic: () => 'sk-' + 'ant-' + 'aB3xK9mP2qR7sT5vW8yZ4nC6',
  stripeLive: () => 'sk_' + 'live_' + 'aB3xK9mP2qR7sT5v',
  stripeTest: () => 'sk_' + 'test_' + 'aB3xK9mP2qR7sT5v',
  githubClassic: () => 'ghp_' + 'aB3'.repeat(12),
  githubPat: () => 'github_' + 'pat_' + 'aB3xK9mP2qR7sT5vW8yZ4nC6dF1gH2jK3lM4nP5q',
  google: () => 'AIza' + 'aB3xK9mP2qR7sT5vW8yZ4nC6dF1gH2jK3lM',
  slack: () => 'xoxb-' + '1234567890-abcd',
  generic: () => 'aB3xK9mP2qR7sT5vW8yZ4nC6dF1gH2j',
  jwt: (payload) => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = 's'.repeat(24);
    return `${header}.${body}.${signature}`;
  },
};

/**
 * Build a tiny file that passes for an Electron binary as far as
 * @electron/fuses is concerned: sentinel + version + wire length + states.
 */
export function fakeFuseBinary(states) {
  const sentinel = 'dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX';
  const wire = Buffer.from(states.map((state) => (state ? 0x31 : 0x30)));
  return Buffer.concat([
    Buffer.alloc(64, 0x90),
    Buffer.from(sentinel, 'ascii'),
    Buffer.from([0x01, wire.length]), // fuse wire version 1, then wire length
    wire,
  ]);
}

/**
 * Tiny valid PE32 image with an import, a certificate directory, a CLI header
 * and a .NET metadata root with a #Strings heap. No binary is committed.
 */
export function buildSyntheticPE() {
  const buffer = Buffer.alloc(0xc20);
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
  u16(peOffset + 4, 0x014c); // x86
  u16(peOffset + 6, 1); // one section
  u16(peOffset + 20, optionalSize);
  u16(peOffset + 22, 0x0102);

  u16(optionalStart, 0x10b); // PE32
  u32(optionalStart + 16, sectionRva); // entry point
  u32(optionalStart + 28, 0x400000); // image base
  u32(optionalStart + 60, 0x400); // size of headers
  u16(optionalStart + 68, 3); // console subsystem
  u32(optionalStart + 92, 16); // data directories

  // .text: import table, CLI header and metadata root all live here.
  buffer.write('.text', sectionTable, 'ascii');
  u32(sectionTable + 8, 0x800);
  u32(sectionTable + 12, sectionRva);
  u32(sectionTable + 16, 0x800);
  u32(sectionTable + 20, rawBase);
  u32(sectionTable + 36, 0x60000020);

  // Import descriptor (20 bytes) + DLL name.
  u32(rawBase + 12, sectionRva + 0x20);
  buffer.write('KERNEL32.dll\0', rawBase + 0x20, 'ascii');

  // CLI header at RVA 0x1100.
  u32(rawBase + 0x100, 0x48);
  u32(rawBase + 0x108, sectionRva + 0x200); // metadata RVA
  u32(rawBase + 0x10c, 0x180); // metadata size

  // Metadata root at RVA 0x1200.
  const metadataRaw = rawBase + 0x200;
  u32(metadataRaw, 0x424a5342); // BSJB
  u16(metadataRaw + 4, 1);
  u16(metadataRaw + 6, 1);
  const version = 'v4.0.30319\0\0';
  u32(metadataRaw + 12, version.length);
  buffer.write(version, metadataRaw + 16, 'ascii');
  const streamHeader = (metadataRaw + 16 + version.length + 3) & ~3;
  u16(streamHeader, 0); // flags
  u16(streamHeader + 2, 2); // two streams, real variable-length headers
  u32(streamHeader + 4, 0x60); // "#~" tables stream (name padded to 4 bytes)
  u32(streamHeader + 8, 0x10);
  buffer.write('#~\0\0', streamHeader + 12, 'ascii');
  u32(streamHeader + 16, 0x80); // #Strings offset relative to metadata root
  u32(streamHeader + 20, 0x80);
  buffer.write('#Strings\0\0\0\0', streamHeader + 24, 'ascii');
  buffer.write('Main\0Program\0<Module>\0', metadataRaw + 0x80, 'ascii');

  // Data directories: import, certificate (file offset), CLI.
  u32(dataDirectoryStart + 1 * 8, sectionRva);
  u32(dataDirectoryStart + 1 * 8 + 4, 40);
  u32(dataDirectoryStart + 4 * 8, 0xc00);
  u32(dataDirectoryStart + 4 * 8 + 4, 0x10);
  u32(dataDirectoryStart + 14 * 8, sectionRva + 0x100);
  u32(dataDirectoryStart + 14 * 8 + 4, 0x48);

  buffer.write('CERT', 0xc00, 'ascii');
  return buffer;
}
