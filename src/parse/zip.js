import fsp from 'node:fs/promises';
import { inflateRawSync } from 'node:zlib';

/**
 * Minimal read-only ZIP reader for APK / IPA / AAB / JAR containers.
 * Reads the central directory only; entries are inflated on demand.
 * Never throws on malformed input: returns { valid: false, error }.
 */

const EOCD_SIG = 0x06054b50;
const CEN_SIG = 0x02014b50;
const LOC_SIG = 0x04034b50;
const MAX_COMMENT = 0xffff;

/**
 * @param {Buffer} buffer
 * @returns {{valid: boolean, error?: string, entries: Array<{name:string, method:number, compressedSize:number, size:number, offset:number}>, read: (name:string, maxBytes?:number) => Buffer|null}}
 */
export function parseZip(buffer) {
  const empty = { valid: false, entries: [], read: () => null };
  if (!Buffer.isBuffer(buffer) || buffer.length < 22) return { ...empty, error: 'too small' };

  let eocd = -1;
  const stop = Math.max(0, buffer.length - 22 - MAX_COMMENT);
  for (let i = buffer.length - 22; i >= stop; i--) {
    if (buffer.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) return { ...empty, error: 'no end of central directory' };

  const count = buffer.readUInt16LE(eocd + 10);
  const cdOffset = buffer.readUInt32LE(eocd + 16);
  // ZIP64 archives store 0xFFFFFFFF here; app packages that large are out of scope.
  if (cdOffset === 0xffffffff) return { ...empty, error: 'zip64 not supported' };

  const entries = [];
  let cursor = cdOffset;
  for (let i = 0; i < count; i++) {
    if (cursor + 46 > buffer.length || buffer.readUInt32LE(cursor) !== CEN_SIG) break;
    const method = buffer.readUInt16LE(cursor + 10);
    const compressedSize = buffer.readUInt32LE(cursor + 20);
    const size = buffer.readUInt32LE(cursor + 24);
    const nameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentLength = buffer.readUInt16LE(cursor + 32);
    const offset = buffer.readUInt32LE(cursor + 42);
    const name = buffer.subarray(cursor + 46, cursor + 46 + nameLength).toString('utf8');
    entries.push({ name, method, compressedSize, size, offset });
    cursor += 46 + nameLength + extraLength + commentLength;
  }

  const byName = new Map(entries.map((entry) => [entry.name, entry]));

  /**
   * Inflate one entry. Returns null when missing, unsupported or larger than maxBytes.
   */
  function read(name, maxBytes = 16 * 1024 * 1024) {
    const entry = byName.get(name);
    if (!entry || entry.size > maxBytes) return null;
    const local = entry.offset;
    if (local + 30 > buffer.length || buffer.readUInt32LE(local) !== LOC_SIG) return null;
    const start = local + 30 + buffer.readUInt16LE(local + 26) + buffer.readUInt16LE(local + 28);
    const data = buffer.subarray(start, start + entry.compressedSize);
    try {
      if (entry.method === 0) return Buffer.from(data);
      if (entry.method === 8) return inflateRawSync(data, { maxOutputLength: maxBytes });
    } catch {
      return null;
    }
    return null;
  }

  return { valid: true, entries, read };
}

/**
 * @param {string} filePath
 */
export async function readZip(filePath) {
  try {
    return parseZip(await fsp.readFile(filePath));
  } catch (error) {
    return { valid: false, error: error.message, entries: [], read: () => null };
  }
}
