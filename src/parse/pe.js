import fsp from 'node:fs/promises';

const MACHINE_NAMES = {
  0x014c: 'x86',
  0x01c0: 'arm',
  0x01c4: 'armnt',
  0x0200: 'ia64',
  0x5032: 'riscv32',
  0x5064: 'riscv64',
  0x8664: 'x64',
  0xaa64: 'arm64',
};

const DIRECTORY_NAMES = [
  'export',
  'import',
  'resource',
  'exception',
  'certificate',
  'base-reloc',
  'debug',
  'architecture',
  'global-ptr',
  'tls',
  'load-config',
  'bound-import',
  'iat',
  'delay-import',
  'clr-runtime',
  'reserved',
];

function readU16(buffer, offset) {
  if (offset < 0 || offset + 2 > buffer.length) throw new Error('truncated u16');
  return buffer.readUInt16LE(offset);
}

function readU32(buffer, offset) {
  if (offset < 0 || offset + 4 > buffer.length) throw new Error('truncated u32');
  return buffer.readUInt32LE(offset);
}

function readU64(buffer, offset) {
  if (offset < 0 || offset + 8 > buffer.length) throw new Error('truncated u64');
  return Number(buffer.readBigUInt64LE(offset));
}

function readCString(buffer, offset, maxLength = 256) {
  if (offset === null || offset < 0 || offset >= buffer.length) return null;
  const end = Math.min(buffer.length, offset + maxLength);
  const zero = buffer.indexOf(0, offset);
  if (zero === -1 || zero >= end) return null;
  return buffer.subarray(offset, zero).toString('utf8');
}

function rvaToOffset(rva, sections, sizeOfHeaders, bufferLength) {
  if (!rva) return null;
  if (rva < sizeOfHeaders && rva < bufferLength) return rva;
  for (const section of sections) {
    const span = Math.max(section.virtualSize, section.rawSize);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
      const delta = rva - section.virtualAddress;
      if (delta >= section.rawSize) return null;
      const offset = section.rawPointer + delta;
      return offset < bufferLength ? offset : null;
    }
  }
  return null;
}

function parseDotnet(buffer, metadataRva, sections, sizeOfHeaders) {
  const metadataOffset = rvaToOffset(
    metadataRva,
    sections,
    sizeOfHeaders,
    buffer.length,
  );
  if (metadataOffset === null) return null;

  const signature = readU32(buffer, metadataOffset);
  if (signature !== 0x424a5342) return null; // BSJB

  const versionLength = readU32(buffer, metadataOffset + 12);
  const versionStart = metadataOffset + 16;
  if (versionLength > 1024 || versionStart + versionLength > buffer.length) return null;
  const version = buffer
    .subarray(versionStart, versionStart + versionLength)
    .toString('utf8')
    .split('\0')[0];

  let cursor = (versionStart + versionLength + 3) & ~3;
  const streamCount = readU16(buffer, cursor + 2);
  cursor += 4;

  const streams = {};
  for (let i = 0; i < streamCount; i++) {
    // Stream header: offset(4) + size(4) + NUL-terminated name padded to a 4-byte boundary.
    if (cursor + 12 > buffer.length) break;
    const offset = readU32(buffer, cursor);
    const size = readU32(buffer, cursor + 4);
    const rawName = buffer.subarray(cursor + 8, Math.min(buffer.length, cursor + 40));
    const zero = rawName.indexOf(0);
    if (zero === -1) break;
    const name = rawName.subarray(0, zero).toString('utf8');
    if (name) streams[name] = { offset, size };
    cursor += 8 + ((zero + 1 + 3) & ~3);
  }

  const strings = [];
  const seen = new Set();
  const stringsStream = streams['#Strings'];
  if (stringsStream) {
    let position = metadataOffset + stringsStream.offset;
    const end = Math.min(buffer.length, position + stringsStream.size);
    while (position < end && strings.length < 10000) {
      const zero = buffer.indexOf(0, position);
      if (zero === -1 || zero >= end) break;
      if (zero > position) {
        const value = buffer.subarray(position, zero).toString('utf8');
        if (value && !seen.has(value)) {
          seen.add(value);
          strings.push(value);
        }
      }
      position = zero + 1;
    }
  }

  return {
    signature: 'BSJB',
    version,
    streams,
    strings,
  };
}

/**
 * Parse a PE/COFF image from a Buffer (or Uint8Array). Never throws for
 * malformed input; returns {valid:false,error}.
 *
 * @param {Buffer|Uint8Array} input
 * @returns {object}
 */
export function parsePE(input) {
  try {
    const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
    if (buffer.length < 64) return { valid: false, error: 'file is smaller than the DOS header' };
    if (buffer.readUInt16LE(0) !== 0x5a4d) {
      return { valid: false, error: 'missing MZ signature' };
    }

    const peOffset = readU32(buffer, 0x3c);
    if (peOffset + 24 > buffer.length) {
      return { valid: false, error: 'PE header is out of bounds' };
    }
    if (readU32(buffer, peOffset) !== 0x00004550) {
      return { valid: false, error: 'missing PE signature' };
    }

    const machine = readU16(buffer, peOffset + 4);
    const numberOfSections = readU16(buffer, peOffset + 6);
    const timestamp = readU32(buffer, peOffset + 8);
    const optionalHeaderSize = readU16(buffer, peOffset + 20);
    const characteristics = readU16(buffer, peOffset + 22);
    const optionalStart = peOffset + 24;
    if (optionalStart + optionalHeaderSize > buffer.length) {
      return { valid: false, error: 'optional header is out of bounds' };
    }

    const magic = readU16(buffer, optionalStart);
    if (magic !== 0x10b && magic !== 0x20b) {
      return { valid: false, error: 'unknown optional header magic' };
    }
    const pe32Plus = magic === 0x20b;
    const entryPoint = readU32(buffer, optionalStart + 16);
    const imageBase = pe32Plus
      ? readU64(buffer, optionalStart + 24)
      : readU32(buffer, optionalStart + 28);
    const sizeOfHeaders = readU32(buffer, optionalStart + 60);
    const subsystem = readU16(buffer, optionalStart + 68);
    const dllCharacteristics = readU16(buffer, optionalStart + 70);
    const numberOfRvaAndSizes = readU32(
      buffer,
      optionalStart + (pe32Plus ? 108 : 92),
    );
    const dataDirectoryStart = optionalStart + (pe32Plus ? 112 : 96);

    const sectionTable = optionalStart + optionalHeaderSize;
    const sections = [];
    for (let i = 0; i < numberOfSections; i++) {
      const offset = sectionTable + i * 40;
      if (offset + 40 > buffer.length) break;
      const name = buffer
        .subarray(offset, offset + 8)
        .toString('utf8')
        .split('\0')[0];
      sections.push({
        name,
        virtualSize: readU32(buffer, offset + 8),
        virtualAddress: readU32(buffer, offset + 12),
        rawSize: readU32(buffer, offset + 16),
        rawPointer: readU32(buffer, offset + 20),
        characteristics: readU32(buffer, offset + 36),
      });
    }

    const directories = [];
    const directoryCount = Math.min(16, numberOfRvaAndSizes);
    for (let i = 0; i < directoryCount; i++) {
      const offset = dataDirectoryStart + i * 8;
      if (offset + 8 > buffer.length) break;
      directories.push({
        index: i,
        name: DIRECTORY_NAMES[i],
        virtualAddress: readU32(buffer, offset),
        size: readU32(buffer, offset + 4),
      });
    }

    const importDirectory = directories[1];
    const imports = [];
    if (importDirectory && importDirectory.virtualAddress) {
      let offset = rvaToOffset(
        importDirectory.virtualAddress,
        sections,
        sizeOfHeaders,
        buffer.length,
      );
      const seen = new Set();
      for (let i = 0; offset !== null && i < 1024 && offset + 20 <= buffer.length; i++) {
        const descriptor = buffer.subarray(offset, offset + 20);
        if (descriptor.every((byte) => byte === 0)) break;
        const nameRva = readU32(buffer, offset + 12);
        const nameOffset = rvaToOffset(nameRva, sections, sizeOfHeaders, buffer.length);
        const name = readCString(buffer, nameOffset);
        if (name && !seen.has(name)) {
          seen.add(name);
          imports.push(name);
        }
        offset += 20;
      }
    }

    const certificate = directories[4] || { virtualAddress: 0, size: 0 };
    const hasCertificate = certificate.size > 0;

    const cliDirectory = directories[14] || { virtualAddress: 0, size: 0 };
    let hasCLIHeader = false;
    let metadataRva = 0;
    let metadataSize = 0;
    if (cliDirectory.virtualAddress && cliDirectory.size >= 16) {
      const cliOffset = rvaToOffset(
        cliDirectory.virtualAddress,
        sections,
        sizeOfHeaders,
        buffer.length,
      );
      if (cliOffset !== null && cliOffset + 16 <= buffer.length) {
        hasCLIHeader = true;
        metadataRva = readU32(buffer, cliOffset + 8);
        metadataSize = readU32(buffer, cliOffset + 12);
      }
    }

    const dotnet = metadataRva
      ? parseDotnet(buffer, metadataRva, sections, sizeOfHeaders)
      : null;

    return {
      valid: true,
      dos: { signature: 'MZ', e_lfanew: peOffset },
      coff: {
        machine,
        machineName: MACHINE_NAMES[machine] || `unknown-0x${machine.toString(16)}`,
        numberOfSections,
        timestamp,
        optionalHeaderSize,
        characteristics,
      },
      machine,
      machineName: MACHINE_NAMES[machine] || `unknown-0x${machine.toString(16)}`,
      numberOfSections,
      entryPoint,
      subsystem,
      optional: {
        magic,
        pe32Plus,
        entryPoint,
        imageBase,
        sizeOfHeaders,
        subsystem,
        dllCharacteristics,
        numberOfRvaAndSizes,
      },
      sections,
      directories,
      dataDirectories: directories,
      imports,
      hasCertificate,
      certificate: {
        fileOffset: certificate.virtualAddress,
        size: certificate.size,
      },
      hasCLIHeader,
      metadata: { rva: metadataRva, size: metadataSize },
      isDotNet: Boolean(hasCLIHeader && metadataRva),
      dotnet,
      metadataRoot: dotnet,
      strings: dotnet?.strings || [],
    };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

/**
 * @param {string} filePath
 * @returns {Promise<object>}
 */
export async function readPE(filePath) {
  return parsePE(await fsp.readFile(filePath));
}

export default { parsePE, readPE };
