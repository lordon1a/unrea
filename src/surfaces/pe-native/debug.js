/**
 * Debug directory / CodeView helpers. `src/parse/pe.js` exposes the debug data
 * directory but does not decode it, and pe.js is shared code, so the decoding
 * lives here (a surface may add parsers, not edit the shared reader).
 */

const DEBUG_ENTRY_SIZE = 28; // IMAGE_DEBUG_DIRECTORY
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;
const MAX_ENTRIES = 64;

/**
 * RVA -> file offset using the section table. Mirrors the shared reader's
 * logic because pe.js does not export it.
 *
 * @param {number} rva
 * @param {object} pe parsed PE
 * @param {number} limit file size used for bounds checks
 * @returns {number|null}
 */
export function rvaToOffset(rva, pe, limit) {
  if (!rva || !Number.isFinite(rva)) return null;
  const sizeOfHeaders = pe.optional?.sizeOfHeaders || 0;
  if (rva < sizeOfHeaders && rva < limit) return rva;
  for (const section of pe.sections || []) {
    const span = Math.max(section.virtualSize, section.rawSize);
    if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
      const delta = rva - section.virtualAddress;
      if (delta >= section.rawSize) return null;
      const offset = section.rawPointer + delta;
      return offset < limit ? offset : null;
    }
  }
  return null;
}

/**
 * @param {object} pe
 * @returns {{virtualAddress:number,size:number}|null}
 */
export function debugDirectory(pe) {
  const directory = (pe.directories || []).find(
    (entry) => entry.name === 'debug' && entry.virtualAddress,
  );
  return directory || null;
}

/**
 * @param {Buffer} buffer head of the file (headers included)
 * @param {object} pe
 * @returns {Array<{type:number,sizeOfData:number,addressOfRawData:number,pointerToRawData:number}>}
 */
export function readDebugEntries(buffer, pe) {
  const directory = debugDirectory(pe);
  if (!directory) return [];
  const base = rvaToOffset(directory.virtualAddress, pe, buffer.length);
  if (base === null) return [];

  const count = Math.min(
    Math.floor(directory.size / DEBUG_ENTRY_SIZE) || 0,
    MAX_ENTRIES,
  );
  const entries = [];
  for (let i = 0; i < count; i++) {
    const offset = base + i * DEBUG_ENTRY_SIZE;
    if (offset + DEBUG_ENTRY_SIZE > buffer.length) break;
    entries.push({
      type: buffer.readUInt32LE(offset + 12),
      sizeOfData: buffer.readUInt32LE(offset + 16),
      addressOfRawData: buffer.readUInt32LE(offset + 20),
      pointerToRawData: buffer.readUInt32LE(offset + 24),
    });
  }
  return entries;
}

/**
 * CodeView record layouts:
 *   RSDS (PDB 7): "RSDS" + 16-byte GUID + u32 age + NUL-terminated UTF-8 path
 *   NB10 (PDB 2): "NB10" + u32 offset + u32 timestamp + u32 age + path
 *
 * @param {Buffer} record
 * @returns {string|null}
 */
export function extractCodeViewPath(record) {
  if (!record || record.length < 8) return null;
  const signature = record.subarray(0, 4).toString('latin1');
  let start;
  if (signature === 'RSDS') start = 24;
  else if (signature === 'NB10') start = 16;
  else return null;

  if (start >= record.length) return null;
  const end = record.indexOf(0, start);
  const stop = end === -1 ? record.length : end;
  const value = record
    .subarray(start, Math.min(stop, start + 512))
    .toString('utf8')
    .replace(/[\u0000-\u001f]/g, '')
    .trim();
  return value || null;
}

export function isCodeView(type) {
  return type === IMAGE_DEBUG_TYPE_CODEVIEW;
}
