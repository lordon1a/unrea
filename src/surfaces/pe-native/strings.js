/**
 * String and build-info helpers for native PE images. Everything here reads
 * bytes that already ship in the file; nothing is decrypted or executed.
 */

const MIN_STRING = 8;
const MAX_STRINGS = 20000;
const GO_MAGIC = ' Go buildinf:';

/**
 * Classic `strings` behaviour: runs of printable ASCII bytes. A second pass
 * decodes UTF-16LE runs (Delphi and some Windows resource strings are stored
 * that way) so a secret is not missed just because every second byte is 0x00.
 *
 * @param {Buffer} buffer
 * @param {{min?:number, limit?:number}} [options]
 * @returns {string[]}
 */
export function printableStrings(buffer, options = {}) {
  const min = options.min || MIN_STRING;
  const limit = options.limit || MAX_STRINGS;
  const out = [];

  let current = [];
  for (const byte of buffer) {
    const printable = byte >= 0x20 && byte <= 0x7e;
    if (printable) {
      current.push(byte);
      continue;
    }
    if (current.length >= min) {
      out.push(Buffer.from(current).toString('latin1'));
      if (out.length >= limit) return out;
    }
    current = [];
  }
  if (current.length >= min) out.push(Buffer.from(current).toString('latin1'));
  if (out.length >= limit) return out;

  // UTF-16LE: printable byte followed by 0x00, at least `min` characters.
  let chars = [];
  for (let i = 0; i + 1 < buffer.length; i += 2) {
    const code = buffer[i];
    if (buffer[i + 1] === 0 && code >= 0x20 && code <= 0x7e) {
      chars.push(code);
      continue;
    }
    if (chars.length >= min) {
      out.push(Buffer.from(chars).toString('latin1'));
      if (out.length >= limit) return out;
    }
    chars = [];
  }
  if (chars.length >= min) out.push(Buffer.from(chars).toString('latin1'));

  return out;
}

// Cargo registry roots, rustc source hashes and crates.io cache folders are
// the fingerprints a Rust release leaves behind even after stripping symbols.
const RUST_PATH_PATTERNS = [
  /(?:^|[\\/])\.?cargo[\\/]registry[\\/]/i,
  /(?:^|[\\/])registry[\\/]src[\\/]index\.crates\.io-[0-9a-f]{6,}/i,
  /index\.crates\.io-[0-9a-f]{6,}/i,
  /(?:^|[\\/])rustc[\\/][0-9a-f]{8,}[\\/]/i,
  /(?:^|[\\/])\.rustup[\\/]toolchains[\\/]/i,
];

/**
 * @param {string[]} strings
 * @returns {{count:number, example:string|null}}
 */
export function countRustPaths(strings) {
  const seen = new Set();
  let example = null;
  for (const value of strings) {
    if (seen.has(value)) continue;
    if (!RUST_PATH_PATTERNS.some((re) => re.test(value))) continue;
    seen.add(value);
    if (!example) example = value;
  }
  return { count: seen.size, example };
}

/**
 * Go 1.18+ puts module metadata in a `.go.buildinfo` section: a magic prefix
 * followed by the plain-text build info that `go version -m` prints
 * (path/mod/dep lines separated by tabs and newlines).
 *
 * @param {Buffer} buffer section raw bytes
 * @returns {{modulePath:string|null, moduleCount:number, goVersion:string|null}|null}
 */
export function readGoBuildInfo(buffer) {
  if (!buffer || !buffer.length) return null;
  const text = buffer.toString('latin1');
  const magicIndex = text.indexOf(GO_MAGIC);
  if (magicIndex === -1) return null;

  const body = text.slice(magicIndex);
  const versionMatch = /go1\.\d+(?:\.\d+)?/.exec(body);
  const start = body.indexOf('path\t');
  if (start === -1) {
    return {
      modulePath: null,
      moduleCount: 0,
      goVersion: versionMatch ? versionMatch[0] : null,
    };
  }

  const lines = body.slice(start).split('\n').slice(0, 500);
  const modulePath = lines[0].slice('path\t'.length).trim() || null;
  const moduleCount = lines.filter((line) => line.startsWith('mod\t')).length;
  return {
    modulePath,
    moduleCount,
    goVersion: versionMatch ? versionMatch[0] : null,
  };
}
