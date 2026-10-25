import fsp from 'node:fs/promises';
import path from 'node:path';

/**
 * Re-iterable lazy view over the files collected by walk.js. The walk happens
 * once; surfaces can iterate this as many times as they need.
 */
class FileCollection {
  /** @param {Array<object>} files */
  constructor(files) {
    this._files = files;
    this.length = files.length;
  }

  *[Symbol.iterator]() {
    yield* this._files;
  }

  toArray() {
    return this._files;
  }

  some(predicate) {
    return this._files.some(predicate);
  }

  filter(predicate) {
    return this._files.filter(predicate);
  }
}

function escapeRegExp(value) {
  return value.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
}

/**
 * Small glob matcher for ctx.has(): **, *, ?. Case-insensitive because these
 * paths come from Windows/macOS packages too.
 *
 * @param {string} pattern
 * @returns {RegExp}
 */
export function globToRegExp(pattern) {
  const normalized = pattern.replace(/\\/g, '/').replace(/^\.\//, '');
  let source = '';
  for (let i = 0; i < normalized.length; i++) {
    const char = normalized[i];
    if (char === '*') {
      if (normalized[i + 1] === '*') {
        i += 1;
        if (normalized[i + 1] === '/') {
          i += 1;
          source += '(?:.*/)?';
        } else {
          source += '.*';
        }
      } else {
        source += '[^/]*';
      }
    } else if (char === '?') {
      source += '[^/]';
    } else {
      source += escapeRegExp(char);
    }
  }
  return new RegExp(`^${source}$`, 'i');
}

/**
 * The asar that directly contains a display path, or '' for the scan root.
 *
 * @param {string} displayPath
 * @returns {string}
 */
export function containerOf(displayPath) {
  const index = displayPath.lastIndexOf('!/');
  return index === -1 ? '' : displayPath.slice(0, index);
}

/**
 * Build the ctx object shared by all surfaces.
 *
 * @param {{
 *   target: string,
 *   root: string,
 *   mode: 'build'|'source',
 *   rootFiles: string[],
 *   files: Array<object>,
 *   scanned: number,
 *   options: object,
 * }} input
 * @returns {object}
 */
export function createContext(input) {
  const fileByPath = new Map(input.files.map((file) => [file.displayPath, file]));
  const matchPaths = [
    ...new Set([...input.rootFiles, ...input.files.map((file) => file.displayPath)]),
  ];
  const globCache = new Map();

  const has = (pattern) => {
    let regex = globCache.get(pattern);
    if (!regex) {
      regex = globToRegExp(pattern);
      globCache.set(pattern, regex);
    }
    return matchPaths.some((candidate) => regex.test(candidate));
  };

  const readBytes = async (absPath, start = 0, length) => {
    const handle = await fsp.open(absPath, 'r');
    try {
      const stat = await handle.stat();
      const remaining = Math.max(0, stat.size - start);
      const size = length === undefined ? remaining : Math.min(length, remaining);
      const buffer = Buffer.alloc(size);
      const { bytesRead } = await handle.read(buffer, 0, size, start);
      return buffer.subarray(0, bytesRead);
    } finally {
      await handle.close();
    }
  };

  return {
    target: input.target,
    root: input.root,
    rootLabel: path.basename(input.root) || input.root,
    mode: input.mode,
    rootFiles: [...input.rootFiles],
    files: new FileCollection(input.files),
    fileByPath,
    has,
    readBytes,
    scanned: input.scanned,
    options: { ...input.options },
  };
}
