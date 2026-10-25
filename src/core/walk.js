import { existsSync } from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { extractAll, extractFile, listPackage } from '@electron/asar';

import { createContext } from './context.js';

const TEXT_EXTENSIONS = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.json',
  '.html',
  '.map',
  '.env',
  '.ts',
  '.txt',
  '.yml',
  '.yaml',
  '.toml',
  '.ini',
  '.cfg',
]);
const MAX_TEXT_SIZE = 5 * 1024 * 1024;
const MAX_ASAR_DEPTH = 3;
const TEST_DIRS = new Set(['test', 'tests', '__tests__', 'e2e', 'spec']);

function isAsarName(name) {
  return /\.asar$/i.test(name);
}

function isNodeModulesPath(displayPath) {
  return /(^|[\\/])node_modules[\\/]/.test(displayPath);
}

function pathSegments(displayPath) {
  return displayPath.split(/[!/\\]/).filter(Boolean);
}

function isVendorDirectory(displayPath) {
  return pathSegments(displayPath).some((part) => part.toLowerCase() === 'vendor');
}

function isVendorPath(displayPath) {
  return isNodeModulesPath(displayPath) || isVendorDirectory(displayPath);
}

function isDirectory(filePath) {
  return fsp
    .stat(filePath)
    .then((stat) => stat.isDirectory())
    .catch(() => false);
}

/**
 * A source repo has package.json plus a source marker at its root and no
 * build artifact at the root.
 *
 * @param {string} root
 * @param {import('node:fs').Stats} stat
 * @returns {Promise<'build'|'source'>}
 */
async function detectScanMode(root, stat) {
  if (!stat.isDirectory()) return 'build';

  const packagePath = path.join(root, 'package.json');
  try {
    if (!(await fsp.stat(packagePath)).isFile()) return 'build';
  } catch {
    return 'build';
  }

  const markers = await Promise.all(
    ['.git', 'src', 'test'].map((name) => isDirectory(path.join(root, name))),
  );
  if (!markers.some(Boolean)) return 'build';

  let entries;
  try {
    entries = await fsp.readdir(root, { withFileTypes: true });
  } catch {
    return 'source';
  }

  const hasBuildArtifact = entries.some(
    (entry) =>
      (entry.isDirectory() && entry.name.toLowerCase() === 'win-unpacked') ||
      (entry.isFile() && /\.(?:asar|exe)$/i.test(entry.name)),
  );
  return hasBuildArtifact ? 'build' : 'source';
}

/**
 * Is this a shipped test/spec file? Path-based, and never true inside
 * node_modules (vendor test files are not our test code).
 *
 * @param {string} displayPath
 * @returns {boolean}
 */
function isTestFile(displayPath) {
  if (isNodeModulesPath(displayPath)) return false;
  const inner = displayPath.split('!/').pop() || '';
  const parts = inner.split(/[\\/]/).filter(Boolean);
  if (!parts.length) return false;
  const base = parts[parts.length - 1];
  const inTestDir = parts.slice(0, -1).some((part) => TEST_DIRS.has(part.toLowerCase()));
  const testName = /\.(?:test|spec)\./i.test(base);
  return inTestDir || testName;
}

function textExtension(name) {
  const lower = name.toLowerCase();
  if (lower === '.env' || lower.startsWith('.env.')) return '.env';
  const ext = path.extname(lower);
  return TEXT_EXTENSIONS.has(ext) ? ext : null;
}

/**
 * Could this path be an Electron executable? Windows builds have .exe files,
 * Linux builds have an extensionless binary next to resources/app.asar, and
 * macOS builds live in <App>.app/Contents/MacOS/<binary>.
 *
 * @param {string} absPath
 * @param {string} [name]
 * @returns {boolean}
 */
export function isFuseCandidate(absPath, name = path.basename(absPath)) {
  if (/\.exe$/i.test(name)) return true;
  if (name.includes('.')) return false;

  const directory = path.dirname(absPath);
  if (existsSync(path.join(directory, 'resources', 'app.asar'))) return true;

  const parent = path.basename(directory).toLowerCase();
  const grandParent = path.basename(path.dirname(directory)).toLowerCase();
  const bundle = path
    .basename(path.dirname(path.dirname(directory)))
    .toLowerCase();
  return parent === 'macos' && grandParent === 'contents' && bundle.endsWith('.app');
}

async function removeQuietly(dir) {
  try {
    await fsp.rm(dir, { recursive: true, force: true, maxRetries: 3 });
  } catch {
    // Best-effort temp cleanup; never fail a scan because of the OS.
  }
}

async function extractWithListing(asarPath, destDir) {
  const entries = listPackage(asarPath, {});
  for (const entry of entries) {
    const relative = entry.replace(/^[/\\]+/, '');
    if (!relative) continue;
    const destination = path.join(destDir, relative);
    const relativeCheck = path.relative(destDir, destination);
    if (relativeCheck.startsWith('..') || path.isAbsolute(relativeCheck)) continue;
    let data;
    try {
      data = extractFile(asarPath, relative);
    } catch {
      continue; // directories, links and unpacked entries
    }
    if (!data) continue;
    await fsp.mkdir(path.dirname(destination), { recursive: true });
    await fsp.writeFile(destination, data);
  }
}

async function extractAsar(asarPath, destDir) {
  try {
    await extractAll(asarPath, destDir);
    return true;
  } catch {
    try {
      await extractWithListing(asarPath, destDir);
      return true;
    } catch {
      return false;
    }
  }
}

function fileMetadata(absPath, displayPath, kind, size) {
  const name = path.basename(displayPath);
  return {
    displayPath,
    absPath,
    kind,
    basename: name,
    ext: path.extname(name).toLowerCase(),
    size,
    inNodeModules: isNodeModulesPath(displayPath),
    inVendor: isVendorPath(displayPath),
    inTest: isTestFile(displayPath),
  };
}

/**
 * Walk a target once and build the shared context. The caller owns cleanup and
 * must call it after all surfaces have run.
 *
 * @param {string} targetPath
 * @param {{mode?: 'build'|'source'}} [options]
 * @returns {Promise<{context: object, cleanup: () => Promise<void>}>}
 */
export async function createScanContext(targetPath, options = {}) {
  const root = path.resolve(targetPath);
  let stat;
  try {
    stat = await fsp.stat(root);
  } catch (error) {
    const reason = error?.code === 'ENOENT' ? 'no such file or directory' : error.message;
    throw new Error(`cannot read "${targetPath}": ${reason}`);
  }

  const mode =
    options.mode === 'source' || options.mode === 'build'
      ? options.mode
      : await detectScanMode(root, stat);

  const state = {
    files: [],
    scanned: 0,
    temps: [],
    rootFiles: [],
  };

  const addFile = (file) => {
    state.files.push(file);
    return file;
  };

  const walkDirectory = async (dirAbs, displayBase, depth) => {
    let entries;
    try {
      entries = await fsp.readdir(dirAbs, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const absPath = path.join(dirAbs, entry.name);
      const displayPath = `${displayBase}${entry.name}`;
      if (entry.isDirectory()) {
        if (mode === 'source' && entry.name.toLowerCase() === 'node_modules') {
          continue;
        }
        await walkDirectory(absPath, `${displayPath}/`, depth);
      } else if (entry.isFile()) {
        await handleFile(absPath, displayPath, depth);
      }
    }
  };

  const handleFile = async (absPath, displayPath, depth) => {
    const name = path.basename(absPath);

    if (isAsarName(name)) {
      let size = 0;
      try {
        size = (await fsp.stat(absPath)).size;
      } catch {
        return;
      }
      addFile(fileMetadata(absPath, displayPath, 'asar', size));
      if (depth >= MAX_ASAR_DEPTH) return;

      let tempRoot;
      try {
        tempRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'unrea-'));
      } catch {
        return;
      }
      state.temps.push(tempRoot);
      const extracted = path.join(tempRoot, 'extracted');
      const ok = await extractAsar(absPath, extracted);
      if (!ok) return;
      await walkDirectory(extracted, `${displayPath}!/`, depth + 1);
      return;
    }

    if (isFuseCandidate(absPath, name)) {
      addFile(fileMetadata(absPath, displayPath, 'binary', 0));
      return;
    }

    const ext = textExtension(name);
    let stat;
    try {
      stat = await fsp.stat(absPath);
    } catch {
      stat = null;
    }

    if (!ext || !stat || !stat.isFile() || stat.size > MAX_TEXT_SIZE) {
      addFile(fileMetadata(absPath, displayPath, 'other', stat?.size ?? 0));
      return;
    }

    let buffer;
    try {
      buffer = await fsp.readFile(absPath);
    } catch {
      addFile(fileMetadata(absPath, displayPath, 'other', stat.size));
      return;
    }
    if (buffer.subarray(0, 8192).includes(0)) {
      addFile(fileMetadata(absPath, displayPath, 'other', buffer.length));
      return;
    }

    let text = buffer.toString('utf8');
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

    state.scanned += 1;
    addFile({
      ...fileMetadata(absPath, displayPath, 'text', buffer.length),
      ext,
      text,
    });
  };

  if (stat.isDirectory()) {
    try {
      state.rootFiles = (await fsp.readdir(root)).sort();
    } catch {
      state.rootFiles = [];
    }
  } else if (stat.isFile()) {
    const name = path.basename(root);
    state.rootFiles = [name];
  } else {
    throw new Error(`unsupported target "${targetPath}"`);
  }

  const cleanup = async () => {
    await Promise.all(state.temps.map(removeQuietly));
  };

  try {
    if (stat.isDirectory()) {
      await walkDirectory(root, '', 0);
    } else {
      await handleFile(root, path.basename(root), 0);
    }

    const context = createContext({
      target: targetPath,
      root,
      mode,
      rootFiles: state.rootFiles,
      files: state.files,
      scanned: state.scanned,
      options,
    });
    return { context, cleanup };
  } catch (error) {
    await cleanup();
    throw error;
  }
}
