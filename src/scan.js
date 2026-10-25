import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { extractAll, extractFile, listPackage } from '@electron/asar';

import * as secret from './checks/secret.js';
import * as sourcemap from './checks/sourcemap.js';
import * as envFile from './checks/env-file.js';
import * as license from './checks/license.js';
import * as codeReadable from './checks/code-readable.js';
import * as endpoint from './checks/endpoint.js';
import * as electronFuses from './checks/electron-fuses.js';
import * as asarCheck from './checks/asar.js';

const CHECKS = [secret, sourcemap, envFile, license, codeReadable, endpoint, electronFuses, asarCheck];

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

const SEVERITY_DOWNGRADE = {
  critical: 'high',
  high: 'medium',
  medium: 'info',
  info: 'info',
};

function downgrade(severity) {
  return SEVERITY_DOWNGRADE[severity] || severity;
}

function isAsarName(name) {
  return /\.asar$/i.test(name);
}

function isVendor(displayPath) {
  return /(^|[\\/])node_modules[\\/]/.test(displayPath);
}

function pathSegments(displayPath) {
  return displayPath.split(/[!/\\]/).filter(Boolean);
}

function isVendorDirectory(displayPath) {
  return pathSegments(displayPath).some((part) => part.toLowerCase() === 'vendor');
}

function isVendorPath(displayPath) {
  return isVendor(displayPath) || isVendorDirectory(displayPath);
}

function isVendorProviderSecret(id) {
  return id.startsWith('secret.') && id !== 'secret.generic';
}

async function isDirectory(filePath) {
  try {
    return (await fsp.stat(filePath)).isDirectory();
  } catch {
    return false;
  }
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
 * @returns {{base:string}|null}
 */
function testFileInfo(displayPath) {
  if (isVendor(displayPath)) return null;
  const inner = displayPath.split('!/').pop() || '';
  const parts = inner.split(/[\\/]/).filter(Boolean);
  if (!parts.length) return null;
  const base = parts[parts.length - 1];
  const inTestDir = parts.slice(0, -1).some((part) => TEST_DIRS.has(part.toLowerCase()));
  const testName = /\.(?:test|spec)\./i.test(base);
  return inTestDir || testName ? { base } : null;
}

/**
 * The asar that directly contains a display path, or '' for the scan root.
 *
 * @param {string} displayPath
 * @returns {string}
 */
function asarContainer(displayPath) {
  const index = displayPath.lastIndexOf('!/');
  return index === -1 ? '' : displayPath.slice(0, index);
}

function textExtension(name) {
  const lower = name.toLowerCase();
  if (lower === '.env' || lower.startsWith('.env.')) return '.env';
  const ext = path.extname(lower);
  return TEXT_EXTENSIONS.has(ext) ? ext : null;
}

function isFuseBinary(absPath, name) {
  return electronFuses.isCandidate(absPath, name);
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

/**
 * Scan a directory or a single .asar/.js/.exe file.
 *
 * @param {string} targetPath
 * @param {{mode?: 'build'|'source'}} [options]
 * @returns {Promise<{findings: Array<object>, scanned: number, durationMs: number, mode: 'build'|'source'}>}
 */
export async function scan(targetPath, options = {}) {
  const started = Date.now();
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

  const rootLabel = path.basename(root) || root;
  const state = {
    mode,
    findings: [],
    scanned: 0,
    temps: [],
    testContainers: new Map(),
  };

  const registerTestFile = (displayPath) => {
    if (!testFileInfo(displayPath)) return false;
    const container = asarContainer(displayPath);
    const entry = state.testContainers.get(container) || { count: 0, example: displayPath };
    entry.count += 1;
    state.testContainers.set(container, entry);
    return true;
  };

  const addFindings = (file, results) => {
    for (const result of results || []) {
      if (!result || !result.id) continue;
      let severity = file.inNodeModules ? downgrade(result.severity) : result.severity;
      let snippet = result.snippet ?? '';
      const prefixes = [];

      if (file.inVendor && isVendorProviderSecret(result.id)) {
        // Provider regexes and PEM headers in vendor bundles are usually
        // library test data or public constants, not live credentials.
        severity = 'info';
        prefixes.push('[vendor code]');
      }
      if (file.isTest && result.id.startsWith('secret.')) {
        // A fixture key is still worth showing, but it is not a live leak.
        severity = 'info';
        prefixes.push('[test file, likely fixture]');
      }
      if (file.inVendor && result.id === 'sourcemap.comment') {
        severity = downgrade(severity);
      }
      if (prefixes.length) snippet = `${prefixes.join(' ')} ${snippet}`;

      state.findings.push({
        id: result.id,
        severity,
        file: result.file || file.displayPath,
        line: result.line ?? null,
        snippet,
        fix: result.fix ?? '',
      });
    }
  };

  const runChecks = async (file) => {
    for (const check of CHECKS) {
      const results = await check.run(file);
      addFindings(file, results);
    }
  };

  const processText = async (absPath, displayPath, ext, isTest, state) => {
    let buffer;
    try {
      buffer = await fsp.readFile(absPath);
    } catch {
      return;
    }
    if (buffer.length > MAX_TEXT_SIZE) return;
    if (buffer.subarray(0, 8192).includes(0)) return; // binary wearing a text extension

    let text = buffer.toString('utf8');
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

    state.scanned += 1;
    await runChecks({
      kind: 'text',
      absPath,
      displayPath,
      basename: path.basename(displayPath),
      ext,
      size: buffer.length,
      text,
      inNodeModules: isVendor(displayPath),
      inVendor: isVendorPath(displayPath),
      isTest,
    });
  };

  const processBinary = async (absPath, displayPath, state) => {
    await runChecks({
      kind: 'binary',
      absPath,
      displayPath,
      basename: path.basename(displayPath),
      ext: path.extname(displayPath).toLowerCase(),
      size: 0,
      text: '',
      inNodeModules: isVendor(displayPath),
      inVendor: isVendorPath(displayPath),
    });
  };

  const walkDirectory = async (dirAbs, displayBase, depth, state) => {
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
        if (state.mode === 'source' && entry.name.toLowerCase() === 'node_modules') {
          continue;
        }
        await walkDirectory(absPath, `${displayPath}/`, depth, state);
      } else if (entry.isFile()) {
        await handleFile(absPath, displayPath, depth, state);
      }
    }
  };

  const handleAsar = async (asarAbs, displayPath, depth, state) => {
    let size = 0;
    try {
      size = (await fsp.stat(asarAbs)).size;
    } catch {
      return;
    }
    await runChecks({
      kind: 'asar',
      absPath: asarAbs,
      displayPath,
      basename: path.basename(displayPath),
      ext: '.asar',
      size,
      text: '',
      inNodeModules: isVendor(displayPath),
      inVendor: isVendorPath(displayPath),
    });

    if (depth >= MAX_ASAR_DEPTH) return;

    let tempRoot;
    try {
      tempRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'unrea-'));
    } catch {
      return;
    }
    state.temps.push(tempRoot);
    const extracted = path.join(tempRoot, 'extracted');
    const ok = await extractAsar(asarAbs, extracted);
    if (!ok) return;
    await walkDirectory(extracted, `${displayPath}!/`, depth + 1, state);
  };

  const handleFile = async (absPath, displayPath, depth, state) => {
    const name = path.basename(absPath);
    const isTest = registerTestFile(displayPath);
    if (isAsarName(name)) {
      await handleAsar(absPath, displayPath, depth, state);
      return;
    }
    if (isFuseBinary(absPath, name)) {
      await processBinary(absPath, displayPath, state);
      return;
    }
    const ext = textExtension(name);
    if (!ext) return;
    let stat;
    try {
      stat = await fsp.stat(absPath);
    } catch {
      return;
    }
    if (!stat.isFile() || stat.size > MAX_TEXT_SIZE) return;
    await processText(absPath, displayPath, ext, isTest, state);
  };

  try {
    if (stat.isDirectory()) {
      await walkDirectory(root, '', 0, state);
    } else if (stat.isFile()) {
      const name = path.basename(root);
      const isTest = registerTestFile(name);
      if (isAsarName(name)) {
        await handleAsar(root, name, 0, state);
      } else if (isFuseBinary(root, name)) {
        await processBinary(root, name, state);
      } else {
        const ext = textExtension(name);
        if (ext) await processText(root, name, ext, isTest, state);
      }
    } else {
      throw new Error(`unsupported target "${targetPath}"`);
    }
  } finally {
    await Promise.all(state.temps.map(removeQuietly));
  }

  if (state.mode !== 'source') {
    for (const [container, info] of state.testContainers) {
      const noun = info.count === 1 ? 'test file ships' : 'test files ship';
      state.findings.push({
        id: 'tests.shipped',
        severity: 'high',
        file: container || rootLabel,
        line: null,
        snippet: `${info.count} ${noun} in the build (e.g. ${info.example})`,
        fix: 'exclude test folders from the package (electron-builder `files` / .npmignore)',
      });
    }
  }

  const seen = new Set();
  const findings = [];
  for (const finding of state.findings) {
    const key = [finding.id, finding.severity, finding.file, finding.line, finding.snippet].join('\u0000');
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(finding);
  }

  const weights = { critical: 4, high: 3, medium: 2, info: 1 };
  findings.sort(
    (a, b) =>
      (weights[b.severity] || 0) - (weights[a.severity] || 0) ||
      a.file.localeCompare(b.file) ||
      (a.line ?? 0) - (b.line ?? 0) ||
      a.id.localeCompare(b.id),
  );

  return {
    findings,
    scanned: state.scanned,
    durationMs: Date.now() - started,
    mode: state.mode,
  };
}
