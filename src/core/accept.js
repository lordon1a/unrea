import fsp from 'node:fs/promises';
import path from 'node:path';

import { globToRegExp } from './context.js';

export const CONFIG_FILE_NAME = '.unrea.json';

/**
 * A bad accept list is a usage error, not a scan finding: accepting a finding
 * has to be a conscious decision, so a missing reason fails the scan.
 */
export class AcceptConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AcceptConfigError';
  }
}

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Read one accept entry and fail loudly when the intent is unclear.
 *
 * @param {unknown} entry
 * @param {string} file
 * @param {number} index
 * @returns {{id:string, reason:string, path:string|null}}
 */
function normalizeEntry(entry, file, index) {
  const where = `${file}: accept[${index}]`;
  if (!isObject(entry)) {
    throw new AcceptConfigError(`${where} must be an object with "id" and "reason"`);
  }
  if (typeof entry.id !== 'string' || !entry.id.trim()) {
    throw new AcceptConfigError(`${where} needs a non-empty "id" (the check id to accept)`);
  }
  if (typeof entry.reason !== 'string' || !entry.reason.trim()) {
    throw new AcceptConfigError(
      `${where} (${entry.id.trim()}) needs a non-empty "reason"; accepting a finding must be a conscious decision`,
    );
  }
  if (entry.path !== undefined && (typeof entry.path !== 'string' || !entry.path.trim())) {
    throw new AcceptConfigError(`${where} (${entry.id.trim()}): "path" must be a non-empty glob string`);
  }

  return {
    id: entry.id.trim(),
    reason: entry.reason.trim(),
    path: entry.path ? entry.path.trim().replace(/\\/g, '/') : null,
  };
}

/**
 * Parse a `.unrea.json` document.
 *
 * @param {string} text
 * @param {string} file
 * @returns {{id:string, reason:string, path:string|null}[]}
 */
export function parseAcceptConfig(text, file) {
  let parsed;
  try {
    parsed = JSON.parse(text.replace(/^\uFEFF/, ''));
  } catch (error) {
    throw new AcceptConfigError(`${file}: invalid JSON (${error.message})`);
  }
  if (!isObject(parsed)) {
    throw new AcceptConfigError(`${file}: expected a JSON object with an "accept" array`);
  }
  if (parsed.accept === undefined) return [];
  if (!Array.isArray(parsed.accept)) {
    throw new AcceptConfigError(`${file}: "accept" must be an array`);
  }
  return parsed.accept.map((entry, index) => normalizeEntry(entry, file, index));
}

function existingFile(file) {
  return fsp.stat(file).then((info) => info.isFile()).catch(() => false);
}

/**
 * Find and read the accept list.
 *
 * Order: an explicit `--config` file, then `.unrea.json` in the scanned target,
 * then `.unrea.json` in the current directory. The first file that exists wins.
 *
 * @param {{target: string, configPath?: string|null, cwd?: string}} options
 * @returns {Promise<{file: string|null, entries: Array<{id:string, reason:string, path:string|null}>}>}
 */
export async function loadAcceptConfig({ target, configPath = null, cwd = process.cwd() }) {
  if (configPath) {
    const explicit = path.resolve(cwd, configPath);
    if (!(await existingFile(explicit))) {
      throw new AcceptConfigError(`config file not found: ${explicit}`);
    }
    let text;
    try {
      text = await fsp.readFile(explicit, 'utf8');
    } catch (error) {
      throw new AcceptConfigError(`cannot read config file ${explicit}: ${error.message}`);
    }
    return { file: explicit, entries: parseAcceptConfig(text, explicit) };
  }

  const resolvedTarget = path.resolve(cwd, target);
  let targetDirectory = resolvedTarget;
  try {
    const info = await fsp.stat(resolvedTarget);
    if (!info.isDirectory()) targetDirectory = path.dirname(resolvedTarget);
  } catch {
    // The scan itself reports an unreadable target; still allow a cwd config.
  }

  const candidates = [path.join(targetDirectory, CONFIG_FILE_NAME), path.join(cwd, CONFIG_FILE_NAME)];
  const seen = new Set();
  for (const candidate of candidates) {
    const resolved = path.resolve(candidate);
    if (seen.has(resolved)) continue;
    seen.add(resolved);
    if (!(await existingFile(resolved))) continue;

    let text;
    try {
      text = await fsp.readFile(resolved, 'utf8');
    } catch (error) {
      throw new AcceptConfigError(`cannot read config file ${resolved}: ${error.message}`);
    }
    return { file: resolved, entries: parseAcceptConfig(text, resolved) };
  }

  return { file: null, entries: [] };
}

/**
 * Does an accept entry cover this finding? `id` matches exactly or as a
 * family wildcard (`secret.*`); `path` is a glob over the finding location.
 *
 * @param {{id:string, reason:string, path:string|null}} entry
 * @param {{id:string, file?:string}} finding
 * @returns {boolean}
 */
export function acceptEntryMatches(entry, finding) {
  const idMatches =
    entry.id === finding.id ||
    (entry.id.endsWith('.*') && finding.id.startsWith(entry.id.slice(0, -1)));
  if (!idMatches) return false;
  if (!entry.path) return true;

  const file = String(finding.file || '').replace(/\\/g, '/');
  if (!file) return false;
  return globToRegExp(entry.path).test(file);
}

function location(finding) {
  return finding.line == null ? String(finding.file || '') : `${finding.file}:${finding.line}`;
}

/**
 * Mark accepted findings. Critical secrets can never be accepted: an attacker
 * who has the key does not care about intent, so the finding stays counted and
 * the scan warns instead of hiding it.
 *
 * @param {Array<object>} findings
 * @param {Array<{id:string, reason:string, path:string|null}>} entries
 * @returns {{findings: Array<object>, accepted: number, warnings: string[]}}
 */
export function applyAcceptList(findings, entries = []) {
  if (!entries.length) return { findings, accepted: 0, warnings: [] };

  const warnings = [];
  const warned = new Set();
  let accepted = 0;

  const next = findings.map((finding) => {
    const entry = entries.find((candidate) => acceptEntryMatches(candidate, finding));
    if (!entry) return finding;

    if (finding.id.startsWith('secret.') && finding.severity === 'critical') {
      const warning = `cannot accept ${finding.id} (${location(finding)}): critical secrets must be rotated, not accepted`;
      if (!warned.has(warning)) {
        warned.add(warning);
        warnings.push(warning);
      }
      return finding;
    }

    accepted += 1;
    return { ...finding, accepted: true, reason: entry.reason };
  });

  return { findings: next, accepted, warnings };
}
