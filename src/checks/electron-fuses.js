import { existsSync } from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { FuseState, FuseV1Options, getCurrentFuseWire } from '@electron/fuses';

const ENABLE = FuseState.ENABLE;
const DISABLE = FuseState.DISABLE;

const FUSE_RULES = [
  {
    option: FuseV1Options.RunAsNode,
    name: 'RunAsNode',
    state: ENABLE,
    stateLabel: 'enabled',
    severity: 'high',
    id: 'electron.fuses.run_as_node',
  },
  {
    option: FuseV1Options.EnableNodeCliInspectArguments,
    name: 'EnableNodeCliInspectArguments',
    state: ENABLE,
    stateLabel: 'enabled',
    severity: 'high',
    id: 'electron.fuses.node_cli_inspect',
  },
  {
    option: FuseV1Options.EnableEmbeddedAsarIntegrityValidation,
    name: 'EnableEmbeddedAsarIntegrityValidation',
    state: DISABLE,
    stateLabel: 'disabled',
    severity: 'medium',
    id: 'electron.fuses.asar_integrity',
  },
  {
    option: FuseV1Options.OnlyLoadAppFromAsar,
    name: 'OnlyLoadAppFromAsar',
    state: DISABLE,
    stateLabel: 'disabled',
    severity: 'medium',
    id: 'electron.fuses.only_load_app_from_asar',
  },
  {
    option: FuseV1Options.EnableNodeOptionsEnvironmentVariable,
    name: 'EnableNodeOptionsEnvironmentVariable',
    state: ENABLE,
    stateLabel: 'enabled',
    severity: 'medium',
    id: 'electron.fuses.node_options',
  },
];

/**
 * Could this path be an Electron executable? Windows builds have .exe files,
 * Linux builds have an extensionless binary next to resources/app.asar, and
 * macOS builds live in <App>.app/Contents/MacOS/<binary>.
 *
 * @param {string} absPath
 * @param {string} [name]
 * @returns {boolean}
 */
export function isCandidate(absPath, name = path.basename(absPath)) {
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

/**
 * @electron/fuses redirects any path containing ".app" to the Electron
 * Framework. That is right for a real app bundle, but a synthetic or local
 * fuse wire in Contents/MacOS needs a direct read. Fall back to a temp copy
 * with no ".app" segment.
 *
 * @param {string} binaryPath
 * @returns {Promise<object>}
 */
async function readFuseWire(binaryPath) {
  try {
    return await getCurrentFuseWire(binaryPath);
  } catch (error) {
    if (!binaryPath.includes('.app')) throw error;
  }

  let tempDir;
  try {
    tempDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'unrea-fuse-'));
    const copy = path.join(tempDir, 'binary');
    await fsp.copyFile(binaryPath, copy);
    return await getCurrentFuseWire(copy);
  } finally {
    if (tempDir) {
      await fsp.rm(tempDir, { recursive: true, force: true }).catch(() => {});
    }
  }
}

/**
 * electron.fuses — weak fuse wire settings expose the binary to debuggers and
 * allow app.asar to be swapped or bypassed.
 *
 * @param {object} file
 * @returns {Promise<Array<object>>}
 */
export async function run(file) {
  if (file.kind !== 'binary') return [];

  let wire;
  try {
    wire = await readFuseWire(file.absPath);
  } catch {
    // Not an Electron binary (or no fuse wire); nothing to report.
    return [];
  }
  if (!wire) return [];

  const findings = [];
  for (const rule of FUSE_RULES) {
    if (wire[rule.option] !== rule.state) continue;
    findings.push({
      id: rule.id,
      severity: rule.severity,
      file: file.displayPath,
      line: null,
      snippet: `${rule.name}: ${rule.stateLabel}`,
      fix: `${rule.name} is ${rule.stateLabel}: flip it with @electron/fuses at build time`,
    });
  }
  return findings;
}
