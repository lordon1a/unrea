import { existsSync } from 'node:fs';
import path from 'node:path';
import fuses from '@electron/fuses';

const { getCurrentFuseWire, FuseV1Options, FuseState } = fuses;
const ENABLE = FuseState?.ENABLE ?? 49;
const DISABLE = FuseState?.DISABLE ?? 48;

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
 * Could this path be an Electron executable? Windows builds have .exe files;
 * other platforms use an extensionless binary sitting next to resources/app.asar.
 *
 * @param {string} absPath
 * @param {string} [name]
 * @returns {boolean}
 */
export function isCandidate(absPath, name = path.basename(absPath)) {
  if (/\.exe$/i.test(name)) return true;
  if (name.includes('.')) return false;
  return existsSync(path.join(path.dirname(absPath), 'resources', 'app.asar'));
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
    wire = await getCurrentFuseWire(file.absPath);
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
