import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SKILL_SOURCE = fileURLToPath(new URL('../skill/unrea/SKILL.md', import.meta.url));
const CLIENTS = new Set(['claude_code', 'codex', 'opencode']);

export const SETUP_CLIENTS = [...CLIENTS];

function mcpCommand(version) {
  return ['npx', '-y', `unrea@${version}`, 'mcp'];
}

async function exists(filePath) {
  try {
    await fsp.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readIfPresent(filePath) {
  try {
    return await fsp.readFile(filePath, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function installSkill(home, targetRelative, dryRun) {
  const target = path.join(home, targetRelative);
  const content = await fsp.readFile(SKILL_SOURCE, 'utf8');
  const existing = await readIfPresent(target);

  if (existing === content) {
    return { source: SKILL_SOURCE, target, status: 'unchanged' };
  }
  if (dryRun) {
    return { source: SKILL_SOURCE, target, status: 'would_copy' };
  }
  await fsp.mkdir(path.dirname(target), { recursive: true });
  await fsp.writeFile(target, content, 'utf8');
  return {
    source: SKILL_SOURCE,
    target,
    status: existing === null ? 'copied' : 'updated',
  };
}

async function backupFile(source, backupPath, dryRun) {
  if (!(await exists(source))) return { path: backupPath, status: 'none' };
  if (await exists(backupPath)) return { path: backupPath, status: 'exists' };
  if (dryRun) return { path: backupPath, status: 'would_create' };
  await fsp.copyFile(source, backupPath);
  return { path: backupPath, status: 'created' };
}

async function claudeSetup(home, version, dryRun) {
  const command = mcpCommand(version);
  return {
    mcp: {
      name: 'unrea',
      command,
      configPath: null,
      status: 'manual',
    },
    registrationCommand: `claude mcp add unrea -- ${command.join(' ')}`,
    skill: await installSkill(
      home,
      path.join('.claude', 'skills', 'unrea', 'SKILL.md'),
      dryRun,
    ),
    notes: [
      'Claude Code registration is manual: run the printed claude command once.',
      'To track the latest release instead of pinning, use: claude mcp add unrea -- npx -y unrea mcp',
    ],
  };
}

async function codexSetup(home, version, dryRun) {
  const configPath = path.join(home, '.codex', 'config.toml');
  const backupPath = `${configPath}.unrea.bak`;
  const command = mcpCommand(version);
  const existing = await readIfPresent(configPath);
  const hasEntry =
    existing !== null && /^\[mcp_servers\.unrea\]\s*$/m.test(existing);

  let status;
  let backup = { path: backupPath, status: 'none' };

  if (hasEntry) {
    status = 'exists';
    backup = {
      path: backupPath,
      status: (await exists(backupPath)) ? 'exists' : 'none',
    };
  } else if (dryRun) {
    status = existing === null ? 'would_create' : 'would_merge';
    backup = await backupFile(configPath, backupPath, true);
  } else {
    backup = await backupFile(configPath, backupPath, false);
    await fsp.mkdir(path.dirname(configPath), { recursive: true });
    const block = [
      '[mcp_servers.unrea]',
      `command = ${JSON.stringify(command[0])}`,
      `args = [${command.slice(1).map((arg) => JSON.stringify(arg)).join(', ')}]`,
      '',
    ].join('\n');
    const separator = existing ? (existing.endsWith('\n') ? '\n' : '\n\n') : '';
    await fsp.writeFile(configPath, `${existing ?? ''}${separator}${block}`, 'utf8');
    status = existing === null ? 'created' : 'merged';
  }

  return {
    mcp: {
      name: 'unrea',
      command,
      configPath,
      status,
      backupPath,
      backupStatus: backup.status,
    },
    skill: await installSkill(
      home,
      path.join('.agents', 'skills', 'unrea', 'SKILL.md'),
      dryRun,
    ),
    notes: ['Restart the Codex session after setup so it loads the MCP server.'],
  };
}

async function opencodeSetup(home, version, dryRun) {
  const configPath = path.join(home, '.config', 'opencode', 'opencode.json');
  const backupPath = `${configPath}.unrea.bak`;
  const command = mcpCommand(version);
  const raw = await readIfPresent(configPath);

  let config = {};
  if (raw !== null) {
    try {
      config = JSON.parse(raw);
    } catch (error) {
      throw new Error(`cannot parse ${configPath}: ${error.message}`);
    }
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
      throw new Error(`${configPath} must contain a JSON object`);
    }
  }
  if (config.mcp !== undefined && (!config.mcp || typeof config.mcp !== 'object' || Array.isArray(config.mcp))) {
    throw new Error(`${configPath}: "mcp" must be an object`);
  }

  const hasEntry = Boolean(config.mcp && config.mcp.unrea);
  let status;
  let backup = { path: backupPath, status: 'none' };

  if (hasEntry) {
    status = 'exists';
    backup = {
      path: backupPath,
      status: (await exists(backupPath)) ? 'exists' : 'none',
    };
  } else if (dryRun) {
    status = raw === null ? 'would_create' : 'would_merge';
    backup = await backupFile(configPath, backupPath, true);
  } else {
    backup = await backupFile(configPath, backupPath, false);
    await fsp.mkdir(path.dirname(configPath), { recursive: true });
    config.mcp = {
      ...(config.mcp || {}),
      unrea: { type: 'local', command, enabled: true },
    };
    await fsp.writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
    status = raw === null ? 'created' : 'merged';
  }

  return {
    mcp: {
      name: 'unrea',
      command,
      configPath,
      status,
      backupPath,
      backupStatus: backup.status,
    },
    skill: await installSkill(
      home,
      path.join('.agents', 'skills', 'unrea', 'SKILL.md'),
      dryRun,
    ),
    notes: ['Restart OpenCode after setup so it loads the MCP server.'],
  };
}

/**
 * Register unrea with an MCP-capable client and copy the bundled skill.
 *
 * @param {{client:string, dryRun?:boolean, version:string}} options
 * @returns {Promise<object>}
 */
export async function runSetup({ client, dryRun = false, version }) {
  if (!CLIENTS.has(client)) {
    throw new Error(`unknown client "${client}" (use ${SETUP_CLIENTS.join(', ')})`);
  }
  if (!version) throw new Error('setup needs the package version');

  const home = path.resolve(process.env.UNREA_HOME || os.homedir());
  let result;
  if (client === 'claude_code') result = await claudeSetup(home, version, dryRun);
  else if (client === 'codex') result = await codexSetup(home, version, dryRun);
  else result = await opencodeSetup(home, version, dryRun);

  return {
    client,
    dryRun: Boolean(dryRun),
    home,
    ...result,
  };
}

/**
 * Human-readable setup output.
 *
 * @param {object} result
 * @returns {string}
 */
export function formatSetupText(result) {
  const lines = [
    `unrea setup - ${result.client}${result.dryRun ? ' (dry run)' : ''}`,
    `home: ${result.home}`,
    '',
  ];

  const { mcp } = result;
  if (mcp.status === 'manual') {
    lines.push('mcp: manual registration; no client config file was touched.');
  } else if (mcp.status === 'exists') {
    lines.push(`mcp: unrea is already registered in ${mcp.configPath} (skipped).`);
  } else if (mcp.status === 'merged') {
    lines.push(`mcp: registered unrea in ${mcp.configPath}.`);
  } else if (mcp.status === 'created') {
    lines.push(`mcp: created ${mcp.configPath}.`);
  } else if (mcp.status === 'would_merge') {
    lines.push(`mcp: would add unrea to ${mcp.configPath}.`);
  } else if (mcp.status === 'would_create') {
    lines.push(`mcp: would create ${mcp.configPath}.`);
  }

  if (mcp.command) {
    lines.push(`command: ${mcp.command.join(' ')}`);
  }
  if (result.registrationCommand) {
    lines.push(`run: ${result.registrationCommand}`);
  }

  if (mcp.backupStatus && mcp.backupStatus !== 'none') {
    lines.push(`backup: ${mcp.backupStatus} ${mcp.backupPath}`);
  }

  if (result.skill.status === 'would_copy') {
    lines.push(`skill: would copy ${result.skill.source} -> ${result.skill.target}`);
  } else if (result.skill.status === 'unchanged') {
    lines.push(`skill: already up to date at ${result.skill.target}`);
  } else {
    lines.push(`skill: ${result.skill.status} ${result.skill.target}`);
  }

  for (const note of result.notes || []) lines.push(`note: ${note}`);
  if (result.dryRun) lines.push('', 'No files were written (dry run).');
  return `${lines.join('\n')}\n`;
}
