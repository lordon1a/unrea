import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { makeTemp, writeAt } from './helpers.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(root, 'bin', 'unrea.js');
const packageVersion = JSON.parse(
  readFileSync(path.join(root, 'package.json'), 'utf8'),
).version;

async function runSetup(home, args) {
  return spawnSync(process.execPath, [cli, 'setup', ...args], {
    encoding: 'utf8',
    cwd: root,
    env: { ...process.env, UNREA_HOME: home },
  });
}

function parseSetup(run) {
  assert.equal(run.status, 0, `setup failed: ${run.stderr}`);
  return JSON.parse(run.stdout);
}

test('setup dry-run writes nothing for every client', async (t) => {
  for (const client of ['claude_code', 'codex', 'opencode']) {
    const home = await makeTemp(`unrea-home-${client}-`);
    t.after(() => rm(home, { recursive: true, force: true }));

    const run = await runSetup(home, ['--client', client, '--dry-run', '--json']);
    const result = parseSetup(run);
    assert.equal(result.client, client);
    assert.equal(result.dryRun, true);
    assert.deepEqual(await readdir(home), [], 'dry run wrote files');
    assert.deepEqual(result.mcp.command, ['npx', '-y', `@yigitguldal/unrea@${packageVersion}`, 'mcp']);
    assert.equal(result.skill.status, 'would_copy');
    assert.ok(result.skill.target.startsWith(home));

    if (client === 'claude_code') {
      assert.equal(result.mcp.status, 'manual');
      assert.match(
        result.registrationCommand,
        new RegExp(`^claude mcp add unrea -- npx -y @yigitguldal\/unrea@${packageVersion.replaceAll('.', '\\.')} mcp$`),
      );
    } else {
      assert.ok(['would_create', 'would_merge'].includes(result.mcp.status));
      assert.ok(result.mcp.configPath.startsWith(home));
    }
  }
});

test('setup codex merges TOML, backs up, and is idempotent', async (t) => {
  const home = await makeTemp('unrea-home-codex-');
  t.after(() => rm(home, { recursive: true, force: true }));
  const original = '# original\nmodel = "gpt-5"\n';
  await writeAt(home, '.codex/config.toml', original);

  const first = parseSetup(await runSetup(home, ['--client', 'codex', '--json']));
  assert.equal(first.mcp.status, 'merged');
  assert.equal(first.mcp.backupStatus, 'created');
  assert.match(first.skill.status, /^(copied|updated)$/);

  const config = await readFileSync(path.join(home, '.codex/config.toml'), 'utf8');
  assert.match(config, /^# original\nmodel = "gpt-5"\n/m);
  assert.match(config, /^\[mcp_servers\.unrea\]$/m);
  assert.match(config, /^command = "npx"$/m);
  assert.match(config, /^args = \["-y", "@yigitguldal\/unrea@0\.2\.0", "mcp"\]$/m);
  assert.equal((config.match(/\[mcp_servers\.unrea\]/g) || []).length, 1);

  const backup = await readFileSync(path.join(home, '.codex/config.toml.unrea.bak'), 'utf8');
  assert.equal(backup, original);

  const skill = await readFileSync(
    path.join(home, '.agents/skills/unrea/SKILL.md'),
    'utf8',
  );
  assert.match(skill, /^---\nname: unrea\n/m);
  assert.match(skill, /unrea_scan/);

  const second = parseSetup(await runSetup(home, ['--client', 'codex', '--json']));
  assert.equal(second.mcp.status, 'exists');
  assert.equal(second.mcp.backupStatus, 'exists');
  assert.equal(second.skill.status, 'unchanged');
  const configAfter = await readFileSync(path.join(home, '.codex/config.toml'), 'utf8');
  assert.equal(configAfter, config, 'second setup changed the config');
  const backupAfter = await readFileSync(path.join(home, '.codex/config.toml.unrea.bak'), 'utf8');
  assert.equal(backupAfter, original, 'second setup overwrote the backup');
});

test('setup opencode merges JSON, preserves keys, and is idempotent', async (t) => {
  const home = await makeTemp('unrea-home-opencode-');
  t.after(() => rm(home, { recursive: true, force: true }));
  const original = `${JSON.stringify({
    theme: 'dark',
    mcp: { other: { type: 'local', command: ['other'] } },
  }, null, 2)}\n`;
  await writeAt(home, '.config/opencode/opencode.json', original);

  const first = parseSetup(await runSetup(home, ['--client', 'opencode', '--json']));
  assert.equal(first.mcp.status, 'merged');
  assert.equal(first.mcp.backupStatus, 'created');

  const config = JSON.parse(
    await readFileSync(path.join(home, '.config/opencode/opencode.json'), 'utf8'),
  );
  assert.equal(config.theme, 'dark');
  assert.deepEqual(config.mcp.other, { type: 'local', command: ['other'] });
  assert.deepEqual(config.mcp.unrea, {
    type: 'local',
    command: ['npx', '-y', `@yigitguldal/unrea@${packageVersion}`, 'mcp'],
    enabled: true,
  });

  const backup = await readFileSync(
    path.join(home, '.config/opencode/opencode.json.unrea.bak'),
    'utf8',
  );
  assert.equal(backup, original);

  const skillPath = path.join(home, '.agents/skills/unrea/SKILL.md');
  assert.match(await readFileSync(skillPath, 'utf8'), /unrea_explain/);

  const second = parseSetup(await runSetup(home, ['--client', 'opencode', '--json']));
  assert.equal(second.mcp.status, 'exists');
  assert.equal(second.mcp.backupStatus, 'exists');
  assert.equal(second.skill.status, 'unchanged');
  assert.deepEqual(
    JSON.parse(await readFileSync(path.join(home, '.config/opencode/opencode.json'), 'utf8')),
    config,
  );
  assert.equal(
    await readFileSync(path.join(home, '.config/opencode/opencode.json.unrea.bak'), 'utf8'),
    original,
  );
});

test('setup claude_code copies the skill and never writes .claude.json', async (t) => {
  const home = await makeTemp('unrea-home-claude-');
  t.after(() => rm(home, { recursive: true, force: true }));

  const first = parseSetup(await runSetup(home, ['--client', 'claude_code', '--json']));
  assert.equal(first.mcp.status, 'manual');
  assert.equal(first.mcp.configPath, null);
  assert.match(first.registrationCommand, /^claude mcp add unrea -- npx -y @yigitguldal\/unrea@0\.2\.0 mcp$/);

  const skillPath = path.join(home, '.claude/skills/unrea/SKILL.md');
  assert.match(await readFileSync(skillPath, 'utf8'), /unrea_fix_plan/);
  assert.deepEqual(
    await readdir(home, { withFileTypes: true }).then((entries) => entries.map((e) => e.name)),
    ['.claude'],
    'claude setup wrote a config file',
  );
  assert.throws(() => readFileSync(path.join(home, '.claude.json')), /ENOENT/);

  const second = parseSetup(await runSetup(home, ['--client', 'claude_code', '--json']));
  assert.equal(second.skill.status, 'unchanged');
  assert.equal(second.registrationCommand, first.registrationCommand);
});
