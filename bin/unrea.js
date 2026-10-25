#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import process from 'node:process';

import { scan } from '../src/scan.js';
import { buildResult, failsThreshold, formatText } from '../src/report.js';
import { formatSetupText, runSetup, SETUP_CLIENTS } from '../src/setup.js';

const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const USAGE = `unrea ${packageJson.version} - see your own built app through a reverse engineer's eyes

Usage:
  unrea scan <path> [--json] [--verbose] [--source|--build] [--fail-on critical|high|medium|none]
  unrea mcp
  unrea setup --client claude_code|codex|opencode [--dry-run] [--json]

Commands:
  scan          Scan a directory (win-unpacked, installed app, dist/) or a single .asar file
  mcp           Start the stdio MCP server for Claude Code, Codex or OpenCode
  setup         Register the MCP server and copy the unrea skill

Options:
  --json        Print machine-readable JSON (always complete)
  --verbose     List every finding in text mode (no collapsing)
  --source      Force source-repo mode (skip node_modules, no tests.shipped)
  --build       Force build mode (auto-detection off)
  --fail-on     Exit 1 when a finding reaches this severity (default: high)
  --client      Setup target: claude_code, codex or opencode
  --dry-run     Setup: show what would be written without writing it
  -h, --help    Show this help
  -v, --version Show the version
`;

function fail(message) {
  process.stderr.write(`unrea: ${message}\n\n${USAGE}`);
  process.exit(2);
}

function parseScanArgs(argv) {
  const options = { target: null, json: false, verbose: false, failOn: 'high', mode: null };
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--json') {
      options.json = true;
    } else if (arg === '--verbose') {
      options.verbose = true;
    } else if (arg === '--source' || arg === '--build') {
      const mode = arg === '--source' ? 'source' : 'build';
      if (options.mode && options.mode !== mode) {
        fail('use only one of --source or --build');
      }
      options.mode = mode;
    } else if (arg === '--fail-on') {
      const value = argv[++i];
      if (!value) fail('--fail-on needs a value');
      options.failOn = value;
    } else if (arg.startsWith('--fail-on=')) {
      options.failOn = arg.slice('--fail-on='.length);
    } else if (arg.startsWith('-')) {
      fail(`unknown option "${arg}"`);
    } else if (options.target === null) {
      options.target = arg;
    } else {
      fail(`unexpected argument "${arg}"`);
    }
  }

  if (!options.target) fail('scan needs a path');
  if (!['critical', 'high', 'medium', 'none'].includes(options.failOn)) {
    fail(`invalid --fail-on "${options.failOn}" (use critical, high, medium or none)`);
  }
  return options;
}

function parseSetupArgs(argv) {
  const options = { client: null, dryRun: false, json: false };
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--client') {
      const value = argv[++i];
      if (!value) fail('--client needs a value');
      options.client = value;
    } else if (arg.startsWith('--client=')) {
      options.client = arg.slice('--client='.length);
    } else if (arg === '--dry-run') {
      options.dryRun = true;
    } else if (arg === '--json') {
      options.json = true;
    } else if (arg.startsWith('-')) {
      fail(`unknown option "${arg}"`);
    } else {
      fail(`unexpected argument "${arg}"`);
    }
  }

  if (!options.client) fail('setup needs --client');
  if (!SETUP_CLIENTS.includes(options.client)) {
    fail(`invalid --client "${options.client}" (use ${SETUP_CLIENTS.join(', ')})`);
  }
  return options;
}

async function runScan(options) {
  let scanResult;
  try {
    scanResult = await scan(options.target, { mode: options.mode || undefined });
  } catch (error) {
    process.stderr.write(`unrea: ${error.message}\n`);
    process.exit(2);
  }

  const result = buildResult(scanResult);
  if (options.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    const color = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
    process.stdout.write(formatText(result, { target: options.target, color, verbose: options.verbose }));
  }

  process.exitCode = failsThreshold(result.findings, options.failOn) ? 1 : 0;
}

async function runSetupCommand(options) {
  try {
    const result = await runSetup({
      client: options.client,
      dryRun: options.dryRun,
      version: packageJson.version,
    });
    if (options.json) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(formatSetupText(result));
    }
  } catch (error) {
    process.stderr.write(`unrea: ${error.message}\n`);
    process.exitCode = 1;
  }
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0) fail('missing command');
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(USAGE);
    process.exit(0);
  }
  if (argv.includes('--version') || argv.includes('-v')) {
    process.stdout.write(`${packageJson.version}\n`);
    process.exit(0);
  }

  if (argv[0] === 'scan') {
    await runScan(parseScanArgs(argv));
  } else if (argv[0] === 'mcp') {
    try {
      const { startMcpServer } = await import('../src/mcp.js');
      await startMcpServer();
    } catch (error) {
      process.stderr.write(`unrea: mcp failed: ${error.message}\n`);
      process.exitCode = 1;
    }
  } else if (argv[0] === 'setup') {
    await runSetupCommand(parseSetupArgs(argv));
  } else {
    fail(`unknown command "${argv[0]}"`);
  }
}

await main();
