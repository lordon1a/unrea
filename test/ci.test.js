import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { buildBadge, buildSummary } from '../src/core/ci.js';
import { buildSarif } from '../src/core/sarif.js';
import { buildResult } from '../src/report.js';
import { makeTemp, writeAt } from './helpers.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cli = path.join(root, 'bin', 'unrea.js');

const mixed = () =>
  buildResult({
    findings: [
      {
        id: 'secret.openai',
        severity: 'critical',
        file: 'resources/app.asar!/main.js',
        line: 12,
        snippet: 'OpenAI key: sk-p…6X',
        fix: 'rotate the OpenAI key',
      },
      {
        id: 'sourcemap.comment',
        severity: 'medium',
        file: 'dist/app.js',
        line: 3,
        snippet: '//# sourceMappingURL=app.js.map',
        fix: 'disable source maps',
        accepted: true,
        reason: 'maps are published on purpose',
      },
      {
        id: 'tests.shipped',
        severity: 'high',
        file: 'resources/app.asar',
        line: null,
        snippet: '2 test files ship | in the build',
        fix: 'exclude test folders',
      },
      {
        id: 'endpoint.internal',
        severity: 'info',
        file: 'dist/app.js',
        line: null,
        snippet: 'http://localhost:3000',
        fix: 'remove internal endpoints',
      },
    ],
    scanned: 4,
    durationMs: 1,
  });

test('SARIF maps ids, levels, locations and accepted suppressions', () => {
  const sarif = buildSarif(mixed());

  assert.equal(sarif.version, '2.1.0');
  assert.match(sarif.$schema, /sarif-2\.1\.0/);

  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'unrea');
  assert.equal(run.results.length, 4);
  assert.deepEqual(
    run.tool.driver.rules.map((rule) => rule.id),
    ['endpoint.internal', 'secret.openai', 'sourcemap.comment', 'tests.shipped'],
  );

  const secret = run.results.find((result) => result.ruleId === 'secret.openai');
  assert.equal(secret.level, 'error');
  assert.equal(secret.ruleIndex, 1);
  assert.deepEqual(secret.locations[0].physicalLocation, {
    artifactLocation: { uri: 'resources/app.asar!/main.js' },
    region: { startLine: 12 },
  });
  assert.match(run.tool.driver.rules[1].help.text, /OpenAI API key/);
  assert.match(run.tool.driver.rules[1].help.text, /How to fix:/);

  const high = run.results.find((result) => result.ruleId === 'tests.shipped');
  assert.equal(high.level, 'error');
  assert.ok(!high.locations[0].physicalLocation.region, 'a finding without a line has no region');
  assert.ok(!high.suppressions);

  const medium = run.results.find((result) => result.ruleId === 'sourcemap.comment');
  assert.equal(medium.level, 'warning');
  assert.deepEqual(medium.suppressions, [
    {
      kind: 'external',
      status: 'accepted',
      justification: 'maps are published on purpose',
    },
  ]);

  const info = run.results.find((result) => result.ruleId === 'endpoint.internal');
  assert.equal(info.level, 'note');
});

test('SARIF keeps a rule for an id without registered explain text', () => {
  const result = buildResult({
    findings: [
      { id: 'custom.unknown', severity: 'info', file: 'blob.bin', line: 1, snippet: 'x', fix: 'y' },
    ],
    scanned: 1,
    durationMs: 1,
  });
  const sarif = buildSarif(result);
  const rule = sarif.runs[0].tool.driver.rules[0];
  assert.equal(rule.id, 'custom.unknown');
  assert.equal(rule.shortDescription.text, 'custom.unknown');
  assert.match(rule.help.text, /No description is registered/);
});

test('badge payload follows shields.io endpoint format and colors', () => {
  const expected = {
    A: 'brightgreen',
    B: 'green',
    C: 'yellow',
    D: 'orange',
    F: 'red',
  };
  for (const [grade, color] of Object.entries(expected)) {
    assert.deepEqual(buildBadge(grade), {
      schemaVersion: 1,
      label: 'unrea',
      message: `grade ${grade}`,
      color,
    });
  }
});

test('job summary has grade, counted stats, top fixes and only high+ rows', () => {
  const markdown = buildSummary(mixed());

  assert.match(markdown, /## unrea scan/);
  assert.match(markdown, /\*\*Grade: F\*\*/);
  assert.match(markdown, /\| Critical \| 1 \|/);
  assert.match(markdown, /\| High \| 1 \|/);
  assert.match(markdown, /\| Medium \| 0 \|/);
  assert.match(markdown, /\| Info \| 1 \|/);
  assert.match(markdown, /accepted finding via `\.unrea\.json`/);
  assert.match(markdown, /### Top fixes/);
  assert.match(markdown, /1\. rotate the OpenAI key/);
  assert.match(markdown, /### High and critical findings/);
  assert.match(markdown, /\| critical \| secret\.openai \|/);
  assert.match(markdown, /test files ship \\\| in the build/, 'table cells escape pipes');
  assert.ok(!markdown.includes('sourcemap.comment'), 'accepted findings stay out of the table');
  assert.ok(!markdown.includes('endpoint.internal'), 'info findings stay out of the table');
});

test('CLI writes SARIF, badge and summary files', async (t) => {
  const dir = await makeTemp('unrea-ci-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'app.js.map', '{"version":3}\n');
  await writeAt(
    dir,
    '.unrea.json',
    JSON.stringify({ accept: [{ id: 'sourcemap.file', reason: 'maps stay public' }] }),
  );

  const out = path.join(dir, 'out');
  const sarifPath = path.join(out, 'unrea.sarif');
  const badgePath = path.join(out, 'unrea-badge.json');
  const summaryPath = path.join(out, 'summary.md');
  const run = spawnSync(
    process.execPath,
    [
      cli,
      'scan',
      dir,
      '--json',
      '--sarif',
      sarifPath,
      '--badge',
      badgePath,
      '--summary',
      summaryPath,
    ],
    { encoding: 'utf8' },
  );

  assert.equal(run.status, 0);
  assert.equal(JSON.parse(run.stdout).grade, 'A');

  const sarif = JSON.parse(await readFile(sarifPath, 'utf8'));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(
    sarif.runs[0].results[0].suppressions[0].justification,
    'maps stay public',
  );

  assert.deepEqual(JSON.parse(await readFile(badgePath, 'utf8')), {
    schemaVersion: 1,
    label: 'unrea',
    message: 'grade A',
    color: 'brightgreen',
  });

  const markdown = await readFile(summaryPath, 'utf8');
  assert.match(markdown, /\*\*Grade: A\*\*/);
  assert.match(markdown, /_No high or critical findings\._/);
});

test('CLI appends to GITHUB_STEP_SUMMARY when --summary is omitted', async (t) => {
  const dir = await makeTemp('unrea-ci-env-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, 'endpoints.js', "fetch('http://localhost:3000/a');\n");
  const summaryPath = path.join(dir, 'step-summary.md');
  await writeAt(dir, 'step-summary.md', 'existing summary\n');

  const run = spawnSync(process.execPath, [cli, 'scan', dir], {
    encoding: 'utf8',
    env: { ...process.env, GITHUB_STEP_SUMMARY: summaryPath },
  });

  assert.equal(run.status, 0);
  const markdown = await readFile(summaryPath, 'utf8');
  assert.ok(markdown.startsWith('existing summary\n'), 'the step summary is appended, not replaced');
  assert.match(markdown, /## unrea scan/);
  assert.match(markdown, /\*\*Grade: A\*\*/);
  assert.match(markdown, /\| Info \| 1 \|/);
});
