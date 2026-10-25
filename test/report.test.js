import assert from 'node:assert/strict';
import test from 'node:test';

import { buildResult, failsThreshold, formatText, grade } from '../src/report.js';

const finding = (severity) => ({
  id: 'x.test',
  severity,
  file: 'app.js',
  line: 1,
  snippet: 'masked',
  fix: 'fix it',
});

test('grades follow the spec thresholds', () => {
  assert.equal(grade([]), 'A');
  assert.equal(grade([finding('info')]), 'A');
  assert.equal(grade([finding('medium')]), 'B');
  assert.equal(grade([finding('medium'), finding('medium'), finding('medium')]), 'B');
  assert.equal(
    grade([finding('medium'), finding('medium'), finding('medium'), finding('medium')]),
    'C',
  );
  assert.equal(grade([finding('high')]), 'D');
  assert.equal(grade([finding('critical')]), 'F');
  assert.equal(grade([finding('critical'), finding('high'), finding('medium')]), 'F');
});

test('fail-on threshold treats none as never failing', () => {
  const findings = [finding('critical'), finding('high'), finding('medium')];
  assert.equal(failsThreshold(findings, 'critical'), true);
  assert.equal(failsThreshold([finding('high')], 'critical'), false);
  assert.equal(failsThreshold([finding('medium')], 'high'), false);
  assert.equal(failsThreshold([finding('medium')], 'medium'), true);
  assert.equal(failsThreshold(findings, 'none'), false);
  assert.equal(failsThreshold([], 'high'), false);
});

test('JSON result has exactly the documented shape', () => {
  const result = buildResult({
    findings: [finding('high')],
    scanned: 3,
    durationMs: 12,
    mode: 'source',
  });
  assert.deepEqual(Object.keys(result), ['grade', 'scanned', 'durationMs', 'findings', 'mode']);
  assert.equal(result.grade, 'D');
  assert.equal(result.scanned, 3);
  assert.equal(result.durationMs, 12);
  assert.equal(result.mode, 'source');
});

test('text report groups by severity and prints two lines per finding', () => {
  const result = buildResult({
    findings: [finding('critical'), finding('medium')],
    scanned: 2,
    durationMs: 5,
  });
  const text = formatText(result, { target: 'dist', color: false });
  assert.match(text, /^unrea \d+\.\d+\.\d+/);
  assert.match(text, /target: dist/);
  assert.match(text, /files scanned: 2/);
  assert.match(text, /duration: 5 ms/);
  assert.match(text, /grade: F/);
  assert.match(text, /CRITICAL \(1\)/);
  assert.match(text, /MEDIUM \(1\)/);
  const lines = text.split('\n');
  const criticalLocation = lines.findIndex((line) => line.includes('app.js:1'));
  assert.ok(criticalLocation > 0);
  assert.match(lines[criticalLocation + 1], /^ {4}fix: /);
});

test('source mode prints a top warning', () => {
  const result = buildResult({
    findings: [],
    scanned: 0,
    durationMs: 1,
    mode: 'source',
  });
  const text = formatText(result, { target: 'my-repo' });
  assert.match(
    text,
    /WARNING: this looks like a source folder, scan your BUILD output \(dist\/, win-unpacked\/, the installed app\)/,
  );
  assert.ok(
    text.indexOf('WARNING:') < text.indexOf('files scanned:'),
    'warning should be near the top of the report',
  );
});

test('clean scan says A and no findings', () => {
  const result = buildResult({ findings: [], scanned: 1, durationMs: 1 });
  assert.equal(result.grade, 'A');
  const text = formatText(result, { target: 'x' });
  assert.match(text, /No findings/);
  assert.match(text, /critical: 0, high: 0, medium: 0, info: 0/);
});

test('info findings collapse to one line per id unless verbose', () => {
  const findings = Array.from({ length: 8 }, (_, i) => ({
    id: 'endpoint.internal',
    severity: 'info',
    file: `f${i}.js`,
    line: i + 1,
    snippet: 'http://localhost',
    fix: 'remove internal endpoints',
  }));
  const result = buildResult({ findings, scanned: 8, durationMs: 1 });

  const text = formatText(result, { target: 'x' });
  const infoLines = text.split('\n').filter((line) => /INFO\s+endpoint\.internal/.test(line));
  assert.equal(infoLines.length, 1);
  assert.match(infoLines[0], /INFO\s+endpoint\.internal x8 \(e\.g\. f0\.js:1\)/);
  assert.ok(!text.includes('f7.js:8'));
  assert.equal((text.match(/^ {4}fix:/gm) || []).length, 0, 'info rows have no fix lines');

  const verbose = formatText(result, { target: 'x', verbose: true });
  assert.ok(verbose.includes('f7.js:8'));
  assert.equal((verbose.match(/^ {4}fix:/gm) || []).length, 8);
  assert.ok(!verbose.includes('use --verbose'));

  // JSON (the result object) stays complete; only text mode collapses.
  assert.equal((JSON.stringify(result).match(/endpoint\.internal/g) || []).length, 8);
});

test('a single id is capped at five rows in text mode', () => {
  const findings = Array.from({ length: 7 }, (_, i) => ({
    id: 'license.client',
    severity: 'medium',
    file: `f${i}.js`,
    line: 1,
    snippet: 'if (isPro)',
    fix: 'move license/payment check to your server',
  }));
  const result = buildResult({ findings, scanned: 7, durationMs: 1 });

  const text = formatText(result, { target: 'x' });
  assert.equal((text.match(/^ {4}fix:/gm) || []).length, 5);
  assert.match(text, /\.\.\. and 2 more \(use --verbose\)/);
  assert.ok(!text.includes('f6.js:1'));

  const verbose = formatText(result, { target: 'x', verbose: true });
  assert.equal((verbose.match(/^ {4}fix:/gm) || []).length, 7);
  assert.ok(verbose.includes('f6.js:1'));
  assert.ok(!verbose.includes('use --verbose'));
});

test('summary counts severities and lists three distinct top fixes', () => {
  const findings = [
    { id: 'secret.a', severity: 'critical', file: 'a.js', line: 1, snippet: 'a', fix: 'fix A' },
    { id: 'secret.b', severity: 'critical', file: 'b.js', line: 1, snippet: 'b', fix: 'fix A' },
    { id: 'secret.c', severity: 'critical', file: 'c.js', line: 1, snippet: 'c', fix: 'fix B' },
    { id: 'high.x', severity: 'high', file: 'd.js', line: 1, snippet: 'd', fix: 'fix C' },
    { id: 'medium.x', severity: 'medium', file: 'e.js', line: 1, snippet: 'e', fix: 'fix D' },
  ];
  const result = buildResult({ findings, scanned: 5, durationMs: 1 });
  const text = formatText(result, { target: 'x' });

  assert.match(text, /Summary/);
  assert.match(text, /critical: 3, high: 1, medium: 1, info: 0/);
  const a = text.indexOf('1. fix A');
  const b = text.indexOf('2. fix B');
  const c = text.indexOf('3. fix C');
  assert.ok(a > 0 && a < b && b < c, 'top fixes are ordered by severity and deduped');
  assert.ok(!text.includes('4. fix'));
  assert.ok(text.trimEnd().endsWith('3. fix C'), 'summary is the last block');
});
