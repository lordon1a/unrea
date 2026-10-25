import { readFileSync } from 'node:fs';

const SEVERITY_WEIGHT = { critical: 4, high: 3, medium: 2, info: 1 };
const SEVERITIES = ['critical', 'high', 'medium', 'info'];
const VERSION = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
).version;

const ANSI = {
  critical: '\u001b[1;31m',
  high: '\u001b[1;33m',
  medium: '\u001b[1;35m',
  info: '\u001b[1;36m',
  dim: '\u001b[2m',
  reset: '\u001b[0m',
};

/**
 * A: nothing medium or worse.
 * B: only medium findings, at most 3.
 * C: more than 3 medium findings.
 * D: at least one high.
 * F: at least one critical.
 *
 * @param {Array<{severity:string}>} findings
 * @returns {'A'|'B'|'C'|'D'|'F'}
 */
export function grade(findings) {
  const counts = countBySeverity(findings);
  if (counts.critical > 0) return 'F';
  if (counts.high > 0) return 'D';
  if (counts.medium > 3) return 'C';
  if (counts.medium > 0) return 'B';
  return 'A';
}

/**
 * @param {Array<{severity:string}>} findings
 * @returns {{critical:number,high:number,medium:number,info:number}}
 */
export function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, info: 0 };
  for (const finding of findings) {
    if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
  }
  return counts;
}

/**
 * Does any finding meet the fail-on threshold?
 *
 * @param {Array<{severity:string}>} findings
 * @param {'critical'|'high'|'medium'|'none'} failOn
 * @returns {boolean}
 */
export function failsThreshold(findings, failOn = 'high') {
  if (failOn === 'none') return false;
  const threshold = SEVERITY_WEIGHT[failOn];
  if (!threshold) return false;
  return findings.some((finding) => (SEVERITY_WEIGHT[finding.severity] || 0) >= threshold);
}

/**
 * Shape the public JSON result. Keep this object exactly as documented.
 *
 * @param {{findings: Array<object>, scanned: number, durationMs: number}} scanResult
 * @returns {{grade:string, scanned:number, durationMs:number, findings:Array<object>}}
 */
export function buildResult(scanResult) {
  return {
    grade: grade(scanResult.findings),
    scanned: scanResult.scanned,
    durationMs: scanResult.durationMs,
    findings: scanResult.findings,
  };
}

function formatDuration(ms) {
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  return `${ms} ms`;
}

function gradeDetail(letter, counts) {
  if (letter === 'F') return `${counts.critical} critical`;
  if (letter === 'D') return `${counts.high} high`;
  if (letter === 'C') return `${counts.medium} medium`;
  if (letter === 'B') return `${counts.medium} medium`;
  return 'nothing obvious';
}

function findingLocation(finding) {
  return finding.line == null ? finding.file : `${finding.file}:${finding.line}`;
}

function groupById(findings) {
  const groups = new Map();
  for (const finding of findings) {
    if (!groups.has(finding.id)) groups.set(finding.id, []);
    groups.get(finding.id).push(finding);
  }
  return groups;
}

/**
 * The first three distinct fixes, starting with the highest severity.
 *
 * @param {Array<{severity:string,fix:string}>} findings
 * @param {number} [limit]
 * @returns {string[]}
 */
export function topFixes(findings, limit = 3) {
  const sorted = [...findings].sort(
    (a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0),
  );
  const seen = new Set();
  const fixes = [];
  for (const finding of sorted) {
    const fix = (finding.fix || '').trim();
    if (!fix || seen.has(fix)) continue;
    seen.add(fix);
    fixes.push(fix);
    if (fixes.length >= limit) break;
  }
  return fixes;
}

function summaryLines(counts, findings) {
  const lines = [
    'Summary',
    `  critical: ${counts.critical}, high: ${counts.high}, medium: ${counts.medium}, info: ${counts.info}`,
  ];
  const fixes = topFixes(findings);
  if (fixes.length) {
    lines.push('  top fixes to do first:');
    for (let i = 0; i < fixes.length; i++) {
      lines.push(`    ${i + 1}. ${fixes[i]}`);
    }
  }
  return lines;
}

/**
 * Text report. Text mode collapses info rows and caps any single id at five
 * findings unless verbose is set; JSON stays complete.
 *
 * @param {{grade:string, scanned:number, durationMs:number, findings:Array<object>}} result
 * @param {{target:string, color?:boolean, verbose?:boolean}} options
 * @returns {string}
 */
export function formatText(result, { target, color = false, verbose = false } = {}) {
  const counts = countBySeverity(result.findings);
  const paint = (severity, text) =>
    color ? `${ANSI[severity] || ''}${text}${ANSI.reset}` : text;
  const dim = (text) => (color ? `${ANSI.dim}${text}${ANSI.reset}` : text);

  const lines = [];
  lines.push(`unrea ${VERSION} - client exposure scan`);
  lines.push(`target: ${target}`);
  lines.push(`files scanned: ${result.scanned}`);
  lines.push(`duration: ${formatDuration(result.durationMs)}`);
  const topSeverity = result.grade === 'F' ? 'critical' : result.grade === 'D' ? 'high' : result.grade === 'C' || result.grade === 'B' ? 'medium' : 'info';
  lines.push(`grade: ${paint(topSeverity, result.grade)} (${gradeDetail(result.grade, counts)})`);
  lines.push('');

  if (!result.findings.length) {
    lines.push('No findings. Nothing obvious from the outside - not a guarantee.');
    lines.push('');
    lines.push(...summaryLines(counts, result.findings));
    return `${lines.join('\n')}\n`;
  }

  for (const severity of SEVERITIES) {
    const group = result.findings.filter((finding) => finding.severity === severity);
    if (!group.length) continue;

    if (severity === 'info' && !verbose) {
      for (const [id, items] of groupById(group)) {
        lines.push(`  ${paint('info', 'INFO')}  ${id} x${items.length} (e.g. ${findingLocation(items[0])})`);
      }
      lines.push('');
      continue;
    }

    lines.push(paint(severity, `${severity.toUpperCase()} (${group.length})`));
    for (const items of groupById(group).values()) {
      const shown = verbose ? items : items.slice(0, 5);
      for (const finding of shown) {
        const location = findingLocation(finding);
        const label = severity.toUpperCase().padEnd(8);
        const detail = finding.snippet ? `  ${finding.snippet}` : '';
        lines.push(
          color
            ? `  ${paint(severity, label)} ${location}${detail}`
            : `  ${label} ${location}${detail}`,
        );
        lines.push(`    ${dim('fix:')} ${finding.fix}`);
      }
      if (!verbose && items.length > 5) {
        lines.push(`  ... and ${items.length - 5} more (use --verbose)`);
      }
    }
    lines.push('');
  }

  lines.push(...summaryLines(counts, result.findings));
  return `${lines.join('\n')}\n`;
}
