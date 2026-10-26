import { countBySeverity, topFixes } from './report.js';

const GRADE_COLORS = {
  A: 'brightgreen',
  B: 'green',
  C: 'yellow',
  D: 'orange',
  F: 'red',
};

/**
 * shields.io endpoint payload. Keep the shape stable: shields only reads these
 * four fields.
 *
 * @param {'A'|'B'|'C'|'D'|'F'} grade
 * @returns {{schemaVersion:number,label:string,message:string,color:string}}
 */
export function buildBadge(grade) {
  return {
    schemaVersion: 1,
    label: 'unrea',
    message: `grade ${grade}`,
    color: GRADE_COLORS[grade] || 'lightgrey',
  };
}

function cell(value) {
  return String(value ?? '')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ')
    .trim();
}

function location(finding) {
  return finding.line == null ? String(finding.file || '') : `${finding.file}:${finding.line}`;
}

/**
 * GitHub job summary markdown: grade, counts, top fixes and the high+ table.
 * Accepted findings are left out of the table and the counts because they do
 * not affect the grade; a note keeps them visible.
 *
 * @param {{grade:string, findings:Array<object>, scanned?:number, surfaces?:string[]}} result
 * @returns {string}
 */
export function buildSummary(result) {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const counted = findings.filter((finding) => !finding.accepted);
  const accepted = findings.length - counted.length;
  const counts = countBySeverity(findings);

  const lines = [
    '## unrea scan',
    '',
    `**Grade: ${result.grade}**`,
    '',
    '| Severity | Count |',
    '| --- | --- |',
    `| Critical | ${counts.critical} |`,
    `| High | ${counts.high} |`,
    `| Medium | ${counts.medium} |`,
    `| Info | ${counts.info} |`,
    '',
  ];

  if (accepted > 0) {
    lines.push(
      `> ${accepted} accepted finding${accepted === 1 ? '' : 's'} via \`.unrea.json\`; excluded from the grade.`,
      '',
    );
  }

  const fixes = topFixes(counted);
  if (fixes.length) {
    lines.push('### Top fixes', '');
    for (const fix of fixes) lines.push(`1. ${cell(fix)}`);
    lines.push('');
  }

  const important = counted.filter(
    (finding) => finding.severity === 'critical' || finding.severity === 'high',
  );
  lines.push('### High and critical findings', '');
  if (!important.length) {
    lines.push('_No high or critical findings._');
  } else {
    lines.push('| Severity | Check | Location | Finding |', '| --- | --- | --- | --- |');
    for (const finding of important) {
      lines.push(
        `| ${cell(finding.severity)} | ${cell(finding.id)} | ${cell(location(finding))} | ${cell(finding.snippet)} |`,
      );
    }
  }

  return `${lines.join('\n')}\n`;
}
