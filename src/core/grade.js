export const SEVERITY_WEIGHT = { critical: 4, high: 3, medium: 2, info: 1 };
export const SEVERITIES = ['critical', 'high', 'medium', 'info'];

const SEVERITY_DOWNGRADE = {
  critical: 'high',
  high: 'medium',
  medium: 'info',
  info: 'info',
};

/**
 * @param {string} severity
 * @returns {string}
 */
export function downgrade(severity) {
  return SEVERITY_DOWNGRADE[severity] || severity;
}

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
 * Accepted findings stay in the report for the reader, but they are an
 * explicit decision: they must not lower the grade or trip --fail-on.
 *
 * @param {Array<{severity:string}>} findings
 * @returns {{critical:number,high:number,medium:number,info:number}}
 */
export function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, info: 0 };
  for (const finding of findings) {
    if (finding.accepted) continue;
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
  return findings.some(
    (finding) => !finding.accepted && (SEVERITY_WEIGHT[finding.severity] || 0) >= threshold,
  );
}
