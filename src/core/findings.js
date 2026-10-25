import { downgrade } from './grade.js';

function isVendorProviderSecret(id) {
  return id.startsWith('secret.') && id !== 'secret.generic';
}

/**
 * Apply the global severity rules that are independent of a surface:
 * node_modules downgrade, vendor provider/PEM info, fixture secrets, vendor
 * source-map comments. Container findings (tests.shipped) are not downgraded.
 *
 * @param {object} finding
 * @param {object|undefined} file
 * @returns {object}
 */
export function normalizeFinding(finding, file) {
  if (!file || finding.id === 'tests.shipped') return finding;

  let severity = file.inNodeModules ? downgrade(finding.severity) : finding.severity;
  let snippet = finding.snippet ?? '';
  const prefixes = [];

  if (file.inVendor && isVendorProviderSecret(finding.id)) {
    severity = 'info';
    prefixes.push('[vendor code]');
  }
  if (file.inTest && finding.id.startsWith('secret.')) {
    severity = 'info';
    prefixes.push('[test file, likely fixture]');
  }
  if (file.inVendor && finding.id === 'sourcemap.comment') {
    severity = downgrade(severity);
  }
  if (prefixes.length) snippet = `${prefixes.join(' ')} ${snippet}`;

  return {
    ...finding,
    severity,
    snippet,
  };
}
