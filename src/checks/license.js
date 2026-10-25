import { safeSnippet } from '../secrets.js';

const LICENSE_RE = /\b(isPro|isPremium|isLicensed|licenseValid|hasLicense|isTrial|trialExpired|isSubscribed|checkLicense|validateLicense)\b/;
const MAX_PER_FILE = 5;

/**
 * license.client — client-side entitlement checks are a hint of where payment
 * or plan logic is enforced. Heuristic, so it stays medium.
 *
 * @param {object} file
 * @returns {Array<object>}
 */
export function run(file) {
  if (file.kind !== 'text') return [];

  const findings = [];
  const lines = file.text.split('\n');
  for (let i = 0; i < lines.length && findings.length < MAX_PER_FILE; i++) {
    const line = lines[i];
    const match = LICENSE_RE.exec(line);
    if (!match) continue;
    findings.push({
      id: 'license.client',
      severity: 'medium',
      file: file.displayPath,
      line: i + 1,
      snippet: safeSnippet(line),
      fix: 'move license/payment check to your server',
    });
  }
  return findings;
}
