import { scanSecrets } from '../secrets.js';

/**
 * secret.* — live provider keys, JWTs and high-entropy literals assigned to
 * secret-looking identifiers.
 *
 * @param {object} file
 * @returns {Array<object>}
 */
export function run(file) {
  if (file.kind !== 'text') return [];
  return scanSecrets(file.text).map((secret) => ({
    id: secret.id,
    severity: secret.severity,
    file: file.displayPath,
    line: secret.line,
    snippet: secret.snippet,
    fix: secret.fix,
  }));
}
