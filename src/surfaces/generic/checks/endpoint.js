import { clip } from '../../../core/mask.js';
import { redactSecrets } from '../../../core/secrets.js';

const URL_RE = /\b(?:https?|wss?):\/\/[^\s"'`<>)\]}]+/gi;

function internalHost(url) {
  const schemeIndex = url.indexOf('//');
  if (schemeIndex === -1) return false;
  let authority = url.slice(schemeIndex + 2).split(/[/?#]/)[0];
  authority = authority.split('@').pop() || '';
  const host = authority.replace(/:\d+$/, '').toLowerCase();
  if (!host) return false;
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host === '127.0.0.1' || host.startsWith('127.0.0.1.')) return true;
  return host.split('.').some((label) => label === 'staging' || label === 'internal' || label === 'dev');
}

function maskUrl(url) {
  return clip(redactSecrets(url).replace(/\/\/[^/@\s]+@/, '//\u2026@'), 120);
}

/**
 * endpoint.internal — URLs that only make sense on a developer machine or
 * inside a private network.
 *
 * @param {object} file
 * @returns {Array<object>}
 */
export function run(file) {
  if (file.kind !== 'text') return [];

  const findings = [];
  const seen = new Set();
  const lines = file.text.split('\n');

  for (let i = 0; i < lines.length; i++) {
    URL_RE.lastIndex = 0;
    let match;
    while ((match = URL_RE.exec(lines[i])) !== null) {
      const url = match[0].replace(/[.,;:]+$/, '');
      if (!internalHost(url)) continue;
      const key = `${i}:${url}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: 'endpoint.internal',
        severity: 'info',
        file: file.displayPath,
        line: i + 1,
        snippet: maskUrl(url),
        fix: 'remove internal/staging endpoints from production builds; point at the public API',
      });
    }
  }

  return findings;
}
