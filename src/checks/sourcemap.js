import path from 'node:path';
import { safeSnippet } from '../secrets.js';

const COMMENT_RE = /\/\/[#@]\s*sourceMappingURL=(\S+)/g;
const BLOCK_COMMENT_RE = /\/\*[#@]\s*sourceMappingURL=([^*\s]+)\s*\*\//g;

/**
 * sourcemap.file  — a .map file was shipped.
 * sourcemap.comment — code points at a source map file (not a data: URI).
 *
 * @param {object} file
 * @returns {Array<object>}
 */
export function run(file) {
  if (file.kind !== 'text') return [];
  const findings = [];
  const base = path.basename(file.displayPath).toLowerCase();

  if (base.endsWith('.map')) {
    findings.push({
      id: 'sourcemap.file',
      severity: 'high',
      file: file.displayPath,
      line: 1,
      snippet: `${path.basename(file.displayPath)} shipped in the build`,
      fix: 'disable source maps in production build',
    });
  }

  const lines = file.text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.includes('sourceMappingURL')) continue;
    for (const regex of [COMMENT_RE, BLOCK_COMMENT_RE]) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(line)) !== null) {
        const target = match[1].trim();
        if (!target || target.startsWith('data:')) continue;
        findings.push({
          id: 'sourcemap.comment',
          severity: 'medium',
          file: file.displayPath,
          line: i + 1,
          snippet: safeSnippet(match[0]),
          fix: 'disable source maps in production build',
        });
      }
    }
  }

  return findings;
}
