import { scanSecrets } from '../secrets.js';

/**
 * env.file — a dotenv file was shipped with the app. Critical when it actually
 * contains a detectable secret, high otherwise (it still leaks config).
 *
 * @param {object} file
 * @returns {Array<object>}
 */
export function run(file) {
  if (file.kind !== 'text') return [];
  if (!/^\.env(\..+)?$/i.test(file.basename || '')) return [];

  const containsSecret = scanSecrets(file.text).length > 0;
  const firstContentLine = file.text
    .split('\n')
    .map((line) => line.trim())
    .find((line) => line.length > 0 && !line.startsWith('#'));
  // Never echo a dotenv value, even one the entropy heuristic did not catch.
  const firstKey = firstContentLine && firstContentLine.includes('=')
    ? `${firstContentLine.split('=')[0].trim()}=\u2026`
    : null;

  return [
    {
      id: 'env.file',
      severity: containsSecret ? 'critical' : 'high',
      file: file.displayPath,
      line: 1,
      snippet: firstKey || `${file.basename} shipped in the build`,
      fix: containsSecret
        ? 'delete this file from the build, move the values to your server and rotate the exposed secrets'
        : 'exclude dotenv files from the packaged app',
    },
  ];
}
