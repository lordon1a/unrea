const MIN_SIZE = 20 * 1024;
const MIN_LINES = 200;
const MAX_AVERAGE_LINE = 200;

/**
 * code.readable — an unminified .js file is easy for a human or an AI agent to
 * read. Only meaningful for files larger than 20 KB.
 *
 * @param {object} file
 * @returns {Array<object>}
 */
export function run(file) {
  if (file.kind !== 'text' || file.ext !== '.js' || file.inNodeModules) return [];
  if (file.size <= MIN_SIZE) return [];

  const newlines = (file.text.match(/\n/g) || []).length;
  const lineCount = file.text.endsWith('\n') ? newlines : newlines + 1;
  if (lineCount <= MIN_LINES) return [];

  const average = (file.text.length - newlines) / lineCount;
  if (average >= MAX_AVERAGE_LINE) return [];

  return [
    {
      id: 'code.readable',
      severity: 'medium',
      file: file.displayPath,
      line: 1,
      snippet: `${lineCount} lines, avg ${Math.round(average)} chars/line`,
      fix: 'unminified code ships; minify/obfuscate (slows, doesn\'t stop)',
    },
  ];
}
