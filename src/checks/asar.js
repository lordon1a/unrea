/**
 * asar.plain — an asar is a concatenated archive, not encryption.
 *
 * @param {object} file
 * @returns {Array<object>}
 */
export function run(file) {
  if (file.kind !== 'asar') return [];
  return [
    {
      id: 'asar.plain',
      severity: 'info',
      file: file.displayPath,
      line: null,
      snippet: 'asar archive, not encrypted',
      fix: 'asar is an archive, not encryption: anyone can extract it in seconds',
    },
  ];
}
