import { readFileSync } from 'node:fs';

import { explainEntry } from '../explain.js';

const VERSION = JSON.parse(
  readFileSync(new URL('../../package.json', import.meta.url), 'utf8'),
).version;

const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const HELP_URI = 'https://github.com/lordon1a/unrea#what-it-checks';

/** SARIF only knows error/warning/note; map unrea's scale onto it. */
const LEVEL = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  info: 'note',
};

function helpText(id, entry) {
  if (!entry) return `${id}\n\nNo description is registered for this check in this unrea version.`;
  return [
    entry.title || id,
    '',
    `What it is: ${entry.what || ''}`,
    `How an agent finds it: ${entry.how_attackers_find_it || entry.step || ''}`,
    `Real risk: ${entry.risk || ''}`,
    `How to fix: ${entry.fix || ''}`,
  ].join('\n');
}

/**
 * A display path may contain `!` (asar) and spaces. Encode each segment so it
 * is a valid URI for GitHub code scanning without rewriting what a human sees.
 *
 * @param {string} file
 * @returns {string}
 */
function artifactUri(file) {
  return String(file || '')
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
}

/**
 * Build a SARIF 2.1.0 log from a scan result.
 *
 * One rule per check id in the results, with the registered explain text as
 * help. Accepted findings stay as results with a suppression so code scanning
 * shows them as dismissed rather than dropping the evidence.
 *
 * @param {{findings: Array<object>}} result
 * @returns {object}
 */
export function buildSarif(result) {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const ids = [...new Set(findings.map((finding) => finding.id))].sort();

  const rules = ids.map((id) => {
    const entry = explainEntry(id);
    return {
      id,
      name: id,
      shortDescription: { text: entry?.title || id },
      fullDescription: { text: entry?.what || id },
      help: { text: helpText(id, entry) },
      helpUri: HELP_URI,
    };
  });
  const ruleIndex = new Map(ids.map((id, index) => [id, index]));

  const results = findings.map((finding) => {
    const entry = {
      ruleId: finding.id,
      ruleIndex: ruleIndex.get(finding.id),
      level: LEVEL[finding.severity] || 'note',
      message: { text: finding.snippet || finding.fix || finding.id },
    };

    if (finding.file) {
      const location = {
        physicalLocation: {
          artifactLocation: { uri: artifactUri(finding.file) },
          ...(finding.line == null || finding.line < 1
            ? {}
            : { region: { startLine: finding.line } }),
        },
      };
      entry.locations = [location];
    }

    if (finding.accepted) {
      entry.suppressions = [
        {
          kind: 'external',
          status: 'accepted',
          justification: finding.reason || 'accepted in .unrea.json',
        },
      ];
    }

    return entry;
  });

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'unrea',
            informationUri: 'https://github.com/lordon1a/unrea',
            version: VERSION,
            rules,
          },
        },
        results,
      },
    ],
  };
}
