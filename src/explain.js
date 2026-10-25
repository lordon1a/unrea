import { loadSurfaces } from './core/surfaces.js';

const surfaces = await loadSurfaces();
const entries = new Map();

for (const surface of surfaces) {
  for (const [id, entry] of Object.entries(surface.explain || {})) {
    entries.set(id, { ...entry, surface: surface.id });
  }
}

export const KNOWN_IDS = [...entries.keys()];

const FAMILY_ALIASES = {
  secret: 'secret.*',
  sourcemap: 'sourcemap.*',
  'electron.fuses': 'electron.fuses.*',
};

/**
 * @param {string} id
 * @returns {string}
 */
export function explain(id) {
  const key = FAMILY_ALIASES[id] || id;
  const entry = entries.get(key);
  if (!entry) {
    return [
      `Unknown check id "${id}".`,
      '',
      'Known check ids:',
      ...KNOWN_IDS.map((known) => `- ${known}`),
    ].join('\n');
  }
  return [
    `${id} - ${entry.title || id}`,
    '',
    `What it is: ${entry.what}`,
    `How an agent finds it: ${entry.how_attackers_find_it || entry.step}`,
    `Real risk: ${entry.risk}`,
    `How to fix: ${entry.fix}`,
  ].join('\n');
}

/**
 * Concrete ids an agent can pass to unrea_fix_plan. Family wildcards are not
 * accepted by the fix planner.
 *
 * @returns {string[]}
 */
export function fixPlanIds() {
  return KNOWN_IDS.filter((id) => !id.endsWith('.*'));
}
