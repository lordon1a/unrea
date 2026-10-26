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
 * Resolve a concrete check id to its explain entry, falling back to the
 * family entry (`secret.openai` -> `secret.*`).
 *
 * @param {string} id
 * @returns {object|null}
 */
export function explainEntry(id) {
  const key = FAMILY_ALIASES[id] || id;
  if (entries.has(key)) return entries.get(key) || null;

  const parts = id.split('.');
  for (let i = parts.length - 1; i >= 1; i--) {
    const family = `${parts.slice(0, i).join('.')}.*`;
    if (entries.has(family)) return entries.get(family) || null;
  }
  return null;
}

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
