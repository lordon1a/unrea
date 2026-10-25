import path from 'node:path';

import { loadSurfaces } from './core/surfaces.js';
import { KNOWN_IDS } from './explain.js';

const surfaces = await loadSurfaces();
const plans = new Map();

for (const surface of surfaces) {
  for (const [id, handler] of Object.entries(surface.fixPlan || {})) {
    plans.set(id, { handler, surface: surface.id });
  }
}

function knownIdsText() {
  return ['Known ids:', ...KNOWN_IDS.map((id) => `- ${id}`)].join('\n');
}

function normalizeAlias(id) {
  if (id === 'electron.fuses') return 'electron.fuses.*';
  if (id === 'sourcemap') return 'sourcemap.*';
  if (id === 'secret') return 'secret.*';
  return id;
}

/**
 * Build a concrete plan for an agent to apply. This function never writes files.
 *
 * @param {string} id
 * @param {string} projectPath
 * @param {object} [finding]
 * @returns {Promise<{ok:boolean,text:string}>}
 */
export async function buildFixPlan(id, projectPath, finding) {
  const resolved = path.resolve(projectPath || '.');
  const normalized = normalizeAlias(id);
  let entry = plans.get(normalized);

  if (!entry && normalized.startsWith('electron.fuses.')) {
    entry = null;
  } else if (!entry) {
    for (const [key, candidate] of plans) {
      if (key.endsWith('.*') && normalized.startsWith(key.slice(0, -1))) {
        entry = candidate;
        break;
      }
    }
  }

  if (!entry) {
    return {
      ok: false,
      text: `Unknown check id "${id}".\n\n${knownIdsText()}`,
    };
  }

  const text = await entry.handler(resolved, finding || { id });
  return { ok: true, text };
}
