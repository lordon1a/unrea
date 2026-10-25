import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SURFACES_DIR = fileURLToPath(new URL('../surfaces', import.meta.url));
let cache = null;

/**
 * Discover every surface folder with an index.js. The folder name is the
 * surface id; load order is deterministic.
 *
 * @returns {Promise<Array<object>>}
 */
export async function loadSurfaces() {
  if (cache) return cache;

  let entries;
  try {
    entries = await fsp.readdir(SURFACES_DIR, { withFileTypes: true });
  } catch {
    cache = [];
    return cache;
  }

  const names = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  const surfaces = [];
  for (const name of names) {
    const filePath = path.join(SURFACES_DIR, name, 'index.js');
    try {
      await fsp.access(filePath);
    } catch {
      continue;
    }
    const module = await import(pathToFileURL(filePath).href);
    const surface = module.default;
    if (!surface || typeof surface.run !== 'function') continue;
    surfaces.push({
      ...surface,
      id: surface.id || name,
      title: surface.title || name,
      covers: Array.isArray(surface.covers) ? surface.covers : [],
      explain: surface.explain || {},
      fixPlan: surface.fixPlan || {},
    });
  }

  cache = surfaces;
  return cache;
}

/**
 * @param {object} context
 * @returns {Promise<Array<object>>}
 */
export async function detectSurfaces(context) {
  const surfaces = await loadSurfaces();
  const detected = [];
  for (const surface of surfaces) {
    if (typeof surface.detect !== 'function' || (await surface.detect(context))) {
      detected.push(surface);
    }
  }
  return detected;
}
