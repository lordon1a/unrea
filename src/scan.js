import { normalizeFinding } from './core/findings.js';
import { SEVERITY_WEIGHT } from './core/grade.js';
import { detectSurfaces } from './core/surfaces.js';
import { createScanContext } from './core/walk.js';

/**
 * Scan a directory or a single .asar/.js/.exe file.
 *
 * @param {string} targetPath
 * @param {{mode?: 'build'|'source'}} [options]
 * @returns {Promise<{findings: Array<object>, scanned: number, durationMs: number, mode: 'build'|'source', surfaces: string[]}>}
 */
export async function scan(targetPath, options = {}) {
  const started = Date.now();
  const { context, cleanup } = await createScanContext(targetPath, options);

  try {
    const detected = await detectSurfaces(context);
    const surfaces = detected.map((surface) => surface.id).sort();
    const found = [];

    // A surface may claim paths it understands better (Unity owns *_Data/Managed, MonoBleedingEdge...).
    // Other surfaces' findings on claimed files are dropped, except secrets, which always count.
    const owners = detected.filter((surface) => typeof surface.owns === 'function');
    const ownerOf = (file) => {
      if (!file) return null;
      return owners.find((surface) => surface.owns(file, context)) || null;
    };

    for (const surface of detected) {
      const results = await surface.run(context);
      for (const result of results || []) {
        if (!result || !result.id) continue;
        const file = context.fileByPath.get(result.file);
        const owner = ownerOf(file);
        if (
          owner &&
          owner.id !== surface.id &&
          !result.id.startsWith('secret.') &&
          !(owner.sharedIds || []).includes(result.id)
        ) {
          continue;
        }
        found.push(normalizeFinding(result, file));
      }
    }

    let engine = null;
    for (const surface of detected) {
      if (typeof surface.info !== 'function') continue;
      const info = await surface.info(context);
      if (info) engine = { ...(engine || {}), ...info };
    }

    const seen = new Set();
    const findings = [];
    for (const finding of found) {
      const key = [finding.id, finding.severity, finding.file, finding.line, finding.snippet].join('\u0000');
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(finding);
    }

    findings.sort(
      (a, b) =>
        (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0) ||
        a.file.localeCompare(b.file) ||
        (a.line ?? 0) - (b.line ?? 0) ||
        a.id.localeCompare(b.id),
    );

    return {
      findings,
      scanned: context.scanned,
      durationMs: Date.now() - started,
      mode: context.mode,
      surfaces,
      engine,
    };
  } finally {
    await cleanup();
  }
}
