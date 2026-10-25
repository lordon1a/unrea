/**
 * Masking helpers. A scan report must never contain a usable secret, so every
 * secret-shaped value goes through mask() before it reaches stdout or JSON.
 */

/**
 * Show first 4 + ellipsis + last 2 characters. Values shorter than 8 chars are
 * masked completely (showing 4+2 of a 6-char value would reveal all of it).
 *
 * @param {string} value
 * @returns {string}
 */
export function mask(value) {
  const s = String(value ?? '');
  if (s.length < 8) return '\u2026';
  return `${s.slice(0, 4)}\u2026${s.slice(-2)}`;
}

/**
 * Collapse whitespace, strip control characters and cut a snippet to a sane
 * length for one terminal line.
 *
 * @param {string} text
 * @param {number} [max]
 * @returns {string}
 */
export function clip(text, max = 140) {
  const flat = String(text ?? '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (flat.length <= max) return flat;
  return `${flat.slice(0, max - 3)}...`;
}
