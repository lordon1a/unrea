/**
 * Identifier judgement on top of `dotnet.strings` from src/parse/pe.js.
 *
 * The shared PE reader already walks the BSJB root and returns the #Strings
 * heap; this module only decides what those strings mean. #Strings holds
 * metadata names (types, methods, fields, namespaces), not user literals, so
 * the values here are safe to print.
 */

// Compiler-generated accessors and backing fields say nothing about how much
// of the *author's* code a decompiler will show.
const COMPILER_GENERATED = /^(?:get_|set_|add_|remove_|op_|\.)/;

// Matches the spec's list: licensing and purchase vocabulary.
export const SENSITIVE_TOKENS = [
  'license',
  'serial',
  'activation',
  'premium',
  'trial',
  'unlock',
  'purchase',
  'apikey',
  'secret',
];

/**
 * @param {string} value
 * @returns {boolean}
 */
export function isIdentifier(value) {
  if (typeof value !== 'string') return false;
  const name = value.trim();
  if (name.length < 1 || name.length > 120) return false;
  // Drops <Module>, .ctor, generic arity (`List`1`) and anything with spaces.
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) return false;
  if (COMPILER_GENERATED.test(name)) return false;
  return true;
}

/**
 * Camel/Pascal word with a vowel: real names (PlayerAccount) pass, renamed
 * names (qzx, x1, ab) fail.
 *
 * @param {string} value
 * @returns {boolean}
 */
export function looksLikeWord(value) {
  return (
    typeof value === 'string' &&
    value.length >= 3 &&
    /^[A-Za-z][A-Za-z0-9]*$/.test(value) &&
    /[aeiouAEIOU]/.test(value)
  );
}

/**
 * Names a rename pass leaves behind: 1-2 characters, or not word-shaped.
 *
 * @param {string} value
 * @returns {boolean}
 */
export function looksObfuscated(value) {
  return !looksLikeWord(value);
}

/**
 * @param {string[]} identifiers
 * @returns {string[]} sensitive names, original order, no duplicates
 */
export function sensitiveNames(identifiers) {
  const seen = new Set();
  const names = [];
  for (const identifier of identifiers) {
    const lower = identifier.toLowerCase();
    if (!SENSITIVE_TOKENS.some((token) => lower.includes(token))) continue;
    if (seen.has(identifier)) continue;
    seen.add(identifier);
    names.push(identifier);
  }
  return names;
}

/**
 * @param {string[]} strings
 * @returns {{
 *   identifiers: string[],
 *   readable: number,
 *   obfuscated: number,
 *   total: number,
 *   readableRatio: number,
 *   obfuscatedRatio: number,
 * }}
 */
export function analyzeNames(strings) {
  const identifiers = [...new Set((strings || []).filter(isIdentifier))];
  const readable = identifiers.filter(looksLikeWord).length;
  const obfuscated = identifiers.length - readable;
  const total = identifiers.length;
  return {
    identifiers,
    readable,
    obfuscated,
    total,
    readableRatio: total === 0 ? 0 : readable / total,
    obfuscatedRatio: total === 0 ? 0 : obfuscated / total,
  };
}
