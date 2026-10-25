/**
 * Identifier analysis on top of `dotnet.strings` from src/parse/pe.js. There is
 * intentionally no .NET metadata parser here: the shared PE reader owns the
 * BSJB -> #Strings traversal, this module only judges the strings it returns.
 */

const SENSITIVE = [
  'gold',
  'coin',
  'gem',
  'currency',
  'money',
  'wallet',
  'purchase',
  'iap',
  'premium',
  'license',
  'unlock',
  'receipt',
  'score',
  'xp',
  'level up',
  'health',
  'damage',
  'godmode',
  'cheat',
  'admin',
  'debug',
];

// Compiler-generated accessors and backing fields are not evidence about how
// readable the shipped code is; `<` covers <Module> and <Gold>k__BackingField.
const COMPILER_GENERATED = /^(?:get_|set_|add_|remove_|op_|\.)/;

/**
 * @param {string} value
 * @returns {boolean}
 */
export function isIdentifier(value) {
  return (
    typeof value === 'string' &&
    value.length >= 3 &&
    !/[<>]/.test(value) &&
    !COMPILER_GENERATED.test(value)
  );
}

/**
 * Camel/Pascal style word with a vowel in it. Obfuscated names (a, x1, qzr)
 * fail this; real names (PlayerController, AddGold) pass it.
 *
 * @param {string} value
 * @returns {boolean}
 */
export function looksLikeWord(value) {
  return /^[A-Za-z][A-Za-z0-9]*$/.test(value) && /[aeiouAEIOU]/.test(value);
}

/**
 * Split CamelCase, digits and separators into lowercase words.
 * "PlayerGold" -> ["player", "gold"]; "player_gold" -> ["player", "gold"].
 *
 * @param {string} value
 * @returns {string[]}
 */
export function splitWords(value) {
  return value
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((word) => word.toLowerCase());
}

/**
 * How strongly an identifier matches one sensitive token.
 * 3 = exact name, 2 = whole CamelCase/snake_case word, 1 = word prefix/suffix.
 *
 * Prefix/suffix keeps the spec's case-insensitive substring intent without the
 * noise of raw substring matching ("Segment" is not a gem, "Export" is not xp).
 *
 * @param {string} identifier
 * @param {string} token
 * @returns {number}
 */
function matchRank(identifier, token) {
  const lower = identifier.toLowerCase();
  const wanted = token.toLowerCase();
  if (wanted.includes(' ')) {
    return splitWords(identifier).join(' ').includes(wanted) ? 2 : 0;
  }
  if (lower === wanted) return 3;
  const words = splitWords(identifier);
  if (words.includes(wanted)) return 2;
  if (wanted.length >= 3 && words.some((word) => word.startsWith(wanted) || word.endsWith(wanted))) {
    return 1;
  }
  return 0;
}

/**
 * @param {string[]} identifiers
 * @returns {string[]} most convincing names first, no duplicates
 */
export function sensitiveNames(identifiers) {
  const ranked = [];
  for (const identifier of identifiers) {
    // Framework attributes/enums (DebuggableAttribute, DebuggingModes) are not game state.
    if (/Attribute$/.test(identifier) || /^Debugg/.test(identifier)) continue;
    let score = 0;
    for (const token of SENSITIVE) {
      score = Math.max(score, matchRank(identifier, token));
    }
    if (score > 0) ranked.push({ name: identifier, score });
  }
  ranked.sort(
    (a, b) =>
      b.score - a.score ||
      a.name.length - b.name.length ||
      a.name.localeCompare(b.name),
  );
  const seen = new Set();
  const names = [];
  for (const entry of ranked) {
    if (seen.has(entry.name)) continue;
    seen.add(entry.name);
    names.push(entry.name);
  }
  return names;
}

/**
 * @param {string[]} strings
 * @returns {{identifiers: string[], readable: number, total: number, ratio: number}}
 */
export function analyzeNames(strings) {
  const identifiers = [...new Set((strings || []).filter(isIdentifier))];
  const readable = identifiers.filter(looksLikeWord).length;
  const total = identifiers.length;
  return {
    identifiers,
    readable,
    total,
    ratio: total === 0 ? 0 : readable / total,
  };
}
