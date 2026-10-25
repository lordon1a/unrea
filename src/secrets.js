import { clip, mask } from './mask.js';

/**
 * Secret detection shared by the secret check, the .env check and snippet
 * redaction. Keeping the patterns in one place is what guarantees that a value
 * flagged as a secret can never leak through some other finding's snippet.
 */

const PRIVATE_KEY_RE = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g;

const PROVIDERS = [
  {
    id: 'secret.private_key',
    re: PRIVATE_KEY_RE,
    severity: 'critical',
    label: 'private key',
    fix: 'remove the private key from the build and rotate it; keys belong on your server',
  },
  {
    id: 'secret.anthropic',
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g,
    severity: 'critical',
    label: 'Anthropic key',
    fix: 'revoke and rotate this Anthropic key; call the API from your server',
  },
  {
    id: 'secret.openai',
    re: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}/g,
    severity: 'critical',
    label: 'OpenAI key',
    fix: 'revoke and rotate this OpenAI key; call the API from your server',
  },
  {
    id: 'secret.aws',
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'critical',
    label: 'AWS access key',
    fix: 'revoke and rotate this AWS key; issue short-lived credentials server-side',
  },
  {
    id: 'secret.stripe.live',
    re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}/g,
    severity: 'critical',
    label: 'Stripe live key',
    fix: 'revoke and rotate this live Stripe key; charge only from your server',
  },
  {
    id: 'secret.stripe.test',
    re: /\bsk_test_[A-Za-z0-9]{16,}/g,
    severity: 'medium',
    label: 'Stripe test key',
    fix: 'test keys do not belong in a production bundle; move payments server-side',
  },
  {
    id: 'secret.github.pat',
    re: /\bgithub_pat_[A-Za-z0-9_]{40,}/g,
    severity: 'critical',
    label: 'GitHub fine-grained token',
    fix: 'revoke and rotate this GitHub token; never ship repo tokens in a client',
  },
  {
    id: 'secret.github',
    re: /\bghp_[A-Za-z0-9]{36}\b/g,
    severity: 'critical',
    label: 'GitHub token',
    fix: 'revoke and rotate this GitHub token; never ship repo tokens in a client',
  },
  {
    id: 'secret.google',
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: 'high',
    label: 'Google API key',
    fix: 'restrict key or proxy it',
  },
  {
    id: 'secret.slack',
    re: /\bxox[abpr]-[A-Za-z0-9-]{10,}/g,
    severity: 'critical',
    label: 'Slack token',
    fix: 'revoke this Slack token; call Slack from your server',
  },
];

const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

const IDENTIFIER_RE = /(secret|api[_-]?key|token|passw(or)?d|private[_-]?key)/i;
const GENERIC_LITERAL_RE = /(['"`])((?:\\.|(?!\1)[^\\\n]){16,})\1/g;
// Either a bare identifier (`apiKey =`, `token:`) or a quoted key (`"apiKey":`). A quote only on the
// right side means the word ended some other string, e.g. `'...rotate secrets' : 'other'`.
const ASSIGNMENT_TAIL_RE = /(?:(["'])([A-Za-z_$][\w$.-]{0,48})\1|(?<![\w$."'-])([A-Za-z_$][\w$.-]{0,48}))\s*[:=]\s*["']?\s*$/;

/**
 * Shannon entropy in bits per character.
 *
 * @param {string} value
 * @returns {number}
 */
export function shannonEntropy(value) {
  if (!value.length) return 0;
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function lineFromStarts(starts, index) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (starts[mid] <= index) lo = mid + 1;
    else hi = mid - 1;
  }
  return hi + 1;
}

function overlaps(ranges, start, end) {
  return ranges.some((r) => start < r.end && end > r.start);
}

/**
 * Find secret-shaped values in a text blob.
 *
 * @param {string} text
 * @returns {Array<{id:string,severity:string,index:number,end:number,value:string,line:number,snippet:string,fix:string}>}
 */
export function scanSecrets(text) {
  const source = String(text ?? '');
  if (!source) return [];

  const lineStarts = [0];
  for (let i = 0; i < source.length; i++) {
    if (source.charCodeAt(i) === 10) lineStarts.push(i + 1);
  }
  const lineAt = (index) => lineFromStarts(lineStarts, index);

  const found = [];
  const occupied = [];

  const add = (entry) => {
    if (overlaps(occupied, entry.index, entry.end)) return;
    occupied.push({ start: entry.index, end: entry.end });
    found.push({ ...entry, line: lineAt(entry.index) });
  };

  for (const provider of PROVIDERS) {
    provider.re.lastIndex = 0;
    let match;
    while ((match = provider.re.exec(source)) !== null) {
      const value = match[0];
      add({
        id: provider.id,
        severity: provider.severity,
        index: match.index,
        end: match.index + value.length,
        value,
        snippet: `${provider.label}: ${mask(value)}`,
        fix: provider.fix,
      });
      if (match[0].length === 0) provider.re.lastIndex++;
    }
  }

  JWT_RE.lastIndex = 0;
  let jwt;
  while ((jwt = JWT_RE.exec(source)) !== null) {
    const value = jwt[0];
    const start = jwt.index;
    const end = start + value.length;
    if (overlaps(occupied, start, end)) continue;

    let role = null;
    try {
      const payload = value.split('.')[1];
      const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
      role = typeof decoded?.role === 'string' ? decoded.role : null;
    } catch {
      // Not a decodable JWT payload; nothing to classify.
    }

    if (role === 'service_role') {
      occupied.push({ start, end });
      found.push({
        id: 'secret.jwt.service_role',
        severity: 'critical',
        index: start,
        end,
        value,
        line: lineAt(start),
        snippet: `Supabase service_role JWT: ${mask(value)}`,
        fix: 'rotate this service key and move privileged Supabase calls server-side',
      });
    } else if (role === 'anon') {
      occupied.push({ start, end });
      found.push({
        id: 'secret.jwt.anon',
        severity: 'info',
        index: start,
        end,
        value,
        line: lineAt(start),
        snippet: `Supabase anon JWT: ${mask(value)}`,
        fix: 'public by design, make sure RLS is on',
      });
    }
  }

  GENERIC_LITERAL_RE.lastIndex = 0;
  let literal;
  while ((literal = GENERIC_LITERAL_RE.exec(source)) !== null) {
    const value = literal[2];
    const start = literal.index + 1;
    const end = start + value.length;
    if (overlaps(occupied, start, end)) continue;

    const before = source.slice(Math.max(0, literal.index - 80), literal.index);
    const assignment = ASSIGNMENT_TAIL_RE.exec(before);
    if (!assignment) continue;
    const identifier = assignment[2] || assignment[3];
    if (!IDENTIFIER_RE.test(identifier)) continue;
    if (shannonEntropy(value) < 3.5) continue;

    add({
      id: 'secret.generic',
      severity: 'high',
      index: start,
      end,
      value,
      snippet: `${identifier}: ${mask(value)}`,
      fix: 'move this secret to a server-side environment variable and rotate it',
    });
  }

  return found.sort((a, b) => a.index - b.index);
}

/**
 * Replace every detected secret in an arbitrary snippet with its masked form.
 *
 * @param {string} text
 * @returns {string}
 */
export function redactSecrets(text) {
  const source = String(text ?? '');
  const secrets = scanSecrets(source);
  if (!secrets.length) return source;

  let out = '';
  let cursor = 0;
  for (const secret of secrets) {
    if (secret.index < cursor) continue;
    out += source.slice(cursor, secret.index);
    out += mask(secret.value);
    cursor = secret.end;
  }
  out += source.slice(cursor);
  return out;
}

/**
 * Snippet helper: redact, then clip to one line.
 *
 * @param {string} text
 * @param {number} [max]
 * @returns {string}
 */
export function safeSnippet(text, max = 140) {
  return clip(redactSecrets(text), max);
}
