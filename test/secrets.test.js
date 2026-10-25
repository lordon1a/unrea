import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import test from 'node:test';

import { scan } from '../src/scan.js';
import { fake, makeTemp, writeAt } from './helpers.mjs';

async function scanText(t, relative, text) {
  const dir = await makeTemp('unrea-secret-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  await writeAt(dir, relative, text);
  return { dir, result: await scan(dir) };
}

test('finds provider keys with the spec severities and masks them', async (t) => {
  const cases = [
    ['main.js', `const a = "${fake.aws()}";`, 'secret.aws', 'critical'],
    ['openai.js', `const b = "${fake.openai()}";`, 'secret.openai', 'critical'],
    ['anthropic.js', `const c = "${fake.anthropic()}";`, 'secret.anthropic', 'critical'],
    ['stripe.js', `const d = "${fake.stripeLive()}";`, 'secret.stripe.live', 'critical'],
    ['stripe-test.js', `const e = "${fake.stripeTest()}";`, 'secret.stripe.test', 'medium'],
    ['github.js', `const f = "${fake.githubClassic()}";`, 'secret.github', 'critical'],
    ['github-pat.js', `const g = "${fake.githubPat()}";`, 'secret.github.pat', 'critical'],
    ['google.js', `const h = "${fake.google()}";`, 'secret.google', 'high'],
    ['slack.js', `const i = "${fake.slack()}";`, 'secret.slack', 'critical'],
    [
      'key.txt',
      '-----BEGIN RSA PRIVATE KEY-----\nnot-a-real-key\n-----END RSA PRIVATE KEY-----\n',
      'secret.private_key',
      'critical',
    ],
  ];

  const dir = await makeTemp('unrea-providers-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  for (const [name, body] of cases) await writeAt(dir, name, `${body}\n`);

  const { findings } = await scan(dir);
  for (const [name, , id, severity] of cases) {
    const finding = findings.find((f) => f.id === id && f.file === name);
    assert.ok(finding, `${id} should be found in ${name}`);
    assert.equal(finding.severity, severity);
    assert.ok(finding.snippet.length > 0);
  }

  // No finding may reproduce its own secret verbatim.
  for (const finding of findings) {
    for (const hidden of [fake.aws(), fake.openai(), fake.anthropic(), fake.stripeLive(), fake.githubClassic()]) {
      assert.ok(!finding.snippet.includes(hidden), 'snippet leaked a full secret');
    }
  }
});

test('classifies Supabase JWTs by role', async (t) => {
  const service = fake.jwt({ role: 'service_role', iss: 'supabase' });
  const anon = fake.jwt({ role: 'anon', iss: 'supabase' });
  const unknown = fake.jwt({ role: 'authenticated', sub: 'user-1' });
  const { result } = await scanText(
    t,
    'jwt.js',
    `const service = "${service}";\nconst anon = "${anon}";\nconst token = "${unknown}";\n`,
  );

  const serviceFinding = result.findings.find((f) => f.id === 'secret.jwt.service_role');
  const anonFinding = result.findings.find((f) => f.id === 'secret.jwt.anon');
  assert.equal(serviceFinding.severity, 'critical');
  assert.equal(anonFinding.severity, 'info');
  assert.ok(!serviceFinding.snippet.includes(service));
  assert.ok(!anonFinding.snippet.includes(anon));

  // Unknown roles fall through to the generic high-entropy check.
  const generic = result.findings.find((f) => f.id === 'secret.generic');
  assert.ok(generic);
  assert.equal(generic.severity, 'high');
  assert.equal(generic.line, 3);
  assert.ok(!generic.snippet.includes(unknown));
});

test('generic high-entropy assignment is high, low entropy is not flagged', async (t) => {
  const value = fake.generic();
  const { result } = await scanText(
    t,
    'config.js',
    `const apiKey = "${value}";\nconst password = "${'a'.repeat(32)}";\n`,
  );

  const finding = result.findings.find((f) => f.id === 'secret.generic');
  assert.ok(finding);
  assert.equal(finding.severity, 'high');
  assert.ok(finding.snippet.startsWith('apiKey: '));
  assert.ok(!finding.snippet.includes(value));
  assert.equal(result.findings.filter((f) => f.id === 'secret.generic').length, 1);
});

test('.env is critical when it contains a secret, high otherwise', async (t) => {
  const secretDir = await makeTemp('unrea-env-secret-');
  const plainDir = await makeTemp('unrea-env-plain-');
  t.after(() => rm(secretDir, { recursive: true, force: true }));
  t.after(() => rm(plainDir, { recursive: true, force: true }));

  await writeAt(secretDir, '.env', `AWS_KEY=${fake.aws()}\n`);
  await writeAt(plainDir, '.env.production', 'VITE_API_URL=https://api.example.com\n');

  const secretEnv = await scan(secretDir);
  const plainEnv = await scan(plainDir);
  assert.equal(secretEnv.findings.find((f) => f.id === 'env.file').severity, 'critical');
  assert.equal(plainEnv.findings.find((f) => f.id === 'env.file').severity, 'high');
  assert.ok(!secretEnv.findings.find((f) => f.id === 'env.file').snippet.includes(fake.aws()));
});

test('.env snippet never echoes a value the entropy check would miss', async (t) => {
  const dir = await makeTemp('unrea-env-low-entropy-');
  t.after(() => rm(dir, { recursive: true, force: true }));
  const value = 'hunter2'.repeat(3);
  await writeAt(dir, '.env', `PASSWORD=${value}\n`);

  const result = await scan(dir);
  const envFinding = result.findings.find((f) => f.id === 'env.file');
  assert.ok(envFinding);
  assert.ok(!envFinding.snippet.includes(value), 'dotenv value leaked in the snippet');
  assert.match(envFinding.snippet, /^PASSWORD=/);
});

test('generic rule reads bare and quoted keys, not words that end another string', async (t) => {
  const value = ['Xk29fLq0', 'Zp81Wm3N', 'v7Rt'].join('');
  const other = ['Zq81Lm0P', 'w2Ks9Dm4', 'Vb6YxYz'].join('');
  const text = [
    `const apiKey = "${value}";`,
    `const c = {"token": "${value}"};`,
    `const t = cond ? "rotate the secrets" : "${other}";`,
  ].join('\n');
  const { result } = await scanText(t, 'app/main.js', text);
  const lines = result.findings.filter((f) => f.id === 'secret.generic').map((f) => f.line);
  assert.deepEqual(lines, [1, 2]);
});
