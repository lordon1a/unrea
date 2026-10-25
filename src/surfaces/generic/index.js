import fsp from 'node:fs/promises';
import path from 'node:path';

import { containerOf } from '../../core/context.js';
import * as endpoint from './checks/endpoint.js';
import * as envFile from './checks/env-file.js';
import * as license from './checks/license.js';
import * as secret from './checks/secret.js';
import * as sourcemap from './checks/sourcemap.js';

const CHECKS = [secret, sourcemap, envFile, license, endpoint];

const SECRET_IDS = [
  'secret.aws',
  'secret.openai',
  'secret.anthropic',
  'secret.stripe.live',
  'secret.stripe.test',
  'secret.github',
  'secret.github.pat',
  'secret.google',
  'secret.slack',
  'secret.private_key',
  'secret.generic',
  'secret.jwt.service_role',
  'secret.jwt.anon',
];

const TEST_GLOBS = [
  '!test/**',
  '!tests/**',
  '!__tests__/**',
  '!e2e/**',
  '!spec/**',
  '!**/*.test.*',
  '!**/*.spec.*',
];

function secretExplain(title, risk) {
  return {
    title,
    what: `${title} value is present in text that ships to users.`,
    how_attackers_find_it:
      'Extract app.asar (or read the bundle), then grep the extracted files for the provider pattern (REA asar-extract + string-grep steps).',
    risk,
    fix: 'Revoke and rotate the credential first, remove it from the client, and call the provider from a server-side proxy.',
  };
}

const explain = {
  'secret.*': {
    title: 'Credential in the client',
    what: 'Any API key, token, private key or high-entropy literal shipped in client code.',
    how_attackers_find_it:
      'Extract app.asar, run strings/ripgrep over the bundle, and apply the provider regex list (REA asar-extract + string-grep steps).',
    risk: 'A live key can be copied and abused for data access, spend or account takeover.',
    fix: 'Rotate/revoke it, move the call behind your server, and keep the key only in server environment variables.',
  },
  'secret.aws': secretExplain(
    'AWS access key',
    'The key can be used with the AWS CLI/SDK; impact depends on its IAM policy.',
  ),
  'secret.openai': secretExplain(
    'OpenAI API key',
    'The key can be used for billable API calls or model access.',
  ),
  'secret.anthropic': secretExplain(
    'Anthropic API key',
    'The key can be used for billable API calls or model access.',
  ),
  'secret.stripe.live': secretExplain(
    'Stripe live key',
    'A live secret key can create charges, refunds or read customer data.',
  ),
  'secret.stripe.test': secretExplain(
    'Stripe test key',
    'A test key does not move real money, but it still reveals payment integration details.',
  ),
  'secret.github': secretExplain(
    'GitHub token',
    'The token may read or push repositories depending on its scopes.',
  ),
  'secret.github.pat': secretExplain(
    'GitHub fine-grained token',
    'The token may read or push repositories depending on its scopes.',
  ),
  'secret.google': secretExplain(
    'Google API key',
    'The key may be usable against billable Google APIs if it is not restricted.',
  ),
  'secret.slack': secretExplain(
    'Slack token',
    'The token may read messages or post as the workspace app.',
  ),
  'secret.private_key': secretExplain(
    'Private key',
    'A private key can impersonate a server, sign tokens or decrypt traffic.',
  ),
  'secret.generic': secretExplain(
    'High-entropy client secret',
    'The value looks like a credential assigned to a secret-looking name and can be replayed.',
  ),
  'secret.jwt.service_role': secretExplain(
    'Supabase service_role JWT',
    'service_role bypasses row-level security and can read or write every row the database role can reach.',
  ),
  'secret.jwt.anon': secretExplain(
    'Supabase anon JWT',
    'The anon key is public by design, but it is only safe when RLS is enabled on every exposed table.',
  ),
  'sourcemap.*': {
    title: 'Source map shipped',
    what: 'A .map file, or a sourceMappingURL comment, lets anyone reconstruct the original sources from the shipped bundle.',
    how_attackers_find_it:
      'Extract app.asar, read the .map file and its sourcesContent, or follow the sourceMappingURL (REA asar-extract + decompile/reconstruct step).',
    risk: 'Original TypeScript/JS, internal paths, comments and accidentally embedded secrets become readable.',
    fix: 'Disable production source maps in your bundler and exclude "!**/*.map" from the package.',
  },
  'sourcemap.file': {
    title: 'Source map file shipped',
    what: 'A .map file is packaged with the app.',
    how_attackers_find_it:
      'Extract app.asar and read the map; sourcesContent often contains the complete original source.',
    risk: 'Full source disclosure and easier vulnerability discovery.',
    fix: 'Disable source maps in production and exclude "!**/*.map" from electron-builder files.',
  },
  'sourcemap.comment': {
    title: 'Source map reference in code',
    what: 'A //# sourceMappingURL comment still points at a map, even if the map was meant to be private.',
    how_attackers_find_it:
      'Read the last lines of the bundle, fetch the referenced map from the package, and reconstruct the source.',
    risk: 'Leaks the original source layout and may reveal secrets embedded in sourcesContent.',
    fix: 'Disable source maps in production; rebuild without sourceMappingURL comments.',
  },
  'env.file': {
    title: 'Dotenv file shipped',
    what: 'A .env* file is included in the packaged app.',
    how_attackers_find_it:
      'Extract app.asar and read the dotenv file directly (REA asar-extract step).',
    risk: 'Every value in the file is public, including credentials and internal hostnames.',
    fix: 'Delete the file from the build, rotate exposed values, and keep secrets in server environment variables.',
  },
  'license.client': {
    title: 'Client-side license check',
    what: 'Plan, trial or payment entitlement is decided in code that ships to the user.',
    how_attackers_find_it:
      'Extract and decompile/beautify the bundle, then search for isPro/isLicensed/checkLicense and patch the branch (REA decompile step).',
    risk: 'A user can bypass payment or unlock paid features by editing one boolean.',
    fix: 'Verify entitlement on your server and return only a short-lived, signed result to the client.',
  },
  'endpoint.internal': {
    title: 'Internal or staging endpoint',
    what: 'The build contains a localhost, staging, internal or dev host.',
    how_attackers_find_it:
      'Grep the extracted bundle for URLs and try the hosts from outside the network.',
    risk: 'Staging services are often weaker, unauthenticated or connected to production data.',
    fix: 'Remove internal hosts from production builds and inject the public API base URL at build time.',
  },
  'tests.shipped': {
    title: 'Test files shipped',
    what: 'Test/spec files are included in the packaged app or asar.',
    how_attackers_find_it:
      'List asar entries and grep test folders; fixtures often contain credentials, internal URLs and expected behavior.',
    risk: 'Source disclosure and a higher chance of real fixture keys or internal details leaking.',
    fix: 'Exclude test folders and "*.test.*"/"*.spec.*" from electron-builder files and .npmignore.',
  },
};

async function exists(filePath) {
  try {
    await fsp.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readJson(filePath) {
  try {
    return JSON.parse(await fsp.readFile(filePath, 'utf8'));
  } catch {
    return null;
  }
}

async function detectBuilderConfig(projectPath) {
  const packagePath = path.join(projectPath, 'package.json');
  if (await exists(packagePath)) {
    const pkg = await readJson(packagePath);
    if (pkg && pkg.build && typeof pkg.build === 'object') {
      return { kind: 'package.json', path: packagePath, build: pkg.build };
    }
  }

  for (const name of ['electron-builder.yml', 'electron-builder.yaml', 'electron-builder.json']) {
    const filePath = path.join(projectPath, name);
    if (await exists(filePath)) {
      const extension = path.extname(name);
      return {
        kind: extension === '.json' ? 'json' : 'yaml',
        path: filePath,
      };
    }
  }
  return null;
}

function filesBlock(globs) {
  return globs.map((glob) => `  - ${JSON.stringify(glob)}`).join('\n');
}

function jsonFilesBlock(globs) {
  return globs.map((glob) => `    ${JSON.stringify(glob)}`).join(',\n');
}

async function testsShippedPlan(projectPath) {
  const config = await detectBuilderConfig(projectPath);
  const lines = [];

  if (!config) {
    lines.push(
      `No electron-builder config found in ${projectPath}.`,
      '',
      'Add this to package.json:',
      '```json',
      '"build": {',
      '  "files": [',
      jsonFilesBlock(TEST_GLOBS),
      '  ]',
      '}',
      '```',
      'Or in electron-builder.yml:',
      '```yaml',
      'files:',
      filesBlock(TEST_GLOBS),
      '```',
    );
  } else if (config.kind === 'package.json') {
    lines.push(
      `Detected electron-builder config in ${config.path} (build).`,
      '',
      'Merge these entries into build.files (keep existing entries):',
      '```json',
      '"files": [',
      jsonFilesBlock(TEST_GLOBS),
      ']',
      '```',
    );
  } else if (config.kind === 'json') {
    lines.push(
      `Detected ${config.path}.`,
      '',
      'Merge these entries into its top-level files array:',
      '```json',
      '"files": [',
      jsonFilesBlock(TEST_GLOBS),
      ']',
      '```',
    );
  } else {
    lines.push(
      `Detected ${config.path}.`,
      '',
      'Merge these entries under its files key:',
      '```yaml',
      'files:',
      filesBlock(TEST_GLOBS),
      '```',
    );
  }

  lines.push(
    '',
    'Also keep tests out of npm packages with .npmignore:',
    '```text',
    'test/',
    'tests/',
    '__tests__/',
    'e2e/',
    'spec/',
    '*.test.*',
    '*.spec.*',
    '```',
    '',
    'Rebuild, then rescan until tests.shipped is gone.',
  );
  return lines.join('\n');
}

function sourcemapPlan(id) {
  return [
    `Fix plan: ${id}`,
    '',
    'Disable production source maps in every bundler you use:',
    '- esbuild: `--sourcemap=false` (or `sourcemap: false` in the JS API)',
    '- Vite: `build: { sourcemap: false }`',
    '- webpack: `devtool: false`',
    '- TypeScript: `"sourceMap": false` in tsconfig.json',
    '- electron-builder files: `"!**/*.map"`',
    '',
    'Also remove any remaining `//# sourceMappingURL=` comments before packaging.',
    'Rebuild and rescan; sourcemap.* must disappear.',
  ].join('\n');
}

function secretPlan(id) {
  const isEnv = id === 'env.file';
  const isAnon = id === 'secret.jwt.anon';
  const lines = [`Fix plan: ${id}`, ''];

  if (isAnon) {
    lines.push(
      'The anon key is public by design. Do not rotate it; fix the exposure instead:',
      '1. Enable row-level security on every table exposed through PostgREST.',
      '2. Test with the anon key from outside your app.',
      '',
    );
  } else {
    lines.push(
      '1. Rotate/revoke the credential at the provider first. Assume the shipped value is compromised.',
      '2. Remove it from the build and from git history; add the file to .gitignore/.npmignore.',
      isEnv
        ? '3. Exclude the dotenv file from packaging (electron-builder files: "!**/.env*").'
        : '3. Keep the new key only in a server-side environment variable.',
      '',
    );
  }

  lines.push(
    'Minimal server proxy outline (server-only, never bundled):',
    '```js',
    '// server: POST /api/proxy',
    'app.post("/api/proxy", async (req, res) => {',
    '  const upstream = await fetch("https://provider.example/v1/endpoint", {',
    '    method: "POST",',
    '    headers: {',
    '      "content-type": "application/json",',
    '      authorization: `Bearer ${process.env.PROVIDER_API_KEY}`,',
    '    },',
    '    body: JSON.stringify(req.body),',
    '  });',
    '  res.status(upstream.status).send(await upstream.text());',
    '});',
    '```',
    '',
    'Add authentication, input validation and rate limiting to the proxy. The client should only call your endpoint.',
    'Rebuild and rescan; secret.* and env.file must be gone.',
  );
  return lines.join('\n');
}

function licensePlan() {
  return [
    'Fix plan: license.client',
    '',
    'Move entitlement decisions to the server:',
    '1. `POST /api/entitlement/verify` checks the user, subscription or payment record on the server.',
    '2. Return only a short-lived signed result: `{ valid, plan, expiresAt }`.',
    '3. The client uses that response for UI and feature gating; never trust a local boolean.',
    '4. Re-check server-side on every privileged API call.',
    '',
    'For offline apps, issue a signed license file with an expiry and verify the signature; do not ship the private key.',
    'Rebuild and rescan.',
  ].join('\n');
}

function endpointPlan() {
  return [
    'Fix plan: endpoint.internal',
    '',
    '1. Remove localhost/staging/internal/dev URLs from production configuration.',
    '2. Inject the public API base URL at build time from an environment variable.',
    '3. Grep the build for internal hostnames before packaging.',
    '',
    'Rebuild and rescan.',
  ].join('\n');
}

const fixPlan = {
  'tests.shipped': testsShippedPlan,
  'sourcemap.*': (projectPath, finding) => sourcemapPlan(finding?.id || 'sourcemap.*'),
  'sourcemap.file': (projectPath, finding) => sourcemapPlan(finding?.id || 'sourcemap.file'),
  'sourcemap.comment': (projectPath, finding) => sourcemapPlan(finding?.id || 'sourcemap.comment'),
  'secret.*': (projectPath, finding) => secretPlan(finding?.id || 'secret.*'),
  'env.file': (projectPath, finding) => secretPlan(finding?.id || 'env.file'),
  'license.client': () => licensePlan(),
  'endpoint.internal': () => endpointPlan(),
};
for (const id of SECRET_IDS) {
  fixPlan[id] = (projectPath, finding) => secretPlan(finding?.id || id);
}

/**
 * @param {object} context
 * @returns {Promise<Array<object>>}
 */
async function run(context) {
  const findings = [];

  for (const file of context.files) {
    if (file.kind !== 'text') continue;
    for (const check of CHECKS) {
      findings.push(...(await check.run(file)));
    }
  }

  if (context.mode !== 'source') {
    const containers = new Map();
    for (const file of context.files) {
      if (!file.inTest) continue;
      const container = containerOf(file.displayPath);
      const entry = containers.get(container) || {
        count: 0,
        example: file.displayPath,
      };
      entry.count += 1;
      containers.set(container, entry);
    }
    for (const [container, info] of containers) {
      const noun = info.count === 1 ? 'test file ships' : 'test files ship';
      findings.push({
        id: 'tests.shipped',
        severity: 'high',
        file: container || context.rootLabel,
        line: null,
        snippet: `${info.count} ${noun} in the build (e.g. ${info.example})`,
        fix: 'exclude test folders from the package (electron-builder `files` / .npmignore)',
      });
    }
  }

  return findings;
}

export default {
  id: 'generic',
  title: 'Generic application exposure',
  covers: ['secrets', 'dotenv', 'source maps', 'internal endpoints', 'client license checks', 'shipped tests'],
  detect: () => true,
  run,
  explain,
  fixPlan,
};
