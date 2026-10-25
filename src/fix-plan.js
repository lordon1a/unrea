import fsp from 'node:fs/promises';
import path from 'node:path';

import { KNOWN_IDS } from './explain.js';

const TEST_GLOBS = [
  '!test/**',
  '!tests/**',
  '!__tests__/**',
  '!e2e/**',
  '!spec/**',
  '!**/*.test.*',
  '!**/*.spec.*',
];

const FUSE_RULES = {
  'electron.fuses.run_as_node': {
    option: 'RunAsNode',
    value: false,
    label: 'RunAsNode = false',
  },
  'electron.fuses.node_cli_inspect': {
    option: 'EnableNodeCliInspectArguments',
    value: false,
    label: 'EnableNodeCliInspectArguments = false',
  },
  'electron.fuses.asar_integrity': {
    option: 'EnableEmbeddedAsarIntegrityValidation',
    value: true,
    label: 'EnableEmbeddedAsarIntegrityValidation = true',
  },
  'electron.fuses.only_load_app_from_asar': {
    option: 'OnlyLoadAppFromAsar',
    value: true,
    label: 'OnlyLoadAppFromAsar = true',
  },
  'electron.fuses.node_options': {
    option: 'EnableNodeOptionsEnvironmentVariable',
    value: false,
    label: 'EnableNodeOptionsEnvironmentVariable = false',
  },
};

const ALL_FUSE_RULES = Object.values(FUSE_RULES);

function knownIdsText() {
  return ['Known ids:', ...KNOWN_IDS.map((id) => `- ${id}`)].join('\n');
}

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

function registrationText(config) {
  if (!config) {
    return [
      'Register the hook in electron-builder (package.json):',
      '```json',
      '"build": { "afterPack": "build/afterPack.cjs" }',
      '```',
      'or in electron-builder.yml:',
      '```yaml',
      'afterPack: build/afterPack.cjs',
      '```',
    ].join('\n');
  }
  if (config.kind === 'package.json') {
    return [
      `Register it in ${config.path} under build:`,
      '```json',
      '"afterPack": "build/afterPack.cjs"',
      '```',
    ].join('\n');
  }
  if (config.kind === 'json') {
    return [
      `Register it in ${config.path}:`,
      '```json',
      '"afterPack": "build/afterPack.cjs"',
      '```',
    ].join('\n');
  }
  return [
    `Register it in ${config.path}:`,
    '```yaml',
    'afterPack: build/afterPack.cjs',
    '```',
  ].join('\n');
}

function fuseHookText(rules) {
  const flips = rules
    .map((rule) => `    [FuseV1Options.${rule.option}]: ${rule.value},`)
    .join('\n');
  return `// build/afterPack.cjs
// Apply the fuse in electron-builder afterPack. Run: npm i -D @electron/fuses
const path = require('node:path');
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');

exports.default = async function afterPack(context) {
  const { appOutDir, packager, electronPlatformName } = context;
  const productName = packager.appInfo.productFilename;
  const executable = electronPlatformName === 'darwin'
    ? path.join(appOutDir, \`\${productName}.app\`)
    : electronPlatformName === 'win32'
      ? path.join(appOutDir, \`\${productName}.exe\`)
      : path.join(appOutDir, productName);

  await flipFuses(executable, {
    version: FuseVersion.V1,
${flips}
  });

  console.log(\`[unrea] fuses applied to \${executable}\`);
};`;
}

async function fusePlan(id, projectPath) {
  let rules;
  let label;
  if (id === 'electron.fuses.*') {
    rules = ALL_FUSE_RULES;
    label = 'all recommended fuses';
  } else if (FUSE_RULES[id]) {
    rules = [FUSE_RULES[id]];
    label = FUSE_RULES[id].label;
  } else {
    return {
      ok: false,
      text: `Unknown fuse id "${id}".\n\n${knownIdsText()}`,
    };
  }

  const config = await detectBuilderConfig(projectPath);
  return {
    ok: true,
    text: [
      `Fix plan: ${id}`,
      '',
      `Set ${label} with @electron/fuses at build time.`,
      '',
      '1. Create build/afterPack.cjs:',
      '```js',
      fuseHookText(rules),
      '```',
      '',
      '2. Install the build-time dependency:',
      '```bash',
      'npm install --save-dev @electron/fuses',
      '```',
      '',
      '3. ' + registrationText(config),
      '',
      '4. Rebuild the app and rescan it. If you already have an afterPack hook, add the flipFuses call to it instead of replacing it.',
    ].join('\n'),
  };
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
  return { ok: true, text: lines.join('\n') };
}

function sourcemapPlan(id) {
  return {
    ok: true,
    text: [
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
    ].join('\n'),
  };
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
    "// server: POST /api/proxy",
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
  return { ok: true, text: lines.join('\n') };
}

function readablePlan() {
  return {
    ok: true,
    text: [
      'Fix plan: code.readable',
      '',
      'Minify production JavaScript:',
      '- esbuild: `--minify`',
      '- Vite: `build.minify: "esbuild"`',
      '- webpack: enable `optimization.minimize` with TerserPlugin',
      '- Optional: javascript-obfuscator for a higher reading cost',
      '',
      'Honest note: minification/obfuscation slows a reverse engineer (and an AI agent), it does not stop them.',
      'Move valuable business logic to your server; that is the only durable fix.',
      'Also disable source maps and rebuild/rescan.',
    ].join('\n'),
  };
}

function licensePlan() {
  return {
    ok: true,
    text: [
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
    ].join('\n'),
  };
}

function endpointPlan() {
  return {
    ok: true,
    text: [
      'Fix plan: endpoint.internal',
      '',
      '1. Remove localhost/staging/internal/dev URLs from production configuration.',
      '2. Inject the public API base URL at build time from an environment variable.',
      '3. Grep the build for internal hostnames before packaging.',
      '',
      'Rebuild and rescan.',
    ].join('\n'),
  };
}

function asarPlan() {
  return {
    ok: true,
    text: [
      'Fix plan: asar.plain',
      '',
      'asar is packaging, not encryption. Do not store secrets in it.',
      '1. Keep credentials and valuable logic on your server.',
      '2. Enable EnableEmbeddedAsarIntegrityValidation and OnlyLoadAppFromAsar with an @electron/fuses afterPack hook.',
      '3. Sign application updates and verify them before applying.',
      '',
      'Run `unrea_fix_plan` for electron.fuses.asar_integrity or electron.fuses.only_load_app_from_asar for the hook content.',
    ].join('\n'),
  };
}

/**
 * Build a concrete plan for an agent to apply. This function never writes files.
 *
 * @param {string} id
 * @param {string} projectPath
 * @returns {Promise<{ok:boolean,text:string}>}
 */
export async function buildFixPlan(id, projectPath) {
  const resolved = path.resolve(projectPath || '.');
  const normalized = id === 'electron.fuses' ? 'electron.fuses.*' : id === 'sourcemap' ? 'sourcemap.*' : id === 'secret' ? 'secret.*' : id;
  if (normalized.startsWith('electron.fuses.')) return fusePlan(normalized, resolved);
  if (normalized === 'tests.shipped') return testsShippedPlan(resolved);
  if (normalized === 'sourcemap.*' || normalized.startsWith('sourcemap.')) {
    return sourcemapPlan(normalized === 'sourcemap.*' ? id : normalized);
  }
  if (
    normalized === 'secret.*' ||
    normalized === 'env.file' ||
    normalized.startsWith('secret.')
  ) {
    return secretPlan(normalized === 'secret.*' ? id : normalized);
  }
  if (normalized === 'code.readable') return readablePlan();
  if (normalized === 'license.client') return licensePlan();
  if (normalized === 'endpoint.internal') return endpointPlan();
  if (normalized === 'asar.plain') return asarPlan();
  return {
    ok: false,
    text: `Unknown check id "${id}".\n\n${knownIdsText()}`,
  };
}
