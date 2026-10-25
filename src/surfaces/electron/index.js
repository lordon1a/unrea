import fsp from 'node:fs/promises';
import path from 'node:path';

import * as asarCheck from './checks/asar.js';
import * as codeReadable from './checks/code-readable.js';
import * as electronFuses from './checks/electron-fuses.js';

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

const explain = {
  'asar.plain': {
    title: 'Asar is not encryption',
    what: 'The app is packaged as an asar archive, which is a concatenated archive rather than an encrypted container.',
    how_attackers_find_it:
      'Extract it in seconds with @electron/asar or any asar tool (REA asar-extract step).',
    risk: 'Anyone can read or replace the packaged code unless fuses and signatures are enforced.',
    fix: 'Treat asar as packaging only; keep secrets server-side and enable asar integrity/OnlyLoadAppFromAsar fuses.',
  },
  'code.readable': {
    title: 'Unminified JavaScript shipped',
    what: 'A large .js file is packaged without minification.',
    how_attackers_find_it:
      'Extract app.asar, beautify the bundle and read function names, strings and control flow (REA decompile step).',
    risk: 'Business logic and hidden endpoints are cheap to understand; it also multiplies the value of any leaked source map.',
    fix: 'Minify/obfuscate production bundles and keep valuable logic server-side; obfuscation slows readers but does not stop them.',
  },
  'electron.fuses.*': {
    title: 'Weak Electron fuses',
    what: 'The Electron binary allows debugging, Node mode, asar swapping or NODE_OPTIONS injection.',
    how_attackers_find_it:
      'Read the fuse wire with @electron/fuses, then use the enabled capability to inspect or modify the app (REA runtime/shipping step).',
    risk: 'Attackers can attach a debugger, execute Node code, or swap app.asar for patched code.',
    fix: 'Flip the affected fuses at build time with an electron-builder afterPack hook using @electron/fuses.',
  },
  'electron.fuses.run_as_node': {
    title: 'RunAsNode enabled',
    what: 'The Electron executable can be started as a plain Node.js process with ELECTRON_RUN_AS_NODE=1.',
    how_attackers_find_it:
      'Read the fuse wire, launch the app binary with ELECTRON_RUN_AS_NODE=1, and run arbitrary Node code with the app runtime.',
    risk: 'Turns the app into a scriptable Node runtime and eases inspection/tampering.',
    fix: 'Set RunAsNode to false with @electron/fuses in an afterPack hook and rebuild.',
  },
  'electron.fuses.node_cli_inspect': {
    title: 'Node CLI inspect enabled',
    what: 'The binary accepts --inspect/--inspect-brk.',
    how_attackers_find_it:
      'Launch the app with --inspect and attach a debugger to the main process.',
    risk: 'Full runtime inspection, breakpoints and memory access.',
    fix: 'Set EnableNodeCliInspectArguments to false with @electron/fuses at build time.',
  },
  'electron.fuses.asar_integrity': {
    title: 'Asar integrity disabled',
    what: 'Electron does not validate the app.asar integrity header at runtime.',
    how_attackers_find_it: 'Replace app.asar with a patched archive and launch the app.',
    risk: 'Code tampering and license bypass become straightforward.',
    fix: 'Set EnableEmbeddedAsarIntegrityValidation to true with @electron/fuses at build time.',
  },
  'electron.fuses.only_load_app_from_asar': {
    title: 'OnlyLoadAppFromAsar disabled',
    what: 'The app can load an unpacked app directory instead of the signed asar.',
    how_attackers_find_it:
      'Drop an app folder next to the binary (or replace resources) and launch it.',
    risk: 'Side-loading modified code bypasses asar integrity checks.',
    fix: 'Set OnlyLoadAppFromAsar to true with @electron/fuses at build time.',
  },
  'electron.fuses.node_options': {
    title: 'NODE_OPTIONS injection enabled',
    what: 'The binary honors the NODE_OPTIONS environment variable.',
    how_attackers_find_it:
      'Start the app with NODE_OPTIONS=--require ./payload.js and load code before the app boots.',
    risk: 'Arbitrary code execution in the main process.',
    fix: 'Set EnableNodeOptionsEnvironmentVariable to false with @electron/fuses at build time.',
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
      return { kind: extension === '.json' ? 'json' : 'yaml', path: filePath };
    }
  }
  return null;
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

exports.default = async function afterPack(context) {
  const { flipFuses, FuseVersion, FuseV1Options } = await import('@electron/fuses');
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
    return `Unknown fuse id "${id}".`;
  }

  const config = await detectBuilderConfig(projectPath);
  return [
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
    `3. ${registrationText(config)}`,
    '',
    '4. Rebuild the app and rescan it. If you already have an afterPack hook, add the flipFuses call to it instead of replacing it.',
  ].join('\n');
}

function readablePlan() {
  return [
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
  ].join('\n');
}

function asarPlan() {
  return [
    'Fix plan: asar.plain',
    '',
    'asar is packaging, not encryption. Do not store secrets in it.',
    '1. Keep credentials and valuable logic on your server.',
    '2. Enable EnableEmbeddedAsarIntegrityValidation and OnlyLoadAppFromAsar with an @electron/fuses afterPack hook.',
    '3. Sign application updates and verify them before applying.',
    '',
    'Run `unrea_fix_plan` for electron.fuses.asar_integrity or electron.fuses.only_load_app_from_asar for the hook content.',
  ].join('\n');
}

const fixPlan = {
  'electron.fuses.*': (projectPath, finding) => {
    const requested = finding?.id;
    const id =
      requested === 'electron.fuses.*' || FUSE_RULES[requested]
        ? requested
        : 'electron.fuses.*';
    return fusePlan(id, projectPath);
  },
  'asar.plain': () => asarPlan(),
  'code.readable': () => readablePlan(),
};
for (const id of Object.keys(FUSE_RULES)) {
  fixPlan[id] = (projectPath, finding) => fusePlan(finding?.id || id, projectPath);
}

/**
 * @param {object} context
 * @returns {Promise<Array<object>>}
 */
async function run(context) {
  const findings = [];
  for (const file of context.files) {
    if (file.kind === 'asar') {
      findings.push(...(await asarCheck.run(file)));
    } else if (file.kind === 'text' && file.ext === '.js') {
      findings.push(...(await codeReadable.run(file)));
    } else if (file.kind === 'binary') {
      findings.push(...(await electronFuses.run(file)));
    }
  }
  return findings;
}

function detect(context) {
  return (
    context.has('**/*.asar') ||
    context.has('**/*.exe') ||
    context.has('**/*.js') ||
    context.has('**/*.mjs') ||
    context.has('**/*.cjs') ||
    context.has('**/Contents/MacOS/*')
  );
}

export default {
  id: 'electron',
  title: 'Electron / JavaScript',
  covers: ['asar', 'js bundles', 'electron fuses', 'readable code'],
  detect,
  run,
  explain,
  fixPlan,
};
