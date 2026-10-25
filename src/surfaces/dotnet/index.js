import { readPE } from '../../parse/pe.js';
import { analyzeNames, sensitiveNames } from './names.js';

const MAX_SENSITIVE_NAMES = 15;
const MIN_IDENTIFIERS = 5;
const READABLE_RATIO = 0.6;
const OBFUSCATED_RATIO = 0.6;

// Unity players ship their own managed assemblies. The unity surface owns
// those; reporting them again here would only duplicate findings.
const UNITY_PATH = /(?:^|\/)(?:[^/]*_Data|Resources\/Data)\/Managed\/|(?:^|\/)MonoBleedingEdge\//i;

// Framework and third-party assemblies are not the developer's code and are
// normally the same in every .NET app.
const FRAMEWORK_PREFIXES = [
  'system.',
  'microsoft.',
  'newtonsoft.',
  'avalonia.',
  'mono.',
  'xamarin.',
  'google.',
  'windowsbase',
  'presentationcore',
  'presentationframework',
  'netstandard',
  'mscorlib',
  'accessibility',
  'skia',
  'harfbuzz',
  'sqlite',
  'entityframework',
  'serilog',
  'nlog',
  'log4net',
  'automapper',
  'fluentvalidation',
  'protobuf',
  'grpc',
  'icsharpcode',
  'sharpziplib',
  'sixlabors',
  'questpdf',
  'closedxml',
  'restsharp',
  'polly',
  'dapper',
  'csvhelper',
  'anglesharp',
  'htmlagilitypack',
  'bouncycastle',
  'messagepack',
];

// Detected PEs are cached per scan so detect() and run() parse each file once.
const peCacheByContext = new WeakMap();

function cacheFor(context) {
  let cache = peCacheByContext.get(context);
  if (!cache) {
    cache = new Map();
    peCacheByContext.set(context, cache);
  }
  return cache;
}

function parseCached(context, file) {
  const cache = cacheFor(context);
  let pending = cache.get(file.absPath);
  if (!pending) {
    pending = readPE(file.absPath).catch(() => ({ valid: false, error: 'read failed' }));
    cache.set(file.absPath, pending);
  }
  return pending;
}

async function hasMzSignature(context, file) {
  try {
    const head = await context.readBytes(file.absPath, 0, 2);
    return head.length === 2 && head[0] === 0x4d && head[1] === 0x5a;
  } catch {
    return false;
  }
}

function isManagedCandidate(file) {
  return file.ext === '.exe' || file.ext === '.dll';
}

function isSkippedPath(displayPath) {
  return UNITY_PATH.test(displayPath);
}

function assemblyName(file) {
  return file.basename.replace(/\.(?:exe|dll)$/i, '');
}

function isFrameworkAssembly(file) {
  const name = assemblyName(file).toLowerCase();
  return FRAMEWORK_PREFIXES.some((prefix) => name.startsWith(prefix));
}

function isAppAssembly(file) {
  return !file.inNodeModules && !isSkippedPath(file.displayPath) && !isFrameworkAssembly(file);
}

async function mainExe(context) {
  const exes = [];
  for (const file of context.files) {
    if (file.ext !== '.exe' || !isAppAssembly(file)) continue;
    const pe = await parseCached(context, file);
    if (!pe.valid || !pe.isDotNet) continue;
    exes.push(file);
  }
  exes.sort(
    (a, b) =>
      a.displayPath.split('/').length - b.displayPath.split('/').length ||
      a.displayPath.localeCompare(b.displayPath),
  );
  return exes[0] || null;
}

function readableFinding(file, analysis) {
  return {
    id: 'dotnet.readable',
    severity: 'medium',
    file: file.displayPath,
    line: null,
    snippet: `most identifiers are readable words, so a decompiler shows near-source C# (${Math.round(
      analysis.readableRatio * 100,
    )}% of ${analysis.total})`,
    fix: 'obfuscate the release build (ConfuserEx/Obfuscar) and/or ship Native AOT where supported',
  };
}

function obfuscatedFinding(file, analysis) {
  return {
    id: 'dotnet.obfuscated',
    severity: 'info',
    file: file.displayPath,
    line: null,
    snippet: `names look obfuscated (${Math.round(
      analysis.obfuscatedRatio * 100,
    )}% of ${analysis.total} identifiers are 1-2 characters or non-words)`,
    fix: 'nothing to do; keep the rename/obfuscation pass in the release build',
  };
}

function sensitiveFinding(file, names) {
  const shown = names.slice(0, MAX_SENSITIVE_NAMES);
  const extra = names.length - shown.length;
  return {
    id: 'dotnet.sensitive_names',
    severity: 'medium',
    file: file.displayPath,
    line: null,
    snippet: `licensing/purchase identifiers live in client code (e.g. ${shown.join(', ')}${
      extra > 0 ? `, +${extra} more` : ''
    })`,
    fix: 'move license/activation decisions server-side; client checks only gate the UI',
  };
}

async function nameFindings(file, pe) {
  const analysis = analyzeNames(pe.dotnet?.strings || []);
  const findings = [];

  if (analysis.total >= MIN_IDENTIFIERS) {
    if (analysis.obfuscatedRatio >= OBFUSCATED_RATIO) {
      findings.push(obfuscatedFinding(file, analysis));
    } else if (analysis.readableRatio >= READABLE_RATIO) {
      findings.push(readableFinding(file, analysis));
    }
  }

  const sensitive = sensitiveNames(analysis.identifiers);
  if (sensitive.length) {
    findings.push(sensitiveFinding(file, sensitive));
  }
  return findings;
}

function pdbFindings(context, assemblies) {
  const pdbPaths = new Map();
  for (const file of context.files) {
    if (file.ext === '.pdb') pdbPaths.set(file.displayPath.toLowerCase(), file);
  }

  const matches = [];
  for (const { file } of assemblies) {
    const expected = file.displayPath.replace(/\.(?:exe|dll)$/i, '.pdb');
    const pdb = pdbPaths.get(expected.toLowerCase());
    if (pdb) matches.push(pdb);
  }

  const unique = [...new Map(matches.map((file) => [file.displayPath, file])).values()];
  if (!unique.length) return [];
  return [
    {
      id: 'dotnet.pdb_shipped',
      severity: 'medium',
      file: unique[0].displayPath,
      line: null,
      snippet: `${unique.length} PDB symbol file(s) ship next to app assemblies (e.g. ${
        unique[0].basename
      })`,
      fix: 'publish without symbols (DebugType none) and delete *.pdb from the installer',
    },
  ];
}

function appsettingsFindings(context) {
  const file = context.files
    .toArray()
    .find(
      (candidate) =>
        !candidate.inNodeModules &&
        candidate.basename.toLowerCase() === 'appsettings.development.json',
    );
  if (!file) return [];
  return [
    {
      id: 'dotnet.appsettings_shipped',
      severity: 'info',
      file: file.displayPath,
      line: null,
      snippet: 'appsettings.Development.json ships with the build',
      fix: 'exclude Development settings from publish/installer and keep secrets out of appsettings',
    },
  ];
}

async function unsignedFinding(context) {
  const exe = await mainExe(context);
  if (!exe) return null;
  const pe = await parseCached(context, exe);
  if (!pe.valid || pe.hasCertificate) return null;
  return {
    id: 'dotnet.unsigned',
    severity: 'medium',
    file: exe.displayPath,
    line: null,
    snippet: `main executable has no Authenticode signature (${exe.basename})`,
    fix: 'sign the executable with a code-signing certificate (signtool sign)',
  };
}

/**
 * @param {object} context
 * @returns {Promise<Array<object>>}
 */
async function run(context) {
  const assemblies = [];
  for (const file of context.files) {
    if (!isManagedCandidate(file) || file.inNodeModules) continue;
    if (isSkippedPath(file.displayPath)) continue;
    if (!isAppAssembly(file)) continue;
    const pe = await parseCached(context, file);
    if (!pe.valid || !pe.isDotNet) continue;
    assemblies.push({ file, pe });
  }

  const findings = [];
  for (const { file, pe } of assemblies) {
    findings.push(...(await nameFindings(file, pe)));
  }

  const unsigned = await unsignedFinding(context);
  if (unsigned) findings.push(unsigned);
  findings.push(...pdbFindings(context, assemblies));
  findings.push(...appsettingsFindings(context));

  return findings;
}

/**
 * @param {object} context
 * @returns {Promise<boolean>}
 */
async function detect(context) {
  for (const file of context.files) {
    if (!isManagedCandidate(file) || file.inNodeModules) continue;
    if (isSkippedPath(file.displayPath)) continue;
    // Avoid reading unrelated .dll/.exe files in mixed native folders.
    if (!(await hasMzSignature(context, file))) continue;
    const pe = await parseCached(context, file);
    if (pe.valid && pe.isDotNet) return true;
  }
  return false;
}

const explain = {
  'dotnet.*': {
    title: '.NET client exposure',
    what: 'The shipped build contains managed .NET assemblies and some of them still carry readable code, licensing names, debug symbols or no signature.',
    how_attackers_find_it:
      'Open the assemblies in ILSpy, dnSpy or dotPeek; the metadata turns back into near-source C# (REA decompile step).',
    risk: 'Business rules, license checks and API details become cheap to read and patch.',
    fix: 'Obfuscate the release assemblies, drop debug symbols, sign the executable and keep valuable decisions on your server.',
  },
  'dotnet.readable': {
    title: 'Readable managed assembly',
    what: 'Most identifiers in an application assembly are ordinary words, so decompilers reconstruct classes and method bodies close to the original C#.',
    how_attackers_find_it:
      'Load the assembly in ILSpy/dnSpy/dotPeek and browse the names; an AI agent can follow the code from the identifiers alone (REA decompile step).',
    risk: 'The attacker reads business logic, endpoints and client-side checks, then edits or reuses them.',
    fix: 'Obfuscate the release build (ConfuserEx or Obfuscar) and/or use Native AOT where the app supports it. This slows readers down; it does not make the client secret.',
  },
  'dotnet.obfuscated': {
    title: 'Obfuscated identifiers',
    what: 'Most metadata identifiers are one or two characters or not word-shaped, which is what a rename pass leaves behind.',
    how_attackers_find_it:
      'Decompile anyway and follow call sites and string literals; renaming raises the cost but does not remove the code (REA decompile step).',
    risk: 'Reading takes longer, but the assembly is still decompilable and patchable.',
    fix: 'No action needed for the scan; keep the rename pass and never ship the symbol map.',
  },
  'dotnet.sensitive_names': {
    title: 'Licensing logic in the client',
    what: 'Identifiers such as license, serial, activation, trial, premium, unlock, purchase, apikey or secret appear in the assembly.',
    how_attackers_find_it:
      'Search the decompiled assembly for these names, follow the method, then patch the branch or feed it a generated key (REA decompile + patch step).',
    risk: 'A client-side license or purchase check can be bypassed on the attacker\'s machine.',
    fix: 'Move license, activation and purchase decisions server-side; the client should only display the result.',
  },
  'dotnet.pdb_shipped': {
    title: 'PDB symbols shipped',
    what: 'A .pdb file with debug symbols sits next to an application assembly.',
    how_attackers_find_it:
      'A decompiler or debugger loads the PDB and restores source file names, line numbers and local names (REA debug-symbol step).',
    risk: 'Symbols turn a slow read into a guided tour of the source.',
    fix: 'Publish with DebugType none (or embedded is still symbols: prefer none) and remove *.pdb from the installer.',
  },
  'dotnet.unsigned': {
    title: 'Unsigned executable',
    what: 'The main .NET executable has no Authenticode signature, so Windows cannot attribute it to a publisher.',
    how_attackers_find_it:
      'Check the file signature (or replace the exe in a local install); there is no publisher check to break (REA shipping step).',
    risk: 'Modified builds spread under your app name, and SmartScreen/antivirus trust is lower.',
    fix: 'Sign the executable (and installer) with a code-signing certificate, using signtool and a timestamp server.',
  },
  'dotnet.appsettings_shipped': {
    title: 'Development settings shipped',
    what: 'appsettings.Development.json is included in the build, although it is meant for local development.',
    how_attackers_find_it:
      'Open the file next to the executable and read endpoints, feature flags or keys (the generic surface also scans text files for secrets).',
    risk: 'Development endpoints, toggles or credentials leak into production builds.',
    fix: 'Exclude Development settings from publish/installer; keep production configuration in environment variables or a secret store.',
  },
};

function releasePlan() {
  return [
    'Fix plan: dotnet (release build)',
    '',
    '1. Publish in Release configuration:',
    '```bash',
    'dotnet publish -c Release -r win-x64 --self-contained',
    '```',
    '2. Turn debug symbols off in the project file:',
    '```xml',
    '<PropertyGroup>',
    '  <DebugType>none</DebugType>',
    '  <DebugSymbols>false</DebugSymbols>',
    '</PropertyGroup>',
    '```',
    '3. Add an obfuscation step after publish (ConfuserEx2 or Obfuscar) and keep the map file out of the installer.',
    '4. Sign the final executable and installer (signtool with a timestamp server, or Azure Trusted Signing).',
    '5. Remove appsettings.Development.json from the publish output and rescan the build with unrea.',
    '',
    'Honest note: obfuscation and Native AOT raise the reading cost; a determined attacker still reads the client. Keep licensing and purchases server-side.',
  ].join('\n');
}

function readablePlan() {
  return [
    'Fix plan: dotnet.readable',
    '',
    '1. Always publish with `dotnet publish -c Release`.',
    '2. Add an obfuscator to the release pipeline:',
    '- ConfuserEx2: create a `.crproj`, then run `Confuser.CLI.exe MyApp.crproj` (use the `rename` and `ctrl flow` protections).',
    '- Obfuscar: add `Obfuscar` as a build tool, configure `obfuscar.xml`, then run `Obfuscar.Console.exe obfuscar.xml`.',
    '3. If the app has no reflection-heavy dependencies, evaluate Native AOT (`<PublishAot>true</PublishAot>`); check that your libraries support it first.',
    '4. Rebuild, rescan with unrea and confirm the finding is gone.',
    '',
    'Honest note: this slows a reverse engineer (and an AI agent) down; it does not make the client secret. Move license and purchase decisions to your server.',
  ].join('\n');
}

function obfuscatedPlan() {
  return [
    'Fix plan: dotnet.obfuscated',
    '',
    'No action is needed for this finding: the assembly already looks obfuscated.',
    'Keep the rename pass in the release pipeline and make sure the symbol/map file is never copied to the publish folder or installer.',
    'Remember that obfuscation only slows reading: licensing and purchase checks still belong on the server.',
  ].join('\n');
}

function sensitivePlan() {
  return [
    'Fix plan: dotnet.sensitive_names',
    '',
    '1. Move license validation, activation and purchase verification to your server.',
    '2. Let the client only display the signed-in user\'s entitlement; never accept a client-generated license flag.',
    '3. If an offline mode is required, verify a server-signed license file or receipt instead of a local boolean.',
    '4. Rebuild, rescan, and check that the identifiers are no longer reachable from shipped code paths.',
    '',
    'Honest note: renaming these identifiers hides the names but does not fix a client-side trust decision.',
  ].join('\n');
}

function pdbPlan() {
  return [
    'Fix plan: dotnet.pdb_shipped',
    '',
    '1. In the project file:',
    '```xml',
    '<PropertyGroup>',
    '  <DebugType>none</DebugType>',
    '  <DebugSymbols>false</DebugSymbols>',
    '</PropertyGroup>',
    '```',
    '2. Or override it on the command line:',
    '```bash',
    'dotnet publish -c Release -p:DebugType=None -p:DebugSymbols=false',
    '```',
    '3. Delete `*.pdb` from the publish output and from the installer package.',
    '4. Keep the symbols in your private symbol server instead of the shipped build.',
    '',
    'Note: `<DebugType>embedded</DebugType>` also ships the symbols inside the assembly, so use `none` for release.',
  ].join('\n');
}

function unsignedPlan() {
  return [
    'Fix plan: dotnet.unsigned',
    '',
    '1. Get a code-signing certificate (OV/EV or Azure Trusted Signing).',
    '2. Sign the executable after obfuscation and before packaging:',
    '```bat',
    'signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a MyApp.exe',
    '```',
    '3. Sign the installer as well, then verify:',
    '```bat',
    'signtool verify /pa /v MyApp.exe',
    '```',
    '4. Rebuild the installer so the signed files are the ones that ship.',
    '',
    'Honest note: signing proves who published the file; it does not stop patching, so keep license checks server-side.',
  ].join('\n');
}

function appsettingsPlan() {
  return [
    'Fix plan: dotnet.appsettings_shipped',
    '',
    '1. Keep `appsettings.json` for defaults and use environment variables or a secret store for production values.',
    '2. Exclude the Development file from publish and installer output:',
    '```xml',
    '<ItemGroup>',
    '  <Content Update="appsettings.Development.json" CopyToPublishDirectory="Never" />',
    '</ItemGroup>',
    '```',
    '3. If the file must ship for local runs, keep it out of the release package and never put credentials in it.',
    '4. Rebuild and rescan; the generic text scan should no longer see the file.',
  ].join('\n');
}

const fixPlan = {
  'dotnet.*': () => releasePlan(),
  'dotnet.readable': () => readablePlan(),
  'dotnet.obfuscated': () => obfuscatedPlan(),
  'dotnet.sensitive_names': () => sensitivePlan(),
  'dotnet.pdb_shipped': () => pdbPlan(),
  'dotnet.unsigned': () => unsignedPlan(),
  'dotnet.appsettings_shipped': () => appsettingsPlan(),
};

export default {
  id: 'dotnet',
  title: '.NET desktop (WinForms / WPF / console / MAUI)',
  covers: [
    'managed assemblies',
    '.NET metadata names',
    'PDB symbols',
    'Authenticode signature',
    'appsettings',
  ],
  detect,
  run,
  explain,
  fixPlan,
};
