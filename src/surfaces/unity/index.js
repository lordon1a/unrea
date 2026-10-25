import { readPE } from '../../parse/pe.js';
import { collectUnityRoots, engineInfo } from './layout.js';
import { analyzeNames, sensitiveNames } from './names.js';

const IL2CPP_METADATA_MAGIC = [0xaf, 0x1b, 0xb1, 0xfa]; // 0xFAB11BAF little-endian
const MAX_AUTHORITY_NAMES = 15;

// Paths inside a Unity player that this surface explains better than the generic/native ones.
// The game's own exe stays unowned, so signing/ASLR findings on it still come from pe-native.
const ENGINE_FILE = /^(UnityPlayer\.dll|UnityCrashHandler(32|64)?\.exe|baselib\.dll|GameAssembly\.dll|dstorage(core)?\.dll)$/i;
const ENGINE_DIR = /^(MonoBleedingEdge|D3D12)\//i;

function ownedPrefixes(context) {
  if (!context.__unityOwned) {
    context.__unityOwned = collectUnityRoots(context).map((root) => ({
      playerRoot: root.playerRoot || '',
      dataDir: root.dataDir,
    }));
  }
  return context.__unityOwned;
}

function owns(file, context) {
  const displayPath = file.displayPath || '';
  for (const { playerRoot, dataDir } of ownedPrefixes(context)) {
    // StreamingAssets is the developer's own content: generic text checks (keys, endpoints) must still run there.
    if (displayPath.startsWith(`${dataDir}StreamingAssets/`)) return false;
    if (displayPath.startsWith(dataDir)) return true;
    if (!displayPath.startsWith(playerRoot)) continue;
    const rest = displayPath.slice(playerRoot.length);
    if (ENGINE_DIR.test(rest) || ENGINE_FILE.test(rest)) return true;
    if (/_BurstDebugInformation_DoNotShip\//i.test(rest)) return true;
    // The player exe is Unity's prebuilt stub: its PDB path is Unity's build machine, not the developer's.
    const gameName = dataDir.slice(playerRoot.length).replace(/_Data\/$/, '');
    if (rest.toLowerCase() === `${gameName}.exe`.toLowerCase()) return true;
  }
  return false;
}

const explain = {
  'unity.*': {
    title: 'Unity client exposure',
    what: 'The build is a Unity player and some of its runtime assets still carry readable code, names or debug data.',
    how_attackers_find_it:
      'Unpack the player folder, then hand Assembly-CSharp.dll or global-metadata.dat to ILSpy/dnSpy/Il2CppDumper (REA decompile step).',
    risk: 'Game logic, balance values and client-side checks become cheap to read and copy.',
    fix: 'Ship IL2CPP with high stripping, obfuscate your own assemblies, remove debug data, and keep economy/score authority on the server.',
  },
  'unity.mono': {
    title: 'Mono scripting backend',
    what: 'Assembly-CSharp.dll is a normal managed assembly that ships with the build.',
    how_attackers_find_it:
      'Open _Data/Managed/Assembly-CSharp.dll in ILSpy or dnSpy and decompile it back to near-source C# (REA decompile step).',
    risk:
      'An attacker (or an AI agent) reads your classes, method bodies, balance constants and client-side checks, then patches them.',
    fix: 'Build with IL2CPP (Player Settings > Scripting Backend) and raise Managed Stripping Level.',
  },
  'unity.il2cpp.metadata': {
    title: 'Unencrypted IL2CPP metadata',
    what: 'global-metadata.dat starts with the stock IL2CPP magic bytes, so the metadata table is not encrypted.',
    how_attackers_find_it:
      'Point Il2CppDumper at the player binary plus global-metadata.dat; it recovers every class, method and field name (REA decompile step).',
    risk:
      'IL2CPP hides the C# bodies, but readable metadata still hands over your class structure and most method names.',
    fix: 'Encrypt or obfuscate global-metadata.dat with a commercial protector and strip names before shipping.',
  },
  'unity.debug_shipped': {
    title: 'Debug symbols shipped',
    what: 'A Burst debug folder, .pdb files or Mono .mdb files were copied into the build.',
    how_attackers_find_it:
      'List the player folder, open the *_BurstDebugInformation_DoNotShip folder or load the .pdb/.mdb next to the assemblies in a debugger (REA debug-symbol step).',
    risk:
      'Symbols restore function names and source line numbers, which turns a slow read into a guided tour.',
    fix: 'Delete debug data before shipping (Unity names the folder DoNotShip for a reason).',
  },
  'unity.names': {
    title: 'Readable symbol names',
    what: 'Most identifiers in Assembly-CSharp.dll look like ordinary Camel/Pascal words instead of obfuscated names.',
    how_attackers_find_it:
      'Decompile Assembly-CSharp.dll and read the class, field and method names; an AI agent can navigate the game from the names alone (REA decompile step).',
    risk:
      'Names leak the design: Gold, PurchaseLimit, IsLicensed and similar identifiers point straight at the valuable logic.',
    fix: 'Rename/obfuscate symbols in a release pass (IL2CPP plus a commercial obfuscator); this slows readers, it does not stop them.',
  },
  'unity.client_authority': {
    title: 'Game-critical state in client code',
    what: 'Identifiers for economy, progress, health, licensing or debug controls are present in the client assembly.',
    how_attackers_find_it:
      'Grep the decompiled assembly for the names, follow the method that owns them, then edit the value or call it directly (REA decompile + patch step).',
    risk:
      'If the server trusts these values, an attacker can grant currency, unlock items, raise scores or enable admin/debug paths.',
    fix: 'Keep economy, score and unlocks server-authoritative; for offline games expect edits and protect saves/IAP receipts with server validation.',
  },
  'unity.saves': {
    title: 'Local saves are outside the build',
    what: 'PlayerPrefs and local save files are written at runtime, so the build scan cannot inspect their integrity.',
    how_attackers_find_it:
      'Read or edit the save location on a machine that ran the game (Windows registry HKCU\\Software\\<Company>\\<Product>, or the platform save folder).',
    risk: 'A client-side save is editable; purchase flags and currency stored there are free to forge.',
    fix: 'Never trust PlayerPrefs/local saves for purchases; validate economy and receipts on the server.',
  },
  'unity.plugins': {
    title: 'Native plugin DLLs',
    what: 'Third-party or native plugin DLLs ship inside _Data/Plugins.',
    how_attackers_find_it:
      'List _Data/Plugins, then run strings/objdump or a .NET decompiler over each DLL (REA inspect step).',
    risk:
      'Plugins add native attack surface and often carry vendor names, endpoints, PDB paths or embedded keys.',
    fix: 'Ship only the plugins you need, strip their symbols, and keep their secrets server-side.',
  },
};

function metadataFinding(file, snippet, fix) {
  return {
    id: 'unity.il2cpp.metadata',
    severity: 'medium',
    file: file.displayPath,
    line: null,
    snippet,
    fix,
  };
}

async function il2cppFindings(context, root) {
  const file = root.il2cppMetadata;
  if (!file) return [];
  let magic;
  try {
    magic = await context.readBytes(file.absPath, 0, 4);
  } catch {
    return [];
  }
  const unencrypted =
    magic.length === 4 && IL2CPP_METADATA_MAGIC.every((byte, index) => magic[index] === byte);
  if (!unencrypted) return [];
  return [
    metadataFinding(
      file,
      'Il2CppDumper recovers every class and method name from this file',
      'encrypt/obfuscate metadata (commercial obfuscator) and strip names',
    ),
  ];
}

async function nameFindings(root) {
  const assembly = root.assemblyCSharp;
  if (!assembly) return [];

  let pe;
  try {
    pe = await readPE(assembly.absPath);
  } catch {
    return [];
  }
  if (!pe.valid || !pe.isDotNet) return [];

  const { identifiers, total, ratio } = analyzeNames(pe.dotnet?.strings || []);
  if (total === 0) return [];

  const findings = [];
  if (ratio > 0.6) {
    findings.push({
      id: 'unity.names',
      severity: 'medium',
      file: assembly.displayPath,
      line: null,
      snippet: `names are readable: the attacker's agent reads your game like docs (${Math.round(
        ratio * 100,
      )}% of ${total} identifiers look like words)`,
      fix: 'rename/obfuscate symbols in a release pass (IL2CPP plus a commercial obfuscator)',
    });
  }

  const sensitive = sensitiveNames(identifiers);
  if (sensitive.length) {
    const shown = sensitive.slice(0, MAX_AUTHORITY_NAMES);
    const extra = sensitive.length - shown.length;
    findings.push({
      id: 'unity.client_authority',
      severity: 'medium',
      file: assembly.displayPath,
      line: null,
      snippet: `game-critical state lives in client code (e.g. ${shown.join(', ')}${
        extra > 0 ? `, +${extra} more` : ''
      })`,
      fix: 'for online games keep economy/score/unlocks server-authoritative; offline: expect it to be edited, protect what matters (saves, IAP receipts) with server validation',
    });
  }
  return findings;
}

function debugFindings({ burstDirs, pdbs, mdbs }) {
  const fix = 'delete before shipping (Unity names it DoNotShip)';
  const findings = [];

  if (burstDirs.length) {
    findings.push({
      id: 'unity.debug_shipped',
      severity: 'high',
      file: burstDirs[0],
      line: null,
      snippet: `Burst debug information folder shipped (${burstDirs.length}): ${burstDirs[0]}${
        burstDirs.length > 1 ? ` (+${burstDirs.length - 1} more)` : ''
      }`,
      fix,
    });
  }
  if (pdbs.length) {
    findings.push({
      id: 'unity.debug_shipped',
      severity: 'high',
      file: pdbs[0].displayPath,
      line: null,
      snippet: `${pdbs.length} PDB debug symbol file(s) shipped (e.g. ${pdbs[0].displayPath})`,
      fix,
    });
  }
  if (mdbs.length) {
    findings.push({
      id: 'unity.debug_shipped',
      severity: 'high',
      file: mdbs[0].displayPath,
      line: null,
      snippet: `${mdbs.length} Mono debug symbol file(s) shipped (e.g. ${mdbs[0].displayPath})`,
      fix,
    });
  }
  return findings;
}

function pluginFinding(plugins) {
  if (!plugins.length) return null;
  const names = plugins.slice(0, 3).map((file) => file.basename);
  return {
    id: 'unity.plugins',
    severity: 'info',
    file: plugins[0].displayPath,
    line: null,
    snippet: `${plugins.length} native plugin DLL(s) in _Data/Plugins (e.g. ${names.join(', ')}${
      plugins.length > names.length ? ', ...' : ''
    })`,
    fix: 'review each plugin for embedded secrets/symbols and ship only the ones you need',
  };
}

function savesFinding(root, context) {
  const candidates = [
    `${root.dataDir}globalgamemanagers`,
    root.assemblyCSharp?.displayPath,
    root.managed[0]?.displayPath,
    root.plugins[0]?.displayPath,
  ];
  const file = candidates.find((candidate) => candidate && context.fileByPath.has(candidate));
  return {
    id: 'unity.saves',
    severity: 'info',
    file: file || root.dataDir.replace(/\/$/, ''),
    line: null,
    snippet:
      'PlayerPrefs and local saves are written outside the build (Windows: HKCU\\Software\\<Company>\\<Product>), so their integrity cannot be checked here',
    fix: 'never trust PlayerPrefs/local saves for purchases; validate economy and IAP receipts on the server',
  };
}

/**
 * @param {object} context
 * @returns {Promise<Array<object>>}
 */
async function run(context) {
  const roots = collectUnityRoots(context);
  const findings = [];
  const pdbs = [];
  const mdbs = [];
  const burstDirs = [];
  const plugins = [];

  for (const root of roots) {
    if (root.assemblyCSharp) {
      findings.push({
        id: 'unity.mono',
        severity: 'high',
        file: root.assemblyCSharp.displayPath,
        line: null,
        snippet:
          'Mono build: ILSpy/dnSpy turn Assembly-CSharp.dll back into near-source C# in seconds',
        fix: 'build with IL2CPP (Player Settings > Scripting Backend)',
      });
      findings.push(...(await nameFindings(root)));
    }

    findings.push(...(await il2cppFindings(context, root)));

    pdbs.push(...root.pdbs);
    mdbs.push(...root.mdbs);
    burstDirs.push(...root.burstDirs);
    plugins.push(...root.plugins);
  }

  const uniquePdbs = [...new Map(pdbs.map((file) => [file.displayPath, file])).values()];
  const uniqueMdbs = [...new Map(mdbs.map((file) => [file.displayPath, file])).values()];
  findings.push(
    ...debugFindings({
      burstDirs: [...new Set(burstDirs)].sort(),
      pdbs: uniquePdbs,
      mdbs: uniqueMdbs,
    }),
  );

  const pluginsFinding = pluginFinding(plugins);
  if (pluginsFinding) findings.push(pluginsFinding);

  if (roots.length) {
    findings.push(savesFinding(roots[0], context));
  }

  return findings;
}

function detect(context) {
  // Cheap path checks only; collectUnityRoots() does the exact grouping in run.
  if (
    context.has('**/*_Data/globalgamemanagers') ||
    context.has('**/*.app/Contents/Resources/Data/globalgamemanagers') ||
    context.has('**/*_Data/data.unity3d') ||
    context.has('**/*_Data/Managed/*.dll') ||
    context.has('**/*_Data/il2cpp_data/**')
  ) {
    return true;
  }

  // Fallback for a stripped player folder: UnityPlayer.dll next to <Name>_Data.
  if (context.has('**/UnityPlayer.dll') && context.has('**/*_Data/*')) return true;

  // Linux: an extensionless player binary next to a root-level <Name>_Data/.
  const extensionlessRootBinary = context.rootFiles.some(
    (name) => Boolean(name) && !name.includes('.'),
  );
  return extensionlessRootBinary && context.has('*_Data/*');
}

function monoPlan() {
  return [
    'Fix plan: unity.mono',
    '',
    '1. Open the Unity project and go to Edit > Project Settings > Player > Other Settings.',
    '2. Set Scripting Backend to IL2CPP for every target platform you ship.',
    '3. Set Managed Stripping Level to High (and enable Strip Engine Code).',
    '4. Optionally add a commercial obfuscator/rename pass for your own assemblies; IL2CPP raises the cost, it does not make the client secret.',
    '5. Rebuild and rescan the player folder with unrea.',
    '',
    'ProjectSettings.asset hint (YAML, 0 = Mono2x, 1 = IL2CPP):',
    '```yaml',
    'PlayerSettings:',
    '  scriptingBackend:',
    '    Standalone: 1',
    '```',
    '',
    'Honest note: IL2CPP removes the easy dnSpy/ILSpy path and inline C# bodies; a determined attacker still reads metadata and patches native code.',
  ].join('\n');
}

function il2cppPlan() {
  return [
    'Fix plan: unity.il2cpp.metadata',
    '',
    '1. Keep IL2CPP, but add a protector that encrypts global-metadata.dat and the generated C++ (for example a commercial Unity obfuscator with runtime support).',
    '2. Strip names: enable il2cpp name stripping/obfuscation in the protector, and rename your own fields/methods before the build.',
    '3. Do not rely on encryption alone; keep prices, rewards, unlocks and score rules on the server.',
    '4. Rebuild and rescan; unrea only flags the stock magic bytes, so the check should disappear once the file is encrypted.',
  ].join('\n');
}

function debugPlan() {
  return [
    'Fix plan: unity.debug_shipped',
    '',
    'Unity writes the Burst debug folder on purpose; it must be removed from the shipped build.',
    '1. Add an editor post-build script (Assets/Editor/StripDebugSymbols.cs):',
    '```csharp',
    'using System.IO;',
    'using UnityEditor.Build;',
    'using UnityEditor.Build.Reporting;',
    '',
    'public sealed class StripDebugSymbols : IPostprocessBuildWithReport',
    '{',
    '    public int callbackOrder => 0;',
    '',
    '    public void OnPostprocessBuild(BuildReport report)',
    '    {',
    '        var root = Path.GetDirectoryName(report.summary.outputPath);',
    '        if (string.IsNullOrEmpty(root)) return;',
    '',
    '        foreach (var dir in Directory.GetDirectories(root, "*_BurstDebugInformation_DoNotShip", SearchOption.AllDirectories))',
    '            Directory.Delete(dir, true);',
    '',
    '        foreach (var file in Directory.GetFiles(root, "*.pdb", SearchOption.AllDirectories))',
    '            File.Delete(file);',
    '        foreach (var file in Directory.GetFiles(root, "*.mdb", SearchOption.AllDirectories))',
    '            File.Delete(file);',
    '    }',
    '}',
    '```',
    '2. If you build from CI, delete the same patterns after the player build as a second guard.',
    '3. Rebuild, rescan, and confirm unity.debug_shipped is gone.',
  ].join('\n');
}

function namesPlan(id) {
  return [
    `Fix plan: ${id}`,
    '',
    'Readable names are a navigation aid, not a secret leak by themselves; lower their value:',
    '1. Switch to IL2CPP with Managed Stripping Level High (see the unity.mono plan).',
    '2. Run a rename/obfuscation pass over your own assemblies in the release build (commercial Unity obfuscators or an IL renamer).',
    '3. Move economy, score, unlock and licensing decisions to the server so the names point at code that cannot change the outcome.',
    '',
    'Honest note: obfuscation slows a reader and an AI agent; it does not make client logic trustworthy.',
  ].join('\n');
}

function authorityPlan() {
  return [
    'Fix plan: unity.client_authority',
    '',
    'The finding lists identifiers that usually own game-critical state. Treat every one as untrusted input:',
    '1. List the matched names from the finding and find their callers in the decompiled/own source.',
    '2. Move the authoritative value to the server: currency balance, score, unlocks, health/damage for online play.',
    '3. Let the client send intents ("buy item", "submit score"), validate them server-side, then send back the new state.',
    '4. For offline games, stop treating saves/PlayerPrefs as proof: sign or encrypt saves and validate IAP receipts server-side.',
    '5. Add a server-side cap/audit for currency and score changes so a patched client cannot mass-grant values.',
  ].join('\n');
}

function savesPlan() {
  return [
    'Fix plan: unity.saves',
    '',
    '1. Do not store purchase state, currency or unlocks only in PlayerPrefs or a local save file.',
    '2. Validate IAP receipts on your server and store the entitlement there.',
    '3. If a local cache is needed, treat it as a hint: re-fetch the authoritative state on login.',
    '4. For offline saves, sign or encrypt the save and detect rollback/tampering; accept that a single-player save is editable.',
    '',
    'Windows PlayerPrefs live in HKCU\\Software\\<Company>\\<Product>; macOS in ~/Library/Preferences/unity.<Company>.<Product>.plist.',
  ].join('\n');
}

function pluginsPlan() {
  return [
    'Fix plan: unity.plugins',
    '',
    '1. List the DLLs under _Data/Plugins and remove anything unused (audio/VR/analytics SDKs are common leftovers).',
    '2. Check each remaining DLL for embedded secrets, endpoints and PDB paths (strings/objdump or a .NET decompiler).',
    '3. Strip native symbols and ship release builds of the plugins.',
    '4. Keep plugin credentials on the server; a key inside a plugin is a key inside the client.',
  ].join('\n');
}

const fixPlan = {
  'unity.mono': () => monoPlan(),
  'unity.il2cpp.metadata': () => il2cppPlan(),
  'unity.debug_shipped': () => debugPlan(),
  'unity.names': () => namesPlan('unity.names'),
  'unity.client_authority': () => authorityPlan(),
  'unity.saves': () => savesPlan(),
  'unity.plugins': () => pluginsPlan(),
};

export default {
  id: 'unity',
  title: 'Unity player',
  covers: [
    'Mono/IL2CPP backend',
    'managed assemblies and names',
    'IL2CPP metadata',
    'Burst/PDB debug data',
    'native plugins',
  ],
  detect,
  run,
  owns,
  // Findings other surfaces may still report on files Unity owns (signing/hardening is the developer's call).
  sharedIds: ['pe-native.unsigned', 'pe-native.no_aslr', 'pe-native.no_dep', 'pe-native.no_cfg'],
  info: engineInfo,
  explain,
  fixPlan,
};

export { engineInfo };
