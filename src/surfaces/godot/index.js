import { clip, mask } from '../../core/mask.js';

const KEY_NAME = 'SCRIPT_AES256_ENCRYPTION_KEY';
// A committed key is 64 hex characters assigned to the documented env var.
const KEY_PATTERN = /SCRIPT_AES256_ENCRYPTION_KEY\s*[=:]\s*["']?([0-9a-fA-F]{64})(?![0-9a-fA-F])/g;
const MAX_OTHER_READ = 1024 * 1024;
const BUILD_EXTS = new Set(['.exe', '.pck']);
const TEXT_SCRIPT_MODES = new Set(['0', 'text']);

function dirOf(displayPath) {
  const index = displayPath.lastIndexOf('/');
  return index === -1 ? '' : displayPath.slice(0, index);
}

/**
 * Is the display path inside (or equal to) the build folder? The scan root
 * itself is '' and contains everything.
 */
function isInside(displayPath, dir) {
  if (!dir) return true;
  return displayPath === dir || displayPath.startsWith(`${dir}/`);
}

function hasDotGodotSegment(displayPath) {
  return displayPath.split('/').includes('.godot');
}

function unquote(raw) {
  const value = raw.trim();
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  return value;
}

/**
 * Godot's export_presets.cfg is an INI-like file:
 *   [preset.0]
 *   name="Windows Desktop"
 *   encrypt_pck=true
 *   [preset.0.options]
 *   script_export_mode=2
 *
 * @param {string} text
 * @returns {Array<{name:string,line:number,values:Map<string,{value:string,line:number}>}>}
 */
function parseGodotIni(text) {
  const sections = [];
  let current = null;
  const lines = text.split(/\r?\n/);

  for (let index = 0; index < lines.length; index++) {
    const line = lines[index].trim();
    if (!line || line.startsWith(';') || line.startsWith('#')) continue;

    const header = line.match(/^\[([^\]]+)\]$/);
    if (header) {
      current = { name: header[1].trim(), line: index + 1, values: new Map() };
      sections.push(current);
      continue;
    }

    if (!current) continue;
    const equals = line.indexOf('=');
    if (equals === -1) continue;
    const key = line.slice(0, equals).trim();
    if (!key) continue;
    current.values.set(key, {
      value: unquote(line.slice(equals + 1)),
      line: index + 1,
    });
  }

  return sections;
}

function presetValue(preset, options, key) {
  if (preset.values.has(key)) return preset.values.get(key);
  if (options && options.values.has(key)) return options.values.get(key);
  return null;
}

function isTrue(entry) {
  return Boolean(entry) && /^(true|1)$/i.test(entry.value.trim());
}

function isFalse(entry) {
  return Boolean(entry) && /^(false|0)$/i.test(entry.value.trim());
}

function presetFindings(file) {
  const findings = [];
  const sections = parseGodotIni(file.text || '');
  const presets = sections
    .map((section) => ({ section, match: section.name.match(/^preset\.(\d+)$/) }))
    .filter((entry) => entry.match)
    .sort((a, b) => Number(a.match[1]) - Number(b.match[1]));

  for (const { section } of presets) {
    const options = sections.find((candidate) => candidate.name === `${section.name}.options`);
    const label = presetValue(section, options, 'name')?.value || section.name;
    const encryptPck = presetValue(section, options, 'encrypt_pck');
    const encryptDirectory = presetValue(section, options, 'encrypt_directory');
    const scriptMode = presetValue(section, options, 'script_export_mode');
    const pckOn = isTrue(encryptPck);

    if (!pckOn) {
      const state = isFalse(encryptPck) ? 'encrypt_pck=false' : 'encrypt_pck is not set';
      findings.push({
        id: 'godot.encryption_off',
        severity: 'high',
        file: file.displayPath,
        line: encryptPck?.line ?? section.line,
        snippet: `preset "${label}" does not encrypt the exported PCK (${state})`,
        fix: 'enable "Encrypt Exported PCK" and "Encrypt Index" in that preset and rebuild export templates with an encryption key',
      });
    } else if (!isTrue(encryptDirectory)) {
      findings.push({
        id: 'godot.directory_unencrypted',
        severity: 'medium',
        file: file.displayPath,
        line: encryptDirectory?.line ?? section.line,
        snippet: `preset "${label}" encrypts the PCK but not the file index (encrypt_directory=false)`,
        fix: 'enable "Encrypt Index" in that preset so file names and the directory table are encrypted too',
      });
    }

    if (scriptMode && TEXT_SCRIPT_MODES.has(scriptMode.value.trim().toLowerCase())) {
      findings.push({
        id: 'godot.script_text',
        severity: 'medium',
        file: file.displayPath,
        line: scriptMode.line,
        snippet: `preset "${label}" exports scripts as text (script_export_mode=${scriptMode.value}), so GDScript ships readable`,
        fix: 'set "Script Export Mode" to binary tokens or compressed binary tokens',
      });
    }
  }

  return findings;
}

function lineAt(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === '\n') line += 1;
  }
  return line;
}

function configKind(file) {
  const basename = file.basename.toLowerCase();
  if (basename === 'export_presets.cfg') return 'preset';
  if (basename === 'project.godot') return 'project';
  if (file.ext === '.gd') return 'script';
  if (hasDotGodotSegment(file.displayPath)) return 'dotgodot';
  return null;
}

async function keyFindings(context) {
  const findings = [];

  for (const file of context.files) {
    if (file.inNodeModules || file.inVendor) continue;

    let text = null;
    if (file.kind === 'text') {
      text = file.text;
    } else if (file.basename.toLowerCase() === 'project.godot' && file.size <= MAX_OTHER_READ) {
      // project.godot is not in the walker's text extension list; read it here.
      const buffer = await context.readBytes(file.absPath, 0, MAX_OTHER_READ);
      text = buffer.toString('utf8');
    }
    if (!text) continue;

    for (const match of text.matchAll(KEY_PATTERN)) {
      findings.push({
        id: 'godot.key_in_repo',
        severity: 'critical',
        file: file.displayPath,
        line: lineAt(text, match.index),
        snippet: `${KEY_NAME} = ${mask(match[1])} is committed in this file`,
        fix: 'rotate the key, remove it from the repo and git history, and keep it only in the CI secret store / build environment',
      });
    }
  }

  return findings;
}

function detect(context) {
  return (
    context.has('**/*.pck') ||
    context.has('**/project.godot') ||
    context.has('**/export_presets.cfg')
  );
}

async function run(context) {
  const findings = [];

  // Build folders: any folder that ships an executable or a PCK.
  const buildDirs = new Map();
  for (const file of context.files) {
    if (file.inNodeModules || file.inVendor) continue;
    if (!BUILD_EXTS.has(file.ext)) continue;
    const dir = dirOf(file.displayPath);
    const entry = buildDirs.get(dir) || { exe: 0, pck: 0, pckExample: null };
    if (file.ext === '.pck') {
      entry.pck += 1;
      entry.pckExample = entry.pckExample || file.displayPath;
    } else {
      entry.exe += 1;
    }
    buildDirs.set(dir, entry);
  }

  // The most specific build folder that contains a path.
  const buildDirFor = (displayPath) => {
    let best = null;
    for (const dir of buildDirs.keys()) {
      if (!isInside(displayPath, dir)) continue;
      if (best === null || dir.length > best.length) best = dir;
    }
    return best;
  };

  const shipped = new Map();
  for (const file of context.files) {
    if (file.inNodeModules || file.inVendor) continue;
    const kind = configKind(file);
    if (!kind) continue;
    const dir = buildDirFor(file.displayPath);
    if (dir === null) continue;

    const entry = shipped.get(dir) || {
      preset: false,
      project: false,
      dotgodot: false,
      scripts: 0,
      example: file.displayPath,
    };
    if (kind === 'preset') entry.preset = true;
    if (kind === 'project') entry.project = true;
    if (kind === 'dotgodot') entry.dotgodot = true;
    if (kind === 'script') entry.scripts += 1;
    shipped.set(dir, entry);
  }

  for (const [dir, entry] of shipped) {
    const parts = [];
    if (entry.preset) parts.push('export_presets.cfg');
    if (entry.project) parts.push('project.godot');
    if (entry.dotgodot) parts.push('.godot/');
    if (entry.scripts) {
      parts.push(`${entry.scripts} *.gd source file${entry.scripts === 1 ? '' : 's'}`);
    }
    findings.push({
      id: 'godot.config_shipped',
      severity: 'high',
      file: dir || context.rootLabel,
      line: null,
      snippet: clip(`project config ships in the build folder: ${parts.join(', ')} (e.g. ${entry.example})`),
      fix: 'delete project-only files from the shipped folder and add them to the export exclude filters',
    });
  }

  for (const entry of buildDirs.values()) {
    if (!entry.pck) continue;
    findings.push({
      id: 'godot.encryption_unknown',
      severity: 'info',
      file: entry.pckExample,
      line: null,
      snippet:
        'PCK ships and unrea does not open PCK contents; run unrea on the project folder to verify encrypt_pck/encrypt_directory',
      fix: 'scan the Godot project folder (export_presets.cfg) to confirm PCK and index encryption are enabled',
    });
  }

  for (const file of context.files) {
    if (file.kind !== 'text') continue;
    if (file.inNodeModules || file.inVendor) continue;
    if (file.basename.toLowerCase() !== 'export_presets.cfg') continue;
    findings.push(...presetFindings(file));
  }

  findings.push(...(await keyFindings(context)));

  return findings;
}

const explain = {
  'godot.*': {
    title: 'Godot export protection',
    what: 'Godot exports are a PCK archive plus a template executable; encryption and script export mode are decided in the export preset.',
    how_attackers_find_it:
      'Read export_presets.cfg, then open or unpack the PCK with Godot/third-party tools and inspect the scripts (REA extraction step).',
    risk: 'An unencrypted PCK exposes scripts, scenes and asset paths, which makes logic and content copying cheap.',
    fix: 'Enable PCK/index encryption in every preset, export scripts as tokens, and keep project files out of the shipped folder.',
  },
  'godot.config_shipped': {
    title: 'Godot project config shipped',
    what: 'project.godot, export_presets.cfg, the .godot/ cache or GDScript sources sit in a folder that also contains an executable or PCK.',
    how_attackers_find_it:
      'List the distribution folder; the project file, preset file and readable .gd files are plain text next to the build.',
    risk: 'The attacker gets the full project layout, export settings, asset paths and readable source without touching the PCK.',
    fix: 'Remove project-only files from the shipped folder and add them to the export exclude filters.',
  },
  'godot.encryption_unknown': {
    title: 'PCK encryption not verified',
    what: 'The build ships a PCK but the scan target has no export_presets.cfg, so encryption settings cannot be read here.',
    how_attackers_find_it:
      'Open the PCK with Godot or a PCK tool; if it is unencrypted, scripts and assets are readable immediately.',
    risk: 'An unencrypted PCK gives away game logic and content; this check only says the setting was not verified.',
    fix: 'Run unrea on the Godot project folder and confirm encrypt_pck and encrypt_directory are on for every preset.',
  },
  'godot.encryption_off': {
    title: 'PCK encryption disabled',
    what: 'The export preset does not set encrypt_pck=true, so the exported PCK body is not encrypted.',
    how_attackers_find_it:
      'Open the shipped PCK with Godot or a PCK extractor and read the resources directly (REA extraction step).',
    risk: 'Scripts, scenes and asset paths are exposed; the game can be copied and its logic read.',
    fix: 'Enable "Encrypt Exported PCK" and "Encrypt Index" in the preset and build export templates with an encryption key.',
  },
  'godot.directory_unencrypted': {
    title: 'PCK index left unencrypted',
    what: 'encrypt_pck=true but encrypt_directory is false, so the PCK file index (paths and sizes) stays readable.',
    how_attackers_find_it:
      'Read the PCK directory table to list every packed path, then target the interesting scripts and assets.',
    risk: 'The attacker learns the full file layout and can carve out the exact resources worth extracting.',
    fix: 'Enable "Encrypt Index" in the preset; it is a separate option from "Encrypt Exported PCK".',
  },
  'godot.script_text': {
    title: 'Scripts exported as text',
    what: 'script_export_mode is text, so GDScript files are packed as readable source instead of binary tokens.',
    how_attackers_find_it:
      'Unpack or open the PCK and read the .gd files; no decompiler is needed when they are plain text.',
    risk: 'Complete game logic is readable and easy to copy or patch.',
    fix: 'Set "Script Export Mode" to binary tokens or compressed binary tokens and re-export.',
  },
  'godot.key_in_repo': {
    title: 'PCK encryption key committed',
    what: 'A 64-hex SCRIPT_AES256_ENCRYPTION_KEY value is stored in a project file, dotenv file or CI config.',
    how_attackers_find_it:
      'Read the repository or the shipped file and take the key, then use it to open the encrypted PCK.',
    risk: 'Anyone with the key can decrypt the PCK, so the encryption provides no protection.',
    fix: 'Rotate the key, purge it from git history, and keep it only in the CI secret store / build environment.',
  },
};

function presetPlan(id, projectPath) {
  const lines = [
    `# Fix plan: ${id}`,
    '',
    `Godot reads encryption settings from the export preset in ${projectPath}/export_presets.cfg.`,
    '',
    '1. Generate a key: `openssl rand -hex 32` (64 hex characters).',
    '2. Build export templates with that key (Godot docs, "Compiling with PCK encryption key"):',
    '   `scons platform=<platform> target=template_release script_encryption_key=<64-hex-key>`',
    '   or set the `SCRIPT_AES256_ENCRYPTION_KEY` environment variable before compiling the templates.',
    '3. In Godot open **Project > Export**, select the preset and open the **Resources** tab.',
    '4. Enable **"Encrypt Exported PCK"** and **"Encrypt Index"**.',
    '5. Keep the key in the CI secret store only; never commit it.',
    '6. Re-export, then rescan the output folder with unrea.',
    '',
    'Honest note: PCK encryption raises the bar, but the key is embedded in the export template',
    'binary, so a determined attacker can still recover it. Keep valuable logic (scoring,',
    'economy, drops) on a server for online games instead of trusting the client.',
  ];
  return lines.join('\n');
}

const fixPlan = {
  'godot.encryption_off': (projectPath) => presetPlan('godot.encryption_off', projectPath),
  'godot.directory_unencrypted': (projectPath) =>
    presetPlan('godot.directory_unencrypted', projectPath),
  'godot.config_shipped': (projectPath) =>
    [
      '# Fix plan: godot.config_shipped',
      '',
      `Project-only files are inside the build output in ${projectPath}.`,
      '',
      '1. In Godot open **Project > Export**, select the preset, open the **Resources** tab.',
      '2. Add project-only files to **"Filters to exclude files/folders from project"**:',
      '   `export_presets.cfg, project.godot, .godot/*`',
      '   Keep the `*.gd` files the PCK needs and export them as binary tokens instead of excluding them.',
      '3. Export into a clean output folder and delete `project.godot`, `export_presets.cfg`,',
      '   `.godot/` and any leftover `*.gd` copies from the folder you distribute.',
      '4. Rescan the distribution folder; godot.config_shipped must be gone.',
      '',
      'Docs: "Exporting projects" (Resources tab, exclude filters).',
    ].join('\n'),
  'godot.encryption_unknown': (projectPath) =>
    [
      '# Fix plan: godot.encryption_unknown',
      '',
      'unrea found a PCK but does not open PCK contents, so encryption was not verified here.',
      '',
      `1. Run unrea on the Godot project folder instead: \`unrea ${projectPath}\``,
      '2. Confirm every preset has "Encrypt Exported PCK" and "Encrypt Index" enabled',
      '   (see godot.encryption_off for the template build steps).',
      '3. Re-export and rescan the build folder.',
    ].join('\n'),
  'godot.script_text': (projectPath) =>
    [
      '# Fix plan: godot.script_text',
      '',
      `The preset in ${projectPath}/export_presets.cfg exports scripts as text.`,
      '',
      '1. Open **Project > Export** and select the preset.',
      '2. Set **"Script Export Mode"** to **Binary tokens** or **Compressed binary tokens**',
      '   (`script_export_mode=1` or `2` in export_presets.cfg).',
      '3. Re-export and check the PCK: `.gd` entries must no longer be readable text.',
      '',
      'Honest note: binary tokens slow down reading; they are not encryption.',
    ].join('\n'),
  'godot.key_in_repo': (projectPath) =>
    [
      '# Fix plan: godot.key_in_repo',
      '',
      `A 64-hex ${KEY_NAME} value is committed in ${projectPath}.`,
      '',
      '1. Treat the key as compromised: generate a new one (`openssl rand -hex 32`).',
      '2. Rebuild the export templates with the new key (Godot docs, "Compiling with PCK encryption key").',
      '3. Remove the value from the file and from git history (`git filter-repo` or BFG);',
      '   a plain delete keeps it in every old commit.',
      '4. Store it only in the CI secret store and inject it as `SCRIPT_AES256_ENCRYPTION_KEY`',
      '   when building templates and exporting.',
      '5. If the repo was public, assume the old PCK builds are decryptable and re-export them.',
    ].join('\n'),
};

export default {
  id: 'godot',
  title: 'Godot exports',
  covers: ['PCK builds', 'export_presets.cfg', 'Godot project files', 'PCK encryption key'],
  detect,
  run,
  explain,
  fixPlan,
};
