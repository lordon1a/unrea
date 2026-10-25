import path from 'node:path';

/**
 * PyInstaller surface: markers only. Nothing is unpacked, decompiled or
 * executed; every check is based on file names and directory layout.
 *
 * A "build root" is the folder a frozen app is shipped in:
 *   onedir:        <root>/_internal/base_library.zip (plus the exe at <root>)
 *   onefile/pyz:   <root>/*.pyz
 *   embedded:      <root>/python3XX.dll or libpython3.XX next to an exe
 */

const INTERNAL_DIR = '_internal';
const PY_DLL_PATTERNS = [
  /^python3(\d{1,2})\.dll$/, // python39.dll, python310.dll
  /^python3\.(\d{1,2})\.dll$/, // python3.11.dll (rare, embeddable builds)
  /^libpython(\d)\.(\d{1,2})\.(?:so|dylib)/, // libpython3.11.so.1.0
];

// Python end-of-life dates from python.org / PEP 619 / PEP 693. An installed
// runtime past its date no longer receives security patches.
const EOL = {
  '2.7': '2020-01-01',
  '3.0': '2009-06-27',
  '3.1': '2012-04-09',
  '3.2': '2016-02-20',
  '3.3': '2017-09-29',
  '3.4': '2019-03-18',
  '3.5': '2020-09-13',
  '3.6': '2021-12-23',
  '3.7': '2023-06-27',
  '3.8': '2024-10-07',
  '3.9': '2025-10-31',
  '3.10': '2026-10-31',
  '3.11': '2027-10-24',
  '3.12': '2028-10-31',
  '3.13': '2029-10-31',
  '3.14': '2030-10-31',
};

const THIRD_PARTY_SEGMENTS = new Set(['site-packages', 'dist-packages']);

function today() {
  return new Date().toISOString().slice(0, 10);
}

function dirOf(displayPath) {
  const index = displayPath.lastIndexOf('/');
  return index === -1 ? '' : displayPath.slice(0, index);
}

function joinDisplay(dir, name) {
  return dir ? `${dir}/${name}` : name;
}

function isInternalDir(displayPath) {
  const name = displayPath.slice(displayPath.lastIndexOf('/') + 1);
  return name.toLowerCase() === INTERNAL_DIR;
}

function isUnder(displayPath, dir) {
  if (!dir) return true;
  return displayPath === dir || displayPath.startsWith(`${dir}/`);
}

/**
 * Parse a bundled CPython runtime version from its library file name.
 *
 * @param {string} name
 * @returns {{major:number, minor:number, key:string}|null}
 */
function pythonVersionFromName(name) {
  const lower = name.toLowerCase();
  for (let index = 0; index < PY_DLL_PATTERNS.length; index++) {
    const match = lower.match(PY_DLL_PATTERNS[index]);
    if (!match) continue;
    const major = index === 2 ? Number(match[1]) : 3;
    const minor = Number(index === 2 ? match[2] : match[1]);
    if (!Number.isFinite(minor)) continue;
    return { major, minor, key: `${major}.${minor}` };
  }
  return null;
}

function newBuild(root) {
  return {
    root,
    internalDirs: new Set(),
    pyz: [],
    dlls: [],
    exes: [],
    reasons: [],
  };
}

/**
 * Locate build roots without reading file contents.
 *
 * @param {object} context
 * @returns {Map<string, object>} keyed by lowercased display root
 */
function collectBuilds(context) {
  const builds = new Map();
  const exeDirs = new Map();
  const dllDirs = new Map();

  const ensure = (root) => {
    const key = root.toLowerCase();
    let build = builds.get(key);
    if (!build) {
      build = newBuild(root);
      builds.set(key, build);
    }
    return build;
  };

  const push = (map, dir, value) => {
    const key = dir.toLowerCase();
    const list = map.get(key);
    if (list) list.push(value);
    else map.set(key, [value]);
  };

  for (const file of context.files) {
    const name = file.basename;
    const lower = name.toLowerCase();
    const dir = dirOf(file.displayPath);

    if (lower === 'base_library.zip' && isInternalDir(dir)) {
      const build = ensure(dirOf(dir));
      build.internalDirs.add(dir);
      build.reasons.push(`${dir}/base_library.zip`);
      continue;
    }

    if (file.ext === '.pyz') {
      const parent = dirOf(dir);
      const root = isInternalDir(dir) ? parent : dir;
      const build = ensure(root);
      build.pyz.push(file.displayPath);
      build.reasons.push(file.displayPath);
      continue;
    }

    if (file.ext === '.exe') {
      push(exeDirs, dir, file.displayPath);
      continue;
    }

    const version = pythonVersionFromName(name);
    if (version) {
      push(dllDirs, dir, { file: file.displayPath, version });
    }
  }

  // An executable alone proves nothing; attach exe names to known builds and
  // create a build only when a python DLL sits next to an exe.
  for (const [key, build] of builds) {
    build.exes = [...(exeDirs.get(key) || [])];
    build.dlls = [...(dllDirs.get(key) || [])];
    // onedir keeps the interpreter inside _internal/, not next to the exe.
    for (const internalDir of build.internalDirs) {
      build.dlls.push(...(dllDirs.get(internalDir.toLowerCase()) || []));
    }
  }
  for (const [key, dlls] of dllDirs) {
    const exes = exeDirs.get(key);
    if (!exes || !exes.length) continue;
    if (!builds.has(key)) {
      const build = newBuild(dirOf(exes[0]));
      build.exes = [...exes];
      build.dlls = [...dlls];
      builds.set(key, build);
    }
  }

  for (const build of builds.values()) {
    build.dlls.sort((a, b) => a.file.localeCompare(b.file));
    build.exes.sort((a, b) => a.localeCompare(b));
    build.pyz.sort((a, b) => a.localeCompare(b));
    build.internalDirs = [...build.internalDirs].sort();

    if (build.dlls.length && build.exes.length) {
      for (const dll of build.dlls) {
        build.reasons.push(`${dll.file} next to ${build.exes[0]}`);
      }
    }
    build.reasons = [...new Set(build.reasons)].sort();
  }

  return builds;
}

function hasPythonDllNextToExe(context) {
  const exeDirs = new Set();
  const dllDirs = new Set();
  for (const file of context.files) {
    if (file.ext === '.exe') exeDirs.add(dirOf(file.displayPath).toLowerCase());
    if (pythonVersionFromName(file.basename)) {
      dllDirs.add(dirOf(file.displayPath).toLowerCase());
    }
  }
  for (const dir of dllDirs) {
    if (exeDirs.has(dir)) return true;
  }
  return false;
}

function detect(context) {
  if (context.has(`**/${INTERNAL_DIR}/base_library.zip`)) return true;
  if (context.has('**/*.pyz')) return true;
  return hasPythonDllNextToExe(context);
}

function buildLabel(build) {
  if (build.exes.length) return build.exes[0];
  if (build.pyz.length) return build.pyz[0];
  if (build.internalDirs.length) return build.internalDirs[0];
  return build.root || '.';
}

function bytecodeFinding(build) {
  const detail = build.reasons.length ? build.reasons.join(', ') : buildLabel(build);
  return {
    id: 'pyinstaller.bytecode',
    severity: 'high',
    file: buildLabel(build),
    line: null,
    snippet: `PyInstaller build found (${detail}): bundled Python bytecode is recoverable with public tools`,
    fix: 'keep valuable logic and secrets server-side; compile client code with Nuitka or Cython instead of shipping PyInstaller bytecode',
  };
}

function pythonVersionFinding(build) {
  const dll = build.dlls.find((entry) => entry.version);
  if (!dll) return null;

  const { key } = dll.version;
  const eol = EOL[key];
  const expired = Boolean(eol) && eol < today();
  const state = expired
    ? `is past end of life (${eol}) and no longer receives security fixes`
    : eol
      ? `is supported (end of life ${eol})`
      : 'has no known end-of-life date in this scanner';

  return {
    id: 'pyinstaller.python_version',
    severity: expired ? 'medium' : 'info',
    file: dll.file,
    line: null,
    snippet: `bundled Python ${key} runtime (${path.basename(dll.file)}) ${state}`,
    fix: expired
      ? `rebuild the app with a supported Python release (${key} no longer gets security patches)`
      : 'keep the bundled Python runtime on a supported release and rebuild when its end-of-life date approaches',
  };
}

/**
 * Is this .py file part of an installed distribution rather than app code?
 * Inside `_internal` PyInstaller puts third-party packages in package folders
 * (a folder with `__init__.py`) or in site-packages. Loose modules and data
 * folders without `__init__.py` are app source.
 */
function isThirdPartyPy(displayPath, internalDir, lowerFileSet) {
  const inner = displayPath.slice(internalDir.length + 1);
  const segments = inner.split('/');
  if (segments.some((segment) => THIRD_PARTY_SEGMENTS.has(segment.toLowerCase()))) {
    return true;
  }
  if (segments.length < 2) return false;
  const packageInit = `${internalDir}/${segments[0]}/__init__.py`.toLowerCase();
  return lowerFileSet.has(packageInit);
}

function sourceFindings(context, build, lowerFileSet) {
  const findings = [];
  for (const internalDir of build.internalDirs) {
    for (const file of context.files) {
      if (file.ext !== '.py') continue;
      if (!isUnder(file.displayPath, internalDir) || file.displayPath === internalDir) {
        continue;
      }
      if (isThirdPartyPy(file.displayPath, internalDir, lowerFileSet)) continue;
      findings.push({
        id: 'pyinstaller.source_shipped',
        severity: 'medium',
        file: file.displayPath,
        line: null,
        snippet: 'application .py source file is shipped loose inside _internal',
        fix: 'remove it from datas/collect_data_files and rebuild; PyInstaller already bundles module code as bytecode',
      });
    }
  }
  return findings;
}

function specFindings(context, builds) {
  const roots = [...builds.values()];
  const findings = [];
  for (const file of context.files) {
    if (file.ext !== '.spec') continue;
    if (!roots.some((build) => isUnder(file.displayPath, build.root))) continue;
    findings.push({
      id: 'pyinstaller.spec_shipped',
      severity: 'medium',
      file: file.displayPath,
      line: null,
      snippet: 'PyInstaller .spec build recipe is shipped with the app',
      fix: 'ship only the executable and _internal; keep the .spec in the repo or CI build, not in the release folder',
    });
  }
  return findings;
}

async function run(context) {
  const builds = collectBuilds(context);
  const lowerFileSet = new Set(
    [...context.fileByPath.keys()].map((displayPath) => displayPath.toLowerCase()),
  );
  const findings = [];

  for (const build of builds.values()) {
    findings.push(bytecodeFinding(build));
    const version = pythonVersionFinding(build);
    if (version) findings.push(version);
    findings.push(...sourceFindings(context, build, lowerFileSet));
  }

  findings.push(...specFindings(context, builds));
  return findings;
}

const explain = {
  'pyinstaller.bytecode': {
    title: 'Bundled Python bytecode is recoverable',
    what: 'The app is a frozen PyInstaller build, so its Python modules travel as bytecode inside the executable or _internal folder.',
    how_attackers_find_it:
      'Run a public extractor such as pyinstxtractor on the build, then decompile the .pyc files (REA unpack/decompile step).',
    risk: 'Business logic, hidden endpoints, license checks and hardcoded values become readable; obfuscation and old encryption only slow this down.',
    fix: 'Keep valuable logic and secrets server-side; compile client code with Nuitka (to C) or key modules with Cython. PyInstaller removed its bytecode encryption option in v6, so that setting is no longer a defense.',
  },
  'pyinstaller.source_shipped': {
    title: 'Python source files shipped in the build',
    what: 'Loose .py application source files sit inside the _internal folder next to the compiled bytecode.',
    how_attackers_find_it:
      'Open the _internal folder of the build and read the .py files directly (REA shipping step).',
    risk: 'An attacker gets the original source, comments, internal names and any values embedded in it, with no decompilation effort.',
    fix: 'Remove the .py files from datas/collect_data_files in the .spec and rebuild; modules are already bundled as bytecode, and valuable logic belongs on your server.',
  },
  'pyinstaller.spec_shipped': {
    title: 'PyInstaller spec file shipped',
    what: 'The .spec build recipe is distributed inside the build folder.',
    how_attackers_find_it:
      'Read the .spec file from the release folder to learn source paths, hidden imports, data files and version metadata (REA shipping step).',
    risk: 'It hands an attacker a map of the app layout and build machine paths, which speeds up extraction and targeted patching.',
    fix: 'Ship only the executable and _internal contents; keep the .spec in the repository or CI workspace and build releases in a clean directory.',
  },
  'pyinstaller.python_version': {
    title: 'Bundled Python runtime version',
    what: 'The build embeds a CPython runtime, identified by python3XX.dll or libpython3.XX.',
    how_attackers_find_it:
      'Read the runtime file name next to the executable and match the version to public CPython security advisories (REA shipping/strings step).',
    risk: 'An interpreter past end of life receives no security fixes, so known CPython vulnerabilities stay unpatched in your app.',
    fix: 'Rebuild with a supported Python release and the current PyInstaller, then rescan the build.',
  },
};

function bytecodePlan(projectPath) {
  return [
    'Fix plan: pyinstaller.bytecode',
    '',
    `Project: ${projectPath}`,
    '',
    'PyInstaller bytecode is not a secret container: public extractors recover it and decompilers read the .pyc files.',
    'PyInstaller 6 removed the old bytecode encryption option (--key), so do not treat it as protection.',
    '',
    '1. Move valuable logic, license decisions and secrets to your server; the client should only ask and render.',
    '2. Compile the client with Nuitka instead of freezing it:',
    '```bash',
    'python -m nuitka --standalone --enable-plugin=tk-inter app.py',
    '# optional: --onefile (slower startup), --windows-console-mode=disable for GUI builds',
    '```',
    '   Docs: https://nuitka.net/user-documentation/usage.html',
    '3. Or compile only the sensitive modules with Cython and keep the rest as normal Python:',
    '```bash',
    'cythonize -i app/secrets.py',
    '# for a package: cythonize -i "app/**/*.py" (C compiler required in the build image)',
    '```',
    '   Docs: https://cython.readthedocs.io/en/latest/src/tutorial/cython_tutorial.html',
    '4. Obfuscation (pyarmor, pyminifier) only slows a reader down; it does not make the code worthless to an attacker.',
    '5. Rebuild the release and run `unrea_scan` again.',
  ].join('\n');
}

function sourcePlan(projectPath, finding) {
  const file = finding?.file || '_internal/app.py';
  return [
    'Fix plan: pyinstaller.source_shipped',
    '',
    `Project: ${projectPath}`,
    `Shipped source: ${file}`,
    '',
    '1. Open the .spec file and find the `datas` entries (or `collect_data_files(...)` calls) that add .py files.',
    '2. Remove those entries. PyInstaller already bundles imported modules into the PYZ as bytecode, so loose source is unnecessary.',
    '3. If a script must stay editable on disk, keep it outside the release folder and load it from the server.',
    '4. Rebuild with the updated .spec and confirm `_internal` no longer contains application .py files:',
    '```bash',
    'pyinstaller app.spec --noconfirm',
    '```',
    '   Docs: https://pyinstaller.org/en/stable/spec-files.html',
    '5. Run `unrea_scan` again.',
  ].join('\n');
}

function specPlan(projectPath, finding) {
  const file = finding?.file || 'app.spec';
  return [
    'Fix plan: pyinstaller.spec_shipped',
    '',
    `Project: ${projectPath}`,
    `Shipped spec: ${file}`,
    '',
    '1. Do not copy the .spec into the release folder; ship only the executable and the _internal contents.',
    '2. Keep the .spec in the repository and build releases in CI, then upload the build output only.',
    '3. If the spec is currently inside the build directory, rebuild from a clean folder:',
    '```bash',
    'pyinstaller --clean --noconfirm --distpath dist app.spec',
    '```',
    '   Docs: https://pyinstaller.org/en/stable/spec-files.html',
    '4. Zip the `dist/` output for release, never the project or build root.',
    '5. Run `unrea_scan` again.',
  ].join('\n');
}

function versionPlan(projectPath, finding) {
  return [
    'Fix plan: pyinstaller.python_version',
    '',
    `Project: ${projectPath}`,
    `Runtime marker: ${finding?.file || 'python3XX.dll / libpython3.XX'}`,
    '',
    '1. Pick a supported Python release from https://www.python.org/downloads/ (a version without an end-of-life date).',
    '2. Rebuild the frozen app with that interpreter and a current PyInstaller:',
    '```bash',
    'python -m PyInstaller --clean --noconfirm app.spec',
    '```',
    '   Docs: https://pyinstaller.org/en/stable/usage.html',
    '3. Confirm the release folder contains only the new runtime library (for example python312.dll) and no old DLLs.',
    '4. End-of-life interpreters get no security patches; upgrading is the only durable fix.',
    '5. Run `unrea_scan` again.',
  ].join('\n');
}

const fixPlan = {
  'pyinstaller.bytecode': (projectPath) => bytecodePlan(projectPath),
  'pyinstaller.source_shipped': (projectPath, finding) => sourcePlan(projectPath, finding),
  'pyinstaller.spec_shipped': (projectPath, finding) => specPlan(projectPath, finding),
  'pyinstaller.python_version': (projectPath, finding) => versionPlan(projectPath, finding),
};

export default {
  id: 'pyinstaller',
  title: 'PyInstaller / frozen Python',
  covers: ['PyInstaller onedir/onefile markers', 'bundled Python version', 'loose .py source', 'shipped .spec'],
  detect,
  run,
  explain,
  fixPlan,
};
