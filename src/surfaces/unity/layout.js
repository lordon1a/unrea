/**
 * Unity player layout detection. Walks the already-collected ctx.files view
 * once (no filesystem access) and groups paths into Unity build roots:
 *
 *   Windows/Linux   <prefix><Name>_Data/...
 *   macOS           <prefix><Name>.app/Contents/Resources/Data/...
 *
 * A root is kept only when it has a real Unity marker so an unrelated folder
 * named "Data" or "something_Data" cannot pull the surface in.
 */

const BURST_SUFFIX = '_burstdebuginformation_donotship';

/**
 * Every directory prefix of a display path, with a trailing slash.
 * "Game/Rift_Data/globalgamemanagers" ->
 * ["Game/", "Game/Rift_Data/"]
 *
 * @param {string} displayPath
 * @returns {string[]}
 */
function ancestorDirs(displayPath) {
  const parts = displayPath.split('/');
  const dirs = [];
  for (let i = 1; i < parts.length; i++) {
    dirs.push(`${parts.slice(0, i).join('/')}/`);
  }
  return dirs;
}

function isMacDataDir(dir) {
  return /(?:^|\/)[^/]+\.app\/Contents\/Resources\/Data\/$/.test(dir);
}

function isWindowsDataDir(dir) {
  const trimmed = dir.endsWith('/') ? dir.slice(0, -1) : dir;
  const segment = trimmed.slice(trimmed.lastIndexOf('/') + 1);
  return /_data$/i.test(segment);
}

function playerRootOf(dir, mac) {
  const trimmed = dir.endsWith('/') ? dir.slice(0, -1) : dir;
  if (mac) {
    const match = trimmed.match(/^(.*?)[^/]+\.app\/Contents\/Resources\/Data$/);
    if (match) return match[1];
  }
  const slash = trimmed.lastIndexOf('/');
  return slash === -1 ? '' : trimmed.slice(0, slash + 1);
}

function isBurstDir(dir) {
  const trimmed = dir.endsWith('/') ? dir.slice(0, -1) : dir;
  const segment = trimmed.slice(trimmed.lastIndexOf('/') + 1);
  return segment.toLowerCase().endsWith(BURST_SUFFIX);
}

/**
 * @param {object} context
 * @returns {{
 *   playerRoot: string,
 *   dataDir: string,
 *   mac: boolean,
 *   backend: 'mono'|'il2cpp',
 *   assemblyCSharp: object|null,
 *   il2cppMetadata: object|null,
 *   managed: object[],
 *   plugins: object[],
 *   pdbs: object[],
 *   mdbs: object[],
 *   burstDirs: string[],
 * }[]}
 */
export function collectUnityRoots(context) {
  const files = new Map();
  const dirs = new Set();

  for (const file of context.files) {
    const displayPath = file.displayPath;
    if (!displayPath || displayPath.includes('!/')) continue; // Unity lives on disk, not in asar
    files.set(displayPath, file);
    for (const dir of ancestorDirs(displayPath)) dirs.add(dir);
  }

  const paths = [...files.keys()];
  const hasPrefix = (prefix) => paths.some((candidate) => candidate.startsWith(prefix));
  const hasFile = (displayPath) => files.has(displayPath);

  const roots = [];
  for (const dir of dirs) {
    const mac = isMacDataDir(dir);
    if (!mac && !isWindowsDataDir(dir)) continue;

    const playerRoot = playerRootOf(dir, mac);
    const hasGlobalManagers = hasFile(`${dir}globalgamemanagers`);
    const hasDataUnity3d = hasFile(`${dir}data.unity3d`);
    const hasUnityPlayer = hasFile(`${playerRoot}UnityPlayer.dll`);
    const hasManagedDir = hasPrefix(`${dir}Managed/`);
    const hasIl2cppDir = hasPrefix(`${dir}il2cpp_data/`);

    if (!hasGlobalManagers && !hasDataUnity3d && !hasUnityPlayer && !hasManagedDir && !hasIl2cppDir) {
      continue;
    }

    const directManaged = [];
    for (const [displayPath, file] of files) {
      if (!displayPath.startsWith(`${dir}Managed/`)) continue;
      if (displayPath.slice(`${dir}Managed/`.length).includes('/')) continue;
      directManaged.push(file);
    }

    const assemblyCSharp =
      directManaged.find((file) => file.basename.toLowerCase() === 'assembly-csharp.dll') || null;

    const managed = [];
    const plugins = [];
    const pdbs = [];
    const mdbs = [];
    for (const [displayPath, file] of files) {
      const inManaged = displayPath.startsWith(`${dir}Managed/`);
      const ext = file.ext;
      if (inManaged) {
        managed.push(file);
        if (ext === '.pdb') pdbs.push(file);
        if (ext === '.mdb') mdbs.push(file);
      }
      if (displayPath.startsWith(`${dir}Plugins/`) && ext === '.dll') plugins.push(file);
      if (ext === '.pdb' && displayPath.startsWith(playerRoot)) pdbs.push(file);
    }

    const il2cppMetadata =
      files.get(`${dir}il2cpp_data/Metadata/global-metadata.dat`) || null;
    const backend = il2cppMetadata || hasIl2cppDir ? 'il2cpp' : 'mono';

    const burstDirs = [...dirs].filter(
      (candidate) => candidate.startsWith(playerRoot) && isBurstDir(candidate),
    );

    roots.push({
      playerRoot,
      dataDir: dir,
      mac,
      backend,
      assemblyCSharp,
      il2cppMetadata,
      managed,
      plugins,
      // Deduplicate: a pdb inside Managed/ also matches the playerRoot scan.
      pdbs: [...new Set(pdbs.map((file) => file.displayPath))].map((path) => files.get(path)),
      mdbs,
      burstDirs: [...new Set(burstDirs.map((candidate) =>
        candidate.endsWith('/') ? candidate.slice(0, -1) : candidate,
      ))],
    });
  }

  roots.sort((a, b) => a.dataDir.localeCompare(b.dataDir));
  return roots;
}

/**
 * Engine metadata for the core report ("engine: unity (mono)"). The current
 * buildResult shape has no engine/backend field, so this is exported for the
 * core to consume when it grows one; `run()` does not depend on it.
 *
 * @param {object} context
 * @returns {{engine: 'unity', backend: 'mono'|'il2cpp', builds: Array<{path: string, backend: string}>}|null}
 */
export function engineInfo(context) {
  const roots = collectUnityRoots(context);
  if (!roots.length) return null;
  const backend = roots.some((root) => root.backend === 'il2cpp') ? 'il2cpp' : 'mono';
  return {
    engine: 'unity',
    backend,
    builds: roots.map((root) => ({ path: root.playerRoot || '.', backend: root.backend })),
  };
}
