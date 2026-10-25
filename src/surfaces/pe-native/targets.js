/**
 * Which files this surface is allowed to look at. Windows apps ship a small
 * number of "own" PE files next to a large pile of third-party runtime
 * binaries; scanning the runtime produces noise that the developer cannot fix.
 */

// Executable and library containers that can hold a PE image. .mui is a
// resource-only container and .pdb is a debug symbol file, so neither is here.
const PE_EXTENSIONS = new Set([
  '.exe',
  '.dll',
  '.node',
  '.sys',
  '.ocx',
  '.scr',
  '.cpl',
  '.pyd',
  '.drv',
  '.efi',
  '.ax',
]);

// Chromium/Electron ships these unchanged with every app; signing, ASLR or
// control-flow guard for them is decided by the upstream vendor, not by the
// developer scanning their own build.
const THIRD_PARTY_EXACT = new Set([
  'ffmpeg.dll',
  'libegl.dll',
  'libglesv2.dll',
  'd3dcompiler_47.dll',
  'vk_swiftshader.dll',
  'vulkan-1.dll',
  'unityplayer.dll',
]);

const THIRD_PARTY_PATTERNS = [
  /^unitycrashhandler.*\.exe$/,
  /^vcruntime.*\.dll$/, // vcruntime140.dll, vcruntime140_1.dll, ...
  /^msvcp.*\.dll$/, // msvcp140.dll, msvcp140_atomic_wait.dll, ...
];

const SEPARATORS = /[!/\\]/;

/**
 * @param {string} basename
 * @returns {boolean}
 */
export function isThirdPartyRuntime(basename) {
  const name = String(basename || '').toLowerCase();
  if (!name) return false;
  return THIRD_PARTY_EXACT.has(name) || THIRD_PARTY_PATTERNS.some((re) => re.test(name));
}

function segments(displayPath) {
  return String(displayPath || '')
    .split(SEPARATORS)
    .filter(Boolean)
    .map((part) => part.toLowerCase());
}

/**
 * Unity builds have their own surface and a huge set of engine binaries; the
 * "Unity" folder name or the engine player/crash-handler names are enough to
 * hand the file over to that surface.
 *
 * @param {string} displayPath
 * @returns {boolean}
 */
export function isUnityPath(displayPath) {
  const parts = segments(displayPath);
  if (parts.includes('unity')) return true;
  const base = parts[parts.length - 1] || '';
  return base.startsWith('unityplayer') || base.startsWith('unitycrashhandler');
}

/**
 * @param {object} file walked file entry
 * @returns {boolean}
 */
export function isPeCandidate(file) {
  if (!file || typeof file !== 'object') return false;
  if (file.inNodeModules) return false;
  if (!file.ext || !PE_EXTENSIONS.has(file.ext)) return false;
  if (isThirdPartyRuntime(file.basename)) return false;
  if (isUnityPath(file.displayPath)) return false;
  return true;
}

/**
 * Cheap content gate: file extensions lie, and an app may ship a text file
 * called app.exe. Both 'MZ' bytes are needed before a file is treated as PE.
 *
 * @param {Buffer} head
 * @returns {boolean}
 */
export function hasMzMagic(head) {
  return Boolean(head) && head.length >= 2 && head[0] === 0x4d && head[1] === 0x5a;
}
