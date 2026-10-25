import { parsePE } from '../../parse/pe.js';
import { safeSnippet, scanSecrets } from '../../core/secrets.js';
import {
  extractCodeViewPath,
  isCodeView,
  readDebugEntries,
  rvaToOffset,
} from './debug.js';
import { countRustPaths, printableStrings, readGoBuildInfo } from './strings.js';
import { hasMzMagic, isPeCandidate } from './targets.js';

// A PE header is a few hundred bytes; the cap exists so strings scanning stays
// bounded on multi-hundred-MB game executables.
const MAX_READ = 2 * 1024 * 1024;
const MAX_GO_SECTION = 64 * 1024;
const MIN_RUST_PATHS = 3;

const DYNAMIC_BASE = 0x40;
const NX_COMPAT = 0x100;
const GUARD_CF = 0x4000;

const explain = {
  'pe-native.*': {
    title: 'Native Windows binary exposure',
    what: 'Checks that apply to the app’s own .exe/.dll files (not .NET, not vendor runtimes).',
    how_attackers_find_it:
      'Open the binary with a PE viewer or REA (pe-info/imports/strings steps), then read headers, debug data and strings.',
    risk: 'Missing hardening and leaked build metadata make tampering, redistribution and vulnerability hunting cheaper.',
    fix: 'Sign the binaries and rebuild with /DYNAMICBASE /NXCOMPAT /guard:cf, /PDBALTPATH and without .pdb files.',
  },
  'pe-native.unsigned': {
    title: 'Native binary is not signed',
    what: 'The PE has no Authenticode certificate, so the shipped executable or DLL can be modified and redistributed without detection.',
    how_attackers_find_it:
      'Open the file properties/signature tab, or read the certificate data directory of the PE (it is empty).',
    risk: 'Modified copies look identical to yours; SmartScreen warns users, and tampering is cheap to hide.',
    fix: 'Sign every shipped .exe/.dll with Authenticode (signtool) in the release build and verify with signtool verify /pa.',
  },
  'pe-native.no_aslr': {
    title: 'ASLR is disabled',
    what: 'DllCharacteristics does not set DYNAMIC_BASE (0x40), so Windows will not randomize the image base.',
    how_attackers_find_it:
      'Read the optional header DllCharacteristics field (0x40) with a PE viewer; a fixed base shows up immediately.',
    risk: 'Fixed load addresses make memory-corruption exploits and ROP chains much easier to build and reuse.',
    fix: 'Link with /DYNAMICBASE (MSVC) or the equivalent linker flag; it is the default, so check for /FIXED or an old toolchain.',
  },
  'pe-native.no_dep': {
    title: 'DEP/NX is not declared',
    what: 'DllCharacteristics does not set NX_COMPAT (0x100), so the binary does not opt into data-execution prevention.',
    how_attackers_find_it: 'Read DllCharacteristics (0x100) with a PE viewer.',
    risk: 'Injected or overflowed data pages can be executed, which turns a crash into code execution.',
    fix: 'Link with /NXCOMPAT (MSVC) or the equivalent, and keep it on for plugin-style DLLs too.',
  },
  'pe-native.no_cfg': {
    title: 'Control Flow Guard is off',
    what: 'DllCharacteristics does not set GUARD_CF (0x4000), so indirect calls are not validated by CFG.',
    how_attackers_find_it: 'Read DllCharacteristics (0x4000) with a PE viewer.',
    risk: 'Control-flow hijacking (vtable/function-pointer overwrite) is easier because indirect targets are unchecked.',
    fix: 'Compile and link with /guard:cf (MSVC); it is informational for toolchains that do not implement CFG, such as Go or Rust on Windows.',
  },
  'pe-native.debug_info': {
    title: 'Debug directory leaks a PDB path',
    what: 'The PE debug directory contains a CodeView record with the path of the .pdb file used at build time.',
    how_attackers_find_it:
      'Read the debug data directory (index 6) with a PE viewer and follow the CodeView record; the path is plain text.',
    risk: 'Build machine paths, usernames and project names become public, and a shipped .pdb additionally exposes function names, types and line numbers.',
    fix: 'Build with /PDBALTPATH:%_PDB% and never ship .pdb files (exclude **/*.pdb from the installer).',
  },
  'pe-native.go_buildinfo': {
    title: 'Go build info is readable',
    what: 'The binary has a .go.buildinfo section, which embeds the module path, dependencies and build settings that `go version -m` prints.',
    how_attackers_find_it:
      'Run `go version -m app.exe` or read the .go.buildinfo section; module paths and dependency versions are plain text.',
    risk: 'Dependency versions are published, so known CVEs in those modules can be matched to your build immediately.',
    fix: 'Build with `-trimpath -buildvcs=false -ldflags="-s -w"`; treat module names/versions as public information and patch dependencies.',
  },
  'pe-native.rust_paths': {
    title: 'Rust build paths are readable',
    what: 'The binary contains many cargo registry and rustc source paths from the build machine.',
    how_attackers_find_it:
      'Run strings over the binary and grep for `cargo/registry` or `index.crates.io`; the crate names and versions are readable.',
    risk: 'The exact crate versions (and sometimes the local folder layout) are disclosed, narrowing the search for known vulnerabilities.',
    fix: 'Build with `--remap-path-prefix`, set `strip = true` in the release profile, and keep dependencies patched.',
  },
};

/**
 * Sibling lookup for shipped .pdb files. A debug path plus the symbol file
 * itself is the combination that actually leaks internal names.
 *
 * @param {object} ctx
 * @returns {Set<string>}
 */
function collectPdbPaths(ctx) {
  const paths = new Set();
  for (const file of ctx.files) {
    if (file.ext === '.pdb') paths.add(file.displayPath.toLowerCase());
  }
  return paths;
}

function siblingPdbName(displayPath, ext) {
  const base = ext ? displayPath.slice(0, -ext.length) : displayPath;
  return `${base}.pdb`.toLowerCase();
}

function dllCharacteristicsText(value) {
  return `0x${(value >>> 0).toString(16)}`;
}

async function checkFile(ctx, file, pdbPaths) {
  const findings = [];
  const readLimit = file.size > 0 ? Math.min(file.size, MAX_READ) : MAX_READ;
  let head;
  try {
    head = await ctx.readBytes(file.absPath, 0, readLimit);
  } catch {
    return findings;
  }
  if (!hasMzMagic(head)) return findings;

  const pe = parsePE(head);
  if (!pe || !pe.valid) return findings;
  // Managed assemblies have their own surface; native hardening flags do not
  // describe them.
  if (pe.isDotNet) return findings;

  const dllCharacteristics = pe.optional?.dllCharacteristics ?? 0;

  if (!pe.hasCertificate) {
    findings.push({
      id: 'pe-native.unsigned',
      severity: 'medium',
      file: file.displayPath,
      line: null,
      snippet: `no Authenticode signature (certificate directory is empty) in ${file.basename}`,
      fix: 'sign every shipped .exe/.dll with Authenticode (also removes SmartScreen “unknown publisher” warnings)',
    });
  }

  if (!(dllCharacteristics & DYNAMIC_BASE)) {
    findings.push({
      id: 'pe-native.no_aslr',
      severity: 'medium',
      file: file.displayPath,
      line: null,
      snippet: `DllCharacteristics ${dllCharacteristicsText(dllCharacteristics)}: DYNAMIC_BASE (0x40) is not set`,
      fix: 'link with /DYNAMICBASE (MSVC) or the equivalent linker flag and rebuild',
    });
  }

  if (!(dllCharacteristics & NX_COMPAT)) {
    findings.push({
      id: 'pe-native.no_dep',
      severity: 'medium',
      file: file.displayPath,
      line: null,
      snippet: `DllCharacteristics ${dllCharacteristicsText(dllCharacteristics)}: NX_COMPAT (0x100) is not set`,
      fix: 'link with /NXCOMPAT (MSVC) or the equivalent linker flag and rebuild',
    });
  }

  if (!(dllCharacteristics & GUARD_CF)) {
    findings.push({
      id: 'pe-native.no_cfg',
      severity: 'info',
      file: file.displayPath,
      line: null,
      snippet: `DllCharacteristics ${dllCharacteristicsText(dllCharacteristics)}: GUARD_CF (0x4000) is not set`,
      fix: 'compile and link with /guard:cf (MSVC); other toolchains may not implement CFG',
    });
  }

  const pdbPath = await readPdbPath(ctx, file, head, pe);
  if (pdbPath) {
    const shipped = pdbPaths.has(siblingPdbName(file.displayPath, file.ext));
    findings.push({
      id: 'pe-native.debug_info',
      severity: shipped ? 'high' : 'medium',
      file: file.displayPath,
      line: null,
      snippet: safeSnippet(
        shipped
          ? `debug directory references PDB path "${pdbPath}" and the .pdb file ships next to the binary`
          : `debug directory references PDB path "${pdbPath}"`,
      ),
      fix: 'build with /PDBALTPATH:%_PDB% and do not ship .pdb files',
    });
  }

  // PE section headers hold 8 bytes, so Go's ".go.buildinfo" arrives truncated
  // as ".go.buil"; match the prefix instead of the full name.
  const section = (pe.sections || []).find((entry) =>
    entry.name.toLowerCase().startsWith('.go.buil'),
  );
  if (section) {
    let info = null;
    try {
      const raw = await ctx.readBytes(
        file.absPath,
        section.rawPointer,
        Math.min(section.rawSize || MAX_GO_SECTION, MAX_GO_SECTION),
      );
      info = readGoBuildInfo(raw);
    } catch {
      info = null;
    }
    const modulePath = info?.modulePath || null;
    const moduleCount = info?.moduleCount || 0;
    const detail = modulePath
      ? `module ${modulePath}${moduleCount ? ` and ${moduleCount} dependency line(s)` : ''}`
      : 'module paths and the dependency list';
    findings.push({
      id: 'pe-native.go_buildinfo',
      severity: 'medium',
      file: file.displayPath,
      line: null,
      snippet: safeSnippet(`.go.buildinfo section exposes ${detail}`),
      fix: 'build with -trimpath -buildvcs=false -ldflags="-s -w" and keep dependencies patched',
    });
  }

  const strings = printableStrings(head);
  if (strings.length) {
    const rust = countRustPaths(strings);
    if (rust.count >= MIN_RUST_PATHS) {
      const example = rust.example ? `, e.g. ${rust.example}` : '';
      findings.push({
        id: 'pe-native.rust_paths',
        severity: 'info',
        file: file.displayPath,
        line: null,
        snippet: safeSnippet(`${rust.count} cargo/rustc build paths${example}`),
        fix: 'build with --remap-path-prefix and set strip = true in the release profile',
      });
    }

    const found = scanSecrets(strings.join('\n'));
    const seen = new Set();
    for (const secret of found) {
      const key = `${secret.id}\u0000${secret.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: secret.id,
        severity: secret.severity,
        file: file.displayPath,
        line: null,
        snippet: safeSnippet(`binary strings: ${secret.snippet}`),
        fix: secret.fix,
      });
    }
  }

  return findings;
}

async function readPdbPath(ctx, file, head, pe) {
  for (const entry of readDebugEntries(head, pe)) {
    if (!isCodeView(entry.type)) continue;
    const offset =
      entry.pointerToRawData ||
      rvaToOffset(entry.addressOfRawData, pe, file.size || head.length);
    if (!offset) continue;

    let record;
    try {
      const length = Math.min(Math.max(entry.sizeOfData || 64, 32), 4096);
      record = await ctx.readBytes(file.absPath, offset, length);
    } catch {
      continue;
    }
    const pdbPath = extractCodeViewPath(record);
    if (pdbPath) return pdbPath;
  }
  return null;
}

async function run(ctx) {
  const findings = [];
  const pdbPaths = collectPdbPaths(ctx);
  for (const file of ctx.files) {
    if (!isPeCandidate(file)) continue;
    findings.push(...(await checkFile(ctx, file, pdbPaths)));
  }
  return findings;
}

async function detect(ctx) {
  for (const file of ctx.files) {
    if (!isPeCandidate(file)) continue;
    let head;
    try {
      head = await ctx.readBytes(file.absPath, 0, 2);
    } catch {
      continue;
    }
    if (hasMzMagic(head)) return true;
  }
  return false;
}

function signPlan(projectPath, finding) {
  const target = finding?.file ? `\`${finding.file}\`` : 'every shipped .exe/.dll';
  return [
    '# Sign your native binaries (Authenticode)',
    '',
    `Sign ${target} in ${projectPath} as the last step of the release build.`,
    '',
    '```bat',
    'signtool sign /fd SHA256 /td SHA256 ^',
    '  /tr http://timestamp.digicert.com ^',
    '  /f cert.pfx /p "%PFX_PASSWORD%" app.exe',
    'signtool verify /pa app.exe',
    '```',
    '',
    '1. Keep the .pfx (or a cloud signing identity) in your CI secret store, never in the repo.',
    '2. Sign every .exe and .dll that ships; an unsigned helper DLL is enough to reload patched code.',
    '3. electron-builder: set `win.signingHashAlgorithms`, `win.certificateFile`/`certificatePassword` (or `win.signtoolOptions`).',
    '4. CMake/MSBuild: add a post-build `signtool` step so local builds behave like CI.',
    '',
    'Rebuild, sign, then rescan: `pe-native.unsigned` must disappear.',
  ].join('\n');
}

function hardeningPlan(projectPath, finding) {
  const id = finding?.id || 'pe-native.no_aslr';
  return [
    `# Fix plan: ${id}`,
    '',
    `Enable the missing image flag for the binaries in ${projectPath} and rebuild.`,
    '',
    'MSVC (linker):',
    '```text',
    '/DYNAMICBASE /NXCOMPAT /guard:cf',
    '```',
    'CMake (MSVC only):',
    '```cmake',
    'add_link_options($<$<CXX_COMPILER_ID:MSVC>:/DYNAMICBASE>)',
    'add_link_options($<$<CXX_COMPILER_ID:MSVC>:/NXCOMPAT>)',
    'add_link_options($<$<CXX_COMPILER_ID:MSVC>:/guard:cf>)',
    '```',
    'Rust (MSVC toolchain):',
    '```text',
    'RUSTFLAGS="-C link-arg=/DYNAMICBASE -C link-arg=/NXCOMPAT -C link-arg=/guard:cf" cargo build --release',
    '```',
    'Go:',
    '```text',
    'go build -trimpath -ldflags="-s -w"',
    '```',
    'The Go linker emits ASLR/NX on Windows itself; if a build report still shows them missing,',
    'check that no `-extldflags`/post-processing step (packer, patcher) rewrites DllCharacteristics.',
    '',
    'Rebuild and rescan; the flag findings must disappear. Do not patch the bytes after linking —',
    'some launchers and updaters re-sign or rewrite the header and silently undo it.',
  ].join('\n');
}

function debugPlan(projectPath, finding) {
  return [
    '# Fix plan: pe-native.debug_info',
    '',
    `Remove the build-machine PDB path from the binaries in ${projectPath}.`,
    '',
    '1. MSVC: link with a relative/blank PDB path instead of the absolute build path:',
    '```text',
    '/PDBALTPATH:%_PDB%',
    '```',
    '   (`/PDBALTPATH:blank` removes the path entirely if you do not need symbol resolution.)',
    '2. CMake: `add_link_options(/PDBALTPATH:%_PDB%)` for MSVC release builds.',
    '3. Rust: the PE debug directory is only populated by a PDB build; use `strip = true` and do not ship',
    '   the `.pdb` from `target/release`.',
    '4. Never ship symbol files: exclude `**/*.pdb` from electron-builder `files`, the NSIS/MSI payload',
    '   and any zip/updater manifest.',
    '5. If a `.pdb` already shipped, rotate nothing (it is not a secret) but remove it in the next release',
    '   and archive the symbols on your own symbol server.',
    '',
    'Rebuild and rescan: `pe-native.debug_info` must disappear and the sibling .pdb finding must go away.',
  ].join('\n');
}

function goPlan(projectPath, finding) {
  return [
    '# Fix plan: pe-native.go_buildinfo',
    '',
    `Rebuild the Go binaries in ${projectPath} without build-machine paths and symbols:`,
    '',
    '```text',
    'go build -trimpath -buildvcs=false -ldflags="-s -w" ./cmd/app',
    '```',
    '',
    '1. `-trimpath` removes local module paths from the binary.',
    '2. `-buildvcs=false` keeps VCS revision/remote metadata out of the build info.',
    '3. `-ldflags="-s -w"` drops the symbol table and DWARF data.',
    '',
    'Be honest with yourself: `go version -m app.exe` still reports the module path and dependency',
    'versions after these flags, because the Go runtime keeps that data. Treat module names as public,',
    'keep dependencies patched, and only obfuscate the binary if that trade-off is worth it.',
    '',
    'Rebuild and rescan; `pe-native.go_buildinfo` will stay, so the honest goal is “no local paths,',
    'known dependency list”.',
  ].join('\n');
}

function rustPlan(projectPath, finding) {
  return [
    '# Fix plan: pe-native.rust_paths',
    '',
    `Remove cargo/rustc source paths from the Rust release build in ${projectPath}:`,
    '',
    '1. Rewrite build prefixes (cargo config or CI env):',
    '```text',
    'RUSTFLAGS="--remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$(pwd)=." cargo build --release',
    '```',
    '2. Strip symbols in `Cargo.toml`:',
    '```toml',
    '[profile.release]',
    'strip = true',
    '```',
    '3. Windows panic/backtrace strings still mention crate names; that is normal.',
    '4. If you need panic messages, consider `panic = "abort"` to drop some of the formatting tables.',
    '',
    'Rebuild and rescan; `pe-native.rust_paths` should disappear or drop to only the crate names.',
  ].join('\n');
}

const fixPlan = {
  'pe-native.unsigned': signPlan,
  'pe-native.no_aslr': hardeningPlan,
  'pe-native.no_dep': hardeningPlan,
  'pe-native.no_cfg': hardeningPlan,
  'pe-native.debug_info': debugPlan,
  'pe-native.go_buildinfo': goPlan,
  'pe-native.rust_paths': rustPlan,
};

export default {
  id: 'pe-native',
  title: 'Windows native binaries',
  covers: [
    'native PE headers (ASLR, DEP, CFG)',
    'Authenticode signing',
    'PDB paths and shipped symbols',
    'Go build info',
    'Rust build paths',
    'secrets in binary strings',
  ],
  detect,
  run,
  explain,
  fixPlan,
};
