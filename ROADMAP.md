# Roadmap

The goal is to cover every target that AI reverse-engineering toolkits like REA can analyze, with a defender module for each. Every module does the same three things: shows what an attacker's agent would get from your build, explains how, and gives you the fix that makes it worthless.

## Shipped
- **Electron / JavaScript:** asar, bundles, source maps, `.env`, shipped tests, Electron fuses, client-side license checks
- **Any build:** provider keys and tokens (masked), internal endpoints
- **Unity:** Mono vs IL2CPP, IL2CPP metadata, DoNotShip/PDB debug data, readable names, client-side game state
- **Godot:** export encryption settings, script export mode, keys committed to the repo, project files shipped in the build
- **.NET:** readable IL, sensitive names, PDBs, signing
- **PyInstaller:** bundled bytecode, shipped sources/spec, Python end-of-life
- **Windows native (PE):** signing, ASLR/DEP/CFG, PDB path leaks, Go build info, Rust path strings, secrets in strings

## Next
- Android APK (R8/ProGuard, debuggable, allowBackup, exported components, keys in resources, cleartext traffic)
- Flutter (`--obfuscate` / `--split-debug-info`)
- Apple bundles / IPA (plist secrets, ATS exceptions, entitlements, signing)
- ELF / Mach-O (symbols, debug info, hardening flags)

## Later
- Web builds (source maps, keys in bundles, CSP), WASM name sections
- Shipped data (SQLite/JSON with user data or keys, unprotected model files)
- Recorded traffic of your own app (tokens in URLs, missing TLS, replayable endpoints)
- `unrea attack`: run REA against your own build when you have it installed, and merge its evidence into the report
- GitHub Action + `unrea grade` badge

Want a surface sooner? Open an issue.
