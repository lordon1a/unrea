# unrea — anti reverse engineering scanner for AI-era apps

[![npm](https://img.shields.io/npm/v/@yigitguldal/unrea?color=cb3837&label=npm)](https://www.npmjs.com/package/@yigitguldal/unrea)
[![license](https://img.shields.io/github/license/lordon1a/unrea)](LICENSE)
[![node](https://img.shields.io/node/v/@yigitguldal/unrea)](package.json)
[![MCP](https://img.shields.io/badge/MCP-Claude%20Code%20%7C%20Codex%20%7C%20OpenCode-6e56cf)](#use-it-from-your-ai-agent)

**AI agents like [REA](https://github.com/morluto/rea) can take apart an Electron app, a .NET tool or a Unity game in minutes. unrea shows you what they would find in *your* build, and your own agent fixes it before you ship.**

```bash
npx @yigitguldal/unrea scan ./dist
```

- **Finds what leaks:** API keys and tokens, `.env` files, source maps, shipped tests and debug symbols, readable code and names (JS, .NET, Unity Mono), unencrypted Godot exports, unsigned or unhardened executables, weak Electron fuses.
- **Built for agents:** an MCP server + skill for Claude Code, Codex and OpenCode. Your agent scans, explains each finding and applies the fix.
- **Honest:** obfuscation only slows attackers down. unrea pushes you toward the fix that holds up: secrets and valuable logic on your server, so a cracked client gets the attacker nothing.
- **Read-only and offline:** it never edits your build and never calls the network. Secrets are masked in every output.


## Why

Reverse engineering used to take a skilled person and a weekend. Now an agent with an MCP toolkit unpacks `app.asar`, greps every string, decompiles your DLLs and writes up the result. "Nobody will bother" doesn't hold anymore. Most leaks are boring: a key in a bundle, a `.map` file, a test folder nobody excluded. unrea catches them in seconds, while they're still cheap to fix.

## What's covered

| Target | Status |
| --- | --- |
| Electron / JavaScript (`asar`, bundles, fuses) | ✅ |
| Any build: keys, `.env`, source maps, tests, internal endpoints | ✅ |
| Unity (Mono / IL2CPP), Godot export settings, .NET, PyInstaller, Windows PE | ✅ |
| Android APK, Flutter, Apple bundles, ELF / Mach-O | 🚧 next |
| Web builds, WASM, shipped databases, recorded traffic | 🗺️ planned |

The goal is to cover everything REA can analyze, with a defender module for each. See [ROADMAP.md](ROADMAP.md).

## Use it from your AI agent

```bash
npx @yigitguldal/unrea setup --client claude_code   # prints the claude mcp add command + copies the skill
npx @yigitguldal/unrea setup --client codex         # merges ~/.codex/config.toml
npx @yigitguldal/unrea setup --client opencode      # merges ~/.config/opencode/opencode.json
```

Add `--dry-run` to see every write first, or `--json` for machine-readable
output. `UNREA_HOME` overrides the home directory (useful for tests and
sandboxes).

Where it writes:

| Client | MCP registration | Skill |
| --- | --- | --- |
| `claude_code` | Prints `claude mcp add unrea -- npx -y @yigitguldal/unrea@<version> mcp`; does not edit `.claude.json` | `~/.claude/skills/unrea/SKILL.md` |
| `codex` | `[mcp_servers.unrea]` in `~/.codex/config.toml` (backup `.unrea.bak`) | `~/.agents/skills/unrea/SKILL.md` |
| `opencode` | `mcp.unrea` in `~/.config/opencode/opencode.json` (backup `.unrea.bak`) | `~/.agents/skills/unrea/SKILL.md` |

The setup merge is idempotent and skips an existing unrea entry. Restart the
client afterwards. For Claude Code, run the printed command once.

Then ask your agent:

```text
scan my build with unrea and fix everything high
```

The agent works this loop:

```text
build -> unrea_scan -> unrea_explain -> unrea_fix_plan -> apply -> rescan
```

Stop when there are no high or critical findings.

### MCP tools

| Tool | What it does |
| --- | --- |
| `unrea_scan` | `{path, min_severity?, max_findings?}` → grade, mode (`build`/`source`), detected surfaces, severity counts, top fixes, masked findings. Defaults: medium, 50. |
| `unrea_explain` | `{id}` → what the check is, how an attacker's agent finds it, real risk and fix. Unknown ids list known ids. |
| `unrea_fix_plan` | `{path, id}` → apply-ready fuse hook, electron-builder exclusions, source-map flags, server proxy or license outline. |
| `unrea_surfaces` | `{path?}` → installed surfaces `{id, title, covers}`; with a path, each also gets `detected`. |

`unrea_scan` honors `min_severity` and `max_findings` for the `findings` array;
`summary`, `grade` and `top_fixes` always describe the full scan. Secrets stay
masked in MCP JSON, just like `--json`.

The skill is bundled at `skill/unrea/SKILL.md`; it tells the agent the rules to
follow while writing code and the release loop above.

## CLI

```bash
npx @yigitguldal/unrea scan ./dist
npx @yigitguldal/unrea scan ./dist/win-unpacked --json
npx @yigitguldal/unrea scan ./MyApp/resources/app.asar --verbose --fail-on critical
npx @yigitguldal/unrea mcp                         # stdio MCP server (normally launched by the client)
```

Options:

| Option | Meaning |
| --- | --- |
| `--json` | Machine-readable output (always complete; includes `mode` and `surfaces`) |
| `--verbose` | List every finding in text mode (no collapsing or 5-row cap) |
| `--source` | Force source-repo mode: skip `node_modules`, no `tests.shipped`, print a warning |
| `--build` | Force build mode even if the folder looks like a source repo |
| `--fail-on critical\|high\|medium\|none` | Exit 1 when a finding reaches this level (default `high`) |

Exit codes: `0` clean (or below threshold), `1` threshold reached, `2` bad
usage or unreadable path. Secrets are always masked in text and JSON output.

If the target looks like a source repo (`package.json` plus `src/`, `test/` or
`.git`, with no build artifact at the root), unrea warns you to scan the build
output instead. In that mode it skips `node_modules` and does not emit
`tests.shipped`. Force it with `--source`, or disable detection with `--build`.

### Sample output

```text
unrea 0.4.0 - client exposure scan
target: dist
surfaces: electron, generic
files scanned: 664
duration: 812 ms
grade: F (1 critical)

CRITICAL (1)
  CRITICAL  resources/app.asar!/main.js:12  OpenAI key: sk-p…6X
    fix: revoke and rotate this OpenAI key; call the API from your server

HIGH (2)
  HIGH      resources/app.asar  14 test files ship in the build (e.g. resources/app.asar!/test/x.test.mjs)
    fix: exclude test folders from the package (electron-builder `files` / .npmignore)
  HIGH      app.exe  RunAsNode: enabled
    fix: RunAsNode is enabled: flip it with @electron/fuses at build time

MEDIUM (1)
  MEDIUM    resources/app.asar!/app.js.map:1  app.js.map shipped in the build
    fix: disable source maps in production build

INFO (458)
  INFO  endpoint.internal x458 (e.g. resources/app.asar!/main.js:88)

Summary
  critical: 1, high: 2, medium: 1, info: 458
  top fixes to do first:
    1. revoke and rotate this OpenAI key; call the API from your server
    2. exclude test folders from the package (electron-builder `files` / .npmignore)
    3. RunAsNode is enabled: flip it with @electron/fuses at build time
```

Text mode collapses info rows to one line per id and shows at most five
findings per id/severity. `--verbose` lists them all; `--json` always contains
every finding.

Grade: **A** nothing medium or worse, **B** up to 3 medium, **C** more than 3
medium, **D** any high, **F** any critical.

## What it checks

| ID | Severity | What it means |
| --- | --- | --- |
| `secret.*` | critical / high / info | Live provider keys (AWS, OpenAI, Anthropic, Stripe, GitHub, Google, Slack, PEM), Supabase JWT roles, high-entropy literals assigned to secret-looking names. Masked in output. Secrets in shipped test files are info. |
| `tests.shipped` | high | Test/spec files were packaged into the build (one finding per asar/root) |
| `sourcemap.file` | high | A `.map` file shipped with the build |
| `sourcemap.comment` | medium | Code points at a source map file |
| `env.file` | critical / high | A `.env*` file shipped (critical if it contains a secret) |
| `license.client` | medium | Client-side plan/license checks (heuristic, max 5 per file) |
| `code.readable` | medium | A `.js` file over 20 KB that was not minified |
| `endpoint.internal` | info | `localhost`, `127.0.0.1`, `staging`, `internal` or `dev` hosts |
| `electron.fuses` | high / medium | Debuggable or bypassable Electron binaries |
| `asar.plain` | info | An `.asar` was found; it is an archive, not encryption |

Every `.asar` is unpacked to a temporary directory (removed afterwards) and its
contents are scanned using paths like `app.asar!/main.js`. Files under
`node_modules` are scanned too, but their findings are reported one severity
lower: it is vendor code, not your logic.

Test paths (`test/`, `tests/`, `__tests__/`, `e2e/`, `spec/`, `*.test.*`,
`*.spec.*`) outside `node_modules` are treated as shipped test code. The scan
emits one `tests.shipped` finding per asar/root, and secret findings inside
those files stay visible but drop to info with a `[test file, likely fixture]`
prefix, so fixtures do not decide the grade.

Provider keys and PEM headers inside `node_modules` or any `vendor/` path are
reported as info with a `[vendor code]` prefix. Vendor paths also skip
`code.readable` and downgrade `sourcemap.comment`, since that is third-party
code rather than yours.

### Engine and binary surfaces

Surfaces are auto-detected; `unrea_surfaces` (MCP) lists them. Each one adds its own checks:

| Surface | Check IDs |
| --- | --- |
| `unity` | `unity.mono`, `unity.il2cpp.metadata`, `unity.debug_shipped`, `unity.names`, `unity.client_authority`, `unity.plugins`, `unity.saves` |
| `godot` | `godot.encryption_off`, `godot.directory_unencrypted`, `godot.script_text`, `godot.key_in_repo`, `godot.config_shipped`, `godot.encryption_unknown` (reads your export settings; never opens the `.pck`) |
| `dotnet` | `dotnet.readable`, `dotnet.obfuscated`, `dotnet.sensitive_names`, `dotnet.pdb_shipped`, `dotnet.unsigned`, `dotnet.appsettings_shipped` |
| `pyinstaller` | `pyinstaller.bytecode`, `pyinstaller.source_shipped`, `pyinstaller.spec_shipped`, `pyinstaller.python_version` |
| `pe-native` | `pe-native.unsigned`, `pe-native.no_aslr`, `pe-native.no_dep`, `pe-native.no_cfg`, `pe-native.debug_info`, `pe-native.go_buildinfo`, `pe-native.rust_paths`, plus secret scanning of embedded strings |

When two surfaces see the same file, the more specific one owns it. Unity owns
`*_Data/Managed`, `MonoBleedingEdge/` and its engine DLLs, so you don't get
generic noise about Unity's own files. Secrets are always reported.

## Honest limits

- **Obfuscation slows, doesn't stop.** Minifying or obfuscating raises the cost
  of reading a bundle; it does not protect a secret or a business rule.
- **The real fix is keeping secrets and valuable logic on your server.** A
  client can only be trusted with what you are comfortable publishing.
- `asar` extraction is trivial, source maps reconstruct readable code, and fuses
  only raise the bar for casual tampering.
- This is a heuristic scanner, not a pentester. Entropy rules produce false
  positives and can miss short or low-entropy secrets.
- MCP gives an agent the same read-only scan results. Applying a fix plan is
  still a code change that you (or your agent) must review and test.

## Development

```bash
npm install
npm test
node bin/unrea.js scan test/fixtures-or-tmp
node bin/unrea.js mcp
```

Tests use `node:test`, build fixtures in the OS temp directory, create a real
`.asar` with `@electron/asar`, and drive the MCP server with the official SDK
over stdio. Setup tests always set `UNREA_HOME` to a temp directory. No network
access is required.

## FAQ

**Can unrea make my app impossible to crack?**
No, and nothing can. Code running on the user's machine can always be read. unrea helps you make sure that what an attacker gets is worthless: no keys, no server-side rules, no free unlocks.

**Is this an attacking tool?**
No. It only reads builds you point it at, and it's meant for your own apps. It doesn't patch, crack or bypass anything.

**Do I need REA installed?**
No. unrea runs on its own. A future `unrea attack` mode will be able to drive REA against your own build if you have it installed.

**Does it send my code anywhere?**
No. There are no network calls, and scanning happens locally.

## License

MIT © lordon1a
