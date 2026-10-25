---
name: unrea
description: Use when building or releasing a desktop/Electron/JS app, before shipping a build, or when the user asks about protecting against reverse engineering / REA.
---

# unrea

Use unrea to look at your own build the way an AI reverse-engineering agent
(like REA) would. unrea only reads and reports; you apply the fixes.

## Rules while writing code

- Never ship API keys, tokens or private keys in the client. Keep them in
  server-side environment variables and call providers through your server.
- Check licenses, plans and payments on the server. The client may render the
  result, but a local boolean is not enforcement.
- Keep valuable business logic server-side; the client should need only what it
  displays.
- Do not package tests, source maps, `.env*` files or readable unminified
  bundles. Set electron-builder `files` exclusions.
- Flip Electron fuses at build time: RunAsNode off, Node CLI inspect off,
  NODE_OPTIONS off, asar integrity on, OnlyLoadAppFromAsar on.

## Release loop

1. Build the app.
2. Call MCP tool `unrea_scan` with the build path. Or run
   `npx @yigitguldal/unrea scan <path>` in a terminal.
3. For each high/critical finding, call `unrea_explain` with the id, then
   `unrea_fix_plan` with the project path and id.
4. Apply the plan yourself. unrea never edits files.
5. Rebuild and rescan. Repeat until there are no high or critical findings.

Real secrets are masked in reports. Rotate any secret that was ever packaged;
removing it from the next build is not enough.

## Tools

- `unrea_scan` - grade, severity counts, top fixes and masked findings.
- `unrea_explain` - what a check means, how an attacker finds it, how to fix it.
- `unrea_fix_plan` - concrete fuse hook, package exclusions, proxy or license
  outline for the agent to apply.
- `unrea_surfaces` - list installed analysis surfaces and whether they detect a
  given path.
