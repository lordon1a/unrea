/**
 * Static explanations for every check id. The MCP `unrea_explain` tool returns
 * this text so an agent knows what it is looking at before it edits a build.
 */

const entries = new Map();

function add(id, title, what, step, risk, fix) {
  entries.set(id, { title, what, step, risk, fix });
}

function secret(id, title, risk) {
  add(
    id,
    title,
    `${title} value is present in text that ships to users.`,
    'Extract app.asar (or read the bundle), then grep the extracted files for the provider pattern (REA asar-extract + string-grep steps).',
    risk,
    'Revoke and rotate the credential first, remove it from the client, and call the provider from a server-side proxy.',
  );
}

add(
  'secret.*',
  'Credential in the client',
  'Any API key, token, private key or high-entropy literal shipped in client code.',
  'Extract app.asar, run strings/ripgrep over the bundle, and apply the provider regex list (REA asar-extract + string-grep steps).',
  'A live key can be copied and abused for data access, spend or account takeover.',
  'Rotate/revoke it, move the call behind your server, and keep the key only in server environment variables.',
);

secret('secret.aws', 'AWS access key', 'The key can be used with the AWS CLI/SDK; impact depends on its IAM policy.');
secret('secret.openai', 'OpenAI API key', 'The key can be used for billable API calls or model access.');
secret('secret.anthropic', 'Anthropic API key', 'The key can be used for billable API calls or model access.');
secret('secret.stripe.live', 'Stripe live key', 'A live secret key can create charges, refunds or read customer data.');
secret('secret.stripe.test', 'Stripe test key', 'A test key does not move real money, but it still reveals payment integration details.');
secret('secret.github', 'GitHub token', 'The token may read or push repositories depending on its scopes.');
secret('secret.github.pat', 'GitHub fine-grained token', 'The token may read or push repositories depending on its scopes.');
secret('secret.google', 'Google API key', 'The key may be usable against billable Google APIs if it is not restricted.');
secret('secret.slack', 'Slack token', 'The token may read messages or post as the workspace app.');
secret('secret.private_key', 'Private key', 'A private key can impersonate a server, sign tokens or decrypt traffic.');
secret('secret.generic', 'High-entropy client secret', 'The value looks like a credential assigned to a secret-looking name and can be replayed.');
secret(
  'secret.jwt.service_role',
  'Supabase service_role JWT',
  'service_role bypasses row-level security and can read or write every row the database role can reach.',
);
secret(
  'secret.jwt.anon',
  'Supabase anon JWT',
  'The anon key is public by design, but it is only safe when RLS is enabled on every exposed table.',
);

add(
  'sourcemap.*',
  'Source map shipped',
  'A .map file, or a sourceMappingURL comment, lets anyone reconstruct the original sources from the shipped bundle.',
  'Extract app.asar, read the .map file and its sourcesContent, or follow the sourceMappingURL (REA asar-extract + decompile/reconstruct step).',
  'Original TypeScript/JS, internal paths, comments and accidentally embedded secrets become readable.',
  'Disable production source maps in your bundler and exclude "!**/*.map" from the package.',
);
add(
  'sourcemap.file',
  'Source map file shipped',
  'A .map file is packaged with the app.',
  'Extract app.asar and read the map; sourcesContent often contains the complete original source.',
  'Full source disclosure and easier vulnerability discovery.',
  'Disable source maps in production and exclude "!**/*.map" from electron-builder files.',
);
add(
  'sourcemap.comment',
  'Source map reference in code',
  'A //# sourceMappingURL comment still points at a map, even if the map was meant to be private.',
  'Read the last lines of the bundle, fetch the referenced map from the package, and reconstruct the source.',
  'Leaks the original source layout and may reveal secrets embedded in sourcesContent.',
  'Disable source maps in production; rebuild without sourceMappingURL comments.',
);

add(
  'env.file',
  'Dotenv file shipped',
  'A .env* file is included in the packaged app.',
  'Extract app.asar and read the dotenv file directly (REA asar-extract step).',
  'Every value in the file is public, including credentials and internal hostnames.',
  'Delete the file from the build, rotate exposed values, and keep secrets in server environment variables.',
);

add(
  'license.client',
  'Client-side license check',
  'Plan, trial or payment entitlement is decided in code that ships to the user.',
  'Extract and decompile/beautify the bundle, then search for isPro/isLicensed/checkLicense and patch the branch (REA decompile step).',
  'A user can bypass payment or unlock paid features by editing one boolean.',
  'Verify entitlement on your server and return only a short-lived, signed result to the client.',
);

add(
  'code.readable',
  'Unminified JavaScript shipped',
  'A large .js file is packaged without minification.',
  'Extract app.asar, beautify the bundle and read function names, strings and control flow (REA decompile step).',
  'Business logic and hidden endpoints are cheap to understand; it also multiplies the value of any leaked source map.',
  'Minify/obfuscate production bundles and keep valuable logic server-side; obfuscation slows readers but does not stop them.',
);

add(
  'endpoint.internal',
  'Internal or staging endpoint',
  'The build contains a localhost, staging, internal or dev host.',
  'Grep the extracted bundle for URLs and try the hosts from outside the network.',
  'Staging services are often weaker, unauthenticated or connected to production data.',
  'Remove internal hosts from production builds and inject the public API base URL at build time.',
);

add(
  'tests.shipped',
  'Test files shipped',
  'Test/spec files are included in the packaged app or asar.',
  'List asar entries and grep test folders; fixtures often contain credentials, internal URLs and expected behavior.',
  'Source disclosure and a higher chance of real fixture keys or internal details leaking.',
  'Exclude test folders and "*.test.*"/"*.spec.*" from electron-builder files and .npmignore.',
);

add(
  'asar.plain',
  'Asar is not encryption',
  'The app is packaged as an asar archive, which is a concatenated archive rather than an encrypted container.',
  'Extract it in seconds with @electron/asar or any asar tool (REA asar-extract step).',
  'Anyone can read or replace the packaged code unless fuses and signatures are enforced.',
  'Treat asar as packaging only; keep secrets server-side and enable asar integrity/OnlyLoadAppFromAsar fuses.',
);

add(
  'electron.fuses.*',
  'Weak Electron fuses',
  'The Electron binary allows debugging, Node mode, asar swapping or NODE_OPTIONS injection.',
  'Read the fuse wire with @electron/fuses, then use the enabled capability to inspect or modify the app (REA runtime/shipping step).',
  'Attackers can attach a debugger, execute Node code, or swap app.asar for patched code.',
  'Flip the affected fuses at build time with an electron-builder afterPack hook using @electron/fuses.',
);
add(
  'electron.fuses.run_as_node',
  'RunAsNode enabled',
  'The Electron executable can be started as a plain Node.js process with ELECTRON_RUN_AS_NODE=1.',
  'Read the fuse wire, launch the app binary with ELECTRON_RUN_AS_NODE=1, and run arbitrary Node code with the app runtime.',
  'Turns the app into a scriptable Node runtime and eases inspection/tampering.',
  'Set RunAsNode to false with @electron/fuses in an afterPack hook and rebuild.',
);
add(
  'electron.fuses.node_cli_inspect',
  'Node CLI inspect enabled',
  'The binary accepts --inspect/--inspect-brk.',
  'Launch the app with --inspect and attach a debugger to the main process.',
  'Full runtime inspection, breakpoints and memory access.',
  'Set EnableNodeCliInspectArguments to false with @electron/fuses at build time.',
);
add(
  'electron.fuses.asar_integrity',
  'Asar integrity disabled',
  'Electron does not validate the app.asar integrity header at runtime.',
  'Replace app.asar with a patched archive and launch the app.',
  'Code tampering and license bypass become straightforward.',
  'Set EnableEmbeddedAsarIntegrityValidation to true with @electron/fuses at build time.',
);
add(
  'electron.fuses.only_load_app_from_asar',
  'OnlyLoadAppFromAsar disabled',
  'The app can load an unpacked app directory instead of the signed asar.',
  'Drop an app folder next to the binary (or replace resources) and launch it.',
  'Side-loading modified code bypasses asar integrity checks.',
  'Set OnlyLoadAppFromAsar to true with @electron/fuses at build time.',
);
add(
  'electron.fuses.node_options',
  'NODE_OPTIONS injection enabled',
  'The binary honors the NODE_OPTIONS environment variable.',
  'Start the app with NODE_OPTIONS=--require ./payload.js and load code before the app boots.',
  'Arbitrary code execution in the main process.',
  'Set EnableNodeOptionsEnvironmentVariable to false with @electron/fuses at build time.',
);

export const KNOWN_IDS = [...entries.keys()];

const FAMILY_ALIASES = {
  secret: 'secret.*',
  sourcemap: 'sourcemap.*',
  'electron.fuses': 'electron.fuses.*',
};

/**
 * @param {string} id
 * @returns {string}
 */
export function explain(id) {
  const key = FAMILY_ALIASES[id] || id;
  const entry = entries.get(key);
  if (!entry) {
    return [
      `Unknown check id "${id}".`,
      '',
      'Known check ids:',
      ...KNOWN_IDS.map((known) => `- ${known}`),
    ].join('\n');
  }
  return [
    `${id} - ${entry.title}`,
    '',
    `What it is: ${entry.what}`,
    `How an agent finds it: ${entry.step}`,
    `Real risk: ${entry.risk}`,
    `How to fix: ${entry.fix}`,
  ].join('\n');
}

/**
 * Concrete ids an agent can pass to unrea_fix_plan. Family wildcards are not
 * accepted by the fix planner.
 *
 * @returns {string[]}
 */
export function fixPlanIds() {
  return KNOWN_IDS.filter((id) => !id.endsWith('.*'));
}
