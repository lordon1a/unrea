import { readFileSync } from 'node:fs';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import { buildResult, countBySeverity, topFixes } from './core/report.js';
import { loadSurfaces } from './core/surfaces.js';
import { createScanContext } from './core/walk.js';
import { scan } from './scan.js';
import { explain } from './explain.js';
import { buildFixPlan } from './fix-plan.js';

const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const SEVERITY_WEIGHT = { critical: 4, high: 3, medium: 2, info: 1 };

function textResult(text, isError = false) {
  return {
    content: [{ type: 'text', text }],
    ...(isError ? { isError: true } : {}),
  };
}

async function scanPayload({ path, min_severity = 'medium', max_findings = 50 }) {
  const scanResult = await scan(path);
  const result = buildResult(scanResult);
  const minimum = SEVERITY_WEIGHT[min_severity] ?? SEVERITY_WEIGHT.medium;
  const filtered = result.findings.filter(
    (finding) => (SEVERITY_WEIGHT[finding.severity] || 0) >= minimum,
  );
  const capped = filtered.slice(0, max_findings);
  const counts = countBySeverity(result.findings);
  const accepted = result.findings.filter((finding) => finding.accepted).length;

  return {
    grade: result.grade,
    mode: result.mode,
    surfaces: result.surfaces,
    scanned: result.scanned,
    accepted,
    summary: {
      critical: counts.critical,
      high: counts.high,
      medium: counts.medium,
      info: counts.info,
    },
    top_fixes: topFixes(result.findings, 3),
    ...(scanResult.accept?.warnings?.length ? { warnings: scanResult.accept.warnings } : {}),
    findings: capped,
    truncated: filtered.length > capped.length,
  };
}

/**
 * Build the MCP server without binding a transport. Exported for tests.
 *
 * @returns {McpServer}
 */
export function createMcpServer() {
  const server = new McpServer({ name: 'unrea', version: packageJson.version });

  server.registerTool(
    'unrea_scan',
    {
      title: 'Scan a built app for client-side exposure',
      description:
        'Scan a directory, win-unpacked folder or .asar file from a built Electron/JS app. ' +
        'Returns grade, mode, severity counts, top fixes and masked findings (default min severity: medium, max 50 findings). ' +
        'Accepted findings carry accepted: true and reason and do not affect the grade. ' +
        'Secrets are always masked; rotate any real secret.',
      inputSchema: {
        path: z.string().min(1).describe('Directory or .asar file to scan'),
        min_severity: z
          .enum(['info', 'medium', 'high', 'critical'])
          .default('medium')
          .describe('Lowest severity to include in findings (default medium)'),
        max_findings: z
          .number()
          .int()
          .min(0)
          .default(50)
          .describe('Maximum number of findings to return (default 50; 0 returns none)'),
      },
    },
    async ({ path, min_severity, max_findings }) => {
      try {
        const payload = await scanPayload({
          path,
          min_severity: min_severity ?? 'medium',
          max_findings: max_findings ?? 50,
        });
        return textResult(JSON.stringify(payload, null, 2));
      } catch (error) {
        return textResult(`unrea_scan failed: ${error.message}`, true);
      }
    },
  );

  server.registerTool(
    'unrea_explain',
    {
      title: 'Explain an unrea check',
      description:
        'Explain what a check id means, how an attacker with an AI/reverse-engineering agent finds it, ' +
        'the real risk, and how to fix it. Unknown ids return the known id list.',
      inputSchema: {
        id: z.string().min(1).describe('Check id, for example secret.openai or tests.shipped'),
      },
    },
    async ({ id }) => textResult(explain(id)),
  );

  server.registerTool(
    'unrea_fix_plan',
    {
      title: 'Get a concrete fix plan',
      description:
        'Return a concrete, agent-applied fix for a finding id (fuse hook, electron-builder exclusions, ' +
        'source map flags, server proxy outline, license check outline). unrea never edits your files.',
      inputSchema: {
        path: z.string().min(1).describe('Project path used to detect electron-builder config'),
        id: z.string().min(1).describe('Check id from unrea_scan, for example tests.shipped'),
      },
    },
    async ({ path, id }) => {
      try {
        const plan = await buildFixPlan(id, path);
        return textResult(plan.text, !plan.ok);
      } catch (error) {
        return textResult(`unrea_fix_plan failed: ${error.message}`, true);
      }
    },
  );

  server.registerTool(
    'unrea_surfaces',
    {
      title: 'List unrea surfaces',
      description:
        'List the installed analysis surfaces (id, title, covers). If path is given, also report whether each surface detects that target.',
      inputSchema: {
        path: z
          .string()
          .min(1)
          .optional()
          .describe('Optional target path used to run cheap surface detection'),
      },
    },
    async ({ path }) => {
      try {
        const surfaces = await loadSurfaces();
        let detected = null;
        if (path) {
          const built = await createScanContext(path);
          detected = new Set();
          try {
            for (const surface of surfaces) {
              if (typeof surface.detect !== 'function' || (await surface.detect(built.context))) {
                detected.add(surface.id);
              }
            }
          } finally {
            await built.cleanup();
          }
        }

        const list = surfaces.map((surface) => ({
          id: surface.id,
          title: surface.title,
          covers: surface.covers,
          ...(path ? { detected: detected.has(surface.id) } : {}),
        }));
        return textResult(JSON.stringify(list, null, 2));
      } catch (error) {
        return textResult(`unrea_surfaces failed: ${error.message}`, true);
      }
    },
  );

  return server;
}

/**
 * Start the stdio MCP server. Nothing may be written to stdout outside MCP.
 */
export async function startMcpServer() {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
