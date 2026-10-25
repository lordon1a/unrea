import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export async function makeTemp(prefix = 'unrea-test-') {
  return mkdtemp(path.join(os.tmpdir(), prefix));
}

export async function writeAt(root, relative, content) {
  const target = path.join(root, relative);
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, content, 'utf8');
  return target;
}

/**
 * Fake credentials, always assembled from pieces so no complete key-shaped
 * literal lives in the repository.
 */
export const fake = {
  aws: () => 'AKIA' + 'X'.repeat(16),
  openai: () => 'sk-' + 'proj-' + 'aB3xK9mP2qR7sT5vW8yZ4nC6',
  anthropic: () => 'sk-' + 'ant-' + 'aB3xK9mP2qR7sT5vW8yZ4nC6',
  stripeLive: () => 'sk_' + 'live_' + 'aB3xK9mP2qR7sT5v',
  stripeTest: () => 'sk_' + 'test_' + 'aB3xK9mP2qR7sT5v',
  githubClassic: () => 'ghp_' + 'aB3'.repeat(12),
  githubPat: () => 'github_' + 'pat_' + 'aB3xK9mP2qR7sT5vW8yZ4nC6dF1gH2jK3lM4nP5q',
  google: () => 'AIza' + 'aB3xK9mP2qR7sT5vW8yZ4nC6dF1gH2jK3lM',
  slack: () => 'xoxb-' + '1234567890-abcd',
  generic: () => 'aB3xK9mP2qR7sT5vW8yZ4nC6dF1gH2j',
  jwt: (payload) => {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = 's'.repeat(24);
    return `${header}.${body}.${signature}`;
  },
};

/**
 * Build a tiny file that passes for an Electron binary as far as
 * @electron/fuses is concerned: sentinel + version + wire length + states.
 */
export function fakeFuseBinary(states) {
  const sentinel = 'dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX';
  const wire = Buffer.from(states.map((state) => (state ? 0x31 : 0x30)));
  return Buffer.concat([
    Buffer.alloc(64, 0x90),
    Buffer.from(sentinel, 'ascii'),
    Buffer.from([0x01, wire.length]), // fuse wire version 1, then wire length
    wire,
  ]);
}
