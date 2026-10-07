#!/usr/bin/env node
'use strict';

/**
 * cli/edge-gpg-shim.js - what git runs as gpg.program inside `okedge exec`
 * (onlykey-edge mcp-service.md §4.2 / §4.2a: "a gpg-compatible signing shim";
 * decided 2026-10-03: it signs itself, no Gpg4win, and holds only the agent's key).
 *
 * git signs a commit by running `<gpg.program> --status-fd=2 -bsau <key>`,
 * writing the commit object to its stdin, and reading an armored detached
 * signature from stdout and gpg's `[GNUPG:] SIG_CREATED` line from the status
 * fd. This does exactly that and nothing else: the agent service makes the
 * signature (cli/edge-agent.js, the agent's own derived PGP key); the exec's
 * one-time token (OKEDGE_GPG_TOKEN, set by `okedge exec`) is what lets the
 * work budget pay for it. Without the token - or once the exec's one use is
 * spent - the key asks for a press. Verifying is not this program's job: it
 * refuses --verify and points at gpg.
 */

const { ask } = require('./edge-control');

const PUBKEY_EDDSA = 22; /* RFC 4880 public-key algorithm (EdDSA legacy, as the certificate) */
const HASH_SHA256 = 8;

function statusFd(args) {
  for (let i = 0; i < args.length; i++) {
    const m = /^--status-fd=(\d+)$/.exec(args[i]);
    if (m) return Number(m[1]);
    if (args[i] === '--status-fd' && args[i + 1]) return Number(args[i + 1]);
  }
  return null;
}

async function main(args, { stdin = process.stdin, stdout = process.stdout, stderr = process.stderr, env = process.env, write = require('fs').writeSync } = {}) {
  if (args.includes('--verify')) {
    stderr.write('onlykey-js edge (gpg): verifying is gpg\'s job - this only signs inside `okedge exec`\n');
    return 2;
  }
  if (!args.some((a) => /^-[a-zA-Z]*b[a-zA-Z]*s|^--detach-sign$/.test(a))) {
    stderr.write(`onlykey-js edge (gpg): only detached signing (-bsau) is supported, not: ${args.join(' ')}\n`);
    return 2;
  }
  const chunks = [];
  for await (const c of stdin) chunks.push(c);
  const data = Buffer.concat(chunks);
  let r;
  try {
    /* the exec's own gpg endpoint (path + key in this exec's environment, 2026-10-06) - no home, no service needed */
    if (!env.OKEDGE_GPG_ENDPOINT || !env.OKEDGE_GPG_KEY) throw new Error('not inside onlykey-js edge exec (no gpg endpoint) - Edge signs only under a budget');
    r = await ask('gpg-sign', { token: env.OKEDGE_GPG_TOKEN || null, data: data.toString('base64') }, { timeoutMs: 60000, where: env.OKEDGE_GPG_ENDPOINT, key: env.OKEDGE_GPG_KEY });
  } catch (e) {
    stderr.write(`onlykey-js edge (gpg): ${e.message}\n`);
    return 1;
  }
  stdout.write(r.armored);
  const fd = statusFd(args);
  const line = `[GNUPG:] SIG_CREATED D ${PUBKEY_EDDSA} ${HASH_SHA256} 00 ${r.created} ${r.fingerprint}\n`;
  if (fd === 1) stdout.write(line);
  else if (fd === 2) stderr.write(`\n${line}`);
  else if (fd !== null) write(fd, line);
  return 0;
}

module.exports = { main, statusFd };

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { process.stderr.write(`onlykey-js edge (gpg): ${e.message}\n`); process.exitCode = 1; });
}
