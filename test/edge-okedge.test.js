'use strict';

/*
 * The agent service end to end on the fake Edge key: the control endpoint,
 * `okedge`, and the gpg shim run by a REAL `git commit -S` in a scratch repo
 * (onlykey-edge daily-loop.md §5 step 1, minus the emulator). The phone's side
 * is in-process (approve.approveRequest). Checks: the budget opens through
 * okedge; a commit signed inside `okedge exec` carries a signature openpgp
 * verifies against the agent's certificate, and the key's link is paid by the
 * budget; the shim outside an exec still signs, as a press.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-test-'));
process.env.OKEDGE_HOME = HOME;

const openpgp = require('../src/vendor/openpgp/openpgp.js');
const pgpCert = require('../src/crypto/pgp-cert.js');
const { request, approve, client, codes, chain, grants } = require('../src/edge');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');
const agentProto = require('../src/protocol/agent');
const { createEdgeAgent, controlHandlers } = require('../cli/edge-agent');
const { serveControl } = require('../cli/edge-control');
const okedge = require('../cli/okedge');

const AGENT = request.signerFromSecret(new Uint8Array(32).fill(41));
const hex = (b) => Buffer.from(b).toString('hex');
const SHIM = path.resolve(__dirname, '..', 'cli', 'edge-gpg-shim.js').replace(/\\/g, '/');

async function stack() {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.ticket(0, 0, new Uint8Array(32));
  const keys = new Map();
  const keyOf = (identity) => {
    const k = hex(agentProto.identityHash(identity));
    if (!keys.has(k)) keys.set(k, crypto.generateKeyPairSync('ed25519'));
    return keys.get(k);
  };
  const device = {
    async publicKey(identity) { return new Uint8Array(keyOf(identity).publicKey.export({ format: 'der', type: 'spki' }).subarray(12)); },
    async sign(identity, message) {
      transport.use(new Uint8Array([...message, ...agentProto.identityHash(identity)]), { slot: 221 });
      return new Uint8Array(crypto.sign(null, Buffer.from(message), keyOf(identity).privateKey));
    },
  };
  const seen = new Set();
  const notes = []; /* what the agent told the phone (EDGE_NOTE) */
  const channel = {
    async send(msg) {
      if (msg.type === require('../src/edge').note.TYPE) { notes.push(msg); return { ok: true }; }
      const r = await approve.approveRequest(msg, {
        edge, registered: [hex(AGENT.publicKey)], seen, ask: async () => 'approve',
        verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }), timeoutMs: 2000,
      });
      return r.dropped ? null : r;
    },
  };
  const c = client.createEdgeClient({ edge, channel, signer: AGENT });
  const sshIdentity = { ssh: { user: 'claude', host: 'test' } };
  const gpgIdentity = { gpg: 'Claude (agent) <claude@test>' };
  const sshRaw = await device.publicKey(sshIdentity);
  const gpgRaw = await device.publicKey(gpgIdentity);
  /* the agent's certificate - made once at setup (two presses on a real key) */
  const ecdh = crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
  const created = 1700000000;
  const cert = await pgpCert.buildCertificate(openpgp, {
    userId: gpgIdentity.gpg, curve: 'ed25519', created, signPublic: gpgRaw, ecdhPublic: new Uint8Array(ecdh),
    sign: async (d) => new Uint8Array(crypto.sign(null, Buffer.from(d), keyOf(gpgIdentity).privateKey)),
  });
  const agent = createEdgeAgent({ device, edge, client: c, ssh: { identity: sshIdentity, name: 'ssh://claude@test', comment: 'claude@test', curve: 'ed25519', raw: sshRaw } });
  const gpg = { identity: gpgIdentity, name: 'gpg://Claude (agent) <claude@test>', raw: gpgRaw, created, fingerprint: cert.fingerprint, committer: { name: 'Claude (agent)', email: 'claude@test' } };
  const control = await serveControl({ handlers: controlHandlers({ agent, client: c, ssh: { name: 'ssh://claude@test' }, gpg, openpgp, shimCommand: SHIM }) });
  const lastLink = async () => { const hd = await edge.head(); return chain.decodeLink((await edge.pickup(hd.seq, 1))[0].link); };
  return { agent, control, cert, lastLink, edge, notes };
}

function capture() {
  const lines = [];
  return { lines, io: { out: (s) => lines.push(s), err: (s) => lines.push(`ERR ${s}`) } };
}

test('okedge budget, then `git commit -S` inside okedge exec: the commit is signed by the agent\'s key and paid by the budget', async () => {
  const s = await stack();
  try {
    let cap = capture();
    assert.equal(await okedge.main(['budget', '--reason', 'work: commit + push', '--ssh', '2', '--gpg', '2', '--ttl', '60'], cap.io), 0, cap.lines.join('\n'));
    const head = cap.lines.find((l) => l.startsWith('head = ')).slice(7);

    const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-repo-'));
    execFileSync('git', ['-C', repo, 'init', '-q']);
    execFileSync('git', ['-C', repo, 'config', 'user.name', 'Claude (agent)']);
    execFileSync('git', ['-C', repo, 'config', 'user.email', 'claude@test']);
    cap = capture();
    const code = await okedge.main(['exec', '--head', head, '--reason', 'commit: an Edge test', '--', 'git', '-C', repo, 'commit', '-q', '--allow-empty', '-S', '-m', 'edge: signed by the agent'], cap.io);
    assert.equal(code, 0, cap.lines.join('\n'));
    assert.ok(cap.lines.some((l) => /^signed: link #\d+ \(gpg\) - ticket owed for #\d+$/.test(l)), cap.lines.join('\n'));
    assert.equal((await s.lastLink()).decision, codes.DECISION.SELF_PRESS, 'paid by the budget');

    /* the commit carries a signature that verifies against the agent's certificate */
    const raw = execFileSync('git', ['-C', repo, 'cat-file', 'commit', 'HEAD']).toString('utf8');
    const m = /\ngpgsig (-----BEGIN PGP SIGNATURE-----[\s\S]*?-----END PGP SIGNATURE-----)\n/.exec(raw);
    assert.ok(m, 'no gpgsig in the commit');
    const armored = m[1].replace(/\n /g, '\n');
    const payload = raw.replace(/gpgsig -----BEGIN PGP SIGNATURE-----[\s\S]*?-----END PGP SIGNATURE-----\n/, '');
    const { signatures } = await openpgp.verify({
      message: await openpgp.createMessage({ binary: new TextEncoder().encode(payload) }),
      signature: await openpgp.readSignature({ armoredSignature: armored }),
      verificationKeys: await openpgp.readKey({ armoredKey: s.cert.armored }),
    });
    await assert.doesNotReject(signatures[0].verified, 'the commit signature does not verify');
    assert.match(raw, /\ncommitter Claude \(agent\) <claude@test> /, 'the committer is the agent');

    /* the ticket, then a stale head is refused by okedge itself, before the command runs */
    const seq = Number(/link #(\d+)/.exec(cap.lines.find((l) => l.startsWith('signed:')))[1]);
    cap = capture();
    assert.equal(await okedge.main(['ticket', String(seq), '--msg', 'committed edge test'], cap.io), 0, cap.lines.join('\n'));
    cap = capture();
    assert.equal(await okedge.main(['exec', '--head', head, '--reason', 'x', '--', 'git', '--version'], cap.io), 1);
    assert.match(cap.lines.join('\n'), /--head is not the budget's head/);
  } finally {
    await s.agent.closeAll();
    await s.control.close();
  }
});

test('the gpg shim outside an exec still signs - as a press, not paid by the budget', async () => {
  const s = await stack();
  try {
    const cap = capture();
    assert.equal(await okedge.main(['budget', '--reason', 'work', '--gpg', '1', '--ttl', '30'], cap.io), 0, cap.lines.join('\n'));
    /* async: this process serves the control endpoint the shim talks to - a sync spawn would deadlock it */
    const out = await new Promise((resolve, reject) => {
      const p = require('child_process').spawn(process.execPath, [SHIM, '--status-fd=2', '-bsau', 'x'], { env: { ...process.env, OKEDGE_GPG_TOKEN: '' } });
      let o = '';
      p.stdout.on('data', (d) => { o += d; });
      p.on('error', reject);
      p.on('exit', () => resolve(o));
      p.stdin.end('some data');
    });
    assert.match(out, /BEGIN PGP SIGNATURE/);
    assert.equal((await s.lastLink()).decision, codes.DECISION.APPROVE, 'a press - no exec, no budget');
  } finally {
    await s.agent.closeAll();
    await s.control.close();
  }
});

test('okedge exec returns the command\'s own exit code', async () => {
  const s = await stack();
  try {
    let cap = capture();
    await okedge.main(['budget', '--reason', 'work', '--ssh', '1', '--ttl', '30'], cap.io);
    const head = cap.lines.find((l) => l.startsWith('head = ')).slice(7);
    cap = capture();
    assert.equal(await okedge.main(['exec', '--head', head, '--reason', 'fails', '--', process.execPath, '-e', 'process.exit(7)'], cap.io), 7);
    assert.ok(cap.lines.includes('signed: nothing under the budget'));
  } finally {
    await s.agent.closeAll();
    await s.control.close();
  }
});

test('okedge watch --once: one line per use with its reason, its ticket under it; an ordinary press shows nothing (not Edge, 2026-10-06)', async () => {
  const s = await stack();
  try {
    let cap = capture();
    await okedge.main(['budget', '--reason', 'work', '--ssh', '1', '--gpg', '2', '--ttl', '30'], cap.io);
    const head = cap.lines.find((l) => l.startsWith('head = ')).slice(7);
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-watch-'));
    execFileSync('git', ['-C', repo, 'init', '-q']);
    execFileSync('git', ['-C', repo, 'config', 'user.name', 'Claude (agent)']);
    execFileSync('git', ['-C', repo, 'config', 'user.email', 'claude@test']);
    cap = capture();
    await okedge.main(['exec', '--head', head, '--reason', 'commit: watch me', '--', 'git', '-C', repo, 'commit', '-q', '--allow-empty', '-S', '-m', 'w'], cap.io);
    const seq = Number(/link #(\d+)/.exec(cap.lines.find((l) => l.startsWith('signed:')) || 'link #0')[1]);
    await okedge.main(['ticket', String(seq), '--msg', 'committed\nwith a newline'], capture().io);
    /* a pressed sign with the agent's key while the budget covers it (the shim outside an exec): an ordinary press, no link */
    await new Promise((resolve) => {
      const p = require('child_process').spawn(process.execPath, [SHIM, '--status-fd=2', '-bsau', 'x'], { env: { ...process.env, OKEDGE_GPG_TOKEN: '' } });
      p.on('exit', resolve);
      p.stdin.end('data');
    });
    cap = capture();
    assert.equal(await okedge.main(['watch', '--once'], cap.io), 0, cap.lines.join('\n'));
    const text = cap.lines.join('\n');
    assert.match(text, new RegExp(`#${seq} \\d\\d:\\d\\d:\\d\\d sign slot 221 · self-press · budget \\d+, use 1 · "commit: watch me"`));
    assert.match(text, new RegExp(`↳ #\\d+ ticket for #${seq}: OK · "committed with a newline"`), 'the message on one plain line');
    assert.doesNotMatch(text, /a press asked for under a live budget/, 'the B7 alarm is gone');
    assert.doesNotMatch(text, /sign slot 221 · pressed/, 'an ordinary press writes no link, so watch has no line for it');
  } finally {
    await s.agent.closeAll();
    await s.control.close();
  }
});

test('okedge exec --press is gone (Brad, 2026-10-06, R13b: budget or no go) - refused before anything runs', async () => {
  const s = await stack();
  try {
    const cap = capture();
    assert.equal(await okedge.main(['exec', '--press', '--intent', 'commit: pressed', '--', 'git', '--version'], cap.io), 2);
    assert.match(cap.lines.join(' | '), /--press was removed - Edge signs only under a budget/);
  } finally {
    await s.control.close();
  }
});

test('an owed ticket filed after the agent lost its budget: straight to the key, its message reaches the phone, the head prints as hex', async () => {
  const s = await stack();
  try {
    let cap = capture();
    assert.equal(await okedge.main(['budget', '--reason', 'work', '--gpg', '1', '--ttl', '60'], cap.io), 0, cap.lines.join('\n'));
    const head = cap.lines.find((l) => l.startsWith('head = ')).slice(7);
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-owed-'));
    execFileSync('git', ['-C', repo, 'init', '-q']);
    execFileSync('git', ['-C', repo, 'config', 'user.name', 'Claude (agent)']);
    execFileSync('git', ['-C', repo, 'config', 'user.email', 'claude@test']);
    cap = capture();
    assert.equal(await okedge.main(['exec', '--head', head, '--reason', 'commit: owed', '--', 'git', '-C', repo, 'commit', '-q', '--allow-empty', '-S', '-m', 'o'], cap.io), 0, cap.lines.join(' | '));
    const seq = Number(/link #(\d+)/.exec(cap.lines.find((l) => l.startsWith('signed:')))[1]);
    /* the agent restarted: it has no budget, the key still owes the ticket */
    s.agent.setBudget(null);
    cap = capture();
    assert.equal(await okedge.main(['ticket', String(seq), '--msg', 'committed o'], cap.io), 0, cap.lines.join(' | '));
    /* the head prints as hex (it printed "[object Object]" on this path, Pixel #431) */
    assert.match(cap.lines.join(' | '), /head = [0-9a-f]{64}/);
    /* and the phone gets the message (it showed "No message synced", Pixel #432) */
    assert.ok(s.notes.some((n) => n.seq === seq && n.ticketMsg === 'committed o'), 'the ticket message reaches the phone');
  } finally {
    await s.control.close();
  }
});
