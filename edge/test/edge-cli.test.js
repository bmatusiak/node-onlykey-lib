'use strict';

/*
 * The agent service end to end on the fake Edge key: the control endpoint,
 * `onlykey-js edge`, and the gpg shim run by a REAL `git commit -S` in a scratch repo
 * (onlykey-edge daily-loop.md §5 step 1, minus the emulator). The phone's side
 * is in-process (approve.approveRequest). Checks: the budget opens through
 * okedge; a commit signed inside `onlykey-js edge exec` carries a signature openpgp
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
require('../cli/control').setHome(HOME); /* a test home: setHome, never the env (CLI.md §5) */

const openpgp = require('../../src/vendor/openpgp/openpgp.js');
const pgpCert = require('../../src/crypto/pgp-cert.js');
const { request, approve, client, codes, chain, grants } = require('../src');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');
const agentProto = require('../../src/protocol/agent');
const { createEdgeAgent, controlHandlers } = require('../cli/agent');
const { serveControl } = require('../cli/control');
/* onlykey-js edge's commands (edge/cli/commands.js; okedge is gone, 2026-10-06) over the real control endpoint, with the dev set */
const okedge = { main: (args, io = {}) => require('../cli/commands').main(args, { ask: require('../cli/control').ask, dev: require('../cli/dev'), ...io }) };

const AGENT = request.signerFromSecret(new Uint8Array(32).fill(41));
const hex = (b) => Buffer.from(b).toString('hex');
const SHIM = path.resolve(__dirname, '..', 'cli', 'gpg-shim.js').replace(/\\/g, '/');

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
      if (msg.type === require('../src').note.TYPE) { notes.push(msg); return { ok: true }; }
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
  const handlers = controlHandlers({ agent, client: c, ssh: { name: 'ssh://claude@test' }, gpg, openpgp, shimCommand: SHIM });
  const control = await serveControl({ handlers });
  const lastLink = async () => { const hd = await edge.head(); return chain.decodeLink((await edge.pickup(hd.seq, 1))[0].link); };
  return { agent, control, handlers, cert, lastLink, edge, notes };
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

test('the gpg shim outside an exec is refused - budget or no go: no signature, no link (CLI.md §3-4, 2026-10-06)', async () => {
  const s = await stack();
  try {
    const cap = capture();
    assert.equal(await okedge.main(['budget', '--reason', 'work', '--gpg', '1', '--ttl', '30'], cap.io), 0, cap.lines.join('\n'));
    /* async: this process serves the control endpoint the shim talks to - a sync spawn would deadlock it */
    const before = await s.edge.head();
    const r = await new Promise((resolve, reject) => {
      const p = require('child_process').spawn(process.execPath, [SHIM, '--status-fd=2', '-bsau', 'x'], { env: { ...process.env, OKEDGE_GPG_TOKEN: '' } });
      let o = '';
      let e = '';
      p.stdout.on('data', (d) => { o += d; });
      p.stderr.on('data', (d) => { e += d; });
      p.on('error', reject);
      p.on('exit', (code) => resolve({ code, out: o, err: e }));
      p.stdin.end('some data');
    });
    assert.notEqual(r.code, 0, 'the shim signed outside an exec');
    assert.doesNotMatch(r.out, /BEGIN PGP SIGNATURE/);
    assert.match(r.err, /not inside onlykey-js edge exec/);
    assert.equal((await s.edge.head()).seq, before.seq, 'no link');
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
    assert.ok(cap.lines.includes('signed: nothing under the budget - the command failed before a sign'));
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

/* CLI.md §4, §7 (2026-10-06): no service - the command runs the handlers in this process, as edge/cli/register.js does */
const localAsk = (handlers) => async (op, fields = {}, o = {}) => {
  if (o.onSent) o.onSent();
  return { ok: true, ...(await handlers[op](fields)) };
};
const listening = (p) => new Promise((resolve) => {
  const k = require('net').connect(p);
  k.once('connect', () => { k.destroy(); resolve(true); });
  k.once('error', () => resolve(false));
});

test('no service: edge exec signs under a budget in-process and leaves nothing listening afterwards (CLI.md §7)', async () => {
  const s = await stack();
  try {
    let cap = capture();
    assert.equal(await okedge.main(['budget', '--reason', 'work', '--gpg', '1', '--ttl', '30'], { ...cap.io, ask: localAsk(s.handlers) }), 0, cap.lines.join(' | '));
    const head = cap.lines.find((l) => l.startsWith('head = ')).slice(7);
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-local-'));
    execFileSync('git', ['-C', repo, 'init', '-q']);
    execFileSync('git', ['-C', repo, 'config', 'user.name', 'Claude (agent)']);
    execFileSync('git', ['-C', repo, 'config', 'user.email', 'claude@test']);
    let seen = null;
    const spawnFn = (cmd, argv, o) => { seen = o.env; return require('child_process').spawn(cmd, argv, o); };
    cap = capture();
    assert.equal(await okedge.main(['exec', '--head', head, '--intent', 'commit: in-process', '--', 'git', '-C', repo, 'commit', '-q', '--allow-empty', '-S', '-m', 'l'], { ...cap.io, ask: localAsk(s.handlers), spawnFn }), 0, cap.lines.join(' | '));
    assert.equal((await s.lastLink()).decision, codes.DECISION.SELF_PRESS, 'paid by the budget');
    assert.ok(seen && seen.SSH_AUTH_SOCK && seen.OKEDGE_GPG_ENDPOINT, 'the exec gave its command its own ssh and gpg endpoints');
    for (const p of [seen.SSH_AUTH_SOCK, seen.OKEDGE_GPG_ENDPOINT]) assert.equal(await listening(p), false, `still listening after the exec: ${p}`);
  } finally {
    await s.control.close();
  }
});

test('edge exec with no live budget is refused at once: no prompt, no link (CLI.md §7)', async () => {
  const s = await stack();
  try {
    const before = await s.edge.head();
    const cap = capture();
    const code = await okedge.main(['exec', '--head', '00'.repeat(32), '--intent', 'x', '--', 'git', '--version'], { ...cap.io, ask: localAsk(s.handlers) });
    assert.notEqual(code, 0);
    assert.match(cap.lines.join(' | '), /no work budget/);
    assert.equal((await s.edge.head()).seq, before.seq, 'no link');
  } finally {
    await s.control.close();
  }
});

/*
 * A FAILED COMMAND FILES A FAILED TICKET (Brad, 2026-10-07: "when a push does not
 * reach, it should give back a failed ticket"): its use gets TARGET_UNREACHABLE
 * (0x21) with the command and its exit code - not left owed, never OK.
 */
test('edge exec: the command signs, then fails - its use gets a TARGET_UNREACHABLE ticket at once', async () => {
  const s = await stack();
  try {
    let cap = capture();
    assert.equal(await okedge.main(['budget', '--reason', 'work', '--gpg', '1', '--ttl', '30'], { ...cap.io, ask: localAsk(s.handlers) }), 0, cap.lines.join(' | '));
    const head = cap.lines.find((l) => l.startsWith('head = ')).slice(7);
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-fail-'));
    execFileSync('git', ['-C', repo, 'init', '-q']);
    execFileSync('git', ['-C', repo, 'config', 'user.name', 'Claude (agent)']);
    execFileSync('git', ['-C', repo, 'config', 'user.email', 'claude@test']);
    /* signs a commit, then fails as a push that did not reach would */
    const script = `require('child_process').execFileSync('git', ['-C', ${JSON.stringify(repo)}, 'commit', '-q', '--allow-empty', '-S', '-m', 'l'], {stdio: 'inherit'}); process.exit(3)`;
    cap = capture();
    const code = await okedge.main(['exec', '--head', head, '--intent', 'push: does not reach', '--', process.execPath, '-e', script], { ...cap.io, ask: localAsk(s.handlers) });
    assert.equal(code, 3, cap.lines.join(' | '));
    const last = await s.lastLink();
    assert.equal(last.op, codes.OP.TICKET, 'the use is ticketed, not left owed');
    assert.equal(last.code, 0x21, 'TARGET_UNREACHABLE, not OK');
    assert.ok(cap.lines.some((l) => /ticket filed \(TARGET_UNREACHABLE\)/.test(l)), cap.lines.join(' | '));
  } finally {
    await s.control.close();
  }
});
