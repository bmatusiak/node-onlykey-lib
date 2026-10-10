/*
 * `onlykey-js agent` - the SSH agent over the derived keys (cli/ssh-wire.js,
 * cli/ssh-agent.js, COMMANDS.agent).
 *
 * Three layers, the same three the code has:
 *
 *   the bytes   framing, string/mpint, the key and signature blobs, and
 *               lib-agent's identity grammar - against ssh-keygen's own
 *               output where there is one, not against this file's opinion
 *   the handler one message in, one reply out
 *   end to end  main() serving a REAL socket (a named pipe on Windows) over
 *               the fake firmware's K132 derivation, and this file talking
 *               to it as ssh would: list the keys, ask for a signature, and
 *               verify it with node:crypto against the listed key
 *
 * The live proofs - ssh-add -L, a real ssh login, parity with python's
 * onlykey-agent on the same device - need a device and an sshd; they are in
 * the F1 report, not here.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');

const wire = require('../cli/ssh-wire');
const agentSrv = require('../cli/ssh-agent');
const { main } = require('../cli/index');
const { startDesktop } = require('../cli/desktop');
const { fakeFirmware } = require('./helpers/fake-firmware');
const { sha256 } = require('../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');

const hex = (b) => Buffer.from(b).toString('hex');
const K132 = new Uint8Array(32).map((_, i) => (i * 29 + 7) & 0xff);

/* ssh-keygen's own public blobs (test/keys.ssh.test.js's throwaway keys). */
const KEYGEN_ED25519 = 'AAAAC3NzaC1lZDI1NTE5AAAAIIr+rCfJzqNktMETws8nswLa2nKO0CxRMnL4c92VwyNO';
const KEYGEN_ECDSA = 'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDLBFRBtETVTQR8pgeodtdIOn2KEZFRijLpTvUFh8bjvHehSjMOpbzztCg5IJLPq28tIylAd22jsvJWUUH0eClc=';

/* ------------------------------------------------------------ the bytes */

test('string and uint32 are RFC 4251: a big-endian length, then the bytes', () => {
  assert.equal(hex(wire.uint32(0x01020304)), '01020304');
  assert.equal(hex(wire.string('ab')), '000000026162');
  assert.equal(hex(wire.string(Buffer.alloc(0))), '00000000');
});

test('mpint is canonical: sign byte only when the top bit is set, no other leading zeros', () => {
  assert.equal(hex(wire.mpint(Buffer.of(0))), '00000000', 'zero is the empty string');
  assert.equal(hex(wire.mpint(Buffer.alloc(32))), '00000000');
  assert.equal(hex(wire.mpint(Buffer.of(0x7f))), '000000017f');
  assert.equal(hex(wire.mpint(Buffer.of(0x80))), '000000020080', 'a set top bit would read as negative');
  assert.equal(hex(wire.mpint(Buffer.of(0, 0, 0x12, 0x34))), '000000021234', 'leading zero bytes dropped');
  assert.equal(hex(wire.mpint(Buffer.of(0, 0x80, 1))), '00000003008001', 'dropped, then the sign byte');
});

test('frame, and a Reader that refuses to run past the end', () => {
  assert.equal(hex(wire.frame(Buffer.of(11))), '000000010b');
  const r = new wire.Reader(Buffer.concat([Buffer.of(13), wire.string('key'), wire.uint32(4)]));
  assert.equal(r.uint8(), 13);
  assert.equal(r.string().toString(), 'key');
  assert.equal(r.uint32(), 4);
  assert.equal(r.remaining, 0);
  assert.throws(() => r.uint8(), /truncated/);
  assert.throws(() => new wire.Reader(Buffer.from('00000009ab', 'hex')).string(), /truncated/);
});

test('the deframer joins split messages, splits joined ones, and refuses a silly length', () => {
  const got = [];
  const feed = wire.createDeframer((m) => got.push(hex(m)));
  const two = Buffer.concat([wire.frame(Buffer.of(11)), wire.frame(Buffer.of(13, 1, 2))]);
  for (const b of two) feed(Buffer.of(b));          // one byte at a time
  feed(Buffer.concat([two, two.subarray(0, 3)]));     // two and a bit
  feed(two.subarray(3));                              // the rest of the bit
  assert.deepEqual(got, ['0b', '0d0102', '0b', '0d0102', '0b', '0d0102']);

  assert.throws(() => wire.createDeframer(() => {})(wire.uint32(wire.MAX_MESSAGE + 1)), /not a message/);
  assert.throws(() => wire.createDeframer(() => {})(wire.uint32(0)), /not a message/);
});

test('the key blobs are byte for byte what ssh-keygen writes', () => {
  const ed = Buffer.from(KEYGEN_ED25519, 'base64');
  assert.equal(wire.publicKeyBlob('ed25519', ed.subarray(-32)).toString('base64'), KEYGEN_ED25519);

  /* The device's P-256 reply is X||Y: ssh-keygen's Q without its 04. */
  const ec = Buffer.from(KEYGEN_ECDSA, 'base64');
  assert.equal(ec[ec.length - 65], 4);
  assert.equal(wire.publicKeyBlob('nist256p1', ec.subarray(-64)).toString('base64'), KEYGEN_ECDSA);

  assert.throws(() => wire.publicKeyBlob('ed25519', Buffer.alloc(64)), /32 bytes/);
  assert.throws(() => wire.publicKeyBlob('nist256p1', Buffer.alloc(65)), /64 bytes/);
  assert.throws(() => wire.publicKeyBlob('secp256k1', Buffer.alloc(64)), /offers/);
});

test('an ECDSA signature blob is name + (mpint r, mpint s), and it verifies', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const data = Buffer.from('an ssh userauth request');
  /* Enough signatures that r or s with a set top bit (and a leading zero) turn up. */
  for (let i = 0; i < 20; i += 1) {
    const sig = crypto.sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
    const r = new wire.Reader(wire.signatureBlob('nist256p1', sig));
    assert.equal(r.string().toString(), 'ecdsa-sha2-nistp256');
    const inner = new wire.Reader(r.string());
    const rr = inner.string();
    const ss = inner.string();
    assert.equal(inner.remaining, 0);
    for (const m of [rr, ss]) {
      assert.ok(m.length <= 33 && !(m[0] & 0x80), 'positive');
      if (m.length > 1) assert.ok(m[0] !== 0 || (m[1] & 0x80), 'no redundant zero');
    }
    const p1363 = Buffer.concat([rr, ss].map((m) => {
      const t = m[0] === 0 ? m.subarray(1) : m;
      return Buffer.concat([Buffer.alloc(32 - t.length), t]);
    }));
    assert.ok(crypto.verify('sha256', data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, p1363));
  }
});

test('an Ed25519 signature blob is name + the 64 bytes', () => {
  const sig = Buffer.alloc(64, 7);
  assert.equal(hex(wire.signatureBlob('ed25519', sig)),
    `0000000b${hex(Buffer.from('ssh-ed25519'))}00000040${hex(sig)}`);
});

test('identities parse as lib-agent\'s regex parses them', () => {
  assert.deepEqual(wire.parseIdentity('okt@example.com'), { proto: 'ssh', user: 'okt', host: 'example.com' });
  assert.deepEqual(wire.parseIdentity('example.com'), { proto: 'ssh', host: 'example.com' });
  /* python's greedy user group: everything up to the LAST @ is the user. */
  assert.deepEqual(wire.parseIdentity('ssh://a@b@c:2222/x/y'),
    { proto: 'ssh', user: 'a@b', host: 'c', port: '2222', path: '/x/y' });
  assert.equal(wire.identityComment(wire.parseIdentity('okt@example.com'), 'ed25519'),
    '<ssh://okt@example.com|ed25519>', 'the comment lib-agent prints');
  assert.equal(wire.identityComment(wire.parseIdentity('ssh://okt@example.com:22'), 'nist256p1'),
    '<ssh://okt@example.com:22|nist256p1>');
  /* Only user and host reach the device - port, path and proto do not. */
  assert.deepEqual(wire.derivationIdentity(wire.parseIdentity('ssh://okt@example.com:22/p')),
    { ssh: { user: 'okt', host: 'example.com' } });
  assert.throws(() => wire.parseIdentity('okt@'), /names no host/);
});

test('an identity file is every <identity|curve> in it - so saved key lines are one', () => {
  const text = 'ssh-ed25519 AAAA <ssh://a@h1|ed25519>\necdsa-sha2-nistp256 AAAA <ssh://b@h2:22|nist256p1>\n';
  const got = wire.parseIdentityFile(text);
  assert.equal(got.length, 2);
  assert.deepEqual(got[1], { identity: { proto: 'ssh', user: 'b', host: 'h2', port: '22' }, curve: 'nist256p1' });
  assert.throws(() => wire.parseIdentityFile('<a@h|rsa2048>'), /offers/);
});

/* ------------------------------------------------------------ the handler */

test('the handler: unknown key, unknown message, and a signature that does not verify are FAILURE', async () => {
  const sk = new Uint8Array(32).fill(5);
  const raw = ed25519.getPublicKey(sk);
  const logs = [];
  let bad = false;
  const h = agentSrv.createAgentHandler({
    keys: [{ curve: 'ed25519', raw, comment: 'c' }],
    sign: async (key, data) => (bad ? new Uint8Array(64) : ed25519.sign(data, sk)),
    log: (l) => logs.push(l),
  });
  const blob = wire.publicKeyBlob('ed25519', raw);
  const signReq = (keyBlob) => Buffer.concat([Buffer.of(13), wire.string(keyBlob), wire.string('data'), wire.uint32(0)]);

  assert.equal((await h.handle(signReq(blob)))[4], 14);
  assert.equal(hex(await h.handle(signReq(wire.publicKeyBlob('ed25519', new Uint8Array(32))))), '0000000105');
  assert.equal(hex(await h.handle(Buffer.concat([Buffer.of(27), wire.string('session-bind@openssh.com')]))), '0000000105');
  assert.equal(hex(await h.handle(Buffer.of(17))), '0000000105', 'no keys can be added');
  assert.equal(hex(await h.handle(Buffer.of(13, 0, 0))), '0000000105', 'a truncated request');
  bad = true;
  assert.equal(hex(await h.handle(signReq(blob))), '0000000105');
  assert.match(logs.join('\n'), /does not verify/);
});

/* ------------------------------------------------------------ end to end */

/** One request, one reply, over the agent's socket - as ssh does it. */
function ask(sockPath, message) {
  return new Promise((resolve, reject) => {
    const c = net.connect(sockPath);
    const feed = wire.createDeframer((reply) => { c.end(); resolve(reply); });
    c.on('data', (d) => feed(d));
    c.on('error', reject);
    c.on('connect', () => c.write(wire.frame(message)));
  });
}

function listIdentities(reply) {
  const r = new wire.Reader(reply);
  assert.equal(r.uint8(), 12, 'IDENTITIES_ANSWER');
  const n = r.uint32();
  const out = [];
  for (let i = 0; i < n; i += 1) out.push({ blob: r.string(), comment: r.string().toString() });
  return out;
}

/** main() over the fake firmware, with the agent's lifetime in the test's hands. */
async function runAgent(argv, { fw = {}, untilStopped, runCommand, readFile } = {}) {
  const out = [];
  const err = [];
  const firmware = fakeFirmware({ agent: { k132: K132 }, ...fw });
  const code = await main(argv, {
    out: (l) => out.push(l),
    err: (l) => err.push(l),
    start: (opts) => startDesktop({ ...opts, pipe: firmware }),
    untilStopped,
    runCommand,
    readFile,
  });
  return { code, out, err, firmware };
}

test('agent <identity> prints lib-agent\'s line: the key the device derives from user@host', async () => {
  const r = await runAgent(['agent', 'okt@example.com']);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(r.out.length, 1);
  const [type, b64, comment] = r.out[0].split(' ');
  assert.equal(type, 'ssh-ed25519');
  assert.equal(comment, '<ssh://okt@example.com|ed25519>');
  const seed = sha256(Buffer.concat([K132, sha256(Buffer.from('okt@example.com'))]));
  assert.equal(b64, wire.publicKeyBlob('ed25519', ed25519.getPublicKey(seed)).toString('base64'),
    'v1: sk = SHA256(K132 || SHA256("user@host"))');
});

test('-e nist256p1 gives the ecdsa-sha2-nistp256 line', async () => {
  const r = await runAgent(['agent', '-e', 'nist256p1', 'okt@example.com']);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.match(r.out[0], /^ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB\S+ <ssh:\/\/okt@example\.com\|nist256p1>$/);
});

test('--skey derived-v2 is refused on firmware without v2, and a different key where it exists', async () => {
  let r = await runAgent(['agent', '--skey', 'derived-v2', 'okt@example.com']);
  assert.equal(r.code, 1);
  assert.match(r.err.join('\n'), /no agent derivation v2/);

  const fw = { version: 'v3.1.0-prodc' };
  const v1 = await runAgent(['agent', 'okt@example.com'], { fw });
  const v2 = await runAgent(['agent', '--skey', 'derived-v2', 'okt@example.com'], { fw });
  assert.equal(v2.code, 0, v2.err.join('\n'));
  assert.notEqual(v2.out[0], v1.out[0]);
  assert.equal(v2.out[0].split(' ')[2], '<ssh://okt@example.com|ed25519>');
});

test('the options are checked before the key is opened', async () => {
  for (const [argv, re] of [
    [['agent'], /needs an identity/],
    [['agent', '-e', 'secp256k1', 'h'], /-e takes/],
    [['agent', '--skey', 'ECC3', 'h'], /stored in an ECC slot/],
    [['agent', '--skey', 'nope', 'h'], /--skey takes/],
    [['agent', '-f', '-s', 'h'], /one mode each/],
    [['status', '-e', 'ed25519'], /does not take --ecdsa-curve-name/],
  ]) {
    const r = await runAgent(argv);
    assert.equal(r.code, 2, argv.join(' '));
    assert.match(r.err.join('\n'), re, argv.join(' '));
  }
});

test('a locked key is refused before any socket exists', async () => {
  const r = await runAgent(['agent', '-f', 'okt@example.com'], {
    fw: { pin: '1234' }, untilStopped: () => assert.fail('served a locked key'),
  });
  assert.equal(r.code, 1);
  assert.match(r.err.join('\n'), /locked/);
});

test('-f serves both key types from an identity file; ssh\'s requests get verified signatures', async () => {
  const file = '/ids/agent.config';
  let sockPath = null;
  const r = await runAgent(['agent', '-f', file], {
    readFile: async (p) => {
      assert.equal(p, file);
      return '<okt@example.com|ed25519>\n<ssh://other@example.org:2222|nist256p1>\n';
    },
    untilStopped: async (server) => {
      sockPath = server.path;
      if (process.platform !== 'win32') {
        assert.equal(fs.statSync(server.path).mode & 0o777, 0o600, 'the socket is 0600');
        assert.equal(fs.statSync(require('path').dirname(server.path)).mode & 0o777, 0o700, 'in a 0700 dir');
      } else {
        assert.match(server.path, /^\\\\\.\\pipe\\onlykey-js-agent-/, 'a private pipe, not openssh-ssh-agent');
      }

      const keys = listIdentities(await ask(server.path, Buffer.of(11)));
      assert.deepEqual(keys.map((k) => k.comment),
        ['<ssh://okt@example.com|ed25519>', '<ssh://other@example.org:2222|nist256p1>']);

      for (const k of keys) {
        const data = crypto.randomBytes(150);
        const reply = await ask(server.path,
          Buffer.concat([Buffer.of(13), wire.string(k.blob), wire.string(data), wire.uint32(0)]));
        const rr = new wire.Reader(reply);
        assert.equal(rr.uint8(), 14, `SIGN_RESPONSE for ${k.comment}`);
        const sigBlob = new wire.Reader(rr.string());
        const name = sigBlob.string().toString();
        const sig = sigBlob.string();
        const kb = new wire.Reader(k.blob);
        assert.equal(kb.string().toString(), name, 'the signature names the key type');
        if (name === 'ssh-ed25519') {
          assert.ok(ed25519.verify(sig, data, kb.string()));
        } else {
          kb.string();
          const q = kb.string();
          const inner = new wire.Reader(sig);
          const pad = (m) => { const t = m[0] === 0 ? m.subarray(1) : m; return Buffer.concat([Buffer.alloc(32 - t.length), t]); };
          const p1363 = Buffer.concat([pad(inner.string()), pad(inner.string())]);
          const key = agentSrv.publicKeyObject('nist256p1', q.subarray(1));
          assert.ok(crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, p1363), 'RFC 5656: ECDSA over SHA-256(data)');
        }
      }
      /* Two requests on one connection, back to back, answer in order. */
      const both = await new Promise((resolve, reject) => {
        const got = [];
        const c = net.connect(server.path);
        const feed = wire.createDeframer((m) => { got.push(m[0]); if (got.length === 2) { c.end(); resolve(got); } });
        c.on('data', feed);
        c.on('error', reject);
        c.on('connect', () => c.write(Buffer.concat([wire.frame(Buffer.of(11)), wire.frame(Buffer.of(99))])));
      });
      assert.deepEqual(both, [12, 5]);
    },
  });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(r.out.length, 1);
  assert.ok(r.out[0].includes(sockPath), 'prints what to set');
  /* the prompt says what is sent - the fingerprint of the request bytes, as a soft key's press sheet shows it (2026-10-10) */
  assert.match(r.err.join('\n'), /Confirm on the OnlyKey to sign for <ssh:\/\/okt@example\.com\|ed25519> \(message [0-9a-f]{4}( [0-9a-f]{4}){3}\): enter \d \d \d/);
  if (process.platform !== 'win32') assert.ok(!fs.existsSync(sockPath), 'the socket is removed on stop');
});

test('agent <identity> -- <command> runs it with SSH_AUTH_SOCK set and exits with its code', async () => {
  const r = await runAgent(['agent', 'okt@example.com', '--', 'ssh', '-v', 'host'], {
    runCommand: async (argv, env) => {
      assert.deepEqual(argv, ['ssh', '-v', 'host']);
      assert.equal(env.SSH_AGENT_PID, String(process.pid));
      const keys = listIdentities(await ask(env.SSH_AUTH_SOCK, Buffer.of(11)));
      assert.equal(keys.length, 1);
      return 7;
    },
  });
  assert.equal(r.code, 7);
});

test('-c runs ssh to the identity, offering only its key (python\'s ssh_args)', async () => {
  const r = await runAgent(['agent', '-c', 'ssh://okt@example.com:2222', '--', 'uptime'], {
    runCommand: async (argv) => {
      const at = argv.indexOf('-o');
      const pubFile = argv[at + 1].replace(/^IdentityFile=/, '');
      assert.deepEqual([...argv.slice(0, at), ...argv.slice(at + 2)],
        ['ssh', '-p', '2222', '-l', 'okt', '-o', 'IdentitiesOnly=true', 'example.com', 'uptime']);
      assert.match(fs.readFileSync(pubFile, 'utf8'), /^ssh-ed25519 \S+ <ssh:\/\/okt@example\.com:2222\|ed25519>\n$/);
      return 0;
    },
  });
  assert.equal(r.code, 0, r.err.join('\n'));
});
