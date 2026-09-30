/*
 * `onlykey-js gpg init` and `onlykey-js gpg-agent` - lib-agent's GPG half
 * (cli/assuan.js, cli/gpg-key.js, cli/gpg-agent.js, COMMANDS.gpg and
 * COMMANDS['gpg-agent']).
 *
 * Four layers, the four the code has:
 *
 *   the bytes    Assuan escaping and lines, canonical S-expressions
 *   the key      the key packet body (read and written back by openpgp.js
 *                to the same bytes), keygrips pinned against what GnuPG
 *                itself printed, the certificate verified by openpgp.js
 *   the handler  one command in, its lines out
 *   end to end   `gpg init` over the fake firmware's K132 derivation (with
 *                a stand-in gpg), then `gpg-agent` serving a REAL socket (a
 *                port-and-nonce file on Windows) and this file speaking
 *                Assuan to it as gpg would: sign, verify; ECDH, compare
 *
 * The live proofs - gpg importing the key, gpg --clearsign / --verify and
 * gpg --decrypt through this agent, parity with python's onlykey-gpg - need
 * GnuPG and a device; they are in the F2 report, not here.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const A = require('../cli/assuan');
const gpgKey = require('../cli/gpg-key');
const agentSrv = require('../cli/gpg-agent');
const { main } = require('../cli/index');
const { startDesktop } = require('../cli/desktop');
const { fakeFirmware } = require('./helpers/fake-firmware');
const openpgp = require('../src/vendor/openpgp/openpgp.js');
const { sha256 } = require('../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519, x25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');

const hex = (b) => Buffer.from(b).toString('hex');
const K132 = new Uint8Array(32).map((_, i) => (i * 29 + 7) & 0xff);
const USER_ID = 'OnlyKey Test <okt@example.com>';

/* ------------------------------------------------------------ the bytes */

test('D-line escaping is %, CR and LF only; unescaping takes any %XX', () => {
  assert.equal(A.escapeData(Buffer.from('a%b\nc\rd\0')).toString('latin1'), 'a%25b%0Ac%0Dd\0');
  assert.equal(A.unescapeData(Buffer.from('a%25b%0Ac%0dd%41%zz%')).toString('latin1'), 'a%b\nc\rdA%zz%');
});

test('data is cut into D lines that each fit Assuan\'s 1000 bytes, even when every byte escapes', () => {
  const lines = A.dataLines(Buffer.alloc(2000, 0x25));
  assert.ok(lines.length > 1);
  for (const l of lines) assert.ok(l.length <= A.MAX_LINE, `a line of ${l.length}`);
  const back = Buffer.concat(lines.map((l) => A.unescapeData(l.subarray(2, -1))));
  assert.ok(back.equals(Buffer.alloc(2000, 0x25)));
  assert.deepEqual(A.dataLines(Buffer.alloc(0)).map(String), ['D \n'], 'empty data is one empty D line');
});

test('the line splitter joins, splits, drops a CR, and refuses an endless line', () => {
  const got = [];
  const feed = A.createLineSplitter((l) => got.push(l.toString()));
  for (const b of Buffer.from('OPTION a=b\r\nNOP\n')) feed(Buffer.of(b));
  feed(Buffer.from('BYE\nRE'));
  feed(Buffer.from('SET\n'));
  assert.deepEqual(got, ['OPTION a=b', 'NOP', 'BYE', 'RESET']);
  assert.throws(() => feed(Buffer.alloc(1200, 0x41)), /longer than 1000/);
  assert.deepEqual(A.splitCommand('sethash  8 AB'), ['SETHASH', '8 AB']);
  assert.deepEqual(A.splitCommand('PKSIGN'), ['PKSIGN', '']);
});

test('canonical S-expressions round-trip, and anything else is refused', () => {
  const sig = A.encodeSexp(['sig-val', ['eddsa', ['r', Buffer.alloc(3, 0x29)], ['s', Buffer.from(')(')]]]);
  assert.equal(sig.toString('latin1'), '(7:sig-val(5:eddsa(1:r3:))))(1:s2:)()))');
  const tree = A.parseSexp(sig);
  assert.ok(A.encodeSexp(tree).equals(sig), 'binary-safe: the parens inside atoms are data');
  assert.equal(A.findToken(tree, 's')[1].toString(), ')(');
  assert.equal(A.findToken(tree, 'nope'), null);
  for (const bad of ['(3:ab)', '3:abc', '(1:a', '(1:a)x', '(01:a)', '(a b)']) {
    assert.throws(() => A.parseSexp(Buffer.from(bad)), /canonical/, bad);
  }
});

test('an ERR line is a libgpg-error code with GPG Agent as the source', () => {
  assert.equal(new A.AssuanError(A.ERR.NO_SECKEY, 'No secret key').line, 'ERR 67108881 No secret key <GPG Agent>',
    'lib-agent\'s literal');
  assert.equal(new A.AssuanError(A.ERR.ENODEV, 'No such device', A.SOURCE.SCD).line,
    'ERR 100696144 No such device <SCD>', 'lib-agent\'s SCD literal');
  assert.equal(new A.AssuanError(A.ERR.ASS_UNKNOWN_CMD, 'Unknown IPC command').line,
    'ERR 67109139 Unknown IPC command <GPG Agent>', 'what gpg-agent answers an unknown command');
});

/* ------------------------------------------------------------ the key */

/* Throwaway keys standing in for the device's. */
const SK = new Uint8Array(32).fill(3);
const XK = new Uint8Array(32).fill(5);
const DEV = {
  ed25519: { sign: ed25519.getPublicKey(SK), ecdh: x25519.getPublicKey(XK), sig: (d) => ed25519.sign(d, SK) },
  nist256p1: {
    sign: p256.getPublicKey(SK, false).slice(1),
    ecdh: p256.getPublicKey(XK, false).slice(1),
    sig: (d) => p256.sign(d.subarray(0, 32), SK, { prehash: false }),
  },
};

test('the key packet body is openpgp.js\'s own: read, then written, to the same bytes', async () => {
  for (const [curve, role, bits] of [['ed25519', 'sign', 263], ['ed25519', 'ecdh', 263], ['nist256p1', 'sign', 515], ['nist256p1', 'ecdh', 515]]) {
    const body = gpgKey.keyPacketBody(gpgKey.CURVES[curve][role], DEV[curve][role], 1234567890);
    const Packet = role === 'sign' ? openpgp.PublicKeyPacket : openpgp.PublicSubkeyPacket;
    const p = new Packet();
    await p.read(body);
    assert.equal(hex(p.write()), hex(body), `${curve} ${role}`);
    assert.equal(p.created.getTime(), 1234567890000);
    const oidLen = body[6];
    assert.equal(body.readUInt16BE(7 + oidLen), bits, `the MPI bit count of 0x40/0x04 || point (${curve} ${role})`);
    if (role === 'ecdh') assert.equal(hex(body.subarray(-4)), '03010807', 'KDF SHA-256 / AES-128, lib-agent\'s');
  }
});

/*
 * Keygrips gpg itself printed (`gpg --with-keygrip -k`) for certificates
 * built by gpg init from these throwaway public keys - GnuPG is the oracle
 * here, not lib-agent's formulas this file's code was ported from.
 */
const GPG_KEYGRIPS = {
  ed25519: { sign: 'AE52FB06236D94B12C7A33DF398C191A61D45D24', ecdh: '5DCE17EA03ADC18FD2DB11F40162A3F27846319D' },
  nist256p1: { sign: 'D82107FAF35CA9AC5D0D86F4027999DA7C382202', ecdh: '4471C0C575A7E6EB9B21A661EE431F26379274F7' },
};

test('keygrips are the ones gpg computes', () => {
  for (const curve of Object.keys(GPG_KEYGRIPS)) {
    for (const role of ['sign', 'ecdh']) {
      assert.equal(gpgKey.keygrip(gpgKey.CURVES[curve][role].grip, DEV[curve][role]), GPG_KEYGRIPS[curve][role], `${curve} ${role}`);
    }
  }
});

async function certificate(curve, { created = 0, sign } = {}) {
  let signatures = 0;
  const cert = await gpgKey.buildCertificate({
    userId: USER_ID,
    curve,
    created,
    signPublic: DEV[curve].sign,
    ecdhPublic: DEV[curve].ecdh,
    sign: sign || (async (digest) => { signatures += 1; return DEV[curve].sig(Buffer.from(digest)); }),
  });
  return { cert, signatures };
}

test('the certificate: two device signatures, and openpgp.js verifies both', async () => {
  for (const curve of ['ed25519', 'nist256p1']) {
    const { cert, signatures } = await certificate(curve, { created: 1700000000 });
    assert.equal(signatures, 2, 'the certification and the subkey binding - lib-agent\'s two confirmations');
    assert.match(cert.armored, /\n=[A-Za-z0-9+/]{4}\n-----END PGP PUBLIC KEY BLOCK-----\n$/,
      'the CRC-24 line: without it GnuPG 2.4.4 rejects the armor');
    const key = await openpgp.readKey({ armoredKey: cert.armored });
    const at = new Date(1700000001000);
    await key.verifyPrimaryKey(at);
    await key.subkeys[0].verify(at);
    assert.deepEqual(key.getUserIDs(), [USER_ID]);
    assert.equal(key.getFingerprint().toUpperCase(), cert.fingerprint);
    const [self] = key.users[0].selfCertifications;
    assert.equal(self.signatureType, 0x13, 'positive certification, as lib-agent');
    assert.deepEqual([...self.keyFlags], [0x03], 'certify + sign');
    assert.deepEqual([...self.preferredHashAlgorithms], [8, 9, 10]);
    assert.ok(self.unhashedSubpackets.some((s) => s.type === 26 && Buffer.from(s.body).toString() === 'ONLYKEY-GPG'),
      'lib-agent\'s ONLYKEY-GPG mark');
    assert.deepEqual([...key.subkeys[0].bindingSignatures[0].keyFlags], [0x0c], 'encrypt communications + storage');
  }
});

test('the fingerprint depends on the device key and the time only: same time, same key, same bytes', async () => {
  const a = await certificate('ed25519');
  const b = await certificate('ed25519');
  const c = await certificate('ed25519', { created: 1 });
  assert.equal(a.cert.fingerprint, b.cert.fingerprint);
  assert.equal(a.cert.armored, b.cert.armored, 'Ed25519 is deterministic and there is no salt notation');
  assert.notEqual(a.cert.fingerprint, c.cert.fingerprint);
});

test('a device signature that does not verify makes no certificate', async () => {
  await assert.rejects(certificate('ed25519', { sign: async () => new Uint8Array(64) }), /does not verify/);
  /* ...and the hook is gone afterwards: openpgp.js signs in software again. */
  const { privateKey } = await openpgp.generateKey({ userIDs: [{ name: 'x' }], format: 'object' });
  await openpgp.sign({ message: await openpgp.createMessage({ text: 'x' }), signingKeys: privateKey });
});

test('readDerivedKeys finds both parts, with the keygrips and the first user id', async () => {
  const { cert } = await certificate('nist256p1');
  const keys = await gpgKey.readDerivedKeys(cert.armored);
  assert.deepEqual(keys.map((k) => [k.role, k.keyType, k.curve, k.keygrip, k.userId]), [
    ['sign', 2, 'nist256p1', GPG_KEYGRIPS.nist256p1.sign, USER_ID],
    ['ecdh', 2, 'nist256p1', GPG_KEYGRIPS.nist256p1.ecdh, USER_ID],
  ]);
  assert.equal(hex(keys[0].raw), hex(DEV.nist256p1.sign));
});

/* ------------------------------------------------------------ the handler */

/** A handler session and a recording io, for one command at a time. */
async function handlerFor(curve, overrides = {}) {
  const { cert } = await certificate(curve);
  const keys = await gpgKey.readDerivedKeys(cert.armored);
  const calls = [];
  const handler = agentSrv.createGpgAgentHandler({
    keys,
    version: '2.4.4',
    publicKey: async (k) => DEV[curve][k.role],
    sign: async (k, digest) => { calls.push(['sign', hex(digest)]); return DEV[curve].sig(Buffer.from(digest)); },
    ecdh: async (k, point) => { calls.push(['ecdh', hex(point)]); return new Uint8Array(k.keyType === 4 ? 32 : 64).fill(7); },
    ...overrides,
  });
  const s = handler.session();
  const run = async (line, inquired = Buffer.alloc(0)) => {
    const out = [];
    const io = {
      send: (l) => out.push(String(l)),
      status: (t) => out.push(`S ${t}`),
      data: (b) => out.push(`D ${Buffer.from(b).toString('latin1')}`),
      inquire: async (kw) => { out.push(`INQUIRE ${kw}`); return inquired; },
    };
    try {
      const r = await s.command(line, io);
      out.push(r && r.ok ? `OK ${r.ok}` : 'OK');
      return { out, r };
    } catch (err) {
      if (!(err instanceof A.AssuanError)) throw err;
      out.push(err.line);
      return { out };
    }
  };
  return { run, keys, calls };
}

test('the handler: lib-agent\'s commands, and ERR for what it does not do', async () => {
  const { run, keys } = await handlerFor('ed25519');
  const [sign, dec] = keys;
  assert.deepEqual((await run('GETINFO version')).out, ['D 2.4.4', 'OK']);
  assert.deepEqual((await run('GETINFO pid')).out, [`D ${process.pid}`, 'OK']);
  assert.deepEqual((await run('GETINFO s2k_count')).out, ['D 67108864', 'OK']);
  assert.deepEqual((await run('GETINFO cmd_has_option HAVEKEY list')).out, ['OK']);
  assert.deepEqual((await run('GETINFO cmd_has_option PKDECRYPT kem')).out, ['ERR 67109120 False <GPG Agent>']);
  assert.deepEqual((await run('OPTION ttyname=/dev/pts/9')).out, ['OK']);
  assert.deepEqual((await run('AGENT_ID')).out, ['D ONLYKEY', 'OK']);
  assert.deepEqual((await run(`HAVEKEY 0000000000000000000000000000000000000000 ${dec.keygrip}`)).out, ['OK']);
  assert.deepEqual((await run('HAVEKEY 0000000000000000000000000000000000000000')).out, ['ERR 67108881 No secret key <GPG Agent>']);
  const list = (await run('HAVEKEY --list=1000')).out;
  assert.equal(list[0], `D ${Buffer.concat([Buffer.from(sign.keygrip, 'hex'), Buffer.from(dec.keygrip, 'hex')]).toString('latin1')}`);
  assert.deepEqual((await run(`KEYINFO ${sign.keygrip}`)).out, [`S KEYINFO ${sign.keygrip} X - - - - - - -`, 'OK']);
  assert.deepEqual((await run('KEYINFO 0000000000000000000000000000000000000000')).out, ['ERR 67108881 No secret key <GPG Agent>']);
  assert.equal((await run('KEYINFO --list')).out.length, 3);
  assert.deepEqual((await run('SCD GETINFO version')).out, ['D 2.4.4', 'OK']);
  assert.deepEqual((await run('SCD SERIALNO')).out, ['ERR 100696144 No such device <SCD>']);
  assert.deepEqual((await run('LEARN --sendinfo')).out, ['ERR 67109139 Unknown IPC command <GPG Agent>'],
    'lib-agent sends nothing here and gpg waits forever');
  assert.deepEqual((await run('BYE')).r, { close: true });
  assert.deepEqual((await run('KILLAGENT')).r, { kill: true });
});

test('SETHASH: gpg\'s two forms, the right length, and no --inquire', async () => {
  const { run } = await handlerFor('ed25519');
  assert.deepEqual((await run(`SETHASH 8 ${'AB'.repeat(32)}`)).out, ['OK']);
  assert.deepEqual((await run(`SETHASH --hash=sha512 ${'AB'.repeat(64)}`)).out, ['OK']);
  assert.match((await run(`SETHASH 8 ${'AB'.repeat(31)}`)).out[0], /^ERR 67108919 a sha256 digest is 32 bytes/);
  assert.match((await run(`SETHASH 99 ${'AB'.repeat(32)}`)).out[0], /^ERR 67108924 /);
  assert.match((await run('SETHASH --inquire')).out[0], /^ERR 67108924 /);
});

test('PKSIGN: the S-expression gpg-agent sends, verified first; ECDSA gets the first 256 bits', async () => {
  for (const curve of ['ed25519', 'nist256p1']) {
    const { run, keys, calls } = await handlerFor(curve);
    const digest = crypto.randomBytes(64);
    await run(`SIGKEY ${keys[0].keygrip}`);
    await run(`SETHASH 10 ${hex(digest)}`);
    const { out } = await run('PKSIGN');
    assert.equal(out[1], 'OK');
    const tree = A.parseSexp(Buffer.from(out[0].slice(2), 'latin1'));
    assert.equal(tree[1][0].toString(), curve === 'ed25519' ? 'eddsa' : 'ecdsa');
    const sig = Buffer.concat([A.findToken(tree, 'r')[1], A.findToken(tree, 's')[1]]);
    assert.equal(sig.length, 64);
    const signed = curve === 'ed25519' ? digest : digest.subarray(0, 32);
    assert.deepEqual(calls, [['sign', hex(signed)]]);
    assert.ok(gpgKey.verifyDigest(keys[0].keyType, keys[0].raw, signed, sig));
  }
  const { run, keys } = await handlerFor('ed25519', { sign: async () => new Uint8Array(64).fill(1) });
  await run(`SIGKEY ${keys[0].keygrip}`);
  await run(`SETHASH 8 ${'00'.repeat(32)}`);
  assert.deepEqual((await run('PKSIGN')).out, ['ERR 67108872 Bad signature <GPG Agent>'], 'not sent when it does not verify');
  await run(`SIGKEY ${keys[1].keygrip}`);
  assert.match((await run('PKSIGN')).out[0], /^ERR 67108881 /, 'the ECDH subkey does not sign');
});

test('PKDECRYPT: INQUIRE CIPHERTEXT, the device\'s point back prefixed as gpg-agent\'s, one device-key check', async () => {
  for (const curve of ['ed25519', 'nist256p1']) {
    let reads = 0;
    const { run, keys, calls } = await handlerFor(curve, { publicKey: async (k) => { reads += 1; return DEV[curve][k.role]; } });
    const e = curve === 'ed25519' ? Buffer.concat([Buffer.of(0x40), crypto.randomBytes(32)]) : Buffer.concat([Buffer.of(4), crypto.randomBytes(64)]);
    const ct = A.encodeSexp(['enc-val', ['ecdh', ['s', Buffer.alloc(40, 1)], ['e', e]]]);
    await run(`SETKEY ${keys[1].keygrip}`);
    for (let i = 0; i < 2; i += 1) {
      const { out } = await run('PKDECRYPT', ct);
      assert.deepEqual(out.slice(0, 2), ['S INQUIRE_MAXLEN 4096', 'INQUIRE CIPHERTEXT']);
      assert.equal(out[2], 'S PADDING 0');
      const value = A.findToken(A.parseSexp(Buffer.from(out[3].slice(2), 'latin1')), 'value')[1];
      assert.equal(hex(value), curve === 'ed25519' ? `40${'07'.repeat(32)}` : `04${'07'.repeat(64)}`);
      assert.equal(out[4], 'OK');
    }
    assert.deepEqual(calls[0], ['ecdh', hex(e)], 'the ephemeral point as gpg sent it (the device drops the prefix)');
    assert.equal(reads, 1, 'the device\'s public key is compared once, then trusted');
  }
  const { run, keys } = await handlerFor('ed25519', { publicKey: async () => new Uint8Array(32).fill(9) });
  await run(`SETKEY ${keys[1].keygrip}`);
  const ct = A.encodeSexp(['enc-val', ['ecdh', ['s', 'x'], ['e', Buffer.alloc(33, 0x40)]]]);
  assert.match((await run('PKDECRYPT', ct)).out.pop(), /^ERR 67108881 the OnlyKey derives a different key/);
  assert.match((await run('PKDECRYPT', Buffer.from('(7:enc-val(3:rsa(1:a1:x)))'))).out.pop(), /^ERR 67108919 cannot use/);
});

test('GET_PASSPHRASE asks pinentry with gpg\'s texts; --data answers as data, cancel is ERR', async () => {
  let asked = null;
  const { run } = await handlerFor('ed25519', {
    askPassphrase: async (session, req) => { asked = { ...req, tty: session.options.ttyname }; return Buffer.from('p%ss'); },
  });
  await run('OPTION ttyname=/dev/pts/3');
  const { out } = await run('GET_PASSPHRASE --data --repeat=1 -- sym X Passphrase: Enter+a+passphrase%0Afor+gpg');
  assert.deepEqual(out, ['D p%ss', 'OK']);
  assert.deepEqual(asked, {
    cacheId: 'sym', error: '', prompt: 'Passphrase:', description: 'Enter a passphrase\nfor gpg', repeat: 1, tty: '/dev/pts/3',
  });
  assert.deepEqual((await run('GET_PASSPHRASE sym')).out, [`OK ${Buffer.from('p%ss').toString('hex').toUpperCase()}`]);
  const refused = await handlerFor('ed25519', { askPassphrase: async () => { throw new Error('no'); } });
  assert.deepEqual((await refused.run('GET_PASSPHRASE --data sym')).out, ['ERR 67108963 Operation cancelled <GPG Agent>']);
});

/* ------------------------------------------------------------ end to end */

/** Speak Assuan to the agent as gpg does: connect, read the greeting, then transact. */
async function client(socketPath) {
  const sock = agentSrv.connectAssuan(socketPath);
  const pending = [];
  let waiter = null;
  sock.on('data', A.createLineSplitter((l) => {
    if (waiter) { const w = waiter; waiter = null; w(l.toString('latin1')); } else pending.push(l.toString('latin1'));
  }));
  const next = () => new Promise((r) => { if (pending.length) r(pending.shift()); else waiter = r; });
  const greeting = await next();
  assert.match(greeting, /^OK Pleased to meet you/);
  return {
    async transact(line, inquired) {
      sock.write(`${line}\n`);
      const lines = [];
      for (;;) {
        const l = await next();
        if (l.startsWith('INQUIRE ')) {
          for (const d of A.dataLines(inquired)) sock.write(d);
          sock.write('END\n');
          continue;
        }
        lines.push(l);
        if (l === 'OK' || l.startsWith('OK ') || l.startsWith('ERR ')) return lines;
      }
    },
    end: () => sock.end(),
  };
}

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'okjs-gpg-'));
}

function stack(fw = {}) {
  const firmware = fakeFirmware({ agent: { k132: K132 }, ...fw });
  return { firmware, start: (opts) => startDesktop({ ...opts, pipe: firmware }) };
}

/** A stand-in gpg: says its version, records what it was asked to do. */
function fakeGpg(calls, version = '2.4.4') {
  return async (args) => {
    calls.push(args);
    if (args[0] === '--version') return { code: 0, stdout: `gpg (GnuPG) ${version}\nlibgcrypt 1.10.3\n`, stderr: '' };
    return { code: 0, stdout: '', stderr: '' };
  };
}

async function runCli(argv, extra = {}) {
  const out = [];
  const err = [];
  const code = await main(argv, { out: (l) => out.push(l), err: (l) => err.push(l), ...extra });
  return { code, out, err };
}

test('gpg init: the device\'s keys in a certificate gpg is told to import, and a home wired to the agent', async () => {
  const parent = tmpdir();
  const home = path.join(parent, 'home');
  const calls = [];
  try {
    const { start } = stack();
    const r = await runCli(['gpg', 'init', USER_ID, '--homedir', home, '-t', '1700000000'], { start, gpg: fakeGpg(calls) });
    assert.equal(r.code, 0, r.err.join('\n'));
    assert.equal(r.err.filter((l) => /Confirm on the OnlyKey to sign the new key .*: enter \d \d \d/.test(l)).length, 2);

    const armored = `${r.out.join('\n')}\n`;
    assert.equal(armored, fs.readFileSync(path.join(home, 'pubkey.asc'), 'utf8'), 'stdout is pubkey.asc');
    const keys = await gpgKey.readDerivedKeys(armored);
    const idHash = sha256(Buffer.from(`gpg://${USER_ID}`));
    const sk = sha256(Buffer.concat([K132, idHash]));
    assert.equal(hex(keys[0].raw), hex(ed25519.getPublicKey(sk)), 'v1: sk = SHA256(K132 || SHA256("gpg://" + user id))');
    assert.equal(hex(keys[1].raw), hex(x25519.getPublicKey(Uint8Array.from(sk).reverse())), 'the X25519 key, same derivation');
    assert.equal(keys[0].created, 1700000000);

    assert.deepEqual(calls.map((a) => a.filter((x) => x.startsWith('--'))), [
      ['--version'],
      ['--homedir', '--batch', '--no-autostart', '--import'],
      ['--homedir', '--batch', '--no-autostart', '--import-ownertrust'],
    ]);
    const conf = fs.readFileSync(path.join(home, 'gpg.conf'), 'utf8');
    const script = process.platform === 'win32' ? 'run-agent.cmd' : 'run-agent.sh';
    assert.ok(conf.includes(`agent-program ${path.join(home, script)}\n`));
    assert.ok(conf.includes(`default-key "${USER_ID}"\n`));
    assert.ok(conf.includes('personal-digest-preferences SHA512\n'));
    const run = fs.readFileSync(path.join(home, script), 'utf8');
    assert.match(run, /gpg-agent'? '?--homedir/);
    assert.match(run, /--skey'? '?ECC32'? '?--dkey'? '?ECC32'? '?--daemon/);
    assert.ok(run.includes(process.execPath), 'an absolute node: gpg starts it with gpg\'s PATH');
    assert.equal(fs.readFileSync(path.join(home, 'ownertrust.txt'), 'utf8'), `${(await openpgp.readKey({ armoredKey: armored })).getFingerprint().toUpperCase()}:6:\n`);
    if (process.platform !== 'win32') {
      assert.equal(fs.statSync(home).mode & 0o777, 0o700);
      assert.equal(fs.statSync(path.join(home, script)).mode & 0o777, 0o700);
    }

    /* Again: refused without --force; with it, the same key (same time) replaces the home. */
    const again = await runCli(['gpg', 'init', USER_ID, '--homedir', home, '-t', '1700000000'], { start, gpg: fakeGpg([]) });
    assert.equal(again.code, 1);
    assert.match(again.err.join('\n'), /exists; remove it, or pass --force/);
    const forced = await runCli(['gpg', 'init', USER_ID, '--homedir', home, '-t', '1700000000', '--force'],
      { start, gpg: fakeGpg([]), gpgconf: () => null });
    assert.equal(forced.code, 0, forced.err.join('\n'));
    assert.equal(`${forced.out.join('\n')}\n`, armored, 'same device, user id and time: the same certificate');

    /* --force does not delete a home it did not make. */
    const foreign = path.join(parent, 'foreign');
    fs.mkdirSync(foreign);
    fs.writeFileSync(path.join(foreign, 'pubring.kbx'), 'x');
    const no = await runCli(['gpg', 'init', USER_ID, '--homedir', foreign, '--force'], { start, gpg: fakeGpg([]) });
    assert.equal(no.code, 1);
    assert.match(no.err.join('\n'), /is not one/);
    assert.ok(fs.existsSync(path.join(foreign, 'pubring.kbx')));
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test('gpg init: the options are checked before gpg or the key is touched', async () => {
  const calls = [];
  for (const [argv, re] of [
    [['gpg'], /one action: init/],
    [['gpg', 'init'], /needs a user id/],
    [['gpg', 'init', 'Alice', '<a@b>'], /ONE user id/],
    [['gpg', 'init', 'Zoë <z@b>'], /not printable ASCII/],
    [['gpg', 'init', 'A', '-e', 'secp256k1'], /-e takes/],
    [['gpg', 'init', 'A', '-t', 'yesterday'], /--time takes seconds/],
    [['gpg', 'init', 'A', '--dkey', 'RSA1'], /--dkey RSA1: a key stored in an ECC slot/],
    [['gpg-agent', '--force'], /does not take --force/],
  ]) {
    const r = await runCli(argv, { start: () => assert.fail('opened the key'), gpg: fakeGpg(calls) });
    assert.equal(r.code, 2, argv.join(' '));
    assert.match(r.err.join('\n'), re, argv.join(' '));
  }
  assert.deepEqual(calls, []);
  const old = await runCli(['gpg', 'init', 'A', '--homedir', path.join(os.tmpdir(), 'okjs-never')],
    { start: () => assert.fail('opened the key'), gpg: fakeGpg([], '2.0.30') });
  assert.equal(old.code, 1);
  assert.match(old.err.join('\n'), /too old/);
});

test('gpg-agent: gpg\'s sign and decrypt conversations over the real socket, then KILLAGENT', async () => {
  for (const curve of ['ed25519', 'nist256p1']) {
    const parent = tmpdir();
    const home = path.join(parent, 'home');
    try {
      const { start } = stack();
      const init = await runCli(['gpg', 'init', USER_ID, '--homedir', home, '-e', curve], { start, gpg: fakeGpg([]) });
      assert.equal(init.code, 0, init.err.join('\n'));
      const keys = await gpgKey.readDerivedKeys(fs.readFileSync(path.join(home, 'pubkey.asc'), 'utf8'));
      const sockPath = path.join(parent, 'S.gpg-agent');
      const gpgconf = (args, env) => {
        assert.equal(env.GNUPGHOME || home, home);
        return args[0] === '--version' ? 'gpgconf (GnuPG) 2.4.4\n' : `${sockPath.replace(/:/g, '%3a')}\n`;
      };

      let served = null;
      const r = await runCli(['gpg-agent', '--homedir', home], {
        start,
        gpgconf,
        untilStopped: async (server) => {
          served = server.path;
          if (process.platform !== 'win32') assert.equal(fs.statSync(server.path).mode & 0o777, 0o600);
          else assert.match(fs.readFileSync(server.path, 'latin1'), /^\d+\n[\s\S]{16}$/, 'port, newline, 16-byte nonce');

          const c = await client(server.path);
          assert.deepEqual(await c.transact('OPTION ttyname=/dev/null-not-a-tty'), ['OK']);
          assert.deepEqual(await c.transact('GETINFO version'), ['D 2.4.4', 'OK']);
          assert.deepEqual(await c.transact(`HAVEKEY ${keys[0].keygrip}`), ['OK']);

          /* sign, as gpg --sign does it */
          const digest = crypto.createHash('sha512').update('hi\n').digest();
          await c.transact(`SIGKEY ${keys[0].keygrip}`);
          await c.transact('SETKEYDESC Please+sign');
          await c.transact(`SETHASH 10 ${hex(digest).toUpperCase()}`);
          const signed = await c.transact('PKSIGN');
          assert.equal(signed.pop(), 'OK');
          const sexp = A.parseSexp(Buffer.concat(signed.map((l) => A.unescapeData(Buffer.from(l.slice(2), 'latin1')))));
          const sig = Buffer.concat([A.findToken(sexp, 'r')[1], A.findToken(sexp, 's')[1]]);
          assert.ok(gpgKey.verifyDigest(keys[0].keyType, keys[0].raw, curve === 'ed25519' ? digest : digest.subarray(0, 32), sig),
            'a signature gpg will verify with the key it imported');

          /* decrypt, as gpg --decrypt does it: the agent's point is ECDH(device key, ephemeral) */
          let e;
          let expect;
          if (curve === 'ed25519') {
            const esk = crypto.randomBytes(32);
            e = Buffer.concat([Buffer.of(0x40), x25519.getPublicKey(esk)]);
            expect = Buffer.concat([Buffer.of(0x40), x25519.getSharedSecret(esk, keys[1].raw)]);
          } else {
            const esk = p256.utils.randomSecretKey();
            e = Buffer.from(p256.getPublicKey(esk, false));
            expect = Buffer.from(p256.getSharedSecret(esk, gpgKey.openpgpPoint(keys[1].raw), false));
          }
          await c.transact(`SETKEY ${keys[1].keygrip}`);
          const dec = await c.transact('PKDECRYPT', A.encodeSexp(['enc-val', ['ecdh', ['s', Buffer.alloc(48, 2)], ['e', e]]]));
          assert.equal(dec.pop(), 'OK');
          assert.deepEqual(dec.slice(0, 2), ['S INQUIRE_MAXLEN 4096', 'S PADDING 0']);
          const value = A.findToken(A.parseSexp(Buffer.concat(dec.slice(2).map((l) => A.unescapeData(Buffer.from(l.slice(2), 'latin1'))))), 'value')[1];
          assert.equal(hex(value), hex(expect));

          assert.deepEqual(await c.transact('KILLAGENT'), ['OK']);
          c.end();
          await new Promise(() => {});   // KILLAGENT, not this, ends the agent
        },
      });
      assert.equal(r.code, 0, r.err.join('\n'));
      assert.match(r.err.join('\n'), /serving 2 key\(s\)/);
      assert.match(r.err.join('\n'), /Confirm on the OnlyKey to sign for <gpg:\/\/OnlyKey Test <okt@example\.com>\|/);
      assert.ok(!fs.existsSync(served), 'the socket is removed on stop');
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  }
});

test('gpg-agent refuses a home with no derived key, and a socket another agent answers on', async () => {
  const parent = tmpdir();
  try {
    const r = await runCli(['gpg-agent', '--homedir', parent], { start: () => assert.fail('opened the key'), gpgconf: () => null });
    assert.equal(r.code, 1);
    assert.match(r.err.join('\n'), /cannot read .*pubkey\.asc/);

    const { cert } = await certificate('ed25519');
    fs.writeFileSync(path.join(parent, 'pubkey.asc'), cert.armored);
    const sockPath = path.join(parent, 'S.gpg-agent');
    const gpgconf = (args) => (args[0] === '--version' ? null : sockPath);
    const { start } = stack();
    const first = runCli(['gpg-agent', '--homedir', parent], {
      start,
      gpgconf,
      untilStopped: async () => {
        const second = await runCli(['gpg-agent', '--homedir', parent], { start, gpgconf, untilStopped: () => assert.fail('served twice') });
        assert.equal(second.code, 1);
        assert.match(second.err.join('\n'), /already answering/);
      },
    });
    assert.equal((await first).code, 0);
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});
