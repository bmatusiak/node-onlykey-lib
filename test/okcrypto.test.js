/*
 * plugins/okcrypto - the second plugin the session authorises.
 *
 * The composite device operations run over the vendor path now. Both hazards
 * the plugin header used to warn about were checked against the firmware and
 * both were real - the chunk frame carries a slot byte the hex chunker does
 * not write, and the response comes back in PLAINTEXT despite an encrypt
 * argument that says otherwise - so the tests below pin the frame byte by
 * byte and the response by shape.
 *
 * The derive operations are still not here, and that is a boundary rather
 * than an omission: their opt bytes live in a CTAP keyhandle and the vendor
 * frame has nowhere to put them.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const Rectify = require('@bmatusiak/rectify');
const hostPlugin = require('../plugins/host');
const embedded = require('../plugins/transport/embedded');
const sessionPlugin = require('../plugins/session');
const devicePlugin = require('../plugins/device');
const okcryptoPlugin = require('../plugins/okcrypto');
const composite = require('../src/crypto/composite_pgp');
const { fakeFirmware } = require('./helpers/fake-firmware');
const { IFACE } = require('../src/transport/contract');
const { MSG } = require('../src/protocol/msg');
const { challengeDigits } = require('../src/protocol/challenge');

function start(plugins, pipe = fakeFirmware()) {
  plugins.config = { transport: { pipe } };
  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => {
      if (err) reject(err);
      else resolve(started);
    });
    app.start();
  });
}

const FULL = () => [hostPlugin, embedded, sessionPlugin, devicePlugin, okcryptoPlugin];

/* ------------------------------------------------------------ composition */

test('device and okcrypto coexist as separate authorised consumers', async () => {
  /*
   * setup.allowed is [['device'], ['okcrypto']] - two groups of one, not one
   * group of two. The distinction is real: a single flat group would mean "a
   * plugin providing BOTH names", which no plugin does, and the session would
   * be unreachable.
   */
  const app = await start(FULL());
  assert.equal(typeof app.services.device.setPin, 'function');
  assert.equal(typeof app.services.okcrypto.registerPgpHooks, 'function');
  assert.equal('session' in app.services, false, 'still restricted from the registry');
  await app.destroy();
});

test('an unauthorised plugin cannot join by also consuming session', async () => {
  // The guarantee is worth re-asserting with okcrypto present: adding a second
  // legitimate consumer must not widen the door for a third.
  const nosy = (imports, register) => register(null, { snooper: {} });
  nosy.consumes = ['session'];
  nosy.provides = ['snooper'];

  await assert.rejects(() => start([...FULL(), nosy]), /snooper|allows|consume/);
});

/* ------------------------------------------------------------ the surface */

test('the device-free crypto is reachable through the service', async () => {
  const app = await start(FULL());
  const { okcrypto } = app.services;

  assert.equal(typeof okcrypto.age.encryptAgeFile, 'function');
  assert.equal(typeof okcrypto.pqc.buildRecipient, 'function');
  assert.equal(typeof okcrypto.composite.packBlob, 'function');
  assert.equal(okcrypto.composite.BLOB_LEN, 160);
  await app.destroy();
});

test('loading the plugin does not pull in the 1.2 MB PGP fork', async () => {
  /*
   * composite_pgp takes the openpgp instance as an argument rather than
   * importing one, and that is what keeps the fork off this plugin's
   * dependency graph. A caller doing age or X-Wing must not pay for PGP.
   */
  const { execFileSync } = require('child_process');
  const path = require('path');
  const loaded = execFileSync(
    process.execPath,
    ['-e', `require('./plugins/okcrypto');
      const hit = Object.keys(require.cache).filter((f) => f.includes('openpgp'));
      process.stdout.write(JSON.stringify(hit));`],
    { cwd: path.resolve(__dirname, '..'), encoding: 'utf8' },
  );
  assert.deepEqual(JSON.parse(loaded), []);
});

test('registerPgpHooks passes the service through as the device', async () => {
  // The hooks are registered against whatever object is handed over, so this
  // pins that it is the okcrypto service itself - the thing that will grow
  // composite_sign/composite_decrypt - and not some inner object.
  const app = await start(FULL());
  const { okcrypto } = app.services;

  let sawDevice = null;
  const fakeOpenpgp = {
    setHardwareHooks(hooks) {
      sawDevice = hooks;
    },
  };
  okcrypto.registerPgpHooks(fakeOpenpgp, 132);

  assert.ok(sawDevice, 'hooks were registered');
  assert.equal(typeof sawDevice.ecdh, 'function');
  assert.equal(typeof sawDevice.mlkemDecaps, 'function');
  await app.destroy();
});

/* -------------------------------------------------- honesty about the gap */

test('the plugin reports what it can do, and why the rest it cannot', async () => {
  /*
   * The alternative is worse than a missing method. composite_pgp registers
   * hooks against this object; if one is silently absent, the failure surfaces
   * from inside openpgp as a complaint about the PGP message, and the actual
   * cause appears nowhere.
   */
  const app = await start(FULL());
  const ops = app.services.okcrypto.deviceOperations;

  assert.equal(ops.compositeSign, true);
  assert.equal(ops.compositeDecrypt, true);

  /*
   * The derive pair is implemented now, and proven against the firmware
   * (ok-rn __e2e_tests__/10-derive): a label derives the same P-256 key twice,
   * and two labels of EQUAL LENGTH derive different ones.
   */
  assert.equal(ops.derivePublicKey, true);
  assert.equal(ops.deriveSharedSecret, true);

  /*
   * X-Wing works too now, proven on device (10-derive, "the X-Wing key type
   * returns its split-custody pair"). Nothing here is unavailable, so the
   * reason is EMPTY rather than a sentence explaining a gap that closed - a
   * stale explanation is worse than none, because it reads as current.
   */
  assert.equal(ops.deriveXwing, true);
  assert.equal(ops.reason, '', `nothing is missing, but reason says: ${ops.reason}`);
  await app.destroy();
});

/* ------------------------------------------------- composite operations */

/** The frames a slot-addressed crypto command puts on the vendor bus. */
const cryptoFrames = (pipe) => pipe.writes.filter((w) => w.iface === IFACE.VENDOR);

test('a sign request is framed the way process_packets reads it', async () => {
  /*
   * Byte for byte, because this is the hazard the plugin header named and it
   * is invisible at every other layer: the hex chunker writes the same 64-byte
   * frame with no slot in it, so the wrong framing has the right length and
   * only the device notices.
   *
   *     buffer[4]  command      okcore.cpp:7472
   *     buffer[5]  SLOT         okcore.cpp:7473
   *     buffer[6]  0xFF or len  okcore.cpp:7482
   *     buffer[7]  data         okcore.cpp:7486
   */
  const pipe = fakeFirmware();
  const app = await start(FULL(), pipe);

  /* 60 bytes: one full chunk then a 3-byte remainder, so both headers show. */
  const payload = new Uint8Array(60).map((_, i) => i);
  const pending = app.services.okcrypto.composite_sign(101, composite.HALF_ECC, payload, { timeoutMs: 200 })
    .catch(() => null);

  await new Promise((r) => setTimeout(r, 30));
  const frames = cryptoFrames(pipe).map((w) => w.data);
  assert.equal(frames.length, 2, `expected two chunks, got ${frames.length}`);

  assert.equal(frames[0][4], MSG.OKSIGN);
  assert.equal(frames[0][5], 101, 'the slot must be at buffer[5]');
  assert.equal(frames[0][6], 0xff, 'a non-final chunk is 0xFF');
  assert.equal(frames[0][7], composite.HALF_ECC, 'the half selector leads the payload at buffer[7]');
  assert.equal(frames[0][8], 0, 'then the digest');

  assert.equal(frames[1][5], 101);
  assert.equal(frames[1][6], 4, 'the final chunk carries its length (61 bytes: selector + 60)');
  assert.equal(frames[1][7], 56, 'the remainder continues the digest');
  assert.ok(frames.every((f) => f.length === 64));

  await pending;
  await app.destroy();
});

test('the challenge digits are the ones the firmware will ask for', async () => {
  /*
   * The device never tells the host which buttons it wants - that would defeat
   * the challenge - so the host derives them from the same sha256 over the
   * same bytes (okcore.cpp:7577-7587). Getting this wrong means pressing three
   * wrong buttons and being told the challenge was incorrect, with nothing to
   * say which side was wrong.
   */
  const pipe = fakeFirmware();
  const app = await start(FULL(), pipe);

  const payload = Uint8Array.from([1, 2, 3, 4, 5]);
  let announced = null;
  app.services.okcrypto.on('challenge', (e) => { announced = e; });

  let handed = null;
  const pending = app.services.okcrypto.composite_sign(101, composite.HALF_ECC, payload, {
    timeoutMs: 200,
    confirm: ({ digits }) => { handed = digits; },
  }).catch(() => null);
  await pending;

  /* Over the bytes the firmware receives: the selector and then the digest. */
  const expected = challengeDigits(Uint8Array.from([composite.HALF_ECC, ...payload]));
  assert.deepEqual(handed, expected);
  assert.deepEqual(announced && announced.digits, expected);
  assert.ok(expected.every((d) => d >= 1 && d <= 6), `out of range: ${expected}`);

  await app.destroy();
});

test('a wrong challenge comes back as the sentence the device said', async () => {
  /*
   * "Error incorrect challenge was entered" is the failure a caller will
   * actually hit, and it is the one place the device explains itself. Losing
   * it - by treating every 64-byte report as a signature - would turn a clear
   * message into 64 bytes of text-shaped nonsense passed to a verifier.
   */
  const pipe = fakeFirmware();
  const app = await start(FULL(), pipe);

  const pending = assert.rejects(
    () => app.services.okcrypto.composite_sign(101, composite.HALF_ECC, Uint8Array.from([9, 9]), {
      timeoutMs: 2000,
      confirm: () => {
        const bytes = new Uint8Array(64);
        const text = 'Error incorrect challenge was entered';
        for (let i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i);
        pipe.deliver(bytes);
      },
    }),
    /incorrect challenge/,
  );

  await pending;
  await app.destroy();
});

test('the signature is returned as raw bytes, not decrypted', async () => {
  /*
   * send_transport_response(sig, 64, true, true) LOOKS like it seals the
   * response under the transit key. It does not: both trailing arguments are
   * ignored unless outputmode is WEBAUTHN (okcore.cpp:2840-2846), so over the
   * vendor interface this is plaintext. Decrypting it would yield noise, and
   * noise that is exactly 64 bytes long looks like a signature.
   */
  const pipe = fakeFirmware();
  const app = await start(FULL(), pipe);

  const signature = new Uint8Array(64).map((_, i) => (i * 7 + 3) & 0xff);
  const got = await app.services.okcrypto.composite_sign(101, composite.HALF_ECC, Uint8Array.from([1, 2, 3]), {
    timeoutMs: 2000,
    confirm: () => pipe.deliver(signature),
  });

  assert.deepEqual(Array.from(got), Array.from(signature));
  await app.destroy();
});

test('the state broadcast is not mistaken for an answer', async () => {
  /*
   * The device broadcasts its lock state about once a second, so one lands in
   * the middle of almost any operation that waits. Resolving on it would hand
   * back the ASCII "UNLOCKED..." as a signature.
   */
  const pipe = fakeFirmware();
  const app = await start(FULL(), pipe);

  const signature = new Uint8Array(64).fill(0xa5);
  const got = await app.services.okcrypto.composite_sign(101, composite.HALF_ECC, Uint8Array.from([4, 5, 6]), {
    timeoutMs: 2000,
    confirm: () => {
      const state = new Uint8Array(64);
      const text = 'UNLOCKEDv3.0.4-testc';
      for (let i = 0; i < text.length; i++) state[i] = text.charCodeAt(i);
      pipe.deliver(state);
      setTimeout(() => pipe.deliver(signature), 10);
    },
  });

  assert.deepEqual(Array.from(got), Array.from(signature));
  await app.destroy();
});

test('decrypt uses OKDECRYPT and the same framing', async () => {
  const pipe = fakeFirmware();
  const app = await start(FULL(), pipe);

  const pending = app.services.okcrypto.composite_decrypt(102, new Uint8Array(10).fill(1), {
    timeoutMs: 200,
  }).catch(() => null);
  await new Promise((r) => setTimeout(r, 30));

  const f = cryptoFrames(pipe)[0].data;
  assert.equal(f[4], MSG.OKDECRYPT);
  assert.equal(f[5], 102);
  assert.equal(f[6], 10, 'a payload under 57 bytes is a single final chunk');

  await pending;
  await app.destroy();
});

test('a timeout says what the challenge was', async () => {
  /*
   * The most likely reason for silence is that nobody pressed the buttons, and
   * the digits are the one piece of information that makes that actionable.
   */
  const app = await start(FULL());
  await assert.rejects(
    () => app.services.okcrypto.composite_sign(101, composite.HALF_ECC, Uint8Array.from([7]), { timeoutMs: 120 }),
    /were those buttons pressed/,
  );
  await app.destroy();
});
test('the crypto that needs no device works end to end through the service', async () => {
  /*
   * Proof the plugin is useful today rather than a placeholder: a full age
   * round trip, with the shared secret supplied directly instead of derived on
   * a device. That is exactly what the derive operations will provide later,
   * so this exercises everything downstream of them.
   */
  const app = await start(FULL());
  const { okcrypto } = app.services;
  const { toLatin1, fromLatin1 } = require('../src/bytes');

  const shared = new Uint8Array(32).fill(0x21);
  const ciphertext = new Uint8Array(1120).fill(0x43);
  const plaintext = fromLatin1('secrets, but only the ones that fit');

  const file = okcrypto.age.encryptAgeFile(plaintext, { ciphertext, sharedSecret: shared });
  const opened = await okcrypto.age.decryptAgeFile(file, async () => shared);

  assert.equal(toLatin1(opened), toLatin1(plaintext));
  await app.destroy();
});

/* ------------------------------------------------------------------ vault */

/**
 * Stand in for the device's two derive round trips.
 *
 * The derives themselves are proven against the firmware
 * (ok-rn __e2e_tests__/10-derive) and cannot run here - they need a CTAPHID
 * ceremony and a finger. What is testable without a device is everything ABOVE
 * them: that a key is derived once and reused, that a policy of 'always'
 * refuses to reuse it, and that a sealed blob round trips.
 *
 * Each label gets a distinct fake secret, so a vault that mixed two labels up
 * would fail to open rather than quietly returning the wrong plaintext.
 */
function stubDerives(okcrypto) {
  let derives = 0;
  okcrypto.deriveSharedSecretFor = async (label) => {
    derives += 1;
    const secret = new Uint8Array(32);
    for (let i = 0; i < 32; i++) secret[i] = (label.charCodeAt(i % label.length) + i) & 0xff;
    return secret;
  };
  return () => derives;
}

test('a vault blob round trips through the device-derived key', async () => {
  const app = await start(FULL());
  const okcrypto = app.services.okcrypto;
  stubDerives(okcrypto);

  const blob = await okcrypto.deviceVault.seal('github.com', 'hunter2');
  assert.notEqual(blob, 'hunter2', 'the blob is not the plaintext');
  assert.equal(await okcrypto.deviceVault.open('github.com', blob), 'hunter2');
  await app.destroy();
});

test('a different label cannot open it, and says nothing about why', async () => {
  /*
   * AES-GCM does not distinguish a wrong key from a tampered blob, and neither
   * should this - saying which would tell someone holding the blob whether a
   * guessed key was close.
   */
  const app = await start(FULL());
  const okcrypto = app.services.okcrypto;
  stubDerives(okcrypto);

  const blob = await okcrypto.deviceVault.seal('github.com', 'hunter2');
  await assert.rejects(() => okcrypto.deviceVault.open('gitlab.com', blob));
  await app.destroy();
});

test('the key is derived once and reused, because deriving costs a touch', async () => {
  const app = await start(FULL());
  const okcrypto = app.services.okcrypto;
  const derives = stubDerives(okcrypto);

  const blob = await okcrypto.deviceVault.seal('github.com', 'hunter2');
  await okcrypto.deviceVault.open('github.com', blob);
  await okcrypto.deviceVault.open('github.com', blob);

  assert.equal(derives(), 1, 'the device was touched more than once');
  assert.equal(okcrypto.deviceVault.isUnlocked('github.com'), true);
  await app.destroy();
});

test("a policy of 'always' caches nothing", async () => {
  /*
   * The whole point of that policy: every use touches the device. A cache that
   * honoured it only on the way IN would still hand back a key it had already
   * stored.
   */
  const app = await start(FULL());
  const okcrypto = app.services.okcrypto;
  const derives = stubDerives(okcrypto);

  okcrypto.deviceVault.setPolicy('github.com', 'always');
  const blob = await okcrypto.deviceVault.seal('github.com', 'hunter2');
  await okcrypto.deviceVault.open('github.com', blob);

  assert.equal(derives(), 2, 'the key was cached despite the policy');
  assert.equal(okcrypto.deviceVault.isUnlocked('github.com'), false);
  await app.destroy();
});

test('locking drops the key, so the next use touches the device again', async () => {
  const app = await start(FULL());
  const okcrypto = app.services.okcrypto;
  const derives = stubDerives(okcrypto);

  const blob = await okcrypto.deviceVault.seal('github.com', 'hunter2');
  assert.equal(okcrypto.deviceVault.isUnlocked('github.com'), true);

  okcrypto.deviceVault.lock('github.com');
  assert.equal(okcrypto.deviceVault.isUnlocked('github.com'), false);

  assert.equal(await okcrypto.deviceVault.open('github.com', blob), 'hunter2');
  assert.equal(derives(), 2);
  await app.destroy();
});

test('locking the device forgets every cached vault key', async () => {
  /*
   * The device locking is the end of the premise every cached key rests on:
   * each was derived with a touch, and after a lock there is nobody who could
   * have touched anything. A key that outlives the lock is the protection gone
   * while the UI still says "locked".
   *
   * Distinct from reap(), which drops only what has EXPIRED. This drops what is
   * still valid, because validity is no longer the question.
   */
  const app = await start(FULL());
  const okcrypto = app.services.okcrypto;
  stubDerives(okcrypto);

  const one = await okcrypto.deviceVault.seal('github.com', 'hunter2');
  const two = await okcrypto.deviceVault.seal('gitlab.com', 'hunter3');
  assert.equal(okcrypto.deviceVault.isUnlocked('github.com'), true);
  assert.equal(okcrypto.deviceVault.isUnlocked('gitlab.com'), true);

  okcrypto.deviceVault.lockAll();

  assert.equal(okcrypto.deviceVault.isUnlocked('github.com'), false);
  assert.equal(okcrypto.deviceVault.isUnlocked('gitlab.com'), false);

  /*
   * And the blobs still open afterwards, by deriving again. Forgetting a key
   * must not be indistinguishable from destroying the data it protects.
   */
  assert.equal(await okcrypto.deviceVault.open('github.com', one), 'hunter2');
  assert.equal(await okcrypto.deviceVault.open('gitlab.com', two), 'hunter3');
  await app.destroy();
});

test('sign() sends the bytes as given - no half selector, one report back', async () => {
  // The ordinary-key path. composite_sign prepends a selector because the
  // firmware's composite handler wants one; an Ed25519 slot wants the digest
  // alone, and the two were one function until the full run said otherwise.
  const pipe = fakeFirmware();
  const app = await start(FULL(), pipe);
  const payload = Uint8Array.from([1, 2, 3, 4, 5]);
  const pending = app.services.okcrypto.sign(101, payload, { timeoutMs: 200 }).catch(() => null);
  await new Promise((r) => setTimeout(r, 30));
  const frames = cryptoFrames(pipe).map((w) => w.data);
  assert.equal(frames.length, 1);
  assert.equal(frames[0][4], MSG.OKSIGN);
  assert.equal(frames[0][5], 101);
  assert.equal(frames[0][7], 1, 'the digest starts at buffer[7], no selector');
  await pending;
  await app.destroy();
});

/* ------------------------------- age files addressed to a SLOT */

const pqcLib = require('../src/crypto/age_pqc');

test('a slot identity is the public key, a recipient and an identity', async () => {
  const publicKey = new Uint8Array(1216);
  for (let i = 0; i < publicKey.length; i++) publicKey[i] = (i * 11 + 5) & 0xff;

  const pipe = fakeFirmware({ pubKeys: { 110: publicKey } });
  const app = await start(FULL(), pipe);

  const id = await app.services.okcrypto.deviceAge.slotIdentity(110);

  assert.equal(id.slot, 110);
  assert.equal(id.publicKey.length, 1216);
  assert.ok(id.recipientString.startsWith('age1onlykey1'));
  assert.ok(id.identityString.startsWith('AGE-PLUGIN-ONLYKEY-1'));

  /* And the identity names this key, not merely this slot. */
  const decoded = pqcLib.decodeIdentity(id.identityString);
  assert.equal(decoded.slot, 110);
  assert.equal(pqcLib.identityMatchesKey(decoded, publicKey), true);
  assert.equal(pqcLib.identityMatchesKey(decoded, new Uint8Array(1216)), false);
});

test('an identity for a slot that has been regenerated is REFUSED, not tried', async () => {
  /*
   * The reason the versioned identity carries a fingerprint at all. Without
   * this the decrypt would go ahead, spend a three-button confirmation, and
   * fail as an age "no identity matched" - which is true and points at the
   * file rather than at the key that changed underneath it.
   */
  const original = new Uint8Array(1216).fill(3);
  const regenerated = new Uint8Array(1216).fill(4);

  const identity = pqcLib.encodeSlotIdentity(110, original);

  /* The device now holds the OTHER key. */
  const pipe = fakeFirmware({ pubKeys: { 110: regenerated } });
  const app = await start(FULL(), pipe);

  await assert.rejects(
    () => app.services.okcrypto.deviceAge.decryptWithIdentity(new Uint8Array(8), identity),
    /generated again/,
  );
});

test('decryptWithIdentity sends a DERIVED identity down the label path', async () => {
  /*
   * The two identity kinds share an HRP because age picks a plugin binary
   * from that prefix. The happy consequence is that a caller holds a string
   * and does not have to know which kind it is - so this checks the branch
   * lands on the label side, by the error it produces when no device answers
   * a derive.
   */
  const pipe = fakeFirmware();
  const app = await start(FULL(), pipe);

  const derived = pqcLib.encodeIdentity('me@example.com');
  const decoded = pqcLib.decodeIdentity(derived);
  assert.equal(decoded.derived, true);
  assert.equal(decoded.label, 'me@example.com');

  /* Not an OnlyKey identity at all is refused before anything is sent. */
  await assert.rejects(
    () => app.services.okcrypto.deviceAge.decryptWithIdentity(new Uint8Array(8), 'nonsense'),
    /not an OnlyKey age identity/,
  );
});

/* --------------------------------------------------- the stored policy */

/**
 * A store, the three methods the host plugin wants, kept in a Map.
 *
 * Shared between two plugin instances on purpose: the restart case below is
 * not a metaphor, it is a second app built over the same bytes.
 */
function memoryStore(backing = new Map()) {
  return {
    backing,
    getItem: async (k) => (backing.has(k) ? backing.get(k) : null),
    setItem: async (k, v) => { backing.set(k, v); },
    removeItem: async (k) => { backing.delete(k); },
  };
}

function startStored(store, pipe = fakeFirmware()) {
  const plugins = FULL();
  plugins.config = { transport: { pipe }, host: { store } };
  return new Promise((resolve, reject) => {
    const app = Rectify.build(plugins, (err, started) => {
      if (err) reject(err);
      else resolve(started);
    });
    app.start();
  });
}

test('changing a policy writes it to the stored record', async () => {
  /*
   * The live map used to be the only copy that received a change, so a screen
   * redrawing from list() read the policy the credential was SAVED with and
   * the control snapped back to it. See
   * ok-rn/FINDING-a-vault-policy-change-was-never-stored.md.
   */
  const store = memoryStore();
  const app = await startStored(store);
  const okcrypto = app.services.okcrypto;
  stubDerives(okcrypto);

  await okcrypto.deviceVault.save('github.com', 'hunter2');
  await okcrypto.deviceVault.setPolicy('github.com', 'always');

  const [record] = await okcrypto.deviceVault.list();
  assert.equal(record.policy, 'always', 'the record kept the policy from save time');
  assert.ok(record.encrypted, 'the read-modify-write lost the sealed blob');
  await app.destroy();
});

test('a stored policy governs caching again after a restart', async () => {
  /*
   * The half that is not cosmetic. A fresh process builds an empty policy map,
   * so getPolicy fell through to the default and vaultKeys.put cached a key
   * for a service stored under 'always' - the one policy whose entire meaning
   * is that the key is never held.
   */
  const store = memoryStore();

  const first = await startStored(store);
  stubDerives(first.services.okcrypto);
  await first.services.okcrypto.deviceVault.save('github.com', 'hunter2');
  await first.services.okcrypto.deviceVault.setPolicy('github.com', 'always');
  await first.destroy();

  const second = await startStored(store);
  const okcrypto = second.services.okcrypto;
  const derives = stubDerives(okcrypto);

  const [record] = await okcrypto.deviceVault.list();
  assert.equal(okcrypto.deviceVault.getPolicy('github.com'), 'always');

  await okcrypto.deviceVault.open('github.com', record.encrypted);
  await okcrypto.deviceVault.open('github.com', record.encrypted);
  assert.equal(derives(), 2, 'the key was cached despite the stored policy');
  assert.equal(okcrypto.deviceVault.isUnlocked('github.com'), false);
  await second.destroy();
});

test('a policy set before the credential exists is written when it is saved', async () => {
  /* setPolicy has no record to update yet; save() records getPolicy(). */
  const store = memoryStore();
  const app = await startStored(store);
  const okcrypto = app.services.okcrypto;
  stubDerives(okcrypto);

  await okcrypto.deviceVault.setPolicy('gitlab.com', 'startup');
  await okcrypto.deviceVault.save('gitlab.com', 'hunter2');

  const [record] = await okcrypto.deviceVault.list();
  assert.equal(record.policy, 'startup');
  await app.destroy();
});
