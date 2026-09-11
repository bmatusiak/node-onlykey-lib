/*
 * FidoAdmin against an authenticator that behaves the way the firmware does.
 *
 * The fake below is not a stub that says yes. It is ctap_client_pin and its
 * two helpers written out in JavaScript - the same state machine, the same
 * error codes, the same counter, and in particular the same two behaviours
 * that make this protocol dangerous to drive by hand:
 *
 *   a wrong PIN regenerates the key agreement pair BEFORE it decrements
 *   (ctap.cpp:2118-2121), and
 *
 *   the counter never rises except on success, and at zero the FIDO2 side is
 *   gone for good (ctap.h:170).
 *
 * A client that caches the authenticator's public key passes a naive mock and
 * fails here on the second attempt, which is the whole reason the fake exists.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const { CtapHid, CTAP2_CMD, CTAPHID } = require('../src/protocol/ctaphid');
const { FidoAdmin, RESET_CONFIRMATION } = require('../src/device/fido');
const clientpin = require('../src/protocol/clientpin');
const credmgmt = require('../src/protocol/credmgmt');
const cbor = require('../src/protocol/cbor');
const cose = require('../src/protocol/cose');
const { fakeCtapHid } = require('./helpers/fake-ctaphid');
const { toHex, utf8ToBytes } = require('../src/bytes');

/* ---- the firmware, in miniature ---------------------------------------- */

const ERR = {
  NO_CREDENTIALS: 0x2e,
  PIN_INVALID: 0x31,
  PIN_BLOCKED: 0x32,
  PIN_AUTH_INVALID: 0x33,
  NOT_ALLOWED: 0x30,
  PIN_NOT_SET: 0x35,
  OTHER: 0x7f,
};

const ZERO_IV = Buffer.alloc(16);

function aes(mode, key, data) {
  const c = mode === 'e'
    ? crypto.createCipheriv('aes-256-cbc', Buffer.from(key), ZERO_IV)
    : crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), ZERO_IV);
  c.setAutoPadding(false);
  return new Uint8Array(Buffer.concat([c.update(Buffer.from(data)), c.final()]));
}

function sha(...parts) {
  const h = crypto.createHash('sha256');
  for (const p of parts) h.update(Buffer.from(p));
  return new Uint8Array(h.digest());
}

function mac16(key, data) {
  const h = crypto.createHmac('sha256', Buffer.from(key));
  h.update(Buffer.from(data));
  return new Uint8Array(h.digest()).subarray(0, 16);
}

function sameBytes(a, b) {
  return a && b && toHex(Uint8Array.from(a)) === toHex(Uint8Array.from(b));
}

/**
 * @param {object} [state] pin (a string or null), retries, and a log of what
 *                         the authenticator was asked to do
 */
function firmware(state = {}) {
  const self = {
    pin: state.pin === undefined ? null : state.pin,
    retries: state.retries === undefined ? 8 : state.retries,
    pinToken: new Uint8Array(16).fill(0xa5),
    /*
     * Resident credentials, and the cursors that walk them - which are
     * FUNCTION STATICS in the firmware (ctap.cpp:1736-1741), one set shared
     * by every channel. Modelled as shared state here for the same reason: a
     * client that interleaves two walks corrupts both, and a mock with
     * per-request state would let that pass.
     */
    credentials: state.credentials || [],
    rpCursor: -1,
    rkCursor: -1,
    rkList: [],
    rpAuth: false,
    rkAuth: false,
    deleted: [],
    keyAgreements: 0,
    keyAgreementRequests: 0,
    resets: 0,
    seen: [],
    /* Regenerated on failure, exactly as ctap_reset_key_agreement() does. */
    ecdh: null,
  };

  function newKeyAgreement() {
    self.ecdh = crypto.createECDH('prime256v1');
    self.ecdh.generateKeys();
    self.keyAgreements++;
    return new Uint8Array(self.ecdh.getPublicKey());
  }
  newKeyAgreement();

  function secretFor(coseKey) {
    const peer = cose.decodeP256(coseKey).uncompressed;
    return sha(new Uint8Array(self.ecdh.computeSecret(Buffer.from(peer))));
  }

  function fail(code) {
    /* The key goes first, then the counter - the order that costs two tries. */
    newKeyAgreement();
    self.retries--;
    return { status: self.retries <= 0 ? ERR.PIN_BLOCKED : code };
  }

  /** The relying parties, in the order the firmware would walk them. */
  function rpsOf() {
    const seen = [];
    for (const c of self.credentials) {
      if (!seen.some((r) => r.id === c.rpId)) {
        seen.push({ id: c.rpId, name: c.rpName || '', hash: c.rpIdHash });
      }
    }
    return seen;
  }

  self.credMgmt = (params) => {
    const sub = params.get(credmgmt.PARAM.SUB_COMMAND);
    const needsAuth = [1, 2, 4, 6].includes(sub);

    if (needsAuth) {
      /*
       * The firmware hashes the subcommand byte followed by the RAW CBOR of
       * subCommandParams as it arrived (ctap.cpp:1607 over
       * {cmd, subCommandParamsCborCopy}). Re-encoding here rather than
       * keeping the wire bytes is the one liberty this fake takes, and it is
       * safe only because cbor.js is canonical: the same map encodes to the
       * same bytes every time.
       */
      const raw = params.has(credmgmt.PARAM.SUB_COMMAND_PARAMS)
        ? cbor.encode(params.get(credmgmt.PARAM.SUB_COMMAND_PARAMS))
        : null;
      const expect = mac16(self.pinToken, credmgmt.pinAuthMessage(sub, raw));
      if (!sameBytes(params.get(credmgmt.PARAM.PIN_AUTH), expect)) {
        /* And a wrong one costs a PIN attempt - ctap.cpp:1609-1616. */
        self.retries--;
        return { status: ERR.PIN_AUTH_INVALID };
      }
    } else if (params.has(credmgmt.PARAM.PIN_AUTH)) {
      /* *Next carries no pinAuth; one here would be hashed against nothing. */
      return { status: ERR.OTHER };
    }

    if (sub === credmgmt.SUB.METADATA) {
      return new Map([
        [credmgmt.RESP.EXISTING_RESIDENT_CREDENTIALS, self.credentials.length],
        [credmgmt.RESP.MAX_POSSIBLE_REMAINING, 12 - self.credentials.length],
      ]);
    }

    /* Everything but metadata answers an EMPTY body when nothing is stored. */
    if (!self.credentials.length) return undefined;

    if (sub === credmgmt.SUB.RP_BEGIN) {
      self.rpCursor = 0;
      self.rpAuth = true;
      const rps = rpsOf();
      const rp = rps[0];
      const out = new Map([
        [credmgmt.RESP.RP, new Map([['id', rp.id], ['name', rp.name]])],
        [credmgmt.RESP.RP_ID_HASH, rp.hash],
      ]);
      /* The total comes with the FIRST answer only. */
      if (rps.length > 0) out.set(credmgmt.RESP.TOTAL_RPS, rps.length);
      return out;
    }

    if (sub === credmgmt.SUB.RP_NEXT) {
      if (!self.rpAuth) return { status: ERR.NO_CREDENTIALS };
      const rps = rpsOf();
      self.rpCursor += 1;
      const rp = rps[self.rpCursor];
      if (!rp) { self.rpAuth = false; return { status: ERR.NO_CREDENTIALS }; }
      return new Map([
        [credmgmt.RESP.RP, new Map([['id', rp.id], ['name', rp.name]])],
        [credmgmt.RESP.RP_ID_HASH, rp.hash],
      ]);
    }

    if (sub === credmgmt.SUB.RK_BEGIN) {
      const wanted = params.get(credmgmt.PARAM.SUB_COMMAND_PARAMS)
        .get(credmgmt.SUB_PARAM.RP_ID_HASH);
      self.rkList = self.credentials.filter((c) => sameBytes(c.rpIdHash, wanted));
      self.rkCursor = 0;
      self.rkAuth = true;
      if (!self.rkList.length) return { status: ERR.NO_CREDENTIALS };
      return credentialMap(self.rkList[0], self.rkList.length);
    }

    if (sub === credmgmt.SUB.RK_NEXT) {
      if (!self.rkAuth) return { status: ERR.NO_CREDENTIALS };
      self.rkCursor += 1;
      const c = self.rkList[self.rkCursor];
      if (!c) { self.rkAuth = false; return { status: ERR.NO_CREDENTIALS }; }
      return credentialMap(c, null);
    }

    if (sub === credmgmt.SUB.RK_DELETE) {
      const id = params.get(credmgmt.PARAM.SUB_COMMAND_PARAMS)
        .get(credmgmt.SUB_PARAM.CREDENTIAL_ID);
      const wanted = id.get('id');
      const before = self.credentials.length;
      self.credentials = self.credentials.filter((c) => !sameBytes(c.id, wanted));
      if (self.credentials.length === before) return { status: ERR.NO_CREDENTIALS };
      self.deleted.push(wanted);
      return undefined;
    }

    return { status: ERR.OTHER };
  };

  function credentialMap(c, total) {
    const out = new Map([
      [credmgmt.RESP.USER, new Map([['id', c.id], ['name', c.userName]])],
      [credmgmt.RESP.CREDENTIAL_ID, new Map([['id', c.id], ['type', 'public-key']])],
      [credmgmt.RESP.PUBLIC_KEY, new Map([[1, 2], [3, -7]])],
    ]);
    if (total !== null) out.set(credmgmt.RESP.TOTAL_CREDENTIALS, total);
    return out;
  }

  self.onCbor = (cmd, params) => {
    self.seen.push(cmd);

    if (cmd === CTAP2_CMD.GET_INFO) {
      const options = new Map([['rk', true], ['up', true]]);
      if (self.pin !== null) options.set('clientPin', true);
      else options.set('clientPin', false);
      return new Map([
        [1, ['FIDO_2_0']],
        [3, new Uint8Array(16)],
        [4, options],
        [6, [1]],
      ]);
    }

    if (cmd === CTAP2_CMD.RESET) {
      self.resets++;
      self.pin = null;
      self.retries = 8;
      return undefined;
    }

    if (cmd === CTAP2_CMD.CREDENTIAL_MANAGEMENT) return self.credMgmt(params);

    if (cmd !== CTAP2_CMD.CLIENT_PIN) return { status: ERR.OTHER };

    if (params.get(clientpin.PARAM.PIN_PROTOCOL) !== 1) return { status: ERR.OTHER };
    const sub = params.get(clientpin.PARAM.SUB_COMMAND);

    if (sub === clientpin.SUB.GET_RETRIES) {
      return new Map([[clientpin.RESP.RETRIES, self.retries]]);
    }

    if (sub === clientpin.SUB.GET_KEY_AGREEMENT) {
      self.keyAgreementRequests++;
      return new Map([
        [clientpin.RESP.KEY_AGREEMENT,
          cose.encodeP256(new Uint8Array(self.ecdh.getPublicKey()))],
      ]);
    }

    if (self.retries <= 0) return { status: ERR.PIN_BLOCKED };

    const secret = secretFor(params.get(clientpin.PARAM.KEY_AGREEMENT));
    const enc = params.get(clientpin.PARAM.NEW_PIN_ENC);
    const hashEnc = params.get(clientpin.PARAM.PIN_HASH_ENC);

    if (sub === clientpin.SUB.SET_PIN) {
      if (self.pin !== null) return { status: ERR.NOT_ALLOWED };
      if (!sameBytes(params.get(clientpin.PARAM.PIN_AUTH), mac16(secret, enc))) {
        return { status: ERR.PIN_AUTH_INVALID };
      }
      const plain = aes('d', secret, enc);
      self.pin = Buffer.from(plain.subarray(0, pinLength(plain))).toString();
      return undefined;
    }

    if (sub === clientpin.SUB.CHANGE_PIN) {
      if (self.pin === null) return { status: ERR.PIN_NOT_SET };
      const both = new Uint8Array(enc.length + hashEnc.length);
      both.set(enc);
      both.set(hashEnc, enc.length);
      if (!sameBytes(params.get(clientpin.PARAM.PIN_AUTH), mac16(secret, both))) {
        return { status: ERR.PIN_AUTH_INVALID };
      }
      if (!sameBytes(aes('d', secret, hashEnc), sha(utf8ToBytes(self.pin)).subarray(0, 16))) {
        return fail(ERR.PIN_INVALID);
      }
      const plain = aes('d', secret, enc);
      self.pin = Buffer.from(plain.subarray(0, pinLength(plain))).toString();
      self.retries = 8;
      return undefined;
    }

    if (sub === clientpin.SUB.GET_PIN_TOKEN) {
      if (self.pin === null) return { status: ERR.PIN_NOT_SET };
      if (!sameBytes(aes('d', secret, hashEnc), sha(utf8ToBytes(self.pin)).subarray(0, 16))) {
        return fail(ERR.PIN_INVALID);
      }
      self.retries = 8;
      return new Map([[clientpin.RESP.PIN_TOKEN, aes('e', secret, self.pinToken)]]);
    }

    return { status: ERR.OTHER };
  };

  return self;
}

/** trailing_zeros(buf, 63), ctap.cpp:2007. */
function pinLength(plain) {
  let i = 63;
  let c = 0;
  while (plain[i] === 0 && i) { i--; c++; }
  return 64 - c;
}

async function admin(state) {
  const device = firmware(state);
  const transport = fakeCtapHid({ onCbor: device.onCbor });
  const ctap = new CtapHid(transport);
  await ctap.init();
  return { device, fido: new FidoAdmin(ctap), transport };
}

/* ----------------------------------------------------------------- tests */

test('pinState reads the three-way answer out of getInfo', async () => {
  const blank = await admin({ pin: null });
  const state = await blank.fido.pinState();
  assert.equal(state.supported, true);
  assert.equal(state.set, false);
  assert.deepEqual(state.protocols, [1]);

  const withPin = await admin({ pin: '1234' });
  assert.equal((await withPin.fido.pinState()).set, true);
});

test('getRetries costs nothing and needs no PIN', async () => {
  const { fido, device } = await admin({ retries: 8 });
  assert.equal(await fido.getRetries(), 8);
  assert.equal(device.retries, 8);
});

test('setPin lands a PIN the firmware can read back', async () => {
  const { fido, device } = await admin({ pin: null });
  assert.equal(await fido.setPin('2468'), true);
  assert.equal(device.pin, '2468');
  assert.equal(device.retries, 8, 'setting a first PIN spends nothing');
});

test('setPin refuses a key that already has one, before sending anything', async () => {
  const { fido, device } = await admin({ pin: '1234' });
  const before = device.seen.length;
  await assert.rejects(() => fido.setPin('9999'), /already set/);
  /* getInfo only - no clientPin subcommand went out. */
  assert.ok(!device.seen.slice(before).includes(CTAP2_CMD.CLIENT_PIN));
});

test('getPinToken returns the token the device holds', async () => {
  const { fido, device } = await admin({ pin: '1234' });
  const token = await fido.getPinToken('1234');
  assert.equal(toHex(token), toHex(device.pinToken));
});

test('changePin proves the old PIN and installs the new one', async () => {
  const { fido, device } = await admin({ pin: '1234' });
  await fido.changePin('1234', '567890');
  assert.equal(device.pin, '567890');
  assert.equal(toHex(await fido.getPinToken('567890')), toHex(device.pinToken));
});

test('a fresh key agreement is fetched for EVERY attempt', async () => {
  /*
   * The bug this guards: caching the authenticator public key. The device
   * regenerates its pair on every failure, so a cached one produces a shared
   * secret nobody can verify - the second attempt fails no matter what PIN
   * is typed, and the user has spent two of eight to learn one thing.
   */
  const { fido, device } = await admin({ pin: '1234' });
  const asked = device.keyAgreementRequests;
  const made = device.keyAgreements;

  await assert.rejects(() => fido.getPinToken('0000'));
  await assert.rejects(() => fido.getPinToken('0001'));

  assert.equal(
    device.keyAgreementRequests - asked, 2,
    'one getKeyAgreement per attempt, no more and no fewer',
  );
  assert.equal(device.keyAgreements - made, 2, 'the device threw its pair away twice');
  assert.equal(device.retries, 6, 'two attempts, two lives');
});

test('a wrong PIN comes back with the count, not a bare status code', async () => {
  const { fido } = await admin({ pin: '1234', retries: 8 });
  await assert.rejects(() => fido.getPinToken('9999'), (e) => {
    assert.match(e.message, /7 attempts left/);
    assert.match(e.message, /one was just spent/);
    assert.equal(e.retries, 7);
    return true;
  });
});

test('a correct PIN restores the count, the way the firmware does', async () => {
  const { fido, device } = await admin({ pin: '1234' });
  await assert.rejects(() => fido.getPinToken('9999'));
  assert.equal(device.retries, 7);

  await fido.getPinToken('1234');
  assert.equal(device.retries, 8);
});

test('the last attempt is not spent unless the caller says so', async () => {
  const { fido, device } = await admin({ pin: '1234', retries: 1 });
  await assert.rejects(() => fido.getPinToken('9999'), /one FIDO2 attempt remains/i);
  assert.equal(device.retries, 1, 'nothing was sent');

  await assert.rejects(
    () => fido.getPinToken('9999', { allowLastAttempt: true }),
    /0 attempts left/,
  );
  assert.equal(device.retries, 0);
});

test('a locked key is reported as locked rather than tried again', async () => {
  const { fido, device } = await admin({ pin: '1234', retries: 0 });
  await assert.rejects(() => fido.getPinToken('1234'), /no FIDO2 attempts left/);
  assert.equal(device.retries, 0);
});

test('reset needs the exact words, and nothing goes out without them', async () => {
  const { fido, device } = await admin({ pin: '1234' });

  await assert.rejects(() => fido.reset(true), /exact confirmation/);
  await assert.rejects(() => fido.reset('yes'), /exact confirmation/);
  await assert.rejects(() => fido.reset(RESET_CONFIRMATION.toLowerCase()), /exact confirmation/);
  assert.equal(device.resets, 0, 'a near miss must not reach the device');

  assert.equal(await fido.reset(RESET_CONFIRMATION), true);
  assert.equal(device.resets, 1);
  assert.equal(device.pin, null, 'a reset takes the PIN with it');
});

test('the channel is allocated once and reused across operations', async () => {
  /*
   * The firmware keeps ten channel records and frees none (ctaphid.cpp:67).
   * A client that calls init() per operation runs out and then collides with
   * whoever holds the channel it is handed next.
   */
  const { fido, transport } = await admin({ pin: '1234' });
  await fido.getRetries();
  await fido.getPinToken('1234');

  const inits = transport.writes.filter((w) => (w.data[4] & 0x7f) === CTAPHID.INIT);
  assert.equal(inits.length, 1);
});

/* ----------------------------------------------- credential management */

function credential(rpId, userName, n) {
  return {
    rpId,
    rpName: rpId,
    rpIdHash: new Uint8Array(32).fill(rpId.length),
    id: new Uint8Array(16).fill(n),
    userName,
  };
}

test('a key with no resident credentials says so, rather than failing', async () => {
  /*
   * Every subcommand but metadata answers SUCCESS WITH AN EMPTY BODY when
   * nothing is stored (ctap.cpp:1754). That is "none", not a malformed
   * reply - and telling those two apart is exactly why metadata is asked
   * first.
   */
  const { fido, device } = await admin({ pin: '1234' });
  const token = await fido.getPinToken('1234');

  const meta = await fido.credentialCount(token);
  assert.equal(meta.stored, 0);
  assert.equal(meta.remaining, 12);
  assert.deepEqual(await fido.listCredentials(token), []);
  assert.equal(device.retries, 8, 'listing must not cost an attempt');
});

test('credentials come back grouped by the site that owns them', async () => {
  const { fido } = await admin({
    pin: '1234',
    credentials: [
      credential('example.com', 'alice', 1),
      credential('example.com', 'bob', 2),
      credential('other.org', 'carol', 3),
    ],
  });
  const token = await fido.getPinToken('1234');

  assert.equal((await fido.credentialCount(token)).stored, 3);

  const sites = await fido.listCredentials(token);
  assert.equal(sites.length, 2);
  assert.equal(sites[0].id, 'example.com');
  assert.equal(sites[0].credentials.length, 2);
  assert.equal(sites[1].id, 'other.org');
  assert.equal(sites[1].credentials.length, 1);

  assert.equal(credmgmt.describeUser(sites[0].credentials[0].user), 'alice');
  assert.equal(credmgmt.describeUser(sites[1].credentials[0].user), 'carol');
});

test('the walks are not interleaved, because the cursors are shared', async () => {
  /*
   * The firmware keeps ONE rp cursor and ONE rk cursor as function statics.
   * Walking sites and credentials at the same time moves both against each
   * other. listCredentials finishes the site walk before it starts any
   * credential walk, and this test would catch a rewrite that did not.
   */
  const { fido } = await admin({
    pin: '1234',
    credentials: [
      credential('a.example', 'one', 1),
      credential('bb.example', 'two', 2),
      credential('ccc.example', 'three', 3),
    ],
  });
  const token = await fido.getPinToken('1234');

  const sites = await fido.listCredentials(token);
  assert.equal(sites.length, 3);
  assert.deepEqual(sites.map((s) => s.id), ['a.example', 'bb.example', 'ccc.example']);
  for (const site of sites) assert.equal(site.credentials.length, 1);
});

test('a credential is deleted by the descriptor the listing returned', async () => {
  const { fido, device } = await admin({
    pin: '1234',
    credentials: [
      credential('example.com', 'alice', 1),
      credential('example.com', 'bob', 2),
    ],
  });
  const token = await fido.getPinToken('1234');

  const sites = await fido.listCredentials(token);
  const bob = sites[0].credentials.find(
    (c) => credmgmt.describeUser(c.user) === 'bob',
  );

  await fido.deleteCredential(token, bob.credentialId);
  assert.equal(device.credentials.length, 1);
  assert.equal((await fido.credentialCount(token)).stored, 1);

  const after = await fido.listCredentials(token);
  assert.equal(after[0].credentials.length, 1);
  assert.equal(credmgmt.describeUser(after[0].credentials[0].user), 'alice');
});

test('deleting by anything but a descriptor is refused before it is sent', async () => {
  const { fido, device } = await admin({
    pin: '1234',
    credentials: [credential('example.com', 'alice', 1)],
  });
  const token = await fido.getPinToken('1234');

  await assert.rejects(() => fido.deleteCredential(token, 0), /not an index/);
  await assert.rejects(() => fido.deleteCredential(token, 'alice'), /not an index/);
  assert.equal(device.credentials.length, 1, 'nothing should have been deleted');
});

test('the pinAuth covers the subcommand AND its exact parameter bytes', async () => {
  /*
   * A wrong pinAuth here decrements the SAME eight-attempt counter a wrong
   * PIN does (ctap.cpp:1609-1616), so a listing bug can lock a key as surely
   * as a PIN bug. The fake verifies the HMAC the firmware's way; these
   * assertions pin the message it is taken over.
   */
  const message = credmgmt.pinAuthMessage(credmgmt.SUB.METADATA);
  assert.equal(toHex(message), '01', 'no params: one byte, the subcommand');

  const params = new Map([[credmgmt.SUB_PARAM.RP_ID_HASH, new Uint8Array(32).fill(5)]]);
  const withParams = credmgmt.pinAuthMessage(
    credmgmt.SUB.RK_BEGIN, cbor.encode(params),
  );
  assert.equal(withParams[0], credmgmt.SUB.RK_BEGIN);
  assert.equal(toHex(withParams.subarray(1)), toHex(cbor.encode(params)));
});

test('a wrong pinAuth costs an attempt, which is why the bytes are pinned', async () => {
  const { fido, device } = await admin({
    pin: '1234',
    credentials: [credential('example.com', 'alice', 1)],
  });
  const token = await fido.getPinToken('1234');
  const before = device.retries;

  /* A token that is not the device's: the HMAC will not verify. */
  const wrong = new Uint8Array(16).fill(0x11);
  await assert.rejects(() => fido.credentialCount(wrong));
  assert.equal(device.retries, before - 1, 'a bad pinAuth spends a PIN attempt');
});

test('the walk subcommands send NO pinAuth', async () => {
  /*
   * Only metadata, RP begin, RK begin and delete take one
   * (ctap.cpp:1598-1605). Sending one on a *Next would be verified against a
   * message the firmware never hashes - and the mismatch costs an attempt.
   */
  assert.equal(credmgmt.rpNextParams().has(credmgmt.PARAM.PIN_AUTH), false);
  assert.equal(credmgmt.rkNextParams().has(credmgmt.PARAM.PIN_AUTH), false);
  assert.equal(credmgmt.metadataParams(new Uint8Array(16)).has(credmgmt.PARAM.PIN_AUTH), true);
});

test('an rpIdHash that is not 32 bytes is refused, not hashed by us', async () => {
  /*
   * It comes back from the RP walk. Hashing an rpId by hand here is how a
   * client ends up enumerating a site it only thinks it named.
   */
  assert.throws(
    () => credmgmt.rkBeginParams(new Uint8Array(16), new Uint8Array(20)),
    /32 bytes/,
  );
});
