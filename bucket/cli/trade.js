'use strict';
/*
 * THIS COMPUTER TRADES ITS BUCKET WITH A PAIRED DEVICE (ok-edge plan S3; Brad, 2026-10-25: "the CLI pair is our hook to
 * try and sync with - those are the pre-set-up trusted devices, what we can replicate with"; "the stale mobile device
 * will most likely talk to the desktop at one point, so they trade when they can").
 *
 * Run whenever this computer and a cli-paired device talk (edge/cli/register.js, after the log swap), over that pair's
 * channel. The computer's side of bucket/src/trade.js:
 *
 *   - the bucket identity is read from the key this computer talks to (the phone's key over Bluetooth - the same
 *     identity's key; no press);
 *   - the bucket is the one this computer keeps opened for that identity (bucket/cli/home.js identityFile) - an empty
 *     one the first time: a new machine starts empty and catches up on its first trade;
 *   - its proof material - the bucket key and the certificate - is made once through that key (the key's ECDH and its
 *     signature: two presses on production) and kept beside the bucket, owner-only. Not in the bucket: a bucket holds
 *     no secret (bucket.js), and the bucket key is one;
 *   - the trade runs on a copy; its result is merged into the kept file under the file's lock, so a desktop app
 *     writing the same file meanwhile loses nothing.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const home = require('./home');
const bucketLib = require('../src/bucket');
const rules = require('../src/rules');
const trade = require('../src/trade');
const bid = require('../src/bucket-identity');
const { toHex, fromHex } = require('../../src/bytes');

const rnd = (n) => new Uint8Array(crypto.randomBytes(n));

/*
 * THE STORE RULES THE APP USES TOO - each feature's own merge where it has one. Required softly: the bucket stands
 * without any feature folder (scripts/check-without.js), and a store without its rule takes the generic newer-wins.
 */
function storeRules() {
  const out = {};
  try {
    const kc = rules.keychain(require('../../keychain/src/list'));
    out.keychain = kc;
    out['keychain-test'] = kc;
  } catch { /* no Key Chain here */ }
  out.guestbook = rules.guestbook();
  out['guestbook-test'] = rules.guestbook();
  out.passwords = rules.passwords();
  return out;
}

/* the bucket key and certificate of an identity, beside its bucket: buckets/<net>/<id>.key */
const keyFile = (id, net) => home.identityFile(id, net).replace(/\.json$/, '.key');

function loadMe(id, net) {
  try {
    const j = JSON.parse(fs.readFileSync(keyFile(id, net), 'utf8'));
    return {
      id,
      identityPublicKey: fromHex(j.identityPublicKey),
      bucketKey: { secretKey: fromHex(j.bucketSecretKey), publicKey: fromHex(j.bucketPublicKey) },
      certificate: fromHex(j.certificate),
    };
  } catch {
    return null;
  }
}

async function makeMe(okcrypto, id, identityPublicKey, net, say, opts) {
  say('bucket: making this computer\'s bucket key, once - the key asks for two presses');
  const bucketKey = await bid.deriveBucketKey(okcrypto, identityPublicKey, opts);
  const certificate = await bid.certify(okcrypto, identityPublicKey, bucketKey.publicKey, opts);
  const file = keyFile(id, net);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, `${JSON.stringify({
    identityPublicKey: toHex(identityPublicKey), bucketPublicKey: toHex(bucketKey.publicKey),
    bucketSecretKey: toHex(bucketKey.secretKey), certificate: toHex(certificate),
  })}\n`, { mode: 0o600 });
  return { id, identityPublicKey, bucketKey, certificate };
}

/**
 * Trade this computer's bucket with the device at the other end of `send`.
 * @param {{send: (message: object) => Promise<object|null>, okcrypto: object, net?: 'live'|'test', say?: (l: string) => void, keyOpts?: object}} o
 *   send: one message to the paired device, its answer (null when it did not answer); okcrypto: the key this computer
 *   talks to (for the bucket identity, and the bucket key the first time); keyOpts: the presses' confirm/onKeepAlive
 * @returns {Promise<{traded: boolean, why?: string, taken?: object, gave?: object}>}
 */
async function tradeWith({ send, okcrypto, net = 'live', say = () => {}, keyOpts = {} }) {
  const { id, publicKey } = await bid.readIdentity(okcrypto);
  const file = home.identityFile(id, net);
  if (!home.hasIdentityBucket(id, net)) home.keepIdentityBucket(id, net, bucketLib.create({ owner: id }));
  const me = loadMe(id, net) || await makeMe(okcrypto, id, publicKey, net, say, keyOpts);
  const copy = home.read(file);
  const r = storeRules();
  const c = trade.computerSide({ bucket: copy, me, randomBytes: rnd, rules: r });
  const m2 = c.prove(await send(c.hello()));
  if (!m2) return { traded: false, why: 'the device did not prove this bucket identity, or does not trade yet' };
  const g = c.give(await send(m2));
  if (!g) return { traded: false, why: 'the device did not answer the trade' };
  const done = c.finish(await send(g.message));
  /* what the trade changed, into the kept file as it is NOW (the newer wins either way round) */
  home.update(file, (b) => {
    const merged = bucketLib.merge(b, copy, { rules: r }).bucket;
    b.stores = merged.stores;
    b.clock = merged.clock;
  });
  return { traded: true, taken: g.taken, gave: done ? done.taken : {} };
}

module.exports = { tradeWith, storeRules, keyFile };
