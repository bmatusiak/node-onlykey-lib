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
const replicate = require('../src/replicate');
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
  out.cryptobox = rules.cryptobox();
  out['cryptobox-test'] = rules.cryptobox();
  return out;
}

/* the bucket key and certificate of an identity, beside its bucket: buckets/<net>/<id>.key */
const keyFile = (id, net) => home.identityFile(id, net).replace(/\.json$/, '.key');

/*
 * A BUCKET KEY IS KEPT ONLY IF ITS CERTIFICATE VERIFIES (the Windows desktop, 2026-10-25: through the desktop app the
 * key's answers were crossed with the app's own, and a bucket key with a certificate from other bytes was kept - every
 * proof from it was refused, for good). Checked when made and when read; one that does not verify is not used, and is
 * made again.
 */
const certifies = (me) => bid.identityIdOf(me.identityPublicKey) === me.id
  && bid.verifyCertificate({ identityPublicKey: me.identityPublicKey, bucketPublicKey: me.bucketKey.publicKey, certificate: me.certificate });

function loadMe(id, net) {
  try {
    const j = JSON.parse(fs.readFileSync(keyFile(id, net), 'utf8'));
    const me = {
      id,
      identityPublicKey: fromHex(j.identityPublicKey),
      bucketKey: { secretKey: fromHex(j.bucketSecretKey), publicKey: fromHex(j.bucketPublicKey) },
      certificate: fromHex(j.certificate),
    };
    return certifies(me) ? me : null;
  } catch {
    return null;
  }
}

/*
 * THE KEY IS BUSY, NOT LOCKED (the Windows desktop, 2026-10-25): the firmware signs or derives only when no other crypto
 * operation is in progress (okcore.cpp OKSIGN/OKDECRYPT: `!CRYPTO_AUTH`), and otherwise answers "Error device locked" -
 * on an unlocked key. The bucket key's ECDH and its signature come back to back, and a derive's gate stays in progress
 * up to its 19 s window, so the second was refused. Such an answer is waited out and asked again, up to BUSY_MS.
 */
const BUSY_MS = 25000;
async function whileBusy(say, what, fn) {
  const until = Date.now() + BUSY_MS;
  for (let told = false; ;) {
    try {
      return await fn();
    } catch (e) {
      if (!/device locked/i.test(String(e && e.message)) || Date.now() >= until) throw e;
      if (!told) { say(`sync: the key is busy with a previous request - asking again for the ${what}`); told = true; }
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
}

async function makeMe(okcrypto, id, identityPublicKey, net, say, opts) {
  say('sync: making this computer\'s bucket key, once - the key asks for two presses');
  const bucketKey = await whileBusy(say, 'bucket key', () => bid.deriveBucketKey(okcrypto, identityPublicKey, opts));
  const certificate = await whileBusy(say, 'certificate', () => bid.certify(okcrypto, identityPublicKey, bucketKey.publicKey, opts));
  if (!certifies({ id, identityPublicKey, bucketKey, certificate })) {
    throw new Error('the key\'s certificate for this computer\'s bucket key does not verify - not kept (the key\'s answers were not its own?)');
  }
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
 * @returns {Promise<{traded: boolean, same?: boolean, settled?: boolean, refused?: boolean, why?: string, taken?: object, gave?: object}>}
 *   same: the states matched, nothing moved; settled: they match after the trade
 */
/*
 * HOW LONG ONE TRADE MESSAGE MAY TAKE (the box, 2026-10-25): over Bluetooth a message crosses at about 2.6 KB/s (469-byte
 * writes, ~180 ms each), and a store kept as one value goes whole - the Key Chain list was 139 KB, about 55 s - so a
 * fixed 30 s wait cut every such GIVE off and the phone's answer was lost. The wait grows with the message: the first
 * round's minute (the phone may ask for presses), then 30 s plus a second for every 1.5 KB.
 */
function tradeTimeoutMs(message, first) {
  const size = JSON.stringify(message || {}).length;
  return Math.max(first ? 60000 : 30000, 30000 + Math.ceil(size / 1.5));
}

/*
 * WHICH IDENTITY TO TRADE AS, WITHOUT ASKING THE KEY EVERY TIME (the box, 2026-10-25). Reading the bucket identity is a
 * derive on the key this computer talks to - over Bluetooth the phone's - and the phone's Key Chain records each derive
 * ("last used"), so a sync that read it every time changed the phone's bucket every time, and never settled. The
 * identity of the last trade that went through is kept (buckets/<net>/synced-with.json, a public id); its bucket key is
 * already here. The key is asked only when there is none, or the device does not prove that identity.
 */
const syncedWithFile = (net) => path.join(home.root(), 'buckets', net === 'test' ? 'test' : 'live', 'synced-with.json');
function rememberedIdentity(net) {
  try {
    const id = JSON.parse(fs.readFileSync(syncedWithFile(net), 'utf8')).id;
    return bid.isBucketIdentityId(id) && loadMe(id, net) ? id : null;
  } catch {
    return null;
  }
}
function rememberIdentity(net, id) {
  try { fs.writeFileSync(syncedWithFile(net), `${JSON.stringify({ id })}\n`, { mode: 0o600 }); } catch { /* asked again next time */ }
}

const count = (o) => Object.values(o || {}).reduce((a, b) => a + b, 0);

/*
 * EACH FEATURE AFTER A TRADE (Brad, 2026-10-25: "a panel that shows the status of each feature, and last sync
 * timestamps"): per store, its items (a split store's entries, contacts or messages; another store's records) and
 * whether it now matches the other device. One line, said after every trade - an app's Sync tab reads it.
 */
function storesLine(bucket, rules, differs) {
  const out = {};
  for (const [name, units] of Object.entries(replicate.summarize(bucket, { rules }))) {
    const keys = Object.keys(units);
    const items = keys.filter((k) => !k.endsWith('\u0001')).length;
    if (!items) continue;
    out[name] = { items, same: differs ? !differs.includes(name) : null };
  }
  return `sync: stores ${JSON.stringify(out)}`;
}
const addTo = (sum, o) => { for (const [k, v] of Object.entries(o || {})) sum[k] = (sum[k] || 0) + v; return sum; };

async function tradeWith({ send, okcrypto, net = 'live', say = () => {}, keyOpts = {} }) {
  const remembered = rememberedIdentity(net);
  const first = await tradeAs({ send, okcrypto, net, say, keyOpts, id: remembered });
  /* the remembered identity is not the one this device proves: ask the key, once */
  if (remembered && first.refused) return tradeAs({ send, okcrypto, net, say, keyOpts, id: null });
  return first;
}

async function tradeAs({ send, okcrypto, net, say, keyOpts, id: knownId }) {
  let id = knownId;
  let me = id ? loadMe(id, net) : null;
  if (!me) {
    /*
     * THE KEY, ONLY WHILE IT IS NEEDED: okcrypto may be a function that opens the key and gives {okcrypto, close} - a
     * service with no Edge agent holds nothing between trades (through the desktop app, one CLI at a time: a held key
     * refused every other onlykey-js "busy").
     */
    const opened = typeof okcrypto === 'function' ? await okcrypto() : { okcrypto, close: async () => {} };
    try {
      const read = await bid.readIdentity(opened.okcrypto);
      id = read.id;
      me = loadMe(id, net) || await makeMe(opened.okcrypto, id, read.publicKey, net, say, keyOpts);
    } finally {
      await opened.close();
    }
  }
  const file = home.identityFile(id, net);
  if (!home.hasIdentityBucket(id, net)) home.keepIdentityBucket(id, net, bucketLib.create({ owner: id }));
  const copy = home.read(file);
  const r = storeRules();
  const c = trade.computerSide({ bucket: copy, me, randomBytes: rnd, rules: r });
  const m2 = c.prove(await send(c.hello()));
  if (!m2) return { traded: false, refused: true, why: 'the device did not prove this bucket identity, or does not trade yet' };
  /* the states first: the same - in sync, nothing more is sent */
  let step = c.compare(await send(m2));
  if (!step) return { traded: false, why: 'the device did not say its state' };
  rememberIdentity(net, id);
  if (step.same) { say(storesLine(copy, r, [])); return { traded: true, same: true, settled: true, taken: {}, gave: {} }; }
  say(`sync: trading - ${step.differs.join(', ') || 'the bucket'} differ`);
  const taken = {};
  const gave = {};
  let settled = false;
  let stillDiffer = step.differs;
  for (;;) {
    const g = c.give(await send(step.message));
    if (!g) { say('sync: the device did not answer its HAVE'); break; }
    addTo(taken, g.taken);
    /* what goes, per store - counts and size only, never a key or value */
    const giving = Object.fromEntries(Object.entries(g.message.give || {}).map(([s, recs]) => [s, Object.keys(recs).length]));
    if (Object.keys(g.taken || {}).length) say(`sync: took ${JSON.stringify(g.taken)}`);
    if (Object.keys(giving).length) say(`sync: giving ${JSON.stringify(giving)} (${Math.round(JSON.stringify(g.message).length / 1024)} KB)`);
    const answer = await send(g.message);
    const s = c.settle(answer);
    /* what it took is the device's own count; an answer without one is said, never read as "took nothing" */
    if (!s) { say(`sync: the device did not confirm what it took (${answer ? JSON.stringify(answer).slice(0, 160) : 'no answer'})`); break; }
    addTo(gave, s.taken);
    if (s.same) { settled = true; stillDiffer = []; break; }
    stillDiffer = s.differs;
    if (!s.message) { say(`sync: not settled - ${s.differs.join(', ')} still differ after every round`); break; }
    say(`sync: another round - ${s.differs.join(', ')} still differ`);
    step = s;
  }
  /*
   * what the trade changed, into the kept file as it is NOW (the newer wins either way round) - and only when it took
   * something: a rewrite that changes nothing still wakes the sync service's watcher, which then traded again, and again
   * (the box, 2026-10-25: "traded - took 0, gave 0", then "trading (changed meanwhile)", without end)
   */
  if (count(taken)) home.update(file, (b) => {
    const merged = bucketLib.merge(b, copy, { rules: r }).bucket;
    b.stores = merged.stores;
    b.clock = merged.clock;
  });
  say(storesLine(copy, r, stillDiffer));
  return { traded: true, settled, taken, gave };
}

module.exports = { tradeWith, tradeTimeoutMs, storeRules, keyFile };
