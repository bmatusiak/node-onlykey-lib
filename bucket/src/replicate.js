'use strict';

/**
 * THE BUCKET REPLICATES BY ITSELF (ok-edge plan S3; Brad, 2026-10-24: "like the blockchain is self replicating in
 * the sense of how it populates itself across each device"; 2026-10-25: "the pixel bucket gets sent to the app to
 * import into my desktop bucket, merging them into it, and same for pixel ... the stale mobile device will most
 * likely talk to the desktop at one point, so they trade when they can").
 *
 * Two devices of one identity, already paired and proven to each other (the caller's job, never this module's),
 * trade what they have whenever they talk. Each IMPORTS the other's changes into its own open bucket - the same
 * merge a bucket import is (bucket.merge: the newer value wins, removals are archived values, nothing asked) - so
 * whichever device traded last holds everything, and a stale one catches up at its next trade:
 *
 *   1. HAVE  each side sends summarize(bucket): per store, per key, when it changed and a hash of its value -
 *            no values, so a side learns nothing it is not about to be given.
 *   2. GIVE  each side sends give(bucket, mine, theirs): every record the other side does not hold as it is here -
 *            older ones too, because a store kept as one value (the Key Chain list, the Guest Book) joins entries
 *            from both sides: the other side's rule decides what an older record still adds, and newer-wins drops
 *            the rest. Nothing the other side already holds alike is sent.
 *   3. take  each side runs take(bucket, given, rules): the given records merged in by the store's rule.
 *
 * Pure: no device, no Node built-ins - the same code runs in the app, the browser and the CLI. What crosses the wire
 * (HAVE, GIVE) is the caller's to seal and authenticate; this module never sends anything.
 */

const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { toHex } = require('../../src/bytes');
const { mergeKeys } = require('./bucket');

const h = (text) => toHex(sha256(new TextEncoder().encode(text)));

/* a record's hash: its value, and whether it is archived (a removal is a change of its own) */
const hashOf = (rec) => h(`${rec.archived || rec.v === null ? 'a' : 'l'}${typeof rec.v === 'string' ? rec.v : JSON.stringify(rec.v ?? '')}`);

/**
 * A BUCKET'S STATE: one hash over every record - its store, key, value hash and date - and the time of its last
 * change (Brad, 2026-10-25: "ping hashes and timestamps so each device can compare its state before it updates,
 * trading until all hashes are the same"; "the phone tells the desktop a hash and timestamp"). Two devices with the
 * same state hold the same bucket: no trade is needed, and a trade is complete only when the states match. Per store
 * too, so a store that never settles is named. An empty store counts as none.
 * @param {{stores: Object, clock?: string|null}} bucket
 * @returns {{hash: string, at: string|null, stores: Object<string, string>}}
 */
function stateOf(bucket) {
  const stores = {};
  for (const name of Object.keys(bucket.stores || {}).sort()) {
    const keys = Object.keys(bucket.stores[name] || {}).sort();
    if (!keys.length) continue;
    stores[name] = h(keys.map((k) => { const r = bucket.stores[name][k]; return `${k}\u0000${hashOf(r)}\u0000${r.at || ''}`; }).join('\n'));
  }
  return { hash: h(Object.entries(stores).map(([n, s]) => `${n}\u0000${s}`).join('\n')), at: bucket.clock || null, stores };
}

/** The stores whose state differs between two states (bucket names only). */
function differs(a, b) {
  const names = new Set([...Object.keys((a && a.stores) || {}), ...Object.keys((b && b.stores) || {})]);
  return [...names].filter((n) => (a.stores || {})[n] !== (b.stores || {})[n]).sort();
}

/**
 * What this side has: per store, per key, its date and record hash.
 * @param {{stores: Object<string, Object<string, {v: string|null, at: string, archived?: true}>>}} bucket
 * @returns {Object<string, Object<string, {at: string, h: string}>>}
 */
function summarize(bucket) {
  const have = {};
  for (const [name, store] of Object.entries(bucket.stores)) {
    have[name] = {};
    for (const [key, rec] of Object.entries(store)) have[name][key] = { at: rec.at, h: hashOf(rec) };
  }
  return have;
}

/**
 * The records to send: every one the other side does not hold alike (its hash differs, or it has none). Whether it
 * wins is the receiving store's rule - the same on both sides (bucket.newer, a list's join).
 * @param {{stores: Object}} bucket
 * @param {ReturnType<typeof summarize>} mine this side's HAVE, as sent
 * @param {ReturnType<typeof summarize>} theirs the other's HAVE
 * @returns {Object<string, Object<string, {v: string|null, at: string, archived?: true}>>}
 */
function give(bucket, mine, theirs) {
  const out = {};
  for (const [name, keys] of Object.entries(mine)) {
    for (const [key, m] of Object.entries(keys)) {
      const t = theirs[name] && theirs[name][key];
      if (t && t.h === m.h) continue;
      const rec = bucket.stores[name] && bucket.stores[name][key];
      /* written since the HAVE went out: what is sent must be what was announced - the caller trades again */
      if (!rec || hashOf(rec) !== m.h) throw Object.assign(new Error('the bucket changed during the trade - trade again'), { code: 'EBUCKET_CHANGED' });
      if (!out[name]) out[name] = {};
      out[name][key] = { ...rec };
    }
  }
  return out;
}

/**
 * Import what the other side gave into this side's bucket (in place), each store by its own rule - the newer wins.
 * @param {{stores: Object, clock?: string|null}} bucket
 * @param {ReturnType<typeof give>} given the other's GIVE
 * @param {{rules?: Object<string, typeof mergeKeys>}} [opts] the stores' merge rules, as bucket.merge takes them
 * @returns {{taken: Object<string, number>, conflicts: Array}} taken: per store, how many changed here; conflicts:
 *   what a store's own rule can never decide (an Edge copy's fork) - the generic rule reports none
 */
function take(bucket, given, { rules = {} } = {}) {
  const taken = {};
  const conflicts = [];
  for (const [name, recs] of Object.entries(given)) {
    const r = (rules[name] || mergeKeys)(bucket.stores[name] || {}, recs);
    bucket.stores[name] = r.store;
    if (r.taken) taken[name] = r.taken;
    for (const c of r.conflicts) conflicts.push({ store: name, ...c });
    /* the clock moves past every stamp taken in (bucket.js stamp) */
    for (const rec of Object.values(r.store)) if (rec && rec.at && (!bucket.clock || rec.at > bucket.clock)) bucket.clock = rec.at;
  }
  return { taken, conflicts };
}

module.exports = { summarize, give, take, hashOf, stateOf, differs };
