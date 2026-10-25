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

/*
 * WHAT IS COMPARED AND SENT: a store's records - or, for a store whose rule splits its value (rules.js listParts: the
 * Key Chain list, the Guest Book, the Cryptobox), that value's PARTS, one per item: `<key>\u0001<part>`. One changed
 * item is one unit that differs, and the only one sent (Brad, 2026-10-25: "this should be easy to separate and chunk").
 * A value that does not split (archived, unreadable) is one unit as before.
 */
const SEP = '\u0001';
const live = (rec) => Boolean(rec) && !rec.archived && rec.v !== null;
function units(bucket, name, rules) {
  const parts = rules[name] && rules[name].parts;
  const out = {};
  for (const [key, rec] of Object.entries((bucket.stores || {})[name] || {})) {
    if (parts && key === parts.key && live(rec)) {
      let split = null;
      try { split = parts.split(rec.v); } catch { /* one unit, as any record */ }
      if (split) {
        for (const [p, text] of Object.entries(split)) out[`${key}${SEP}${p}`] = { at: rec.at, h: h(`l${text}`), part: text };
        continue;
      }
    }
    out[key] = { at: rec.at, h: hashOf(rec), rec };
  }
  return out;
}

/**
 * A BUCKET'S STATE: one hash over every unit - its store, key, value hash and date - and the time of its last change
 * (Brad, 2026-10-25: "ping hashes and timestamps so each device can compare its state before it updates, trading until
 * all hashes are the same"; "the phone tells the desktop a hash and timestamp"). Two devices with the same state hold
 * the same bucket: no trade is needed, and a trade is complete only when the states match. Per store too, so a store
 * that never settles is named. An empty store counts as none. A split value is hashed by its parts in id order, so the
 * order its items were written in does not count.
 * @param {{stores: Object, clock?: string|null}} bucket
 * @param {{rules?: Object}} [opts] the stores' rules (their parts)
 * @returns {{hash: string, at: string|null, stores: Object<string, string>}}
 */
function stateOf(bucket, { rules = {} } = {}) {
  const stores = {};
  for (const name of Object.keys(bucket.stores || {}).sort()) {
    const u = units(bucket, name, rules);
    const keys = Object.keys(u).sort();
    if (!keys.length) continue;
    stores[name] = h(keys.map((k) => `${k}\u0000${u[k].h}\u0000${u[k].at || ''}`).join('\n'));
  }
  return { hash: h(Object.entries(stores).map(([n, s]) => `${n}\u0000${s}`).join('\n')), at: bucket.clock || null, stores };
}

/** The stores whose state differs between two states (bucket names only). */
function differs(a, b) {
  const names = new Set([...Object.keys((a && a.stores) || {}), ...Object.keys((b && b.stores) || {})]);
  return [...names].filter((n) => (a.stores || {})[n] !== (b.stores || {})[n]).sort();
}

/**
 * What this side has: per store, per unit, its date and hash - no values.
 * @param {{stores: Object<string, Object<string, {v: string|null, at: string, archived?: true}>>}} bucket
 * @param {{rules?: Object}} [opts]
 * @returns {Object<string, Object<string, {at: string, h: string}>>}
 */
function summarize(bucket, { rules = {} } = {}) {
  const have = {};
  for (const name of Object.keys(bucket.stores)) {
    have[name] = {};
    for (const [k, u] of Object.entries(units(bucket, name, rules))) have[name][k] = { at: u.at, h: u.h };
  }
  return have;
}

/**
 * The units to send: every one the other side does not hold alike (its hash differs, or it has none). Whether it wins
 * is the receiving store's rule - the same on both sides (bucket.newer, a list's join).
 * @param {{stores: Object}} bucket
 * @param {ReturnType<typeof summarize>} mine this side's HAVE, as sent
 * @param {ReturnType<typeof summarize>} theirs the other's HAVE
 * @param {{rules?: Object}} [opts]
 * @returns {Object<string, Object<string, {v: string|null, at: string, archived?: true, part?: true}>>}
 */
function give(bucket, mine, theirs, { rules = {} } = {}) {
  const out = {};
  for (const [name, keys] of Object.entries(mine)) {
    let u = null;
    for (const [key, m] of Object.entries(keys)) {
      const t = theirs[name] && theirs[name][key];
      if (t && t.h === m.h) continue;
      if (!u) u = units(bucket, name, rules);
      const now = u[key];
      /* written since the HAVE went out: what is sent must be what was announced - the caller trades again */
      if (!now || now.h !== m.h) throw Object.assign(new Error('the bucket changed during the trade - trade again'), { code: 'EBUCKET_CHANGED' });
      if (!out[name]) out[name] = {};
      out[name][key] = now.part !== undefined ? { v: now.part, at: now.at, part: true } : { ...now.rec };
    }
  }
  return out;
}

/*
 * The parts given for one key, back into a value holding just them - the other fields' part from this side's own
 * value when it was not sent (it did not differ) - for the store's rule to merge like any other copy.
 */
function joinParts(bucket, name, key, given, parts) {
  const map = {};
  let at = null;
  for (const [k, rec] of Object.entries(given)) {
    if (!k.startsWith(`${key}${SEP}`)) continue;
    map[k.slice(key.length + 1)] = rec.v;
    if (!at || rec.at > at) at = rec.at;
  }
  if (map[''] === undefined) {
    const own = ((bucket.stores || {})[name] || {})[key];
    try { if (live(own)) map[''] = parts.split(own.v)['']; } catch { /* the rule reads it without */ }
  }
  return { v: parts.join(map), at };
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
    const parts = rules[name] && rules[name].parts;
    let incoming = recs;
    /* parts of a value this side cannot join (its rule has no parts - an older app): not stored as keys of their own */
    if (!parts) incoming = Object.fromEntries(Object.entries(recs).filter(([k]) => !k.includes(SEP)));
    if (parts && Object.keys(recs).some((k) => k.startsWith(`${parts.key}${SEP}`))) {
      incoming = Object.fromEntries(Object.entries(recs).filter(([k]) => !k.startsWith(`${parts.key}${SEP}`)));
      incoming[parts.key] = joinParts(bucket, name, parts.key, recs, parts);
    }
    const r = (rules[name] || mergeKeys)(bucket.stores[name] || {}, incoming);
    bucket.stores[name] = r.store;
    if (r.taken) taken[name] = r.taken;
    for (const c of r.conflicts) conflicts.push({ store: name, ...c });
    /* the clock moves past every stamp taken in (bucket.js stamp) */
    for (const rec of Object.values(r.store)) if (rec && rec.at && (!bucket.clock || rec.at > bucket.clock)) bucket.clock = rec.at;
  }
  return { taken, conflicts };
}

module.exports = { summarize, give, take, hashOf, stateOf, differs };
