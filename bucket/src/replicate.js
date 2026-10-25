'use strict';

/**
 * THE BUCKET REPLICATES BY ITSELF (ok-edge plan S3; Brad, 2026-10-24: "like the blockchain is self replicating in
 * the sense of how it populates itself across each device"; "the user does not need to provide a bucket").
 *
 * Two devices of one identity, already paired and proven to each other (the cli pair, the owner-signed acceptance:
 * the caller's job, never this module's), swap what they have and end up holding the same bucket:
 *
 *   1. HAVE  each side sends summarize(bucket): per store, per key, when it changed and a hash of its value -
 *            no values, so a side learns nothing it is not about to be given.
 *   2. GIVE  each side sends give(bucket, mine, theirs, base): the values of the keys IT changed since the base that
 *            the other side does not hold as they are here.
 *   3. take  each side runs take(bucket, given, mine, theirs, base, rules) and keeps the base it returns.
 *
 * WHY A BASE. bucket.merge is an IMPORT: two copies of unknown history, so any value that differs is the person's
 * to pick. Between devices that swap every time they meet, that would ask about every edit. So each pair of devices
 * keeps the hash of every key both last agreed on (the base) - hashes only, no values. Against it a difference says
 * who changed: only one side (the other takes it), or both (the store's own merge rule, as an import uses - else a
 * conflict, kept for the person with both dates, each side keeping its own value until then). With no base yet (the
 * first swap), every difference is "both changed": the import's rules, nothing dropped.
 *
 * BOTH SIDES DECIDE ALIKE. Each side decides every key from the same three facts - its HAVE, the other's HAVE, the
 * shared base - so both reach the same answer and keep the same new base without a third message. A store's rule
 * runs with its two sides in a fixed order (by hash), so both compute the same merge.
 *
 * Removals travel as values: a removed key is a dated marker (bucket.kv), so "removed there" is not "never had it".
 *
 * Pure: no device, no Node built-ins - the same code runs in the app, the browser and the CLI. What crosses the wire
 * (HAVE, GIVE) is the caller's to seal and authenticate; this module never sends anything.
 */

const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { toHex } = require('../../src/bytes');
const { mergeKeys } = require('./bucket');

/* a removed key's hash: no value hashes to this (a value is hashed with a leading 'v') */
const REMOVED = 'removed';
const hashOf = (rec) => (rec.v === null ? REMOVED : toHex(sha256(new TextEncoder().encode(`v${rec.v}`))));

/**
 * What this side has: per store, per key, its date and value hash.
 * @param {{stores: Object<string, Object<string, {v: string|null, at: string}>>}} bucket
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

const at = (map, name, key) => (map && map[name] ? map[name][key] : undefined);

/*
 * One key's case, the same on both sides. a: this side's hash, b: the other's, base: both last agreed.
 *   'same'  - alike;  'mine' - only this side changed (the other takes it);  'theirs' - only the other changed;
 *   'both'  - both changed, or no base to tell: the store's rule decides.
 */
function caseOf(a, b, base) {
  if (a === b) return 'same';
  if (a === undefined) return 'theirs';
  if (b === undefined) return 'mine';
  if (base === a) return 'theirs';
  if (base === b) return 'mine';
  return 'both';
}

/**
 * The values to send: every key this side changed (alone, or with the other) that the other does not hold alike.
 * @param {{stores: Object}} bucket
 * @param {ReturnType<typeof summarize>} mine this side's HAVE, as sent
 * @param {ReturnType<typeof summarize>} theirs the other's HAVE
 * @param {Object<string, Object<string, string>>} [base] what both last agreed on (hash per key)
 * @returns {Object<string, Object<string, {v: string|null, at: string}>>}
 */
function give(bucket, mine, theirs, base = {}) {
  const out = {};
  for (const [name, keys] of Object.entries(mine)) {
    for (const [key, m] of Object.entries(keys)) {
      const t = at(theirs, name, key);
      const c = caseOf(m.h, t && t.h, at(base, name, key));
      if (c !== 'mine' && c !== 'both') continue;
      const rec = bucket.stores[name] && bucket.stores[name][key];
      /* written since the HAVE went out: both sides would no longer decide alike - the caller swaps again */
      if (!rec || hashOf(rec) !== m.h) throw Object.assign(new Error('the bucket changed during the swap - swap again'), { code: 'EBUCKET_CHANGED' });
      if (!out[name]) out[name] = {};
      out[name][key] = { v: rec.v, at: rec.at };
    }
  }
  return out;
}

/**
 * Take what the other side gave. Changes `bucket` in place.
 * @param {{stores: Object}} bucket
 * @param {ReturnType<typeof give>} given the other's GIVE
 * @param {ReturnType<typeof summarize>} mine this side's HAVE, as sent (before this take)
 * @param {ReturnType<typeof summarize>} theirs the other's HAVE
 * @param {Object<string, Object<string, string>>} [base] what both last agreed on
 * @param {{rules?: Object<string, typeof mergeKeys>}} [opts] the stores' merge rules, as bucket.merge takes them
 * @returns {{base: Object<string, Object<string, string>>, taken: Object<string, number>, conflicts: Array<{store: string, key: string, into: object, from: object}>}}
 *   base: the new base to keep for this peer (the other side computes the same); taken: per store, how many keys
 *   changed here; conflicts: for the person - this side keeps its own value until they pick
 */
function take(bucket, given, mine, theirs, base = {}, { rules = {} } = {}) {
  const taken = {};
  const conflicts = [];
  const next = {};
  const agree = (name, key, h) => { if (!next[name]) next[name] = {}; next[name][key] = h; };
  const keep = (name, key) => { const h = at(base, name, key); if (h !== undefined) agree(name, key, h); };
  const names = new Set([...Object.keys(mine), ...Object.keys(theirs)]);
  for (const name of names) {
    if (!bucket.stores[name]) bucket.stores[name] = {};
    const store = bucket.stores[name];
    const keys = new Set([...Object.keys(mine[name] || {}), ...Object.keys(theirs[name] || {})]);
    const both = [];
    for (const key of keys) {
      const m = at(mine, name, key);
      const t = at(theirs, name, key);
      const c = caseOf(m && m.h, t && t.h, at(base, name, key));
      const g = at(given, name, key);
      if (c === 'same') agree(name, key, m.h);
      else if (c === 'mine') agree(name, key, m.h);
      else if (c === 'theirs') {
        /* a GIVE that does not match the HAVE it came with is not taken: nothing is agreed, the next swap retries */
        if (!g || hashOf(g) !== t.h) { keep(name, key); continue; }
        store[key] = { v: g.v, at: g.at };
        taken[name] = (taken[name] || 0) + 1;
        agree(name, key, t.h);
      } else if (!g || hashOf(g) !== t.h) keep(name, key);
      else both.push(key);
    }
    if (!both.length) continue;
    /* the rule, in a fixed order: the side whose value hashes lower goes first, so both sides compute the same */
    const sideA = {}; const sideB = {};
    for (const key of both) {
      const m = store[key]; const g = given[name][key];
      const [lo, hi] = hashOf(m) < hashOf(g) ? [m, g] : [g, m];
      sideA[key] = { ...lo }; sideB[key] = { ...hi };
    }
    const r = (rules[name] || mergeKeys)(sideA, sideB);
    const conflicted = new Set(r.conflicts.map((c) => c.key));
    for (const c of r.conflicts) {
      /* named from this side: into = what is here, from = what came */
      const here = store[c.key]; const came = given[name][c.key];
      conflicts.push({ ...c, store: name, key: c.key, into: here ? { ...here } : c.into, from: came ? { ...came } : c.from });
    }
    for (const key of both) {
      if (conflicted.has(key) || !r.store[key]) { keep(name, key); continue; }
      const merged = r.store[key];
      if (hashOf(merged) !== hashOf(store[key])) { store[key] = { v: merged.v, at: merged.at }; taken[name] = (taken[name] || 0) + 1; }
      agree(name, key, hashOf(merged));
    }
  }
  return { base: next, taken, conflicts };
}

module.exports = { summarize, give, take, hashOf, REMOVED };
