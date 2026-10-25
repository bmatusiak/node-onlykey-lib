'use strict';

/**
 * THE MERGE RULES PER STORE (PROPOSAL-one-gui.md, "Merge: one rule, per store"). Brad, 2026-10-21:
 * merge on import, "safer to not lose important logging" - the concept Edge sync already uses,
 * cleaned up into one rule every store follows: take what the other copy has and this one lacks, and
 * where both have it the NEWER wins (Brad, 2026-10-25: "timestamps are how we determine who wins,
 * overwrite old, and stuff never gets deleted, just flagged as archived") - per entry inside a store
 * kept as one value (the Key Chain list, the Guest Book), so an entry added on one device is never lost
 * to a later edit of the same list on another. Drop nothing.
 *
 * A rule is (into, from) -> {store, taken, conflicts} over one store's part of two buckets, the
 * shape bucket.merge() calls. A rule that needs a feature's own merge is MADE from that feature's
 * module (keychain(list)), so the bucket never requires a feature folder - each one stands without
 * the others (scripts/check-without.js).
 */

const { mergeKeys, newer } = require('./bucket');

/* a live value: not archived, not an old-style removal marker (v null) */
const live = (rec) => Boolean(rec) && !rec.archived && rec.v !== null;
/* both sides in a fixed order (older first, the same tie-break as newer()), so a merge run on either device is the same */
const ordered = (a, b) => (newer(a, b) ? [a, b] : [b, a]);

const later = (a, b) => (a && b ? (a > b ? a : b) : a || b);

/** Settings: key by key, the newer value wins (bucket.mergeKeys). */
const settings = mergeKeys;

/**
 * The Key Chain list: one key holding the list (the phone's export format); the list's own merge
 * (keychain/src/list.js merge) - entries by id, twins joined, nothing either side knew dropped.
 * It has no conflicts: two records of one key combine.
 * @param {{parse: (text: string) => object[], serialize: (entries: object[]) => string, merge: (a: object[], b: object[]) => {entries: object[], added: number, paired: number}}} list
 * @param {{key?: string}} [opts]
 */
function keychain(list, { key = 'list' } = {}) {
  return (into = {}, from = {}) => {
    const store = { ...into };
    const a = into[key];
    const b = from[key];
    if (!b) return { store, taken: 0, conflicts: [] };
    /* one side has no live list (none, or the whole list archived): the newer record of the key wins */
    if (!live(a) || !live(b)) {
      if (!newer(a, b)) return { store, taken: 0, conflicts: [] };
      store[key] = { ...b };
      return { store, taken: live(b) ? list.parse(b.v).length : 1, conflicts: [] };
    }
    const [lo, hi] = ordered(a, b);
    const r = list.merge(list.parse(lo.v), list.parse(hi.v));
    const v = list.serialize(r.entries);
    if (v === a.v) return { store, taken: 0, conflicts: [] };
    store[key] = { v, at: later(a.at, b.at) };
    return { store, taken: Math.max(1, r.added + r.paired), conflicts: [] };
  };
}

/**
 * Password entries (passwords/ over src/crypto/vault_store.js): each credential is its own key and
 * merges key by key - the same entry changed on both sides is a conflict, never overwritten. The
 * index is not a value to choose between: it is the set of credentials, so it is rebuilt as the
 * union. Works for every vault in the store (each is a prefix: `<storeId>/onlyagent-vault/...`).
 */
function passwords() {
  const INDEX = 'onlyagent-vault/index';
  return (into = {}, from = {}) => {
    const notIndex = (s) => Object.fromEntries(Object.entries(s).filter(([k]) => !k.endsWith(INDEX)));
    const r = mergeKeys(notIndex(into), notIndex(from));
    const store = r.store;
    const indexes = new Set([...Object.keys(into), ...Object.keys(from)].filter((k) => k.endsWith(INDEX)));
    for (const k of indexes) {
      const ids = new Set();
      for (const side of [into[k], from[k]]) {
        if (live(side)) for (const id of JSON.parse(side.v)) ids.add(id);
      }
      /* an id whose record was removed on either side is not listed */
      const prefix = k.slice(0, -INDEX.length);
      const listed = [...ids].filter((id) => {
        const rec = store[`${prefix}onlyagent-vault/credentials/${id}`];
        return live(rec);
      }).sort();
      store[k] = { v: JSON.stringify(listed), at: later(into[k] && into[k].at, from[k] && from[k].at) };
    }
    return { store, taken: r.taken, conflicts: r.conflicts };
  };
}

/**
 * The Guest Book (guestbook/src/store.js, one blob {v, contacts}): per contact, by id. One only the other
 * copy has is added; the same contact, different on the two sides, is taken from the copy where it changed
 * LATER - its newest key's updatedAt, else the blob's date; the same time decided the same way on every
 * device. Nothing is asked. (A fetched key's update is guestbook/src/merge.js classify, at fetch time.)
 * @param {{key?: string}} [opts] key: the blob's name ('guestbook:v1')
 */
function guestbook({ key = 'guestbook:v1' } = {}) {
  /* when a contact last changed: its newest key's updatedAt, else the blob's date */
  const changedAt = (c, blobAt) => (c.keys || []).map((k) => String(k.updatedAt || '')).filter(Boolean).sort().pop() || blobAt;
  return (into = {}, from = {}) => {
    const store = { ...into };
    const a = into[key];
    const b = from[key];
    if (!b) return { store, taken: 0, conflicts: [] };
    if (!live(a) || !live(b)) {
      if (!newer(a, b)) return { store, taken: 0, conflicts: [] };
      store[key] = { ...b };
      return { store, taken: live(b) ? JSON.parse(b.v).contacts.length : 1, conflicts: [] };
    }
    const mine = JSON.parse(a.v);
    const theirs = JSON.parse(b.v);
    const at = new Map(mine.contacts.map((c, i) => [c.id, i]));
    let taken = 0;
    for (const c of theirs.contacts) {
      const i = at.get(c.id);
      if (i === undefined) {
        at.set(c.id, mine.contacts.length);
        mine.contacts.push(c);
        taken += 1;
        continue;
      }
      const have = mine.contacts[i];
      const h = JSON.stringify(have);
      const o = JSON.stringify(c);
      if (h === o) continue;
      const ha = changedAt(have, a.at);
      const oa = changedAt(c, b.at);
      if (oa > ha || (oa === ha && o > h)) {
        mine.contacts[i] = c;
        taken += 1;
      }
    }
    if (!taken) return { store, taken: 0, conflicts: [] };
    store[key] = { v: JSON.stringify(mine), at: later(a.at, b.at) };
    return { store, taken, conflicts: [] };
  };
}

/**
 * The Edge copies (edge/src/copyfile.js): one key per device, its copy's JSON. Two copies of one
 * device merge by the copy's own rules; a FORK - the copies disagree at a seq both hold, or name
 * different keys - is reported and never repaired: this copy stays, nothing of the other is taken,
 * and the conflict cannot be picked away.
 * @param {{fromJSON: Function, toJSON: Function, merge: Function}} copyfile edge's copyfile module
 */
function edgeCopies(copyfile) {
  const { fromHex } = require('../../src/bytes');
  return (into = {}, from = {}) => {
    const store = { ...into };
    const conflicts = [];
    let taken = 0;
    for (const [key, rec] of Object.entries(from)) {
      const have = into[key];
      if (!rec || rec.v === null) continue;
      if (!have || have.v === null) {
        store[key] = { ...rec };
        taken += JSON.parse(rec.v).links.length;
        continue;
      }
      const ja = JSON.parse(have.v);
      const jb = JSON.parse(rec.v);
      const id = fromHex(ja.deviceId);
      const r = copyfile.merge(copyfile.fromJSON(ja, id), copyfile.fromJSON(jb, id));
      if (r.fork) {
        conflicts.push({
          key, reason: r.fork.reason, into: { ...have }, from: { ...rec },
          apply() { throw new Error(`${r.fork.reason}: a fork is reported, never repaired`); },
        });
        continue;
      }
      if (!r.taken && JSON.stringify(copyfile.toJSON(r.copy)) === JSON.stringify(ja)) continue;
      store[key] = { v: JSON.stringify(copyfile.toJSON(r.copy)), at: later(have.at, rec.at) };
      taken += r.taken;
    }
    return { store, taken, conflicts };
  };
}

/**
 * THE AUDIT DUMP (Brad, 2026-10-21: "the bucket may contain passwords, so the dump is just for the
 * Edge blockchain so it can be externally verified using pubkeys"): every Edge copy in the bucket
 * as JSON blocks, each checked against the keys kept with its copy. Public by nature - nothing
 * else in the bucket ever leaves it unsealed.
 * @param {{stores: Object}} bucket an opened bucket
 * @param {{fromJSON: Function, blocks: Function}} copyfile edge's copyfile module
 * @param {{net: string, store?: string}} opts
 */
function edgeBlocks(bucket, copyfile, { net, store = 'edge.copies' }) {
  const { fromHex } = require('../../src/bytes');
  return Object.values(bucket.stores[store] || {})
    .filter(live)
    .map((rec) => {
      const j = JSON.parse(rec.v);
      return copyfile.blocks(copyfile.fromJSON(j, fromHex(j.deviceId)), { net });
    });
}

module.exports = { settings, keychain, passwords, guestbook, edgeCopies, edgeBlocks };
