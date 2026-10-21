'use strict';

/**
 * THE MERGE RULES PER STORE (PROPOSAL-one-gui.md, "Merge: one rule, per store"). Brad, 2026-10-21:
 * merge on import, "safer to not lose important logging" - the concept Edge sync already uses,
 * cleaned up into one rule every store follows: take what the other copy has and this one lacks,
 * report what both changed, drop nothing.
 *
 * A rule is (into, from) -> {store, taken, conflicts} over one store's part of two buckets, the
 * shape bucket.merge() calls. A rule that needs a feature's own merge is MADE from that feature's
 * module (keychain(list)), so the bucket never requires a feature folder - each one stands without
 * the others (scripts/check-without.js).
 */

const { mergeKeys } = require('./bucket');

const later = (a, b) => (a && b ? (a > b ? a : b) : a || b);

/**
 * Settings: key by key - a setting both copies changed is asked, both values shown with their
 * dates (Brad, 2026-10-21: "ask to show changes, with the dates displayed to give user the best
 * option to decide").
 */
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
    if (!b || b.v === null) return { store, taken: 0, conflicts: [] };
    if (!a || a.v === null) {
      store[key] = { ...b };
      return { store, taken: list.parse(b.v).length, conflicts: [] };
    }
    const r = list.merge(list.parse(a.v), list.parse(b.v));
    store[key] = { v: list.serialize(r.entries), at: later(a.at, b.at) };
    return { store, taken: r.added + r.paired, conflicts: [] };
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
        if (side && side.v !== null) for (const id of JSON.parse(side.v)) ids.add(id);
      }
      /* an id whose record was removed on either side is not listed */
      const prefix = k.slice(0, -INDEX.length);
      const live = [...ids].filter((id) => {
        const rec = store[`${prefix}onlyagent-vault/credentials/${id}`];
        return rec && rec.v !== null;
      }).sort();
      store[k] = { v: JSON.stringify(live), at: later(into[k] && into[k].at, from[k] && from[k].at) };
    }
    return { store, taken: r.taken, conflicts: r.conflicts };
  };
}

/**
 * The Guest Book (guestbook/src/store.js, one blob {v, contacts}): contacts by id. One only the other
 * copy has is added; the same contact, different on the two sides, is a conflict - the person
 * picks, the copy here stays until then. (A fetched key's update is guestbook/src/merge.js
 * classify, at fetch time; two people's edits to one contact are theirs to choose between.)
 * @param {{key?: string}} [opts] key: the blob's name ('guestbook:v1')
 */
function guestbook({ key = 'guestbook:v1' } = {}) {
  return (into = {}, from = {}) => {
    const store = { ...into };
    const a = into[key];
    const b = from[key];
    if (!b || b.v === null) return { store, taken: 0, conflicts: [] };
    if (!a || a.v === null) {
      store[key] = { ...b };
      return { store, taken: JSON.parse(b.v).contacts.length, conflicts: [] };
    }
    const mine = JSON.parse(a.v);
    const theirs = JSON.parse(b.v);
    const byId = new Map(mine.contacts.map((c) => [c.id, c]));
    const conflicts = [];
    let taken = 0;
    for (const c of theirs.contacts) {
      const have = byId.get(c.id);
      if (!have) {
        mine.contacts.push(c);
        taken += 1;
      } else if (JSON.stringify(have) !== JSON.stringify(c)) {
        conflicts.push({
          key: `${key}#${c.id}`,
          into: { v: JSON.stringify(have), at: a.at },
          from: { v: JSON.stringify(c), at: b.at },
          /* the pick replaces that one contact inside the blob */
          apply(s, side) {
            if (side !== 'from') return;
            const blob = JSON.parse(s[key].v);
            blob.contacts = blob.contacts.map((x) => (x.id === c.id ? c : x));
            s[key] = { v: JSON.stringify(blob), at: b.at };
          },
        });
      }
    }
    store[key] = { v: JSON.stringify(mine), at: taken ? later(a.at, b.at) : a.at };
    return { store, taken, conflicts };
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
    .filter((rec) => rec && rec.v !== null)
    .map((rec) => {
      const j = JSON.parse(rec.v);
      return copyfile.blocks(copyfile.fromJSON(j, fromHex(j.deviceId)), { net });
    });
}

module.exports = { settings, keychain, passwords, guestbook, edgeCopies, edgeBlocks };
