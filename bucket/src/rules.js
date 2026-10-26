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

/*
 * A STORE KEPT AS ONE VALUE HAS OTHER KEYS TOO (a trade test, 2026-10-25: Guest Book's your-name and offered keys were
 * never merged - the rule saw only its contacts blob). The rule joins its own key per entry; every other key in the
 * store takes the generic newer-wins.
 */
function withOthers(key, rule) {
  const omit = (s) => Object.fromEntries(Object.entries(s).filter(([k]) => k !== key));
  const pick = (s) => (s[key] ? { [key]: s[key] } : {});
  return (into = {}, from = {}) => {
    const others = mergeKeys(omit(into), omit(from));
    const own = rule(pick(into), pick(from));
    return { store: { ...others.store, ...own.store }, taken: others.taken + own.taken, conflicts: [...others.conflicts, ...own.conflicts] };
  };
}

/*
 * A STORE KEPT AS ONE VALUE GOES OVER IN PIECES (Brad, 2026-10-25: "this should be easy to separate and chunk"). The
 * Key Chain list, the Guest Book and the Cryptobox are each one value holding a list of items with ids - 140, 29 and
 * 110 KB on the test key - and a sync sent the whole value whenever any item changed. Their rules say how the value
 * splits: one part per item (`#<id>`, the item with its keys in one order) and one part for everything else (``).
 * replicate.js compares and gives parts, not the value: one changed item moves alone. The parts given are joined back
 * into a value holding just them, and the store's own rule merges that in as it merges any other copy (items join by
 * id, the newer wins, archived stays archived) - so a value need not arrive whole to merge whole.
 */
function canonical(v) {
  if (Array.isArray(v)) return v.map(canonical);
  if (v && typeof v === 'object') return Object.keys(v).sort().reduce((o, k) => { o[k] = canonical(v[k]); return o; }, {});
  return v;
}
function listParts(key, field) {
  return {
    key,
    /** @param {string} v the value @returns {Object<string, string>} part id -> its text */
    split(v) {
      const j = JSON.parse(v);
      if (!j || typeof j !== 'object' || !Array.isArray(j[field])) throw new Error(`not a list of ${field}`);
      const { [field]: items, ...rest } = j;
      const out = { '': JSON.stringify(canonical(rest)) };
      for (const it of items) if (it && it.id !== undefined) out[`#${it.id}`] = JSON.stringify(canonical(it));
      return out;
    },
    /** @param {Object<string, string>} parts @returns {string} a value holding just these parts */
    join(parts) {
      const rest = parts[''] ? JSON.parse(parts['']) : {};
      const items = Object.keys(parts).filter((p) => p !== '').sort().map((p) => JSON.parse(parts[p]));
      return JSON.stringify({ ...rest, [field]: items });
    },
  };
}
/* a rule with its parts: replicate.js finds them on the rule */
const withParts = (rule, parts) => Object.assign(rule, { parts });

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
  return withParts(withOthers(key, (into = {}, from = {}) => {
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
    /* counted against this side's list - the other copy may be just the entries that differed (listParts) */
    const had = new Set(list.parse(a.v).map((e) => e.id));
    return { store, taken: Math.max(1, r.entries.filter((e) => !had.has(e.id)).length), conflicts: [] };
  }), listParts(key, 'entries'));
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
  /*
   * when a contact last changed: the newest of its keys' updatedAt AND its history (every edit stamps one - details
   * edited, renamed, key removed - guestbook/src/store.js), else the blob's date. Keys alone missed every edit that is
   * not a key: a note added on the Windows desktop never won on the A13 and the store never settled (2026-10-25).
   */
  const changedAt = (c, blobAt) => [...(c.keys || []).map((k) => k.updatedAt), ...(c.history || []).map((h) => h && h.at)]
    .map((t) => String(t || '')).filter(Boolean).sort().pop() || blobAt;
  return withParts(withOthers(key, (into = {}, from = {}) => {
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
  }), listParts(key, 'contacts'));
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

/**
 * The Cryptobox (cryptobox/src/store.js): one key holding `{v, messages}`. Messages join by id from both sides - a
 * message written on one device is never lost to a message written on the other - and a message removed on either side
 * stays removed (removal is an archived flag, never a drop). The joined list is in one order (when written, then id),
 * so both devices end with the same value byte for byte and their bucket states match (replicate.js stateOf). Not
 * made from the Cryptobox module: the blob's shape is all it reads.
 * @param {{key?: string}} [opts]
 */
function cryptobox({ key = 'cryptobox:v1' } = {}) {
  const parse = (rec) => {
    try {
      const j = JSON.parse(rec.v);
      return j && Array.isArray(j.messages) ? j : null;
    } catch {
      return null;
    }
  };
  return withParts(withOthers(key, (into = {}, from = {}) => {
    const store = { ...into };
    const a = into[key];
    const b = from[key];
    if (!b) return { store, taken: 0, conflicts: [] };
    const pa = live(a) ? parse(a) : null;
    const pb = live(b) ? parse(b) : null;
    /* one side has no readable list: the newer record of the key wins */
    if (!pa || !pb) {
      if (!newer(a, b)) return { store, taken: 0, conflicts: [] };
      store[key] = { ...b };
      return { store, taken: 1, conflicts: [] };
    }
    const [lo, hi] = ordered(a, b).map((r) => (r === a ? pa : pb));
    const byId = new Map(lo.messages.map((m) => [m.id, m]));
    for (const m of hi.messages) {
      const old = byId.get(m.id);
      if (!old) { byId.set(m.id, m); continue; }
      /* the same message: the newer list's copy (a thread moved), archived if either side removed it */
      const gone = old.archived || m.archived;
      byId.set(m.id, gone ? { ...m, archived: true, archivedAt: m.archivedAt || old.archivedAt || '' } : m);
    }
    const messages = [...byId.values()].sort((x, y) => (x.at < y.at ? -1 : x.at > y.at ? 1 : x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
    const v = JSON.stringify({ v: hi.v || 1, messages });
    if (v === a.v) return { store, taken: 0, conflicts: [] };
    store[key] = { v, at: later(a.at, b.at) };
    const had = new Set(pa.messages.filter((m) => !m.archived).map((m) => m.id));
    const changed = messages.filter((m) => !had.has(m.id) || m.archived).length;
    return { store, taken: Math.max(1, changed), conflicts: [] };
  }), listParts(key, 'messages'));
}

module.exports = { settings, keychain, passwords, guestbook, edgeCopies, edgeBlocks, cryptobox };
