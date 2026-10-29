'use strict';

/**
 * THE SERVER'S SEALED COPY OF AN IDENTITY BUCKET (PROPOSAL-sync-and-identity.md Phase 3; Brad, 2026-10-29: "the server's
 * sealed copy will have a hash table for changes, so checking what is on the key when asking the server is cheap"; the
 * room's own SQLite, one row per unit).
 *
 * The server keeps rows it cannot read, one per unit a trade compares (replicate.js: a record, or one part of a split
 * value):
 *   id    HMAC(table key, store \0 unit key) - which unit, without naming it (a bucket holds labels: the server never
 *         learns a store's or a record's name)
 *   tag   HMAC(table key, unit hash \0 its date) - the CHANGE TABLE: a row whose tag differs from a device's changed on
 *         one side. Keyed, so the server cannot test a guess at a short value (a nametag, a name) against a plain hash
 *   blob  the unit (its store, key and record, and the row's own id) sealed with the unit key (AES-256-GCM, vault.js)
 * Both keys come from the bucket key (bucket-identity.js), which every device of the identity derives alike and the
 * server never holds. A device reads the table (ids and tags only, a few KB), compares it with its own, and moves only
 * the rows that differ: puts what the server lacks or holds older, gets what it lacks - and every get goes through the
 * stores' own rules (replicate.take), exactly as a trade's GIVE does.
 *
 * THE KEY'S HEAD AGAINST THE TABLE (Brad's answer, 2026-10-29: "key head vs table"): one more row, HEADS, holds - sealed -
 * each Edge log's newest link the server's copy has. A device reads the key's head (one request, no press) and opens
 * that row: when the server already holds through the key's head, that log has nothing to send and nothing needs
 * reading from the key's ring (lib edge logblocks.newestSeqs gives a copy's).
 *
 * A row's blob names its own id inside the seal, so a server that moves a blob to another row is caught at open.
 * Pure: no device, no Node built-ins.
 */

const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { hkdf } = require('../../src/vendor/exports/@noble/hashes/hkdf.js');
const { hmac } = require('../../src/vendor/exports/@noble/hashes/hmac.js');
const { toHex } = require('../../src/bytes');
const vault = require('../../src/crypto/vault');
const replicate = require('./replicate');

const utf8 = (s) => new TextEncoder().encode(s);
const mac = (key, text) => toHex(hmac(sha256, key, utf8(text))).slice(0, 32);
const HEADS = '\u0000heads';

/**
 * The table key and the unit key, from the bucket key - the same on every device of the identity.
 * @param {{secretKey: Uint8Array}} bucketKey bucket-identity.deriveBucketKeyAt's
 */
function keysOf(bucketKey) {
  const salt = utf8('OKBUCKET-SEALED-v1');
  return {
    tableKey: hkdf(sha256, bucketKey.secretKey, salt, utf8('table'), 32),
    unitKey: hkdf(sha256, bucketKey.secretKey, salt, utf8('unit'), 32),
  };
}

/** The id of the heads row (each Edge log's newest link on the server). */
const headsId = (keys) => mac(keys.tableKey, HEADS);

/**
 * This bucket as the server's table would hold it.
 * @returns {{rows: Object<string, string>, where: Object<string, [string, string]>}} rows: id -> tag; where: id -> [store, unit key]
 */
function table(bucket, keys, { rules = {} } = {}) {
  const rows = {};
  const where = {};
  for (const [name, units] of Object.entries(replicate.summarize(bucket, { rules }))) {
    for (const [k, u] of Object.entries(units)) {
      const id = mac(keys.tableKey, `${name}\u0000${k}`);
      rows[id] = mac(keys.tableKey, `${u.h}\u0000${u.at || ''}`);
      where[id] = [name, k];
    }
  }
  return { rows, where };
}

/**
 * What to move: get the rows the server holds that this device lacks or holds differently (first - the stores' rules
 * merge them), then put the rows this device holds that the server lacks or holds differently (after the gets, from the
 * table made again). The heads row is never a unit.
 * @param {Object<string, string>} mine this device's table rows
 * @param {Object<string, string>} theirs the server's table rows
 */
function plan(mine, theirs, keys) {
  const h = keys ? headsId(keys) : null;
  const get = Object.keys(theirs).filter((id) => id !== h && mine[id] !== theirs[id]).sort();
  const put = Object.keys(mine).filter((id) => theirs[id] !== mine[id]).sort();
  return { get, put };
}

/**
 * The rows to put, sealed: each unit as a trade's GIVE carries it.
 * @param {string[]} ids from plan().put, against this bucket's table (made now)
 * @returns {Object<string, {tag: string, blob: string}>}
 */
function sealRows(bucket, keys, ids, { rules = {}, randomBytes }) {
  const t = table(bucket, keys, { rules });
  const mine = replicate.summarize(bucket, { rules });
  /* what the server is taken to hold: everything but the units to send - so give() sends exactly those */
  const theirs = JSON.parse(JSON.stringify(mine));
  for (const id of ids) {
    const w = t.where[id];
    if (!w) throw Object.assign(new Error('a row to put is not in this bucket now - plan again'), { code: 'EBUCKET_CHANGED' });
    delete theirs[w[0]][w[1]];
  }
  const given = replicate.give(bucket, mine, theirs, { rules });
  const out = {};
  for (const id of ids) {
    const [name, k] = t.where[id];
    out[id] = { tag: t.rows[id], blob: vault.seal(keys.unitKey, JSON.stringify({ id, s: name, k, r: given[name][k] }), randomBytes) };
  }
  return out;
}

/**
 * Rows from the server back into a GIVE for replicate.take. A blob that does not open, or names another row's id, is
 * refused - never taken.
 * @param {Object<string, string>} rows id -> blob
 * @returns {{given: Object, refused: string[]}}
 */
function openRows(rows, keys) {
  const given = {};
  const refused = [];
  for (const [id, blob] of Object.entries(rows)) {
    let u;
    try { u = JSON.parse(vault.open(keys.unitKey, blob)); } catch (_) { refused.push(`${id}: does not open with this bucket key`); continue; }
    if (!u || u.id !== id || typeof u.s !== 'string' || typeof u.k !== 'string' || !u.r) { refused.push(`${id}: not this row's unit`); continue; }
    if (!given[u.s]) given[u.s] = {};
    given[u.s][u.k] = u.r;
  }
  return { given, refused };
}

/**
 * The heads row: each Edge log's newest link the server's copy holds ({<dev>: seq}), sealed.
 * @returns {{id: string, tag: string, blob: string}}
 */
function sealHeads(heads, keys, randomBytes) {
  const text = JSON.stringify(Object.fromEntries(Object.entries(heads).sort()));
  const id = headsId(keys);
  return { id, tag: mac(keys.tableKey, text), blob: vault.seal(keys.unitKey, JSON.stringify({ id, heads: JSON.parse(text) }), randomBytes) };
}

/** The heads row opened ({<dev>: seq}), or {} when it is missing or not this bucket's. */
function openHeads(blob, keys) {
  if (!blob) return {};
  try {
    const u = JSON.parse(vault.open(keys.unitKey, blob));
    return u && u.id === headsId(keys) && u.heads && typeof u.heads === 'object' ? u.heads : {};
  } catch (_) {
    return {};
  }
}

/**
 * ONE SYNC WITH A ROW STORE (Brad, 2026-10-29: "we load the key on a fresh session empty, and it then needs to compare
 * the remote and session, and decide"; "the webapp can have an encrypted backup for caching"). A row store is anything
 * that keeps these rows - the server's room, or the web app's own encrypted cache in the browser - so a fresh session
 * compares its cache and the server the same way, and moves only what differs:
 *   store.table()      -> {id: tag}                 ids and tags only
 *   store.get(ids)     -> {id: blob}
 *   store.put(rows)    rows: {id: {tag, blob}}
 * heads: this bucket's Edge logs' newest links ({<dev>: seq}, from logblocks.newestSeqs) - the heads row is put again
 * whenever it changed.
 * @param {{stores: Object, clock?: string|null}} bucket changed in place by what is taken
 * @param {{tableKey: Uint8Array, unitKey: Uint8Array}} keys keysOf(bucket key)
 * @param {{table: () => Promise<Object<string, string>>, get: (ids: string[]) => Promise<Object<string, string>>, put: (rows: Object<string, {tag: string, blob: string}>) => Promise<void>}} store
 * @param {{rules?: Object, randomBytes: (n: number) => Uint8Array, heads?: Object<string, number>|null}} opts
 * @returns {Promise<{got: number, put: number, taken: Object<string, number>, conflicts: Array, refused: string[]}>}
 */
async function syncWith(bucket, keys, store, { rules = {}, randomBytes, heads = null } = {}) {
  const theirs = await store.table();
  const p = plan(table(bucket, keys, { rules }).rows, theirs, keys);
  let taken = {};
  let conflicts = [];
  let refused = [];
  if (p.get.length) {
    const opened = openRows(await store.get(p.get), keys);
    refused = opened.refused;
    const r = replicate.take(bucket, opened.given, { rules });
    taken = r.taken;
    conflicts = r.conflicts;
  }
  /* what this side holds after the gets, against what the server held */
  const put = plan(table(bucket, keys, { rules }).rows, theirs, keys).put;
  const rows = put.length ? sealRows(bucket, keys, put, { rules, randomBytes }) : {};
  if (heads) {
    const h = sealHeads(heads, keys, randomBytes);
    if (theirs[h.id] !== h.tag) rows[h.id] = { tag: h.tag, blob: h.blob };
  }
  if (Object.keys(rows).length) await store.put(rows);
  return { got: p.get.length, put: Object.keys(rows).length, taken, conflicts, refused };
}

/*
 * A BUCKET KEPT AS ROWS (Brad, 2026-10-29: "the webapp can have an encrypted backup for caching"; "making reloads of the
 * app even cheaper"; IndexedDB in the browser). A device may keep its own bucket as these same rows - one write per
 * changed unit, not the whole bucket sealed again - under keys from its own sealing secret. The OWNER row names whose
 * bucket the rows are, sealed like the rest: rows that open with the secret the key derives, and name this identity,
 * prove the key (as a sealed bucket opening did).
 */
const OWNER = '\u0000owner';
const ownerId = (keys) => mac(keys.tableKey, OWNER);
function sealOwner(owner, keys, randomBytes) {
  const id = ownerId(keys);
  return { id, tag: mac(keys.tableKey, `${OWNER}\u0000${owner}`), blob: vault.seal(keys.unitKey, JSON.stringify({ id, owner }), randomBytes) };
}

/**
 * Rows kept on this device back into its bucket: every row must open and the owner row must name `owner` - else null.
 * @param {Object<string, string>} rows id -> blob (all of them, the heads row and the owner row included)
 * @returns {{stores: Object, owner: string}|null}
 */
function bucketFromRows(rows, keys, { owner, rules = {} }) {
  const oid = ownerId(keys);
  const hid = headsId(keys);
  let who = null;
  try { const u = JSON.parse(vault.open(keys.unitKey, rows[oid])); who = u && u.id === oid ? u.owner : null; } catch (_) { return null; }
  if (who !== owner) return null;
  const units = Object.fromEntries(Object.entries(rows).filter(([id]) => id !== oid && id !== hid));
  const { given, refused } = openRows(units, keys);
  if (refused.length) return null;
  const { create } = require('./bucket');
  const b = create({ owner });
  replicate.take(b, given, { rules });
  return b;
}

module.exports = { keysOf, headsId, table, plan, sealRows, openRows, sealHeads, openHeads, syncWith, ownerId, sealOwner, bucketFromRows };
