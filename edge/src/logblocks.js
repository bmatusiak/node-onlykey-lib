'use strict';

/**
 * A DEVICE'S EDGE LOG IN THE IDENTITY BUCKET, AS BLOCKS (Brad, 2026-10-29: "sync should be simple and easy, it should
 * compare and merge, newest edit time wins"; "the newest one wins don't matter with edge because it's a block chain,
 * they're all signed and unique").
 *
 * One device's copy of the chain (copyfile.js) was one value - 436 KB for 1141 links on the live key - so a trade sent
 * all of it for one new link, and no trade carried it at all. In the identity bucket's `edge-logs` store it is cut into
 * keys a trade compares one by one (bucket/src/replicate.js units): a full block never changes again, so after the
 * first trade a ship moves the block it grew and the meta.
 *
 *   <dev>.meta             the newest checkpoint and lastSeen - what changes at every read of the key
 *   <dev>.keys             the device's Edge public keys (P-256, ML-DSA-65) - never change
 *   <dev>.statement        its owner statement (nametag) - changes when it is renamed
 *   <dev>.seals            the seals (only the newest with its ML-DSA-65 half) - change when a budget is sealed
 *   <dev>.links.<n>        links n*64 .. n*64+63 (seq), with their heads (and a press's reveal)
 *   <dev>.notes.<n>        the intents, receipt messages and seen marks for those links
 *   <dev>.open.<grantId>   one budget's opening words
 * <dev> is the device id's first 16 hex (the copies store's key); <n> zero-padded so the keys sort.
 *
 * MERGE (mergeEntry), the same result on both sides:
 *   links  the union by seq - links are signed and unique, nothing to choose; the same seq with different bytes is a
 *          FORK, reported and never repaired (copyfile.merge's rule)
 *   notes  the union by seq; the same seq written differently on two devices: the newer record's (ordered)
 *   keys   must match (two keys are two devices) - else a fork
 *   meta, statement, seals   copyfile.merge's own rules for those fields: the newest checkpoint / lastSeen /
 *          statement by seq, the seals' union with one hybrid anchor
 *   open   written once per budget: the newer record's
 * The fields are split by how often they change, so a trade after a ship carries a links block and a few KB - not the
 * ~28 KB of post-quantum keys and signatures every time (measured on the live key's log, 2026-10-29).
 * Checking a link against the key's signatures is the reader's (copy.js verify, edgeStore), not the merge's.
 */

const copyfile = require('./copyfile');
const { fromHex } = require('../../src/bytes');
const chain = require('./chain');

const BLOCK = 64;
const pad = (n) => String(n).padStart(6, '0');
const devOf = (deviceIdHex) => String(deviceIdHex).slice(0, 16).toLowerCase();
const seqOfHex = (l) => chain.decodeLink(fromHex(l.link)).seq;

/* the copy's fields each one-off key holds (deviceId and v in each, so every key reads alone) */
const FIELDS = {
  meta: ['lastSeen', 'checkpoint'],
  keys: ['publicKey', 'publicKeyPq'],
  statement: ['statement'],
  seals: ['seals'],
};
const NUMBERED = ['links', 'notes', 'open'];

/** The key's kind and device: {dev, kind, n} or null for a key that is not a log's. */
function parseKey(key) {
  const m = /^([0-9a-f]{16})\.(meta|keys|statement|seals|links|notes|open)(?:\.(\d+))?$/.exec(key);
  if (!m) return null;
  if (NUMBERED.includes(m[2]) !== (m[3] !== undefined)) return null;
  return { dev: m[1], kind: m[2], n: m[3] === undefined ? null : Number(m[3]) };
}

/**
 * A copy (copyfile.toJSON's shape) as the store's keys -> values (JSON text).
 * @param {object} j the copy as JSON
 * @returns {Object<string, string>}
 */
function split(j) {
  const dev = devOf(j.deviceId);
  const out = {};
  const { links = [], notes = {}, openings = [] } = j;
  for (const [kind, fields] of Object.entries(FIELDS)) {
    const part = { v: j.v, deviceId: j.deviceId };
    for (const f of fields) if (j[f] !== undefined) part[f] = j[f];
    /* an empty one-off key is not written (the meta always is: it names the device) */
    if (kind === 'meta' || fields.some((f) => j[f] !== undefined && !(Array.isArray(j[f]) && !j[f].length))) out[`${dev}.${kind}`] = JSON.stringify(part);
  }
  const byBlock = new Map();
  for (const l of links) {
    const n = Math.floor(seqOfHex(l) / BLOCK);
    if (!byBlock.has(n)) byBlock.set(n, []);
    byBlock.get(n).push(l);
  }
  for (const [n, ls] of byBlock) out[`${dev}.links.${pad(n)}`] = JSON.stringify(ls.sort((a, b) => seqOfHex(a) - seqOfHex(b)));
  const noteBlocks = new Map();
  for (const field of ['reasons', 'messages', 'seen']) {
    for (const [seq, v] of Object.entries(notes[field] || {})) {
      const n = Math.floor(Number(seq) / BLOCK);
      if (!noteBlocks.has(n)) noteBlocks.set(n, { reasons: {}, messages: {}, seen: {} });
      noteBlocks.get(n)[field][seq] = v;
    }
  }
  for (const [n, nb] of noteBlocks) out[`${dev}.notes.${pad(n)}`] = JSON.stringify(nb);
  for (const o of openings) out[`${dev}.open.${o.grantId}`] = JSON.stringify(o);
  return out;
}

/**
 * One device's keys back into its copy (copyfile.toJSON's shape), or null when the store holds no meta for it.
 * @param {Object<string, string>} entries the store's live keys -> values (only this device's are read)
 * @param {string} deviceIdHex
 */
function join(entries, deviceIdHex) {
  const dev = devOf(deviceIdHex);
  const metaText = entries[`${dev}.meta`];
  if (metaText === undefined) return null;
  const meta = JSON.parse(metaText);
  /* the copy's fields in copyfile.toJSON's order, so a joined copy reads as the one that was split */
  const one = {};
  for (const kind of Object.keys(FIELDS)) if (entries[`${dev}.${kind}`] !== undefined) Object.assign(one, JSON.parse(entries[`${dev}.${kind}`]));
  const j = { v: meta.v, deviceId: meta.deviceId, links: [] };
  if (one.lastSeen !== undefined) j.lastSeen = one.lastSeen;
  for (const f of ['publicKey', 'publicKeyPq', 'seals', 'checkpoint', 'statement']) if (one[f] !== undefined) j[f] = one[f];
  /* copyfile.toJSON always writes the seals, even none (an empty list is not kept as a key) */
  if (!j.seals) j.seals = [];
  j.notes = { reasons: {}, messages: {}, seen: {} };
  j.openings = [];
  for (const key of Object.keys(entries).sort()) {
    const k = parseKey(key);
    if (!k || k.dev !== dev || !NUMBERED.includes(k.kind)) continue;
    const v = JSON.parse(entries[key]);
    if (k.kind === 'links') j.links.push(...v);
    if (k.kind === 'notes') for (const f of ['reasons', 'messages', 'seen']) Object.assign(j.notes[f], v[f] || {});
    if (k.kind === 'open') j.openings.push(v);
  }
  j.links.sort((a, b) => seqOfHex(a) - seqOfHex(b));
  j.openings.sort((a, b) => a.grantId - b.grantId);
  /* as copyfile.toJSON writes a copy: no openings field when there are none, no seen marks when none were kept */
  if (!j.openings.length) delete j.openings;
  if (!Object.keys(j.notes.seen).length) delete j.notes.seen;
  return j;
}

/** The devices whose log the store holds (by their meta). */
function devices(keys) {
  return keys.map(parseKey).filter((k) => k && k.kind === 'meta').map((k) => k.dev).sort();
}

/*
 * Two values of one key into one. lo/hi: the two sides in a fixed order (older first), so both devices reach the same
 * value. -> {v, taken, fork}: v the merged text (=== lo/hi's own text when nothing changed), taken how many entries it
 * added over `have`, fork a reason when the two cannot merge (nothing is taken).
 */
function mergeEntry(key, haveText, lo, hi) {
  const k = parseKey(key);
  if (!k) return { v: hi, taken: hi === haveText ? 0 : 1, fork: null };
  if (k.kind === 'links') {
    const bySeq = new Map();
    for (const l of JSON.parse(lo)) bySeq.set(seqOfHex(l), l);
    for (const l of JSON.parse(hi)) {
      const s = seqOfHex(l);
      const was = bySeq.get(s);
      if (was && (was.link !== l.link || was.head !== l.head)) return { v: haveText, taken: 0, fork: `the logs disagree at #${s} - a fork, reported, never repaired` };
      bySeq.set(s, was && was.reveal && !l.reveal ? was : l);
    }
    const had = new Set(JSON.parse(haveText).map(seqOfHex));
    const merged = [...bySeq.entries()].sort((a, b) => a[0] - b[0]).map(([, l]) => l);
    return { v: JSON.stringify(merged), taken: merged.filter((l) => !had.has(seqOfHex(l))).length, fork: null };
  }
  if (k.kind === 'notes') {
    const a = JSON.parse(lo);
    const b = JSON.parse(hi);
    const out = {};
    for (const f of ['reasons', 'messages', 'seen']) out[f] = { ...(a[f] || {}), ...(b[f] || {}) };
    const v = JSON.stringify(out);
    const have = JSON.parse(haveText);
    const count = (x) => ['reasons', 'messages', 'seen'].reduce((s, f) => s + Object.keys(x[f] || {}).length, 0);
    return { v, taken: v === haveText ? 0 : Math.max(1, count(out) - count(have)), fork: null };
  }
  if (FIELDS[k.kind]) {
    const a = JSON.parse(lo);
    const b = JSON.parse(hi);
    if (k.kind === 'keys' && ((a.publicKey && b.publicKey && a.publicKey !== b.publicKey) || (a.publicKeyPq && b.publicKeyPq && a.publicKeyPq !== b.publicKeyPq))) {
      return { v: haveText, taken: 0, fork: 'the logs name different keys for this device' };
    }
    /*
     * copyfile's own merge for these fields - the newest checkpoint / lastSeen / statement by seq, the seals' union with
     * one hybrid anchor - over two copies that hold only them; the key keeps only its own fields
     */
    const id = fromHex(a.deviceId || b.deviceId);
    const r = copyfile.merge(copyfile.fromJSON({ ...a, v: copyfile.VERSION, links: [] }, id), copyfile.fromJSON({ ...b, v: copyfile.VERSION, links: [] }, id));
    const merged = copyfile.toJSON(r.copy);
    const part = { v: a.v ?? b.v, deviceId: a.deviceId || b.deviceId };
    for (const f of FIELDS[k.kind]) if (merged[f] !== undefined && (a[f] !== undefined || b[f] !== undefined)) part[f] = merged[f];
    const v = JSON.stringify(part);
    return { v, taken: v === haveText ? 0 : 1, fork: null };
  }
  /* an opening: written once - the newer record's */
  return { v: hi, taken: hi === haveText ? 0 : 1, fork: null };
}

/*
 * A HOST FILES ITS COPY INTO WHAT THE BUCKET ALREADY HOLDS (Phase 5; Brad, 2026-10-29: the app's own log in the bucket,
 * so the CLI and every device see its budgets). A host's copy may hold less than the bucket - a fresh web app starts at
 * the key's checkpoint, while the CLI filed the whole history - so its blocks are merged into the ones there (mergeEntry:
 * links by union, a fork reported and not written), never written over them.
 * @param {Object<string, string>} have the store's live keys -> values
 * @param {object} j the host's copy as JSON (copyfile.toJSON)
 * @returns {{changed: Object<string, string>, forks: string[]}} the keys to write (only those that change), and why any were not
 */
function fileInto(have, j) {
  const changed = {};
  const forks = [];
  for (const [key, mine] of Object.entries(split(j))) {
    const was = have[key];
    if (was === undefined || was === null) { changed[key] = mine; continue; }
    if (was === mine) continue;
    const r = mergeEntry(key, was, was, mine);
    if (r.fork) { forks.push(`${key}: ${r.fork}`); continue; }
    if (r.v !== was) changed[key] = r.v;
  }
  return { changed, forks };
}

/*
 * EACH LOG'S NEWEST LINK in a store's entries ({<dev>: seq}) - what a sealed copy's heads row says (bucket sealedcopy.js),
 * so a device compares the key's head with it before reading anything from the key. From the last links block only.
 * @param {Object<string, string>} entries the store's live keys -> values
 */
function newestSeqs(entries) {
  const last = {};
  for (const key of Object.keys(entries)) {
    const k = parseKey(key);
    if (k && k.kind === 'links' && (last[k.dev] === undefined || key > last[k.dev])) last[k.dev] = key;
  }
  const out = {};
  for (const [dev, key] of Object.entries(last)) {
    const ls = JSON.parse(entries[key]);
    if (ls.length) out[dev] = Math.max(...ls.map(seqOfHex));
  }
  return out;
}

module.exports = { BLOCK, split, join, devices, parseKey, mergeEntry, devOf, fileInto, newestSeqs };
