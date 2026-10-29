'use strict';

/**
 * THE CLI'S BUCKET AND THE SERVER'S SEALED COPY (bucket/src/sealedcopy.js; Phase 3): this computer's kept identity
 * bucket (bucket/cli/home.js, shared with the desktop app) synced with the room's rows, the way the app syncs its own
 * (ok-edge src/serverRoom.ts) - the tables compared first, then only the rows that differ.
 *
 * The file is written under its lock (home.update) and the server is asked over the network, so the lock is never held
 * across a request: the rows to get are fetched first, taken in one locked write (the stores' own rules, as a trade
 * takes a GIVE), then what this side must put is read from the file as it is after that.
 */

const home = require('./home');
const sealedCopy = require('../src/sealedcopy');
const replicate = require('../src/replicate');

/**
 * @param {{id: string, net: 'live'|'test', me: {bucketKey: {secretKey: Uint8Array}}, store: object, rules: object, randomBytes: Function, heads?: Function}} o
 *   store: the room's row store (room-client sealedStore); heads(bucket) -> {<dev>: seq} for the heads row
 * @returns {Promise<{on: boolean, got?: number, put?: number, taken?: Object<string, number>, refused?: string[]}>}
 */
async function syncKept({ id, net, me, store, rules, randomBytes, heads }) {
  if (typeof store.on === 'function' && !(await store.on())) return { on: false };
  const file = home.identityFile(id, net);
  const keys = sealedCopy.keysOf(me.bucketKey);
  const theirs = await store.table();
  const p = sealedCopy.plan(sealedCopy.table(home.read(file), keys, { rules }).rows, theirs, keys);
  let taken = {};
  let refused = [];
  if (p.get.length) {
    const opened = sealedCopy.openRows(await store.get(p.get), keys);
    refused = opened.refused;
    home.update(file, (b) => { taken = replicate.take(b, opened.given, { rules }).taken; });
  }
  const now = home.read(file);
  const put = sealedCopy.plan(sealedCopy.table(now, keys, { rules }).rows, theirs, keys).put;
  const rows = put.length ? sealedCopy.sealRows(now, keys, put, { rules, randomBytes }) : {};
  if (heads) {
    const h = sealedCopy.sealHeads(heads(now), keys, randomBytes);
    if (theirs[h.id] !== h.tag) rows[h.id] = { tag: h.tag, blob: h.blob };
  }
  if (Object.keys(rows).length) await store.put(rows);
  return { on: true, got: p.get.length, put: Object.keys(rows).length, taken, refused };
}

module.exports = { syncKept };
