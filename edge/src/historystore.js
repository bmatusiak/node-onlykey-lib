'use strict';

/**
 * THE KEY'S OWN CHAIN COPY, KEPT BY A HOST (the structure track S4 step 8, 2026-11-02): the links this host read off its
 * key, where the copy starts (anchor), the head it last verified (lastSeen), the seals it took, and the host's own notes
 * on them (when each link was first seen, the agents' reasons and refusals, records set aside). The copy the verdict
 * (verdict.js) checks and the bucket's edge-logs block (copyfile.js) is filed from.
 *
 * It was the ok-edge app's alone (edgeStore.ts: loadMirror / saveMirror over AsyncStorage); here it is one store over the
 * host's kv - the app's AsyncStorage, later the CLI's home - with the SAME key and the SAME stored form (v1 JSON), so
 * every copy a host already holds reads as it is: nothing is migrated.
 *
 *   <prefix><deviceIdHex>  ->  {v: 1, deviceId, links: [{link, head, reveal?}], messages, lastSeen, lastSync, anchor?,
 *                               seen?, reasons?, refusals?, setAside?, publicKey?, publicKeyPq?, continued?, merged?,
 *                               seals?}   (bytes as hex)
 *
 *   createHistory({kv, prefix})  kv: {getItem, setItem, removeItem?, getAllKeys?} (sync or async; strings);
 *                                prefix: () => string - the net's own (the app's edgeKey('mirror.'))
 *     load(deviceId) -> copy      the session's copy (read from the store once a session), a copy of its lists
 *     read(deviceId) -> copy      from the store, the session's copy untouched
 *     save(copy) -> {written, outside}
 *     forget(deviceId)            the session's copy and the stored one
 *     drop(deviceId)              the session's copy only: the next load reads the store (an edit made there shows)
 *     ends(deviceId) -> {seq, head} | null    the newest link held with its head, else the anchor - what the key's
 *                                              session is told it already knows (edge client knownHead)
 *     take(deviceId, added, now?) -> {written, outside, added}   links of the key's own chain kept (verdict.takeOwn said yes)
 *     ids() -> [deviceIdHex]      every copy the store holds
 *     empty(deviceId) -> copy
 *
 * THE COPY IN MEMORY FOR THE SESSION (Brad, 2026-10-07: "option A is good"): reading the whole copy back from the store,
 * parsing and hashing it on every sync cost the A13 130 ms to load and 60-500 ms to hash. So the store is read once a
 * session and the copy lives here after; other apps cannot edit this process's memory. An edit to the STORED copy while
 * the host runs must still show, so it is never written over: each save first reads the stored text back and compares
 * it with what this session last read or wrote (a string compare). Different: something else wrote it - nothing is
 * written, the session's copy is dropped ({outside: true}), and the next load reads the store and the verdict checks it.
 * Records are never changed in place, and load hands out a copy of the lists, so a caller that changes it without
 * saving changes nothing. Each record's stored form is kept with it, so a save turns only NEW records into hex (A13:
 * "save 80-290").
 */

const chain = require('./chain');
const { merge } = require('./sync');

const toHex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => Uint8Array.from(Buffer.from(String(h || ''), 'hex'));
const numKeys = (o) => Object.fromEntries(Object.entries(o || {}).map(([k, v]) => [Number(k), v]));
const strKeys = (o) => Object.fromEntries(Object.entries(o || {}).map(([k, v]) => [String(k), v]));
const pointIn = (a) => ({ seq: a.seq, head: fromHex(a.head), signature: fromHex(a.signature), ...(a.signaturePq ? { signaturePq: fromHex(a.signaturePq) } : {}) });
const pointOut = (a) => ({ seq: a.seq, head: toHex(a.head), signature: toHex(a.signature), ...(a.signaturePq ? { signaturePq: toHex(a.signaturePq) } : {}) });

/**
 * @param {{kv: {getItem: (k: string) => any, setItem: (k: string, v: string) => any, removeItem?: (k: string) => any, getAllKeys?: () => any}, prefix: () => string}} o
 * @returns {{key: (deviceId: Uint8Array | string) => string, load: (deviceId: Uint8Array | string) => Promise<any>,
 *   read: (deviceId: Uint8Array | string) => Promise<any>, save: (copy: any) => Promise<{written: boolean, outside: boolean}>,
 *   forget: (deviceId: Uint8Array | string) => Promise<void>, drop: (deviceId: Uint8Array | string) => void,
 *   ends: (deviceId: Uint8Array | string) => Promise<{seq: number, head: Uint8Array} | null>, ids: () => Promise<string[]>,
 *   take: (deviceId: Uint8Array | string, added: Array<{link: Uint8Array, head: Uint8Array, reveal?: Uint8Array | null}>, now?: number) => Promise<{written: boolean, outside: boolean, added: number}>,
 *   empty: (deviceId: Uint8Array | string) => any}}
 */
function createHistory({ kv, prefix }) {
  for (const fn of ['getItem', 'setItem']) {
    if (!kv || typeof kv[fn] !== 'function') throw new TypeError(`history store: the host store needs ${fn}()`);
  }
  if (typeof prefix !== 'function') throw new TypeError('history store: prefix is a function (the net decides it)');
  const idOf = (deviceId) => (typeof deviceId === 'string' ? deviceId.toLowerCase() : toHex(deviceId));
  const key = (deviceId) => `${prefix()}${idOf(deviceId)}`;

  const inMemory = new Map();
  /* the stored text as this session last read or wrote it */
  const storedText = new Map();
  const storedForm = new WeakMap();
  const storedOf = (l) => {
    let x = storedForm.get(l);
    if (!x) {
      x = { link: toHex(l.link), head: l.head ? toHex(l.head) : '', ...(l.reveal ? { reveal: toHex(l.reveal) } : {}) };
      storedForm.set(l, x);
    }
    return x;
  };

  const empty = (deviceId) => ({
    deviceId: typeof deviceId === 'string' ? fromHex(deviceId) : deviceId,
    links: [], messages: {}, lastSeen: null, lastSync: null, setAside: [], seen: {}, reasons: {}, refusals: [],
  });
  const clone = (m) => ({
    ...m, links: m.links.slice(), messages: { ...m.messages }, seen: { ...m.seen }, reasons: { ...m.reasons },
    refusals: m.refusals.slice(), setAside: m.setAside.slice(),
    ...(m.merged ? { merged: m.merged.slice() } : {}), ...(m.seals ? { seals: m.seals.slice() } : {}),
  });

  async function read(deviceId) {
    const id = idOf(deviceId);
    const raw = await kv.getItem(key(id));
    if (raw) storedText.set(id, raw); else storedText.delete(id);
    if (!raw) return empty(deviceId);
    let s;
    try { s = JSON.parse(raw); } catch { s = null; }
    /* the old chain's copy (before the clean start, 2026-10-07: no v) is not read - this key starts again */
    if (!s || s.v !== 1) { storedText.delete(id); return empty(deviceId); }
    return {
      deviceId: fromHex(s.deviceId),
      links: s.links.map((l) => {
        const r = { link: fromHex(l.link), head: fromHex(l.head), reveal: l.reveal ? fromHex(l.reveal) : null };
        storedForm.set(r, l);
        return r;
      }),
      messages: numKeys(s.messages),
      lastSeen: s.lastSeen ? { seq: s.lastSeen.seq, head: fromHex(s.lastSeen.head) } : null,
      lastSync: s.lastSync,
      anchor: s.anchor ? { seq: s.anchor.seq, head: fromHex(s.anchor.head) } : null,
      setAside: (s.setAside || []).map((x) => ({ link: fromHex(x.link), head: fromHex(x.head), at: x.at })),
      seen: numKeys(s.seen),
      reasons: numKeys(s.reasons),
      refusals: s.refusals || [],
      publicKey: s.publicKey ? fromHex(s.publicKey) : null,
      publicKeyPq: s.publicKeyPq ? fromHex(s.publicKeyPq) : null,
      continued: s.continued || null,
      merged: (s.merged || []).map((a) => ({ ...pointIn(a), at: a.at })),
      seals: (s.seals || []).map((x) => ({ ...pointIn(x), ended: x.ended || [] })),
    };
  }

  async function load(deviceId) {
    const id = idOf(deviceId);
    const kept = inMemory.get(id);
    if (kept) return clone(kept);
    const m = await read(deviceId);
    inMemory.set(id, m);
    return clone(m);
  }

  async function save(m) {
    const id = idOf(m.deviceId);
    const s = {
      v: 1,
      deviceId: id,
      links: m.links.map(storedOf),
      messages: strKeys(m.messages),
      lastSeen: m.lastSeen ? { seq: m.lastSeen.seq, head: toHex(m.lastSeen.head) } : null,
      lastSync: m.lastSync,
      ...(m.anchor ? { anchor: { seq: m.anchor.seq, head: toHex(m.anchor.head) } } : {}),
      seen: strKeys(m.seen),
      ...(Object.keys(m.reasons).length ? { reasons: strKeys(m.reasons) } : {}),
      ...(m.refusals.length ? { refusals: m.refusals } : {}),
      ...(m.setAside.length ? { setAside: m.setAside.map((x) => ({ link: toHex(x.link), head: toHex(x.head), at: x.at })) } : {}),
      ...(m.publicKey ? { publicKey: toHex(m.publicKey) } : {}),
      ...(m.publicKeyPq ? { publicKeyPq: toHex(m.publicKeyPq) } : {}),
      ...(m.continued ? { continued: m.continued } : {}),
      ...(m.merged && m.merged.length ? { merged: m.merged.map((a) => ({ ...pointOut(a), at: a.at })) } : {}),
      ...(m.seals && m.seals.length ? { seals: m.seals.map((x) => ({ ...pointOut(x), ended: x.ended })) } : {}),
    };
    const text = JSON.stringify(s);
    const now = (await kv.getItem(key(id))) ?? null;
    if (inMemory.has(id) && now !== (storedText.get(id) ?? null)) {
      inMemory.delete(id);
      return { written: false, outside: true };
    }
    inMemory.set(id, clone(m));
    if (now === text) return { written: false, outside: false };
    await kv.setItem(key(id), text);
    storedText.set(id, text);
    return { written: true, outside: false };
  }

  async function forget(deviceId) {
    const id = idOf(deviceId);
    inMemory.delete(id);
    storedText.delete(id);
    if (typeof kv.removeItem === 'function') await kv.removeItem(key(id));
  }

  function drop(deviceId) {
    inMemory.delete(idOf(deviceId));
  }

  /* the LAST link only (an earlier head would tell the key's session an older end than the copy has), or the anchor of a
     copy that holds nothing after it yet */
  async function ends(deviceId) {
    const m = await load(deviceId);
    const last = m.links[m.links.length - 1];
    if (last) return last.head && last.head.length ? { seq: chain.decodeLink(last.link).seq, head: last.head } : null;
    return m.anchor ? { seq: m.anchor.seq, head: m.anchor.head } : null;
  }

  /*
   * Links of the key's OWN chain taken into the stored copy (S4 step 6; verdict.takeOwn said yes): merged into the copy
   * as it is NOW, not saved from the candidate that was checked - a sync that loaded the copy meanwhile and saved after
   * would drop them (the Pixel, 2026-10-05: five approved links lost). A host serialises this with its own syncs. A link
   * that now disagrees is a fork: nothing kept. Each new link's first-seen time is `now`.
   */
  async function take(deviceId, added, now = Date.now()) {
    const m = await load(deviceId);
    const r = merge(m.links, added);
    if (r.conflicts.length) throw new Error(`a fork at #${r.conflicts.join(', #')} - nothing kept`);
    m.links = r.links;
    for (const l of r.added) {
      const seq = chain.decodeLink(l.link).seq;
      if (m.seen[seq] === undefined) m.seen[seq] = now;
    }
    return { ...(await save(m)), added: r.added.length };
  }

  async function ids() {
    if (typeof kv.getAllKeys !== 'function') return [];
    const p = prefix();
    return (await kv.getAllKeys()).filter((k) => k.startsWith(p)).map((k) => k.slice(p.length));
  }

  return { key, load, read, save, forget, drop, ends, take, ids, empty };
}

module.exports = { createHistory };
