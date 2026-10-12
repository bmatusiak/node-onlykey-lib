'use strict';

/**
 * THE GUEST BOOK STORE (GUEST-BOOK-SPEC.md, "Data model").
 *
 * One versioned JSON blob, `guestbook:v1`, through the storage the host passes in (AsyncStorage in
 * ok-rn, a memory store in tests). Local only. A contact holds any number of keys, each pinned by
 * its own fingerprint and each with the sources that can refresh it; nothing here talks to the
 * network or to an OnlyKey.
 *
 * PUBLIC ONLY: the private-key guard (src/crypto/public-only.js, shared with Key Chain) runs over
 * the whole list on every save, as well as at every way in (formats.js) - a private key can never
 * be written, however it got this far.
 *
 * A blob that does not read (damaged, or a version this code does not know) is not thrown away:
 * it is kept under `guestbook:v1:damaged:<time>` and the list starts empty, and load() says so.
 */

const { toHex } = require('../../src/bytes');
const { refusePrivate } = require('../../src/crypto/public-only');
const { FORMATS } = require('./formats');

const KEY = 'guestbook:v1';
const VERSION = 1;
const SOURCE_KINDS = ['keybase', 'protonmail', 'github', 'url', 'paste', 'qr', 'connect'];
const HISTORY_MAX = 20;
const HOLDER = 'Guest Book';

/** @typedef {{kind: string, handle: string, lastChecked?: string, lastResult?: string}} SourceLink */

function shapeSource(s) {
  if (!s || !SOURCE_KINDS.includes(s.kind)) throw new Error(`guestbook: a source is one of ${SOURCE_KINDS.join(', ')}`);
  const out = { kind: s.kind, handle: String(s.handle || '') };
  if (s.lastChecked) out.lastChecked = String(s.lastChecked);
  if (s.lastResult) out.lastResult = String(s.lastResult);
  return out;
}

function shapeKey(k) {
  if (!k || !FORMATS.includes(k.format)) throw new Error(`guestbook: a key's format is one of ${FORMATS.join(', ')}`);
  if (!k.text || !k.fingerprint) throw new Error('guestbook: a key needs its text and fingerprint');
  const out = {
    id: String(k.id),
    format: k.format,
    label: String(k.label || ''),
    text: String(k.text),
    fingerprint: String(k.fingerprint),
    verified: k.verified === true,
    sources: (k.sources || []).map(shapeSource),
    addedAt: String(k.addedAt),
    updatedAt: String(k.updatedAt),
  };
  if (k.info && typeof k.info === 'object') out.info = k.info;
  if (k.pending) out.pending = k.pending;
  return out;
}

function shapeContact(c) {
  if (!c || !c.id) throw new Error('guestbook: a contact needs its id');
  /* on what came in, before shaping: a private field is refused, never quietly dropped */
  refusePrivate(c, 'contact', HOLDER);
  const out = {
    id: String(c.id),
    name: String(c.name || '').trim() || 'Unnamed',
    keys: (c.keys || []).map(shapeKey),
    history: (c.history || []).slice(0, HISTORY_MAX),
  };
  if (c.note) out.note = String(c.note);
  refusePrivate(out, 'contact', HOLDER);
  return out;
}

/**
 * The Guest Book over a key-value storage.
 * @param {{storage: {getItem(k: string): Promise<string|null>, setItem(k: string, v: string): Promise<void>}, randomBytes: (n: number) => Uint8Array, now?: () => Date, key?: string}} deps - key: the storage key (a host keeps a test list apart under another)
 */
function createGuestBook({ storage, randomBytes, now = () => new Date(), key = KEY }) {
  const stamp = () => now().toISOString();
  const newId = () => toHex(randomBytes(16));

  async function load() {
    const raw = await storage.getItem(key);
    if (!raw) return { contacts: [], recovered: false };
    try {
      const blob = JSON.parse(raw);
      if (!blob || blob.v !== VERSION || !Array.isArray(blob.contacts)) throw new Error('not a guestbook v1 blob');
      return { contacts: blob.contacts.map(shapeContact), recovered: false };
    } catch (e) {
      await storage.setItem(`${key}:damaged:${stamp()}`, raw);
      await storage.setItem(key, JSON.stringify({ v: VERSION, contacts: [] }));
      return { contacts: [], recovered: true, reason: String(e.message || e) };
    }
  }

  async function save(contacts) {
    const shaped = contacts.map(shapeContact);
    refusePrivate(shaped, 'contacts', HOLDER);
    await storage.setItem(key, JSON.stringify({ v: VERSION, contacts: shaped }));
    return shaped;
  }

  const historyOf = (c, what) => [{ at: stamp(), what }, ...(c.history || [])].slice(0, HISTORY_MAX);

  /** A key as Guest Book keeps it, from a detector's find and where it came from. */
  function keyFrom(found, source) {
    const at = stamp();
    return shapeKey({ ...found, id: newId(), verified: false, sources: source ? [source] : [], addedAt: at, updatedAt: at });
  }

  /** A new contact holding the keys found (a person's Add). */
  function newContact({ name, found, source }) {
    if (!found || !found.length) throw new Error('guestbook: a contact needs at least one key');
    return shapeContact({
      id: newId(),
      name: name || found[0].label,
      keys: found.map((f) => keyFrom(f, source)),
      history: [{ at: stamp(), what: `added from ${source ? source.kind : 'paste'}` }],
    });
  }

  /**
   * More keys onto a contact. A key already there (same format and fingerprint) only gains the
   * source; a new one is added. Nothing is replaced - a changed key is the refresh rule's business.
   */
  function addKeys(contact, found, source) {
    const keys = contact.keys.map((k) => ({ ...k, sources: [...k.sources] }));
    for (const f of found) {
      const same = keys.find((k) => k.format === f.format && k.fingerprint === f.fingerprint);
      if (same) {
        if (source && !same.sources.some((s) => s.kind === source.kind && s.handle === source.handle)) same.sources.push(shapeSource(source));
      } else {
        keys.push(keyFrom(f, source));
      }
    }
    return shapeContact({ ...contact, keys, history: historyOf(contact, 'keys added') });
  }

  /** Set (or clear) the person's out-of-band check of one key's fingerprint. */
  function setVerified(contact, keyId, verified) {
    return shapeContact({
      ...contact,
      keys: contact.keys.map((k) => (k.id === keyId ? { ...k, verified: !!verified, updatedAt: stamp() } : k)),
      history: historyOf(contact, verified ? 'fingerprint verified' : 'verified mark cleared'),
    });
  }

  const rename = (contact, name, note) =>
    shapeContact({ ...contact, name, note: note === undefined ? contact.note : note, history: historyOf(contact, 'renamed') });

  const removeKey = (contact, keyId) =>
    shapeContact({ ...contact, keys: contact.keys.filter((k) => k.id !== keyId), history: historyOf(contact, 'key removed') });

  return { KEY: key, load, save, newContact, addKeys, setVerified, rename, removeKey };
}

module.exports = { KEY, VERSION, SOURCE_KINDS, HISTORY_MAX, createGuestBook, shapeContact };
