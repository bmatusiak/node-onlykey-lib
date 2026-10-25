'use strict';

/**
 * THE CRYPTOBOX STORE (onlykey-edge/features/CRYPTOBOX-SPEC.md).
 *
 * Messages kept in the app, chat-style, one thread per person (Brad, 2026-10-18: "i want to store
 * messages in the app, i dont want to store decrypted or unsigned data ... a list of contacts i
 * created encrypted messages for ... a pre-design to a messenger chat").
 *
 * WHAT MAY BE STORED is decided here, on every write, not by the screen: an armored PGP MESSAGE
 * (encrypted) or an armored PGP SIGNED MESSAGE (signed in the clear). Anything else - a decrypted
 * text, an unsigned note, a key - is refused with a reason. Opening a message is the host's job and
 * its result is never written back.
 *
 * One versioned JSON blob, `cryptobox:v1`, through the storage the host passes in (AsyncStorage in
 * ok-rn, a memory store in tests). A thread is the messages that share a `contact` id - a Guest
 * Book contact's id, or `me` for messages to yourself. A blob that does not read is kept aside
 * under `cryptobox:v1:damaged:<time>` and the list starts empty, and load() says so.
 */

const { toHex } = require('../../src/bytes');
const { refusePrivate } = require('../../src/crypto/public-only');

const KEY = 'cryptobox:v1';
const VERSION = 1;
const HOLDER = 'Cryptobox';
const DIRECTIONS = ['out', 'in'];
/* an X-Wing-sized composite message to several people is tens of KB; a file is not a chat message */
const ARMORED_MAX = 512 * 1024;
const MESSAGES_MAX = 5000;
const CONTACT_MAX = 64;

const ENCRYPTED = /^-----BEGIN PGP MESSAGE-----\r?\n[\s\S]*\r?\n-----END PGP MESSAGE-----\s*$/;
const SIGNED = /^-----BEGIN PGP SIGNED MESSAGE-----\r?\n[\s\S]*\r?\n-----BEGIN PGP SIGNATURE-----\r?\n[\s\S]*\r?\n-----END PGP SIGNATURE-----\s*$/;

/**
 * What an armored block is, for the store: 'encrypted', 'signed', or a thrown reason. One block
 * only - two messages pasted together are two messages, imported one at a time.
 * @param {string} armored
 * @returns {'encrypted'|'signed'}
 */
function kindOf(armored) {
  const t = String(armored == null ? '' : armored).trim();
  if (!t) throw new Error('Cryptobox stores PGP messages; this is empty.');
  if (t.length > ARMORED_MAX) throw new Error(`Cryptobox keeps messages up to ${ARMORED_MAX / 1024} KB; this one is ${Math.ceil(t.length / 1024)} KB.`);
  const begins = (t.match(/-----BEGIN PGP /g) || []).length;
  if (ENCRYPTED.test(t) && begins === 1) return 'encrypted';
  if (SIGNED.test(t) && begins === 2) return 'signed';
  throw new Error('Cryptobox stores only encrypted or signed PGP messages - never a decrypted or unsigned text.');
}

/** @typedef {{id: string, contact: string, dir: 'out'|'in', armored: string, kind: 'encrypted'|'signed', signed: boolean, at: string, archived?: true, archivedAt?: string}} BoxMessage */

function shapeMessage(m) {
  if (!m || typeof m !== 'object') throw new Error('not a message');
  const contact = String(m.contact || '').slice(0, CONTACT_MAX);
  if (!contact) throw new Error('a message belongs to a thread (contact)');
  if (!DIRECTIONS.includes(m.dir)) throw new Error(`a message is 'out' or 'in', not ${m.dir}`);
  const armored = String(m.armored).trim();
  const kind = kindOf(armored);
  return {
    id: String(m.id || ''),
    contact,
    dir: m.dir,
    armored,
    kind,
    /* a signed-in-the-clear message is signed by what it is; an encrypted one says whether it carried a signature */
    signed: kind === 'signed' ? true : !!m.signed,
    at: String(m.at || ''),
    /* removed: kept, archived - a removal syncs as one, and a sync never brings the message back (bucket rules) */
    ...(m.archived ? { archived: true, archivedAt: String(m.archivedAt || '') } : {}),
  };
}

/**
 * The Cryptobox over a key-value storage.
 * @param {{storage: {getItem(k: string): Promise<string|null>, setItem(k: string, v: string): Promise<void>}, randomBytes: (n: number) => Uint8Array, now?: () => Date, key?: string}} deps - key: the storage key (a host keeps a test list apart under another)
 */
function createCryptobox({ storage, randomBytes, now = () => new Date(), key = KEY }) {
  const stamp = () => now().toISOString();
  const newId = () => toHex(randomBytes(16));

  /*
   * EVERY MESSAGE, REMOVED ONES TOO (Brad, 2026-10-25: "stuff never gets deleted, just flagged as archived"). The list
   * syncs between devices (the bucket's cryptobox rule joins both sides' messages by id): a message dropped here would
   * come back from the other side, so a removal is a flag the other side takes in too.
   */
  async function readAll() {
    const raw = await storage.getItem(key);
    if (!raw) return { all: [], recovered: false };
    try {
      const blob = JSON.parse(raw);
      if (!blob || blob.v !== VERSION || !Array.isArray(blob.messages)) throw new Error('not a cryptobox v1 blob');
      return { all: blob.messages.map(shapeMessage), recovered: false };
    } catch (e) {
      await storage.setItem(`${key}:damaged:${stamp()}`, raw);
      await storage.setItem(key, JSON.stringify({ v: VERSION, messages: [] }));
      return { all: [], recovered: true, reason: String(e.message || e) };
    }
  }

  async function writeAll(all) {
    const shaped = all.map(shapeMessage);
    if (shaped.filter((m) => !m.archived).length > MESSAGES_MAX) throw new Error(`Cryptobox keeps up to ${MESSAGES_MAX} messages; delete some first.`);
    refusePrivate(shaped, 'messages', HOLDER);
    await storage.setItem(key, JSON.stringify({ v: VERSION, messages: shaped }));
    return shaped;
  }

  /** The messages (removed ones are not among them). @returns {Promise<{messages: BoxMessage[], recovered: boolean, reason?: string}>} */
  async function load() {
    const { all, recovered, reason } = await readAll();
    return { messages: all.filter((m) => !m.archived), recovered, ...(reason ? { reason } : {}) };
  }

  /** Write the messages as given; the removed ones already kept stay kept. */
  async function save(messages) {
    const { all } = await readAll();
    const given = new Set(messages.map((m) => m.id));
    const shaped = await writeAll([...messages, ...all.filter((m) => m.archived && !given.has(m.id))]);
    return shaped.filter((m) => !m.archived);
  }

  /**
   * Keep one message (refused unless it is an encrypted or signed PGP block).
   * @param {{contact: string, dir: 'out'|'in', armored: string, signed?: boolean}} m
   * @returns {Promise<BoxMessage>}
   */
  async function add(m) {
    const msg = shapeMessage({ ...m, id: newId(), at: stamp() });
    const { all } = await readAll();
    await writeAll([...all, msg]);
    return msg;
  }

  const live = (all) => all.filter((m) => !m.archived);

  /* removed: archived, kept (readAll) */
  async function remove(id) {
    const { all } = await readAll();
    return live(await writeAll(all.map((m) => (m.id === id && !m.archived ? { ...m, archived: true, archivedAt: stamp() } : m))));
  }

  async function removeThread(contact) {
    const { all } = await readAll();
    return live(await writeAll(all.map((m) => (m.contact === contact && !m.archived ? { ...m, archived: true, archivedAt: stamp() } : m))));
  }

  /** Move a thread's messages to another contact id (a contact merged or re-made in Guest Book). */
  async function moveThread(from, to) {
    const { all } = await readAll();
    return live(await writeAll(all.map((m) => (m.contact === from ? { ...m, contact: to } : m))));
  }

  return { KEY: key, load, save, add, remove, removeThread, moveThread };
}

/**
 * The threads, newest first: who, how many, the last message.
 * @param {BoxMessage[]} messages
 * @returns {{contact: string, count: number, last: BoxMessage}[]}
 */
function threads(messages) {
  const by = new Map();
  for (const m of messages) {
    const t = by.get(m.contact);
    if (!t) by.set(m.contact, { contact: m.contact, count: 1, last: m });
    else {
      t.count += 1;
      if (m.at >= t.last.at) t.last = m;
    }
  }
  return [...by.values()].sort((a, b) => (a.last.at < b.last.at ? 1 : a.last.at > b.last.at ? -1 : 0));
}

module.exports = { KEY, VERSION, ARMORED_MAX, MESSAGES_MAX, kindOf, shapeMessage, createCryptobox, threads };
