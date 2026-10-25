'use strict';

/**
 * cli/keychain-record.js - every derived public key this CLI makes is written
 * into the host's Key Chain list (spec session, 2026-10-03: Brad's idea).
 *
 * Why: a derived key is never stored anywhere - the OnlyKey re-derives it from
 * its label each time - so nothing remembered which labels this machine had
 * used, which tool used them, or what their public keys were. Agents and
 * scripts need to look that up (`onlykey-js keychain list --json`), and the
 * person needs to see it next to the phone's list.
 *
 * The list lives in the CLI's bucket (bucket/cli/home.js): the 'keychain' store, key 'list'
 * ('keychain-test' for the testnet), in the phone's own export format
 * (src/keychain/list.js), so merging with the phone is the existing import - no sync.
 * ONLYKEY_KEYCHAIN (or setFile with a path) names a plain list file instead. Public
 * data only: list.createEntry refuses anything private. Written owner-only (0600, in
 * a 0700 directory).
 *
 * "Yours" - the own-identities mark that drives the phone's red warning - is
 * NEVER set or cleared here: it is the phone's, set and removed only there,
 * with its confirm. list.createEntry drops the field from every entry, so a
 * recorded or imported entry cannot carry it.
 *
 * Recording never fails a command: the derivation is what the person asked
 * for; a list that cannot be written is reported once on stderr.
 */
const fs = require('fs');
const path = require('path');
const list = require('../src/list');
const bucketHome = require('../../bucket/cli/home');
const bucketLib = require('../../bucket/src/bucket');
const { toHex } = require('../../src/bytes');

/* okcrypto.agent keyType -> the list's type */
const TYPE_OF_KEYTYPE = { 1: 'ed25519', 2: 'p256', 3: 'secp256k1', 4: 'x25519' };
/* okcrypto.derivePublicKey keytype -> the list's type (src/keychain/derive.js LABEL_TYPES) */
const LABEL_TYPE_OF_KEYTYPE = { 1: 'p256', 2: 'secp256k1', 3: 'x25519' };

/*
 * The testnet's list is its own (onlykey-js edge --test-mode; BLOCKS.md): its soft
 * key is another key with other keys, so its entries never land in the live list.
 */
/*
 * WHERE THE LIST IS: a bucket store (the default) or a plain list file (a path: ONLYKEY_KEYCHAIN,
 * or setFile with one - a test's scratch list). A bucket store prints as the bucket and the store,
 * so messages that name where the list is stay readable.
 */
let fileOverride = null;
function setFile(file) {
  fileOverride = !file ? null : typeof file === 'string' ? path.resolve(file) : file;
  identity = null;
}

/*
 * IN THE IDENTITY'S BUCKET (ok-edge plan S2; Brad, 2026-10-24: "cli and desktop decrypt once, share same bucket
 * stored in filesystem"). The list is the user's own data, kept in the bucket of the key's BUCKET IDENTITY (its ""
 * agent key, bucket/src/bucket-identity.js - not Edge's identity) that this computer keeps opened (bucket/cli/home.js
 * identityFile) - the same file the desktop app reads and writes. Which one: the key a device command talks to
 * (recordingStart reads it from the key), or the one picked with keychain --identity; with neither, the one bucket
 * identity this computer keeps on that net. A computer that keeps none yet keeps the list in bucket.json, as before.
 */
let identity = null;
/** The identity this run's list belongs to (an id, or its first characters as keychain --identity takes them). */
function setIdentity(id) { identity = id ? String(id).toLowerCase() : null; }

const netOf = (store) => (store === 'keychain-test' ? 'test' : 'live');

function inIdentity(id, store) {
  const net = netOf(store);
  if (!bucketHome.hasIdentityBucket(id, net)) bucketHome.keepIdentityBucket(id, net, bucketLib.create({ owner: id }));
  const at = bucketHome.identityAt(id, net, store);
  /*
   * The list this computer kept before identities moves into the first identity's bucket used here - whoever made
   * that bucket (the desktop's identity check, or this) - merged with what it holds (entries by id, twins joined,
   * nothing dropped), stored first, then removed from bucket.json (the phone's rule too).
   */
  const before = bucketHome.kv(bucketHome.at(store));
  const old = before.getItem('list');
  if (old !== null) {
    const now = bucketHome.kv(at).getItem('list');
    bucketHome.kv(at).setItem('list', now === null ? old : list.serialize(list.merge(list.parse(now), list.parse(old)).entries));
    before.removeItem('list');
  }
  return { ...at, toString: () => `${at.file} (${store})` };
}

function inBucket(store) {
  const kept = bucketHome.keptIdentities(netOf(store));
  if (identity) {
    /* keychain --identity takes an id's first characters, as the lists print it */
    const picked = kept.filter((k) => k.startsWith(identity));
    if (identity.length < 32 && picked.length !== 1) {
      throw new Error(picked.length ? `--identity ${identity} matches more than one kept identity` : `no identity ${identity} is kept on this computer`);
    }
    return inIdentity(identity.length < 32 ? picked[0] : identity, store);
  }
  if (kept.length === 1) return inIdentity(kept[0], store);
  if (kept.length > 1) {
    throw new Error(`more than one identity keeps its bucket on this computer (${kept.map((k) => k.slice(0, 12)).join(', ')}) - pick one with --identity <id>`);
  }
  const at = bucketHome.at(store);
  return { ...at, toString: () => `${at.file} (${store})` };
}
/** The testnet's Key Chain: edge --test-mode records here, keychain --test-mode reads it. Resolved when used. */
function testFile() { return { store: 'keychain-test' }; }

function keychainFile() {
  if (fileOverride && fileOverride.store && !fileOverride.file) return inBucket(fileOverride.store);
  if (fileOverride) return fileOverride;
  return process.env.ONLYKEY_KEYCHAIN ? path.resolve(process.env.ONLYKEY_KEYCHAIN) : inBucket('keychain');
}

function load(file = keychainFile()) {
  if (typeof file !== 'string') {
    const text = bucketHome.kv(file).getItem('list');
    return text ? list.parse(text) : [];
  }
  if (!fs.existsSync(file)) return [];
  return list.parse(fs.readFileSync(file, 'utf8'));
}

function save(entries, file = keychainFile()) {
  if (typeof file !== 'string') {
    bucketHome.kv(file).setItem('list', list.serialize(entries));
    return;
  }
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, list.serialize(entries), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/**
 * Record one derived public key: added the first time, `lastSeen` and `tools`
 * updated after that (the same id = the same key from the same label).
 * @param {{scheme: string, label: string, type: string, publicKey: Uint8Array|string, code?: number, tool?: string}} fields
 * @returns {object} the entry as stored
 */
function record(fields, { file = keychainFile(), now = new Date().toISOString() } = {}) {
  const { tool, ...rest } = fields;
  const e = list.createEntry({ kind: 'derived', ...rest, firstSeen: now, lastSeen: now, tools: tool ? [tool] : [] });
  e.fingerprint = list.fingerprint(e.publicKey);
  let entries = load(file);
  /* the same key already here under its other name (a phone's hash:…): one entry, under the name */
  const twin = entries.find((x) => x.id === e.id) ? null : list.findTwin(entries, e);
  if (twin) {
    const one = list.combine(twin, e);
    entries = entries.filter((x) => x !== twin).concat(one);
    save(entries, file);
    return one;
  }
  const old = entries.find((x) => x.id === e.id);
  if (old) {
    old.lastSeen = now;
    old.tools = [...new Set([...(old.tools || []), ...e.tools])];
    if (!old.fingerprint) old.fingerprint = e.fingerprint;
    /* keychain cert: a new certificate (or renewal) and a revocation replace the saved ones - public blocks only (createEntry checked them) */
    for (const k of ['pgp', 'pgpFingerprint', 'certCreated', 'certExpires', 'revocation']) if (e[k] !== undefined) old[k] = e[k];
  } else {
    entries.push(e);
  }
  save(entries, file);
  return old || e;
}

/* ssh://user@host, gpg://uid - the same names the agent and Edge use (R11a) */
function identityName(identity) {
  if (identity instanceof Uint8Array) return { scheme: 'hash', label: toHex(identity) };
  if (identity && identity.ssh) {
    const { user, host } = identity.ssh;
    return { scheme: 'ssh', label: `${user ? `${user}@` : ''}${host}` };
  }
  /*
   * The scheme and the bare name, as the phone and keychain/src/derive.js file
   * them (Brad, 2026-10-21: one spelling): the label is what the key hashes
   * (labelHashOf), so "gpg://<uid>" in it would name a key the phone can never
   * match. derive.identityName gives the full gpg:// / ssh:// name to show.
   */
  if (identity && typeof identity.gpg === 'string') return { scheme: 'gpg', label: identity.gpg };
  return null;
}

/**
 * Wrap a CLI `start` so every okcrypto.agent.publicKey it makes is recorded,
 * whichever command made it (agent, gpg-agent, edge-agent, keychain derive).
 * @param {(opts: object) => Promise<object>} start
 * @param {{tool: string, err?: (line: string) => void, recordFn?: typeof record}} o
 */
function recordingStart(start, { tool, err = () => {}, recordFn = record }) {
  let warned = false;
  const note = (fields) => {
    try {
      recordFn({ ...fields, tool });
    } catch (e) {
      if (!warned) err(`keychain: could not record a derived key (${e.message})`);
      warned = true;
    }
  };
  return async (opts) => {
    const app = await start(opts);
    const okc = app && app.services && app.services.okcrypto;
    /* the agent's own derive, before it is wrapped below: reading the bucket identity is not a derive to record */
    const derive = okc && okc.agent && typeof okc.agent.publicKey === 'function' ? okc.agent.publicKey.bind(okc.agent) : null;
    /*
     * WHOSE LIST: the key's BUCKET IDENTITY (its "" agent key, bucket/src/bucket-identity.js - every OnlyKey since
     * 2.1.0, Edge or not), read once per run, the first time something is recorded (after the derive, so a command's
     * own exchange is never interrupted). The owner moved once from the Edge identity (Brad, 2026-10-25): a bucket
     * this computer kept under the key's Edge identity id moves to the bucket identity id here.
     */
    let learned = null;
    const learn = () => {
      if (!learned) {
        learned = (async () => {
          if (identity || !derive) return;
          const bucketId = (await require('../../bucket/src/bucket-identity').readIdentity({ agent: { publicKey: derive } })).id;
          try {
            if (app.edge && typeof app.edge.identityId === 'function'
              && (typeof app.edge.probe !== 'function' || (await app.edge.probe({ timeoutMs: 4000 })) === 'edge')) {
              const edgeId = await app.edge.identityId();
              for (const net of ['live', 'test']) bucketHome.moveIdentityBucket(edgeId, bucketId, net);
            }
          } catch { /* no Edge to move from */ }
          setIdentity(bucketId);
        })().catch(() => {});
      }
      return learned;
    };
    if (derive) {
      okc.agent.publicKey = async (identity, o = {}) => {
        const raw = await derive(identity, o);
        const name = identityName(identity);
        const type = TYPE_OF_KEYTYPE[o.keyType || 1];
        if (name && type) { await learn(); note({ ...name, type, publicKey: raw, code: (o.version === 2 ? 232 : 132) }); }
        return raw;
      };
    }
    /* the label scheme (keychain derive label, the web page's derive): okcrypto.derivePublicKey */
    if (okc && typeof okc.derivePublicKey === 'function') {
      const deriveLabel = okc.derivePublicKey.bind(okc);
      okc.derivePublicKey = async (label, o = {}) => {
        const r = await deriveLabel(label, o);
        const type = LABEL_TYPE_OF_KEYTYPE[o.keytype];
        let pub = r && r.publicKey ? Uint8Array.from(r.publicKey) : null;
        if (pub && pub.length === 65 && (type === 'p256' || type === 'secp256k1')) pub = pub.slice(1); /* X||Y, as the slots */
        if (pub && type && typeof label === 'string') { await learn(); note({ scheme: 'label', label, type, publicKey: pub, code: o.keytype }); }
        return r;
      };
    }
    return app;
  };
}

module.exports = { keychainFile, setFile, setIdentity, testFile, load, save, record, recordingStart, identityName };
