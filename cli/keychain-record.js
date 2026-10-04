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
 * The file is ~/.onlykey-js/keychain.json (ONLYKEY_KEYCHAIN moves it), in the
 * phone's own export format (src/keychain/list.js), so merging with the phone
 * is the existing import - no sync. Public data only: list.createEntry refuses
 * anything private. Written owner-only (0600, in a 0700 directory).
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
const os = require('os');
const path = require('path');
const list = require('../src/keychain/list');
const { toHex } = require('../src/bytes');

/* okcrypto.agent keyType -> the list's type */
const TYPE_OF_KEYTYPE = { 1: 'ed25519', 2: 'p256', 3: 'secp256k1', 4: 'x25519' };
/* okcrypto.derivePublicKey keytype -> the list's type (src/keychain/derive.js LABEL_TYPES) */
const LABEL_TYPE_OF_KEYTYPE = { 1: 'p256', 2: 'secp256k1', 3: 'x25519' };

function keychainFile() {
  return process.env.ONLYKEY_KEYCHAIN ? path.resolve(process.env.ONLYKEY_KEYCHAIN) : path.join(os.homedir(), '.onlykey-js', 'keychain.json');
}

function load(file = keychainFile()) {
  if (!fs.existsSync(file)) return [];
  return list.parse(fs.readFileSync(file, 'utf8'));
}

function save(entries, file = keychainFile()) {
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
    return { scheme: 'ssh', label: `ssh://${user ? `${user}@` : ''}${host}` };
  }
  if (identity && typeof identity.gpg === 'string') return { scheme: 'gpg', label: `gpg://${identity.gpg}` };
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
    if (okc && okc.agent && typeof okc.agent.publicKey === 'function') {
      const derive = okc.agent.publicKey.bind(okc.agent);
      okc.agent.publicKey = async (identity, o = {}) => {
        const raw = await derive(identity, o);
        const name = identityName(identity);
        const type = TYPE_OF_KEYTYPE[o.keyType || 1];
        if (name && type) note({ ...name, type, publicKey: raw, code: (o.version === 2 ? 232 : 132) });
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
        if (pub && type && typeof label === 'string') note({ scheme: 'label', label, type, publicKey: pub, code: o.keytype });
        return r;
      };
    }
    return app;
  };
}

module.exports = { keychainFile, load, save, record, recordingStart, identityName };
