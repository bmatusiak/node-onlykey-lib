'use strict';

/**
 * THE BUCKET (PROPOSAL-one-gui.md; Brad, 2026-10-21): one portable file that holds everything a
 * front end keeps for its person - the Key Chain list, the Guest Book, password entries, the Edge
 * copy, the computer's Bluetooth pairings, settings - and moves between the phone, the desktop app,
 * the web page and the CLI. "the web will ask for a bucket, from the computer we upload the backup
 * with drag and drop, and download bucket ... so the bucket is transferable."
 *
 * WHAT A BUCKET MAY HOLD (Brad, 2026-10-25: "the buckets should not carry actual secrets or decrypted
 * messages - those take a press on their own; it does keep the labels for those secrets, for their
 * encrypted form, so they can be identified by the user"). A store keeps public things (keys, contacts)
 * and LABELS beside the encrypted form of each secret - a password entry's site beside its sealed blob, an
 * armored PGP message - never the secret or a decrypted text: opening one is its own press, every time. So
 * an opened bucket on a computer (bucket/cli/home.js identity buckets) shows which keys and sites there
 * are, and nothing more. Sealing the bucket to the key when it travels ("decrypting with the key protects
 * the privacy of those labels") is what keeps even the labels to the person. A new store follows this, or
 * it does not belong in the bucket. (A PGP SIGNED message is the one readable text a store keeps: it was
 * never encrypted - cryptobox/src/store.js.)
 *
 * One bucket, many stores. Each store is what one feature already keeps through the storage seam
 * every lib store takes - {getItem, setItem, removeItem} (vault_store, edge's pointer store, the
 * Guest Book, Cryptobox, Passwords) - so a feature does not know it lives in a bucket. kv() hands a
 * store that seam over its own part of the bucket.
 *
 * EVERY KEY REMEMBERS WHEN IT CHANGED. Two copies of a bucket meet when one is imported into
 * another, and Brad's rule for a value both changed is to ask, "with the dates displayed to give
 * the user the best option to decide". A removed key stays as a marker with its date, so a merge
 * can tell "removed here" from "never had it" - without it a deletion would come back from the
 * other copy every time.
 *
 * SEALED BY THE KEY (Brad: "seals allow us to make sure the key owns the bucket"). The whole bucket
 * is AES-256-GCM sealed (src/crypto/vault.js) under a key the OnlyKey derives - the host passes it
 * in, from okcrypto.deviceVault.key('bucket'). A bucket from another key does not open, and says
 * so. "development is unsealed": an unsealed bucket opens only where the host allows it, and a
 * production host does not, or a planted unsealed bucket would be read as the person's own.
 *
 * Pure: no device, no Node built-ins - the same code runs in the app, the browser and the CLI.
 */

const vault = require('../../src/crypto/vault');

const FORMAT = 'onlykey-bucket';
const SEALED_FORMAT = 'onlykey-bucket-sealed';
const VERSION = 1;

const err = (code, message) => Object.assign(new Error(message), { code });
const iso = () => new Date().toISOString();

/**
 * A new, empty bucket.
 * @param {{owner?: string|null}} [opts] owner: who the bucket belongs to, as the host names it
 *   (the key's id) - two buckets merge only when it is the same
 * @returns {{format: string, v: number, owner: string|null, stores: Object<string, Object<string, {v: string|null, at: string}>>}}
 */
function create({ owner = null } = {}) {
  return { format: FORMAT, v: VERSION, owner, stores: {} };
}

/**
 * The storage seam for one store, over its part of the bucket.
 * @param {ReturnType<typeof create>} bucket
 * @param {string} name the store's name ('keychain', 'guestbook', 'settings', ...)
 * @param {{now?: () => string}} [opts]
 * @returns {{getItem: (key: string) => string|null, setItem: (key: string, value: string) => void, removeItem: (key: string) => void, keys: () => string[]}}
 */
function kv(bucket, name, { now = iso } = {}) {
  if (!name || typeof name !== 'string') throw new Error('a store needs a name');
  const store = () => {
    if (!bucket.stores[name]) bucket.stores[name] = {};
    return bucket.stores[name];
  };
  return {
    getItem(key) {
      const rec = (bucket.stores[name] || {})[key];
      return rec && rec.v !== null ? rec.v : null;
    },
    setItem(key, value) {
      const text = String(value);
      const rec = store()[key];
      /* an unchanged write keeps its date: the date is when it last CHANGED, which is what a merge shows */
      if (rec && rec.v === text) return;
      store()[key] = { v: text, at: now() };
    },
    removeItem(key) {
      const rec = store()[key];
      if (!rec || rec.v === null) return;
      store()[key] = { v: null, at: now() };
    },
    keys() {
      return Object.keys(bucket.stores[name] || {}).filter((k) => bucket.stores[name][k].v !== null);
    },
  };
}

/* JSON with its keys in order, so the same bucket is the same text */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/**
 * The bucket as text (unsealed).
 * @param {ReturnType<typeof create>} bucket
 * @returns {string}
 */
function serialize(bucket) {
  return canonical(bucket);
}

/**
 * Read an unsealed bucket's text, checking its shape.
 * @param {string} text
 * @returns {ReturnType<typeof create>}
 */
function parse(text) {
  let b;
  try {
    b = JSON.parse(String(text));
  } catch (e) {
    throw err('EBUCKET_FORMAT', `not a bucket: ${e.message}`);
  }
  if (!b || b.format !== FORMAT) throw err('EBUCKET_FORMAT', 'not a bucket (no "onlykey-bucket" format)');
  if (b.v !== VERSION) throw err('EBUCKET_VERSION', `bucket version ${b.v}; this build reads ${VERSION}`);
  if (!b.stores || typeof b.stores !== 'object') throw err('EBUCKET_FORMAT', 'a bucket without stores');
  for (const [name, store] of Object.entries(b.stores)) {
    for (const [key, rec] of Object.entries(store || {})) {
      if (!rec || typeof rec.at !== 'string' || (rec.v !== null && typeof rec.v !== 'string')) {
        throw err('EBUCKET_FORMAT', `store "${name}" key "${key}" is not {v, at}`);
      }
    }
  }
  return { format: FORMAT, v: VERSION, owner: b.owner ?? null, stores: b.stores };
}

/**
 * The bucket sealed under the key's bucket key - the file that travels.
 * @param {ReturnType<typeof create>} bucket
 * @param {Uint8Array} key 32 bytes, from okcrypto.deviceVault.key('bucket')
 * @param {(n: number) => Uint8Array} randomBytes
 * @returns {string}
 */
function seal(bucket, key, randomBytes) {
  return canonical({ format: SEALED_FORMAT, v: VERSION, owner: bucket.owner ?? null, blob: vault.seal(key, serialize(bucket), randomBytes) });
}

/*
 * SEALED TO THE KEY ITSELF (Brad, 2026-10-24: "the bucket encrypted ... that the hardkey can only decrypt"; "a
 * button press here is needed to decrypt the container"). The bucket becomes an age file to the key's own
 * X-Wing recipient for one label (okcrypto.deviceAge.identity(AGE_LABEL)): the same recipient on every device
 * restored from one backup, public - so any device can seal to it with no key at all - while only the key can
 * open it: it does the X-Wing decapsulation itself, and on 3.1.0 it asks for a press to do it.
 *
 * Kept free of the device: the caller hands in deviceAge's encrypt and decrypt. `owner` is the identity id
 * (the owner key's, edge identityId) - written outside for a refusal before any press, and inside, where it
 * counts.
 */
const AGE_FORMAT = 'onlykey-bucket-age';
const AGE_LABEL = 'onlykey-bucket';
const { toBase64: toB64, fromBase64: fromB64 } = require('../../src/bytes');


/**
 * Seal a bucket to the key's X-Wing recipient - no device involved.
 * @param {ReturnType<typeof create>} bucket
 * @param {Uint8Array|string} recipient okcrypto.deviceAge.identity(AGE_LABEL).recipient
 * @param {(plaintext: Uint8Array, recipient: Uint8Array|string) => Uint8Array} encrypt okcrypto.deviceAge.encrypt
 * @returns {string}
 */
function sealToKey(bucket, recipient, encrypt) {
  const plain = new TextEncoder().encode(serialize(bucket));
  return canonical({ format: AGE_FORMAT, v: VERSION, owner: bucket.owner ?? null, label: AGE_LABEL, age: toB64(encrypt(plain, recipient)) });
}

/**
 * Open a bucket sealed to the key: the key decapsulates (a press on 3.1.0). A bucket of another identity is
 * refused before the key is asked; one that does not open is never read some other way.
 * @param {string} text
 * @param {{decrypt: (age: Uint8Array, label: string) => Promise<Uint8Array>, owner?: string|null}} o
 *   decrypt: okcrypto.deviceAge.decrypt (with the caller's confirm); owner: the identity id expected
 * @returns {Promise<{bucket: ReturnType<typeof create>, sealed: true}>}
 */
async function openWithKey(text, { decrypt, owner = null }) {
  let outer;
  try {
    outer = JSON.parse(String(text));
  } catch (e) {
    throw err('EBUCKET_FORMAT', `not a bucket: ${e.message}`);
  }
  if (!outer || outer.format !== AGE_FORMAT) throw err('EBUCKET_FORMAT', 'not a bucket sealed to a key');
  if (owner !== null && (outer.owner ?? null) !== owner) throw err('EBUCKET_NOT_YOURS', 'this bucket belongs to another identity - its key is not this one');
  let inner;
  try {
    inner = new TextDecoder().decode(await decrypt(fromB64(outer.age), outer.label || AGE_LABEL));
  } catch (e) {
    throw Object.assign(err('EBUCKET_NOT_OPENED', `the key did not open this bucket: ${e && e.message}`), { cause: e });
  }
  const bucket = parse(inner);
  if ((outer.owner ?? null) !== (bucket.owner ?? null)) throw err('EBUCKET_FORMAT', 'the owner outside the seal does not match the one inside');
  return { bucket, sealed: true };
}

/**
 * Open a bucket file, sealed or not.
 *
 * Sealed: opened with the key; one that does not open was sealed by another key (or is damaged) -
 * it is never read some other way. Unsealed: only where the host allows it (development builds).
 * @param {string} text
 * @param {{key?: Uint8Array|null, allowUnsealed?: boolean}} [opts]
 * @returns {{bucket: ReturnType<typeof create>, sealed: boolean}}
 */
function open(text, { key = null, allowUnsealed = false } = {}) {
  let outer;
  try {
    outer = JSON.parse(String(text));
  } catch (e) {
    throw err('EBUCKET_FORMAT', `not a bucket: ${e.message}`);
  }
  if (outer && outer.format === SEALED_FORMAT) {
    if (!key) throw err('EBUCKET_KEY', 'this bucket is sealed: it opens with its OnlyKey');
    let inner;
    try {
      inner = vault.open(key, outer.blob);
    } catch (_) {
      throw err('EBUCKET_NOT_YOURS', 'this bucket does not open with this key - it was sealed by another OnlyKey, or the file is damaged');
    }
    const bucket = parse(inner);
    /* the owner written outside is a label only; the one inside the seal is the one that counts */
    if ((outer.owner ?? null) !== (bucket.owner ?? null)) throw err('EBUCKET_FORMAT', 'the owner outside the seal does not match the one inside');
    return { bucket, sealed: true };
  }
  if (outer && outer.format === FORMAT) {
    if (!allowUnsealed) throw err('EBUCKET_UNSEALED', 'an unsealed bucket opens only in a development build');
    return { bucket: parse(text), sealed: false };
  }
  throw err('EBUCKET_FORMAT', 'not a bucket');
}

/**
 * The generic merge for one store: key by key. A key only one side has is taken; the same value is
 * kept; two different values (a removal counts as a value) are a CONFLICT - both kept in the report
 * with their dates, `into`'s value stays until the person picks (resolve()).
 * @param {Object<string, {v: string|null, at: string}>} into
 * @param {Object<string, {v: string|null, at: string}>} from
 * @returns {{store: Object<string, {v: string|null, at: string}>, taken: number, conflicts: Array<{key: string, into: {v: string|null, at: string}, from: {v: string|null, at: string}}>}}
 */
function mergeKeys(into = {}, from = {}) {
  const store = { ...into };
  const conflicts = [];
  let taken = 0;
  for (const [key, rec] of Object.entries(from)) {
    const have = into[key];
    if (!have) {
      store[key] = { ...rec };
      taken += 1;
    } else if (have.v !== rec.v) {
      conflicts.push({ key, into: { ...have }, from: { ...rec } });
    }
  }
  return { store, taken, conflicts };
}

/**
 * Import one bucket into another. Each store merges by its own rule (rules[name]), or key by key;
 * nothing is dropped - what could not be merged comes back in the report, for the person to pick.
 * Buckets of different owners do not merge.
 * @param {ReturnType<typeof create>} into
 * @param {ReturnType<typeof create>} from
 * @param {{rules?: Object<string, typeof mergeKeys>}} [opts]
 * @returns {{bucket: ReturnType<typeof create>, report: {taken: Object<string, number>, conflicts: Array<{store: string, key: string, into: {v: string|null, at: string}, from: {v: string|null, at: string}}>}}}
 */
function merge(into, from, { rules = {} } = {}) {
  if ((into.owner ?? null) !== (from.owner ?? null)) {
    throw err('EBUCKET_OWNER', 'these buckets belong to different keys - they do not merge');
  }
  const bucket = { format: FORMAT, v: VERSION, owner: into.owner ?? null, stores: {} };
  const report = { taken: {}, conflicts: [] };
  const names = new Set([...Object.keys(into.stores), ...Object.keys(from.stores)]);
  for (const name of [...names].sort()) {
    const rule = rules[name] || mergeKeys;
    const r = rule(into.stores[name] || {}, from.stores[name] || {});
    bucket.stores[name] = r.store;
    report.taken[name] = r.taken;
    for (const c of r.conflicts) report.conflicts.push({ store: name, ...c });
  }
  return { bucket, report };
}

/**
 * The person's pick for one conflict: 'into' keeps what is there, 'from' takes the other copy's
 * value and date.
 * @param {ReturnType<typeof create>} bucket
 * @param {{store: string, key: string, into: {v: string|null, at: string}, from: {v: string|null, at: string}}} conflict
 * @param {'into'|'from'} side
 */
function resolve(bucket, conflict, side) {
  if (side !== 'into' && side !== 'from') throw new Error("pick 'into' or 'from'");
  if (!bucket.stores[conflict.store]) bucket.stores[conflict.store] = {};
  /* a conflict inside one value (a contact in the Guest Book's blob) brings its own way to apply the pick */
  if (typeof conflict.apply === 'function') {
    conflict.apply(bucket.stores[conflict.store], side);
    return;
  }
  bucket.stores[conflict.store][conflict.key] = { ...conflict[side] };
}

module.exports = { FORMAT, SEALED_FORMAT, AGE_FORMAT, AGE_LABEL, VERSION, create, kv, serialize, parse, seal, open, sealToKey, openWithKey, mergeKeys, merge, resolve };
