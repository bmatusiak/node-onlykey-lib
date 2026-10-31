/**
 * THE CLI'S BUCKET (ok-edge stage 3): what onlykey-js keeps about its keys, in one file -
 * ~/.onlykey-js/bucket.json - instead of a file per feature. The same bucket every front end keeps
 * (bucket/src/bucket.js, PROPOSAL-one-gui.md), so `onlykey-js bucket export` hands a phone or a
 * desktop exactly what the CLI knows.
 *
 * PLAIN ON THIS DISK, SEALED WHEN IT TRAVELS (Brad, 2026-10-21): the working bucket is the CLI's
 * own state on its own disk, with the protection the separate files had; `bucket export` seals it
 * with the key and `bucket import` opens a sealed one with the key. So an everyday command needs no
 * derive and no press to read its own state.
 *
 * WHAT IS NOT HERE: machine files stay files - the Edge homes' control.key, peer.key and agent.key (private keys), agent-gpg.asc
 * and the GnuPG home.
 *
 * Stores (one per net, the testnet's beside the live one; Edge's per identity - edgeAt):
 *   keychain / keychain-test           key 'list': the Key Chain list (keychain/src/list.js text)
 *   edge[-test].<id>.copies            key: device id (16 hex): its copy (edge/src/copyfile.js JSON)
 *   edge[-test].<id>.budgets           key: device id + budget id: the budget this computer asked for (JSON)
 *   edge[-test].<id>.pointers          key: as edge/src/store.js names them: one pointer per key
 *   edge[-test].<id>.identity          key 'record': the agent identity this computer keeps for a hard key
 *   (<id>: the key's identity, edge/src/identity-id.js. The net-only edge.copies / .budgets / .pointers /
 *   .identity are the records from before identities - kept until moved, B3.0.)
 *
 * ONE WRITER AT A TIME: `edge agent` and a command run side by side, and a whole-file write from
 * each would drop the other's change. Every write is read-modify-write under a lock file, the
 * bucket read again inside the lock; the file is replaced by a rename, so a reader sees the old
 * bucket or the new one, never half of one.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const bucket = require('../src/bucket');

const FILE = 'bucket.json';
const LOCK_WAIT_MS = 10000;
/* a lock older than this was left by a process that died holding it */
const LOCK_STALE_MS = 30000;

/* this computer's CLI folder; a test points it at a scratch home */
let rootOverride = null;
function setRoot(dir) { rootOverride = dir ? path.resolve(dir) : null; movedFrom.clear(); }
function root() { return rootOverride || path.join(os.homedir(), '.onlykey-js'); }

/**
 * Where an Edge home's state lives. The two default homes share the CLI's bucket, the net naming
 * the stores; any other home (a test's scratch home, a second agent - --edge-home) keeps a bucket
 * of its own inside it, so it never touches this computer's.
 * @param {string} home an Edge home folder
 * @param {string} name 'copies' | 'budgets' | 'pointers'
 * @returns {{file: string, store: string}}
 */
function edgeAt(home, name) {
  const h = path.resolve(home);
  /*
   * AN IDENTITY'S HOME (ok-edge B3.0; Brad, 2026-10-24: "one identity, one store"): <net home>/<identity
   * id>. Its stores are the net's with the identity in their name - edge.<id>.copies, edge-test.<id>.
   * budgets - in the same bucket file as the net's, so every piece of code that takes a home files under
   * the key's identity once it is handed that home, and two identities (a GitLab key and a GitHub key)
   * never meet in a store.
   */
  const { isIdentityId } = require('../../edge/src/identity-id');
  if (isIdentityId(path.basename(h))) {
    const id = path.basename(h);
    const net = path.dirname(h);
    if (net === path.join(root(), 'edge')) return { file: path.join(root(), FILE), store: `edge.${id}.${name}` };
    if (net === path.join(root(), 'edge-test')) return { file: path.join(root(), FILE), store: `edge-test.${id}.${name}` };
    return { file: path.join(net, FILE), store: `edge.${id}.${name}` };
  }
  if (h === path.join(root(), 'edge')) return { file: path.join(root(), FILE), store: `edge.${name}` };
  if (h === path.join(root(), 'edge-test')) return { file: path.join(root(), FILE), store: `edge-test.${name}` };
  moveHomeFiles(h);
  return { file: path.join(h, FILE), store: `edge.${name}` };
}

/** A store in this computer's bucket ('keychain', 'keychain-test', ...). */
function at(store) {
  return { file: path.join(root(), FILE), store };
}

const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

function lock(file) {
  const lockFile = `${file}.lock`;
  /* a computer's first write: the folder is made here, before its lock can be */
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const until = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      fs.closeSync(fs.openSync(lockFile, 'wx', 0o600));
      return () => { try { fs.unlinkSync(lockFile); } catch { /* gone */ } };
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      try {
        if (Date.now() - fs.statSync(lockFile).mtimeMs > LOCK_STALE_MS) { fs.unlinkSync(lockFile); continue; }
      } catch { continue; }
      if (Date.now() > until) throw new Error(`the bucket is locked by another onlykey-js (${lockFile}); if none is running, delete that file`);
      sleep(25);
    }
  }
}

function readFile(file) {
  if (!fs.existsSync(file)) return bucket.create();
  return bucket.open(fs.readFileSync(file, 'utf8'), { allowUnsealed: true }).bucket;
}

function writeFile(file, b) {
  writeText(file, `${bucket.serialize(b)}\n`);
}

function writeText(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  /* Windows: a reader holding the old file open makes the rename fail for a moment */
  for (let i = 0; ; i++) {
    try { fs.renameSync(tmp, file); return; } catch (e) {
      if (i >= 40 || (e.code !== 'EPERM' && e.code !== 'EACCES' && e.code !== 'EBUSY')) throw e;
      sleep(25);
    }
  }
}

/** The bucket in a file, as it is now. */
function read(file = path.join(root(), FILE)) {
  if (file === path.join(root(), FILE)) moveOldFiles();
  return readFile(file);
}

/** Change the bucket in a file: fn(bucket) runs on the bucket read inside the lock, then it is written. */
function update(file, fn) {
  if (file === path.join(root(), FILE)) moveOldFiles();
  const unlock = lock(file);
  try {
    const b = readFile(file);
    const out = fn(b);
    writeFile(file, b);
    return out;
  } finally {
    unlock();
  }
}

/**
 * The storage seam (getItem/setItem/removeItem/keys) for one store at a location: each read is
 * the file as it is now, each write a locked read-modify-write.
 * @param {{file: string, store: string}} where
 */
function kv(where) {
  return {
    getItem: (k) => bucket.kv(read(where.file), where.store).getItem(k),
    setItem: (k, v) => update(where.file, (b) => bucket.kv(b, where.store).setItem(k, v)),
    removeItem: (k) => update(where.file, (b) => bucket.kv(b, where.store).removeItem(k)),
    keys: () => bucket.kv(read(where.file), where.store).keys(),
    /* many keys in ONE locked read-modify-write (an Edge log is a dozen blocks; one file rewrite each was a dozen) */
    setMany: (entries) => update(where.file, (b) => { const s = bucket.kv(b, where.store); for (const [k, v] of Object.entries(entries)) s.setItem(k, v); }),
    /* every live key and its value, from one read */
    entries: () => { const s = bucket.kv(read(where.file), where.store); return Object.fromEntries(s.keys().map((k) => [k, s.getItem(k)])); },
  };
}

/*
 * THE IDENTITY BUCKETS (ok-edge plan S2; Brad, 2026-10-24: "cli and desktop decrypt once, share same bucket stored in
 * filesystem"; "the webapp has no way to save decrypted stuff, the desktop cli share the same file system"). The
 * user's own data - the Key Chain list, Guest Book, the crypto box, passwords - is one bucket per BUCKET IDENTITY (the
 * key's "" agent key, bucket/src/bucket-identity.js - not Edge's identity, a different thing). It
 * travels sealed to the key (bucket.sealToKey; the web app only ever holds it sealed), and the identity check on
 * the desktop opens it ONCE with the key's press and keeps it here, opened, for the desktop and the CLI alike:
 * buckets/<live|test>/<bucket identity id>.json, read and written as bucket.json is (kv, update: one writer at a time).
 * What it holds is public keys and blocks that are encrypted on their own (crypto box messages, password entries
 * under the vault's key), so this disk sees which keys and sites there are, never a secret.
 * The Edge records above (copies, budgets, pointers) are public, signed chain data and stay in bucket.json.
 */
function identityFile(identity, net = 'live') {
  const { isBucketIdentityId } = require('../src/bucket-identity');
  const id = String(identity).toLowerCase();
  /* a name that is not a bucket identity id never becomes a path (the desktop page hands it over IPC) */
  if (!isBucketIdentityId(id)) throw new Error('an identity bucket is named by a bucket identity id');
  return path.join(root(), 'buckets', net === 'test' ? 'test' : 'live', `${id}.json`);
}

/** One store of an identity's bucket, for kv(). */
function identityAt(identity, net, store) {
  return { file: identityFile(identity, net), store };
}

/** The identities whose bucket this computer keeps on a net. */
function keptIdentities(net = 'live') {
  const { isBucketIdentityId } = require('../src/bucket-identity');
  const dir = path.join(root(), 'buckets', net === 'test' ? 'test' : 'live');
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => f.endsWith('.json') && isBucketIdentityId(f.slice(0, -5))).map((f) => f.slice(0, -5)).sort();
}

/** Whether this computer already keeps the identity's bucket opened (decrypted once, by the key). */
function hasIdentityBucket(identity, net) {
  return fs.existsSync(identityFile(identity, net));
}

/**
 * THE OWNER CHANGED ONCE (Brad, 2026-10-25: the bucket identity - the key's "" agent key - owns the bucket, "nothing
 * to do with edge"): a bucket this computer kept under the key's Edge identity id moves to its bucket identity id,
 * its owner rewritten, the old file removed - only when the new one does not exist yet. -> whether it moved.
 */
function moveIdentityBucket(fromId, toId, net) {
  const from = identityFile(fromId, net);
  const to = identityFile(toId, net);
  if (from === to || !fs.existsSync(from)) return false;
  const unlock = lock(to);
  try {
    if (fs.existsSync(to)) return false;
    const b = readFile(from);
    b.owner = String(toId).toLowerCase();
    writeFile(to, b);
    fs.unlinkSync(from);
    return true;
  } finally {
    unlock();
  }
}

/**
 * Keep an identity's bucket, just opened by the key (or new), as this computer's. One already kept is not replaced
 * (another process kept it first): -> whether this one was kept.
 */
function keepIdentityBucket(identity, net, b) {
  const file = identityFile(identity, net);
  const unlock = lock(file);
  try {
    if (fs.existsSync(file)) return false;
    writeFile(file, b);
    return true;
  } finally {
    unlock();
  }
}

/** Empty stores, keeping a dated removal for every key so a later merge does not bring them back. */
function clear(file, stores) {
  update(file, (b) => {
    for (const s of stores) { const k = bucket.kv(b, s); for (const key of k.keys()) k.removeItem(key); }
  });
}

/*
 * THE ONE-TIME MOVE (Brad, 2026-10-21: "one-time move"). The first time this computer's bucket is
 * wanted and there is none, the files the CLI kept before are read into it ONCE, the bucket is
 * written, and each file read is renamed <name>.moved - kept, never read again: there is no
 * reader for the old files anywhere else. A file whose schema the CLI had already stopped reading
 * (a budgets or pointers file without v: 1, from before the 2026-10-07 clean start) is left as it
 * was. agent.json is not moved: the agent's host keeps its identity since 2026-10-20.
 */
const movedFrom = new Set();

/* one Edge home's files into a bucket: budgets and pointers (schema v1 only), every copy */
function moveNet(b, home, net, done) {
  if (!fs.existsSync(home)) return;
  const json = (f) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } };
  for (const [name, store] of [['budgets.json', 'budgets'], ['pointers.json', 'pointers']]) {
    const f = path.join(home, name);
    const all = fs.existsSync(f) ? json(f) : null;
    if (!all || all.v !== 1) continue;
    const k = bucket.kv(b, `${net}.${store}`);
    for (const [key, v] of Object.entries(all)) {
      if (key !== 'v') k.setItem(key, store === 'budgets' ? JSON.stringify(v) : String(v));
    }
    done.push(f);
  }
  for (const n of fs.readdirSync(home).filter((x) => /^copy-[0-9a-f]{16}\.json$/.test(x))) {
    const j = json(path.join(home, n));
    if (!j) continue;
    bucket.kv(b, `${net}.copies`).setItem(n.slice(5, 21), JSON.stringify(j));
    done.push(path.join(home, n));
  }
}

/* a bucket file that does not exist yet, made from the files fill() finds; each file read is renamed .moved */
function moveInto(file, fill) {
  if (movedFrom.has(file)) return;
  movedFrom.add(file);
  if (fs.existsSync(file) || !fs.existsSync(path.dirname(file))) return;
  const unlock = lock(file);
  try {
    if (fs.existsSync(file)) return;
    const b = bucket.create();
    const done = [];
    fill(b, done);
    if (!done.length) return;
    writeFile(file, b);
    for (const f of done) fs.renameSync(f, `${f}.moved`);
  } finally {
    unlock();
  }
}

/* this computer's CLI folder: the Key Chain lists and both default Edge homes */
function moveOldFiles() {
  const dir = root();
  moveInto(path.join(dir, FILE), (b, done) => {
    for (const [name, store] of [['keychain.json', 'keychain'], ['keychain-test.json', 'keychain-test']]) {
      const f = path.join(dir, name);
      if (!fs.existsSync(f)) continue;
      bucket.kv(b, store).setItem('list', fs.readFileSync(f, 'utf8'));
      done.push(f);
    }
    for (const net of ['edge', 'edge-test']) moveNet(b, path.join(dir, net), net, done);
  });
}

/* a home of its own (--edge-home): its files into its own bucket */
function moveHomeFiles(home) {
  moveInto(path.join(home, FILE), (b, done) => moveNet(b, home, 'edge', done));
}

/**
 * How this computer shows in a server room (bucket sync --server, the --service): one id for good, kept beside the
 * buckets, and the machine's name.
 */
function thisDevice() {
  const f = path.join(root(), 'device.json');
  let id = null;
  try { id = JSON.parse(fs.readFileSync(f, 'utf8')).id; } catch { /* first time */ }
  if (!/^[0-9a-f]{16}$/.test(String(id))) {
    id = require('crypto').randomBytes(8).toString('hex');
    fs.mkdirSync(path.dirname(f), { recursive: true, mode: 0o700 });
    fs.writeFileSync(f, `${JSON.stringify({ id })}\n`, { mode: 0o600 });
  }
  return { id, name: os.hostname().slice(0, 64) || 'computer', kind: 'cli' };
}

module.exports = { FILE, writeText, setRoot, root, edgeAt, at, read, update, kv, clear, moveOldFiles, identityFile, identityAt, keptIdentities, hasIdentityBucket, keepIdentityBucket, moveIdentityBucket, thisDevice };
