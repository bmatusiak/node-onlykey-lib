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
 * WHAT IS NOT HERE: machine files stay files - bt-pairing.json (each computer pairs: Brad,
 * 2026-10-21), the Edge homes' control.key, peer.key and agent.key (private keys), agent-gpg.asc
 * and the GnuPG home.
 *
 * Stores (one per net, the testnet's beside the live one):
 *   keychain / keychain-test           key 'list': the Key Chain list (keychain/src/list.js text)
 *   edge.copies / edge-test.copies     key: device id (16 hex): its copy (edge/src/copyfile.js JSON)
 *   edge.budgets / edge-test.budgets   key: budget id: the budget this computer asked for (JSON)
 *   edge.pointers / edge-test.pointers key: as edge/src/store.js names them: one pointer per key
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
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${bucket.serialize(b)}\n`, { mode: 0o600 });
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
  };
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
 * was. agent.json is not moved: the phone keeps the agent's identity since 2026-10-20.
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

module.exports = { FILE, setRoot, root, edgeAt, at, read, update, kv, clear, moveOldFiles };
