'use strict';
/*
 * THE SYNC SERVICE (Brad, 2026-10-25: "this service is a sync service"): watch this computer's bucket and trade it, by itself (Brad, 2026-10-25: "we don't have a service
 * for watching changes - the desktop app is long-lived so a service can live in that, but for normal cli `--service`
 * will be our long-lived, and --soft-key is also long-lived until it ends").
 *
 * It lives in the computer's one long-lived process (`onlykey-js --service`, which is the Edge agent too) and trades
 * (bucket/cli/trade.js) with the devices its caller's tradeOnce reaches - the other devices of the identity in the
 * key's server room (edge/cli/register.js) - whenever there may be something to trade:
 *
 *   - THIS COMPUTER'S BUCKET CHANGED: the folder of kept buckets is watched - the desktop app writes the same files, so
 *     a password added there is traded from here. Changes in a burst are waited out (DEBOUNCE_MS) and one trade
 *     covers them.
 *   - A REGULAR CHECK (INTERVAL_MS): what changed on the other device - this side starts the trades - and anything a
 *     watcher missed. Short, because a check costs two small messages: the
 *     trade compares the two buckets' hashes and timestamps first, and moves records only when they differ (Brad,
 *     2026-10-25: "shorter regular check is easy if we check hashes and timestamps").
 *
 * One trade at a time. A change this computer's own trade wrote is not a change to trade again: each trade notes the
 * kept files' contents after it, and a watch event on files that still read the same is skipped - so it never loops.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEBOUNCE_MS = 3000;
const INTERVAL_MS = 30 * 1000;

/* what the kept buckets read now: one hash over every bucket file in the folder */
function contentsOf(dir) {
  const h = crypto.createHash('sha256');
  let names = [];
  /* the buckets only, by identity id - not synced-with.json beside them */
  try { names = fs.readdirSync(dir).filter((f) => /^[0-9a-f]{32}\.json$/.test(f)).sort(); } catch { return ''; }
  for (const n of names) {
    h.update(n);
    try { h.update(fs.readFileSync(path.join(dir, n))); } catch { /* replaced while read: the next event reads it */ }
  }
  return h.digest('hex');
}

/*
 * ONE SYNC SERVICE PER COMPUTER. The desktop app runs one while it is open (ok-edge electron/desktop/sync.js), a terminal
 * `onlykey-js --service` runs one, `--soft-key` runs one - two at once would both trade the same kept files with the
 * same devices, each undoing the other's view of what changed. The first to start holds a lock (lockFile: its pid and who it is,
 * owner-only); a later one sees a live holder and does not trade - it says who does. A holder that died leaves a lock
 * whose pid no longer runs: the next one takes it. The liveness check is desktop/trust.js's.
 *
 * A PID ALONE IS NOT ENOUGH (Windows, 2026-10-30: the desktop app said "Another sync service on this computer has it
 * (the desktop app, pid 149784)" - that desktop app was long gone, and Windows had given 149784 to GameInputSvc.exe,
 * which answers EPERM, so it counted as alive and no sync ran at all). EPERM cannot simply mean "dead": a service
 * started elevated answers it too. So the holder also beats: it rewrites the lock's time on its regular tick, and a
 * lock is held only while its pid answers AND its time is under three ticks old.
 */
function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}
function holderOf(lockFile, alive, now = Date.now()) {
  try {
    const j = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
    const beat = Date.parse(j && j.at);
    const fresh = Number.isFinite(beat) && now - beat <= 3 * (Number(j.every) || INTERVAL_MS);
    return j && j.pid !== process.pid && fresh && alive(j.pid) ? j : null;
  } catch {
    return null;
  }
}

/**
 * Start watching and trading.
 * @param {{dir: string, tradeOnce: () => Promise<{traded: boolean, why?: string, taken?: object, gave?: object}>, say?: (l: string) => void, debounceMs?: number, intervalMs?: number, watch?: typeof fs.watch}} o
 *   dir: the folder of this net's kept buckets (bucket/cli/home.js); tradeOnce: one round of trades (the server room's devices)
 *   lockFile: this computer's one sync lock (omitted: no lock - tests); who: how the holder is named to the next one
 * @returns {{trade: (why: string) => Promise<void>, stop: () => void, heldBy?: {pid: number, who: string}}}
 */
function startBucketService({ dir, tradeOnce, say = () => {}, debounceMs = DEBOUNCE_MS, intervalMs = INTERVAL_MS, watch = fs.watch, lockFile = null, who = `onlykey-js --service (pid ${process.pid})`, alive = pidAlive }) {
  if (lockFile) {
    const held = holderOf(lockFile, alive);
    if (held) {
      say(`sync: runs in pid ${held.pid} (${held.who}) - not here`);
      return { trade: async () => {}, stop() {}, heldBy: { pid: held.pid, who: held.who } };
    }
    fs.mkdirSync(path.dirname(lockFile), { recursive: true, mode: 0o700 });
  }
  /* the lock, with this tick's time (its beat - holderOf); only while it is still this process's */
  const beatLock = () => {
    if (!lockFile) return;
    try {
      const j = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
      if (j && j.pid !== process.pid) return;
    } catch { /* none yet, or unreadable: this process writes it */ }
    fs.writeFileSync(lockFile, `${JSON.stringify({ pid: process.pid, who, at: new Date().toISOString(), every: intervalMs })}\n`, { mode: 0o600 });
  };
  if (lockFile) {
    try { fs.unlinkSync(lockFile); } catch { /* none */ }
    beatLock();
  }
  let synced = contentsOf(dir);
  let running = null;
  let again = false;
  let timer = null;
  let stopped = false;

  const n = (o) => Object.values(o || {}).reduce((a, b) => a + b, 0);
  async function trade(why) {
    if (stopped) return;
    if (running) { again = true; return running; }
    running = (async () => {
      /*
       * the trade itself says "sync: trading" once records move (a host flashes then - ok-edge's ⇄); a check that finds
       * the same state says "in sync", and nothing moved
       */
      try {
        const r = await tradeOnce();
        if (r.traded && r.same) say(`sync: in sync (${why})`);
        else if (r.traded) say(`sync: traded (${why}) - took ${n(r.taken)}, gave ${n(r.gave)}${r.settled === false ? ' - NOT settled' : ''}`);
        else say(`sync: not traded (${why}) - ${r.why}`);
      } catch (e) {
        say(`sync: not traded (${why}) - ${e.message}`);
      } finally {
        synced = contentsOf(dir);
        running = null;
      }
      if (again && !stopped) { again = false; await trade('changed meanwhile'); }
    })();
    return running;
  }

  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  let watcher = null;
  try {
    watcher = watch(dir, () => {
      if (stopped) return;
      clearTimeout(timer);
      const settled = () => {
        /*
         * a trade running now is writing this folder itself: look again once it ends, against what it left - never
         * queue another trade for its own write
         */
        if (running) { void running.then(settled); return; }
        /* this computer's own trade wrote it, or a write that changed nothing: nothing to trade */
        if (contentsOf(dir) === synced) return;
        void trade('this computer\'s bucket changed');
      };
      timer = setTimeout(settled, debounceMs);
    });
  } catch (e) {
    say(`sync: cannot watch ${dir} (${e.message}) - trading on the timer only`);
  }
  const tick = setInterval(() => {
    try { beatLock(); } catch { /* the folder went: the next tick writes it again */ }
    void trade('the regular check');
  }, intervalMs);
  if (tick.unref) tick.unref();
  return {
    trade,
    stop() {
      stopped = true;
      clearTimeout(timer);
      clearInterval(tick);
      if (watcher) watcher.close();
      /* the lock goes only if it is still ours (a later holder that took over a dead one's keeps it) */
      if (lockFile) {
        try { if (JSON.parse(fs.readFileSync(lockFile, 'utf8')).pid === process.pid) fs.unlinkSync(lockFile); } catch { /* gone already */ }
      }
    },
  };
}

module.exports = { startBucketService, contentsOf };
