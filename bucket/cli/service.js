'use strict';
/*
 * THE SYNC SERVICE (Brad, 2026-10-25: "this service is a sync service"): watch this computer's bucket and trade it, by itself (Brad, 2026-10-25: "we don't have a service
 * for watching changes - the desktop app is long-lived so a service can live in that, but for normal cli `--service`
 * will be our long-lived, and --soft-key is also long-lived until it ends").
 *
 * It lives in the computer's one long-lived process (`onlykey-js --service`, which is the Edge agent too) and trades
 * with the paired device that process reaches (bucket/cli/trade.js) whenever there may be something to trade:
 *
 *   - THIS COMPUTER'S BUCKET CHANGED: the folder of kept buckets is watched - the desktop app writes the same files, so
 *     a password added there is traded from here (the desktop app has no Bluetooth of its own). Changes in a burst are
 *     waited out (DEBOUNCE_MS) and one trade covers them.
 *   - A SLOW BACKSTOP (INTERVAL_MS): what changed on the other device - the phone cannot start a link to a computer;
 *     the computer reaches it - and anything a watcher missed.
 *
 * One trade at a time. A change this computer's own trade wrote is not a change to trade again: each trade notes the
 * kept files' contents after it, and a watch event on files that still read the same is skipped - so it never loops.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEBOUNCE_MS = 3000;
const INTERVAL_MS = 5 * 60 * 1000;

/* what the kept buckets read now: one hash over every bucket file in the folder */
function contentsOf(dir) {
  const h = crypto.createHash('sha256');
  let names = [];
  try { names = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort(); } catch { return ''; }
  for (const n of names) {
    h.update(n);
    try { h.update(fs.readFileSync(path.join(dir, n))); } catch { /* replaced while read: the next event reads it */ }
  }
  return h.digest('hex');
}

/**
 * Start watching and trading.
 * @param {{dir: string, tradeOnce: () => Promise<{traded: boolean, why?: string, taken?: object, gave?: object}>, say?: (l: string) => void, debounceMs?: number, intervalMs?: number, watch?: typeof fs.watch}} o
 *   dir: the folder of this net's kept buckets (bucket/cli/home.js); tradeOnce: one trade with the paired device
 * @returns {{trade: (why: string) => Promise<void>, stop: () => void}}
 */
function startBucketService({ dir, tradeOnce, say = () => {}, debounceMs = DEBOUNCE_MS, intervalMs = INTERVAL_MS, watch = fs.watch }) {
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
      /* said first, so a host shows a sync in progress (ok-edge: the 🔁 flashes) */
      say(`sync: trading (${why})`);
      try {
        const r = await tradeOnce();
        say(r.traded ? `sync: traded (${why}) - took ${n(r.taken)}, gave ${n(r.gave)}` : `sync: not traded (${why}) - ${r.why}`);
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
  const tick = setInterval(() => { void trade('the regular check'); }, intervalMs);
  if (tick.unref) tick.unref();
  return {
    trade,
    stop() {
      stopped = true;
      clearTimeout(timer);
      clearInterval(tick);
      if (watcher) watcher.close();
    },
  };
}

module.exports = { startBucketService, contentsOf };
