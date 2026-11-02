'use strict';
/*
 * THIS COMPUTER'S KEPT BUCKETS, WATCHED (bucket/cli/roomservice.js's ears): the desktop app, `onlykey-js` commands and
 * the trades all write the same files (~/.onlykey-js/buckets/<net>/), so a password added by any of them reaches the
 * room from the computer's member - with no step.
 *
 *   - a burst of writes is waited out (DEBOUNCE_MS) and one onChange covers it;
 *   - what the member wrote itself is not a change to send again: it says so (noteOwn) after each write, the folder's
 *     contents are noted then, and a watch event on files that still read the same is skipped - so it never loops (the
 *     box, 2026-10-25: "traded - took 0, gave 0", then "trading (changed meanwhile)", without end).
 *
 * EVENTS, NOT A TIMER (Brad, 2026-10-29: "timers are only meant to help inactivity protection"): it was the sync
 * service with a 30 s regular check and a lock it beat on that tick; the room now says what changed on the other
 * devices (a device online, the sealed copy changed), and one member per computer is desktop/member.js's endpoint.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEBOUNCE_MS = 3000;

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

/**
 * @param {{dir: string, onChange: () => void, say?: (l: string) => void, debounceMs?: number, watch?: typeof fs.watch}} o
 *   dir: the folder of this net's kept buckets (bucket/cli/home.js)
 * @returns {{noteOwn: () => void, stop: () => void}} noteOwn: the member wrote the folder itself - not a change
 */
function watchBuckets({ dir, onChange, say = () => {}, debounceMs = DEBOUNCE_MS, watch = fs.watch }) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  let known = contentsOf(dir);
  let timer = null;
  let stopped = false;
  let watcher = null;
  try {
    watcher = watch(dir, () => {
      if (stopped) return;
      clearTimeout(timer);
      timer = setTimeout(() => {
        const now = contentsOf(dir);
        /* the member's own write, or a write that changed nothing: nothing to send */
        if (now === known) return;
        known = now;
        onChange();
      }, debounceMs);
    });
  } catch (e) {
    say(`sync: cannot watch ${dir} (${e.message}) - a change here waits for the next one the room brings`);
  }
  return {
    noteOwn() { known = contentsOf(dir); },
    stop() {
      stopped = true;
      clearTimeout(timer);
      if (watcher) watcher.close();
    },
  };
}

module.exports = { watchBuckets, contentsOf };
