'use strict';

/**
 * ONE LANE PER KEY: one conversation with the key at a time.
 *
 * The vendor interface carries no request ids. A reply is "whatever comes
 * next", so two conversations in flight on one key swap answers. MEASURED ON
 * THE PHONES (2026-10-03):
 *   - the app's background Edge copy ran a PICKUP while an e2e test waited
 *     for its GRANT_CREATE, and the grant read link bytes as its answer;
 *   - Key Chain read its slots while a sync ran: the same slots read
 *     "unknown", then ECC1 as ed25519 (it holds x25519), and signing a PGP key
 *     locked the production firmware.
 * Each plugin had its own care (busQuiet, Edge's own queue), but nothing made
 * the device plugin wait for Edge, or Edge for the device plugin.
 *
 * The lane belongs to the TRANSPORT - the one thing every plugin shares - and
 * holds one CONVERSATION: from the first write until its answer is in, a press
 * included. It is taken at request level, never around code that makes
 * several requests: a function holding the lane that called another laned
 * function would wait for itself. So a conversation uses only raw writes,
 * transport.requestNow and listeners inside it.
 *
 * Plain promises: no Node built-ins, Hermes-clean.
 */

const lanes = new WeakMap();

/**
 * The lane of `transport`: exclusive(fn) runs fn after every conversation
 * queued before it has settled, and returns fn's result.
 *
 * URGENT (rule 8, Brad 2026-10-06): a Hold or Revoke the person taps must not
 * wait behind an agent's conversation. exclusive(fn, {urgent: true}) goes to
 * the FRONT of what is waiting (behind earlier urgent ones) - never into the
 * conversation already running: one conversation at a time still holds. The
 * phone's bridge ends a computer's hold at its next request boundary when one
 * waits (urgentWaiting).
 * @param {object} transport
 * @returns {(fn: () => Promise<any>, opts?: {urgent?: boolean}) => Promise<any>}
 */
function laneOf(transport) {
  let lane = lanes.get(transport);
  if (!lane) {
    const waiting = []; /* {fn, urgent, resolve, reject} not yet started */
    let running = false;
    let lastEnd = Date.now(); /* when the lane last went idle (ms) */
    const next = () => {
      const item = waiting.shift();
      if (!item) { running = false; lastEnd = Date.now(); return; }
      start(item);
    };
    const start = (item) => {
      running = true;
      let run;
      try {
        run = Promise.resolve(item.fn());
      } catch (e) {
        run = Promise.reject(e);
      }
      run.then(item.resolve, item.reject);
      run.then(next, next);
    };
    lane = (fn, opts = {}) => new Promise((resolve, reject) => {
      const item = { fn, urgent: Boolean(opts && opts.urgent), resolve, reject };
      /*
       * An IDLE lane runs fn at once, in this same tick: a conversation that
       * subscribes and writes synchronously (transport.request) behaves
       * exactly as it did before there was a lane. Only a busy lane queues.
       */
      if (!running) { start(item); return; }
      if (item.urgent) {
        let at = 0;
        while (at < waiting.length && waiting[at].urgent) at += 1;
        waiting.splice(at, 0, item);
      } else {
        waiting.push(item);
      }
    });
    lane.urgentWaiting = () => waiting.some((x) => x.urgent);
    /* idle: nothing running, nothing waiting - and since when (an agent lets its Bluetooth link go after a quiet spell) */
    lane.state = () => ({ idle: !running && waiting.length === 0, since: lastEnd });
    lanes.set(transport, lane);
  }
  return lane;
}

/**
 * Run fn in `transport`'s lane: its own exclusive() when it has one (the
 * lib's transports), otherwise a lane kept here for it - so a transport
 * written to the older contract (a host's own, a test's fake) still gets
 * one conversation at a time.
 */
function inLane(transport, fn, opts) {
  return typeof transport.exclusive === 'function' ? transport.exclusive(fn, opts) : laneOf(transport)(fn, opts);
}

/** An urgent conversation (a Hold, a Revoke) is waiting for `transport`'s lane. */
function urgentWaiting(transport) {
  if (typeof transport.urgentWaiting === 'function') return transport.urgentWaiting();
  const lane = lanes.get(transport);
  return Boolean(lane && lane.urgentWaiting());
}

module.exports = { laneOf, inLane, urgentWaiting };
