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
 * @param {object} transport
 * @returns {(fn: () => Promise<any>) => Promise<any>}
 */
function laneOf(transport) {
  let lane = lanes.get(transport);
  if (!lane) {
    let tail = null; /* the last queued conversation's settling, or null when the lane is idle */
    lane = (fn) => {
      /*
       * An IDLE lane runs fn at once, in this same tick: a conversation that
       * subscribes and writes synchronously (transport.request) behaves
       * exactly as it did before there was a lane. Only a busy lane queues.
       */
      let run;
      if (tail === null) {
        try {
          run = Promise.resolve(fn());
        } catch (e) {
          run = Promise.reject(e);
        }
      } else {
        run = tail.then(fn, fn);
      }
      const settled = run.then(() => {}, () => {});
      tail = settled;
      settled.then(() => { if (tail === settled) tail = null; });
      return run;
    };
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
function inLane(transport, fn) {
  return typeof transport.exclusive === 'function' ? transport.exclusive(fn) : laneOf(transport)(fn);
}

module.exports = { laneOf, inLane };
