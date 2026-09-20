/*
 * console.js - the device's debug console, as something you can wait on.
 *
 * The classic PIN flow is not request/response. The device announces where it
 * is by PRINTING - "Enter PIN", "Storing PIN", "Both PINs Match" - on the
 * SEREMU interface, and the host advances by waiting for the right line. There
 * is no reply to correlate and no status byte to read; the text is the
 * protocol.
 *
 * So this is a small accumulator with two waits on it. It replaces the
 * DebugLog buried inside ok-rn's provision.ts, which polled the buffer every
 * 50 ms. This one is event driven, which removes up to 50 ms of latency per
 * step - six steps per PIN, twice for a confirm - and, more importantly,
 * removes the race described below.
 */
'use strict';

const { IFACE } = require('../protocol/msg');

/** Keep the tail of the console; a long session should not grow without end. */
const DEFAULT_LIMIT = 65536;

/**
 * The console tail, with the PIN taken out of it.
 *
 * A tail in an error message earns its place - "timed out" against a device
 * that printed something unexpected is close to undiagnosable from a phone,
 * which is why these errors carry one. But on a DEBUG firmware the last thing
 * the console said during a PIN bracket is the device acknowledging each digit
 * BY VALUE: "password appended with 4", once per keypress, in order. An Error
 * travels further than a log line - up through every catch, into whatever the
 * caller renders, and off-device if anything crash-reports - so a tail must
 * not carry one.
 *
 * The line survives with its digit removed. That the device was acknowledging
 * presses is the diagnostic fact; WHICH presses is the secret, and no reader of
 * a timeout message needs it.
 *
 * A production firmware never reaches this: it does not enumerate SEREMU, so
 * the buffer is empty and the tail is "". This protects the developer key,
 * which is the one a maintainer actually holds.
 */
function safeTail(text, n = 120) {
  return JSON.stringify(
    String(text).replace(/(password appended with\s*)\d/gi, '$1#').slice(-n),
  );
}

class DeviceConsole {
  constructor({ limit = DEFAULT_LIMIT } = {}) {
    this.limit = limit;
    this.buffer = '';
    this.waiters = new Set();
    this.off = null;
  }

  /**
   * Subscribe to a transport's log events.
   *
   * The transport has already stripped NUL padding and decoded latin1 - see
   * src/transport/contract.js. Nothing here re-does that, because doing it in
   * two places is how the two end up disagreeing.
   */
  attach(transport) {
    if (this.off) return this;
    this.off = transport.on('log', (event) => this.push(event.text));
    return this;
  }

  detach() {
    if (this.off) this.off();
    this.off = null;
    for (const waiter of [...this.waiters]) {
      waiter.fail(new Error('device console detached while waiting'));
    }
    return this;
  }

  /** Feed text directly. Exposed for tests and for transports without events. */
  push(text) {
    if (!text) return;
    this.buffer = (this.buffer + text).slice(-this.limit);
    for (const waiter of [...this.waiters]) waiter.check();
  }

  /**
   * Drop what has been said so far.
   *
   * Called before each step, so a prompt from the PREVIOUS step cannot satisfy
   * this one. The firmware prints the same words at several points in the
   * bracket - "Enter PIN" appears for both the primary and the confirmation -
   * so without this a step can be satisfied by stale text and the sequence
   * runs ahead of the device.
   */
  clear() {
    this.buffer = '';
    return this;
  }

  get text() {
    return this.buffer;
  }

  /**
   * Wait for a pattern, failing early on any of `reject`.
   *
   * The buffer is checked BEFORE subscribing, and that ordering is the whole
   * point: the device can print between the write that provoked it and the
   * caller's wait, and a wait that only looked at future text would miss a line
   * that had already arrived and then time out against a device that answered
   * correctly. Same hazard as writing before subscribing on the vendor
   * interface, in a different costume.
   *
   * @returns {Promise<string>} the console text at the moment it matched
   */
  waitFor(pattern, { reject = [], timeoutMs = 10000 } = {}) {
    return this._wait({
      timeoutMs,
      reject,
      describe: `${pattern}`,
      test: () => (pattern.test(this.buffer) ? this.buffer : null),
    });
  }

  /**
   * Wait until a pattern has matched `count` times.
   *
   * The firmware prints one acknowledgement per PIN digit, so a first-match
   * wait returns after digit one while the rest of the burst is still being
   * consumed. The next message then lands mid-burst and the device sees a
   * short PIN - which surfaces much later as "PINs don't match" against two
   * PINs that were typed identically.
   */
  waitForCount(pattern, count, { reject = [], timeoutMs = 10000 } = {}) {
    return this._wait({
      timeoutMs,
      reject,
      describe: `${count}x ${pattern}`,
      test: () => {
        const found = this.buffer.match(pattern);
        return found && found.length >= count ? found.length : null;
      },
    });
  }

  _wait({ test, reject, timeoutMs, describe }) {
    return new Promise((resolve, rejectPromise) => {
      const waiter = {
        check: () => {
          for (const bad of reject) {
            if (bad.test(this.buffer)) {
              // The device's own words, not a paraphrase - they are what the
              // user is told and what a caller matches on to recover.
              const line = (this.buffer.match(bad) || [])[0];
              return waiter.fail(new Error(line || `device reported ${bad}`));
            }
          }
          const hit = test();
          if (hit === null) return undefined;
          return waiter.done(hit);
        },
        done: (value) => {
          cleanup();
          resolve(value);
        },
        fail: (err) => {
          cleanup();
          rejectPromise(err);
        },
      };

      const timer = setTimeout(() => {
        waiter.fail(new Error(
          `timed out after ${timeoutMs}ms waiting for ${describe}; ` +
          `console tail: ${safeTail(this.buffer)}`,
        ));
      }, timeoutMs);

      const cleanup = () => {
        clearTimeout(timer);
        this.waiters.delete(waiter);
      };

      this.waiters.add(waiter);
      // Check what has already arrived before waiting for more.
      waiter.check();
    });
  }
}

/**
 * Send a line of button presses.
 *
 * ONE write for the whole PIN, terminated by a newline. The firmware queues
 * the presses and replays them one per loop() iteration, so there is no
 * per-digit delay to tune - and splitting the burst across writes is how a
 * subsequent message lands in the middle of it and the firmware sees a short
 * PIN.
 */
function pressLine(transport, digits) {
  const line = `${digits}\n`;
  const bytes = new Uint8Array(line.length);
  for (let i = 0; i < line.length; i++) bytes[i] = line.charCodeAt(i) & 0xff;
  return transport.write(IFACE.SEREMU, bytes);
}

module.exports = { DeviceConsole, pressLine, safeTail, DEFAULT_LIMIT };
