'use strict';
/*
 * --soft-key: THE DESKTOP APP'S SOFT KEY, BOOTED BY THE CLI (Brad, 2026-10-25: "--soft-key will boot the same softkey
 * the desktop app does ... it will need to be interactive to input pin code and send a 1-6 button press, it will need
 * to use stdio").
 *
 * The CLI's order is: the desktop app when it runs (it does the work, with whatever key it has open); else a hard
 * key on USB; --soft-key this. The app records where its soft key lives and which emulator build it
 * loaded (ok-edge electron/desktop/okemu.js -> ~/.onlykey-js/softkey.json, per net), so this boots exactly that one -
 * never a second soft key - and only while the app is not running (two firmwares on one storage would corrupt it).
 *
 * THE PERSON IS THE KEY'S FINGER, OVER STDIO. At start the soft key asks for its PIN on the terminal (typed, not shown)
 * and presses those digits; while a command runs, typing 1..6 and Enter presses that button (a waiting budget, a sign,
 * a decrypt); and when the firmware waits for a press it says so. A soft key has no buttons of its own - this is them.
 *
 * The pipe contract is cli/transport-hid's (isRunning, start, stop, write, on 'stream' / 'close', device,
 * interfaces), so every command runs on it unchanged.
 *
 * (Later, the same soft key in USB gadget mode - the emulator's gadget bridge: on the Linux box a browser then sees it
 * as a plugged-in key for the web app's WebAuthn/CTAP, and on the Pi's OTG port another computer does.)
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');
const { PRESS_TICKS } = require('../src/device/press');

const DIR = { out: 0, in: 1 };

/* a condition polled until it holds, or the reason */
async function until(test, timeoutMs, why) {
  const end = Date.now() + timeoutMs;
  while (!test()) {
    if (Date.now() > end) throw new Error(why);
    await new Promise((r) => setTimeout(r, 50));
  }
}
const VENDOR = 2;
const POLL_MS = 400;

/** Where the desktop app's soft key lives, per net (written by the app each time it starts its soft key). */
function softKeyRecord(net, home = os.homedir()) {
  const file = path.join(home, '.onlykey-js', 'softkey.json');
  let rec;
  try { rec = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {
    throw new Error(`no soft key recorded yet (${file}) - start the soft key once in the ok-edge desktop app, then --soft-key boots the same one`);
  }
  const r = rec && rec[net];
  if (!r || !r.storageDir || !r.emulator) {
    throw new Error(`the desktop app has not started its ${net === 'test' ? 'testnet' : 'live'} soft key yet - start it once there (${net === 'test' ? 'Enter testing mode' : 'Log in'})`);
  }
  return r;
}

/*
 * What the firmware waits for (the emulator's confirmState, packed as ok-edge src/transport/OkEmu.ts decodes it):
 * 1..3 waiting with the window open, for an operation other than WebAuthn - else nothing.
 */
function waitingFrom(packed) {
  if (!(packed >= 0)) return null;
  const auth = packed & 0xff;
  const opcode = (packed >>> 8) & 0xff;
  const open = ((packed >>> 27) & 1) === 1;
  if (auth < 1 || auth > 3 || !open || !opcode || opcode === 0xf6) return null;
  const what = { 0xed: 'a sign', 0xf0: 'a decrypt', 0xf5: 'an HMAC challenge', 0xf8: 'an Edge approval' }[opcode] || 'an operation';
  return { what, code: ((packed >>> 24) & 0x7) === 0 && opcode !== 0xf5 && opcode !== 0xf8 };
}

/**
 * The soft key as a pipe.
 * @param {{net?: 'live'|'test', input?: NodeJS.ReadableStream, output?: NodeJS.WritableStream, loadEmulator?: (dir: string) => object, record?: object}} [o]
 */
/* how long a closed soft key keeps running for a reopen in the same process (stop) */
const REOPEN_GRACE_MS = 3000;
/*
 * THE FIRMWARE RUNS ONCE PER PROCESS (box, 2026-10-27: `--soft-key --service` on a key with no agent identity closes
 * its device and opens a new one for the sync alone; the second boot failed "cannot map flash: File exists", then
 * "emulator already started" - the flash is mapped at a fixed address for the life of the process, the emulator module
 * is one per process, and the firmware thread cannot be restarted in place). So the running key is shared by every
 * pipe of this process: a stop() lets its pipe go and keeps the firmware for the grace; a start() inside it - this
 * pipe or a new one, the same soft key - takes the running key back, unlocked as it was left.
 */
let shared = null; /* {emu, storageDir, holders, stopTimer} - holders: the pipes running on it now */

function createSoftKeyPipe({ net = 'live', input = process.stdin, output = process.stderr, loadEmulator, record } = {}) {
  const say = (line) => output.write(`onlykey-js soft key: ${line}\n`);
  let emu = null;
  let running = false;
  /* this pipe's listener on the shared emulator (removed when the pipe goes) */
  let onStream = null;
  let rl = null;
  let poll = null;
  let lastWait = '';
  const streamL = new Set();
  const closeL = new Set();

  const press = (digits) => {
    try {
      emu.pressQueue(String(digits), PRESS_TICKS.TAP);
    } catch (e) {
      say(`not pressed: ${e.message}`);
    }
  };

  /* the PIN, typed without echo - a soft key has no keypad of its own */
  const askPin = () => new Promise((resolve) => {
    const tty = input.isTTY;
    output.write('onlykey-js soft key: PIN (digits 1-6, Enter; empty if the soft key has none): ');
    const r = readline.createInterface({ input, output, terminal: !!tty });
    if (tty) r._writeToOutput = () => {}; /* the digits are not shown */
    r.question('', (a) => { r.close(); output.write('\n'); resolve(String(a).trim()); });
  });

  /* 1..6 + Enter while a command runs: the soft key's buttons */
  const listen = () => {
    rl = readline.createInterface({ input, terminal: false });
    rl.on('line', (l) => {
      const t = l.trim();
      if (/^[1-6]+$/.test(t)) press(t);
      else if (t) say('type the buttons to press, 1 to 6, then Enter');
    });
    if (typeof input.unref === 'function') input.unref();
  };

  const attach = () => {
    onStream = ({ buffer, iface, dir }) => {
      const ev = { iface, dir: DIR[dir] ?? dir, bytes: Uint8Array.from(buffer) };
      for (const l of streamL) l(ev);
    };
    emu.on('stream', onStream);
  };
  const startPoll = () => {
    poll = setInterval(() => {
      const w = waitingFrom(emu.confirmState());
      const now = w ? `${w.what}:${w.code}` : '';
      if (now && now !== lastWait) {
        say(`the soft key is waiting for ${w.what} - ${w.code ? 'type the 3-digit code the computer shows' : 'type a button (1) and Enter'}`);
      }
      lastWait = now;
    }, POLL_MS);
    if (typeof poll.unref === 'function') poll.unref();
  };

  return {
    isRunning: () => running,
    async start() {
      if (running) return { started: true, path: 'soft key' };
      const r = record || softKeyRecord(net);
      /* running already in this process (another pipe holds it, or one let it go): the same key taken back */
      if (shared && shared.storageDir === r.storageDir) {
        clearTimeout(shared.stopTimer);
        shared.stopTimer = null;
        if (shared.holders === 0 && typeof shared.emu.ref === 'function') shared.emu.ref();
        shared.holders += 1;
        emu = shared.emu;
        attach();
        running = true;
        listen();
        startPoll();
        return { started: true, path: 'soft key' };
      }
      emu = loadEmulator ? loadEmulator(r.emulator) : require(path.join(r.emulator, 'emulator'));
      attach();
      emu.start({ storageDir: r.storageDir });
      shared = { emu, storageDir: r.storageDir, holders: 1, stopTimer: null };
      running = true;
      say(`booted the desktop app's ${net === 'test' ? 'testnet ' : ''}soft key (${r.storageDir})`);
      const pin = await askPin();
      if (pin) {
        if (!/^[1-6]{7,10}$/.test(pin)) throw new Error('a PIN is 7 to 10 of the digits 1-6');
        /*
         * PRESSED ONCE THE FIRMWARE RUNS (box, 2026-10-25: a PIN pressed right after start was lost - the key answered
         * "locked"): wait for its sense loop to turn, hand it the digits, wait until it has taken every one, then let
         * the PIN settle before the first question.
         */
        await until(() => emu.rounds() > 20, 10000, 'the soft key\'s firmware did not start running');
        press(pin);
        await until(() => emu.pressPending() === 0, 10000, 'the soft key did not take the PIN\'s presses');
        await new Promise((res) => setTimeout(res, 1500));
      }
      listen();
      say('type 1-6 and Enter to press its buttons while the command runs');
      startPoll();
      return { started: true, path: 'soft key' };
    },
    async stop() {
      if (poll) clearInterval(poll);
      if (rl) rl.close();
      /*
       * THE FIRMWARE IS NOT STOPPED, ONLY LET GO (box, 2026-10-27: a stop under the service released the callbacks the
       * still-running firmware thread calls - it aborted on its next LED update). It cannot be restarted in one process,
       * so the last pipe to close unrefs it: the process may exit (the thread goes with it), and a reopen refs it again
       * (see `shared`). An emulator without unref (older builds): stopped after the grace, as before.
       */
      if (emu && running) {
        if (onStream && typeof emu.removeListener === 'function') emu.removeListener('stream', onStream);
        onStream = null;
        const s = shared;
        /* only when no other pipe still runs on it (the service's, while a command's own pipe comes and goes) */
        if (s && s.emu === emu && --s.holders <= 0) {
          if (typeof s.emu.unref === 'function') {
            s.emu.unref();
          } else {
            clearTimeout(s.stopTimer);
            s.stopTimer = setTimeout(() => {
              if (shared !== s || s.holders > 0) return;
              shared = null;
              try { s.emu.stop(); } catch { /* already stopped */ }
            }, REOPEN_GRACE_MS);
          }
        }
      }
      running = false;
      for (const l of closeL) l(null);
    },
    async write(iface, bytes) {
      if (!running) throw new Error('the soft key is not running');
      const buf = Buffer.from(bytes);
      if (iface === VENDOR) await emu.writeHidTaken(buf, iface);
      else emu.writeHid(buf, iface);
      return buf.length;
    },
    on(event, listener) {
      const set = event === 'stream' ? streamL : event === 'close' ? closeL : null;
      if (!set) throw new Error(`the soft key's pipe has no "${event}" event`);
      set.add(listener);
      return () => set.delete(listener);
    },
    get device() { return running ? { path: 'soft key', product: 'OnlyKey (soft key)', serialNumber: '' } : null; },
    interfaces() { return running ? [{ iface: VENDOR, path: 'soft key' }, { iface: 1, path: 'soft key' }] : []; },
  };
}

module.exports = { createSoftKeyPipe, softKeyRecord, waitingFrom };
