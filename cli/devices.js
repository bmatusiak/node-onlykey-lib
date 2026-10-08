'use strict';

/**
 * `onlykey-js devices [--ble]` - the parts the command and its child processes use
 * (Brad, 2026-10-08: "onlykey-js devices helps us pick a target").
 *
 * WHY CHILD PROCESSES. node-hid (USB) and noble (Bluetooth, Windows) are native
 * add-ons with threads of their own. Asking a USB key and then starting a noble scan
 * in the same Node process crashed Node in native code ("Check failed:
 * (array_buffer_allocator) != nullptr", Brad's run and mine, 2026-10-08); with noble
 * moved out, the parent still segfaulted now and then while it waited for the phones
 * - node-hid had closed its keys seconds before. Neither crashes when its process ends
 * right after its work. So each transport runs as a child (this file, run directly:
 * `usb` or `ble`) that prints one JSON row per line and exits; the parent loads no
 * native add-on and shows the rows as they come. A test hands in its own bus and scan
 * and runs everything in one process.
 */
const okmsg = require('../src/protocol/okmsg');

const ASK_MS = 25000;
/* the Bluetooth search's default: the A13 advertises slower than the Pixel and was missed once in 6 s (2026-10-08) */
const SCAN_SECONDS = 10;

/** Open one key, connect, read its answer, release - bounded, so one silent key does not stall the list. */
async function askKey(start, target) {
  let app = null;
  let timer = null;
  const work = (async () => {
    app = await start(target);
    const connected = await app.services.device.connect();
    return connected.identity || {};
  })();
  try {
    return await Promise.race([work, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('no answer in 25 s')), ASK_MS); })]);
  } finally {
    /* a key that answered must not leave its 25 s wait holding the process open */
    clearTimeout(timer);
    work.catch(() => {});
    if (app) await Promise.resolve(app.destroy()).catch(() => {});
  }
}

/*
 * What a key said, as the row's facts. Locked is connectable (Brad, 2026-10-08:
 * "locked is connectable, include that; show details about the device state if we
 * can") - it answers, it just needs its PIN before it does more. The same facts make
 * the text line (details) and the --json fields.
 */
function describe(identity) {
  if (identity.state === 'error' && okmsg.errorKind(identity.raw) === 'stopped') {
    return { verdict: 'not connectable', state: 'stopped', details: 'the soft key stopped (ok-rn\'s inactivity lockout) - restart ok-rn and log in' };
  }
  const facts = {
    state: identity.state || 'unknown',
    model: identity.model || null,
    firmware: identity.version || null,
    build: identity.build && identity.build !== 'unknown' ? identity.build : null,
    pinSet: identity.pinSet === true || identity.pinSet === false ? identity.pinSet : null,
  };
  const details = [
    `state ${facts.state}`,
    facts.model ? `model ${facts.model}` : null,
    facts.firmware ? `firmware ${facts.firmware}` : facts.state === 'locked' ? 'firmware not reported while locked' : null,
    facts.build ? `build ${facts.build}` : null,
    facts.pinSet === true ? 'PIN set' : facts.pinSet === false ? 'no PIN yet' : null,
  ].filter(Boolean).join(' · ');
  const ok = ['unlocked', 'locked', 'uninitialized'].includes(facts.state);
  return { verdict: ok ? 'connectable' : 'answered', ...facts, details };
}

const silent = (e) => ({ verdict: 'not connectable', error: e.message, details: `did not answer - ${e.message}` });

/*
 * A row: what `devices` prints and what --json gives (Brad, 2026-10-08: "now we add
 * --json for machinecode output"). target is what to pass on; arg is the same as
 * command-line text.
 */
const usbRow = (d, answer) => ({ transport: 'usb', name: d.product || 'OnlyKey', ...answer, target: { path: d.path }, arg: `--path "${d.path}"` });

/** The USB keys: each OnlyKey's vendor interface asked. -> rows through onRow */
async function usbRows({ start, find, onRow, onNote }) {
  let usb = [];
  try {
    usb = await find();
  } catch (e) {
    onNote(`usb: ${e.message}`);
  }
  for (const d of usb) {
    let answer;
    try {
      answer = describe(await askKey(start, { path: d.path }));
    } catch (e) {
      /*
       * One retry, a second later, for a key that did not reply: run straight after
       * another command, Windows had not released the key yet (2026-10-08, the 4th
       * of 5 back-to-back runs). A key that still does not reply is said so.
       */
      if (!/no reply/.test(e.message)) answer = silent(e);
      else {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        try { answer = describe(await askKey(start, { path: d.path })); } catch (e2) { answer = silent(e2); }
      }
    }
    onRow(usbRow(d, answer));
  }
}

/**
 * The phones in reach: a paired one is asked, an unpaired one is listed with how to
 * pair (never opened - opening it would start a pairing). -> rows through onRow;
 * notes through onNote
 */
async function bleRows({ start, scan, pairingFor, onRow, onNote }) {
  let phones = [];
  try {
    phones = await scan();
  } catch (e) {
    onNote(`ble: ${e.message}`);
  }
  for (const p of phones) {
    const address = String(p.address).toUpperCase();
    const key = address.replace(/[:-]/g, '');
    const arg = `--ble --address ${address}`;
    const base = { transport: 'ble', name: p.name || 'a phone', rssi: p.rssi === null || p.rssi === undefined ? null : p.rssi, target: { ble: true, address }, arg };
    if (!pairingFor(key)) {
      onRow({ ...base, paired: false, verdict: 'not paired', details: `this computer has no pairing with it - onlykey-js pair ${arg}` });
      continue;
    }
    let answer;
    try { answer = describe(await askKey(start, { ble: true, address: p.address })); } catch (e) { answer = silent(e); }
    onRow({ ...base, paired: true, ...answer });
  }
  if (!phones.length) onNote('ble: no phone in reach - ok-rn must be open and logged in (it is not on Bluetooth while logged out)');
}

/**
 * Run one transport in a child process (this file) and hand its rows and notes on as
 * they come. -> resolves when the child has ended
 */
function viaChild(which, { onRow, onNote, onError, args = [] }) {
  return new Promise((resolve) => {
    const child = require('child_process').spawn(process.execPath, [__filename, which, ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
    let buf = '';
    child.stdout.on('data', (chunk) => {
      buf += chunk;
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        try {
          const m = JSON.parse(line);
          if (m.row) onRow(m.row);
          else if (m.note) onNote(m.note);
        } catch { /* not a row */ }
      }
    });
    child.on('error', (e) => { onError(e); resolve(); });
    child.on('close', () => resolve());
  });
}

module.exports = { ASK_MS, SCAN_SECONDS, askKey, describe, silent, usbRows, bleRows, viaChild };

/* a child: one transport alone (`usb` or `ble`), one JSON line per row or note, then it ends */
if (require.main === module) {
  const say = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);
  const start = (opts) => require('./desktop').startDesktop(opts);
  const which = process.argv[2];
  const work = which === 'usb'
    ? usbRows({
      start,
      find: () => { const hid = require('./transport-hid'); return hid.findOnlyKeys(hid.loadNodeHid()).vendor; },
      onRow: (row) => say({ row }),
      onNote: (note) => say({ note }),
    })
    : bleRows({
      start,
      /* the parent's --seconds, else SCAN_SECONDS */
      scan: () => require('./transport-ble').scanPhones({ seconds: Number(process.argv[3]) || SCAN_SECONDS }),
      pairingFor: (key) => require('./btpair-store').pairingFor(key),
      onRow: (row) => say({ row }),
      onNote: (note) => say({ note }),
    });
  work.then(() => process.exit(0), (e) => { say({ note: `${which}: ${e.message}` }); process.exit(1); });
}
