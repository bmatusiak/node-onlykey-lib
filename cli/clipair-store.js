'use strict';
/*
 * PART T: THIS COMPUTER USER'S CLI PAIRS (onlykey-edge
 * features/CLI-PAIR-SPEC.md, rule 1: "a pairing belongs to one user
 * account on one computer").
 *
 *   ~/.onlykey-js/cli-pairing.json   {identity: {secretKey, publicKey}, pairings: {<phone>: record}}
 *
 * OWNER-ONLY, which is the whole point: another account on this computer must not
 * be able to read it, or it could talk to ok-rn as this user. On Linux/mac the file
 * is 0600 in a 0700 folder. On Windows the mode bits do nothing; the protection is
 * the user profile's own ACL (C:\Users\<name> is readable only by that user, SYSTEM
 * and administrators) - the same as agent.key and the Edge copies.
 *
 * Phones are filed under the address the Bluetooth link REACHED (normalised), never
 * under --address as typed: a name, a MAC and no --address must all find the same
 * pairing (audit F1/F2, 2026-10-20). Each record also keeps the phone's Bluetooth
 * name (`phoneName`, for forget and list) and its pairing id (`phoneId`).
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const clipair = require('../src/clipair');

const toHex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));

function fileOf(home = os.homedir()) {
  const file = path.join(home, '.onlykey-js', 'cli-pairing.json');
  /*
   * ONE NAME PER THING (Brad, 2026-10-25: "we can't call 2 different things the same thing, this is how bugs
   * happen"): these are cli pairs, not Bluetooth's own pairings, and the file was named bt-pairing.json before.
   * A computer paired then keeps its pairings: the old file is renamed once, the first time it is looked for.
   */
  const old = path.join(home, '.onlykey-js', 'bt-pairing.json');
  if (!fs.existsSync(file) && fs.existsSync(old)) {
    try { fs.renameSync(old, file); } catch { /* another onlykey-js moved it first */ }
  }
  return file;
}

/*
 * How the phone lists this pairing: the computer's name ("NITRO16"). The phone's
 * list is paired computers; the keys live in this user's owner-only home.
 */
function computerName() {
  return os.hostname();
}

/* the --address as a key: case and separators do not matter */
const phoneKey = (address) => String(address || 'default').toUpperCase().replace(/[^0-9A-Z]/g, '');

function read(home) {
  try { return JSON.parse(fs.readFileSync(fileOf(home), 'utf8')); } catch { return { pairings: {} }; }
}

function write(home, data) {
  const file = fileOf(home);
  /*
   * never a half-written pairing file; on Windows the rename waits out a reader holding the old file open (the
   * bucket store's writer, bucket/cli/home.js). The desktop app reads this file while its sync service marks a phone
   * used: EPERM, and a finished trade was reported "not traded" (Windows desktop + A13, 2026-10-25).
   */
  require('../bucket/cli/home').writeText(file, JSON.stringify(data, null, 1) + '\n');
  if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
}

/** This user's static X-Wing identity, made on first use. */
function identity(home) {
  const data = read(home);
  if (!data.identity) {
    const id = clipair.generateIdentity();
    data.identity = { secretKey: toHex(id.secretKey), publicKey: toHex(id.publicKey) };
    data.pairings = data.pairings || {};
    write(home, data);
  }
  return { secretKey: fromHex(data.identity.secretKey), publicKey: fromHex(data.identity.publicKey) };
}

/** The pairing with the phone at this --address, or null. */
function pairingFor(address, home) {
  return (read(home).pairings || {})[phoneKey(address)] || null;
}

/**
 * Store (or replace) the pairing with the phone at this address - the address the
 * link reached, so it is never empty: a pairing filed under '' was found by no
 * later command that named the phone (audit F2).
 */
function savePairing(address, record, home, phoneName) {
  if (!address) throw new Error('a pairing is filed under the phone\'s Bluetooth address, and none is known');
  const data = read(home);
  const old = (data.pairings || {})[phoneKey(address)] || {};
  const name = phoneName !== undefined ? phoneName : old.phoneName;
  /* this computer's own facts about the phone (switched off, last used) outlive a renewal */
  const kept = { ...(old.off ? { off: true } : {}), ...(old.lastUsed ? { lastUsed: old.lastUsed } : {}) };
  data.pairings = { ...(data.pairings || {}), [phoneKey(address)]: { ...kept, ...record, address: String(address), ...(name ? { phoneName: name } : {}) } };
  write(home, data);
}

/*
 * ON OR OFF, AND LAST USED - the phone's Paired devices card has both per computer, so this computer has both per phone
 * (Brad, 2026-10-25: "each device in desktop should have a toggle"; one card, both sides). Off: the sync service leaves
 * that phone alone until it is on again.
 */
function setOn(address, on, home) {
  const data = read(home);
  const k = phoneKey(address);
  const r = (data.pairings || {})[k];
  if (!r) return false;
  if (on) delete r.off; else r.off = true;
  write(home, data);
  return true;
}
function markUsed(address, at = Date.now(), home) {
  const data = read(home);
  const r = (data.pairings || {})[phoneKey(address)];
  if (!r) return;
  r.lastUsed = at;
  write(home, data);
}

/**
 * Forget the pairing(s) for a phone named by address OR Bluetooth name, as --address
 * takes either. Returns the records removed - an empty list means nothing matched,
 * and the caller says so (audit F3: it used to say "forgot" regardless).
 */
function removePairing(address, home) {
  const data = read(home);
  const all = data.pairings || {};
  const want = String(address || '').toLowerCase();
  const gone = Object.keys(all).filter((k) => (address
    ? k === phoneKey(address) || String(all[k].phoneName || '').toLowerCase() === want
    : false));
  const removed = gone.map((k) => all[k]);
  if (!removed.length) return [];
  for (const k of gone) delete all[k];
  write(home, data);
  return removed;
}

function list(home) {
  return Object.values(read(home).pairings || {});
}

/*
 * The pairing conversation over a started Bluetooth pipe (the `pair` command):
 * commit -> keys (asked again every few seconds until the phone's window opens)
 * -> reveal + print the code -> the phone's approval -> confirm -> the phone's
 * PAIRED -> only then this side is stored.
 */
async function pairOverPipe(pipe, { home, name = computerName(), out = () => {}, windowWaitMs = 120000, askEveryMs = 5000, approveWaitMs = 150000 } = {}) {
  /* filed under the phone the link reached - checked BEFORE pairing, so a pairing is never made that nothing could find */
  const phone = pipe.phone;
  if (!phone) throw Object.assign(new Error('the Bluetooth link did not say which phone it reached - not pairing'), { code: 'EBTPAIR_NOPHONE' });
  const id = identity(home);
  const a = clipair.cliPairStart({ identity: id, name });
  let keys = null;
  for (const until = Date.now() + windowWaitMs; !keys && Date.now() < until;) keys = await pipe.pairExchange(a.msg, askEveryMs);
  if (!keys) throw Object.assign(new Error('no answer: "Pair a computer" was not open on the phone (or Bluetooth API is off there)'), { code: 'EBTPAIR_SILENT' });
  const c = clipair.cliPairOnKeys(a.state, keys);
  out(`code  ${c.code}  - check the phone shows the same code, then approve there`);
  const done = await pipe.pairExchange(c.msg, approveWaitMs);
  if (!done) throw Object.assign(new Error('not approved on the phone (declined, or its window closed)'), { code: 'EBTPAIR_DECLINED' });
  const f = clipair.cliPairOnDone(c.state, done, Date.now());
  const ack = await pipe.pairExchange(f.msg, 8000);
  if (!ack || !clipair.cliPairOnAck(f.record, ack)) throw Object.assign(new Error('the phone did not confirm it stored the pairing - pair again'), { code: 'EBTPAIR_NOACK' });
  const record = { ...f.record, name };
  savePairing(phone.address, record, home, phone.name);
  return { record, code: c.code, phone };
}

module.exports = { fileOf, computerName, phoneKey, identity, pairingFor, savePairing, setOn, markUsed, removePairing, list, pairOverPipe };
