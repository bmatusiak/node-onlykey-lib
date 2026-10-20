'use strict';
/*
 * PART T: THIS COMPUTER USER'S BLUETOOTH PAIRINGS (onlykey-edge
 * features/BLUETOOTH-PAIRING-SPEC.md, rule 1: "a pairing belongs to one user
 * account on one computer").
 *
 *   ~/.onlykey-js/bt-pairing.json   {identity: {secretKey, publicKey}, pairings: {<phone>: record}}
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
const btpair = require('../src/btpair');

const toHex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));

function fileOf(home = os.homedir()) {
  return path.join(home, '.onlykey-js', 'bt-pairing.json');
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
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 1) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file); /* never a half-written pairing file */
  if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
}

/** This user's static X-Wing identity, made on first use. */
function identity(home) {
  const data = read(home);
  if (!data.identity) {
    const id = btpair.generateIdentity();
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
  data.pairings = { ...(data.pairings || {}), [phoneKey(address)]: { ...record, address: String(address), ...(name ? { phoneName: name } : {}) } };
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
  const a = btpair.cliPairStart({ identity: id, name });
  let keys = null;
  for (const until = Date.now() + windowWaitMs; !keys && Date.now() < until;) keys = await pipe.pairExchange(a.msg, askEveryMs);
  if (!keys) throw Object.assign(new Error('no answer: "Pair a computer" was not open on the phone (or Bluetooth API is off there)'), { code: 'EBTPAIR_SILENT' });
  const c = btpair.cliPairOnKeys(a.state, keys);
  out(`code  ${c.code}  - check the phone shows the same code, then approve there`);
  const done = await pipe.pairExchange(c.msg, approveWaitMs);
  if (!done) throw Object.assign(new Error('not approved on the phone (declined, or its window closed)'), { code: 'EBTPAIR_DECLINED' });
  const f = btpair.cliPairOnDone(c.state, done, Date.now());
  const ack = await pipe.pairExchange(f.msg, 8000);
  if (!ack || !btpair.cliPairOnAck(f.record, ack)) throw Object.assign(new Error('the phone did not confirm it stored the pairing - pair again'), { code: 'EBTPAIR_NOACK' });
  const record = { ...f.record, name };
  savePairing(phone.address, record, home, phone.name);
  return { record, code: c.code, phone };
}

module.exports = { fileOf, computerName, phoneKey, identity, pairingFor, savePairing, removePairing, list, pairOverPipe };
