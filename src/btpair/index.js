'use strict';
/*
 * PART T: BLUETOOTH PAIRING BETWEEN THE CLI AND ok-rn
 * (onlykey-edge features/BLUETOOTH-PAIRING-SPEC.md, decided 2026-10-04).
 *
 * WHY. Bluetooth's encryption protects the link between two DEVICES. On a
 * bonded computer every user account and every app can use that link, so ok-rn
 * trusts only a PAIRED CLI USER: a pairing belongs to one OS user on one
 * computer (the CLI keeps it in that user's owner-only ~/.onlykey-js/), and
 * everything else - unpaired, switched off, revoked, plaintext, a copy of a
 * renewed pairing - gets no answer. Not Edge, not firmware: only the CLI and the
 * phone app.
 *
 * WHAT IS HERE: pure functions over bytes, no I/O, no clock, no storage - the
 * caller passes `now` and keeps the records. The same code runs in the CLI and
 * in ok-rn (Hermes-clean: vendored noble only, no Node built-ins).
 *
 *   identity        a static X-Wing key pair (ML-KEM-768 + X25519, hybrid
 *                   post-quantum): {secretKey 32, publicKey 1216}
 *   pairing         commit-then-reveal, so a man in the middle can't grind keys
 *                   until the codes match; a 6-digit code both sides show; both
 *                   encapsulate to the other -> the pairing secret PS; key
 *                   confirmation both ways before either side stores it
 *   connection      the CLI's fresh ephemeral X-Wing key + HMAC(PS); the phone
 *                   encapsulates -> per-direction session keys (forward secrecy:
 *                   PS alone does not open recorded traffic)
 *   frames          [ctr 4][AES-256-GCM ciphertext][tag 16]; the receiver takes
 *                   only a higher counter (no replay, no reorder)
 *   renewal         on day 6 of 7, inside a session: PS' = HKDF(PS || new ss),
 *                   epoch + 1; the phone keeps old secrets ONLY to recognise
 *                   them - a hello under one is a copied pairing: alarm + drop
 *
 * Messages are compact binary: [type][version][fixed fields] (sizes below).
 */
const { ml_kem768_x25519: xwing } = require('../vendor/exports/@noble/post-quantum/hybrid.js');
const { gcm } = require('../vendor/exports/@noble/ciphers/aes.js');
const { randomBytes } = require('../vendor/exports/@noble/ciphers/utils.js');
const { sha256 } = require('../vendor/exports/@noble/hashes/sha2.js');
const { hmac } = require('../vendor/exports/@noble/hashes/hmac.js');
const { hkdf } = require('../vendor/exports/@noble/hashes/hkdf.js');

const VERSION = 1;
const PUB = 1216; /* X-Wing public key */
const CT = 1120; /* X-Wing ciphertext */
const N = 32; /* nonces, MACs, secrets */
const ID = 16;
const DAY = 24 * 60 * 60 * 1000;
const RENEW_AFTER = 6 * DAY; /* "day 6 of 7" */
const EXPIRES_AFTER = 7 * DAY;
const PAIR_WINDOW = 2 * 60 * 1000; /* "Pair a computer" is open about 2 minutes */
const NAME_MAX = 64;

const T = Object.freeze({
  COMMIT: 0x01, KEYS: 0x02, REVEAL: 0x03, DONE: 0x04, CONFIRM: 0x05, PAIRED: 0x06,
  HELLO: 0x10, HELLO_OK: 0x11,
  RENEW_OFFER: 0x20, RENEW_ACCEPT: 0x21,
});

const te = new TextEncoder();
const td = new TextDecoder();
const ascii = (s) => te.encode(s);
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
const H = (...parts) => sha256(concat(...parts.map((p) => (typeof p === 'string' ? ascii(p) : p))));
const mac = (key, ...parts) => hmac(sha256, key, concat(...parts.map((p) => (typeof p === 'string' ? ascii(p) : p))));
const u32 = (n) => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const rd32 = (b, o) => ((b[o] << 24) >>> 0) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3];
/* constant time: a MAC check that leaks how many bytes matched helps a forger */
function same(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
/* a Bluetooth address as one form: "aa:bb:cc:dd:ee:ff" / "AABBCCDDEEFF" -> "AABBCCDDEEFF"; null if none */
const normMac = (a) => { const s = String(a || '').toUpperCase().replace(/[^0-9A-F]/g, ''); return s.length === 12 ? s : null; };
const fromHex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));

function fail(code, message) {
  return Object.assign(new Error(`btpair: ${message}`), { code });
}
function header(type) { return Uint8Array.of(type, VERSION); }
function parse(msg, type, size) {
  if (!(msg instanceof Uint8Array) || msg.length < 2 || msg[0] !== type || msg[1] !== VERSION) return null;
  if (size !== undefined && msg.length !== size) return null;
  return msg;
}

/* ------------------------------------------------------------ identity */

/** A static X-Wing key pair: the CLI user's (in its owner-only file) or the phone's (Keystore-wrapped). */
function generateIdentity() {
  const k = xwing.keygen();
  return { secretKey: k.secretKey, publicKey: k.publicKey };
}
/** A pairing is named by its CLI user's public key: SHA256("OKT-ID-v1" || pub)[0..16]. */
const idOf = (pub) => H('OKT-ID-v1', pub).slice(0, ID);

/* ------------------------------------------------------------ pairing */

/*
 * The 6-digit code: SHA256("OKT-PAIR-v1" || cli pub || phone pub || cli nonce ||
 * phone nonce), first 4 bytes as a number, mod 1,000,000. The CLI committed to
 * its pub and nonce BEFORE it saw the phone's, so it can't search for a pair
 * that matches a code it wants; a relay in the middle has its own keys on each
 * side and so shows two different codes.
 */
function codeOf(cliPub, phonePub, cliNonce, phoneNonce) {
  const h = H('OKT-PAIR-v1', cliPub, phonePub, cliNonce, phoneNonce);
  return String(rd32(h, 0) % 1000000).padStart(6, '0');
}

/** CLI step 1 -> PAIR_COMMIT {C, name}. Keep `state` for the next step. */
function cliPairStart({ identity, name }) {
  const nameBytes = ascii(String(name || '').slice(0, NAME_MAX));
  const nonce = randomBytes(N);
  const commit = H('OKT-COMMIT-v1', identity.publicKey, nonce);
  return { state: { identity, nonce, commit, nameBytes }, msg: concat(header(T.COMMIT), commit, Uint8Array.of(nameBytes.length), nameBytes) };
}

/**
 * Phone step 1: a PAIR_COMMIT while "Pair a computer" is open (`windowOpenUntil`,
 * ms) -> PAIR_KEYS {phone pub, phone nonce}. Outside the window: null (silence).
 */
function phonePairOnCommit({ identity, windowOpenUntil, now }, msg) {
  if (!windowOpenUntil || now > windowOpenUntil) return null;
  const m = parse(msg, T.COMMIT);
  if (!m || m.length < 2 + N + 1 || m.length !== 2 + N + 1 + m[2 + N]) return null;
  const commit = m.slice(2, 2 + N);
  const name = td.decode(m.slice(2 + N + 1));
  const nonce = randomBytes(N);
  return { state: { identity, commit, name, nonce, windowOpenUntil }, msg: concat(header(T.KEYS), identity.publicKey, nonce) };
}

/** CLI step 2: PAIR_KEYS -> PAIR_REVEAL {cli pub, cli nonce, ct to the phone} and the code to print. */
function cliPairOnKeys(state, msg) {
  const m = parse(msg, T.KEYS, 2 + PUB + N);
  if (!m) throw fail('EBTPAIR_MSG', 'not a pairing answer from the phone');
  const phonePub = m.slice(2, 2 + PUB);
  const phoneNonce = m.slice(2 + PUB);
  const { cipherText, sharedSecret } = xwing.encapsulate(phonePub);
  const code = codeOf(state.identity.publicKey, phonePub, state.nonce, phoneNonce);
  return {
    state: { ...state, phonePub, phoneNonce, ctCli: cipherText, ssCli: sharedSecret, code },
    msg: concat(header(T.REVEAL), state.identity.publicKey, state.nonce, cipherText),
    code,
  };
}

/** Phone step 2: PAIR_REVEAL -> the code to show (or null: the reveal does not match the commitment - silence). */
function phonePairOnReveal(state, msg, now) {
  if (now > state.windowOpenUntil) return null;
  const m = parse(msg, T.REVEAL, 2 + PUB + N + CT);
  if (!m) return null;
  const cliPub = m.slice(2, 2 + PUB);
  const cliNonce = m.slice(2 + PUB, 2 + PUB + N);
  const ctCli = m.slice(2 + PUB + N);
  if (!same(H('OKT-COMMIT-v1', cliPub, cliNonce), state.commit)) return null;
  let ssCli;
  try { ssCli = xwing.decapsulate(ctCli, state.identity.secretKey); } catch { return null; }
  const code = codeOf(cliPub, state.identity.publicKey, cliNonce, state.nonce);
  return { state: { ...state, cliPub, cliNonce, ctCli, ssCli, code }, code };
}

function pairingSecret(st, ctPhone, ssPhone) {
  const transcript = H('OKT-PAIR-TRANSCRIPT-v1', st.cliPub || st.identity.publicKey, st.phonePub || st.identity.publicKey,
    st.cliNonce || st.nonce, st.phoneNonce || st.nonce, st.ctCli, ctPhone);
  return hkdf(sha256, concat(st.ssCli, ssPhone), transcript, ascii('okt/pair/v1'), N);
}

/**
 * Phone step 3, after Brad checked the code and approved (Pair + confirm):
 * -> PAIR_DONE {ct to the CLI, MAC} and a PENDING record, stored only once the
 * CLI's PAIR_CONFIRM proves it derived the same secret.
 */
function phonePairApprove(state, now, { peerAddress } = {}) {
  const { cipherText, sharedSecret } = xwing.encapsulate(state.cliPub);
  const st = { ...state, phonePub: state.identity.publicKey, phoneNonce: state.nonce };
  const ps = pairingSecret({ ...st, cliNonce: state.cliNonce }, cipherText, sharedSecret);
  /*
   * BOUND TO THE COMPUTER'S NAME AND ITS BLUETOOTH MAC (Brad, 2026-10-04: "pairing
   * uses both NAME and MAC - if one changes = revoke"). The keys alone could be
   * copied to another machine or kept across a rename; a pairing used from another
   * name or another Bluetooth address is revoked (phoneOnHello).
   */
  const record = {
    id: toHex(idOf(state.cliPub)), name: state.name, mac: normMac(peerAddress), cliPub: toHex(state.cliPub), ps: toHex(ps),
    epoch: 0, renewedAt: now, on: true, lastUsed: null, oldPs: [], code: state.code,
  };
  return { pending: record, msg: concat(header(T.DONE), cipherText, mac(ps, 'okt/pair/phone-confirm')) };
}

/** CLI step 3: PAIR_DONE -> the CLI's record to store, and PAIR_CONFIRM for the phone. */
function cliPairOnDone(state, msg, now) {
  const m = parse(msg, T.DONE, 2 + CT + N);
  if (!m) throw fail('EBTPAIR_MSG', 'not the phone\'s pairing result');
  const ctPhone = m.slice(2, 2 + CT);
  const ssPhone = xwing.decapsulate(ctPhone, state.identity.secretKey);
  const ps = pairingSecret({ ...state, cliPub: state.identity.publicKey, cliNonce: state.nonce }, ctPhone, ssPhone);
  if (!same(m.slice(2 + CT), mac(ps, 'okt/pair/phone-confirm'))) throw fail('EBTPAIR_CONFIRM', 'the phone did not derive the same pairing secret - pair again');
  const record = { phoneId: toHex(idOf(state.phonePub)), phonePub: toHex(state.phonePub), id: toHex(idOf(state.identity.publicKey)), ps: toHex(ps), epoch: 0, renewedAt: now, code: state.code };
  return { record, msg: concat(header(T.CONFIRM), mac(ps, 'okt/pair/cli-confirm')) };
}

/** Phone step 4: PAIR_CONFIRM -> the record becomes active (true), or not (false: drop it). */
function phonePairOnConfirm(pending, msg) {
  const m = parse(msg, T.CONFIRM, 2 + N);
  return !!m && same(m.slice(2), mac(fromHex(pending.ps), 'okt/pair/cli-confirm'));
}

/*
 * Phone step 5, after storing the record: PAIRED {MAC}. The CLI stores ITS side
 * only on this, so the two never disagree about whether a pairing exists.
 */
function phonePairAck(record) {
  return concat(header(T.PAIRED), mac(fromHex(record.ps), 'okt/pair/stored'));
}
function cliPairOnAck(record, msg) {
  const m = parse(msg, T.PAIRED, 2 + N);
  return !!m && same(m.slice(2), mac(fromHex(record.ps), 'okt/pair/stored'));
}

/* ------------------------------------------------------------ connections */

function sessionKeys(ps, ss, transcript) {
  const k = hkdf(sha256, concat(ps, ss), transcript, ascii('okt/session/v1'), 2 * N);
  return { c2p: k.slice(0, N), p2c: k.slice(N) };
}
const helloBody = (id, epoch, nameBytes, ephPub) => concat(id, u32(epoch), Uint8Array.of(nameBytes.length), nameBytes, ephPub);

/** CLI: HELLO {pairing id, epoch, computer name, ephemeral pub, MAC(PS)}; keep `state` for HELLO_OK. */
function cliHello(record, { name } = {}) {
  const eph = xwing.keygen();
  const ps = fromHex(record.ps);
  const nameBytes = ascii(String(name ?? record.name ?? '').slice(0, NAME_MAX));
  const body = helloBody(fromHex(record.id), record.epoch, nameBytes, eph.publicKey);
  return { state: { record, eph, body }, msg: concat(header(T.HELLO), body, mac(ps, 'okt/hello/v1', body)) };
}

/*
 * Phone: a HELLO against its records. -> one of
 *   {silence: true}                       unknown, Off, expired, a bad MAC, junk
 *   {alarm: id}                           the MAC verifies under an OLD secret of
 *                                         that pairing: someone copied it - the
 *                                         caller raises the alarm and DROPS it
 *   {revoke: id, reason: 'name'|'mac'}    the right secret, but from another computer
 *                                         name or another Bluetooth address: the
 *                                         caller DELETES the pairing (Brad: "if one
 *                                         changes = revoke")
 *   {session, msg: HELLO_OK, record}      a live session (record: lastUsed set)
 *
 * `peerAddress`: the Bluetooth address the HELLO arrived from (the phone knows it).
 * Only a hello whose MAC verifies can revoke - a forger without the secret gets
 * silence and can't make anyone else's pairing disappear.
 */
function phoneOnHello(records, msg, now, { peerAddress } = {}) {
  const fixed = 2 + ID + 4 + 1 + PUB + N;
  const m = parse(msg, T.HELLO);
  if (!m || m.length < fixed || m.length !== fixed + m[2 + ID + 4]) return { silence: true };
  const nameLen = m[2 + ID + 4];
  const body = m.slice(2, 2 + ID + 4 + 1 + nameLen + PUB);
  const tag = m.slice(2 + ID + 4 + 1 + nameLen + PUB);
  const id = toHex(body.slice(0, ID));
  const epoch = rd32(body, ID);
  const name = td.decode(body.slice(ID + 5, ID + 5 + nameLen));
  const ephPub = body.slice(ID + 5 + nameLen);
  const rec = (records || []).find((r) => r.id === id);
  if (!rec) return { silence: true };
  /* a copied pairing: an old secret still in use after the renewal replaced it */
  for (const old of rec.oldPs || []) {
    if (same(tag, mac(fromHex(old.ps), 'okt/hello/v1', body))) return { alarm: id };
  }
  /*
   * TWO-PHASE RENEWAL (found on the Pixel, 2026-10-04: a short command ended
   * the link before the phone got the CLI's answer, the CLI had already dropped
   * the old secret, and the pairing was dead). The phone keeps the renewed
   * secret as PENDING; the first hello that proves it promotes it, and only
   * then does the old secret join oldPs (the copy alarm). A hello under the
   * current secret means the CLI never kept the renewal: the pending one goes.
   */
  let rec2;
  if (rec.pending && epoch === rec.pending.epoch && same(tag, mac(fromHex(rec.pending.ps), 'okt/hello/v1', body))) {
    rec2 = { ...rec, ps: rec.pending.ps, epoch: rec.pending.epoch, renewedAt: rec.pending.renewedAt, oldPs: [...(rec.oldPs || []), { epoch: rec.epoch, ps: rec.ps }], pending: null };
  } else if (epoch === rec.epoch && same(tag, mac(fromHex(rec.ps), 'okt/hello/v1', body))) {
    rec2 = rec.pending ? { ...rec, pending: null } : rec;
  } else {
    return { silence: true };
  }
  return helloAccepted(rec2, id, name, ephPub, body, now, peerAddress);
}

function helloAccepted(rec, id, name, ephPub, body, now, peerAddress) {
  /* the pairing is bound to the computer's name and its Bluetooth address: either changed -> revoked */
  if (name !== rec.name) return { revoke: id, reason: 'name' };
  if (rec.mac) {
    const from = normMac(peerAddress);
    if (!from) return { silence: true }; /* the caller did not say where it came from: can't check, so no */
    if (from !== rec.mac) return { revoke: id, reason: 'mac' };
  }
  if (!rec.on) return { silence: true };
  if (now - rec.renewedAt > EXPIRES_AFTER) return { silence: true, expired: id };
  const { cipherText, sharedSecret } = xwing.encapsulate(ephPub);
  const transcript = H('OKT-SESSION-v1', body, cipherText);
  const keys = sessionKeys(fromHex(rec.ps), sharedSecret, transcript);
  const okBody = cipherText;
  return {
    session: { send: keys.p2c, recv: keys.c2p, sendCtr: 0, recvCtr: -1, dirSend: 1, dirRecv: 0, id },
    record: { ...rec, lastUsed: now },
    msg: concat(header(T.HELLO_OK), okBody, mac(fromHex(rec.ps), 'okt/hello-ok/v1', body, okBody)),
  };
}

/** CLI: HELLO_OK -> its session (throws on a bad answer - never talks to a phone that can't prove PS). */
function cliOnHelloOk(state, msg) {
  const m = parse(msg, T.HELLO_OK, 2 + CT + N);
  if (!m) throw fail('EBTPAIR_MSG', 'not a hello answer');
  const ct = m.slice(2, 2 + CT);
  const ps = fromHex(state.record.ps);
  if (!same(m.slice(2 + CT), mac(ps, 'okt/hello-ok/v1', state.body, ct))) throw fail('EBTPAIR_PEER', 'the phone did not prove the pairing');
  const ss = xwing.decapsulate(ct, state.eph.secretKey);
  state.eph.secretKey.fill(0); /* forward secrecy: the ephemeral secret dies here */
  const keys = sessionKeys(ps, ss, H('OKT-SESSION-v1', state.body, ct));
  return { send: keys.c2p, recv: keys.p2c, sendCtr: 0, recvCtr: -1, dirSend: 0, dirRecv: 1, id: state.record.id };
}

/* ------------------------------------------------------------ frames */

const iv = (dir, ctr) => concat(Uint8Array.of(dir), new Uint8Array(7), u32(ctr));

/** Seal one message: [ctr 4][AES-256-GCM ct][tag 16]. Mutates the session's send counter. */
function seal(session, plaintext) {
  if (session.sendCtr >= 0xffffffff) throw fail('EBTPAIR_CTR', 'session counter exhausted - reconnect');
  const ctr = session.sendCtr++;
  return concat(u32(ctr), gcm(session.send, iv(session.dirSend, ctr)).encrypt(plaintext));
}

/** Open one frame, or throw. Only a counter higher than the last one is taken. */
function open(session, frame) {
  if (!(frame instanceof Uint8Array) || frame.length < 4 + 16) throw fail('EBTPAIR_FRAME', 'frame too short');
  const ctr = rd32(frame, 0);
  if (ctr <= session.recvCtr) throw fail('EBTPAIR_REPLAY', `frame ${ctr} is not after ${session.recvCtr} (replayed or reordered)`);
  let pt;
  try { pt = gcm(session.recv, iv(session.dirRecv, ctr)).decrypt(frame.slice(4)); } catch { throw fail('EBTPAIR_TAG', 'frame failed authentication'); }
  session.recvCtr = ctr;
  return pt;
}

/* ------------------------------------------------------------ renewal */

const renewDue = (record, now) => now - record.renewedAt >= RENEW_AFTER;

/** Phone, in a session, on day 6+: RENEW_OFFER {ephemeral pub} (send it sealed); keep `state`. */
function phoneRenewOffer() {
  const eph = xwing.keygen();
  return { state: { eph }, payload: concat(header(T.RENEW_OFFER), eph.publicKey) };
}

/**
 * CLI: RENEW_OFFER -> RENEW_ACCEPT {ct, MAC(PS')} (send it sealed) and the record
 * to SAVE: the current secret kept, the renewed one beside it as `next`
 * (two-phase - see phoneOnHello). cliUseNext / cliDropNext settle it on the
 * next connection.
 */
function cliRenewAccept(record, payload, now) {
  const m = parse(payload, T.RENEW_OFFER, 2 + PUB);
  if (!m) throw fail('EBTPAIR_MSG', 'not a renewal offer');
  const { cipherText, sharedSecret } = xwing.encapsulate(m.slice(2));
  const next = hkdf(sha256, concat(fromHex(record.ps), sharedSecret), H('OKT-RENEW-v1', u32(record.epoch), cipherText), ascii('okt/renew/v1'), N);
  return {
    record: { ...record, next: { ps: toHex(next), epoch: record.epoch + 1, renewedAt: now } },
    payload: concat(header(T.RENEW_ACCEPT), cipherText, mac(next, 'okt/renew/confirm', u32(record.epoch + 1))),
  };
}

/** Phone: RENEW_ACCEPT -> the record with the renewed secret PENDING until the CLI first proves it (or null). */
function phoneRenewFinish(record, state, payload, now) {
  const m = parse(payload, T.RENEW_ACCEPT, 2 + CT + N);
  if (!m) return null;
  const ct = m.slice(2, 2 + CT);
  const ss = xwing.decapsulate(ct, state.eph.secretKey);
  state.eph.secretKey.fill(0);
  const next = hkdf(sha256, concat(fromHex(record.ps), ss), H('OKT-RENEW-v1', u32(record.epoch), ct), ascii('okt/renew/v1'), N);
  if (!same(m.slice(2 + CT), mac(next, 'okt/renew/confirm', u32(record.epoch + 1)))) return null;
  return { ...record, pending: { ps: toHex(next), epoch: record.epoch + 1, renewedAt: now } };
}

/** CLI: the renewed secret worked (the phone answered a hello under it) - it becomes the pairing; the old is forgotten. */
function cliUseNext(record) {
  if (!record.next) return record;
  const { next, ...rest } = record;
  return { ...rest, ps: next.ps, epoch: next.epoch, renewedAt: next.renewedAt };
}
/** CLI: the phone never got the renewal (it answered the current secret) - forget the unused one. */
function cliDropNext(record) {
  if (!record.next) return record;
  const { next, ...rest } = record;
  return rest;
}

module.exports = {
  VERSION, T, PAIR_WINDOW, RENEW_AFTER, EXPIRES_AFTER,
  generateIdentity, idOf, codeOf,
  cliPairStart, phonePairOnCommit, cliPairOnKeys, phonePairOnReveal, phonePairApprove, cliPairOnDone, phonePairOnConfirm, phonePairAck, cliPairOnAck,
  cliHello, phoneOnHello, cliOnHelloOk,
  seal, open,
  renewDue, phoneRenewOffer, cliRenewAccept, phoneRenewFinish, cliUseNext, cliDropNext,
};
