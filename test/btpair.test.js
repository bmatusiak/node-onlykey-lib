'use strict';
/*
 * Part T, T1 (onlykey-edge features/BLUETOOTH-PAIRING-SPEC.md): the pairing and
 * transit crypto between the CLI and ok-rn, with fake CLI users and a fake phone.
 */
const test = require('node:test');
const assert = require('node:assert');
const bt = require('../src/btpair');

const DAY = 24 * 60 * 60 * 1000;
const t0 = Date.UTC(2026, 9, 4, 20, 0, 0);

/* a full pairing: one paired computer (its user's keys), one phone; returns both sides' records */
function pair({ cli = bt.generateIdentity(), phone = bt.generateIdentity(), name = 'NITRO16', now = t0 } = {}) {
  const a = bt.cliPairStart({ identity: cli, name });
  const b = bt.phonePairOnCommit({ identity: phone, windowOpenUntil: now + bt.PAIR_WINDOW, now }, a.msg);
  assert.ok(b, 'the phone ignored a commit inside the window');
  const c = bt.cliPairOnKeys(a.state, b.msg);
  const d = bt.phonePairOnReveal(b.state, c.msg, now);
  assert.ok(d, 'the phone refused a true reveal');
  assert.strictEqual(c.code, d.code, 'the CLI and the phone show different codes');
  const e = bt.phonePairApprove(d.state, now, { peerAddress: PC_MAC }); /* Brad: Pair + confirm */
  const f = bt.cliPairOnDone(c.state, e.msg, now);
  assert.ok(bt.phonePairOnConfirm(e.pending, f.msg), 'the phone did not accept the CLI\'s confirmation');
  return { cli, phone, cliRec: { ...f.record, name }, phoneRec: e.pending, code: c.code };
}

/* the paired computer's Bluetooth address, as the phone sees it */
const PC_MAC = 'aa:bb:cc:00:11:22';

function connect(cliRec, phoneRecs, now = t0, { peerAddress = PC_MAC, name } = {}) {
  const h = bt.cliHello(cliRec, name !== undefined ? { name } : {});
  const r = bt.phoneOnHello(phoneRecs, h.msg, now, { peerAddress });
  if (!r.session) return { phone: r };
  return { phone: r, cli: bt.cliOnHelloOk(h.state, r.msg) };
}

test('pairing: both sides show the same 6-digit code, and derive the same pairing secret', () => {
  const { cliRec, phoneRec, code } = pair();
  assert.match(code, /^\d{6}$/);
  assert.strictEqual(cliRec.ps, phoneRec.ps);
  assert.strictEqual(cliRec.id, phoneRec.id);
  assert.strictEqual(phoneRec.name, 'NITRO16');
  assert.strictEqual(phoneRec.on, true);
});

test('pairing: only while "Pair a computer" is open - before, or after its 2 minutes, silence', () => {
  const cli = bt.generateIdentity(), phone = bt.generateIdentity();
  const a = bt.cliPairStart({ identity: cli, name: 'NITRO16' });
  assert.strictEqual(bt.phonePairOnCommit({ identity: phone, windowOpenUntil: 0, now: t0 }, a.msg), null, 'not open');
  assert.strictEqual(bt.phonePairOnCommit({ identity: phone, windowOpenUntil: t0 - 1, now: t0 }, a.msg), null, 'closed');
  const b = bt.phonePairOnCommit({ identity: phone, windowOpenUntil: t0 + bt.PAIR_WINDOW, now: t0 }, a.msg);
  const c = bt.cliPairOnKeys(a.state, b.msg);
  assert.strictEqual(bt.phonePairOnReveal(b.state, c.msg, t0 + bt.PAIR_WINDOW + 1), null, 'the reveal came after the window');
});

test('pairing: commit-then-reveal - a reveal that differs from what was committed is silence (no grinding after seeing the phone\'s values)', () => {
  const cli = bt.generateIdentity(), other = bt.generateIdentity(), phone = bt.generateIdentity();
  const a = bt.cliPairStart({ identity: cli, name: 'x@y' });
  const b = bt.phonePairOnCommit({ identity: phone, windowOpenUntil: t0 + bt.PAIR_WINDOW, now: t0 }, a.msg);
  /* an attacker who saw the phone's pub and nonce now swaps in another key it ground for a chosen code */
  const swapped = bt.cliPairOnKeys({ ...a.state, identity: other }, b.msg);
  assert.strictEqual(bt.phonePairOnReveal(b.state, swapped.msg, t0), null);
});

test('pairing: a relay in the middle with its own keys shows two DIFFERENT codes', () => {
  const cli = bt.generateIdentity(), phone = bt.generateIdentity(), mitm = bt.generateIdentity();
  /* CLI <-> MITM (as phone) */
  const a = bt.cliPairStart({ identity: cli, name: 'NITRO16' });
  const m1 = bt.phonePairOnCommit({ identity: mitm, windowOpenUntil: t0 + bt.PAIR_WINDOW, now: t0 }, a.msg);
  const c = bt.cliPairOnKeys(a.state, m1.msg);
  /* MITM (as CLI) <-> phone */
  const m2 = bt.cliPairStart({ identity: mitm, name: 'NITRO16' });
  const b = bt.phonePairOnCommit({ identity: phone, windowOpenUntil: t0 + bt.PAIR_WINDOW, now: t0 }, m2.msg);
  const m3 = bt.cliPairOnKeys(m2.state, b.msg);
  const d = bt.phonePairOnReveal(b.state, m3.msg, t0);
  assert.notStrictEqual(c.code, d.code, 'a relay made the codes match');
});

test('pairing: a CLI that did not derive the same secret is never stored (PAIR_CONFIRM checked)', () => {
  const { phoneRec } = pair();
  const forged = Uint8Array.of(bt.T.CONFIRM, bt.VERSION, ...new Uint8Array(32));
  assert.strictEqual(bt.phonePairOnConfirm(phoneRec, forged), false);
});

test('connection + frames: both ways; replayed, reordered or bit-flipped frames are refused', () => {
  const { cliRec, phoneRec } = pair();
  const { phone, cli } = connect(cliRec, [phoneRec]);
  assert.ok(phone.session && cli);
  const f1 = bt.seal(cli, Uint8Array.of(1, 2, 3));
  const f2 = bt.seal(cli, Uint8Array.of(4, 5));
  assert.deepStrictEqual(bt.open(phone.session, f1), Uint8Array.of(1, 2, 3));
  assert.deepStrictEqual(bt.open(phone.session, f2), Uint8Array.of(4, 5));
  assert.throws(() => bt.open(phone.session, f2), (e) => e.code === 'EBTPAIR_REPLAY', 'a replay');
  assert.throws(() => bt.open(phone.session, f1), (e) => e.code === 'EBTPAIR_REPLAY', 'a reorder');
  const back = bt.seal(phone.session, Uint8Array.of(9));
  const flipped = back.slice(); flipped[6] ^= 1;
  assert.throws(() => bt.open(cli, flipped), (e) => e.code === 'EBTPAIR_TAG');
  assert.deepStrictEqual(bt.open(cli, back), Uint8Array.of(9));
  /* a frame for one direction does not open in the other */
  assert.throws(() => bt.open(cli, bt.seal(cli, Uint8Array.of(7))), (e) => e.code === 'EBTPAIR_TAG' || e.code === 'EBTPAIR_REPLAY');
});

test('forward secrecy: recorded traffic does not open with the pairing secret alone', () => {
  const { cliRec, phoneRec } = pair();
  const h = bt.cliHello(cliRec);
  const r = bt.phoneOnHello([phoneRec], h.msg, t0, { peerAddress: PC_MAC });
  const cli = bt.cliOnHelloOk(h.state, r.msg);
  const frame = bt.seal(cli, new TextEncoder().encode('OKGETLABELS'));
  assert.ok(h.state.eph.secretKey.every((x) => x === 0), 'the ephemeral secret was not wiped');
  /* an attacker with PS and the whole recording tries the session keys a hello would give without the ephemeral secret */
  const guess = { recv: require('../src/vendor/exports/@noble/hashes/sha2.js').sha256(new Uint8Array(32)), recvCtr: -1, dirRecv: 0 };
  assert.throws(() => bt.open(guess, frame), (e) => e.code === 'EBTPAIR_TAG');
});

test('silence: unknown, switched Off, revoked, expired, junk and plaintext hellos get no answer', () => {
  const { cliRec, phoneRec } = pair();
  assert.ok(connect(cliRec, [{ ...phoneRec, on: false }]).phone.silence, 'Off');
  assert.ok(connect(cliRec, []).phone.silence, 'revoked (no record)');
  assert.ok(connect(cliRec, [phoneRec], t0 + bt.EXPIRES_AFTER + 1).phone.silence, 'expired (missed the renewal window)');
  assert.ok(bt.phoneOnHello([phoneRec], new Uint8Array(64), t0).silence, 'a plaintext 64-byte report');
  assert.ok(bt.phoneOnHello([phoneRec], Uint8Array.of(0x10, 1, 2, 3), t0).silence, 'junk');
  /* a wrong MAC: someone who knows the id but not the secret */
  assert.ok(connect({ ...cliRec, ps: '00'.repeat(32) }, [phoneRec]).phone.silence, 'a forged hello');
});

/*
 * Spec rule 1: any other user or app on the paired computer is the ATTACKER - no
 * multi-user feature. It has no pairing file, so the best it can do is a hello under
 * a record it made up; the phone answers nothing.
 */
test('another OS user (or app) on the paired computer, without the pairing file, gets silence', () => {
  const { phoneRec } = pair();
  const attacker = bt.generateIdentity(); /* its own home: another identity, no pairing */
  const madeUp = { id: Buffer.from(bt.idOf(attacker.publicKey)).toString('hex'), ps: '11'.repeat(32), epoch: 0 };
  assert.ok(connect(madeUp, [phoneRec]).phone.silence, 'its own id');
  /* it may even learn the paired id (it is not secret) - without the secret, still silence */
  assert.ok(connect({ ...madeUp, id: phoneRec.id }, [phoneRec]).phone.silence, 'the paired id, a guessed secret');
});

test('renewal on day 6, and THE COPY ALARM: after renewal, any use of the old secret = alarm + that pairing dropped', () => {
  const { cliRec, phoneRec } = pair();
  const copied = { ...cliRec }; /* a copy of ~/.onlykey-js taken before the renewal */
  const day6 = t0 + 6 * DAY;
  assert.strictEqual(bt.renewDue(phoneRec, t0 + 5 * DAY), false);
  assert.strictEqual(bt.renewDue(phoneRec, day6), true);
  const { phone, cli } = connect(cliRec, [phoneRec], day6);
  /* inside the session: offer -> accept -> finish */
  const offer = bt.phoneRenewOffer();
  const acc = bt.cliRenewAccept(cliRec, bt.open(cli, bt.seal(phone.session, offer.payload)), day6);
  const renewed = bt.phoneRenewFinish(phoneRec, offer.state, bt.open(phone.session, bt.seal(cli, acc.payload)), day6);
  assert.ok(renewed, 'the renewal did not complete');
  assert.strictEqual(renewed.epoch, 1);
  assert.strictEqual(acc.record.ps, renewed.ps, 'the two sides renewed to different secrets');
  assert.notStrictEqual(renewed.ps, phoneRec.ps);
  /* the CLI connects with the new secret */
  assert.ok(connect(acc.record, [renewed], day6 + 1000).cli, 'the renewed pairing does not connect');
  /* the copy uses the old one -> alarm (the caller drops the pairing) */
  const hit = connect(copied, [renewed], day6 + 2000).phone;
  assert.strictEqual(hit.alarm, renewed.id, 'a copied pairing used after renewal raised no alarm');
  /* after the drop, even the real CLI gets silence until it re-pairs */
  assert.ok(connect(acc.record, [], day6 + 3000).phone.silence);
});

test('a forged renewal answer is refused (the phone keeps its record)', () => {
  const { cliRec, phoneRec } = pair();
  const offer = bt.phoneRenewOffer();
  const acc = bt.cliRenewAccept(cliRec, offer.payload, t0);
  const bad = acc.payload.slice(); bad[bad.length - 1] ^= 1;
  assert.strictEqual(bt.phoneRenewFinish(phoneRec, offer.state, bad, t0), null);
});

/*
 * Brad, 2026-10-04: "pairing uses both NAME and MAC - if one changes = revoke".
 * Only a hello that proves the secret can revoke; a forger gets silence.
 */
test('bound to the computer\'s name and Bluetooth MAC: a rename or another address = revoked; a forger only gets silence', () => {
  const { cliRec, phoneRec } = pair({ name: 'NITRO16' });
  assert.strictEqual(phoneRec.mac, 'AABBCC001122');
  assert.ok(connect(cliRec, [phoneRec], t0, { peerAddress: 'AA-BB-CC-00-11-22' }).cli, 'the same computer, any MAC spelling');
  assert.deepStrictEqual(connect(cliRec, [phoneRec], t0, { name: 'NITRO17' }).phone, { revoke: phoneRec.id, reason: 'name' });
  assert.deepStrictEqual(connect(cliRec, [phoneRec], t0, { peerAddress: '11:22:33:44:55:66' }).phone, { revoke: phoneRec.id, reason: 'mac' });
  /* where it came from unknown: no session, but no revoke either */
  assert.ok(connect(cliRec, [phoneRec], t0, { peerAddress: null }).phone.silence);
  /* a forger without the secret, claiming another name from another address: silence, the pairing stays */
  const forged = connect({ ...cliRec, ps: '22'.repeat(32) }, [phoneRec], t0, { name: 'EVIL', peerAddress: '11:22:33:44:55:66' }).phone;
  assert.deepStrictEqual(forged, { silence: true });
});
