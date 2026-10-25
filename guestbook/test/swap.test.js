'use strict';

/*
 * Guest Book's in-person key swap (src/swap.js) between two phones, each with a stand-in
 * OnlyKey that holds a real X-Wing key and opens seals the way the device does (async,
 * a 32-byte secret). Everything a pretender, a bystander or a tamperer could try is refused,
 * and the shower's OnlyKey is never asked to press for a peer without the QR's token.
 */

const test = require('node:test');
const assert = require('node:assert');
const nodeCrypto = require('crypto');

const { ml_kem768_x25519: xwing } = require('../../src/vendor/exports/@noble/post-quantum/hybrid.js');
const clipair = require('../../src/clipair');
const { invite: inv, swap } = require('../src');

const randomBytes = (n) => new Uint8Array(nodeCrypto.randomBytes(n));

/** A stand-in OnlyKey: its contact key, and decapsulate counted - every call is a press. */
function onlyKey({ lies = false } = {}) {
  const kp = xwing.keygen();
  const key = {
    presses: 0,
    publicKey: kp.publicKey,
    async decapsulate(ct) {
      key.presses += 1;
      return lies ? randomBytes(32) : xwing.decapsulate(ct, kp.secretKey);
    },
  };
  return key;
}

const ALICE_CARD = { name: 'Alice', keys: [{ format: 'age', label: 'files', text: 'age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq' }] };
const BOB_CARD = { name: 'Bob', keys: [{ format: 'ssh', label: 'laptop', text: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGh3c1h5c2dlbl9rZXlfZm9yX3Rlc3RzX29ubHlfMDAw bob@laptop' }] };

/** Run the handshake; returns both ends, or throws where a side refuses. */
async function handshake({ alice = onlyKey(), bob = onlyKey(), invite, tamper = {} } = {}) {
  const made = inv.makeInvite({ publicKey: alice.publicKey, randomBytes });
  const seen = invite || inv.readInvite(made.url);
  let a = swap.showerStart({ identity: alice, invite: made, randomBytes });
  const b0 = swap.scannerStart({ identity: bob, invite: seen, randomBytes });
  const a1 = swap.showerOnOpen(a, b0.msg);
  const keysMsg = tamper.keys ? tamper.keys(a1.msg) : a1.msg;
  const b1 = swap.scannerOnKeys(b0.state, keysMsg);
  const a2 = await swap.showerOnReveal(a1.state, tamper.reveal ? tamper.reveal(b1.msg) : b1.msg);
  const b2 = await swap.scannerOnDone(b1.state, tamper.done ? tamper.done(a2.msg) : a2.msg);
  const a3 = swap.showerOnConfirm(a2.state, b2.msg);
  return { alice, bob, a: a3, b: b2 };
}

const flip = (i) => (m) => { const c = Uint8Array.from(m); c[i] ^= 1; return c; };

test('the swap: both OnlyKeys press once, both sides learn the other\'s key, the cards cross', async () => {
  const { alice, bob, a, b } = await handshake();
  assert.equal(alice.presses, 1);
  assert.equal(bob.presses, 1);
  assert.deepEqual(a.peer.publicKey, bob.publicKey);
  assert.deepEqual(b.peer.publicKey, alice.publicKey);
  assert.deepEqual(swap.openCard(b.session, swap.sealCard(a.session, ALICE_CARD)), ALICE_CARD);
  assert.deepEqual(swap.openCard(a.session, swap.sealCard(b.session, BOB_CARD)), BOB_CARD);
});

test('a phone that is not the one in the QR is refused before anything is sealed to it', async () => {
  const stand = onlyKey();
  const made = inv.makeInvite({ publicKey: onlyKey().publicKey, randomBytes });
  /* a stand-in answers with its own key, under the real invite's QR */
  const imposter = swap.showerStart({ identity: stand, invite: inv.makeInvite({ publicKey: stand.publicKey, randomBytes }), randomBytes });
  const b0 = swap.scannerStart({ identity: onlyKey(), invite: inv.readInvite(made.url), randomBytes });
  const a1 = swap.showerOnOpen(imposter, b0.msg);
  assert.throws(() => swap.scannerOnKeys(b0.state, a1.msg), (e) => e.code === 'ESWAP_ID');
  assert.equal(stand.presses, 0);
});

test('a phone without the QR\'s token is refused BEFORE the shower\'s OnlyKey is asked to press', async () => {
  const alice = onlyKey();
  const made = inv.makeInvite({ publicKey: alice.publicKey, randomBytes });
  const guessed = { ...inv.readInvite(made.url), token: randomBytes(16) };
  await assert.rejects(handshake({ alice, invite: guessed }), (e) => e.code === 'ESWAP_TOKEN');
  assert.equal(alice.presses, 0, 'the shower pressed for a peer that never saw the QR');
});

test('an OnlyKey that does not hold its key (opens to the wrong secret) is caught by the MAC', async () => {
  await assert.rejects(handshake({ alice: onlyKey({ lies: true }) }), (e) => e.code === 'ESWAP_CONFIRM');
  await assert.rejects(handshake({ bob: onlyKey({ lies: true }) }), (e) => e.code === 'ESWAP_CONFIRM');
});

test('a changed message anywhere in the handshake ends it', async () => {
  /* the shower's key: no longer the QR's */
  await assert.rejects(handshake({ tamper: { keys: flip(10) } }), (e) => e.code === 'ESWAP_ID');
  /* the scanner's key or seal: the token MAC no longer matches */
  await assert.rejects(handshake({ tamper: { reveal: flip(10) } }), (e) => e.code === 'ESWAP_TOKEN');
  /* the shower's seal or confirmation */
  await assert.rejects(handshake({ tamper: { done: flip(10) } }), (e) => e.code === 'ESWAP_CONFIRM');
  await assert.rejects(handshake({ tamper: { done: (m) => flip(m.length - 1)(m) } }), (e) => e.code === 'ESWAP_CONFIRM');
});

test('cards: a tampered, replayed or private one is refused', async () => {
  const { a, b } = await handshake();
  const card = swap.sealCard(a.session, ALICE_CARD);
  assert.throws(() => swap.openCard(b.session, flip(card.length - 3)(card)), (e) => e.code === 'EBTPAIR_TAG');
  swap.openCard(b.session, card);
  assert.throws(() => swap.openCard(b.session, card), (e) => e.code === 'EBTPAIR_REPLAY');

  const privateText = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----';
  assert.throws(() => swap.sealCard(a.session, { name: 'x', keys: [{ format: 'ssh', text: privateText }] }));
  /* a sender that skips sealCard's check: the receiver refuses it too */
  const raw = clipair.seal(a.session, new TextEncoder().encode(JSON.stringify({ name: 'x', keys: [{ format: 'ssh', text: privateText }] })));
  const frame = new Uint8Array(2 + raw.length);
  frame.set([swap.T.CARD, swap.VERSION], 0);
  frame.set(raw, 2);
  assert.throws(() => swap.openCard(b.session, frame));
});

test('steps out of order are refused; an invite made for another key cannot be shown', async () => {
  const alice = onlyKey();
  const made = inv.makeInvite({ publicKey: alice.publicKey, randomBytes });
  const a = swap.showerStart({ identity: alice, invite: made, randomBytes });
  await assert.rejects(swap.showerOnReveal(a, new Uint8Array(4)), (e) => e.code === 'ESWAP_STEP');
  assert.throws(() => swap.showerStart({ identity: onlyKey(), invite: made, randomBytes }), /another contact key/);
});

test('frames: a 60 KB card crosses a 20-byte link and a 244-byte link intact; a gap is refused', () => {
  const { fragment, createAssembler } = require('../src/frames');
  const msg = randomBytes(60000);
  for (const size of [20, 244]) {
    const asm = createAssembler();
    const parts = fragment(msg, size);
    assert.ok(parts.every((p) => p.length <= size));
    let out = null;
    for (const p of parts) out = asm.push(p) || out;
    assert.deepEqual(out, msg);
  }
  const asm = createAssembler();
  const parts = fragment(msg, 244);
  asm.push(parts[0]);
  assert.throws(() => asm.push(parts[2]), /link broke/);
  assert.throws(() => fragment(randomBytes(70000), 244), /at most/);
});

test('goodbye: sealed on the cards\' counter - a card then a goodbye in order; a forged, replayed or unknown one is refused', async () => {
  const { a, b } = await handshake();
  const card = swap.sealCard(a.session, ALICE_CARD);
  const bye = swap.sealBye(a.session, 'done');
  assert.deepEqual(swap.openMessage(b.session, card), { kind: 'card', card: ALICE_CARD });
  assert.deepEqual(swap.openMessage(b.session, bye), { kind: 'bye', reason: 'done' });
  assert.throws(() => swap.openMessage(b.session, bye), (e) => e.code === 'EBTPAIR_REPLAY');
  /* one sealed under another swap's keys */
  const other = await handshake();
  other.a.session.sendCtr = 9; /* ahead of ours, so only its key can refuse it */
  assert.throws(() => swap.openMessage(b.session, swap.sealBye(other.a.session, 'leaving')), (e) => e.code === 'EBTPAIR_TAG');
  assert.throws(() => swap.sealBye(a.session, 'whenever'), /one of done, leaving/);
  assert.deepEqual(swap.openMessage(a.session, swap.sealBye(b.session, 'leaving')), { kind: 'bye', reason: 'leaving' });
});

test('ROTATING QR: the token turns over every 15 s; this window\'s and the last one\'s work, an older photo does not', async () => {
  const alice = onlyKey();
  const t0 = 1_800_000_000_000;
  const made = inv.makeRotatingInvite({ publicKey: alice.publicKey, randomBytes });
  const a = inv.inviteUrlAt(made, t0);
  const b = inv.inviteUrlAt(made, t0 + inv.PERIOD_MS);
  assert.notEqual(a.url, b.url, 'the QR did not change');
  assert.equal(inv.readInvite(a.url).id.join(), inv.readInvite(b.url).id.join(), 'the id changed with the token');
  assert.equal(inv.readInvite(a.url).link.join(), inv.readInvite(b.url).link.join(), 'the link id changed with the token');

  const tryAt = async (url, now) => {
    const sh = swap.showerStart({ identity: alice, invite: made, randomBytes });
    const sc = swap.scannerStart({ identity: onlyKey(), invite: inv.readInvite(url), randomBytes });
    const a1 = swap.showerOnOpen(sh, sc.msg);
    const b1 = swap.scannerOnKeys(sc.state, a1.msg);
    const a2 = await swap.showerOnReveal(a1.state, b1.msg, now);
    const b2 = await swap.scannerOnDone(b1.state, a2.msg);
    return swap.showerOnConfirm(a2.state, b2.msg);
  };
  assert.ok(await tryAt(a.url, t0), 'the code on screen now');
  assert.ok(await tryAt(a.url, t0 + inv.PERIOD_MS), 'the code from the window before (scanned just as it changed)');
  const before = alice.presses;
  await assert.rejects(tryAt(a.url, t0 + 2 * inv.PERIOD_MS), (e) => e.code === 'ESWAP_TOKEN');
  assert.equal(alice.presses, before, 'an old photo cost a press');
});

test('a swap is a trade: an empty card is refused when sealed and when opened', async () => {
  const { a, b } = await handshake();
  assert.throws(() => swap.sealCard(a.session, { name: 'x', keys: [] }), /at least one key/);
  const raw = clipair.seal(a.session, new TextEncoder().encode(JSON.stringify({ name: 'x', keys: [] })));
  const frame = new Uint8Array(2 + raw.length);
  frame.set([swap.T.CARD, swap.VERSION], 0);
  frame.set(raw, 2);
  assert.throws(() => swap.openCard(b.session, frame), /at least one key/);
});

test('frames: progress says how much of the arriving message is in, then null once it is whole', () => {
  const { fragment, createAssembler } = require('../src/frames');
  const msg = randomBytes(1000);
  const parts = fragment(msg, 244);
  const asm = createAssembler();
  assert.equal(asm.progress(), null);
  asm.push(parts[0]);
  assert.deepEqual(asm.progress(), { have: 241, want: 1000 });
  for (const p of parts.slice(1, -1)) asm.push(p);
  assert.ok(asm.progress().have < 1000);
  assert.deepEqual(asm.push(parts[parts.length - 1]), msg);
  assert.equal(asm.progress(), null);
});
