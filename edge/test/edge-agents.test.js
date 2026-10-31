'use strict';
/*
 * THE AGENT IDENTITIES (edge/src/agents.js; Brad, 2026-10-30): a certified list in the identity bucket - created once at a
 * press, never renamed, one per label, picked by label, revoked into the archive. Against the fake key.
 */
const test = require('node:test');
const assert = require('node:assert');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { agents, certify } = require('../src');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

/* today's record (edge/src/identity.js), as `edge setup` made it for nitro16 */
const RECORD = {
  ssh: 'ssh://claude@nitro16', gpgUid: 'Claude (nitro16) <bmatusiak+agent@gmail.com>', committer: { name: 'Claude (nitro16)', email: 'bmatusiak+agent@gmail.com' },
  expires: 31536000,
  cert: { armored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n', fingerprint: '7fbf276c85dd192794b46cc4f75a92949d5603ca', created: 1759550000, expires: 31536000, signPublic: 'ab'.repeat(32) },
};
const ownerOf = async (e) => [await e.ownerPublicKey(), await e.publicKeyPq('owner')];

async function storeWith(e, ...entries) {
  const out = {};
  for (const x of entries) out[x.card.thing.label] = JSON.stringify(x);
  return out;
}

test('the first card comes from today\'s record: same labels, the certificate\'s created time - the gpg key and fingerprint stay', async () => {
  const info = agents.infoFromRecord(RECORD, 'nitro16 claude');
  assert.equal(info.created, RECORD.cert.created, 'the created time the gpg fingerprint is made from');
  assert.deepEqual(info.derive, { ssh: RECORD.ssh, gpg: RECORD.gpgUid });
  assert.deepEqual(agents.certsFromRecord(RECORD).gpg.fingerprint, RECORD.cert.fingerprint.toUpperCase());
});

test('certified at a press, listed as usable, picked by label; no label is refused; a taken label is taken', async () => {
  const e = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey() }));
  const card = await e.certifyAgent(agents.infoFromRecord(RECORD, 'nitro16 claude'));
  const entries = await storeWith(e, { card, certs: agents.certsFromRecord(RECORD) });
  const [ok, okPq] = await ownerOf(e);
  const l = agents.list(entries, ok, okPq, RECORD.cert.created + 10);
  assert.deepEqual(l.map((x) => [x.label, x.status, x.kinds.join(',')]), [['nitro16 claude', 'usable', 'ssh,gpg']]);
  assert.equal(agents.pick(entries, 'nitro16 claude', ok, okPq, RECORD.cert.created + 10).card.thing.derive.ssh, RECORD.ssh);
  assert.throws(() => agents.pick(entries, '', ok, okPq), { code: 'EAGENT_PICK' });
  assert.throws(() => agents.pick(entries, 'another', ok, okPq), { code: 'EAGENT_NONE' });
  assert.equal(agents.taken(entries, 'nitro16 claude'), true);
});

test('revoked: archived - still listed, never picked; expired the same; another owner\'s card is unverified', async () => {
  const owner = p256.utils.randomSecretKey();
  const e = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey(), ownerSecret: owner }));
  const [ok, okPq] = await ownerOf(e);
  const live = await e.certifyAgent({ ...agents.infoFromRecord(RECORD, 'ci signer'), expires: 0 });
  const revoked = await e.certifyRevoke({ label: 'ci signer', created: live.thing.created });
  const entries = await storeWith(e, { card: live, revoked });
  assert.equal(agents.list(entries, ok, okPq)[0].status, 'revoked');
  assert.throws(() => agents.pick(entries, 'ci signer', ok, okPq), { code: 'EAGENT_UNUSABLE' });
  const short = await e.certifyAgent({ ...agents.infoFromRecord(RECORD, 'short lived'), expires: 60 });
  assert.equal(agents.list(await storeWith(e, { card: short }), ok, okPq, RECORD.cert.created + 61)[0].status, 'expired');
  const stranger = edgeOver(fakeKey({ secret: p256.utils.randomSecretKey(), ownerSecret: p256.utils.randomSecretKey() }));
  const theirs = await stranger.certifyAgent(agents.infoFromRecord(RECORD, 'theirs'));
  assert.equal(agents.list(await storeWith(e, { card: theirs }), ok, okPq)[0].status, 'unverified');
  /* a card moved under another label is not that label's */
  const moved = { [`not ${live.thing.label}`]: JSON.stringify({ card: live }) };
  assert.equal(agents.list(moved, ok, okPq)[0].status, 'unverified');
});

test('a budget only inside the agent card\'s derivation labels', async () => {
  const card = { thing: certify.agentCard(agents.infoFromRecord(RECORD, 'nitro16 claude')) };
  assert.equal(agents.budgetAllowed(card, [{ op: 1, slot: 221, cap: 2, identity: RECORD.ssh }, { op: 1, slot: 221, cap: 3, identity: `gpg://${RECORD.gpgUid}` }]).ok, true);
  assert.equal(agents.budgetAllowed(card, [{ op: 1, slot: 221, cap: 1, identity: 'ssh://someone@else' }]).ok, false);
  assert.equal(agents.budgetAllowed(card, [{ op: 1, slot: 2, cap: 1 }]).ok, false, 'a stored slot is no agent identity\'s');
});

test('the messages: LIST, GET by label, CREATE with its creation info; malformed and replayed refused', () => {
  const info = agents.infoFromRecord(RECORD, 'nitro16 claude');
  for (const m of [agents.buildList(), agents.buildGet({ label: 'nitro16 claude' }), agents.buildCreate({ info })]) assert.equal(agents.verify(m).ok, true, m.type);
  const bad = { ...agents.buildCreate({ info }), info: { ...info, label: '' } };
  assert.equal(agents.verify(bad).ok, false);
  const m = agents.buildList();
  assert.equal(agents.verify(m, { seen: new Set([m.nonce]) }).reason, 'replayed');
});
