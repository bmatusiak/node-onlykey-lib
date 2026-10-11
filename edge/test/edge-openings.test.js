'use strict';
/*
 * FULL CARDS FOR YOUR OTHER DEVICES (Brad, 2026-10-09: "full cards, i want to see them in the
 * budget history list"): a budget's opening words travel with its device's log and are kept
 * only when they check against that log (devices.checkOpenings -> grants.verifyBudgetOpening):
 * the grant-create link, the head before it, the key's checkpoint signature from the press
 * (its P-256 half: an opening is an older checkpoint, "B", 2026-10-10).
 */
const test = require('node:test');
const assert = require('node:assert');
const { request, approve, devices, chain } = require('../src');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');

async function openedBudget(secret, scope = { op: 'sign', slot: 221, cap: 2, identity: 'ssh://claude@nitro16' }) {
  const transport = fakeKey(secret ? { secret } : {});
  const edge = edgeOver(transport);
  await edge.receipt(0, 0, new Uint8Array(32)); /* the fake starts with one owed use */
  const msg = await request.build({ reason: 'TEST: push the work', scopes: [scope], lifetime: 15 });
  const r = await approve.approveRequest(msg, {
    edge, from: 'pc-nitro16', seen: new Set(), ask: async () => 'approve',
    verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }), timeoutMs: 2000,
  });
  assert.equal(r.ok, true, JSON.stringify(r));
  const { publicKey, deviceId } = await edge.publicKey();
  const h = await edge.head();
  const records = await edge.pickup(0, h.seq + 1);
  /* what the opening phone keeps (ok-rn edgeSoftKey Kept), as it travels */
  const opening = {
    grantId: r.budget.grantId, reason: msg.reason, scopes: request.grantScopes(msg), uses: r.budget.uses, lifetime: r.budget.lifetime || 15,
    genesis: r.budget.genesis, signature: r.budget.checkpoint.signature, opened: 1760000000000, from: 'nitro16',
  };
  return { deviceId, publicKey, records, opening };
}

test('an opening whose words match the log is kept; changed words, a wrong budget or another log are not', async () => {
  const { deviceId, publicKey, records, opening } = await openedBudget();
  const kept = devices.checkOpenings({ deviceId, publicKey, records, openings: [opening] });
  assert.equal(kept.length, 1);
  assert.equal('signaturePq' in kept[0], false, 'kept with its P-256 half only');
  assert.equal(kept[0].reason, 'TEST: push the work');
  assert.equal(kept[0].from, 'nitro16');
  for (const bad of [
    { ...opening, reason: 'TEST: something else' },
    { ...opening, scopes: [{ ...opening.scopes[0], identity: 'ssh://someone@else' }] },
    { ...opening, uses: opening.uses + 1 },
    { ...opening, grantId: opening.grantId + 7 },
    { ...opening, signature: '00'.repeat(64) },
    { ...opening, signature: (opening.signature[0] === '0' ? '1' : '0') + opening.signature.slice(1) },
    null, 'nonsense',
  ]) assert.deepEqual(devices.checkOpenings({ deviceId, publicKey, records, openings: [bad] }), [], JSON.stringify(bad));
  const other = await openedBudget(p256.utils.randomSecretKey());
  assert.deepEqual(devices.checkOpenings({ deviceId: other.deviceId, publicKey: other.publicKey, records: other.records, openings: [opening] }), [], 'another log');
  assert.equal(chain.decodeLink(records[records.length - 1].link).grantId, opening.grantId);
});

/*
 * AN IDENTITY NAME ONLY WHERE THE KEY SIGNED IT (2026-10-11): on a stored slot the slot is the key,
 * and a name the computer sent with it is not in the signed subject - the kept opening drops it.
 */
test('a stored-slot scope keeps no identity name; a derived-code scope keeps the one the key signed', async () => {
  const stored = await openedBudget(undefined, { op: 'sign', slot: 2, cap: 2 });
  /* the opening as it travels to another phone, with a name added on the way */
  stored.opening.scopes = stored.opening.scopes.map((sc) => ({ ...sc, identity: 'ssh://not-signed@anywhere' }));
  const [a] = devices.checkOpenings({ deviceId: stored.deviceId, publicKey: stored.publicKey, records: stored.records, openings: [stored.opening] });
  assert.ok(a, 'the opening itself still checks');
  assert.equal('identity' in a.scopes[0], false);
  const derived = await openedBudget();
  const [b] = devices.checkOpenings({ deviceId: derived.deviceId, publicKey: derived.publicKey, records: derived.records, openings: [derived.opening] });
  assert.equal(b.scopes[0].identity, 'ssh://claude@nitro16');
});
