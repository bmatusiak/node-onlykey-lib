'use strict';

/*
 * B7 stage 2: EDGE_NOTE - from the paired computer, unsigned, changes nothing, dropped when malformed or replayed.
 * No agent key since 2026-10-08 (Brad: "so the claude key thing is overkill" / "lets cut it out"): the
 * Bluetooth pairing says which computer sent it, so a note carries no signature to check.
 */
const test = require('node:test');
const assert = require('node:assert');
const { note } = require('../src');

test('a note verifies; each field is optional but one must be there', async () => {
  const m = await note.build({ seq: 233, reason: 'git push origin master' });
  assert.deepEqual(note.verify(m), { ok: true });
  assert.equal('signature' in m, false, 'no signature: the pairing is the gate');
  const t = await note.build({ seq: 233, receiptMsg: 'pushed ok-rn' });
  assert.deepEqual(note.verify(t), { ok: true });
  const r = await note.build({ seq: 240, txRefused: 'receipt_owed' });
  assert.deepEqual(note.verify(r), { ok: true });
  await assert.rejects(note.build({ seq: 1 }), /nothing to say/);
});

test('dropped: a replay, a field past its size limit, a bad seq, nothing to say', async () => {
  const m = await note.build({ seq: 7, reason: 'fine' });
  assert.equal(note.verify(m, { seen: new Set([m.nonce]) }).reason, 'replayed');
  await assert.rejects(note.build({ seq: 7, reason: 'x'.repeat(note.MAX_REASON + 1) }), /too long/);
  /* the limits are in bytes, and the app enforces them too - a note it gets is not trusted to be build()'s */
  assert.equal(note.verify({ ...m, reason: 'x'.repeat(note.MAX_REASON + 1) }).reason, 'malformed');
  assert.equal(note.verify({ ...m, reason: '\u00e9'.repeat(note.MAX_REASON / 2 + 1) }).reason, 'malformed', 'bytes, not characters');
  assert.equal(note.verify({ ...m, receiptMsg: 'x'.repeat(note.MAX_RECEIPT_MSG + 1) }).reason, 'malformed');
  assert.equal(note.verify({ ...m, txRefused: 'x'.repeat(note.MAX_TX_REFUSED + 1) }).reason, 'malformed');
  assert.deepEqual(note.verify({ ...m, reason: 'x'.repeat(note.MAX_REASON) }), { ok: true }, 'the limit itself fits');
  assert.equal(note.verify({ ...m, seq: -1 }).reason, 'malformed');
  assert.equal(note.verify({ ...m, reason: undefined }).reason, 'malformed');
});

test('no reason and an empty reason are different notes', async () => {
  const empty = await note.build({ seq: 3, reason: '', receiptMsg: 'm' });
  assert.equal(empty.reason, '');
  assert.deepEqual(note.verify(empty), { ok: true });
  assert.deepEqual(note.verify({ ...empty, receiptMsg: undefined }), { ok: true }, 'an empty reason is still something said');
  assert.equal(note.verify({ ...empty, reason: undefined, receiptMsg: undefined }).reason, 'malformed');
});

/* the client sends them: the reason after a paid use, the message after its receipt, a refused TX start */
test('the edge client sends a note for a use (its reason), its receipt (the message) and a refused TX start', async () => {
  const { approve, client } = require('../src');
  const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.receipt(0, 0, new Uint8Array(32));
  const notes = [];
  const seen = new Set();
  const channel = {
    async send(msg) {
      if (msg.type === note.TYPE) {
        assert.deepEqual(note.verify(msg, { seen }), { ok: true });
        notes.push(msg);
        return { ok: true };
      }
      const r = await approve.approveRequest(msg, {
        edge, seen, ask: async () => 'approve',
        verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }), timeoutMs: 2000,
      });
      return r.dropped ? null : r;
    },
  };
  const c = client.createEdgeClient({ edge, channel });
  const b = await c.request({ reason: 'push', scopes: [{ op: 'sign', slot: 222, cap: 2, identity: 'ssh://agent@nitro16' }], ttlMinutes: 10 });
  const used = await b.use(Uint8Array.from([1, 2]), (x) => transport.use(x, { slot: 222 }), { reason: 'git push origin master' });
  assert.deepEqual(notes.map((n) => [n.seq, n.reason]), [[used.link.seq, 'git push origin master']]);
  await b.receipt(used.link, { message: 'pushed' });
  assert.deepEqual(notes[1].receiptMsg, 'pushed');
  assert.equal(notes[1].seq, used.link.seq);
  /* a refused TX start at the KEY: the budget on hold and NO intent (a used-up one now ends at its last receipt and never reaches the key) */
  await edge.hold(b.grantId);
  await assert.rejects(b.use(Uint8Array.from([3]), (x) => transport.use(x, { slot: 222 }), {}), { code: 'EEDGE_TX' });
  assert.ok(notes[2].txRefused, 'the refused TX start is reported in the agent\'s own note');
  /* R13b, budget or no go (Brad, 2026-10-06): WITH an intent too, nothing can pay - refused, never pressed */
  await assert.rejects(b.use(Uint8Array.from([4]), (x) => transport.use(x, { slot: 222 }), { reason: 'again' }), { code: 'EEDGE_TX' });
});

