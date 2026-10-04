'use strict';

/* B7 stage 2: EDGE_NOTE - signed by the registered agent key, changes nothing, dropped otherwise */
const test = require('node:test');
const assert = require('node:assert');
const { note, request } = require('../src/edge');

const AGENT = request.signerFromSecret(new Uint8Array(32).fill(41));
const OTHER = request.signerFromSecret(new Uint8Array(32).fill(42));
const hex = (b) => Buffer.from(b).toString('hex');
const registered = [hex(AGENT.publicKey)];

test('a note from the registered agent verifies; each field is optional but one must be there', async () => {
  const m = await note.build({ signer: AGENT, seq: 233, reason: 'git push origin master' });
  assert.deepEqual(note.verify(m, { registered }), { ok: true });
  const t = await note.build({ signer: AGENT, seq: 233, ticketMsg: 'pushed ok-rn' });
  assert.deepEqual(note.verify(t, { registered }), { ok: true });
  const r = await note.build({ signer: AGENT, seq: 240, armRefused: 'ticket_owed' });
  assert.deepEqual(note.verify(r, { registered }), { ok: true });
  await assert.rejects(note.build({ signer: AGENT, seq: 1 }), /nothing to say/);
});

test('dropped: an unregistered key, edited text, a replay, an oversize reason', async () => {
  const m = await note.build({ signer: AGENT, seq: 7, reason: 'fine' });
  assert.equal(note.verify(await note.build({ signer: OTHER, seq: 7, reason: 'fine' }), { registered }).reason, 'unregistered');
  assert.equal(note.verify({ ...m, reason: 'not what it signed' }, { registered }).reason, 'bad-signature');
  assert.equal(note.verify({ ...m, seq: 8 }, { registered }).reason, 'bad-signature');
  assert.equal(note.verify(m, { registered, seen: new Set([m.nonce]) }).reason, 'replayed');
  await assert.rejects(note.build({ signer: AGENT, seq: 7, reason: 'x'.repeat(note.MAX_REASON + 1) }), /at most 280/);
  assert.equal(note.verify({ ...m, reason: 'x'.repeat(note.MAX_REASON + 1) }, { registered }).reason, 'bad-signature');
});

test('no reason and an empty reason are different notes', async () => {
  const empty = await note.build({ signer: AGENT, seq: 3, reason: '', ticketMsg: 'm' });
  assert.equal(note.verify({ ...empty, reason: undefined }, { registered }).reason, 'bad-signature');
});

/* the client sends them: the reason after a paid use, the message after its ticket, a refused ARM */
test('the edge client sends a note for a use (its reason), its ticket (the message) and a refused ARM', async () => {
  const { approve, client } = require('../src/edge');
  const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.ticket(0, 0, new Uint8Array(32));
  const notes = [];
  const seen = new Set();
  const channel = {
    async send(msg) {
      if (msg.type === note.TYPE) {
        assert.deepEqual(note.verify(msg, { registered, seen }), { ok: true });
        notes.push(msg);
        return { ok: true };
      }
      const r = await approve.approveRequest(msg, {
        edge, registered, seen, ask: async () => 'approve',
        verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }), timeoutMs: 2000,
      });
      return r.dropped ? null : r;
    },
  };
  const c = client.createEdgeClient({ edge, channel, signer: AGENT });
  const b = await c.request({ reason: 'push', scopes: [{ op: 'sign', slot: 222, cap: 1, identity: 'ssh://agent@nitro16' }], ttlMinutes: 10 });
  const used = await b.use(Uint8Array.from([1, 2]), (x) => transport.use(x, { slot: 222 }), { reason: 'git push origin master' });
  assert.deepEqual(notes.map((n) => [n.seq, n.reason]), [[used.link.seq, 'git push origin master']]);
  await b.ticket(used.link, { message: 'pushed' });
  assert.deepEqual(notes[1].ticketMsg, 'pushed');
  assert.equal(notes[1].seq, used.link.seq);
  await assert.rejects(b.use(Uint8Array.from([3]), (x) => transport.use(x, { slot: 222 }), { reason: 'again' }), { code: 'EEDGE_ARM' });
  assert.ok(notes[2].armRefused, 'the refused ARM is reported in the agent\'s own note');
});

