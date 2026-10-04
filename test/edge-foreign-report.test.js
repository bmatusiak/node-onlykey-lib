'use strict';

/*
 * A report that is not the Edge answer arrives while an Edge request waits.
 * The vendor channel is shared with a computer on the phone's Bluetooth bridge:
 * a pressed ssh sign answers when the press lands, long after the bus went
 * quiet. On the A13 (2026-10-04) that signature was stored as link #447194052,
 * the copy read as a rollback, and Sync read nothing past it. HEAD and PICKUP
 * now check their answer's shape; a report that fails is someone else's.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { IFACE } = require('../src/protocol/msg');
const { chain } = require('../src/edge');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

/* the fake key, plus a way to put a stranger's report on the bus before the key's answer */
function sharedBus() {
  const transport = fakeKey();
  const lis = new Set();
  const innerOn = transport.on.bind(transport);
  transport.on = (ev, fn) => {
    const off = innerOn(ev, fn);
    if (ev === 'report') lis.add(fn);
    return () => { off(); lis.delete(fn); };
  };
  const plan = []; /* [{sub, data}] - one stranger per matching write */
  const innerWrite = transport.write.bind(transport);
  transport.write = (iface, frame) => {
    const i = plan.findIndex((p) => frame[4] === 0xf8 && frame[5] === p.sub);
    if (i >= 0) {
      const { data } = plan.splice(i, 1)[0];
      setTimeout(() => lis.forEach((l) => l({ iface: IFACE.VENDOR, data })), 0); /* before the key's 1 ms answer */
    }
    return innerWrite(iface, frame);
  };
  return { transport, edge: edgeOver(transport), stranger: (sub, data) => plan.push({ sub, data }) };
}

async function withLinks(n) {
  const bus = sharedBus();
  await bus.edge.ticket(0, 0, new Uint8Array(32));
  for (let i = 0; i < n; i++) bus.transport.use(crypto.randomBytes(40), { slot: 201 });
  return bus;
}

test('PICKUP skips a signature that lands while it waits: the links come back as the key holds them', async () => {
  const { edge, stranger } = await withLinks(3);
  const h = await edge.head();
  const clean = await edge.pickup(h.oldest, h.seq - h.oldest + 1);
  stranger(0x02, new Uint8Array(crypto.randomBytes(64)));
  const got = await edge.pickup(h.oldest, h.seq - h.oldest + 1);
  assert.equal(got.length, clean.length);
  got.forEach((l, i) => {
    assert.deepEqual(l.link, clean[i].link);
    assert.deepEqual(l.head, clean[i].head);
  });
});

test('PICKUP skips a report shaped like a link but for another seq', async () => {
  const { edge, stranger } = await withLinks(2);
  const h = await edge.head();
  const [real] = await edge.pickup(h.seq, 1);
  const other = chain.encodeLink({ ...chain.decodeLink(real.link), seq: h.seq + 1000 });
  stranger(0x02, other);
  const [got] = await edge.pickup(h.seq, 1);
  assert.equal(chain.decodeLink(got.link).seq, h.seq);
});

test('HEAD skips a signature that lands while it waits', async () => {
  const { edge, stranger } = await withLinks(2);
  const clean = await edge.head();
  const sig = new Uint8Array(crypto.randomBytes(64));
  sig[63] = 0x5a; /* never zero padding */
  stranger(0x01, sig);
  const h = await edge.head();
  assert.equal(h.seq, clean.seq);
  assert.deepEqual(h.head, clean.head);
});
