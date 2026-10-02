'use strict';

/*
 * plugins/edge: the device calls, against a fake transport that answers the
 * way the soft-key firmware plugin does (ok-rn/android/okemu/plugins/edge) -
 * the same report layouts, the same "EDGE:xx" status codes, a real P-256 key
 * for the checkpoints. The firmware itself is tested by its own kit test on
 * the emulator; this pins the host's reading of those bytes.
 */
const test = require('node:test');
const assert = require('node:assert');
const setup = require('../plugins/edge');
const { chain, codes, grants } = require('../src/edge');
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');
const { IFACE } = require('../src/protocol/msg');

const SECRET = new Uint8Array(32).fill(5);
const PUB = p256.getPublicKey(SECRET, false).slice(1);
const DEVICE = chain.deviceIdOf(PUB);

const u32 = (n) => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
const report = (bytes) => { const r = new Uint8Array(64); r.set(bytes.slice(0, 64)); return r; };
const status = (code) => report([...Buffer.from(`EDGE:${code.toString(16).toUpperCase().padStart(2, '0')}`)]);

/* a fake key: a tiny chain, one held link, answers by sub-op */
function fakeKey({ silent = false, noPin = false, delay = 1 } = {}) {
  const listeners = new Set();
  let head = chain.genesis(DEVICE);
  const held = [];
  const live = [];
  const emit = (r) => setTimeout(() => listeners.forEach((l) => l({ iface: IFACE.VENDOR, data: r })), delay);
  const append = (fields) => {
    const seq = held.length;
    const link = chain.encodeLink({ seq, ...fields });
    head = chain.weld(head, link);
    held.push({ link, head });
    return seq;
  };
  const checkpoint = () => {
    const seq = held.length - 1;
    const sig = chain.signCheckpoint({ deviceId: DEVICE, seq, head }, SECRET);
    emit(report([...u32(seq), ...head]));
    emit(report([...sig]));
  };
  /* one approved use, so there is something to pick up and ticket */
  append({ op: codes.OP.SIGN, decision: codes.DECISION.APPROVE, slot: 2, flags: 1, subject: new Uint8Array(32).fill(9) });

  const transport = {
    open() {}, close() {}, isOpen: () => true, request() { throw new Error('not used'); },
    on(event, fn) { if (event === 'report') { listeners.add(fn); return () => listeners.delete(fn); } return () => {}; },
    write(iface, frame) {
      if (silent || frame[4] !== 0xf8) return;
      if (noPin) return emit(status(0x01));
      const sub = frame[5];
      const arg = frame.subarray(6);
      if (sub === 0x01) {
        emit(report([...u32(held.length - 1), ...head, ...u32(0), ...u32(live[0] || 0), ...u32(0), ...u32(0), ...u32(0)]));
      } else if (sub === 0x04) {
        emit(report([...PUB]));
      } else if (sub === 0x03) {
        checkpoint();
      } else if (sub === 0x02) {
        const from = arg[0] | (arg[1] << 8);
        for (let s = from; s < from + arg[4]; s++) {
          if (!held[s]) return emit(status(0x09));
        }
        for (let s = from; s < from + arg[4]; s++) {
          emit(report([...held[s].link]));
          emit(report([...held[s].head, ...new Uint8Array(32)]));
        }
      } else if (sub === 0x20) {
        const ref = arg[0] | (arg[1] << 8);
        if (ref !== held.length - 1) return emit(status(0x08));
        append({ op: codes.OP.TICKET, decision: arg[4], subject: new Uint8Array(32), grantId: ref });
        emit(status(0x00));
      } else if (sub === 0x10) {
        const n = arg[0];
        const scopes = Array.from({ length: n }, (_, j) => ({ op: arg[1 + 4 * j], slot: arg[2 + 4 * j], cap: arg[3 + 4 * j] | (arg[4 + 4 * j] << 8) }));
        const uses = scopes.reduce((a, s) => a + s.cap, 0);
        if (uses > 255) return emit(status(0x04));
        const genesis = grants.grantGenesis(new Uint8Array(32).fill(3), uses);
        const seq = held.length;
        const id = seq + 1;
        append({ op: codes.OP.GRANT_CREATE, decision: 1, flags: 1, grantId: id,
          subject: grants.grantSubject({ scopes, reasonHash: arg.slice(17, 49), genesis }) });
        live.push(id);
        emit(report([...u32(id), uses & 0xff, uses >> 8, ...genesis, ...u32(seq)]));
        checkpoint();
      } else if (sub === 0x12) {
        const id = arg[0] | (arg[1] << 8);
        const i = live.indexOf(id);
        if (i < 0) return emit(status(0x07));
        live.splice(i, 1);
        emit(status(0x00));
      } else {
        emit(status(0x0a));
      }
    },
  };
  return transport;
}

function edgeOver(transport) {
  let edge = null;
  setup({ transport }, (err, services) => { if (err) throw err; edge = services.edge; });
  return edge;
}

test('edge: HEAD, the public key and device id, PICKUP of a held link', async () => {
  const edge = edgeOver(fakeKey());
  const h = await edge.head();
  assert.equal(h.seq, 0);
  assert.equal(h.oldest, 0);
  assert.deepEqual(h.live, []);
  const { publicKey, deviceId } = await edge.publicKey();
  assert.deepEqual(Array.from(publicKey), Array.from(PUB));
  assert.deepEqual(Array.from(deviceId), Array.from(DEVICE));
  const [l] = await edge.pickup(0, 1);
  assert.equal(chain.decodeLink(l.link).op, codes.OP.SIGN);
  assert.equal(l.reveal, null, 'a pressed use has no reveal');
  assert.ok(chain.verify([l], { deviceId, expectHead: { seq: 0, head: h.head } }).ok);
});

test('edge: the checkpoint is read and verifies with the Edge key', async () => {
  const edge = edgeOver(fakeKey());
  const c = await edge.checkpoint();
  assert.ok(chain.verifyCheckpoint({ deviceId: DEVICE, seq: c.seq, head: c.head }, c.signature, PUB));
});

test('edge: a budget\'s opening comes back as a proof verifyBudgetOpening accepts', async () => {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  const before = await edge.head();
  const scopes = [{ op: codes.OP.SIGN, slot: 2, cap: 4 }];
  const reasonHash = new Uint8Array(32).fill(7);
  let asked = false;
  const g = await edge.grant({ scopes, reasonHash, onPress: () => { asked = true; } });
  assert.ok(asked, 'onPress tells the UI to ask for the press');
  assert.equal(g.uses, 4);
  assert.equal(g.seq, 1);
  assert.equal(g.checkpoint.seq, 1);
  const [l] = await edge.pickup(1, 1);
  const r = grants.verifyBudgetOpening({
    deviceId: DEVICE, publicKey: PUB, link: l.link, prevHead: before.head,
    head: g.checkpoint.head, signature: g.checkpoint.signature, scopes, reasonHash, genesis: g.genesis, uses: g.uses,
  });
  assert.deepEqual(r, { ok: true, grantId: g.grantId, seq: 1 });
  assert.deepEqual((await edge.head()).live, [g.grantId]);
  assert.equal(await edge.revoke(g.grantId), true);
});

test('edge: EDGE:xx refusals become named errors', async () => {
  const edge = edgeOver(fakeKey());
  await assert.rejects(edge.revoke(99), (e) => e instanceof edge.EdgeError && e.status === 'no-such-budget' && e.code === 7);
  await assert.rejects(edge.ticket(5, 0, new Uint8Array(32)), (e) => e.status === 'no-ticket-waiting');
  await assert.rejects(edge.pickup(3, 1), (e) => e.status === 'not-held');
  await assert.rejects(edge.grant({ scopes: [{ op: 1, slot: 2, cap: 200 }, { op: 1, slot: 3, cap: 100 }], reasonHash: new Uint8Array(32) }),
    (e) => e.status === 'too-many-uses' || /255/.test(e.message));
  assert.equal(await edge.ticket(0, 0, new Uint8Array(32)), true, 'the use just made takes its ticket');
});

test('edge: a stray report on the bus is not taken as the answer (measured on the Pixel soft key)', async () => {
  /* the key leaves a report behind after an agent sign; the next Edge request must not read it */
  const transport = fakeKey({ delay: 60 }); /* a key slower than the stray: it lands between request and answer */
  const edge = edgeOver(transport);
  const listeners = [];
  const realOn = transport.on;
  transport.on = (ev, fn) => { const off = realOn.call(transport, ev, fn); listeners.push(fn); return off; };
  const stray = report([0x02, 0x0c, 0x79, 0xb1, ...new Uint8Array(60).fill(0xab)]); /* would read as seq 0xB1790C02 */
  setTimeout(() => listeners.forEach((l) => l({ iface: IFACE.VENDOR, data: stray })), 20);
  const h = await edge.head();
  assert.equal(h.seq, 0, 'the stray report was taken as HEAD\'s answer');
});

test('edge: probe - edge, no-pin, or silence (never a hang)', async () => {
  assert.equal(await edgeOver(fakeKey()).probe(), 'edge');
  assert.equal(await edgeOver(fakeKey({ noPin: true })).probe(), 'no-pin');
  const t0 = Date.now();
  assert.equal(await edgeOver(fakeKey({ silent: true })).probe({ timeoutMs: 300 }), 'none');
  assert.ok(Date.now() - t0 < 2000, 'a silent key is answered by the timeout');
});

test('edge: status codes - every code the firmware sends has words on the host', () => {
  for (let c = 0; c <= 0x0a; c++) assert.ok(codes.STATUS[c], `code 0x${c.toString(16)}`);
  assert.deepEqual(codes.parseStatus('EDGE:07'), { code: 7, name: 'no-such-budget', text: codes.STATUS[7].text });
  assert.equal(codes.parseStatus('Error something'), null);
});
