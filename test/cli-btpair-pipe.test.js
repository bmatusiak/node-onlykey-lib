'use strict';
/*
 * Part T, T2: the CLI's Bluetooth pipe with a pairing - against a fake ok-rn gate
 * (the phone side of src/btpair, over the fake BLE stack) and the fake key behind it.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const bt = require('../src/btpair');
const store = require('../cli/btpair-store');
const { createBlePipe } = require('../cli/transport-ble');
const { fakeNoble } = require('./helpers/fake-ble');
const { fakeFirmware } = require('./helpers/fake-firmware');
const { IFACE } = require('../src/protocol/msg');
const { DIR } = require('../src/transport/contract');
const { MSG } = require('../src/protocol/msg');

const FAST = { scanMs: 300, connectMs: 300, discoverMs: 300, subscribeMs: 300, helloMs: 400 };
const quiet = () => {};
const cat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
const report = (msg, payload = []) => { const r = new Uint8Array(64); r.set([0xff, 0xff, 0xff, 0xff, msg, ...payload]); return r; };
const tmpHome = () => fs.mkdtempSync(path.join(os.tmpdir(), 'okt-btpair-'));

/* ok-rn's gate, as T3 will build it: pairing only inside the window, then sealed traffic only */
function gate({ windowOpen = true, approve = true, batch = false, mtu } = {}) {
  const g = { windowOpen, approve, records: [], session: null, code: null, renewed: null, plaintextSeen: 0, peer: 'aa:bb:cc:00:11:22', toKey: [], packed: 0 };
  const phone = bt.generateIdentity();
  const firmware = fakeFirmware();
  let pairState = null, pending = null, renewState = null;
  const noble = fakeNoble({
    ...(mtu ? { mtu } : {}),
    onMessage(cmd, msg) {
      const now = Date.now();
      if (cmd === 0x85) {
        if (msg[0] === bt.T.COMMIT) {
          if (!g.windowOpen) return [];
          const r = bt.phonePairOnCommit({ identity: phone, windowOpenUntil: now + bt.PAIR_WINDOW, now }, msg);
          if (!r) return [];
          pairState = r.state;
          return [{ cmd: 0x85, bytes: r.msg }];
        }
        if (msg[0] === bt.T.REVEAL) {
          const r = bt.phonePairOnReveal(pairState, msg, now);
          if (!r) return [];
          g.code = r.code;
          if (!g.approve) return [];
          const a = bt.phonePairApprove(r.state, now, { peerAddress: g.peer });
          pending = a.pending;
          return [{ cmd: 0x85, bytes: a.msg }];
        }
        if (msg[0] === bt.T.CONFIRM) {
          if (!pending || !bt.phonePairOnConfirm(pending, msg)) return [];
          g.records.push(pending);
          const ack = bt.phonePairAck(pending);
          pending = null;
          return [{ cmd: 0x85, bytes: ack }];
        }
        if (msg[0] === bt.T.HELLO) {
          const r = bt.phoneOnHello(g.records, msg, now, { peerAddress: g.peer });
          g.lastHello = r;
          if (!r.session) return [];
          g.session = r.session;
          g.records = g.records.map((x) => (x.id === r.record.id ? r.record : x)); /* a promoted renewal sticks */
          /* a phone that reads several reports per write says so, sealed, right after the hello */
          if (batch) return [{ cmd: 0x85, bytes: r.msg }, { cmd: 0x84, bytes: bt.seal(r.session, Uint8Array.of(0x02, 0x30, 1)) }];
          return [{ cmd: 0x85, bytes: r.msg }];
        }
        return [];
      }
      if (cmd === 0x84 && g.session) {
        const pt = bt.open(g.session, msg);
        if (pt[0] === 0x01) { g.toKey.push(pt.slice(1)); firmware.write(IFACE.VENDOR, pt.slice(1)); }
        if (pt[0] === 0x03 && batch) {
          g.packed += 1;
          for (let i = 1; i < pt.length; i += 64) { g.toKey.push(pt.slice(i, i + 64)); firmware.write(IFACE.VENDOR, pt.slice(i, i + 64)); }
        }
        /* the computer's goodbye - checked first and never a renewal answer, as ok-rn's btTransit.onControl */
        if (pt[0] === 0x02 && pt[1] === 0x31) { g.bye = (g.bye || 0) + 1; return []; }
        if (pt[0] === 0x02 && renewState) {
          const rec = g.records[0];
          g.renewed = bt.phoneRenewFinish(rec, renewState, pt.slice(1), Date.now());
          if (g.renewed) g.records[0] = g.renewed;
        }
        return [];
      }
      if (cmd === 0x83) g.plaintextSeen += 1; /* silence */
      return [];
    },
  });
  /* the key's replies go back sealed - never plaintext */
  firmware.on('stream', (e) => {
    if (e.dir !== DIR.OUT || e.iface !== IFACE.VENDOR || !g.session) return;
    noble.phone.send(0x84, bt.seal(g.session, cat(Uint8Array.of(0x01), Uint8Array.from(e.bytes))));
  });
  g.noble = noble;
  g.offerRenewal = () => {
    const o = bt.phoneRenewOffer();
    renewState = o.state;
    noble.phone.send(0x84, bt.seal(g.session, cat(Uint8Array.of(0x02), o.payload)));
  };
  return g;
}

const pipeOver = (g, opts = {}) => createBlePipe({ platform: 'win32', loadNoble: () => g.noble, timeouts: FAST, log: quiet, ...opts });
const nextOut = (pipe, ms = 1500) => new Promise((resolve) => {
  const t = setTimeout(() => { off(); resolve(null); }, ms);
  const off = pipe.on('stream', (e) => { if (e.dir === DIR.OUT) { clearTimeout(t); off(); resolve(e); } });
});

test('pair, then every report travels sealed: the key answers, nothing readable goes over the air', async () => {
  const home = tmpHome();
  const g = gate();
  /* pair (the `pair` command's steps) */
  const p0 = pipeOver(g);
  await p0.start();
  const lines = [];
  const { record, code } = await store.pairOverPipe(p0, { address: 'PIXEL', home, name: 'NITRO16', out: (l) => lines.push(l), windowWaitMs: 2000, askEveryMs: 300, approveWaitMs: 2000 });
  await p0.stop();
  assert.strictEqual(code, g.code, 'the CLI and the phone showed different codes');
  assert.match(lines[0], new RegExp(code));
  assert.strictEqual(g.records.length, 1);
  assert.strictEqual(g.records[0].name, 'NITRO16');
  assert.deepStrictEqual(store.pairingFor('pixel', home).ps, record.ps, 'not stored (or the address key is case-sensitive)');
  if (process.platform !== 'win32') assert.strictEqual(fs.statSync(store.fileOf(home)).mode & 0o777, 0o600);

  /* a paired run */
  const p = pipeOver(g, { pairing: store.pairingFor('PIXEL', home) });
  const started = await p.start();
  assert.strictEqual(started.encrypted, true);
  const before = g.noble.phone.received.length;
  const reply = nextOut(p);
  await p.write(IFACE.VENDOR, report(MSG.OKCONNECT, [0x66, 0, 0, 0]));
  const r = await reply;
  assert.ok(r, 'no answer from the key through the sealed session');
  assert.strictEqual(r.bytes.length, 64);
  const onAir = g.noble.phone.received.slice(before);
  assert.ok(onAir.every((m) => m.length === 4 + 1 + 64 + 16), 'a report went over the air without the seal');
  assert.strictEqual(g.plaintextSeen, 0);
  await p.stop();
});

test('silence: a pairing the phone does not know (revoked / switched off) fails at once with what to check', async () => {
  const g = gate();
  const stale = { id: '00'.repeat(16), ps: '11'.repeat(32), epoch: 0, renewedAt: Date.now() };
  const p = pipeOver(g, { pairing: stale });
  await assert.rejects(() => p.start(), (e) => e.code === 'ESILENT' && /paired, and switched on/.test(e.message));
  /*
   * ...and the link it opened is CLOSED (the A13, 2026-10-05: a silent hello on a
   * reconnect left it open - the phone showed "connected", stopped advertising,
   * and every later write went out unencrypted and was dropped).
   */
  assert.equal(p.isRunning(), false, 'a pipe with no session reports itself running');
  assert.ok(g.noble.log.some((e) => e[0] === 'disconnect'), 'the link a silent hello met was left open');
});

test('pairing outside the phone\'s window: no answer, nothing stored', async () => {
  const home = tmpHome();
  const g = gate({ windowOpen: false });
  const p = pipeOver(g);
  await p.start();
  await assert.rejects(() => store.pairOverPipe(p, { address: 'PIXEL', home, windowWaitMs: 900, askEveryMs: 300 }), (e) => e.code === 'EBTPAIR_SILENT');
  assert.strictEqual(store.pairingFor('PIXEL', home), null);
  await p.stop();
});

test('renewal on day 6 travels inside the session; the CLI saves the new secret; the copy of the old one raises the alarm', async () => {
  const home = tmpHome();
  const g = gate();
  const p0 = pipeOver(g);
  await p0.start();
  const { record } = await store.pairOverPipe(p0, { address: 'PIXEL', home, windowWaitMs: 2000, askEveryMs: 300, approveWaitMs: 2000 });
  await p0.stop();
  const copied = { ...record }; /* someone copied ~/.onlykey-js before the renewal */
  const saved = [];
  const p = pipeOver(g, { pairing: store.pairingFor('PIXEL', home), onPairingRenewed: (rec) => { saved.push(rec); store.savePairing('PIXEL', rec, home); } });
  await p.start();
  g.offerRenewal();
  for (let i = 0; i < 40 && !g.renewed; i++) await new Promise((r) => setTimeout(r, 25));
  assert.ok(g.renewed, 'the phone never finished the renewal');
  assert.strictEqual(saved.length, 1);
  /* two-phase: saved beside the current secret, the phone holds it pending */
  assert.strictEqual(saved[0].next.epoch, 1);
  assert.strictEqual(store.pairingFor('PIXEL', home).next.ps, g.renewed.pending.ps, 'the CLI did not save the renewed secret');
  await p.stop();
  /* the next connection uses the renewed secret, the phone promotes it, the CLI settles and saves */
  const ok = pipeOver(g, { pairing: store.pairingFor('PIXEL', home), onPairingRenewed: (rec) => store.savePairing('PIXEL', rec, home) });
  assert.strictEqual((await ok.start()).encrypted, true);
  await ok.stop();
  assert.strictEqual(store.pairingFor('PIXEL', home).epoch, 1);
  assert.strictEqual(store.pairingFor('PIXEL', home).next, undefined);
  assert.strictEqual(g.records[0].epoch, 1);
  const thief = pipeOver(g, { pairing: copied });
  await assert.rejects(() => thief.start(), (e) => e.code === 'ESILENT');
  assert.strictEqual(g.lastHello.alarm, record.id, 'the copied pairing raised no alarm');
});

test('the CLI says its CURRENT computer name: after a rename the phone revokes the pairing', async () => {
  const home = tmpHome();
  const g = gate();
  const p0 = pipeOver(g);
  await p0.start();
  await store.pairOverPipe(p0, { address: 'PIXEL', home, name: 'NITRO16', windowWaitMs: 2000, askEveryMs: 300, approveWaitMs: 2000 });
  await p0.stop();
  const same = pipeOver(g, { pairing: store.pairingFor('PIXEL', home), computerName: 'NITRO16' });
  assert.strictEqual((await same.start()).encrypted, true);
  await same.stop();
  const renamed = pipeOver(g, { pairing: store.pairingFor('PIXEL', home), computerName: 'NITRO16-NEW' });
  await assert.rejects(() => renamed.start(), (e) => e.code === 'ESILENT');
  assert.deepStrictEqual({ revoke: g.lastHello.revoke, reason: g.lastHello.reason }, { revoke: g.records[0].id, reason: 'name' });
});

test('a short command still answers a renewal: stop() waits for it (the Pixel, 2026-10-04: status closed the link first, every time)', async () => {
  const home = tmpHome();
  const g = gate();
  const p0 = pipeOver(g);
  await p0.start();
  await store.pairOverPipe(p0, { address: 'PIXEL', home, windowWaitMs: 2000, askEveryMs: 300, approveWaitMs: 2000 });
  await p0.stop();
  /* a slow save (a real disk) keeps the renewal in flight when the command ends */
  const p = pipeOver(g, { pairing: store.pairingFor('PIXEL', home), onPairingRenewed: async (rec) => { await new Promise((r) => setTimeout(r, 200)); store.savePairing('PIXEL', rec, home); } });
  await p.start();
  g.offerRenewal();
  await new Promise((r) => setTimeout(r, 30)); /* the offer is in; the command is already done */
  await p.stop();
  await new Promise((r) => setTimeout(r, 50)); /* the fake phone handles a write on a later tick */
  assert.ok(g.renewed, 'the link closed before the CLI answered the renewal');
  assert.strictEqual(store.pairingFor('PIXEL', home).next.epoch, 1);
});

/*
 * THE DEADLOCK (reproduced on the Pixel, 2026-10-05): a PAIRED link dropped, and
 * the reconnect ran inside the queued write that found it down - its hello was
 * queued behind that same write, never left the PC, timed out, and read as the
 * phone's silence. Only a fresh process got through. The hello now skips the
 * queue while connect() runs it: the next request reconnects ENCRYPTED and is
 * answered.
 */
test('a paired link that drops reconnects inside the next write - the hello is not stuck behind it, the answer comes sealed', async () => {
  const home = tmpHome();
  const g = gate();
  const p0 = pipeOver(g);
  await p0.start();
  await store.pairOverPipe(p0, { address: 'PIXEL', home, windowWaitMs: 2000, askEveryMs: 300, approveWaitMs: 2000 });
  await p0.stop();
  const said = [];
  const p = pipeOver(g, { pairing: store.pairingFor('PIXEL', home), onLink: (l) => said.push(l) });
  assert.strictEqual((await p.start()).encrypted, true);
  g.noble.peripheral(g.noble.phoneId || '24293486eaaf').emit('disconnect', 'the phone app restarted');
  assert.strictEqual(p.isRunning(), false);
  const reply = nextOut(p, 4000);
  await p.write(IFACE.VENDOR, report(MSG.OKCONNECT, [0x66, 0, 0, 0]));
  const r = await reply;
  assert.ok(r, `no answer after the reconnect: ${said.join(' | ')}`);
  assert.strictEqual(p.encrypted, true, 'the reconnect came back without its session');
  assert.ok(said.some((l) => /^reconnected \(encrypted\)/.test(l)), said.join(' | '));
  await p.stop();
});

test('several reports in one write: 9 reports in 2 writes to a phone that reads them; one per write to one that does not, or when the MTU fits fewer than two (Brad, 2026-10-06)', async () => {
  const home = tmpHome();
  const reports = Array.from({ length: 9 }, (_, i) => report(0xe4, [i]));
  async function run(opts) {
    const g = gate(opts);
    const p0 = pipeOver(g);
    await p0.start();
    await store.pairOverPipe(p0, { address: 'PIXEL', home, name: 'NITRO16', out: quiet, windowWaitMs: 2000, askEveryMs: 300, approveWaitMs: 2000 });
    await p0.stop();
    const p = pipeOver(g, { pairing: store.pairingFor('PIXEL', home) });
    assert.strictEqual((await p.start()).encrypted, true);
    await new Promise((r) => setTimeout(r, 50)); /* the phone's announcement lands */
    const echoes = [];
    const off = p.on('stream', (e) => { if (e.dir === DIR.IN) echoes.push(e.bytes); });
    const before = g.noble.phone.fragments.length;
    await p.writeMany(IFACE.VENDOR, reports);
    await new Promise((r) => setTimeout(r, 50)); /* the fake phone acts on a write a turn after acking it */
    off();
    const writes = g.noble.phone.fragments.length - before;
    await p.stop();
    return { g, writes, echoes };
  }
  const packed = await run({ batch: true });
  assert.strictEqual(packed.writes, 2, '9 reports at 7 per write');
  assert.strictEqual(packed.g.packed, 2);
  assert.deepStrictEqual(packed.g.toKey.map((r) => r[5]), [0, 1, 2, 3, 4, 5, 6, 7, 8], 'every report reached the key, in order');
  assert.deepStrictEqual(packed.echoes.map((r) => r[5]), [0, 1, 2, 3, 4, 5, 6, 7, 8], 'echoed one by one, in order');

  const old = await run({ batch: false });
  assert.strictEqual(old.writes, 9, 'a phone that never said so: one report per write');
  assert.strictEqual(old.g.packed, 0);

  const small = await run({ batch: true, mtu: 150 });
  assert.strictEqual(small.g.packed, 0, 'at MTU 150 two reports do not fit one write: one report per write');
  assert.deepStrictEqual(small.g.toKey.map((r) => r[5]), [0, 1, 2, 3, 4, 5, 6, 7, 8]);
});

test('release(): the link is let go, the next write connects fresh and says hello first, and is answered (Brad, 2026-10-06)', async () => {
  const home = tmpHome();
  const g = gate();
  const p0 = pipeOver(g);
  await p0.start();
  await store.pairOverPipe(p0, { address: 'PIXEL', home, name: 'NITRO16', out: quiet, windowWaitMs: 2000, askEveryMs: 300, approveWaitMs: 2000 });
  await p0.stop();
  const seen = g.noble;
  const p = pipeOver(g, { pairing: store.pairingFor('PIXEL', home) });
  await p.start();
  const firstSession = g.session;
  let r = nextOut(p);
  await p.write(IFACE.VENDOR, report(MSG.OKCONNECT, [0x66, 0, 0, 0]));
  assert.ok(await r, 'answered before the release');
  await p.release('idle');
  assert.strictEqual(p.isRunning(), false, 'the link is let go');
  await new Promise((r) => setTimeout(r, 30));
  assert.strictEqual(g.bye, 1, 'the phone was told goodbye, sealed, before the link closed');
  /* the phone loses its session meanwhile (the app's screen re-created) - a fresh hello must not need it */
  g.session = null;
  r = nextOut(p);
  await p.write(IFACE.VENDOR, report(MSG.OKCONNECT, [0x66, 0, 0, 0]));
  assert.ok(await r, 'answered after the release - a new connection, hello first');
  assert.ok(g.session && g.session !== firstSession, 'a new session from a new hello');
  assert.strictEqual(seen, g.noble);
  await p.stop();
});

test('link counts: connects and reconnects are counted, and a failed reconnect is counted and sends nothing (Brad, 2026-10-06)', async () => {
  const home = tmpHome();
  const g = gate();
  const p0 = pipeOver(g);
  await p0.start();
  await store.pairOverPipe(p0, { address: 'PIXEL', home, name: 'NITRO16', out: quiet, windowWaitMs: 2000, askEveryMs: 300, approveWaitMs: 2000 });
  await p0.stop();
  const p = pipeOver(g, { pairing: store.pairingFor('PIXEL', home) });
  await p.start();
  await p.release('idle');
  let r = nextOut(p);
  await p.write(IFACE.VENDOR, report(MSG.OKCONNECT, [0x66, 0, 0, 0]));
  assert.ok(await r);
  assert.deepStrictEqual({ connects: p.linkStats.connects, reconnects: p.linkStats.reconnects, failed: p.linkStats.reconnectsFailed }, { connects: 2, reconnects: 1, failed: 0 });
  assert.ok(typeof p.linkStats.lastUpMs === 'number');
  /* the phone is gone: the reconnect fails, is counted, and the request never goes out */
  await p.release('idle');
  const before = g.noble.phone.received.length;
  g.noble.state = 'poweredOff';
  await assert.rejects(p.write(IFACE.VENDOR, report(MSG.OKCONNECT, [0x66, 0, 0, 0])), /reconnecting failed/);
  assert.strictEqual(p.linkStats.reconnectsFailed, 1);
  assert.strictEqual(g.noble.phone.received.length, before, 'nothing went out');
  g.noble.state = 'poweredOn';
  await p.stop();
});

/*
 * A COMMAND'S END SAYS GOODBYE (A13, 2026-10-07): closing on this side left the LE link
 * up ~3.6 s in Windows, into the next onlykey-js process - its scan waited for it, or its
 * first request got no answer. stop() now tells the phone, sealed, so it lets the link go.
 */
test('stop(): a command\'s end tells the phone goodbye, sealed - not only release()', async () => {
  const home = tmpHome();
  const g = gate();
  const p0 = pipeOver(g);
  await p0.start();
  await store.pairOverPipe(p0, { address: 'PIXEL', home, windowWaitMs: 2000, askEveryMs: 300, approveWaitMs: 2000 });
  await p0.stop();
  const p = pipeOver(g, { pairing: store.pairingFor('PIXEL', home) });
  assert.strictEqual((await p.start()).encrypted, true);
  const before = g.bye || 0;
  await p.stop();
  await new Promise((r) => setTimeout(r, 50)); /* the fake phone handles a write on a later tick */
  assert.strictEqual((g.bye || 0) - before, 1);
});
