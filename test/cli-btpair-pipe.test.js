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
function gate({ windowOpen = true, approve = true } = {}) {
  const g = { windowOpen, approve, records: [], session: null, code: null, renewed: null, plaintextSeen: 0, peer: 'aa:bb:cc:00:11:22' };
  const phone = bt.generateIdentity();
  const firmware = fakeFirmware();
  let pairState = null, pending = null, renewState = null;
  const noble = fakeNoble({
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
          return [{ cmd: 0x85, bytes: r.msg }];
        }
        return [];
      }
      if (cmd === 0x84 && g.session) {
        const pt = bt.open(g.session, msg);
        if (pt[0] === 0x01) firmware.write(IFACE.VENDOR, pt.slice(1));
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
});

test('another OS user (or app) on the paired computer, without the pairing file, gets silence', async () => {
  const g = gate();
  const brad = tmpHome();
  const p0 = pipeOver(g);
  await p0.start();
  await store.pairOverPipe(p0, { address: 'PIXEL', home: brad, name: 'NITRO16', windowWaitMs: 2000, askEveryMs: 300, approveWaitMs: 2000 });
  await p0.stop();
  /* the attacker: another account (another ~), no pairing file - its plaintext request gets no answer */
  const attacker = tmpHome();
  assert.strictEqual(store.pairingFor('PIXEL', attacker), null);
  const p = pipeOver(g, { pairing: store.pairingFor('PIXEL', attacker) });
  const started = await p.start();
  assert.strictEqual(started.encrypted, false);
  const reply = nextOut(p, 600);
  await p.write(IFACE.VENDOR, report(MSG.OKCONNECT, [0x66, 0, 0, 0]));
  assert.strictEqual(await reply, null, 'the gate answered an unpaired user');
  assert.ok(g.plaintextSeen >= 1);
  await p.stop();
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
  assert.strictEqual(saved[0].epoch, 1);
  assert.strictEqual(store.pairingFor('PIXEL', home).ps, g.renewed.ps, 'the CLI did not save the renewed secret');
  await p.stop();
  /* the renewed pairing connects; the copy is the alarm */
  const ok = pipeOver(g, { pairing: store.pairingFor('PIXEL', home) });
  assert.strictEqual((await ok.start()).encrypted, true);
  await ok.stop();
  const thief = pipeOver(g, { pairing: copied });
  await assert.rejects(() => thief.start(), (e) => e.code === 'ESILENT');
  assert.strictEqual(g.lastHello.alarm, record.id, 'the copied pairing raised no alarm');
});
