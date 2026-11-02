'use strict';

/*
 * The room as the matrix and the room-sync tests reach it: an identity whose key is a stand-in (its derives and signs are
 * plain hashes of a seed), the mcp-server's room in memory (the join, and the identity's sealed copy by id), and the
 * carriers that dial it - a websocket and a Bluetooth socket (src/transport/ble-socket.js).
 */
const crypto = require('crypto');
const { sha256 } = require('../../../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519, x25519 } = require('../../../src/vendor/exports/@noble/curves/ed25519.js');
const bid = require('../../src/bucket-identity');
const room = require('../../src/room');
const { storeRules } = require('../../src/store-rules');
const bleSocket = require('../../../src/transport/ble-socket');

const rnd = (n) => new Uint8Array(crypto.randomBytes(n));
const HOST = 'ok-edge.example.workers.dev';
const RULES = storeRules();

async function identity(seed) {
  const secretOf = (label, keyType) => sha256(new Uint8Array([...new TextEncoder().encode(seed), ...label, keyType]));
  const key = {
    deriveSecret: async (label, { rpId } = {}) => sha256(new TextEncoder().encode(`${seed}|${label}|${rpId}`)),
    keySite: async () => ({ on: true, site: 'okt.example' }),
    agent: {
      publicKey: async (label, { keyType }) => (keyType === 1 ? ed25519.getPublicKey(secretOf(label, 1)) : x25519.getPublicKey(secretOf(label, 4))),
      ecdh: async (label, peer) => x25519.getSharedSecret(secretOf(label, 4), peer),
      sign: async (label, message) => ed25519.sign(message, secretOf(label, 1)),
    },
  };
  const { publicKey, id } = await bid.readIdentity(key);
  const bucketKey = await bid.deriveBucketKeyAt(key, publicKey, 'okt.example');
  const certificate = await bid.certify(key, publicKey, bucketKey.publicKey);
  return { id, identityPublicKey: publicKey, bucketKey, certificate };
}

/* the room as the mcp-server keeps it, in memory: the join, and the identity's sealed copy (rows by id) */
function fakeServer() {
  const sealed = new Map();
  /* the devices joined now, per room and device id: a second join of an id replaces the first (core/room.js: 4409) */
  const joined = new Map();
  const rowsOf = (r) => { if (!sealed.has(r)) sealed.set(r, new Map()); return sealed.get(r); };
  /* one room socket: deliver(message) is the server's word to the device; text() what the device sent */
  function roomSocket(roomId, deliver, onClose) {
    const { nonce, message } = room.challenge(rnd);
    let device = null;
    setImmediate(() => deliver(message));
    return {
      text(raw) {
        const m = JSON.parse(raw);
        if (!device) {
          const c = room.checkJoin(roomId, m, { nonce, host: HOST });
          if (!c.ok) { deliver({ t: 'refused' }); onClose(); return; }
          device = c.device;
          const key = `${roomId}|${device.id}`;
          const old = joined.get(key);
          joined.set(key, () => onClose(4409));
          if (old) old();
          deliver({ t: 'joined', you: device.id, peers: [] });
          return;
        }
        if (m.t === 'ping') return deliver({ t: 'pong' });
        if (m.t === 'sealed') {
          const rows = rowsOf(roomId);
          if (m.op === 'table') return deliver({ t: 'sealed', re: m.re, on: true, rows: Object.fromEntries([...rows].map(([id, r]) => [id, r.tag])) });
          if (m.op === 'get') return deliver({ t: 'sealed', re: m.re, rows: Object.fromEntries((m.ids || []).filter((id) => rows.has(id)).map((id) => [id, rows.get(id).blob])) });
          if (m.op === 'put') { for (const [id, r] of Object.entries(m.rows || {})) rows.set(id, { tag: r.tag, blob: r.blob }); return deliver({ t: 'sealed', re: m.re, ok: true, n: Object.keys(m.rows || {}).length }); }
          return deliver({ t: 'sealed', re: m.re, ok: false, why: 'no such op' });
        }
        return undefined;
      },
    };
  }
  /* the room over a websocket: a WebSocket-shaped class, as Node's or the browser's */
  class FakeWS {
    constructor(url) {
      this.readyState = 1;
      const roomId = new URL(url).pathname.split('/').pop();
      this.side = roomSocket(roomId, (m) => this.onmessage && this.onmessage({ data: JSON.stringify(m) }), (code) => this.close(code));
      setImmediate(() => this.onopen && this.onopen({}));
    }
    send(text) { this.side.text(text); }
    close(code = 1000) { if (this.readyState === 3) return; this.readyState = 3; setImmediate(() => this.onclose && this.onclose({ code })); }
  }
  /*
   * the room over Bluetooth: the phone's end (createSocketLink) sends 0x86 payloads; this server end decodes them, opens
   * the same room socket on OPEN and answers with OPENED / TEXT - the frames a real link carries, fragments aside
   */
  function bleLink() {
    const dec = bleSocket.createDecoder();
    let side = null;
    let phone = null;
    const toPhone = (payload) => setImmediate(() => phone.push(payload));
    const link = bleSocket.createSocketLink({
      sendFrame: (payload) => {
        const ev = dec.push(payload);
        if (!ev) return;
        if (ev.kind === 'open') {
          side = roomSocket(ev.room, (m) => { for (const p of bleSocket.encodeText(JSON.stringify(m))) toPhone(p); }, () => toPhone(bleSocket.encodeClose({ code: 1000 })));
          toPhone(bleSocket.encodeOpened({ host: HOST }));
        } else if (ev.kind === 'text' && side) side.text(ev.text);
      },
    });
    phone = link;
    toPhone(bleSocket.encodeHere({ host: HOST }));
    return link;
  }
  return { FakeWS, bleLink, sealed };
}

/* a carrier: how a device reaches the identity's room - the url and the WebSocket class room-client dials */
const CARRIERS = {
  websocket: (server) => ({ url: `https://${HOST}`, WebSocket: server.FakeWS }),
  bluetooth: (server) => { const l = server.bleLink(); return { url: `ble://${HOST}`, WebSocket: l.WebSocket }; },
};

module.exports = { rnd, HOST, RULES, identity, fakeServer, CARRIERS };
