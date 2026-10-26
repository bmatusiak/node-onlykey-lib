'use strict';

/**
 * A DEVICE IN ITS IDENTITY'S ROOM ON THE USER'S SERVER (ok-edge plan M2): the carrier the bucket trade runs over when
 * two devices of one identity are not side by side (Brad, 2026-10-26: "when a key gets plugged into the webapp, its a
 * blank bucket, and we need to get remote buckets from other devices that are connected to the same service").
 *
 *   const room = await connectRoom({ url, me, device, WebSocket, randomBytes });
 *   room.peers()                         the other devices online now: [{id, name, kind}]
 *   room.on('peer', ({up|down}) => ..)   a device came or went
 *   await room.request(peerId, message)  one message, its answer (the trade's `send`)
 *   room.serve(async (from, message) => answer)   answer the requests other devices send
 *   room.close()
 *
 * It joins with room.js's proof (the bucket key over the server's host and a fresh nonce - the key alone, no code) and
 * every frame is sealed with room.js's frame key, so the server passes ciphertext between devices it has seen prove
 * themselves. `me` is what the trade uses too: {id, identityPublicKey, bucketKey, certificate}.
 *
 * Pure apart from what it is handed: a WebSocket class (the browser's, Node 22+'s global, or React Native's) and
 * randomness. No timers other than the request deadlines and a keepalive ping the server answers without waking.
 */
const room = require('./room');

const PING_MS = 25000;

/**
 * @param {{url: string, me: {id: string, identityPublicKey: Uint8Array, bucketKey: object, certificate: Uint8Array},
 *   device: {id: string, name: string, kind: string}, WebSocket: any, randomBytes: (n: number) => Uint8Array,
 *   timeoutMs?: number}} o
 */
function connectRoom({ url, me, device, WebSocket: WS, randomBytes, timeoutMs = 15000 }) {
  const base = new URL(url);
  const host = base.host;
  const wsUrl = `${base.protocol === 'https:' ? 'wss:' : 'ws:'}//${host}/ws/${me.id}`;
  const key = room.frameKey(me.bucketKey, me.id);
  const listeners = new Map();
  const emit = (ev, v) => (listeners.get(ev) || []).forEach((l) => { try { l(v); } catch { /* a listener's own trouble */ } });
  const peers = new Map();
  const pending = new Map();
  let handler = null;
  let you = null;
  let seq = 0;
  let ping = null;

  return new Promise((resolve, reject) => {
    const ws = new WS(wsUrl);
    const send = (m) => ws.send(JSON.stringify(m));
    const fail = (why) => {
      for (const [, p] of pending) p.reject(new Error(why));
      pending.clear();
    };
    const joinTimer = setTimeout(() => { reject(new Error(`${host}: no answer to the join within ${timeoutMs} ms`)); try { ws.close(); } catch { /* closed */ } }, timeoutMs);

    ws.onmessage = async (ev) => {
      let m;
      try { m = JSON.parse(typeof ev.data === 'string' ? ev.data : new TextDecoder().decode(ev.data)); } catch { return; }
      switch (m.t) {
        case 'challenge':
          send(room.join(me, { nonce: m.nonce, host }, device));
          return;
        case 'joined':
          clearTimeout(joinTimer);
          you = m.you;
          for (const p of m.peers || []) peers.set(p.id, p);
          ping = setInterval(() => { try { send({ t: 'ping' }); } catch { /* closing */ } }, PING_MS);
          if (ping.unref) ping.unref();
          resolve(api);
          return;
        case 'refused':
          clearTimeout(joinTimer);
          reject(new Error(`${host} refused the join: this key is not this room's identity, or the server's host is not the one it answers on`));
          return;
        case 'peer':
          if (m.up) { peers.set(m.up.id, m.up); emit('peer', { up: m.up }); }
          if (m.down) {
            peers.delete(m.down);
            for (const [id, p] of pending) if (p.to === m.down) { pending.delete(id); p.reject(new Error(`the device ${m.down} left the room`)); }
            emit('peer', { down: m.down });
          }
          return;
        case 'gone':
          for (const [id, p] of pending) if (p.to === m.to) { pending.delete(id); p.reject(new Error(`the device ${m.to} is not in the room`)); }
          return;
        case 'frame': {
          const body = room.openFrame(key, { room: me.id, from: m.from, to: you }, m.body);
          if (!body) return; /* not sealed by a device of this identity for this one: dropped, unanswered */
          if (body.re !== undefined) {
            const p = pending.get(body.re);
            if (p && p.to === m.from) { pending.delete(body.re); p.resolve(body.answer === undefined ? null : body.answer); }
            return;
          }
          if (body.id === undefined || !handler) return;
          let answer = null;
          try { answer = await handler(m.from, body.message); } catch { answer = null; }
          try { send({ t: 'frame', to: m.from, body: room.sealFrame(key, { room: me.id, from: you, to: m.from }, { re: body.id, answer }, randomBytes) }); } catch { /* closed meanwhile */ }
          return;
        }
        default:
      }
    };
    ws.onclose = () => { clearTimeout(joinTimer); if (ping) clearInterval(ping); fail('the room connection closed'); emit('close'); reject(new Error(`${host}: the connection closed before the join`)); };
    ws.onerror = () => { /* onclose follows and says it */ };

    const api = {
      get you() { return you; },
      peers: () => [...peers.values()],
      on(ev, l) { if (!listeners.has(ev)) listeners.set(ev, []); listeners.get(ev).push(l); return api; },
      serve(fn) { handler = fn; return api; },
      request(to, message, { timeoutMs: t = 120000 } = {}) {
        return new Promise((res, rej) => {
          const id = ++seq;
          const timer = setTimeout(() => { if (pending.delete(id)) rej(new Error(`no answer from ${to} within ${t} ms`)); }, t);
          pending.set(id, {
            to,
            resolve: (v) => { clearTimeout(timer); res(v); },
            reject: (e) => { clearTimeout(timer); rej(e); },
          });
          try { send({ t: 'frame', to, body: room.sealFrame(key, { room: me.id, from: you, to }, { id, message }, randomBytes) }); }
          catch (e) { pending.delete(id); clearTimeout(timer); rej(e); }
        });
      },
      close() { try { ws.close(); } catch { /* closed */ } },
    };
  });
}

module.exports = { connectRoom };
