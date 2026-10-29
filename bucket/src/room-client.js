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
 *   room.on('mcp', (m) => ..)            the agents (the server's /mcp, the MCP plan): {ev: 'agent' | 'plan' |
 *                                        'plan-gone' | 'submit' | 'fill' | 'finish', ...} - what an agent asks of
 *                                        this identity, live
 *   await room.agents()                  {agents: [{id, name, state}], plans: [...]} - the room's list, for a device
 *                                        that joins later
 *   await room.setAgent(id, state)       the owner's word on an agent: 'accepted' | 'blocked' | 'removed'
 *   await room.planUpdate(planId, {state, results, receipts, why})   a plan's progress, back to its agent
 *   room.close()
 *
 * It joins with room.js's proof (the bucket key over the server's host and a fresh nonce - the key alone, no code) and
 * every frame is sealed with room.js's frame key, so the server passes ciphertext between devices it has seen prove
 * themselves. `me` is what the trade uses too: {id, identityPublicKey, bucketKey, certificate}.
 *
 * Pure apart from what it is handed: a WebSocket class (the browser's, Node 22+'s global, or React Native's) and
 * randomness. No timers other than the request deadlines and a keepalive ping the server answers without waking.
 *
 * THE AGENTS ARE NOT SEALED (decided 2026-10-28: the server relays plans over TLS; sealing end to end needs tooling an
 * agent does not have): an agent's plan reaches the room in the clear, and the owner's answers go back the same way.
 * Only the room's joined devices hear them or answer - the identity's own key proved each one at its join.
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
  /* the owner's answers to the agents (mcp-re), by the id the server echoes in its reply */
  const mcpPending = new Map();
  let handler = null;
  let you = null;
  let seq = 0;
  let mcpSeq = 0;
  let ping = null;

  return new Promise((resolve, reject) => {
    const ws = new WS(wsUrl);
    const send = (m) => ws.send(JSON.stringify(m));
    const fail = (why) => {
      for (const [, p] of pending) p.reject(new Error(why));
      pending.clear();
      for (const [, p] of mcpPending) p.reject(new Error(why));
      mcpPending.clear();
    };
    const joinTimer = setTimeout(() => { reject(new Error(`${host}: no answer to the join within ${timeoutMs} ms`)); try { ws.close(); } catch { /* closed */ } }, timeoutMs);

    ws.onmessage = async (ev) => {
      let m;
      try { m = JSON.parse(typeof ev.data === 'string' ? ev.data : new TextDecoder().decode(ev.data)); } catch { return; }
      /* a reply to one of this device's mcp-re: its waiter, not a listener */
      if (m.re !== undefined && mcpPending.has(m.re) && (m.t === 'mcp' || m.t === 'error')) {
        const p = mcpPending.get(m.re);
        mcpPending.delete(m.re);
        if (m.t === 'error') p.reject(new Error(`the room refused it: ${m.why}`));
        else p.resolve(m);
        return;
      }
      switch (m.t) {
        case 'mcp': {
          const { t, ...rest } = m;
          emit('mcp', rest);
          return;
        }
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
      /* one answer to the agents' side of the room, and the room's reply ({ev: 'ok' | 'agents', ...}) */
      mcp(op, fields = {}, { timeoutMs: t = 15000 } = {}) {
        return new Promise((res, rej) => {
          const re = ++mcpSeq;
          const timer = setTimeout(() => { if (mcpPending.delete(re)) rej(new Error(`the room did not answer ${op} within ${t} ms`)); }, t);
          mcpPending.set(re, {
            resolve: (v) => { clearTimeout(timer); res(v); },
            reject: (e) => { clearTimeout(timer); rej(e); },
          });
          try { send({ t: 'mcp-re', op, re, ...fields }); } catch (e) { mcpPending.delete(re); clearTimeout(timer); rej(e); }
        });
      },
      async agents() { const r = await api.mcp('agents'); return { agents: r.agents || [], plans: r.plans || [] }; },
      async setAgent(agent, state) { await api.mcp('agent', { agent, state }); },
      async planUpdate(plan, { state, results, receipts, why } = {}) {
        await api.mcp('plan', { plan, ...(state ? { state } : {}), ...(results ? { results } : {}), ...(receipts ? { receipts } : {}), ...(why ? { why } : {}) });
      },
      close() { try { ws.close(); } catch { /* closed */ } },
    };
  });
}

module.exports = { connectRoom };
