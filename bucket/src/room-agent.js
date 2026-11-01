'use strict';

/**
 * bucket/src/room-agent.js - A COMPUTER AS AN AGENT OF AN IDENTITY'S ROOM, reaching a device's key through it (ok-edge
 * plan B4; Brad, 2026-11-01: "the phone asks over ble to talk to the mcp-server like it was connected to it over
 * websockets"; "the app authorizes/approves ble over to the host using the same mechanism").
 *
 * The room is the one on a local mcp-server (the box's headless server, later the desktop or `onlykey-js --service`),
 * where a phone joined over Bluetooth. The agent does not join - it holds no login proof - it introduces itself with its
 * agent key ({t:'agent', agent_key, name}); the room keeps it pending until the identity's owner accepts it in the app's
 * Agents list, and passes its key-session messages only while accepted (ok-edge mcp-server core room.js).
 *
 *   const a = await connectAgent({url, room, agentKey, name, WebSocket})  -> {you, state, devices}
 *   a.keyChannel(deviceId)   the channel cli/transport-desktop.js takes ({channel}): desktop/protocol.js messages to the
 *                            device's key session (desktop/session.js) and back
 *
 * The agent key is a secret of this computer's user (the CLI keeps it owner-only beside its home); its sha256 is the
 * agent id the owner sees. Over the network it is a bearer secret - fine on 127.0.0.1, sealed by TLS beyond.
 */

/**
 * @param {{url: string, room: string, agentKey: string, name: string, WebSocket: any, timeoutMs?: number}} o
 * @returns {Promise<object>} the agent connection
 */
function connectAgent({ url, room, agentKey, name, WebSocket: WS, timeoutMs = 10000 }) {
  const base = new URL(url);
  const wsUrl = `${base.protocol === 'https:' ? 'wss:' : 'ws:'}//${base.host}/ws/${room}`;
  const listeners = new Map();
  const emit = (ev, v) => (listeners.get(ev) || []).forEach((l) => { try { l(v); } catch { /* a listener's own trouble */ } });
  const on = (ev, l) => { if (!listeners.has(ev)) listeners.set(ev, []); listeners.get(ev).push(l); return () => { listeners.set(ev, (listeners.get(ev) || []).filter((x) => x !== l)); }; };

  return new Promise((resolve, reject) => {
    const ws = new WS(wsUrl);
    const send = (m) => ws.send(JSON.stringify(m));
    let you = null;
    let state = null;
    let devices = [];
    const timer = setTimeout(() => { reject(new Error(`${base.host}: no answer to the agent's hello in ${timeoutMs} ms`)); try { ws.close(); } catch { /* closed */ } }, timeoutMs);
    /* the hello waits for the room's challenge, as a device's join does: before it the room has not taken the socket in */
    ws.onerror = () => { /* onclose follows */ };
    ws.onclose = (ev) => {
      clearTimeout(timer);
      emit('close', { code: ev && ev.code, reason: ev && ev.reason });
      if (!you) reject(new Error(`${base.host} closed the agent's connection${ev && ev.reason ? ` (${ev.reason})` : ''}`));
    };
    ws.onmessage = (ev) => {
      let m;
      try { m = JSON.parse(typeof ev.data === 'string' ? ev.data : String(ev.data)); } catch { return; }
      switch (m.t) {
        case 'challenge':
          /* every socket gets one; an agent answers with its hello, not a join */
          if (!you) send({ t: 'agent', agent_key: agentKey, name });
          return;
        case 'agent':
          state = m.state;
          if (Array.isArray(m.devices)) devices = m.devices;
          if (!you) {
            you = m.you;
            clearTimeout(timer);
            if (state === 'blocked') { reject(new Error('the owner blocked this computer')); return; }
            resolve(api);
          } else emit('state', state);
          return;
        case 'refused':
          clearTimeout(timer);
          reject(new Error(`${base.host} refused the agent: ${m.why}`));
          return;
        case 'devices':
          state = m.state;
          devices = m.devices || [];
          emit('devices', devices);
          return;
        case 'peer':
          emit('peer', m);
          return;
        case 'key': emit('key', m); return;
        case 'key-refused': emit('key-refused', m); return;
        case 'gone': emit('gone', m); return;
        default: return;
      }
    };

    const api = {
      get you() { return you; },
      get state() { return state; },
      get devices() { return devices; },
      on,
      refreshDevices() { send({ t: 'devices' }); },
      close() { try { ws.close(); } catch { /* closed */ } },

      /**
       * The channel cli/transport-desktop.js takes: the device's key session, by its device id. The room's refusal (not
       * accepted yet), the device going, or this connection closing all end it as the protocol's refused / close.
       */
      keyChannel(deviceId, { name: holder = 'the phone' } = {}) {
        const msgs = new Set();
        const closes = new Set();
        const offs = [
          on('key', (k) => { if (k.from === deviceId) for (const f of [...msgs]) f(k.m); }),
          on('key-refused', (k) => { for (const f of [...msgs]) f({ t: 'refused', why: k.why }); }),
          on('gone', (g) => { if (g.to === deviceId) for (const f of [...msgs]) f({ t: 'refused', why: `${holder} is not in the room` }); }),
          on('peer', (p) => { if (p.down === deviceId) for (const f of [...closes]) f(); }),
          on('close', () => { for (const f of [...closes]) f(); }),
        ];
        return Promise.resolve({
          send: (m) => send({ t: 'key', to: deviceId, m }),
          onMessage: (f) => msgs.add(f),
          onClose: (f) => closes.add(f),
          close: () => { for (const off of offs) off(); api.close(); },
          hello: { t: 'hello' },
          name: holder,
        });
      },
    };
  });
}

module.exports = { connectAgent };
