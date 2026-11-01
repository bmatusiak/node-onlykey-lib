'use strict';

/**
 * cli/ble-room.js - `onlykey-js --ble`: THE PHONE'S KEY, THROUGH THE ROOM IT JOINED OVER BLUETOOTH (ok-edge plan B4;
 * Brad, 2026-11-01: "the --server/local-mcp-server will hold the ble service, so the mcp server should make
 * communication with ble transparent"; "the cli pair code stuff that gates communication is replaced").
 *
 * This computer runs a local mcp-server with --ble (ok-edge mcp-server/src/localhost/main.js); the phone links to it over
 * Bluetooth and joins its identity's room there with the login proof. The CLI does not talk Bluetooth at all: it asks
 * the server which room the phone is in (/ble, answered to this computer only), comes into that room as an AGENT with
 * this user's agent key (bucket/src/room-agent.js), and - once the owner accepts the computer in the app's Agents list -
 * its pipe is the phone's key session (desktop/session.js on the phone, keyAgents.ts). The pipe itself is
 * cli/transport-desktop.js with this channel, so everything above it is the same code as the desktop app's.
 *
 *   createDesktopPipe({channel: phoneChannel({say})})
 *
 * THE AGENT KEY is a secret of this computer's user: 32 random bytes in ~/.onlykey-js/agent-key, owner-only, made on
 * first use. Its sha256 is the agent id the owner sees and accepts or blocks; a new file is a new computer to accept.
 *
 * THE FIRST USE WAITS FOR THE OWNER: a pending computer is told so ("accept <name> on the phone ...") and the channel
 * waits for the room's answer - the owner's accept or block arrives as an event (the room tells the agent's socket) -
 * up to ACCEPT_MS, then gives up saying so. Accepted once, later runs go straight through.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const trust = require('../desktop/trust');

/* the local mcp-server: its default port (main.js), or ONLYKEY_LOCAL_MCP */
const LOCAL_MCP = 'http://127.0.0.1:8790';
/* a person answering on the phone */
const ACCEPT_MS = 120000;

const bleError = (message) => Object.assign(new Error(message), { code: 'EBLE' });

/** This user's agent key (hex), made owner-only on first use. */
function agentKey(root) {
  const file = path.join(trust.homeRoot(root), 'agent-key');
  try {
    const have = fs.readFileSync(file, 'utf8').trim();
    if (/^[0-9a-f]{64}$/.test(have)) return have;
  } catch { /* none yet */ }
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const key = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(file, `${key}\n`, { mode: 0o600 });
  return key;
}

/* which room the phone joined over Bluetooth, from the local mcp-server */
async function wherePhone(url, fetchFn) {
  let res;
  try {
    res = await fetchFn(`${url}/ble`);
  } catch (e) {
    throw bleError(`no mcp-server at ${url} (${e && e.cause ? e.cause.code || e.cause.message : e && e.message}) - start it with --ble: node mcp-server/src/localhost/main.js --ble`);
  }
  if (res.status === 404 || res.headers.get('content-type') !== 'application/json') throw bleError(`the mcp-server at ${url} has no Bluetooth - start it with --ble`);
  if (!res.ok) throw bleError(`the mcp-server at ${url} answered ${res.status}: ${await res.text()}`);
  const { host, phones } = await res.json();
  if (!phones.length) throw bleError(`no phone has joined the room over Bluetooth (${host}) - on the phone: the Bluetooth tab, Bluetooth MCP on, with Edge logged in`);
  if (phones.length > 1) throw bleError(`more than one phone joined over Bluetooth (${phones.map((p) => p.device.name).join(', ')}) - one at a time`);
  return phones[0];
}

/* the room's answer for a pending computer: accepted, or why not */
function untilAccepted(agent, name, say, acceptMs) {
  if (agent.state === 'accepted') return Promise.resolve();
  say(`>>> accept "${name}" on the phone: the Edge tab, Agents (waiting ${Math.round(acceptMs / 1000)} s)`);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { done(); reject(bleError(`"${name}" was not accepted on the phone in ${Math.round(acceptMs / 1000)} s`)); }, acceptMs);
    const offs = [
      agent.on('state', (s) => {
        if (s === 'accepted') { done(); resolve(); } else if (s === 'blocked' || s === 'removed') { done(); reject(bleError(`the phone's owner ${s} "${name}"`)); }
      }),
      agent.on('close', () => { done(); reject(bleError('the room closed before the phone answered')); }),
    ];
    function done() { clearTimeout(timer); for (const off of offs) off(); }
  });
}

/**
 * The channel factory cli/transport-desktop.js takes ({channel}): each start finds the phone, comes into its room as
 * this computer's agent, waits for the owner's accept, and opens the phone's key session.
 * @param {{url?: string, root?: string, name?: string, say?: (line: string) => void, fetch?: Function, WebSocket?: any, acceptMs?: number}} [o]
 */
function phoneChannel({ url = process.env.ONLYKEY_LOCAL_MCP || LOCAL_MCP, root, name = `${os.hostname()} (onlykey-js)`, say = () => {}, fetch: fetchFn = globalThis.fetch, WebSocket: WS = globalThis.WebSocket, acceptMs = ACCEPT_MS } = {}) {
  const { connectAgent } = require('../bucket/src/room-agent');
  return async () => {
    const phone = await wherePhone(url, fetchFn);
    const agent = await connectAgent({ url, room: phone.room, agentKey: agentKey(root), name, WebSocket: WS });
    try {
      await untilAccepted(agent, name, say, acceptMs);
    } catch (e) {
      agent.close();
      throw e;
    }
    return agent.keyChannel(phone.device.id, { name: `the phone (${phone.device.name})` });
  };
}

module.exports = { phoneChannel, agentKey, LOCAL_MCP };
