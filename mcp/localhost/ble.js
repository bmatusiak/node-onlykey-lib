/*
 * THE MCP-SERVER'S BLUETOOTH (ok-edge plan B2; Brad, 2026-11-01: "the --server/local-mcp-server will hold the ble
 * service, so the mcp server should make communication with ble transparent - the phone asks over ble to talk to the
 * mcp-server like it was connected to it over websockets").
 *
 * The phone advertises (its GATT service, VendorGattService.kt); this server is the central: it holds a link to each
 * phone (node-onlykey-lib cli/ble-link.js - BlueZ over D-Bus on Linux, noble on Windows), says its name (HERE), and
 * each socket the phone opens (OPEN {room}) becomes a socket handed to the room exactly as a websocket upgrade is
 * (plugin.js attach) - origin 'ble', so the room asks it for the login proof whatever OPEN_JOIN says (core room.js).
 * The messages are node-onlykey-lib src/transport/ble-socket.js's, the same code the phone runs.
 *
 * In this process: the headless Node server (main.js --ble) loads the Bluetooth stack itself. The desktop's Electron
 * cannot load the noble fork (a native module built for Node's ABI), so its turn (plan B5) runs this in a Node child.
 *
 * A LINK THAT GOES IS OPENED AGAIN: the next open is a pending LE connect (Connect() with a long wait), which the
 * controller completes when the phone advertises again - the phone's coming back is the event. A failed open (the
 * phone's Bluetooth off, out of range past the wait) tries again after a short pause so it never spins; each state is
 * logged once when it changes, not per try.
 */
import os from 'node:os';
import { EventEmitter } from 'node:events';
import bleLinkLib from '../../cli/ble-link.js';
import bleSocket from '../../src/transport/ble-socket.js';

const { CMD_SOCKET, encodeHere, encodeOpened, encodeText, encodeClose, createDecoder } = bleSocket;

/* how long one open waits for the phone to advertise (a pending LE connect), and the pause after one that failed */
const WAIT_FOR_PHONE_MS = 5 * 60 * 1000;
const AFTER_FAILURE_MS = 5000;

/** This server's name over Bluetooth: the host its challenges are for (the phone signs it in the login proof). */
export function defaultHost() {
  return `${os.hostname().toLowerCase().replace(/[^a-z0-9.-]/g, '-')}.ble`;
}

/*
 * ONE PHONE'S SOCKET, as the room and plugin.js handle a websocket: send(text), close(code, reason), terminate(),
 * and 'message' / 'close' events. Sends ride the link in order (ble-link serialises them).
 */
class BleServerSocket extends EventEmitter {
  constructor(link) {
    super();
    this.link = link;
    this.isOpen = true;
  }

  send(text) {
    if (!this.isOpen) throw new Error('the Bluetooth socket is closed');
    for (const p of encodeText(text)) this.link.send(CMD_SOCKET, p).catch((e) => this.gone(1006, e.message));
  }

  close(code = 1000, reason = '') {
    if (!this.isOpen) return;
    this.link.send(CMD_SOCKET, encodeClose({ code, reason })).catch(() => {});
    this.gone(code, reason);
  }

  terminate() { this.gone(1006, 'terminated'); }

  gone(code, reason) {
    if (!this.isOpen) return;
    this.isOpen = false;
    this.emit('close', code, reason);
  }
}

/**
 * Hold Bluetooth links to the phones and hand their sockets to the room.
 *
 * @param {object} o
 * @param {(socket: object, room: string, url: URL) => boolean} o.attach  plugin.js: the socket into the room (false: no such room)
 * @param {string[]} [o.addresses]  the phones (address or Bluetooth name); none = the one bonded phone with the service
 * @param {string} [o.host]  this server's name (defaultHost())
 * @param {(line: string) => void} [o.log]
 * @param {(opts: object) => object} [o.createLink]  cli/ble-link's createBleLink; a test's fake
 * @returns {{stop: () => Promise<void>, phones: () => object[], host: string}}
 */
export function startBle({ attach, addresses = [], host = defaultHost(), log = () => {}, createLink = (opts) => bleLinkLib.createBleLink(opts) }) {
  let stopped = false;
  const live = new Map(); /* address key -> {link, phone} */
  /* each holder's wait, ended by stop() */
  const wakers = new Set();
  const wait = (ms, value) => new Promise((resolve) => {
    const done = () => { clearTimeout(t); wakers.delete(done); resolve(value); };
    const t = ms === null ? null : setTimeout(done, ms);
    wakers.add(done);
  });

  function serve(link, phone, say) {
    const dec = createDecoder();
    let socket = null;
    const here = () => link.send(CMD_SOCKET, encodeHere({ host })).catch(() => {});
    here();
    link.on('message', (m) => {
      if ((m.command & 0x7f) !== (CMD_SOCKET & 0x7f)) return;
      const ev = dec.push(m.bytes);
      if (!ev) return;
      if (ev.kind === 'where') {
        /*
         * THE PHONE HAS NO SOCKET OPEN, THIS SIDE STILL HOLDS ONE (the Pixel, 2026-11-01: a Metro reload restarted the
         * app's JS under a link that stayed up - the room kept the dead socket as the phone, and a computer's onlykey-js
         * waited on it): that socket is gone, as a dropped websocket is.
         */
        if (!ev.open && socket) socket.gone(1006, 'the phone has no socket open (its app started over)');
        here();
        return;
      }
      if (ev.kind === 'open') {
        if (socket) socket.gone(1000, 'replaced');
        const s = new BleServerSocket(link);
        socket = s;
        s.on('close', () => { if (socket === s) socket = null; });
        const url = new URL(`ble://${host}/ws/${ev.room}`);
        link.send(CMD_SOCKET, encodeOpened({ host })).catch(() => {});
        if (!attach(s, ev.room, url)) { s.close(4404, 'no such room'); return; }
        say(`${phone.name}: socket open to room ${ev.room.slice(0, 12)}`);
        return;
      }
      if (!socket) return;
      if (ev.kind === 'text') socket.emit('message', ev.text, false);
      else if (ev.kind === 'close') socket.gone(ev.code, ev.reason);
    });
    link.on('down', () => { if (socket) socket.gone(1006, 'the Bluetooth link went'); });
  }

  async function keep(address) {
    let said = '';
    const say = (line) => { if (line !== said) { said = line; log(line); } };
    while (!stopped) {
      const link = createLink({ address: address || undefined, known: addresses, timeouts: { connectMs: WAIT_FOR_PHONE_MS } });
      const down = new Promise((resolve) => link.on('down', resolve));
      let phone;
      try {
        phone = await link.open();
      } catch (e) {
        say(`no link${address ? ` to ${address}` : ''}: ${e.code ? `${e.code} ` : ''}${String(e.message).split('\n')[0]}`);
        await wait(AFTER_FAILURE_MS);
        continue;
      }
      if (stopped) { await link.close(); return; }
      const key = String(phone.address).toLowerCase();
      live.set(key, { link, phone });
      say(`linked to ${phone.name} (${phone.address}), mtu ${phone.mtu} - its sockets go to the rooms as ${host}`);
      serve(link, phone, say);
      const why = await Promise.race([down, wait(null, 'stopped')]);
      live.delete(key);
      if (why !== 'stopped') say(`${phone.name}: the link went (${why}) - waiting for it to advertise again`);
      await link.close();
    }
  }

  const holders = (addresses.length ? addresses : [null]).map((a) => keep(a));
  return {
    host,
    phones: () => [...live.values()].map((x) => x.phone),
    async stop() {
      stopped = true;
      for (const w of [...wakers]) w();
      await Promise.all([...live.values()].map((x) => x.link.close()));
      await Promise.race([Promise.all(holders), new Promise((r) => setTimeout(r, 3000))]);
    },
  };
}
