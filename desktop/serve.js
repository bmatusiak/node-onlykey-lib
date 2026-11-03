'use strict';

/**
 * desktop/serve.js - the ok-edge desktop app's side of `onlykey-js --desktop` (and of plain
 * `onlykey-js` while the app runs), made as the twin of the phone's Bluetooth link (ok-edge TODO B4b;
 * Brad, 2026-10-23: "we treat --desktop like --ble, where the desktop app does the usb talking"; --ble
 * itself was removed 2026-10-30). It gives the CLI two things on one local socket:
 *   1. THE KEY: every report the CLI writes goes to the hard key the app holds, and every report the
 *      key sends comes back - so budget, exec and the key's signing work as on USB.
 *   2. THE HOST: an 0xF7 piece is not for the key. Its pieces are gathered into the message and
 *      answered by the host the caller gives (hostFor): the desktop app's page (ok-edge electron/desktop/hosting.js),
 *      or the CLI's own local-host.js - and the answer goes back in
 *      0xF7 pieces, stamped with the request's net (wire.answerEnvelope). The CLI's wire channel
 *      is the same one any Edge host answers, and needs no other code.
 *
 * THE RECORDS: the desktop app's page answers from the identity bucket it holds, the CLI's local-host.js from
 * the CLI's Edge homes (~/.onlykey-js) - the desktop app reads and merges that same bucket file ("desktop and
 * cli use the same bucket data", Brad, 2026-10-23).
 *
 * THE NET is the request's own (wire.net): one running app answers the testnet and the live chain,
 * each from its own home, and never mixes them.
 *
 * WHILE THE HOST USES THE KEY (a budget's copy check and grant, an identity's), the key's reports are
 * the host's: they are not forwarded to the CLI, whose own transport would read them as answers to
 * nothing. The CLI is waiting for the host's answer then and writes nothing. A note does not touch
 * the key and mutes nothing.
 *
 * One CLI at a time: a second hello is refused "busy" (the key has one conversation).
 *
 * THE CONVERSATION ITSELF IS desktop/session.js (2026-11-01, plan B4): the phone runs the same one over the room on a
 * local mcp-server. This file is the desktop's carrier around it - the local socket, and its gate: the token in
 * desktop.json (the CLI and the app are the same user on this machine).
 */

const net = require('net');
const fs = require('fs');
const trust = require('./trust');
const { createKeySession } = require('./session');
const { HELLO_MS, send, readLines } = require('./protocol');

/**
 * @param {object} o
 * @param {object} o.pipe the hard key's pipe (cli/transport-hid's contract), shared with the app's page;
 *   its optional beforeWrite() resolves when the app has handed the key over for a CLI write
 * @param {() => Promise<void>} [o.openKey] makes sure the pipe is open (default: pipe.start() if not running)
 * @param {(net: 'live'|'test') => {send: Function}} o.hostFor the host for a net (local-host.js)
 * @param {string} [o.root] the shared home (default ~/.onlykey-js)
 * @param {string} [o.socket] where to listen (default trust.socketPath(root))
 * @param {(line: string) => void} [o.log]
 * @param {(b: {kind: 'tunnel'|'edge'|'gone', e: object}) => void} [o.onBusy] the CLI's request progress, for the app's sheet
 * @param {(connected: boolean) => void} [o.onClient] a CLI was accepted (true) / went away (false) -
 *   the app keeps its own key traffic out of the CLI's whole conversation, as the phone's bridge does
 */
function createDesktopServer({ pipe, openKey, hostFor, root, socket, log = () => {}, onClient = () => {}, onBusy = () => {} }) {
  const where = socket || trust.socketPath(root);
  let server = null;
  let record = null;
  const session = createKeySession({ pipe, openKey, hostFor, dev: 'desktop', holder: 'the desktop app', log, onClient, onBusy });
  const sockets = new Set();

  function onConnection(sock) {
    let accepted = false;
    const c = { send: (obj) => send(sock, obj), gone: () => sock.destroyed };
    sockets.add(sock);
    const helloTimer = setTimeout(() => { if (!accepted) sock.destroy(); }, HELLO_MS);
    sock.on('error', () => {});
    sock.on('close', () => { clearTimeout(helloTimer); sockets.delete(sock); session.close(c); });
    readLines(sock, async (m) => {
      if (!accepted) {
        if (m.t !== 'hello' || !trust.tokenMatches(record, m.token)) {
          send(sock, { t: 'refused', why: "not this app's token (desktop.json) - the CLI and the app must be the same user on this machine" });
          sock.end();
          return;
        }
        accepted = await session.open(c);
        clearTimeout(helloTimer);
        if (!accepted) sock.end();
        return;
      }
      await session.message(c, m);
    });
  }

  return {
    get socket() { return where; },
    /** listen, then write desktop.json; returns the trust record */
    async start() {
      if (process.platform !== 'win32') { try { fs.unlinkSync(where); } catch (_) { /* none left */ } }
      server = net.createServer(onConnection);
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(where, resolve); });
      if (process.platform !== 'win32') { try { fs.chmodSync(where, 0o600); } catch (_) { /* best effort */ } }
      record = trust.writeTrust({ root, socket: where });
      log(`desktop: listening on ${where}`);
      return record;
    },
    /** stop listening, drop the CLI, remove desktop.json (if still ours) */
    async stop() {
      session.stop();
      for (const sk of sockets) sk.destroy();
      sockets.clear();
      if (record) trust.removeTrust(record, root);
      record = null;
      if (server) await new Promise((resolve) => server.close(() => resolve()));
      server = null;
      if (process.platform !== 'win32') { try { fs.unlinkSync(where); } catch (_) { /* gone */ } }
    },
    /** the host's queue settles (tests) */
    idle: () => session.idle(),
    get connected() { return session.connected; },
  };
}

module.exports = { createDesktopServer };
