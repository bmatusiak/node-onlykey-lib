'use strict';

/**
 * desktop/serve.js - the ok-edge desktop app's side of `onlykey-js --desktop` (and of plain
 * `onlykey-js` while the app runs): the phone's twin on this machine (ok-edge TODO B4b; Brad,
 * 2026-10-23: "we treat --desktop like --ble, where the desktop app does the usb talking").
 *
 * Over Bluetooth the phone gives the CLI two things on one link, and so does this, on one local socket:
 *   1. THE KEY: every report the CLI writes goes to the hard key the app holds, and every report the
 *      key sends comes back - so budget, exec and the key's signing work as on USB.
 *   2. THE HOST: an 0xF7 piece is not for the key. Its pieces are gathered into the message and
 *      answered by the host - local-host.js, the CLI's own (hostFor) - and the answer goes back in
 *      0xF7 pieces, stamped with the request's net (wire.answerEnvelope), exactly as the phone's
 *      bridge answers (ok-edge vendorBridge keepForApp). The CLI's wire channel cannot tell the
 *      app from the phone, and needs no other code.
 *
 * ONE HOST, ONE SET OF RECORDS: the host is the CLI's local-host.js with the CLI's own Edge homes
 * (the bucket in ~/.onlykey-js), so the identity record, the copies and the openings are the same
 * ones the CLI uses alone ("desktop and cli use the same bucket data", Brad, 2026-10-23). Only the
 * person's approval comes from the app's window (the confirm the app gives hostFor).
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
 */

const net = require('net');
const fs = require('fs');
const { DIR } = require('../src/transport/contract');
const wire = require('../edge/src/wire');
const { TYPE: NOTE_TYPE } = require('../edge/src/note');
const trust = require('./trust');
const { HELLO_MS, send, readLines, toB64, fromB64 } = require('./protocol');

/**
 * @param {object} o
 * @param {object} o.pipe the hard key's pipe (cli/transport-hid's contract), shared with the app's page;
 *   its optional beforeWrite() resolves when the app has handed the key over for a CLI write
 * @param {() => Promise<void>} [o.openKey] makes sure the pipe is open (default: pipe.start() if not running)
 * @param {(net: 'live'|'test') => {send: Function}} o.hostFor the host for a net (local-host.js)
 * @param {string} [o.root] the shared home (default ~/.onlykey-js)
 * @param {string} [o.socket] where to listen (default trust.socketPath(root))
 * @param {(line: string) => void} [o.log]
 * @param {(connected: boolean) => void} [o.onClient] a CLI was accepted (true) / went away (false) -
 *   the app keeps its own key traffic out of the CLI's whole conversation, as the phone's bridge does
 */
function createDesktopServer({ pipe, openKey, hostFor, root, socket, log = () => {}, onClient = () => {} }) {
  const where = socket || trust.socketPath(root);
  let server = null;
  let record = null;
  let client = null; /* the one CLI connected and accepted */
  let muted = false;
  /*
   * THE CLI GETS ONLY ITS OWN CONVERSATION (box, 2026-10-24: a ship's budget step read 'answered ""' 29 ms
   * after connecting). The app's page reads the key too, between CLI conversations; the reply to its last
   * read can arrive just after a new CLI is accepted, and the CLI took it for the answer to its connect.
   * So a CLI is sent the key's reports only from its own first write on.
   */
  let spoke = false;
  /* a CLI write is waiting for the app to hand the key over: nothing that arrives meanwhile answers it */
  let handing = false;
  let hostQueue = Promise.resolve();
  const asm = { current: wire.createAssembler() };
  const ensureKey = openKey || (async () => { if (!pipe.isRunning()) await pipe.start(); });

  /* the key's reports to the CLI - the key's own (dir OUT), never the echo of a write */
  const offStream = pipe.on('stream', (ev) => {
    if (!client || muted || !spoke || handing || ev.dir !== DIR.OUT) return;
    send(client, { t: 'report', iface: ev.iface, b64: toB64(ev.bytes) });
  });
  const offClose = pipe.on('close', (err) => {
    if (client) send(client, { t: 'close', why: (err && err.message) || 'the key went away' });
  });

  /* one host message, answered in pieces as the phone answers */
  function answerHost(message, to) {
    const isNote = message && message.type === NOTE_TYPE;
    hostQueue = hostQueue.then(async () => {
      const n = message && message.wire && message.wire.net === 'test' ? 'test' : 'live';
      if (!isNote) muted = true;
      let answer = null;
      try {
        answer = await hostFor(n).send(message, {});
      } catch (e) {
        log(`host: ${e && e.message}`);
        answer = { ok: false, refusal: 'invalid', detail: `the desktop app could not answer: ${e && e.message}` };
      } finally {
        muted = false;
      }
      if (!answer || to !== client) return;
      for (const frame of wire.encode(wire.KIND.ANSWER, wire.answerEnvelope(message, answer, { dev: 'desktop', net: n }))) {
        send(to, { t: 'report', iface: 2, b64: toB64(frame) });
      }
    });
    return hostQueue;
  }

  function onConnection(sock) {
    let accepted = false;
    const helloTimer = setTimeout(() => { if (!accepted) sock.destroy(); }, HELLO_MS);
    sock.on('error', () => {});
    sock.on('close', () => {
      clearTimeout(helloTimer);
      if (client === sock) { client = null; asm.current = wire.createAssembler(); onClient(false); }
    });
    readLines(sock, async (m) => {
      if (!accepted) {
        if (m.t !== 'hello' || !trust.tokenMatches(record, m.token)) {
          send(sock, { t: 'refused', why: 'not this app\'s token (desktop.json) - the CLI and the app must be the same user on this machine' });
          sock.end();
          return;
        }
        /* a client whose connection is gone is no client (its close came while it was being accepted - below) */
        if (client && client.destroyed) { client = null; asm.current = wire.createAssembler(); onClient(false); }
        if (client) { send(sock, { t: 'refused', why: 'busy: another onlykey-js is talking to the key through the desktop app' }); sock.end(); return; }
        try {
          await ensureKey();
        } catch (e) {
          send(sock, { t: 'refused', why: `the desktop app has no key open: ${e && e.message}` });
          sock.end();
          return;
        }
        /*
         * GONE WHILE THE KEY WAS MADE READY (the Windows desktop, 2026-10-25: the key restarting after a restore, the CLI
         * gave up meanwhile; its close found no client to clear, then it was made the client - and every later CLI was
         * refused "busy" until the app restarted)
         */
        if (sock.destroyed) return;
        accepted = true;
        clearTimeout(helloTimer);
        client = sock;
        spoke = false;
        onClient(true);
        asm.current = wire.createAssembler();
        const d = pipe.device || null;
        send(sock, {
          t: 'ready',
          device: d ? { path: d.path, product: d.product, serialNumber: d.serialNumber } : null,
          interfaces: typeof pipe.interfaces === 'function' ? pipe.interfaces() : [],
        });
        return;
      }
      if (m.t !== 'write') return;
      const bytes = fromB64(m.b64);
      if (m.iface === 2 && wire.isEdgeRequestFrame(bytes)) {
        const got = asm.current.push(bytes);
        if (got && !got.error && got.kind === wire.KIND.REQUEST) answerHost(got.message, sock);
        return;
      }
      try {
        /* the app hands the key over first (pipe.beforeWrite: its own reads finished, the key quiet) - what arrives meanwhile is not this CLI's */
        if (typeof pipe.beforeWrite === 'function') {
          handing = true;
          try { await pipe.beforeWrite(); } finally { handing = false; }
        }
        spoke = true;
        await pipe.write(m.iface, bytes);
      } catch (e) {
        send(sock, { t: 'error', why: (e && e.message) || String(e) });
      }
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
      offStream();
      offClose();
      if (client) client.destroy();
      client = null;
      if (record) trust.removeTrust(record, root);
      record = null;
      if (server) await new Promise((resolve) => server.close(() => resolve()));
      server = null;
      if (process.platform !== 'win32') { try { fs.unlinkSync(where); } catch (_) { /* gone */ } }
    },
    /** the host's queue settles (tests) */
    idle: () => hostQueue,
    get connected() { return Boolean(client); },
  };
}

module.exports = { createDesktopServer };
