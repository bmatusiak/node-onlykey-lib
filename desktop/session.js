'use strict';

/**
 * desktop/session.js - ONE CONVERSATION BETWEEN A CLI AND A KEY SOMEONE ELSE HOLDS, with no transport of its own
 * (Brad, 2026-11-01, plan B4: "the cli + bluetooth communication works again ... reuse code that we already have").
 *
 * It was desktop/serve.js's inside: the desktop app holds the key and a CLI on the same machine talks to it over a
 * local socket. The same conversation now also runs on the PHONE, the CLI an MCP agent reaching it through the room on
 * a local mcp-server (ok-edge plan B4): only the carrier differs, so the logic is here once and each carrier hands it
 * messages (desktop/protocol.js's: hello / write in, ready / refused / report / error / close out).
 *
 * What it does, as serve.js always did:
 *   1. THE KEY: every report the CLI writes goes to the key, and every report the key sends comes back.
 *   2. THE HOST: an 0xF7 piece is not for the key - its pieces are gathered into the message, answered by the host the
 *      caller gives (hostFor), and the answer goes back in 0xF7 pieces stamped with the request's net.
 *   3. While the host uses the key, the key's reports are the host's (muted). A CLI gets the key's reports only from
 *      its own first write on, and none while the key is being handed over to it.
 *   4. One CLI at a time.
 * Who may talk at all is the CARRIER's question, decided before open(): the desktop's token (desktop/trust.js), the
 * room's accepted agent (ok-edge mcp-server core room.js).
 *
 * Hermes-clean (the phone runs it): no Buffer, no net, no fs.
 */

const { DIR } = require('../src/transport/contract');
const wire = require('../edge/src/wire');
const { TYPE: NOTE_TYPE } = require('../edge/src/note');
const { toBase64, fromBase64 } = require('../src/bytes');

/**
 * @param {object} o
 * @param {object} o.pipe the key's pipe (start, isRunning, write, on 'stream' / 'close', device, interfaces); its
 *   optional beforeWrite() resolves when the holder has handed the key over for a CLI write
 * @param {() => Promise<void>} [o.openKey] makes sure the key is open (default: pipe.start() if not running)
 * @param {(net: 'live'|'test') => {send: Function}} o.hostFor the Edge host for a net
 * @param {string} [o.dev] who answers, in the answer's envelope ('desktop', 'android')
 * @param {string} [o.holder] who holds the key, in what the CLI is told ('the desktop app', 'the phone')
 * @param {(line: string) => void} [o.log]
 * @param {(connected: boolean) => void} [o.onClient] a CLI was accepted (true) / went away (false)
 */
function createKeySession({ pipe, openKey, hostFor, dev = 'desktop', holder = 'the desktop app', log = () => {}, onClient = () => {} }) {
  /* the one CLI: {send(obj), gone(): boolean} */
  let client = null;
  let muted = false;
  /*
   * THE CLI GETS ONLY ITS OWN CONVERSATION (box, 2026-10-24: a ship's budget step read 'answered ""' 29 ms after
   * connecting). The holder reads the key too, between CLI conversations; the reply to its last read can arrive just
   * after a new CLI is accepted. So a CLI is sent the key's reports only from its own first write on.
   */
  let spoke = false;
  /* a CLI write is waiting for the holder to hand the key over: nothing that arrives meanwhile answers it */
  let handing = false;
  let hostQueue = Promise.resolve();
  let asm = wire.createAssembler();
  const ensureKey = openKey || (async () => { if (!pipe.isRunning()) await pipe.start(); });

  const offStream = pipe.on('stream', (ev) => {
    if (!client || muted || !spoke || handing || ev.dir !== DIR.OUT) return;
    client.send({ t: 'report', iface: ev.iface, b64: toBase64(ev.bytes) });
  });
  const offClose = pipe.on('close', (err) => {
    if (client) client.send({ t: 'close', why: (err && err.message) || 'the key went away' });
  });

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
        answer = { ok: false, refusal: 'invalid', detail: `${holder} could not answer: ${e && e.message}` };
      } finally {
        muted = false;
      }
      if (!answer || to !== client) return;
      for (const frame of wire.encode(wire.KIND.ANSWER, wire.answerEnvelope(message, answer, { dev, net: n }))) {
        to.send({ t: 'report', iface: 2, b64: toBase64(frame) });
      }
    });
    return hostQueue;
  }

  function drop(c) {
    if (client !== c) return;
    client = null;
    asm = wire.createAssembler();
    onClient(false);
  }

  return {
    /**
     * A CLI the carrier let in: accepted, or refused (busy, no key) - the reply is sent to it here.
     * @param {{send: (obj: object) => void, gone?: () => boolean}} c
     * @returns {Promise<boolean>} accepted
     */
    async open(c) {
      /* a client whose connection is gone is no client */
      if (client && client.gone && client.gone()) drop(client);
      if (client) { c.send({ t: 'refused', why: `busy: another onlykey-js is talking to the key through ${holder}` }); return false; }
      try {
        await ensureKey();
      } catch (e) {
        c.send({ t: 'refused', why: `${holder} has no key open: ${e && e.message}` });
        return false;
      }
      /*
       * GONE WHILE THE KEY WAS MADE READY (the Windows desktop, 2026-10-25: the CLI gave up meanwhile, was made the
       * client anyway - and every later CLI was refused "busy" until the app restarted)
       */
      if (c.gone && c.gone()) return false;
      client = c;
      spoke = false;
      asm = wire.createAssembler();
      onClient(true);
      const d = pipe.device || null;
      c.send({
        t: 'ready',
        device: d ? { path: d.path, product: d.product, serialNumber: d.serialNumber } : null,
        interfaces: typeof pipe.interfaces === 'function' ? pipe.interfaces() : [],
      });
      return true;
    },

    /** one message from the accepted CLI (a write: for the key, or an 0xF7 piece for the host) */
    async message(c, m) {
      if (c !== client || !m || m.t !== 'write') return;
      const bytes = fromBase64(m.b64 || '');
      if (m.iface === 2 && wire.isEdgeRequestFrame(bytes)) {
        const got = asm.push(bytes);
        if (got && !got.error && got.kind === wire.KIND.REQUEST) answerHost(got.message, c);
        return;
      }
      try {
        /* the holder hands the key over first (pipe.beforeWrite: its own reads finished, the key quiet) */
        if (typeof pipe.beforeWrite === 'function') {
          handing = true;
          try { await pipe.beforeWrite(); } finally { handing = false; }
        }
        spoke = true;
        await pipe.write(m.iface, bytes);
      } catch (e) {
        c.send({ t: 'error', why: (e && e.message) || String(e) });
      }
    },

    /** the CLI's carrier closed */
    close(c) { drop(c); },

    /** the session ends: the pipe is let go of */
    stop() { offStream(); offClose(); if (client) drop(client); },

    /** the host's queue settles (tests) */
    idle: () => hostQueue,
    get connected() { return Boolean(client); },
  };
}

module.exports = { createKeySession };
