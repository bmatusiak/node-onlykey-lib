/*
 * cli/ssh-agent.js - an ssh-agent whose keys are derived inside the OnlyKey.
 *
 * WHAT IT REPLACES. python lib-agent's `onlykey-agent`: ssh asks an agent for
 * its public keys and for signatures, and this agent answers both by asking
 * the OnlyKey (okcrypto.agent - the derivation lives in the device, keyed by
 * the identity "user@host"). The private key never exists on the host.
 *
 * THREE LAYERS, each testable without the next:
 *
 *   createAgentHandler  one agent message in, one reply out (Buffer -> Buffer).
 *                       Knows the protocol; asks a `sign` function for the
 *                       device's 64 bytes. No socket.
 *   serveAgent          the socket or pipe: framing, one request at a time
 *                       per connection, cleanup. Knows no keys.
 *   defaultAgentPath    where the socket goes when nobody said.
 *
 * The device side - opening the key, the challenge prompt - is the caller's
 * (cli/index.js `agent`), so a test drives this whole file with a fake
 * signer and a real socket.
 *
 * The wire encoding is cli/ssh-wire.js.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const wire = require('./ssh-wire');

const { MSG } = wire;

/* ------------------------------------------------------------ verifying */

/*
 * The fixed DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): the
 * only variable part is the 32-byte key, so node:crypto can take a raw key
 * with no ASN.1 code at all.
 */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * A node:crypto public key for a key the device returned.
 *
 * P-256 goes in as a JWK because that is the one raw-coordinate form
 * node:crypto accepts without DER.
 */
function publicKeyObject(curve, raw) {
  const key = Buffer.from(raw);
  if (curve === 'ed25519') {
    return crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, key]), format: 'der', type: 'spki' });
  }
  return crypto.createPublicKey({
    key: {
      kty: 'EC', crv: 'P-256', x: key.subarray(0, 32).toString('base64url'), y: key.subarray(32, 64).toString('base64url'),
    },
    format: 'jwk',
  });
}

/**
 * Does the device's signature verify, over exactly what ssh will send?
 *
 * WHY CHECK AT ALL. lib-agent does (protocol.py sign_message() calls the key's
 * verifier and refuses a bad signature), and for a reason that is sharper
 * here: the device derives the private key from the identity hash sent WITH
 * the data, so a wrong hash signs perfectly well - with a different key. ssh
 * would pass that to the server, the server would say "Permission denied",
 * and nothing would say why. Verifying turns it into a named failure on the
 * host where it happened.
 *
 * ECDSA is over SHA-256 of the data (RFC 5656 6.2.1 for nistp256), which is
 * what the device computes itself for a message that is not 32 or 64 bytes.
 */
function verifySignature(curve, raw, data, sig) {
  const key = publicKeyObject(curve, raw);
  if (curve === 'ed25519') return crypto.verify(null, data, key, sig);
  return crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, sig);
}

/* ------------------------------------------------------------ the protocol */

/**
 * The agent protocol, over a fixed list of keys.
 *
 * @param {object} opts
 * @param {Array<{curve: string, raw: Uint8Array, comment: string}>} opts.keys
 *   the identities, with the public key the device gave for each (read once,
 *   at start: a public key needs no press and does not change)
 * @param {(key: object, data: Buffer) => Promise<Uint8Array>} opts.sign
 *   the device's 64-byte signature for `data`, with `key` one of `keys`
 * @param {(line: string) => void} [opts.log]  one line of diagnosis (stderr)
 * @returns {{handle: (message: Buffer) => Promise<Buffer>}} `handle` takes
 *   one message (no length word) and resolves to one whole framed reply
 */
function createAgentHandler({ keys, sign, log = () => {} }) {
  const entries = keys.map((k) => ({ ...k, blob: wire.publicKeyBlob(k.curve, k.raw) }));
  const failure = () => wire.frame(Buffer.of(MSG.FAILURE));

  function identities() {
    const parts = [Buffer.of(MSG.IDENTITIES_ANSWER), wire.uint32(entries.length)];
    for (const e of entries) parts.push(wire.string(e.blob), wire.string(e.comment));
    return wire.frame(...parts);
  }

  async function signRequest(r) {
    const blob = r.string();
    const data = r.string();
    /*
     * flags: SSH_AGENT_RSA_SHA2_256 / _512 choose an RSA hash and mean
     * nothing for Ed25519 or ECDSA, whose hash is fixed by the key type
     * (draft-miller-ssh-agent 4.5.1). Read so a malformed request is caught,
     * then ignored, as OpenSSH's own agent ignores them for these keys.
     */
    if (r.remaining >= 4) r.uint32();
    const key = entries.find((e) => e.blob.equals(blob));
    if (!key) {
      log('asked to sign with a key this agent does not hold');
      return failure();
    }
    const sig = Buffer.from(await sign(key, Buffer.from(data)));
    if (!verifySignature(key.curve, key.raw, data, sig)) {
      log(`the OnlyKey's signature for ${key.comment} does not verify against its own public key - not sent`);
      return failure();
    }
    return wire.frame(Buffer.of(MSG.SIGN_RESPONSE), wire.string(wire.signatureBlob(key.curve, sig)));
  }

  async function handle(message) {
    const r = new wire.Reader(message);
    const type = r.uint8();
    try {
      if (type === MSG.REQUEST_IDENTITIES) return identities();
      if (type === MSG.SIGN_REQUEST) return await signRequest(r);
    } catch (err) {
      /*
       * A refused challenge, a timeout, a locked key: ssh gets FAILURE and
       * moves on to its next key or method; the person gets the reason on
       * stderr, because ssh only ever says "agent refused operation".
       */
      log(err && err.message ? err.message : String(err));
      return failure();
    }
    /*
     * Everything else - ADD/REMOVE_IDENTITY, LOCK, the SSH1 messages, and
     * EXTENSION (OpenSSH 8.9+ sends session-bind@openssh.com on every
     * connection) - is FAILURE, as the draft says an agent answers what it
     * does not support. lib-agent answers EXTENSION with
     * SSH_AGENT_EXTENSION_FAILURE (28) instead; the draft keeps 28 for an
     * extension the agent knows but failed, and OpenSSH's own agent sends 5.
     * ssh treats either as "not bound" and carries on.
     */
    return failure();
  }

  return { handle };
}

/* ------------------------------------------------------------ the socket */

/*
 * WHERE THE SOCKET GOES, per platform - and both platforms are kept, never
 * one traded for the other.
 *
 * POSIX: an AF_UNIX socket in a FRESH PRIVATE DIRECTORY (mkdtemp, mode 0700),
 * the layout ssh-agent itself uses (/tmp/ssh-XXXX/agent.<pid>). The directory
 * is what keeps other users out: a socket's own mode is not honoured by every
 * kernel, so the 0600 set on it below is the second lock, not the first.
 *
 * WINDOWS: a named pipe. Windows OpenSSH's ssh.exe and ssh-add.exe take a
 * pipe path in SSH_AUTH_SOCK (or IdentityAgent in ssh_config), defaulting to
 * \\.\pipe\openssh-ssh-agent - which is the "OpenSSH Authentication Agent"
 * SERVICE's pipe. Taking that name would collide with the service whenever it
 * runs, and would silently stand in for it when it does not; so the default
 * is a private name and the caller prints what to set. Node cannot put a
 * security descriptor on the pipe: it gets Windows' default, which gives
 * full access to the creator, SYSTEM and Administrators and READ to
 * Everyone - read is not enough to send a request, so another user cannot
 * ask this agent for a signature.
 *
 * Git for Windows' MSYS ssh cannot use a named pipe at all (its
 * SSH_AUTH_SOCK is a Cygwin-emulated Unix socket), so on Windows this agent
 * serves the Windows OpenSSH client.
 */
const IS_WINDOWS = process.platform === 'win32';
const PIPE_PREFIX = '\\\\.\\pipe\\';

/**
 * A path nobody else is using, and a cleanup for it.
 *
 * @returns {{path: string, cleanup: () => void}}
 */
function defaultAgentPath({ windows = IS_WINDOWS } = {}) {
  if (windows) {
    const name = `${PIPE_PREFIX}onlykey-js-agent-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
    return { path: name, cleanup: () => {} };
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'onlykey-js-agent-'));
  fs.chmodSync(dir, 0o700);
  const sock = path.join(dir, `agent.${process.pid}`);
  return {
    path: sock,
    cleanup: () => {
      try { fs.unlinkSync(sock); } catch { /* already gone */ }
      try { fs.rmdirSync(dir); } catch { /* not empty, or gone */ }
    },
  };
}

/** A --sock-path as given: on Windows a bare name becomes a pipe path. */
function resolveAgentPath(given, { windows = IS_WINDOWS } = {}) {
  if (!windows) return { path: path.resolve(given), cleanup: () => { try { fs.unlinkSync(path.resolve(given)); } catch { /* gone */ } } };
  return { path: given.startsWith(PIPE_PREFIX) ? given : `${PIPE_PREFIX}${given}`, cleanup: () => {} };
}

/**
 * Is something answering on this socket path? A stale POSIX socket file
 * (left by a killed agent) refuses the connect; a live one accepts it.
 */
function probe(sockPath) {
  return new Promise((resolve) => {
    const c = net.connect(sockPath);
    c.once('connect', () => { c.destroy(); resolve(true); });
    c.once('error', () => resolve(false));
  });
}

/**
 * Serve the agent protocol on a Unix socket or a Windows named pipe.
 *
 * ONE REQUEST AT A TIME, on every connection together. The device takes one
 * operation at a time (a second OKSIGN while the first waits for a press
 * would be read as part of it), so the handler calls are queued globally -
 * lib-agent holds a device mutex for the same reason (server.py
 * handle_connection). Replies still go back on the connection that asked.
 *
 * @param {object} opts
 * @param {{handle: (m: Buffer) => Promise<Buffer>}} opts.handler
 * @param {{path: string, cleanup: () => void}} opts.where  from
 *   defaultAgentPath() or resolveAgentPath()
 * @param {(line: string) => void} [opts.log]
 * @returns {Promise<{path: string, server: net.Server, close: () => Promise<void>}>}
 */
async function serveAgent({ handler, where, log = () => {} }) {
  let queue = Promise.resolve();
  const sockets = new Set();

  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => { /* the client went away; nothing to answer */ });
    const feed = wire.createDeframer((message) => {
      queue = queue.then(async () => {
        const reply = await handler.handle(message);
        if (!socket.destroyed) socket.write(reply);
      }).catch((err) => log(`agent: ${err && err.message ? err.message : err}`));
    });
    socket.on('data', (chunk) => {
      try {
        feed(chunk);
      } catch (err) {
        log(`agent: dropping a connection - ${err.message}`);
        socket.destroy();
      }
    });
  });

  const listen = () => new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(where.path, () => { server.removeListener('error', reject); resolve(); });
  });

  try {
    await listen();
  } catch (err) {
    /*
     * EADDRINUSE on POSIX is usually a socket FILE left by an agent that was
     * killed: nothing answers it, and binding needs it gone. A live one is
     * refused - replacing someone's running agent under them is not ours to
     * do. (A Windows pipe vanishes with its last handle, so this is POSIX's.)
     */
    if (err.code !== 'EADDRINUSE' || IS_WINDOWS) throw err;
    if (await probe(where.path)) throw new Error(`an agent is already answering on ${where.path}`);
    fs.unlinkSync(where.path);
    await listen();
  }
  if (!IS_WINDOWS) fs.chmodSync(where.path, 0o600);

  let closed = null;
  const close = () => {
    if (!closed) {
      closed = new Promise((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(() => resolve());
      }).then(() => where.cleanup());
    }
    return closed;
  };
  return { path: where.path, server, close };
}

module.exports = {
  createAgentHandler,
  serveAgent,
  defaultAgentPath,
  resolveAgentPath,
  verifySignature,
  publicKeyObject,
  IS_WINDOWS,
};
