/*
 * cli/gpg-agent.js - a gpg-agent whose keys are derived inside the OnlyKey.
 *
 * WHAT IT REPLACES. lib-agent's `onlykey-gpg-agent` (libagent/gpg/agent.py):
 * gpg never holds a private key; it asks gpg-agent to sign a digest or to
 * finish an ECDH, naming the key by its keygrip. This agent answers those
 * requests by asking the OnlyKey (okcrypto.agent), keyed by "gpg://<user
 * id>", so the key gpg thinks it has is the one the device derives.
 *
 * THREE LAYERS, as cli/ssh-agent.js has, each testable without the next:
 *
 *   createGpgAgentHandler  one Assuan command in, its reply lines out. Knows
 *                          the commands; asks `sign` / `ecdh` / `publicKey`
 *                          functions for the device's bytes. No socket.
 *   serveGpgAgent          the socket: the greeting, the line framing, the
 *                          INQUIRE round trip, one device operation at a
 *                          time, cleanup. Knows no keys.
 *   agentSocketPath        where gpg will look for the agent.
 *
 * THE COMMAND SET IS lib-agent's (agent.py Handler.handlers), no more:
 * RESET OPTION SETKEYDESC NOP GETINFO AGENT_ID SIGKEY SETKEY SETHASH PKSIGN
 * PKDECRYPT HAVEKEY KEYINFO SCD GET_PASSPHRASE GET_CONFIRMATION BYE
 * KILLAGENT. Where this one differs it is named at the command, and it is
 * always toward what gpg-agent itself answers: an unknown command gets ERR
 * (lib-agent sends nothing and gpg waits forever), GETINFO pid is answered.
 *
 * The encoding is cli/assuan.js; the keys and keygrips are cli/gpg-key.js.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');

const A = require('./assuan');
const { verifyDigest } = require('./gpg-key');

const { AssuanError, ERR } = A;

/* libgcrypt's digest algorithm numbers (SETHASH's first argument) and sizes. */
const HASHES = {
  2: { name: 'sha1', size: 20 },
  3: { name: 'rmd160', size: 20 },
  8: { name: 'sha256', size: 32 },
  9: { name: 'sha384', size: 48 },
  10: { name: 'sha512', size: 64 },
  11: { name: 'sha224', size: 28 },
};
const HASH_BY_NAME = Object.fromEntries(Object.entries(HASHES).map(([n, h]) => [h.name, Number(n)]));

/* lib-agent's GETINFO s2k_count: the highest iteration count (64 << 20). */
const S2K_COUNT = String(64 << 20);

/* ------------------------------------------------------------ the protocol */

/**
 * The Assuan command set, over the derived keys a keyring holds.
 *
 * @param {object} opts
 * @param {Array<object>} opts.keys  cli/gpg-key.js readDerivedKeys() entries
 * @param {(key: object, digest: Buffer, session: object) => Promise<Uint8Array>} opts.sign
 *   the device's 64-byte signature over `digest` (already cut to 32 bytes for
 *   ECDSA) with the signing key `key`
 * @param {(key: object, point: Buffer, session: object) => Promise<Uint8Array>} opts.ecdh
 *   the device's ECDH result with the sender's ephemeral `point`
 * @param {(key: object) => Promise<Uint8Array>} opts.publicKey
 *   the device's public key for `key` - checked against the keyring's before
 *   an ECDH, see pkdecrypt
 * @param {string} opts.version  what GETINFO version answers - gpg's own
 *   version, as lib-agent does (a lower one makes gpg warn on every call
 *   that "server 'gpg-agent' is older than us")
 * @param {(session: object, args: object) => Promise<Buffer>} [opts.askPassphrase]
 *   GET_PASSPHRASE: ask the person (pinentry); rejects to cancel
 * @param {(line: string) => void} [opts.log]
 */
function createGpgAgentHandler({ keys, sign, ecdh, publicKey, version, askPassphrase, log = () => {} }) {
  /*
   * Keygrip -> the keys with it. Usually one each, but a P-256 identity's
   * signing key and ECDH key are the SAME key - the device derives one
   * secret per identity and version, whatever the key type - so both
   * packets share a keygrip, and the operation asked for picks which.
   */
  const byGrip = new Map();
  for (const k of keys) byGrip.set(k.keygrip, [...(byGrip.get(k.keygrip) || []), k]);
  const checked = new Map();

  /*
   * ONE DEVICE OPERATION AT A TIME, across every connection: the device
   * takes one request at a time, and a second OKSIGN while the first waits
   * for a press would be read as part of it. lib-agent serves one connection
   * at a time for the same reason; here connections may overlap (gpg opens
   * a second one while a first is idle), only the device calls queue.
   */
  let queue = Promise.resolve();
  function serial(fn) {
    const run = queue.then(fn, fn);
    queue = run.catch(() => {});
    return run;
  }

  function held(grip, role) {
    const all = byGrip.get(String(grip).toUpperCase()) || [];
    const key = role ? all.find((k) => k.role === role) : all[0];
    if (!key) throw new AssuanError(ERR.NO_SECKEY, 'No secret key');
    return key;
  }

  /*
   * Is the key gpg holds the key the device derives? For a signature the
   * answer is in the signature (it is verified against the keyring's key
   * before it is sent). An ECDH result cannot be checked that way - a wrong
   * key gives a wrong secret and gpg's "decryption failed: Bad session key"
   * - so before the first ECDH with a key the device's public key is read
   * (no press) and compared. A mismatch is the same user id derived with the
   * other --dkey version, or a different OnlyKey: named, not guessed at.
   */
  async function checkPublic(key) {
    if (checked.get(key.keygrip)) return;
    const raw = Buffer.from(await publicKey(key));
    if (!raw.equals(key.raw)) {
      throw new AssuanError(ERR.NO_SECKEY,
        `the OnlyKey derives a different key for "${key.userId}" than the keyring holds (another derivation version, or another OnlyKey)`);
    }
    checked.set(key.keygrip, true);
  }

  function keyinfoLine(key) {
    /*
     * gpg-agent's format: keygrip, type, serial, idstr, cached, protection,
     * fpr, ttl, flags. lib-agent's type "X" (not a key file on disk, not a
     * smartcard) and "-" for the rest.
     */
    return `S KEYINFO ${key.keygrip} X - - - - - - -`;
  }

  function session() {
    const state = { keygrip: null, digest: null, hashAlgo: null, options: {} };

    const commands = {
      RESET() {
        state.keygrip = null;
        state.digest = null;
        state.hashAlgo = null;
      },

      /*
       * gpg's ttyname, display, lc-ctype and the like: kept, because the
       * challenge prompt goes to that tty and pinentry gets them - the agent
       * gpg starts has no terminal of its own.
       */
      OPTION(_io, args) {
        const m = /^([^=\s]+)(?:[=\s]\s*(.*))?$/.exec(args);
        if (m) state.options[m[1].replace(/^--/, '')] = m[2] === undefined ? true : m[2];
      },

      SETKEYDESC() {},
      NOP() {},
      GET_CONFIRMATION() {},

      GETINFO(io, args) {
        const [what, ...rest] = args.split(/\s+/);
        if (what === 'version') return io.data(version);
        if (what === 'pid') return io.data(String(process.pid));
        if (what === 's2k_count') return io.data(S2K_COUNT);
        /*
         * cmd_has_option is gpg asking whether a command takes an option
         * before it uses it. lib-agent answers OK to every GETINFO it does not
         * know - "yes" - which would have gpg use options this agent does not
         * have; the one it does have is HAVEKEY --list. gpg-agent's "no" is
         * ERR False.
         */
        if (what === 'cmd_has_option') {
          if (rest[0] === 'HAVEKEY' && rest[1] === 'list') return undefined;
          throw new AssuanError(ERR.FALSE, 'False');
        }
        log(`GETINFO ${args}: not answered (OK, as lib-agent)`);
        return undefined;
      },

      /* lib-agent's "fake" agent id. */
      AGENT_ID(io) {
        return io.data('ONLYKEY');
      },

      SIGKEY(_io, args) { state.keygrip = args.split(/\s+/)[0].toUpperCase(); },
      SETKEY(_io, args) { state.keygrip = args.split(/\s+/)[0].toUpperCase(); },

      /*
       * SETHASH <algo> <hex> (gpg's form), or --hash=<name> <hex>. --inquire
       * (the whole message, for PureEdDSA keys) is not something a legacy
       * EdDSA or ECDSA key is signed with; refused rather than half done.
       */
      SETHASH(_io, args) {
        const parts = args.split(/\s+/).filter(Boolean);
        let algo = null;
        let hex = null;
        for (const p of parts) {
          if (p === '--inquire') throw new AssuanError(ERR.NOT_SUPPORTED, 'SETHASH --inquire is not supported');
          const named = /^--hash=(.+)$/.exec(p);
          if (named) algo = HASH_BY_NAME[named[1]] || -1;
          else if (algo === null && /^\d+$/.test(p)) algo = Number(p);
          else if (!p.startsWith('--')) hex = p;
        }
        const h = HASHES[algo];
        if (!h) throw new AssuanError(ERR.NOT_SUPPORTED, `hash algorithm ${algo} is not supported`);
        if (!hex || !/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== h.size * 2) {
          throw new AssuanError(ERR.INV_VALUE, `a ${h.name} digest is ${h.size} bytes`);
        }
        state.hashAlgo = algo;
        state.digest = Buffer.from(hex, 'hex');
      },

      async PKSIGN(io) {
        if (!state.keygrip || !state.digest) throw new AssuanError(ERR.INV_VALUE, 'SIGKEY and SETHASH come first');
        const key = held(state.keygrip, 'sign');
        /*
         * ECDSA over P-256 signs the leftmost 256 bits of the digest (FIPS
         * 186-4 6.4; lib-agent client.py sign() cuts it the same way), and
         * the device signs a 32-byte message as given. A shorter digest
         * (SHA-1) would be hashed again by the device - a signature over the
         * wrong thing - so it is refused; gpg picks SHA-512 here anyway
         * (gpg.conf personal-digest-preferences).
         */
        let digest = state.digest;
        if (key.keyType === 2) {
          if (digest.length < 32) throw new AssuanError(ERR.NOT_SUPPORTED, 'ECDSA P-256 needs a digest of at least 256 bits');
          digest = digest.subarray(0, 32);
        }
        const sig = Buffer.from(await serial(() => sign(key, digest, state)));
        /*
         * Verified before it is sent, as the ssh agent does: the device
         * derives the key from the identity hash sent WITH the digest, so a
         * wrong user id or derivation version signs perfectly well - with a
         * different key - and gpg would write a signature nobody can verify.
         */
        if (!verifyDigest(key.keyType, key.raw, digest, sig)) {
          log(`the OnlyKey's signature for "${key.userId}" does not verify against the keyring's key - not sent`);
          throw new AssuanError(ERR.BAD_SIGNATURE, 'Bad signature');
        }
        const name = key.keyType === 1 ? 'eddsa' : 'ecdsa';
        return io.data(A.encodeSexp(['sig-val', [name, ['r', sig.subarray(0, 32)], ['s', sig.subarray(32, 64)]]]));
      },

      /*
       * The ciphertext comes by INQUIRE; its ECDH part is
       * (enc-val (ecdh (s <wrapped key>) (e <ephemeral point>))) and the
       * agent's whole job is the shared point for `e`. gpg unwraps the
       * session key itself (RFC 6637 8) from what comes back.
       */
      async PKDECRYPT(io) {
        if (!state.keygrip) throw new AssuanError(ERR.INV_VALUE, 'SETKEY comes first');
        const key = held(state.keygrip, 'ecdh');
        io.status('INQUIRE_MAXLEN 4096');
        const ciphertext = await io.inquire('CIPHERTEXT');
        let e;
        try {
          const tree = A.parseSexp(ciphertext);
          if (A.findToken(tree, 'rsa') && !A.findToken(tree, 'ecdh')) throw new Error('an RSA ciphertext');
          const found = A.findToken(A.findToken(tree, 'ecdh'), 'e');
          if (!found || !Buffer.isBuffer(found[1])) throw new Error('no (ecdh (e ...)) in it');
          e = found[1];
        } catch (err) {
          throw new AssuanError(ERR.INV_VALUE, `cannot use this ciphertext: ${err.message}`);
        }
        const secret = await serial(async () => {
          await checkPublic(key);
          return Buffer.from(await ecdh(key, e, state));
        });
        /*
         * The shared point, prefixed as gpg-agent's own answer is: 0x40 || X
         * for Curve25519 (libgcrypt's native form), 04 || X || Y for P-256.
         * gpg drops the prefix by the length being odd (g10/ecdh.c). The
         * prefix is not decoration: lib-agent sends P-256's X||Y bare, 64
         * bytes. That works while the length stays even; but GnuPG 2.2
         * reads the value through an unsigned MPI (pubkey-enc.c
         * gcry_mpi_scan USG), which drops a leading zero byte of X - the
         * length turns odd and gpg strips a byte of X itself, about one
         * message in 256. (A reading of the GnuPG source, not a measured
         * failure; 2.4 copies the bytes as they came.)
         */
        const value = Buffer.concat([Buffer.of(secret.length === 32 ? 0x40 : 0x04), secret]);
        io.status('PADDING 0');
        return io.data(A.encodeSexp(['value', value]));
      },

      /*
       * HAVEKEY <grip>...: OK when any of them is held. HAVEKEY --list[=n]:
       * every held grip, 20 raw bytes each, as data (gpg's fast path for
       * --list-secret-keys). Answered from the keyring alone - lib-agent asks
       * the device here, so gpg -K with the key unplugged said "no secret
       * key"; the device is asked when there is something to sign.
       */
      HAVEKEY(io, args) {
        const parts = args.split(/\s+/).filter(Boolean);
        if (parts.length === 1 && /^--list(=\d+)?$/.test(parts[0])) {
          return io.data(Buffer.concat([...byGrip.keys()].map((g) => Buffer.from(g, 'hex'))));
        }
        if (parts.some((g) => byGrip.has(g.toUpperCase()))) return undefined;
        throw new AssuanError(ERR.NO_SECKEY, 'No secret key');
      },

      /*
       * KEYINFO <grip> or KEYINFO --list. lib-agent answers a KEYINFO line
       * for ANY grip asked about; that tells gpg it has secret keys it does
       * not have, so an unknown grip is "No secret key" here.
       */
      KEYINFO(io, args) {
        const parts = args.split(/\s+/).filter(Boolean);
        if (parts.includes('--list')) {
          for (const [k] of byGrip.values()) io.send(keyinfoLine(k));
          return undefined;
        }
        const grip = parts.filter((p) => !p.startsWith('--')).pop();
        io.send(keyinfoLine(held(grip || '')));
        return undefined;
      },

      /* No smartcard daemon behind this agent: only its version, as lib-agent. */
      SCD(io, args) {
        if (/^GETINFO\s+version$/i.test(args.trim())) return io.data(version);
        throw new AssuanError(ERR.ENODEV, 'No such device', A.SOURCE.SCD);
      },

      /*
       * GET_PASSPHRASE [--data] [--repeat[=N]] ... <cache id> [<error> <prompt> <desc>]:
       * gpg's symmetric encryption (gpg -c) asks the agent for the
       * passphrase, and the agent asks the person through pinentry. The
       * three texts are Assuan-escaped with '+' for space; "X" means none.
       * --data answers as data (what gpg asks for); otherwise OK <hex>.
       */
      async GET_PASSPHRASE(io, args) {
        if (!askPassphrase) throw new AssuanError(ERR.NOT_SUPPORTED, 'no pinentry');
        const parts = args.split(/\s+/).filter(Boolean);
        const flags = [];
        while (parts.length && parts[0].startsWith('--')) {
          const f = parts.shift();
          if (f === '--') break;
          flags.push(f);
        }
        const text = (s) => (s === undefined || s === 'X' ? '' : A.unescapeData(s.replace(/\+/g, ' ')).toString('utf8'));
        const repeat = flags.find((f) => f.startsWith('--repeat'));
        const request = {
          cacheId: parts[0],
          error: text(parts[1]),
          prompt: text(parts[2]),
          description: text(parts[3]),
          repeat: repeat ? Number((repeat.split('=')[1]) || 1) : 0,
        };
        let pass;
        try {
          pass = Buffer.from(await askPassphrase(state, request));
        } catch (err) {
          log(`pinentry: ${err && err.message ? err.message : err}`);
          throw new AssuanError(ERR.CANCELED, 'Operation cancelled');
        }
        if (flags.includes('--data')) return io.data(pass, { confidential: true });
        return { ok: pass.toString('hex').toUpperCase() };
      },
    };

    /**
     * One command line.
     *
     * @param {Buffer|string} line
     * @param {{send: (line: string) => void, data: (bytes: Uint8Array|string) => void,
     *   status: (text: string) => void, inquire: (kw: string) => Promise<Buffer>}} io
     * @returns {Promise<{ok?: string, close?: boolean, kill?: boolean} | undefined>}
     *   undefined = OK; throws AssuanError for an ERR line
     */
    async function command(line, io) {
      const [name, args] = A.splitCommand(line);
      if (name === 'BYE') return { close: true };
      if (name === 'KILLAGENT') return { kill: true };
      const fn = commands[name];
      if (!fn) {
        log(`unknown command ${name}`);
        throw new AssuanError(ERR.ASS_UNKNOWN_CMD, 'Unknown IPC command');
      }
      try {
        return await fn(io, args);
      } catch (err) {
        if (err instanceof AssuanError) throw err;
        /*
         * A refused challenge, a timeout, a locked key: gpg gets one ERR and
         * says "signing failed" / "decryption failed"; the reason goes to
         * the log, because gpg prints only the error code's own text.
         */
        log(err && err.message ? err.message : String(err));
        throw new AssuanError(ERR.GENERAL, err && err.message ? err.message : 'General error');
      }
    }

    return { command, state };
  }

  return { session, keys };
}

/* ------------------------------------------------------------ one connection */

/**
 * Hold the conversation on one connection: greeting, then command after
 * command, each with exactly one OK or ERR, until BYE or the peer leaves.
 *
 * INQUIRE is the one place the server reads WHILE a command runs, so lines
 * are not handed to the handler directly: they go to a queue, and whoever is
 * waiting - the command loop, or an inquire - takes the next one.
 */
function converse(socket, handler, { log, onKill }) {
  const lines = [];
  let waiting = null;
  let ended = false;

  const nextLine = () => new Promise((resolve) => {
    if (lines.length) resolve(lines.shift());
    else if (ended) resolve(null);
    else waiting = resolve;
  });
  const push = (line) => {
    if (waiting) {
      const w = waiting;
      waiting = null;
      w(line);
    } else {
      lines.push(line);
    }
  };

  const feed = A.createLineSplitter(push);
  socket.on('data', (chunk) => {
    try {
      feed(chunk);
    } catch (err) {
      log(`dropping a connection - ${err.message}`);
      socket.destroy();
    }
  });
  const finish = () => {
    ended = true;
    if (waiting) {
      const w = waiting;
      waiting = null;
      w(null);
    }
  };
  socket.on('end', finish);
  socket.on('close', finish);
  socket.on('error', () => finish());

  const write = (text) => { if (!socket.destroyed) socket.write(Buffer.isBuffer(text) ? text : `${text}\n`); };

  const io = {
    send: write,
    status: (text) => write(`S ${text}`),
    data: (bytes) => { for (const l of A.dataLines(typeof bytes === 'string' ? Buffer.from(bytes) : bytes)) write(l); },
    /* INQUIRE <kw>, then D lines until END; CAN is the client cancelling. */
    async inquire(keyword) {
      write(`INQUIRE ${keyword}`);
      const parts = [];
      for (;;) {
        const line = await nextLine();
        if (line === null) throw new AssuanError(ERR.ASS_CANCELED, 'connection closed during INQUIRE');
        const [name] = A.splitCommand(line);
        if (name === 'END') return Buffer.concat(parts);
        if (name === 'CAN') throw new AssuanError(ERR.ASS_CANCELED, 'IPC call has been cancelled');
        if (line[0] === 0x44 && line[1] === 0x20) parts.push(A.unescapeData(line.subarray(2)));
        else if (line.length === 1 && line[0] === 0x44) { /* an empty D line */ } else {
          throw new AssuanError(ERR.ASS_SYNTAX, 'expected D, END or CAN');
        }
      }
    },
  };

  const s = handler.session();
  write(`OK Pleased to meet you, process ${process.pid}`);

  return (async () => {
    for (;;) {
      const line = await nextLine();
      if (line === null) return;
      if (!line.length || line[0] === 0x23) continue;   // empty, or a # comment
      try {
        const r = await s.command(line, io);
        write(r && r.ok ? `OK ${r.ok}` : 'OK');
        if (r && r.close) { socket.end(); return; }
        if (r && r.kill) { socket.end(); onKill(); return; }
      } catch (err) {
        if (err instanceof AssuanError) write(err.line);
        else {
          log(`internal: ${err && err.stack ? err.stack : err}`);
          write(new AssuanError(ERR.GENERAL, 'General error').line);
        }
      }
    }
  })();
}

/* ------------------------------------------------------------ the socket */

/*
 * WHERE gpg LOOKS FOR ITS AGENT, per platform - both kept, neither traded
 * for the other.
 *
 * POSIX: an AF_UNIX socket named S.gpg-agent, in the homedir - or, when the
 * system has /run/user/<uid>, in /run/user/<uid>/gnupg/d.<hash of the
 * homedir>/ (GnuPG 2.1.13+ keeps sockets off network home directories).
 * The hash is GnuPG's own; rather than re-derive it, `gpgconf --list-dirs
 * agent-socket` is asked with GNUPGHOME set, as lib-agent does
 * (keyring.get_agent_sock_path). The directory is 0700 - gpg refuses a
 * socket directory other users can enter.
 *
 * WINDOWS: GnuPG (Gpg4win) has no Unix sockets. libassuan's emulation is a
 * FILE at the socket path holding a TCP port on 127.0.0.1, a newline, and a
 * 16-byte nonce; a client connects to the port and must send the nonce
 * before anything else. So: listen on an ephemeral loopback port, write the
 * file, and drop every connection whose first 16 bytes are not the nonce -
 * the nonce is what keeps other local users out, the file's ACL (the
 * user's profile) is what keeps the nonce from them.
 */
const IS_WINDOWS = process.platform === 'win32';
const NONCE_LEN = 16;

/** gpgconf's output is percent-escaped (':' is %3a in a path). */
function unpercent(text) {
  return text.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

/**
 * Where gpg looks for this homedir's agent.
 *
 * @param {string} homedir
 * @param {object} [opts]
 * @param {(args: string[], env: object) => string|null} [opts.gpgconf]  run
 *   gpgconf and return its stdout (null when it cannot run); the default
 *   runs the one on PATH
 * @returns {string}
 */
function agentSocketPath(homedir, { gpgconf = runGpgconf } = {}) {
  const out = gpgconf(['--list-dirs', 'agent-socket'], { ...process.env, GNUPGHOME: homedir });
  const line = out && out.split(/\r?\n/).map((l) => l.trim()).find(Boolean);
  if (line) return unpercent(line);
  return path.join(homedir, 'S.gpg-agent');
}

/** GnuPG's version, from gpgconf (what GETINFO version answers). */
function gnupgVersion({ gpgconf = runGpgconf } = {}) {
  const out = gpgconf(['--version'], process.env);
  const m = out && /\(GnuPG[^)]*\)\s+(\d+\.\d+\.\d+)/.exec(out);
  return m ? m[1] : null;
}

function runGpgconf(args, env) {
  try {
    return require('child_process').execFileSync('gpgconf', args, {
      env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 10000,
    });
  } catch {
    return null;
  }
}

/** Connect to an Assuan socket as gpg would: a Unix socket, or Windows' port-and-nonce file. */
function connectAssuan(socketPath, { windows = IS_WINDOWS } = {}) {
  if (!windows) return net.connect(socketPath);
  const file = fs.readFileSync(socketPath);
  const nl = file.indexOf(0x0a);
  const port = Number(file.subarray(0, nl).toString('latin1'));
  const nonce = file.subarray(nl + 1, nl + 1 + NONCE_LEN);
  const c = net.connect(port, '127.0.0.1');
  c.once('connect', () => c.write(nonce));
  return c;
}

/** Is an agent answering there? A stale socket (a killed agent's) refuses the connect. */
function probe(socketPath) {
  return new Promise((resolve) => {
    let c;
    try {
      c = connectAssuan(socketPath);
    } catch {
      resolve(false);
      return;
    }
    c.once('data', () => { c.destroy(); resolve(true); });
    c.once('error', () => resolve(false));
    c.setTimeout(3000, () => { c.destroy(); resolve(false); });
  });
}

/**
 * Serve the Assuan protocol where gpg will look for it.
 *
 * @param {object} opts
 * @param {{session: () => object}} opts.handler  createGpgAgentHandler()
 * @param {string} opts.socketPath  agentSocketPath()
 * @param {(line: string) => void} [opts.log]
 * @param {() => void} [opts.onKill]  KILLAGENT arrived (gpgconf --kill gpg-agent)
 * @returns {Promise<{path: string, close: () => Promise<void>}>}
 */
async function serveGpgAgent({ handler, socketPath, log = () => {}, onKill = () => {} }) {
  const sockets = new Set();
  const nonce = crypto.randomBytes(NONCE_LEN);

  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => { /* the client went away */ });
    const start = () => converse(socket, handler, { log, onKill }).catch((err) => log(`connection: ${err.message}`));
    if (!IS_WINDOWS) {
      start();
      return;
    }
    /* Windows: the first 16 bytes are the nonce, or the connection is dropped. */
    let got = Buffer.alloc(0);
    const onData = (chunk) => {
      got = Buffer.concat([got, chunk]);
      if (got.length < NONCE_LEN) return;
      socket.removeListener('data', onData);
      if (!crypto.timingSafeEqual(got.subarray(0, NONCE_LEN), nonce)) {
        log('dropping a connection without the socket nonce');
        socket.destroy();
        return;
      }
      start();
      if (got.length > NONCE_LEN) socket.emit('data', got.subarray(NONCE_LEN));
    };
    socket.on('data', onData);
  });

  const listen = (...where) => new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(...where, () => { server.removeListener('error', reject); resolve(); });
  });

  fs.mkdirSync(path.dirname(socketPath), { recursive: true, mode: 0o700 });
  if (fs.existsSync(socketPath)) {
    /*
     * A socket (or Windows port file) left by an agent that was killed:
     * nothing answers it and it has to go. A live one is refused - taking
     * over someone's running agent is not ours to do; `gpgconf --kill
     * gpg-agent` stops it.
     */
    if (await probe(socketPath)) throw new Error(`an agent is already answering on ${socketPath}`);
    fs.unlinkSync(socketPath);
  }

  if (IS_WINDOWS) {
    await listen(0, '127.0.0.1');
    fs.writeFileSync(socketPath, Buffer.concat([Buffer.from(`${server.address().port}\n`), nonce]), { mode: 0o600 });
  } else {
    await listen(socketPath);
    fs.chmodSync(socketPath, 0o600);
  }

  let closed = null;
  const close = () => {
    if (!closed) {
      closed = new Promise((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(() => resolve());
      }).then(() => { try { fs.unlinkSync(socketPath); } catch { /* already gone */ } });
    }
    return closed;
  };
  return { path: socketPath, close };
}

module.exports = {
  createGpgAgentHandler,
  serveGpgAgent,
  agentSocketPath,
  gnupgVersion,
  connectAssuan,
  unpercent,
  IS_WINDOWS,
  HASHES,
};
