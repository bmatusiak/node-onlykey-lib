/*
 * cli/ssh-wire.js - the bytes of the SSH agent protocol, and nothing else.
 *
 * WHAT THIS IS. `onlykey-js agent` answers ssh the way python lib-agent's
 * `onlykey-agent` does, with the key derived inside the OnlyKey. This file is
 * the half of that which is pure encoding: framing, the key and signature
 * blobs, and lib-agent's identity strings. No socket, no device - so every
 * rule below is testable from a byte string (test/ssh-agent.test.js), and
 * cli/ssh-agent.js does the I/O on top.
 *
 * WHERE THE RULES COME FROM. The OpenSSH agent protocol, PROTOCOL.agent in
 * openssh-portable and its IETF write-up draft-miller-ssh-agent; the key and
 * signature formats of RFC 4251 (string, uint32, mpint), RFC 5656 (ECDSA) and
 * RFC 8709 (Ed25519). Where lib-agent differs from them, the spec wins and the
 * difference is named at the spot it happens.
 *
 * WHY NOT src/. The encoding needs no Node built-in and could live there, but
 * an ssh-agent is a desktop process by nature - a phone or a page has no ssh
 * to serve - and cli/ is where the one consumer is. Buffer is used freely for
 * that reason. If a GUI ever wants these blobs (to SHOW an authorized_keys
 * line, say), the byte helpers move to src/ with Uint8Array and this file
 * re-exports them.
 *
 * DEPENDENCY-LESS on purpose: an agent holds the path by which a server
 * decides who you are, so everything in it is here to be read.
 */
'use strict';

/*
 * The message numbers this agent speaks (PROTOCOL.agent / draft-miller-ssh-
 * agent section 5.1). Everything else - adding keys, locking, the SSH1
 * messages - is answered FAILURE: an OnlyKey agent has no keys to add or
 * remove, only identities it was started with.
 */
const MSG = {
  FAILURE: 5,
  SUCCESS: 6,
  REQUEST_IDENTITIES: 11,
  IDENTITIES_ANSWER: 12,
  SIGN_REQUEST: 13,
  SIGN_RESPONSE: 14,
  EXTENSION: 27,
};

/*
 * The largest message accepted: OpenSSH's own AGENT_MAX_LEN (authfd.h,
 * 256 KiB). A length word above it is not a big request, it is a peer that
 * is not speaking this protocol - and allocating what it asks for would let
 * any local process make the agent reserve 4 GiB.
 */
const MAX_MESSAGE = 256 * 1024;

/*
 * The two key types, by the names each side uses for them.
 *
 *   curve    lib-agent's name (`-e ed25519`, `-e nist256p1`), which is also
 *            what it prints in the key comment `<ssh://u@h|ed25519>`
 *   sshName  the SSH key-type string that opens every blob
 *   keyType  the OnlyKey's derivation key type (src/protocol/agent.js)
 *
 * secp256k1 and X25519 are derivable too, but ssh has no key type for either.
 */
const CURVES = {
  ed25519: { curve: 'ed25519', sshName: 'ssh-ed25519', keyType: 1 },
  nist256p1: { curve: 'nist256p1', sshName: 'ecdsa-sha2-nistp256', keyType: 2, sshCurve: 'nistp256' },
};

/* ------------------------------------------------------------ primitives */

const toBuf = (v) => (typeof v === 'string' ? Buffer.from(v, 'utf8') : Buffer.from(v));

/** RFC 4251 uint32: four bytes, big-endian. */
function uint32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

/** RFC 4251 string: a uint32 length, then the bytes. */
function string(v) {
  const bytes = toBuf(v);
  return Buffer.concat([uint32(bytes.length), bytes]);
}

/**
 * RFC 4251 mpint, from an UNSIGNED big-endian magnitude.
 *
 * The rules that make this more than `string()`: two's complement, so a
 * positive number whose top bit is set gets a 0x00 in front, or it would read
 * as negative; and no UNNECESSARY leading bytes - "0x00 or 0xff are not
 * allowed" beyond that one - with zero as the empty string.
 *
 * lib-agent does not follow the second rule. formats.py ecdsa_verifier()
 * frames `b'\x00' + r` and `b'\x00' + s` unconditionally, so half its
 * signatures carry a redundant zero and any r below 2^248 keeps its own
 * leading zero bytes too. OpenSSH's sshbuf_get_bignum2_bytes_direct() strips
 * leading zeros and so accepts both; a stricter verifier (RFC 4251 says the
 * encoding is canonical) need not. This one emits the canonical form.
 */
function mpint(magnitude) {
  let b = toBuf(magnitude);
  let i = 0;
  while (i < b.length && b[i] === 0) i += 1;
  b = b.subarray(i);
  if (b.length && (b[0] & 0x80)) b = Buffer.concat([Buffer.of(0), b]);
  return string(b);
}

/** One whole agent message on the wire: a uint32 length, then the message. */
function frame(...parts) {
  const body = Buffer.concat(parts.map(toBuf));
  return Buffer.concat([uint32(body.length), body]);
}

/**
 * Reads RFC 4251 fields off a message, refusing to run past its end.
 *
 * A short read throws rather than returning what was there: a truncated key
 * blob that happened to match a prefix of ours must not be taken for it.
 */
class Reader {
  constructor(bytes) {
    this.buf = toBuf(bytes);
    this.at = 0;
  }

  need(n, what) {
    if (this.at + n > this.buf.length) {
      throw new Error(`truncated agent message: ${what} needs ${n} bytes, ${this.buf.length - this.at} left`);
    }
  }

  uint8() {
    this.need(1, 'a byte');
    return this.buf[this.at++];
  }

  uint32() {
    this.need(4, 'a uint32');
    const v = this.buf.readUInt32BE(this.at);
    this.at += 4;
    return v;
  }

  string() {
    const n = this.uint32();
    this.need(n, 'a string');
    const v = this.buf.subarray(this.at, this.at + n);
    this.at += n;
    return v;
  }

  get remaining() { return this.buf.length - this.at; }
}

/**
 * Split a byte stream into agent messages.
 *
 * A stream socket delivers whatever it has: half a length word, three
 * messages in one chunk, a message across two. So bytes are kept until a
 * whole `uint32 length || message` is there, and each whole message goes to
 * `onMessage` in order. A length over MAX_MESSAGE (or a zero length, which
 * has no message number to answer) throws, and the caller drops the
 * connection - OpenSSH's agent does the same.
 *
 * @param {(message: Buffer) => void} onMessage
 * @returns {(chunk: Buffer) => void} feed it every chunk the socket reads
 */
function createDeframer(onMessage, { max = MAX_MESSAGE } = {}) {
  let pending = Buffer.alloc(0);
  return (chunk) => {
    pending = pending.length ? Buffer.concat([pending, chunk]) : Buffer.from(chunk);
    while (pending.length >= 4) {
      const n = pending.readUInt32BE(0);
      if (n === 0 || n > max) throw new Error(`agent message length ${n} is not a message (limit ${max})`);
      if (pending.length < 4 + n) return;
      const message = pending.subarray(4, 4 + n);
      pending = pending.subarray(4 + n);
      onMessage(message);
    }
  };
}

/* ------------------------------------------------------------ blobs */

function curveInfo(curve) {
  const info = CURVES[curve];
  if (!info) throw new Error(`the SSH agent offers ${Object.keys(CURVES).join(' and ')}, not ${curve}`);
  return info;
}

/**
 * The SSH public-key blob for a key the OnlyKey returned.
 *
 *   ssh-ed25519          string "ssh-ed25519", string key(32)      RFC 8709
 *   ecdsa-sha2-nistp256  string name, string "nistp256",
 *                        string 0x04 || X || Y                     RFC 5656 3.1
 *
 * The device's P-256 reply is X||Y with no prefix (src/protocol/agent.js), so
 * the uncompressed-point 0x04 is added here.
 */
function publicKeyBlob(curve, raw) {
  const info = curveInfo(curve);
  const key = toBuf(raw);
  if (info.keyType === 1) {
    if (key.length !== 32) throw new Error(`an Ed25519 public key is 32 bytes, not ${key.length}`);
    return Buffer.concat([string(info.sshName), string(key)]);
  }
  if (key.length !== 64) throw new Error(`a P-256 public key from the device is X||Y, 64 bytes, not ${key.length}`);
  return Buffer.concat([string(info.sshName), string(info.sshCurve), string(Buffer.concat([Buffer.of(4), key]))]);
}

/**
 * The signature blob ssh sends the server, from the device's 64 bytes.
 *
 *   ssh-ed25519          string name, string R||S(64)              RFC 8709 6
 *   ecdsa-sha2-nistp256  string name, string (mpint r || mpint s)  RFC 5656 3.1.2
 */
function signatureBlob(curve, sig) {
  const info = curveInfo(curve);
  const s = toBuf(sig);
  if (s.length !== 64) throw new Error(`the device's signature is 64 bytes, not ${s.length}`);
  if (info.keyType === 1) return Buffer.concat([string(info.sshName), string(s)]);
  return Buffer.concat([
    string(info.sshName),
    string(Buffer.concat([mpint(s.subarray(0, 32)), mpint(s.subarray(32))])),
  ]);
}

/** An authorized_keys line: type, base64 blob, comment - lib-agent's layout. */
function publicKeyLine(curve, raw, comment) {
  return `${curveInfo(curve).sshName} ${publicKeyBlob(curve, raw).toString('base64')} ${comment}`;
}

/* ------------------------------------------------------------ identities */

/*
 * lib-agent's identity grammar, the SAME regular expression
 * (libagent/device/interface.py _identity_regexp):
 *
 *   ^(?:(?P<proto>.*)://)?(?:(?P<user>.*)@)?(?P<host>.*?)(?::(?P<port>\w*))?(?P<path>/.*)?$
 *
 * Copied rather than improved, because the parse decides the HASH and the
 * hash decides the key: `a@b@c` is user "a@b" there (the greedy `.*`), and a
 * parser that said user "a" would derive a different key for the same line
 * in someone's config and nothing would say why. JavaScript's `.*` and `.*?`
 * are greedy and lazy exactly as Python's are.
 */
const IDENTITY_RE = /^(?:(?<proto>.*):\/\/)?(?:(?<user>.*)@)?(?<host>.*?)(?::(?<port>\w*))?(?<path>\/.*)?$/;

/**
 * Parse `[proto://][user@]host[:port][/path]` as lib-agent does.
 *
 * Empty parts are dropped (python's `{k: v ... if v}`), and the proto is
 * forced to "ssh" as ssh/__init__.py main() forces it - so `okt@example.com`
 * and `ssh://okt@example.com` are one identity with one comment.
 */
function parseIdentity(text) {
  const m = IDENTITY_RE.exec(String(text));
  const out = { proto: 'ssh' };
  for (const k of ['user', 'host', 'port', 'path']) if (m && m.groups[k]) out[k] = m.groups[k];
  if (!out.host) throw new Error(`"${text}" names no host; an identity is [ssh://][user@]host[:port][/path]`);
  return out;
}

/** python identity_to_string(): the identity as it is written back. */
function identityToString(id) {
  return `${id.proto ? `${id.proto}://` : ''}${id.user ? `${id.user}@` : ''}${id.host}`
    + `${id.port ? `:${id.port}` : ''}${id.path || ''}`;
}

/**
 * The key comment lib-agent prints and ssh-add -l shows: `<ssh://u@h|curve>`
 * (python Identity.to_string()). Kept identical so a line from either agent
 * is the same line, comment and all.
 */
function identityComment(id, curve) {
  return `<${identityToString(id)}|${curve}>`;
}

/**
 * What the device derives from: `{ ssh: { user, host } }`. Port, path and
 * proto are NOT part of it - lib-agent hashes "user@host", or "host" alone
 * (libagent/device/onlykey.py:273-278), and src/protocol/agent.js does the
 * hashing.
 */
function derivationIdentity(id) {
  return { ssh: { user: id.user, host: id.host } };
}

/**
 * A lib-agent identity file: every `<identity|curve>` in it
 * (ssh/__init__.py parse_config, the regex `\<(.*?)\|(.*?)\>`), which is also
 * what the agent prints - so a file of saved key lines is a valid config.
 */
function parseIdentityFile(text) {
  const out = [];
  for (const m of String(text).matchAll(/<(.*?)\|(.*?)>/g)) {
    out.push({ identity: parseIdentity(m[1]), curve: curveInfo(m[2]).curve });
  }
  return out;
}

module.exports = {
  MSG,
  MAX_MESSAGE,
  CURVES,
  uint32,
  string,
  mpint,
  frame,
  Reader,
  createDeframer,
  publicKeyBlob,
  signatureBlob,
  publicKeyLine,
  parseIdentity,
  identityToString,
  identityComment,
  derivationIdentity,
  parseIdentityFile,
};
