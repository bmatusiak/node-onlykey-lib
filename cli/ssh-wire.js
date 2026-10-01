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
 * WHAT IS IN src/. The key blobs and their primitives: Key Chain shows an
 * authorized_keys line in a GUI, so those moved to src/crypto/ssh-pub.js with
 * Uint8Array (Hermes has no Buffer) and this file re-exports them as Buffer.
 * The agent protocol itself - framing, the reader, signature blobs, the
 * identity grammar - stays here: an ssh-agent is a desktop process by
 * nature, and a phone or a page has no ssh to serve.
 *
 * DEPENDENCY-LESS on purpose (beyond that one sibling): an agent holds the
 * path by which a server decides who you are, so everything in it is here to
 * be read.
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
 * The key types and the RFC 4251 primitives are src/crypto/ssh-pub.js's - the
 * SAME encoder Key Chain uses to show an authorized_keys line in a GUI, moved
 * there with Uint8Array as this header once said they would be. Re-exported
 * here with Buffer back on them, because the agent and its tests use Buffer
 * methods on what comes out. The rules (mpint's sign byte and canonical form,
 * the blob layouts) are documented at their one home there.
 */
const sshPub = require('../src/crypto/ssh-pub.js');

const { CURVES, curveInfo } = sshPub;

/* ------------------------------------------------------------ primitives */

const toBuf = (v) => (typeof v === 'string' ? Buffer.from(v, 'utf8') : Buffer.from(v));
const buf = (u8) => Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength);

/** RFC 4251 uint32: four bytes, big-endian. */
const uint32 = (n) => buf(sshPub.uint32(n));

/** RFC 4251 string: a uint32 length, then the bytes. */
const string = (v) => buf(sshPub.string(v));

/** RFC 4251 mpint, from an UNSIGNED big-endian magnitude (src/crypto/ssh-pub.js). */
const mpint = (magnitude) => buf(sshPub.mpint(magnitude));

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

/** The SSH public-key blob for a key the OnlyKey returned (src/crypto/ssh-pub.js). */
const publicKeyBlob = (curve, raw) => buf(sshPub.publicKeyBlob(curve, raw));

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
const { publicKeyLine } = sshPub;

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
