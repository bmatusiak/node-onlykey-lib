'use strict';

/**
 * cli/ssh-session-bind.js - which server an ssh connection is talking to,
 * PROVEN, so an Edge budget pays only for the hosts it was opened for
 * (onlykey-edge APP.md, decided 2026-10-03: "check the
 * host key against the pinned github.com keys before the budget pays").
 *
 * OpenSSH 8.9+ sends the agent `session-bind@openssh.com` on every
 * connection (PROTOCOL.agent §1):
 *
 *   byte    SSH_AGENTC_EXTENSION (27)
 *   string  "session-bind@openssh.com"
 *   string  hostkey          the server's host key blob
 *   string  session id       the exchange hash H of this ssh session
 *   string  signature        the server's signature over the session id
 *   bool    is_forwarding
 *
 * The signature is what makes it a proof and not a claim: only the holder of
 * that host key could have signed this session's id, so a forged bind for
 * github.com fails here. A sign request then names its session id as the
 * first field of the data it asks to sign (RFC 4252 §7, the userauth
 * request), and the agent signs under the budget only when that id is the
 * bound one - a signature for some other session never rides on github.com's
 * bind.
 *
 * Pins are SHA-256 fingerprints, the form GitHub publishes ("GitHub's SSH key
 * fingerprints", docs.github.com) and `ssh-keygen -lf` prints. Node only;
 * no device.
 */

const crypto = require('crypto');
const wire = require('./ssh-wire');

const SESSION_BIND = 'session-bind@openssh.com';
const USERAUTH_REQUEST = 50;

/* GitHub's published host key fingerprints (docs.github.com, "GitHub's SSH key fingerprints") */
const GITHUB_FINGERPRINTS = Object.freeze([
  'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU', /* ed25519 */
  'SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM', /* ecdsa-sha2-nistp256 */
  'SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s', /* rsa */
]);

/** `ssh-keygen -lf`'s fingerprint of a key blob: SHA256:<base64, no padding> */
function fingerprint(blob) {
  return `SHA256:${crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;
}

/* an mpint's bytes as an unsigned number of exactly `len` bytes (ECDSA r, s) */
function fixed(mpint, len) {
  let b = Buffer.from(mpint);
  while (b.length > len && b[0] === 0) b = b.subarray(1);
  if (b.length > len) throw new Error('an ECDSA signature value is too long');
  return Buffer.concat([Buffer.alloc(len - b.length), b]);
}

/* a host key blob -> {type, key: node:crypto KeyObject} (ed25519, ecdsa-sha2-nistp256, rsa) */
function hostKeyObject(blob) {
  const r = new wire.Reader(blob);
  const type = r.string().toString('latin1');
  if (type === 'ssh-ed25519') {
    const pk = r.string();
    return { type, key: crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pk]), format: 'der', type: 'spki' }) };
  }
  if (type === 'ecdsa-sha2-nistp256') {
    r.string(); /* the curve name, "nistp256" */
    const q = r.string();
    if (q.length !== 65 || q[0] !== 4) throw new Error('an ecdsa-sha2-nistp256 host key that is not an uncompressed point');
    return {
      type,
      key: crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: q.subarray(1, 33).toString('base64url'), y: q.subarray(33).toString('base64url') }, format: 'jwk' }),
    };
  }
  if (type === 'ssh-rsa') {
    const e = r.string();
    const n = r.string();
    const trim = (b) => { let x = Buffer.from(b); while (x.length > 1 && x[0] === 0) x = x.subarray(1); return x; };
    return { type, key: crypto.createPublicKey({ key: { kty: 'RSA', n: trim(n).toString('base64url'), e: trim(e).toString('base64url') }, format: 'jwk' }) };
  }
  throw new Error(`a host key of type ${type} is not one this agent can check`);
}

/** Does `sigBlob` (string algorithm ‖ string signature) verify `data` under host key `blob`? */
function verifyHostSignature(blob, data, sigBlob) {
  const { type, key } = hostKeyObject(blob);
  const r = new wire.Reader(sigBlob);
  const alg = r.string().toString('latin1');
  const sig = r.string();
  if (type === 'ssh-ed25519' && alg === 'ssh-ed25519') return crypto.verify(null, data, key, sig);
  if (type === 'ecdsa-sha2-nistp256' && alg === 'ecdsa-sha2-nistp256') {
    const s = new wire.Reader(sig);
    const p1363 = Buffer.concat([fixed(s.string(), 32), fixed(s.string(), 32)]);
    return crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, p1363);
  }
  if (type === 'ssh-rsa' && (alg === 'rsa-sha2-256' || alg === 'rsa-sha2-512')) {
    return crypto.verify(alg === 'rsa-sha2-256' ? 'sha256' : 'sha512', data, key, sig);
  }
  return false; /* ssh-rsa with SHA-1, or an algorithm that does not match the key */
}

/**
 * Read a session-bind extension's body (after the name). -> {hostKey,
 * sessionId, fingerprint, forwarding, verified}. `verified` is the host's
 * signature over the session id checking out; a bind that does not verify is
 * still returned (the agent logs it) but never counts as bound.
 */
function parseSessionBind(reader) {
  const hostKey = reader.string();
  const sessionId = reader.string();
  const signature = reader.string();
  const forwarding = reader.remaining > 0 ? reader.uint8() !== 0 : false;
  let verified = false;
  try { verified = verifyHostSignature(hostKey, sessionId, signature); } catch { verified = false; }
  return { hostKey, sessionId, fingerprint: fingerprint(hostKey), forwarding, verified };
}

/** The session id a userauth sign request names (its first field), or null when the data is not a userauth request. */
function userauthSessionId(data) {
  try {
    const r = new wire.Reader(Buffer.from(data));
    const sid = r.string();
    return r.uint8() === USERAUTH_REQUEST ? sid : null;
  } catch {
    return null;
  }
}

/**
 * May the budget pay for this sign request on this connection? Only when the
 * connection was bound - verified, not forwarded - to a host whose
 * fingerprint is pinned, and the request is a userauth for THAT session.
 * -> {ok: true, host} or {ok: false, reason}
 */
function boundToPinned(bind, data, pins) {
  if (!bind) return { ok: false, reason: 'the ssh connection was not bound to a host (no session-bind)' };
  if (!bind.verified) return { ok: false, reason: 'the host\'s session-bind signature does not verify' };
  if (bind.forwarding) return { ok: false, reason: 'a forwarded agent connection' };
  if (!pins.includes(bind.fingerprint)) return { ok: false, reason: `host key ${bind.fingerprint} is not pinned` };
  const sid = userauthSessionId(data);
  if (!sid || !sid.equals(bind.sessionId)) return { ok: false, reason: 'the sign request is not for the bound session' };
  return { ok: true, host: bind.fingerprint };
}

module.exports = {
  SESSION_BIND, GITHUB_FINGERPRINTS, fingerprint, verifyHostSignature, parseSessionBind, userauthSessionId, boundToPinned,
};
