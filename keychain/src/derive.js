'use strict';
const { identityHash } = require('../../src/protocol/agent');
const { toHex } = require('../../src/bytes');

/**
 * DERIVE - a public key the OnlyKey makes from a label, kept in Key Chain so it
 * can be copied, shared and used as a recipient (owner, 2026-10-01).
 *
 * Nothing private is kept: the device derives the same key from the same
 * label every time, so its private half is re-made on the device whenever it
 * is needed and never exists anywhere else. What Key Chain keeps is the label,
 * the type and the public key - an entry in its public list.
 *
 * Three ways the device derives, each already in okcrypto:
 *
 *   label  derivePublicKey(label, { keytype }) - the web/vault derivation
 *          (P-256, secp256k1, X25519) and the X-Wing age identity
 *          (deviceAge.identity). Over FIDO, as the web app does.
 *   ssh    agent.publicKey(identity) - what an SSH agent would offer for
 *          user@host (Ed25519, P-256), derivation v1 or v2.
 *   gpg    agent.publicKey({ gpg: uid }) - the same for a GPG user id.
 *
 * okcrypto is passed in, as composite takes openpgp: this module stays plain
 * and any host that composed the lib's plugins can call it.
 */

const artifacts = require('./artifacts');

const LABEL_TYPES = Object.freeze({ p256: 1, secp256k1: 2, x25519: 3 });
const AGENT_TYPES = Object.freeze({ ed25519: 1, p256: 2 });

/**
 * @param {any} okcrypto the okcrypto service (app.services.okcrypto)
 * @param {{scheme: 'label'|'ssh'|'gpg', label: string, type: string,
 *   version?: 1|2, requirePress?: boolean, comment?: string, now?: () => Date}} spec
 * @returns {Promise<{kind: 'derived', scheme: string, label: string, type: string,
 *   version?: number, publicKey: Uint8Array, artifacts: object, created: string}>}
 */
async function derivePublic(okcrypto, spec) {
  const { scheme, label, type, version = 1, requirePress = false, comment, now = () => new Date() } = spec;
  if (!okcrypto) throw new Error('derivePublic needs the okcrypto service');
  if (typeof label !== 'string' || !label) throw new Error('a derived key needs a label (or identity)');

  let publicKey;
  if (scheme === 'label') {
    if (type === 'xwing') {
      publicKey = (await okcrypto.deviceAge.identity(label)).recipient;
    } else if (LABEL_TYPES[type] !== undefined) {
      const derived = await okcrypto.derivePublicKey(label, { keytype: LABEL_TYPES[type], requirePress });
      publicKey = Uint8Array.from(derived.publicKey);
      /* A P-256/secp256k1 point may come as 0x04||X||Y; Key Chain keeps X||Y like the slots. */
      if ((type === 'p256' || type === 'secp256k1') && publicKey.length === 65) publicKey = publicKey.slice(1);
    } else {
      throw new Error(`a label derives ${Object.keys(LABEL_TYPES).join(', ')} or xwing; not "${type}"`);
    }
  } else if (scheme === 'ssh' || scheme === 'gpg') {
    if (AGENT_TYPES[type] === undefined) {
      throw new Error(`an ${scheme} identity derives ${Object.keys(AGENT_TYPES).join(' or ')}; not "${type}"`);
    }
    /* The agent's identity shapes (protocol/agent.js identityHash): user@host, or a host alone. */
    const at = label.lastIndexOf('@');
    const identity = scheme === 'gpg'
      ? { gpg: label }
      : { ssh: at > 0 ? { user: label.slice(0, at), host: label.slice(at + 1) } : { host: label } };
    publicKey = Uint8Array.from(await okcrypto.agent.publicKey(identity, { keyType: AGENT_TYPES[type], version }));
  } else {
    throw new Error(`unknown derivation scheme "${scheme}" - label, ssh or gpg`);
  }

  return {
    kind: 'derived',
    scheme,
    label,
    type,
    ...(scheme === 'label' ? {} : { version }),
    publicKey,
    artifacts: artifacts.forKey({ type, publicKey, comment: comment || (scheme === 'ssh' ? label : undefined) }),
    created: now().toISOString(),
  };
}

/*
 * THE 32-BYTE LABEL A KEY SEES for an entry (Brad, 2026-10-10: the firmware presents what it
 * signs). A derived sign carries only this hash, never the text; the soft key reports it with
 * each press (its key_chain plugin), and the phone names the identity by finding the entry whose
 * label hashes to it - the same shapes as protocol/agent.js identityHash: gpg://<uid>, user@host,
 * or a host alone. An entry the firmware recorded already carries its hash (labelHash, or a
 * "hash:" label). -> lowercase hex, or null for an entry no agent sign can name.
 */
function labelHashOf(entry) {
  if (!entry || entry.kind !== 'derived') return null;
  if (typeof entry.labelHash === 'string' && /^[0-9a-f]{64}$/i.test(entry.labelHash)) return entry.labelHash.toLowerCase();
  const label = String(entry.label || '');
  if (label.startsWith('hash:')) return /^[0-9a-f]{64}$/i.test(label.slice(5)) ? label.slice(5).toLowerCase() : null;
  if (entry.scheme !== 'ssh' && entry.scheme !== 'gpg') return null;
  const at = label.lastIndexOf('@');
  const identity = entry.scheme === 'gpg'
    ? { gpg: label }
    : { ssh: at > 0 ? { user: label.slice(0, at), host: label.slice(at + 1) } : { host: label } };
  try {
    return toHex(identityHash(identity));
  } catch {
    return null;
  }
}

/** An entry's identity as the person knows it: gpg://<uid> or ssh://user@host. */
function identityName(entry) {
  if (!entry || entry.kind !== 'derived') return null;
  if (entry.scheme === 'gpg') return `gpg://${entry.label}`;
  if (entry.scheme === 'ssh') return `ssh://${entry.label}`;
  /* an entry the firmware recorded holds only the hash ("hash:…"): it has no name to give */
  const label = entry.label ? String(entry.label) : '';
  return label && !label.startsWith('hash:') ? label : null;
}

module.exports = { LABEL_TYPES, AGENT_TYPES, derivePublic, labelHashOf, identityName };
