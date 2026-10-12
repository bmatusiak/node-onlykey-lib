'use strict';

/**
 * PUBLIC ONLY: the one guard for lists that must never hold a private key.
 *
 * Key Chain's list (keychain/src/list.js) and Guest Book (guestbook/) both hold other people's or
 * your own PUBLIC keys and nothing else (Brad, 2026-10-12, for Guest Book: "guest book is only for
 * public output, it should not contain or show any private keys"). One rule, shared, so the two
 * can never drift apart: a field a private key travels under, or text only a private key carries,
 * is refused before it is stored.
 */

/* Field names a private key travels under, and text that only a private key carries. */
const PRIVATE_FIELDS = ['secret', 'privateKey', 'private', 'scalar', 'seed', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'blob'];
/* PEM "... PRIVATE KEY" (OpenSSH, PKCS#8, EC), age's AGE-SECRET-KEY-1..., an armored PGP private block */
const PRIVATE_TEXT = /PRIVATE KEY|AGE-SECRET-KEY-|-----BEGIN PGP PRIVATE/i;

/**
 * Throws when `value` (an object walked deeply, or a string) carries private key material.
 * @param {unknown} value
 * @param {string} where - the path named in the message
 * @param {string} [holder] - what refuses it, named in the message
 */
function refusePrivate(value, where, holder = 'the Key Chain list') {
  if (value && typeof value === 'object' && !(value instanceof Uint8Array)) {
    for (const [k, v] of Object.entries(value)) {
      if (PRIVATE_FIELDS.includes(k)) {
        throw new Error(`${holder} holds public data only - "${where}.${k}" looks like a private key`);
      }
      refusePrivate(v, `${where}.${k}`, holder);
    }
  } else if (typeof value === 'string' && PRIVATE_TEXT.test(value)) {
    throw new Error(`${holder} holds public data only - "${where}" contains private key text`);
  }
}

/** True when the text carries private key material (the same test, for a caller that explains it itself). */
const isPrivateText = (text) => typeof text === 'string' && PRIVATE_TEXT.test(text);

module.exports = { PRIVATE_FIELDS, PRIVATE_TEXT, refusePrivate, isPrivateText };
