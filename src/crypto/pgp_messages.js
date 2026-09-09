/**
 * Encrypt, decrypt, sign and verify PGP messages and files.
 *
 * These are the four pages the desktop app links out to - `/app/encrypt`,
 * `/app/decrypt`, `/app/encrypt-file`, `/app/decrypt-file`. They live here so
 * that every GUI gets the same behaviour rather than each one calling openpgp
 * differently, which is the whole argument for this library existing.
 *
 * ## openpgp is an ARGUMENT, not an import
 *
 * The same rule composite_pgp.js follows, and for the same reason: the vendored
 * fork is 1.2 MB, and a caller doing age or X-Wing must not drag it in. Pass it
 * from `node-onlykey-lib/crypto/pgp`.
 *
 * On a runtime without WebCrypto - React Native - that module cannot even be
 * required until the shim is installed, because OpenPGP.js v6 reads WebCrypto
 * at module scope. See src/webcrypto/subtle.js.
 *
 * ## Text and binary are different, and the difference is not cosmetic
 *
 * A PGP message carries a format byte saying whether its content is text or
 * binary, and openpgp normalises line endings for text. Encrypting a file as
 * text corrupts it - CRLF conversion applied to a PNG is not reversible - so
 * the two entry points are separate rather than one with a flag that is easy to
 * leave at its default.
 *
 * ## Armour is a transport choice, not a security one
 *
 * Armoured output is base64 with a header, for pasting into a message box.
 * Binary output is the same bytes without it, for a file. Both are the same
 * ciphertext; `armor: false` is not weaker.
 */
'use strict';

const { utf8ToBytes } = require('../bytes');

/**
 * An armoured key, or an openpgp Key object already in hand.
 *
 * @typedef {string|object} KeyLike
 */

/**
 * One signature's verdict.
 *
 * `valid` is false rather than absent when verification failed, and `error`
 * says why - openpgp's own result rejects a promise instead, which surfaces as
 * an unhandled rejection somewhere unrelated.
 *
 * @typedef {{keyID: string, valid: boolean, error: string|null}} SignatureResult
 */

/*
 * Every option object below is written out in full, INCLUDING the properties
 * with no default. TypeScript's declaration emit infers a destructured
 * parameter's type from the defaults alone, so `data` and `recipients` - which
 * have none - were simply missing from the generated .d.ts, and a consumer
 * passing them got "Object literal may only specify known properties".
 */

/**
 * Read one or more public keys from armour.
 *
 * Takes a single armoured block or an array of them, and always returns an
 * array - because "encrypt to one recipient" and "encrypt to three" should not
 * be different call shapes at the caller.
 */
async function readPublicKeys(openpgp, armored) {
  const list = Array.isArray(armored) ? armored : [armored];
  const keys = [];
  for (const item of list) {
    if (!item) continue;
    // Already a Key object? Pass it through; re-reading is lossy for a key
    // that was decrypted in memory.
    keys.push(typeof item === 'string' ? await openpgp.readKey({ armoredKey: item }) : item);
  }
  if (!keys.length) throw new Error('no recipient keys');
  return keys;
}

/** The same, for private keys, unlocking with a passphrase when one is given. */
async function readPrivateKeys(openpgp, armored, passphrase) {
  const list = Array.isArray(armored) ? armored : [armored];
  const keys = [];
  for (const item of list) {
    if (!item) continue;
    let key = typeof item === 'string' ? await openpgp.readPrivateKey({ armoredKey: item }) : item;
    /*
     * A locked key fails LATER and unhelpfully - the decrypt reports that no
     * decryption key matched, which is true and says nothing about the
     * passphrase. Unlock here so the error names the real problem.
     */
    if (passphrase && !key.isDecrypted()) {
      key = await openpgp.decryptKey({ privateKey: key, passphrase });
    }
    keys.push(key);
  }
  if (!keys.length) throw new Error('no decryption keys');
  return keys;
}

/**
 * Encrypt text to one or more recipients.
 *
 * @param {object} openpgp the vendored fork
 * @param {{
 *   text: string,
 *   recipients: KeyLike|KeyLike[],
 *   signWith?: KeyLike|KeyLike[]|null,
 *   passphrase?: string|null,
 *   armor?: boolean,
 * }} opts
 * @returns {Promise<string|Uint8Array>} armoured text, or bytes when armor is false
 */
async function encryptText(openpgp, {
  text, recipients, signWith = null, passphrase = null, armor = true,
} = {}) {
  if (typeof text !== 'string') throw new TypeError('encryptText needs text');

  const encryptionKeys = await readPublicKeys(openpgp, recipients);
  const signingKeys = signWith ? await readPrivateKeys(openpgp, signWith, passphrase) : undefined;

  const message = await openpgp.createMessage({ text });
  return openpgp.encrypt({
    message,
    encryptionKeys,
    signingKeys,
    format: armor ? 'armored' : 'binary',
  });
}

/**
 * Encrypt a file's bytes.
 *
 * `filename` travels inside the message. openpgp defaults it to 'msg.txt',
 * which is wrong for a file and is what the receiving client will offer to save
 * it as, so it is passed explicitly.
 *
 * @param {object} openpgp
 * @param {{
 *   data: Uint8Array,
 *   filename?: string,
 *   recipients: KeyLike|KeyLike[],
 *   signWith?: KeyLike|KeyLike[]|null,
 *   passphrase?: string|null,
 *   armor?: boolean,
 * }} opts
 * @returns {Promise<string|Uint8Array>}
 */
async function encryptFile(openpgp, {
  data, filename = 'file', recipients, signWith = null, passphrase = null, armor = false,
} = {}) {
  if (!(data instanceof Uint8Array)) throw new TypeError('encryptFile needs data as a Uint8Array');

  const encryptionKeys = await readPublicKeys(openpgp, recipients);
  const signingKeys = signWith ? await readPrivateKeys(openpgp, signWith, passphrase) : undefined;

  const message = await openpgp.createMessage({ binary: data, filename });
  return openpgp.encrypt({
    message,
    encryptionKeys,
    signingKeys,
    format: armor ? 'armored' : 'binary',
  });
}

/**
 * Read a message back.
 *
 * ## Verification failures do not throw here
 *
 * openpgp's signature results are promises that REJECT when a signature is bad,
 * and a caller that does not await them individually gets an unhandled
 * rejection rather than an answer. Worse, `expectSigned` would make a bad
 * signature indistinguishable from a bad key at the call site.
 *
 * So each signature is awaited and reported: `signatures` is a list of
 * `{ keyID, valid, error }`. A caller decides what to do about an invalid one -
 * which is the only place that decision can sensibly be made, since "encrypted
 * to me but signed by someone I do not know" is a different problem in a chat
 * client than in a backup tool.
 *
 * @param {object} openpgp
 * @param {{
 *   armored?: string|null,
 *   binary?: Uint8Array|null,
 *   decryptWith: KeyLike|KeyLike[],
 *   passphrase?: string|null,
 *   verifyWith?: KeyLike|KeyLike[]|null,
 *   format?: 'utf8'|'binary',
 * }} opts
 * @returns {Promise<{data: string|Uint8Array, filename: string, signatures: SignatureResult[]}>}
 */
async function decryptMessage(openpgp, {
  armored, binary, decryptWith, passphrase = null, verifyWith = null, format = 'utf8',
} = {}) {
  const message = armored
    ? await openpgp.readMessage({ armoredMessage: armored })
    : await openpgp.readMessage({ binaryMessage: binary });

  const decryptionKeys = await readPrivateKeys(openpgp, decryptWith, passphrase);
  const verificationKeys = verifyWith ? await readPublicKeys(openpgp, verifyWith) : undefined;

  const result = await openpgp.decrypt({
    message,
    decryptionKeys,
    verificationKeys,
    format,
  });

  return {
    data: result.data,
    filename: result.filename,
    signatures: await describeSignatures(result.signatures),
  };
}

/**
 * Sign text without encrypting it.
 *
 * `detached` produces a signature that travels separately from the text;
 * otherwise the result is a cleartext-signed message, which is the form a
 * person can still read without a PGP client.
 *
 * @param {object} openpgp
 * @param {{
 *   text: string,
 *   signWith: KeyLike|KeyLike[],
 *   passphrase?: string|null,
 *   detached?: boolean,
 *   armor?: boolean,
 * }} opts
 * @returns {Promise<string|Uint8Array>}
 */
async function signText(openpgp, {
  text, signWith, passphrase = null, detached = false, armor = true,
} = {}) {
  if (typeof text !== 'string') throw new TypeError('signText needs text');
  const signingKeys = await readPrivateKeys(openpgp, signWith, passphrase);

  if (detached) {
    const message = await openpgp.createMessage({ text });
    return openpgp.sign({
      message, signingKeys, detached: true, format: armor ? 'armored' : 'binary',
    });
  }

  const message = await openpgp.createCleartextMessage({ text });
  return openpgp.sign({ message, signingKeys, format: 'armored' });
}

/**
 * Check a signature.
 *
 * Handles both shapes: a cleartext-signed message carrying its own text, and a
 * detached signature over text supplied separately. Which one it is is decided
 * by whether `text` was given, not by inspecting the armour - a caller that
 * holds the text knows which it meant.
 *
 * @param {object} openpgp
 * @param {{
 *   armored: string,
 *   text?: string|null,
 *   verifyWith: KeyLike|KeyLike[],
 * }} opts
 * @returns {Promise<{data: string|Uint8Array, signatures: SignatureResult[], valid: boolean}>}
 */
async function verifyText(openpgp, {
  armored, text = null, verifyWith,
} = {}) {
  const verificationKeys = await readPublicKeys(openpgp, verifyWith);

  const result = text === null
    ? await openpgp.verify({
      message: await openpgp.readCleartextMessage({ cleartextMessage: armored }),
      verificationKeys,
    })
    : await openpgp.verify({
      message: await openpgp.createMessage({ text }),
      signature: await openpgp.readSignature({ armoredSignature: armored }),
      verificationKeys,
    });

  const signatures = await describeSignatures(result.signatures);
  return {
    data: result.data,
    signatures,
    /** True only if there is at least one signature and every one is good. */
    valid: signatures.length > 0 && signatures.every((s) => s.valid),
  };
}

/**
 * Turn openpgp's signature promises into plain results.
 *
 * Each `verified` is a promise that REJECTS on a bad signature. Leaving them
 * unawaited produces an unhandled rejection somewhere else entirely, which is
 * the kind of failure that gets blamed on the wrong subsystem.
 *
 * @param {object[]} signatures
 * @returns {Promise<SignatureResult[]>}
 */
async function describeSignatures(signatures) {
  if (!Array.isArray(signatures)) return [];
  const out = [];
  for (const sig of signatures) {
    const entry = { keyID: sig.keyID && sig.keyID.toHex ? sig.keyID.toHex() : String(sig.keyID) };
    try {
      entry.valid = await sig.verified;
      entry.error = null;
    } catch (e) {
      entry.valid = false;
      entry.error = String(e && e.message ? e.message : e);
    }
    out.push(entry);
  }
  return out;
}

/** Is this text a PGP message, a signed message, or neither? */
function classifyArmor(text) {
  const s = String(text || '');
  if (/-----BEGIN PGP MESSAGE-----/.test(s)) return 'message';
  if (/-----BEGIN PGP SIGNED MESSAGE-----/.test(s)) return 'signed';
  if (/-----BEGIN PGP SIGNATURE-----/.test(s)) return 'signature';
  if (/-----BEGIN PGP PUBLIC KEY BLOCK-----/.test(s)) return 'public-key';
  if (/-----BEGIN PGP PRIVATE KEY BLOCK-----/.test(s)) return 'private-key';
  return 'unknown';
}

module.exports = {
  encryptText,
  encryptFile,
  decryptMessage,
  signText,
  verifyText,
  readPublicKeys,
  readPrivateKeys,
  classifyArmor,
  describeSignatures,
  utf8ToBytes,
};
