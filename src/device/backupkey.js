/*
 * backupkey.js - which backup key opens a backup file, decided on the HOST.
 *
 * ## Why this exists: the device cannot be asked twice
 *
 * The owner's decision (2026-09-30, N-1) is that a restore tries the UTF-8
 * key and falls back to the Latin-1 key when the device refuses. The firmware
 * does not allow that conversation. RESTORE (okcore.cpp:6477 at release
 * 3.1.0) answers a wrong key with "Error incorrect backup key set", blinks,
 * and CPU_RESTART()s (:6630-6636) - and it restarts on success too (:6846-6853).
 * So a second attempt is not a second packet; it is:
 *
 *   - the key re-enumerating, then a PIN entered ON THE DEVICE to unlock it;
 *   - config mode entered again - also a gesture on the device - because the
 *     first-use window (`!initcheck`) closes at the first reboot after the PIN
 *     is set (initcheck = a nonce hash exists in flash, :760, :863-865), and
 *     both OKSETPRIV and OKRESTORE need one or the other (:417, :516);
 *   - and on a key whose backup-key mode is LOCKED, no second attempt at all:
 *     set_private refuses to replace slot 131 once initcheck is set (:4775).
 *
 * None of that is automatic, and the last case is not possible. So the
 * fallback happens before anything is sent: the host works out which key the
 * device would accept, sets that one, and restores once.
 *
 * ## Why the host CAN work it out
 *
 * Everything the device uses to decrypt a passphrase backup is derived from
 * the 32-byte key the host itself computed:
 *
 *   file  = ciphertext || iv(12) || (type + 100)          (backup, :6346-6357)
 *   pub   = Ed25519 public key of the slot-131 scalar     (okcrypto_compute_pubkey)
 *   s     = crypto_box_beforenm(pub, scalar)              (okcrypto_shared_secret,
 *                                                          KEYTYPE_NACL = 1)
 *   key   = sha256(s || pub || iv)                        (:6571-6582)
 *   plain = AES-256-GCM decrypt, tag NOT checked          (okcrypto_aes_gcm_decrypt2,
 *                                                          s=false: no sundae layers)
 *
 * and the device's ONLY test of the key is the first plaintext byte: below
 * 0xFD it is "Error incorrect backup key set" (:6629-6636). This module runs
 * exactly that test. It is a prediction of the device's answer, not a stronger
 * check - the device would take any key that passes it - so where both
 * candidates pass (about 1 in 85 for a Latin-range passphrase, 3/256), it
 * refuses to guess and the caller names the encoding.
 *
 * GCM without the tag is CTR from J0+1: for a 12-byte IV the first keystream
 * block is AES(key, iv || 00000002), which is what rweather's GCM does.
 */
'use strict';

const { sha256 } = require('../vendor/exports/@noble/hashes/sha2.js');
const { ctr } = require('../vendor/exports/@noble/ciphers/aes.js');
const { ed25519 } = require('../vendor/exports/@noble/curves/ed25519.js');
const { beforenm } = require('../session/transit');
const { concat } = require('../bytes');
const keys = require('./keys');

/** The trailing byte of a backup made with an Ed25519 key - every passphrase key. */
const PASSPHRASE_BACKUP_TRAILER = 100 + keys.CURVE.ED25519;

/** The device's acceptance threshold for the first decrypted byte (:6629). */
const FIRST_BYTE_MIN = 0xfd;

const IV_BYTES = 12;

/**
 * Would the device accept this backup with this slot-131 key?
 *
 * @param {Uint8Array} blob  the decoded backup (parsers.parseBackup, as bytes)
 * @param {Uint8Array} key   the 32-byte backup key (sha256 of the passphrase bytes)
 * @returns {{accepted: boolean|null, firstByte?: number, reason?: string}}
 *   `accepted: null` when the file is not a passphrase-protected backup and
 *   the question cannot be answered.
 */
function predictRestore(blob, key) {
  if (!(blob instanceof Uint8Array) || blob.length < IV_BYTES + 2) {
    return { accepted: null, reason: 'the backup is too short to hold a key trailer' };
  }
  const trailer = blob[blob.length - 1];
  if (trailer !== PASSPHRASE_BACKUP_TRAILER) {
    return {
      accepted: null,
      reason: `the backup was made with a key of type ${trailer - 100}, not the `
        + `Ed25519 key a passphrase becomes (trailer ${trailer}, expected `
        + `${PASSPHRASE_BACKUP_TRAILER}) - it is protected by an RSA or PGP backup key`,
    };
  }
  const iv = blob.subarray(blob.length - 1 - IV_BYTES, blob.length - 1);
  const head = blob.subarray(0, Math.min(16, blob.length - 1 - IV_BYTES));

  const pub = ed25519.getPublicKey(key);
  const aesKey = sha256(concat([beforenm(pub, key), pub, iv]));
  const counter = concat([iv, Uint8Array.from([0, 0, 0, 2])]);
  const firstByte = ctr(aesKey, counter).decrypt(head)[0];
  return { accepted: firstByte >= FIRST_BYTE_MIN, firstByte };
}

/**
 * Pick the key a passphrase backup will restore with.
 *
 * Tries keys.backupPassphraseCandidates() in order - UTF-8, then Latin-1
 * legacy only when the two differ - against predictRestore().
 *
 * @param {Uint8Array} blob
 * @param {string} passphrase
 * @param {object} [opts]
 * @param {'utf-8'|'latin-1-legacy'|'truncated-legacy'|null} [opts.encoding] skip the choice and
 *   use this form (still checked: a key the device would refuse is refused here)
 * @returns {{slot: number, type: number, key: Uint8Array, encoding: string, tried: string[]}}
 * @throws when no candidate opens the backup, or two do and none was named
 */
function chooseBackupKey(blob, passphrase, { encoding = null } = {}) {
  const candidates = encoding
    ? [keys.backupKeyFromPassphrase(passphrase, { encoding })]
    : keys.backupPassphraseCandidates(passphrase);
  const tried = candidates.map((c) => c.encoding);

  const results = candidates.map((c) => ({ c, p: predictRestore(blob, c.key) }));
  const unknown = results.find((r) => r.p.accepted === null);
  if (unknown) throw new Error(`cannot restore this backup with a passphrase: ${unknown.p.reason}`);

  const opens = results.filter((r) => r.p.accepted);
  if (opens.length === 1) return { ...opens[0].c, tried };
  if (opens.length > 1) {
    /*
     * Both pass the device's one-byte test, so the device would take either,
     * and the wrong one would be written into the slots as garbage. Refused
     * rather than guessed; the caller asks the person which App made it.
     */
    throw new Error(
      'this passphrase opens the backup in both its UTF-8 and its Latin-1 form '
      + 'by the device\'s own test, so which one made it cannot be told apart. '
      + 'Nothing was sent. Restore again naming the encoding: '
      + '{ passphraseEncoding: \'latin-1-legacy\' } for a backup made by the '
      + 'classic OnlyKey App, \'utf-8\' otherwise.',
    );
  }
  throw new Error(
    `the passphrase does not open this backup (tried ${tried.join(' and ')}). `
    + 'Nothing was sent: the device would have answered "Error incorrect backup '
    + 'key set" and restarted.',
  );
}

module.exports = {
  PASSPHRASE_BACKUP_TRAILER,
  FIRST_BYTE_MIN,
  predictRestore,
  chooseBackupKey,
};
