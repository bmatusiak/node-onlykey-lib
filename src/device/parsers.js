/*
 * parsers.js - backup and firmware file formats.
 *
 * From OnlyKeyComm.js (parseBackupData:2624, parseFirmwareData:2419,
 * verifyBackupFile:1968). The two file formats look alike - armoured text with
 * BEGIN/END markers - and are not interchangeable: a backup is base64 and
 * becomes ONE hex stream, firmware is already hex and stays as SEPARATE
 * blocks.
 */
'use strict';

const { sha256 } = require('@noble/hashes/sha2.js');
const { toHex, concat, fromBase64 } = require('../bytes');

const BACKUP_BEGIN = '-----BEGIN ONLYKEY BACKUP-----';
const BACKUP_END = '-----END ONLYKEY BACKUP-----';
const FIRMWARE_BEGIN = '-----BEGIN SIGNED FIRMWARE-----';

/**
 * Lines beginning with '--' are structural, not data.
 *
 * That covers the BEGIN and END markers AND the trailing '--<base64 digest>'
 * line, which is why the test is a prefix rather than an exact match.
 */
function isMarker(line) {
  return line.indexOf('--') === 0;
}

/*
 * Was a runtime branch: atob when present, Buffer otherwise. Under Hermes
 * NEITHER exists - older React Native has no atob and no Buffer at all - so
 * the fallback was not a fallback, and a backup file would have failed to
 * parse on the one platform this library was written for. bytes.fromBase64 is
 * the same twenty lines with no platform question in them.
 */
function base64ToBytes(b64) {
  return fromBase64(String(b64).trim());
}

/**
 * A backup file to the hex stream the device restores from.
 *
 * Every non-marker line is base64; decoded and concatenated they form one
 * continuous stream, which the restore chunker then splits at 57 bytes.
 */
function parseBackup(text) {
  const lines = String(text).split('\n').map((l) => l.trim()).filter(Boolean);
  const data = lines.filter((l) => !isMarker(l)).map(base64ToBytes);
  if (!data.length) {
    throw new Error('no backup data found: every line was a marker or blank');
  }
  return toHex(concat(data));
}

/**
 * Verify a backup file's trailing digest.
 *
 * A rolling hash: start from 32 zero bytes and, for each data line, hash the
 * previous digest concatenated with that line's decoded bytes. The expected
 * value is the base64 on the '--' line that is not the BEGIN/END marker.
 *
 * Chained rather than a hash over the whole file, so a reordering is caught as
 * well as a modification.
 */
function verifyBackup(text) {
  const lines = String(text).split('\n').map((l) => l.trim()).filter(Boolean);

  let digest = new Uint8Array(32);
  let expected = null;

  for (const line of lines) {
    if (isMarker(line)) {
      // The digest line is a marker that is neither BEGIN nor END.
      if (!/BACKUP/.test(line)) expected = line.replace(/^--/, '').trim();
      continue;
    }
    digest = sha256(concat([digest, base64ToBytes(line)]));
  }

  if (!expected) {
    return { ok: false, reason: 'no digest line found', digest: toHex(digest) };
  }

  const want = toHex(base64ToBytes(expected));
  const got = toHex(digest);
  return { ok: want === got, expected: want, digest: got };
}

/**
 * A firmware file to its blocks.
 *
 * NOT the same shape as a backup: these lines are already hex, there is no
 * base64 step, and each line stays a SEPARATE block that is chunked and
 * acknowledged on its own. Concatenating them - which the backup path does -
 * would destroy the block structure the loader depends on.
 *
 * The first line is the BEGIN marker and the last is the END footer; the
 * original drops both by shifting and by iterating to length - 1.
 */
function parseFirmware(text) {
  const lines = String(text).split('\n').map((l) => l.trim()).filter(Boolean);
  const blocks = lines.filter((l) => !isMarker(l));
  if (!blocks.length) {
    throw new Error('no firmware blocks found: every line was a marker or blank');
  }
  for (const block of blocks) {
    if (!/^[0-9a-fA-F]+$/.test(block)) {
      throw new Error('firmware blocks must be hex; this file may be a backup');
    }
    if (block.length % 2 !== 0) {
      throw new Error(`firmware block has odd length ${block.length}`);
    }
  }
  return blocks;
}

/**
 * A firmware block's structure, in HEX CHARACTERS.
 *
 *   [0..63]    this block's signature      (32 bytes)
 *   [64..65]   block info                  (1 byte)
 *   [66..129]  the next block's signature  (32 bytes)
 *   [130..]    the block itself
 *
 * THE INFO FIELD IS A BYTE, AND THIS READ IT AS A NIBBLE. The loader's own
 * comment calls it a nibble, which is true of what it CONTAINS and not of the
 * space it occupies, and every field after the signature was shifted one hex
 * character left as a result. firmware.js:describeBlock had it right all along,
 * so the app's screen was never affected; the only caller here was a test built
 * to the same wrong shape.
 *
 * The release images settle it. Their block lines are 33026 and 32898 hex
 * characters: a 130-character header leaves 16448 and 16384 bytes, the second
 * being exactly a 16 KB flash page, while a 129-character one leaves an odd
 * number of hex characters, which is not a whole number of bytes at all.
 * See ok-rn/FINDING-two-block-describers-disagree-by-a-nibble.md.
 */
function describeFirmwareBlock(block) {
  if (block.length < 66) return null;
  return {
    signature: block.slice(0, 64),
    info: block.slice(64, 66),
    nextSignature: block.length >= 130 ? block.slice(66, 130) : null,
  };
}

/**
 * The literal string that bounces a config-mode device into the bootloader.
 *
 * Sent through the firmware upload path before any real firmware. Four
 * characters, so its packet header is (4/2).toString(16) = '2'. It appears
 * three times in the original, inline and unexplained.
 */
const BOOTLOADER_KICK = '1234';

module.exports = {
  BACKUP_BEGIN,
  BACKUP_END,
  FIRMWARE_BEGIN,
  BOOTLOADER_KICK,
  isMarker,
  parseBackup,
  verifyBackup,
  parseFirmware,
  describeFirmwareBlock,
};
