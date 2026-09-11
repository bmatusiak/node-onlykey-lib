'use strict';

/**
 * Firmware update, the wire half: a signed firmware file → the frames the
 * desktop app sends (OnlyKeyComm.js submitFirmware / loadFirmware /
 * submitFirmwareData), and the texts the device answers with.
 *
 * THE SEQUENCE, as the desktop does it:
 *
 *   1. In config mode, send OKFWUPDATE with the payload "1234" - a kick. The
 *      firmware answers "SUCCESSFULL FW LOAD REQUEST, REBOOTING...", writes
 *      two EEPROM bytes (go to bootloader, firmware ready) and restarts
 *      (okcore.cpp:619-626). Anywhere else it answers "Error not in config
 *      mode" or "Error device locked".
 *   2. The key re-enumerates saying BOOTLOADER. Now each LINE of the file is
 *      a block, sent as 57-byte packets with the same 0xFF-or-length header
 *      a restore uses (chunker.hexPackets); the bootloader answers
 *      "RECEIVED OKFWUPDATE" per packet, "NEXT BLOCK" when a block checks
 *      out against the signature chain, and "SUCCESSFULLY LOADED FW" after
 *      the last, then boots the new firmware.
 *
 * Each line is 64 hex characters of this block's signature, one of block
 * info, 64 of the NEXT block's signature, then the block - a chain, so a
 * block sent out of order is refused by the bootloader, not by anything
 * here. The parser keeps the lines whole and in order for that reason.
 *
 * NOT RUN ON HARDWARE. Nothing here has touched a key: the bench key is a
 * developer build nobody can re-image, and a firmware update is the one
 * operation that can brick one. The framing is tested against the fake
 * transport and against the desktop's byte layout; the first hardware run
 * waits for a spare production key, and this comment goes when it happens.
 */

const chunker = require('./chunker');
const { MSG } = require('../protocol/msg');

const BEGIN = '-----BEGIN SIGNED FIRMWARE-----';
const END = '-----END SIGNED FIRMWARE-----';

/** The kick: OKFWUPDATE with "1234" as its two bytes (OnlyKeyComm.js:2100). */
const KICK_HEX = '1234';

/** What the device says at each step. */
const SAYS = {
  REQUESTED: /SUCCESSFULL FW LOAD REQUEST/i,
  RECEIVED: /RECEIVED OKFWUPDATE/i,
  NEXT_BLOCK: /NEXT BLOCK/i,
  LOADED: /SUCCESSFULLY LOADED FW/i,
  ERROR: /^Error/i,
};

/**
 * The blocks of a signed firmware file, in order.
 *
 * The desktop trims the file, drops the first line and the last
 * (parseFirmwareData) and sends everything between - which is BEGIN and
 * END going, since every signed file ends with END. This asks that the
 * first line be the BEGIN marker rather than assuming, stops at END when
 * it is there and keeps every block when it is not (dropping "the last
 * line" of a file without END would drop a block), and refuses a line that
 * is not hex - a block the bootloader would reject halfway through an
 * update is better refused before the kick.
 *
 * @param {string} text
 * @returns {string[]} hex lines, one per block
 */
function parseSignedFirmware(text) {
  const lines = String(text).split(/\r?\n/).map((l) => l.trim());
  while (lines.length && !lines[0]) lines.shift();
  if (lines[0] !== BEGIN) {
    throw new Error(`not a signed firmware file: expected "${BEGIN}" on the first line`);
  }
  lines.shift();
  const endAt = lines.indexOf(END);
  const body = endAt >= 0 ? lines.slice(0, endAt) : lines;
  const blocks = body.filter(Boolean);
  if (!blocks.length) throw new Error('signed firmware file has no blocks');
  blocks.forEach((line, i) => {
    if (!/^[0-9a-f]+$/i.test(line) || line.length % 2) {
      throw new Error(`block ${i + 1} is not hex (${line.length} characters)`);
    }
    if (line.length < 130) {
      throw new Error(`block ${i + 1} is ${line.length} characters, shorter than its two signatures`);
    }
  });
  return blocks;
}

/**
 * What the desktop logs per block, for a progress line.
 *
 * Read in whole bytes. loadFirmware logs slice(64,65) as "block info" and
 * slice(65,129) as the next signature - a nibble boundary, which no byte
 * layout has - so this takes the info byte as two hex characters and the
 * next signature from 66. Which of the two is right is a question for a
 * real signed file, and nothing is sent differently either way: the line
 * goes to the bootloader whole.
 */
function describeBlock(line) {
  return {
    signature: line.slice(0, 64),
    info: line.slice(64, 66),
    nextSignature: line.slice(66, 130),
    bytes: line.length / 2,
  };
}

/** The one frame that asks a config-mode key to reboot into its bootloader. */
function kickFrame() {
  const [packet] = chunker.hexPackets(KICK_HEX);
  return chunker.buildHexPacket(MSG.OKFWUPDATE, packet);
}

/**
 * A block as frames: [{frame, final}], 57 bytes each, 0xFF header on all but
 * the last, whose header is its length - exactly submitFirmwareData's
 * `maxPacketSize = 114` hex characters and `packetHeader`.
 */
function blockFrames(line) {
  return chunker.hexPackets(line).map((packet) => ({
    frame: chunker.buildHexPacket(MSG.OKFWUPDATE, packet),
    final: packet.final,
    bytes: packet.data.length,
  }));
}

module.exports = {
  BEGIN,
  END,
  KICK_HEX,
  SAYS,
  parseSignedFirmware,
  describeBlock,
  kickFrame,
  blockFrames,
};
