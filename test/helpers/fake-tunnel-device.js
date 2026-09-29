/*
 * A fake OnlyKey behind the WebAuthn tunnel - the ctap a browser would hand
 * okcrypto, with bridge_to_onlykey() behind it.
 *
 * Modelled on libraries/fido2/ok_extension.cpp (master, 3.0.5) and the v3.0.4
 * staged tree, for the parts a stored-key operation touches. Each behaviour
 * below is one the plugin has to get right, and each is written the way the
 * firmware does it rather than the way a host would like it:
 *
 *   the whole data region is the payload - handle_len, never byte 9 - so a
 *     padded sealed keyhandle fails, as it does on the device;
 *   v2 opens with IV [1 | ctr] and REFUSES a bad tag, staging "Error message
 *     failed authentication" only when nothing else is staged; v1 decrypts
 *     with the zero-IV box and dispatches whatever comes out;
 *   plaintext is split into 57-byte packets, only the final keyhandle's last
 *     packet carries a length;
 *   the duplicate guard drops opt3 <= last with a ret-0 answer (71 bytes of
 *     "stack"); 3.0.5 clears the mark on the final chunk, 3.0.4 leaves the
 *     RNG2 byte process_packets writes there until wipetasks();
 *   a served reply stays staged, re-served from 0, until `wipeMs` of quiet -
 *     the 5-second Wipedata timer, shortened;
 *   from 3.0.5 a composite result is sealed as a v2 frame (libraries a29b063),
 *     before it in the clear.
 *
 * The result bytes are a function of the reassembled payload, so a payload
 * that arrived damaged cannot produce the expected answer.
 */
'use strict';

const nacl = require('../../src/vendor/exports/tweetnacl.js');
const { gcm } = require('../../src/vendor/exports/@noble/ciphers/aes.js');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');

const okconnect = require('../../src/crypto/okconnect');
const transit = require('../../src/session/transit');
const ctap = require('../../src/protocol/ctap');
const version = require('../../src/device/version');
const { challengeDigits } = require('../../src/protocol/challenge');
const { MSG } = require('../../src/protocol/msg');
const { fromLatin1, concat } = require('../../src/bytes');

const CODE = {
  SUCCESS: 0x00,
  EXTENSION_NOT_SUPPORTED: 0x18,
  USER_ACTION_PENDING: 0x23,
  NO_OPERATION_PENDING: 0x2a,
};

/** What the device signs or decrypts to: a function of exactly what arrived. */
function resultFor(cmd, payload) {
  if (cmd === MSG.OKDECRYPT) return sha256(payload);
  const length = payload[0] === 0 ? 64 : 3309;
  const seed = sha256(payload);
  return Uint8Array.from({ length }, (_, i) => (seed[i % 32] + i) & 0xff);
}

/* RESERVED_KEY_WEB_AGENT_DERIVATION: the web-and-agent derivation slot. */
const DERIVED_SLOT = 128;

function fakeTunnelDevice({
  firmware = 'v3.0.5-prodc',
  webcryptLevel = 2,
  wipeMs = 30,
  derived = Uint8Array.from({ length: 65 }, (_, i) => (i === 0 ? 0x04 : i)),
} = {}) {
  const status = `UNLOCKED${firmware}`;
  const v2 = version.capabilities(status).transitV2 === true;

  let key = null;
  let ctrOut = 0;
  let staged = null;
  let cursor = 0;
  let lastServedAt = 0;
  let lastOpt3 = 0;
  let packets = [];
  /*
   * Whether the gathered packets show in the answer to a chunk. On a stored
   * slot they are packet_buffer, so send_stored_response() answers
   * CTAP2_ERR_USER_ACTION_PENDING (ok_extension.cpp:787, packet_buffer_offset).
   * The web-and-agent derivation slot (128) gathers its [label32 | ct] elsewhere
   * - packet_buffer_offset stays 0 - so an ACCEPTED non-final chunk there falls
   * through to CTAP2_ERR_NO_OPERATION_PENDING, "no data ready" (:793-798).
   * Measured on the emulator 2026-09-28 (the device's console: transit open,
   * OKDECRYPT chunk, message received, then "Error no data ready").
   */
  let packetsVisible = true;
  let cryptoAuth = false;
  let pending = null;

  const requests = [];

  function wipetasks() {
    staged = null;
    cursor = 0;
    packets = [];
    cryptoAuth = false;
    pending = null;
    /* v3.0.4 keeps the mark in packet_buffer_details[3], which this zeroes. */
    if (!v2) lastOpt3 = 0;
  }

  /* Staging arms the wipe too: fadeoff() and the serve both call wipedata(). */
  function stage(bytes) { staged = Uint8Array.from(bytes); cursor = 0; lastServedAt = Date.now(); }
  function stageText(text) { stage(fromLatin1(text)); }

  function sealOut(plain) {
    const counter = ctrOut++;
    const ct = gcm(key, transit.transitIv(transit.DIR_FROM_DEVICE, counter)).encrypt(plain);
    return concat([Uint8Array.from([counter >>> 24, (counter >>> 16) & 0xff, (counter >>> 8) & 0xff, counter & 0xff]), ct]);
  }

  function openIn(region) {
    if (region.length < transit.OVERHEAD) return null;
    const counter = ((region[0] << 24) >>> 0) + (region[1] << 16) + (region[2] << 8) + region[3];
    try {
      return gcm(key, transit.transitIv(transit.DIR_TO_DEVICE, counter)).decrypt(region.subarray(4));
    } catch (_) {
      return null;
    }
  }

  function answer(code, data = null) {
    const sig = data ? concat([Uint8Array.of(code), data]) : Uint8Array.of(code);
    return new Map([[2, new Uint8Array(37)], [3, sig]]);
  }

  function serve() {
    if (staged) {
      const piece = staged.subarray(cursor, cursor + 512);
      cursor += piece.length;
      lastServedAt = Date.now();
      if (cursor >= staged.length) cursor = 0; /* delivered, and STILL staged */
      return answer(CODE.SUCCESS, piece);
    }
    /* ret with no writeback: sigder's default 72 bytes, 71 of them stack. */
    if (cryptoAuth || (packets.length && packetsVisible)) return answer(CODE.USER_ACTION_PENDING, new Uint8Array(71));
    return answer(CODE.NO_OPERATION_PENDING);
  }

  function connect(region, opt1, opt3) {
    const pair = nacl.box.keyPair();
    key = okconnect.transitKey(region.subarray(9, 41), pair.secretKey);
    ctrOut = 0;
    const statusBytes = concat([fromLatin1(status), Uint8Array.of(0)]);
    if (!opt1) {
      /* opt3 is sent 0 for a plain connect; the reply is not sealed. */
      stage(concat([pair.publicKey, statusBytes]));
      return;
    }
    /* A P-256 public-key derive, sealed "everything but the transit pubkey". */
    const body = concat([statusBytes, derived]);
    const sealed = v2 ? sealOut(body) : okconnect.decryptBody(key, body);
    stage(concat([pair.publicKey, sealed]));
  }

  const device = {
    firmware,
    v2,
    requests,

    /** What another client connecting would do: a key this host does not hold. */
    rekey() { key = nacl.randomBytes(32); ctrOut = 0; },

    /** The challenge being entered on the device. */
    enter(digits) {
      if (!pending) throw new Error('fake: no challenge is pending');
      const want = challengeDigits(pending.payload, { formula: 'modern' });
      if (digits && digits.join('-') !== want.join('-')) {
        cryptoAuth = false;
        pending = null;
        stageText('Error incorrect challenge was entered');
        return;
      }
      const result = resultFor(pending.cmd, pending.payload);
      stage(v2 ? sealOut(result) : result);
      cryptoAuth = false;
      pending = null;
      packets = [];
    },

    get pendingPayload() { return pending ? pending.payload : null; },

    async getAssertion(params) {
      const id = params.get(3)[0].get('id');
      const [cmd, opt1, opt2, opt3] = id;
      /* handle_len - 10: the WHOLE region, padding included. */
      const region = Uint8Array.from(id.subarray(ctap.HEADER));
      const record = { cmd, opt1, opt2, opt3, length: region.length };
      requests.push(record);

      if (staged && !cryptoAuth && !packets.length && Date.now() - lastServedAt >= wipeMs) {
        wipetasks();
      }
      if (!webcryptLevel) return answer(CODE.EXTENSION_NOT_SUPPORTED);

      if (cmd === okconnect.OKCONNECT && !cryptoAuth) {
        connect(region, opt1, opt3);
        return serve();
      }

      let plain;
      if (v2) {
        plain = openIn(region);
        record.counter = ((region[0] << 24) >>> 0) + (region[1] << 16) + (region[2] << 8) + region[3];
        if (!plain) {
          record.authFailed = true;
          if (!staged && !cryptoAuth) stageText('Error message failed authentication');
          return serve();
        }
      } else {
        plain = transit.box(key, region);
      }

      if (cmd === MSG.OKPING) {
        if (!cryptoAuth && !staged) stageText('Error incorrect challenge was entered');
        return serve();
      }

      if (!cryptoAuth && (cmd === MSG.OKSIGN || cmd === MSG.OKDECRYPT)) {
        if (webcryptLevel < 2) {
          stageText('Error stored key use over FIDO2 not enabled');
          return serve();
        }
        if (!lastOpt3) lastOpt3 = opt3;
        else if (opt3 <= lastOpt3) {
          record.dropped = true;
          return answer(CODE.SUCCESS, new Uint8Array(71).fill(0xcc));
        }
        packetsVisible = !(cmd === MSG.OKDECRYPT && opt1 === DERIVED_SLOT);
        let left = plain.length;
        let at = 0;
        while (left > 0) {
          const last = opt2 && left <= 57;
          const take = last ? left : 57;
          const packet = new Uint8Array(take);
          packet.set(plain.subarray(at, at + Math.min(take, left)));
          packets.push(packet);
          lastOpt3 = opt3;
          at += 57;
          left -= 57;
        }
        if (opt2) {
          /* 3.0.5 clears the mark; 3.0.4's RNG2 leaves a byte of noise in it. */
          lastOpt3 = v2 ? 0 : 200;
          cryptoAuth = true;
          pending = { cmd, payload: concat(packets) };
        }
      }
      return serve();
    },
  };
  return device;
}

module.exports = { fakeTunnelDevice, resultFor };
