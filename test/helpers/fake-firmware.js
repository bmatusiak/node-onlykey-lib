/*
 * A fake firmware, layered over the fake pipe.
 *
 * The device plugin is almost entirely sequencing - which message, in what
 * order, waiting for which printed line - so testing it needs something that
 * answers the way the firmware answers, not something that returns canned
 * bytes. In particular it has to reproduce the two behaviours that make the
 * PIN flow awkward:
 *
 *   The same message id means different things depending on how many times it
 *   has been sent. The firmware treats OKPIN as a toggle, so the bracket is
 *   positional and a host that sends one too many silently skips a step.
 *
 *   Digits are acknowledged INDIVIDUALLY, one printed line each. A host that
 *   waits for the first ack carries on while the rest are still arriving.
 *
 * Everything it prints is the firmware's own wording, matched by the regexes
 * in src/device/pin.js.
 */
'use strict';

const { fakePipe } = require('./fake-pipe');
const { IFACE } = require('../../src/transport/contract');
const { MSG } = require('../../src/protocol/msg');
const { toLatin1 } = require('../../src/bytes');

/**
 * The classic bracket, in order. One entry per OKPIN the host sends.
 *
 * THE LAST SEND ANSWERS TWICE. A real device prints "Both PINs Match" at the
 * top of its commit block and "Successfully set PIN" once the flash write is
 * done, and the host waits for the second - see PROMPTS.committed in
 * src/device/pin.js for what went wrong when it did not.
 */
const PIN_REPLIES = ['Enter PIN\n', 'Storing PIN\n', 'Confirm PIN\n', 'Both PINs Match\nSuccessfully set PIN\n'];
/* The same bracket as the vendor interface carries it (see `noConsole`). */
const PIN_WIRE_REPLIES = [
  'OnlyKey is ready, enter your PIN',
  'Successful PIN entry',
  'Now re-enter your PIN',
  'Successfully set PIN',
];

/**
 * @param {object} [opts]
 *   pinFailAt   - index into PIN_REPLIES to answer with an error instead
 *   pinError    - the error text to use
 *   labels      - array of label strings, 1-based by slot
 *   labelSlots  - how many slots the device reports (12 classic, 24 duo)
 *   dropTerminal- never send the last label, to exercise the deadline
 */
/* wipe_slot()'s replies, one per field (okcore.cpp at 8d28305). */
const WIPED_FIELDS = [
  'Label', 'URL', 'Additional Characters', 'Delay 1', 'Username',
  'Delay 2', 'Password', 'Delay 3', '2FA Type', '2FA Key',
];

function fakeFirmware(opts = {}) {
  const {
    slotError = null,
    slotSilent = false,
    /* The real firmware drops OKSETPRIV outside config mode, saying nothing. */
    setPrivSilent = false,
    pinFailAt = -1,
    pinError = 'Error PIN is not between 7 - 10 digits',
    labels = null,
    labelSlots = 12,
    dropTerminal = false,
    ackDigits = true,
    /* No readable debug console: PIN replies on the vendor interface only. */
    noConsole = false,
    pin = null,          // when set, the device starts LOCKED and this unlocks it
    /*
     * The model letter is part of this, because HW_MODEL() appends one
     * unconditionally - 'c' Classic, 'p'/'n' DUO, 'o' Original. A fixture
     * without it is a device that has never existed, and detection reading
     * "unknown" from a fixture would hide a real failure to detect.
     */
    version = 'v3.0.4-prodc',
    /* slot -> public key bytes, for OKGETPUBKEY. Absent means an empty slot. */
    pubKeys = {},
    /*
     * slot -> what probeKeySlot has to tell apart: 'ed25519' (answers its
     * X25519 conversion, `converted[slot]`, when asked with field 4),
     * 'composite' (an RSA slot that refuses OKGETPUBKEY with its own
     * sentence). Anything else answers `pubKeys[slot]` whatever the field.
     */
    keyKinds = {},
    converted = {},
    /* Config mode: OKGETPUBKEY is dropped without a word (okcore.cpp:335-340). */
    inConfigMode = false,
    /* label index (25..44) -> text, for the KEY label list. */
    keyLabels = {},
    /*
     * slot -> the public key an on-device generation will produce.
     *
     * Absent means the slot refuses to generate, which is how a test asks
     * what happens when the firmware says no.
     */
    generates = {},
    /* { k132, v2 } - see the agent derivation model in handleVendor. */
    agent = null,
    /* Answer every restore with this refusal, whatever the key. */
    restoreRefusal = null,
  } = opts;

  const pipe = fakePipe({ autoStart: true });
  /*
   * resp_buffer: send_transport_response copies each 64-byte piece over it
   * WITHOUT clearing it first (okcore.cpp:2568-2573), so a short last piece
   * leaves the previous reply's bytes behind it. Modelled because probeKeySlot
   * leans on exactly that to tell ML-KEM from X-Wing, and must not lean on
   * zeros that the real key never sends.
   */
  const respBuffer = new Uint8Array(64).fill(0xa5);
  let generations = 0;
  /* Agent derivation: the slot stream being assembled, and every completed payload. */
  let agentStream = null;
  const agentPayloads = [];
  let pinStep = 0;
  /* RESTORE: the slot-131 key last set, the packets so far, and every verdict. */
  let backupKey = null;
  let restoreBuf = [];
  const restores = [];

  /*
   * The lock state, modelled because it gates almost everything. A locked
   * device answers "Error device locked" rather than failing to answer, which
   * is a distinction a client has to get right.
   */
  let unlocked = pin === null;
  let entered = '';

  function handleVendor(frame) {
    const msg = frame[4];

    if (msg === MSG.OKRESTORE) {
      /*
       * RESTORE (okcore.cpp:6477 at release 3.1.0): [5] = 0xFF is "57 more",
       * anything else is the last packet's length. Then the key is checked
       * the only way the firmware checks it - the first decrypted byte must
       * be >= 0xFD - and either answer is followed by a restart (not modelled:
       * a fake pipe has nothing to re-enumerate).
       */
      const more = frame[5] === 0xff;
      restoreBuf.push(...frame.slice(6, 6 + (more ? 57 : frame[5])));
      if (more) return undefined;
      const blob = Uint8Array.from(restoreBuf);
      restoreBuf = [];
      /* An empty restore is the App's restart: `if (offset == 0) CPU_RESTART();`
       * comes before the key is looked at, so it says nothing (:6535). */
      if (!blob.length) return undefined;
      const words = restoreRefusal
        || (!backupKey ? 'Error no backup key set'
          : openBackup(blob, backupKey) ? 'Successfully loaded backup'
            : 'Error incorrect backup key set');
      restores.push({ key: backupKey, words });
      return pipe.deliver(reportText(words));
    }

    /*
     * AGENT DERIVATION, modelled from the 3.1.0 source (src/protocol/agent.js
     * has the spec): a per-device secret K132, the v1 or v2 derivation chosen
     * by the code, real Ed25519 / ECDSA / ECDH, one 64-byte report back.
     * `agent: { k132, v2 = true }`; with v2 false the v2 codes go unanswered,
     * as they do on firmware before 3.0.5.
     */
    if (agent && (msg === MSG.OKGETPUBKEY || msg === MSG.OKSIGN || msg === MSG.OKDECRYPT)) {
      const code = frame[5];
      const version = code === 132 || (code > 200 && code < 205) ? 1
        : code === 232 || (code > 220 && code < 225) ? 2 : 0;
      if (version) {
        if (version === 2 && agent.v2 === false) return undefined;
        if (msg === MSG.OKGETPUBKEY) {
          const keyType = frame[6];
          const sk = agentKey(agent.k132, version, frame.slice(7, 39));
          return pipe.deliver(agentPublicReport(keyType, sk));
        }
        /* The slot stream: [6] = 0xFF, 57 more bytes; otherwise the last chunk's length. */
        const more = frame[6] === 0xff;
        const part = frame.slice(7, 7 + (more ? 57 : frame[6]));
        agentStream = agentStream ? concatBytes(agentStream, part) : part;
        if (more) return undefined;
        const payload = agentStream;
        agentStream = null;
        agentPayloads.push(payload);
        const keyType = code - (version === 1 ? 200 : 220);
        const sk = agentKey(agent.k132, version, payload.slice(-32));
        const body = payload.slice(0, -32);
        const refused = msg === MSG.OKSIGN ? keyType === 4 : keyType === 1;
        if (refused) return pipe.deliver(reportText('Error invalid derived key slot'));
        return pipe.deliver(msg === MSG.OKSIGN
          ? agentSignReport(keyType, sk, body)
          : agentEcdhReport(keyType, sk, body));
      }
    }


    if (msg === MSG.OKCONNECT) {
      /*
       * OKCONNECT over the vendor interface is set_time(), and set_time replies
       * with the status string - a plaintext announcement, no key exchange
       * (okcore.cpp:1348-1375). That string is where the version, the model and
       * the build come from, so a fixture that stayed silent here left every
       * caller of connect() looking at a device that had never said what it is.
       */
      return pipe.deliver(reportText(
        unlocked ? `UNLOCKED${version}` : 'INITIALIZED',
      ));
    }

    if (msg === MSG.OKPIN) {
      const at = pinStep++;
      if (noConsole) {
        /*
         * A key whose console nobody can read - a production build, or any key
         * seen from Windows, which will not open the console interface. It
         * answers the bracket on the VENDOR interface only, in the wording the
         * library's HID_PROMPTS match (src/device/pin.js).
         */
        if (at === pinFailAt) return pipe.deliver(reportText(pinError));
        const wire = PIN_WIRE_REPLIES[at];
        if (wire) pipe.deliver(reportText(wire));
        return undefined;
      }
      if (at === pinFailAt) return pipe.deliverText(`${pinError}\n`);
      const reply = PIN_REPLIES[at];
      if (reply) pipe.deliverText(reply);
      return undefined;
    }

    if (msg === MSG.OKSETSLOT || msg === MSG.OKWIPESLOT) {
      /*
       * Acknowledged as a VENDOR report, which is what hidprint() produces -
       * it calls send_transport_response, not the debug console. The wording
       * varies per field in the real firmware and one of them is misspelled,
       * so a host must not match the exact strings; only the "Error" prefix is
       * load-bearing.
       */
      if (slotSilent) return undefined;
      if (!slotError && msg === MSG.OKWIPESLOT && frame[5] >= 1 && frame[5] <= 24) {
        /*
         * wipe_slot() answers ONCE PER FIELD it erases - these ten, in this
         * order, on v2.1.2 through 3.1.0 (okcore.cpp wipe_slot at c8804e3 and
         * 8d28305), whatever field byte was sent.
         */
        for (const name of WIPED_FIELDS) pipe.deliver(reportText(`Successfully wiped ${name}`));
        return undefined;
      }
      const text = slotError || (msg === MSG.OKSETSLOT
        ? 'Successfully set Label'
        : 'Successfully wiped slot');
      return pipe.deliver(reportText(text));
    }

    if (msg === MSG.OKWIPEPRIV) {
      /*
       * wipe_private() answers, and which sentence depends on the slot
       * (okcore.cpp:5405 for ECC, :5516 for RSA). Modelled because wipeKey
       * WAITS for it now - it used to write one frame and return, so a wipe
       * the device refused looked exactly like one it did.
       */
      if (slotSilent) return undefined;
      if (slotError) return pipe.deliver(reportText(slotError));
      const slot = frame[5];
      return pipe.deliver(reportText(
        slot >= 1 && slot <= 4
          ? 'Successfully wiped RSA Private Key'
          : 'Successfully wiped ECC Key',
      ));
    }

    if (msg === MSG.OKSETPRIV) {
      /*
       * THE GENERATE TRIGGER, which is not a flag but a SUM: set_private()
       * adds buffer[7..14] and compares against 2040 (okcore.cpp:5311).
       *
       * Modelled faithfully in the two ways that matter to a client:
       *
       *   it answers the ONE request, with no button challenge - libraries
       *   97f0149 removed the PQC keygen gate, and 3.0.5 and release 3.1.0
       *   generate straight away (ecc_priv_flash: "No confirmation, as for ECC
       *   keygen"). It answers from INSIDE the write here, the fastest a device
       *   can, so a client that only starts listening after its write returns
       *   loses the key's first reports and fails these tests; and
       *
       *   there is NO acknowledgement sentence, only the raw key.
       *   ecc_priv_flash runs `quiet` for exactly this reason, and a fake that
       *   acknowledged would let a client pass here and then read
       *   "Successfully set ECC Key" as the first 64 bytes of a real key.
       */
      /* Outside config mode the whole frame is dropped - the generate trigger too. */
      if (setPrivSilent) return undefined;
      let sum = 0;
      for (let i = 7; i <= 14; i++) sum += frame[i];
      if (sum === 2040 && (frame[6] & 0x0f) >= 1 && (frame[6] & 0x0f) <= 4) {
        /*
         * An ECC generation (types 1-4) is NOT the post-quantum shape below:
         * okcrypto_generate_random_key() writes the new scalar over the
         * trigger in the buffer and returns, and ecc_priv_flash() goes on to
         * flash and acknowledge it exactly as it would a loaded key
         * (okcore.cpp:4906, then :4945, at eb25290). So it falls through to the
         * ordinary acknowledgement.
         */
        generations += 1;
      } else if (sum === 2040) {
        generations += 1;
        const key = generates[frame[5]];
        if (!key) return pipe.deliver(reportText('Error not in config mode'));
        for (let at = 0; at < key.length; at += 64) {
          const report = new Uint8Array(64);
          report.set(key.subarray(at, Math.min(at + 64, key.length)));
          pipe.deliver(report);
        }
        return undefined;
      }

      /*
       * ecc_priv_flash acknowledges, and which sentence depends on the slot
       * (okcore.cpp:5399,5413). Modelled because setBackupPassphrase now WAITS
       * for it - the real firmware drops this frame entirely outside config
       * mode, so a client that did not wait reported success for a passphrase
       * the device never took.
       */
      if (setPrivSilent) return undefined;
      const slot = frame[5];
      if (slot === 131) backupKey = Uint8Array.from(frame.slice(7, 39));
      /*
       * An RSA slot's sentence is rsa_priv_flash's (okcore.cpp:5138 at
       * eb25290). The real key says it once, after the last chunk; this says
       * it per chunk, which a client that takes the first answer cannot tell.
       */
      return pipe.deliver(reportText(
        slot === 131 ? 'Successfully set Backup Passphrase'
          : slot >= 1 && slot <= 4 ? 'Successfully set RSA Key'
            : 'Successfully set ECC Key',
      ));
    }

    if (msg === MSG.OKGETPUBKEY) {
      /*
       * okcrypto_getpubkey: the key as RAW 64-byte reports with no length
       * and no terminator, an empty slot as an error sentence
       * (okcore.cpp:5245). `pubKeys` maps slot -> bytes; a slot not in it is
       * empty, which is how a caller asks whether a slot is free.
       */
      if (inConfigMode) return undefined;
      const slot = frame[5];
      if (keyKinds[slot] === 'composite') {
        return pipe.deliver(reportText('Error use OKGETPUBKEY PQC for composite keys'));
      }
      const key = keyKinds[slot] === 'ed25519' && frame[6] === 4 && converted[slot]
        ? converted[slot]
        : pubKeys[slot];
      if (!key) {
        return pipe.deliver(reportText(
          slot >= 1 && slot <= 4
            ? 'Error no RSA Private Key set in this slot'
            : 'Error no ECC Private Key set in this slot',
        ));
      }
      for (let at = 0; at < key.length; at += 64) {
        respBuffer.set(key.subarray(at, Math.min(at + 64, key.length)));
        pipe.deliver(Uint8Array.from(respBuffer));
      }
      return undefined;
    }

    if (msg === MSG.OKGETLABELS && !unlocked) {
      return pipe.deliver(reportText('Error device locked'));
    }

    if (msg === MSG.OKGETLABELS && frame[5] === 0x6b) {
      /*
       * KEY labels, which the slot byte 'k' selects (okcore.cpp:387).
       *
       * get_key_labels() sends one row per host key slot at its own label
       * index - 25..28 for RSA 1..4, then 29..44 for ECC 101..116 - as the
       * raw index, a pipe, and the text. The RSA rows go out as 21 bytes and
       * the ECC rows as 22 (okcore.cpp:1445 vs :1491), which is modelled
       * here only so a reader that assumed one width would fail.
       */
      for (let index = 25; index <= 44; index++) {
        const text = keyLabels[index] || '';
        const bytes = new Uint8Array(index <= 28 ? 21 : 22);
        bytes[0] = index;
        bytes[1] = 0x7c;
        for (let i = 0; i < text.length && 2 + i < 18; i++) {
          bytes[2 + i] = text.charCodeAt(i) & 0xff;
        }
        pipe.deliver(bytes);
      }
      return undefined;
    }

    if (msg === MSG.OKGETLABELS) {
      /*
       * The wire format, not the app's reconstruction of it.
       *
       * get_slot_labels() sends 18 bytes per slot on the HID path: the slot as
       * a RAW BYTE (i for 1..9, i+6 above that), then 0x7C, then the text.
       * There is no priming message and no terminator - it simply sends
       * maxslots of them and returns.
       */
      const last = dropTerminal ? labelSlots - 1 : labelSlots;
      for (let slot = 1; slot <= last; slot++) {
        const text = (labels && labels[slot - 1]) || `slot${slot}`;
        const bytes = new Uint8Array(18);
        bytes[0] = slot <= 9 ? slot : slot + 6;
        bytes[1] = 0x7c;
        for (let i = 0; i < text.length && 2 + i < 18; i++) {
          bytes[2 + i] = text.charCodeAt(i) & 0xff;
        }
        pipe.deliver(bytes);
      }
      return undefined;
    }

    return undefined;
  }

  /** A 64-byte vendor report carrying text, padded the way hidprint() pads. */
  function reportText(text) {
    const bytes = new Uint8Array(64);
    for (let i = 0; i < text.length && i < 64; i++) bytes[i] = text.charCodeAt(i) & 0xff;
    return bytes;
  }

  function handleSeremu(frame) {
    const line = toLatin1(frame).replace(/\n$/, '');

    /*
     * A hold - "6!" - is the device's clear gesture: the >= 72 duration band at
     * OnlyKey.ino:914 that calls password.reset(). Without it a failed
     * attempt's digits stay in the buffer and the next attempt appends to them.
     */
    if (line.indexOf('!') !== -1) {
      entered = '';
      return;
    }

    if (ackDigits) {
      // One acknowledgement per digit, exactly as the firmware prints them.
      for (const digit of line) {
        pipe.deliverText(`password appended with ${digit}\n`);
      }
    }

    /*
     * The firmware evaluates the hash after EVERY press, so unlocking needs no
     * submit and there is nothing to acknowledge until it matches. Announced on
     * both interfaces, as the firmware announces it.
     */
    if (!unlocked && pin !== null) {
      entered += line;
      /*
       * EXACT match on the whole accumulated buffer, not a suffix.
       *
       * profile1hashevaluate() hashes everything entered since the last reset
       * and compares, so a wrong attempt does not slide out of a window - it
       * stays, and the correct PIN typed after it hashes to something else
       * entirely. Modelling this as endsWith() made a poisoned buffer look
       * recoverable, which is precisely the confusion the real device causes.
       */
      if (entered === pin) {
        unlocked = true;
        entered = '';
        pipe.deliver(reportText(`UNLOCKED${version}`));
        pipe.deliverText('UNLOCKED\n');
      }
    }
  }

  const wrapped = {
    ...pipe,
    async write(iface, bytes) {
      const n = await pipe.write(iface, bytes);
      const frame = Uint8Array.from(bytes);
      /*
       * Answered on a later turn, like a device that has to come back round
       * its loop. Replying synchronously inside write() would let a host that
       * subscribes afterwards still see the reply, hiding an ordering bug that
       * hardware would expose.
       */
      await Promise.resolve();
      if (iface === IFACE.VENDOR) handleVendor(frame);
      else if (iface === IFACE.SEREMU) handleSeremu(frame);
      return n;
    },
    /**
     * Acknowledge presses the way the firmware does, one line per digit.
     *
     * For hosts that enter a PIN by pressing the device's BUTTONS rather than
     * by writing to the debug console. The firmware prints the same line
     * either way - it is acknowledging an append, not a channel - but this
     * fake only sees writes, and a button press is not one.
     */
    ackPresses(digits) {
      for (const digit of String(digits)) {
        pipe.deliverText(`password appended with ${digit}
`);
      }
    },

    /** Every agent sign/ECDH payload the device assembled, in order. */
    get agentPayloads() { return agentPayloads; },

    /** How many generate triggers have arrived. */
    get generations() { return generations; },

    /** How many OKPIN messages have been received. */
    get pinStep() { return pinStep; },
    get unlocked() { return unlocked; },

    /** Every restore the device finished: the slot-131 key it used and its answer. */
    get restores() { return restores; },
  };

  return wrapped;
}

/* ---- agent derivation (see the model in handleVendor) ------------------- */

const { sha256: agentSha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { extract: hkdfExtract, expand: hkdfExpand } = require('../../src/vendor/exports/@noble/hashes/hkdf.js');
const { ed25519, x25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { secp256k1 } = require('../../src/vendor/exports/@noble/curves/secp256k1.js');

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/* v1 SHA256(K132 || hash); v2 HKDF(salt 0x20 || hash, K132, "onlykey/agent/v2", 32). */
function agentKey(k132, version, hash) {
  if (version === 1) return agentSha256(concatBytes(k132, hash));
  const prk = hkdfExtract(agentSha256, k132, concatBytes(Uint8Array.of(0x20), hash));
  return hkdfExpand(agentSha256, prk, new TextEncoder().encode('onlykey/agent/v2'), 32);
}

/* X25519 takes the key byte-reversed (swap_buffer, okcrypto.cpp:2371-2373). */
const reversed = (b) => Uint8Array.from(b).reverse();
const ecdsa = (keyType) => (keyType === 2 ? p256 : secp256k1);

function report64(bytes) {
  const r = new Uint8Array(64);
  r.set(bytes.slice(0, 64));
  return r;
}

function agentPublicReport(keyType, sk) {
  if (keyType === 1) return report64(ed25519.getPublicKey(sk));
  if (keyType === 4) return report64(x25519.getPublicKey(reversed(sk)));
  return report64(ecdsa(keyType).getPublicKey(sk, false).slice(1));
}

function agentSignReport(keyType, sk, message) {
  if (keyType === 1) return report64(ed25519.sign(message, sk));
  const h = message.length === 32 || message.length === 64 ? message : agentSha256(message);
  return report64(ecdsa(keyType).sign(h, sk, { prehash: false }));
}

function agentEcdhReport(keyType, sk, peer) {
  const p = peer.length === 33 || peer.length === 65 ? peer.slice(1) : peer;
  if (keyType === 4) return report64(x25519.getSharedSecret(reversed(sk), p));
  return report64(ecdsa(keyType).getSharedSecret(sk, concatBytes(Uint8Array.of(4), p), false).slice(1));
}

/* ---- backup encryption (okcore.cpp backup() / RESTORE at 3.1.0) ---------
 *
 * Written with node:crypto and the vendored tweetnacl, NOT with
 * src/device/backupkey.js: the fake has to be an independent statement of what
 * the firmware does, or a test of the predictor would be the predictor
 * agreeing with itself. A passphrase key is an Ed25519 scalar (type 1 =
 * KEYTYPE_NACL), so:
 *   pub = Ed25519 public key of the scalar, s = crypto_box_beforenm(pub, scalar),
 *   aes = sha256(s || pub || iv), body = AES-256-GCM without its tag = CTR from
 *   iv||00000002, file = body || iv || (1 + 100).
 */
function backupAesKey(key, iv) {
  const nacl = require('../../src/vendor/exports/tweetnacl.js');
  const crypto = require('crypto');
  const pub = nacl.sign.keyPair.fromSeed(Uint8Array.from(key)).publicKey;
  const s = nacl.box.before(pub, Uint8Array.from(key));
  return crypto.createHash('sha256').update(s).update(pub).update(iv).digest();
}

function backupCtr(key, iv, data) {
  const crypto = require('crypto');
  const counter = Buffer.concat([Buffer.from(iv), Buffer.from([0, 0, 0, 2])]);
  const c = crypto.createCipheriv('aes-256-ctr', backupAesKey(key, iv), counter);
  return Uint8Array.from(Buffer.concat([c.update(Buffer.from(data)), c.final()]));
}

/** Encrypt a backup body as the firmware does for a passphrase key. */
function sealBackup(plain, key, iv) {
  return Uint8Array.from([...backupCtr(key, iv, plain), ...iv, 101]);
}

/** The firmware's acceptance test: would this key restore this file? */
function openBackup(blob, key) {
  if (blob.length < 14 || blob[blob.length - 1] !== 101) return false;
  const iv = blob.slice(blob.length - 13, blob.length - 1);
  return backupCtr(key, iv, blob.slice(0, blob.length - 13))[0] >= 0xfd;
}

module.exports = { fakeFirmware, PIN_REPLIES, WIPED_FIELDS, sealBackup, openBackup };
