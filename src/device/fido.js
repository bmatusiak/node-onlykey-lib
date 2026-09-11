/*
 * fido.js - administering the key's FIDO2 side over a CTAPHID channel.
 *
 * clientpin.js builds the bytes; this drives the conversation. Everything
 * here is I/O ordering and safety rules, not cryptography - the rule about
 * re-fetching the key agreement key, the rule about never sending a PIN
 * before asking how many attempts remain, the rule about what a failure
 * costs.
 *
 * ## The counter is the whole design constraint
 *
 * FIDO2 on this firmware allows EIGHT wrong PINs in the lifetime of the key
 * (PIN_LOCKOUT_ATTEMPTS, ctap.h:170) and three per boot (PIN_BOOT_ATTEMPTS,
 * ctap.h:171). Nothing resets the lifetime counter except a successful PIN or
 * a reset that destroys every credential. So this module:
 *
 *   - re-issues getKeyAgreement before EVERY attempt, because a failure
 *     regenerates the authenticator's key pair before it decrements
 *     (ctap.cpp:2120, 2170) and a cached key burns a second attempt;
 *   - reads the remaining count before each attempt and refuses to spend the
 *     last one without the caller saying so out loud;
 *   - never retries a PIN on its own.
 *
 * ## Reset is not in here by accident
 *
 * `reset()` regenerates the key space and zeroes all twelve resident
 * credentials, and the firmware guards it with ONE button press - no PIN, no
 * powerup window, no delay (ctap.cpp:2417-2424). Every WebAuthn account on
 * the key stops working the moment a finger lands. It is exported because an
 * owner of a key is entitled to wipe it, and it takes an explicit
 * confirmation argument so it cannot be reached by a typo.
 */
'use strict';

const clientpin = require('../protocol/clientpin');
const credmgmt = require('../protocol/credmgmt');
const { CTAP2_CMD, Ctap2Error } = require('../protocol/ctaphid');
const cbor = require('../protocol/cbor');

/** getInfo response labels (ctap.cpp ctap_get_info). */
const INFO = {
  VERSIONS: 1,
  EXTENSIONS: 2,
  AAGUID: 3,
  OPTIONS: 4,
  MAX_MSG_SIZE: 5,
  PIN_PROTOCOLS: 6,
};

/**
 * The word a caller has to pass to reset(). Not a boolean: a stray `true`
 * is one keystroke, and this is the one call that cannot be undone.
 */
const RESET_CONFIRMATION = 'ERASE MY CREDENTIALS';

class FidoAdmin {
  /**
   * @param {import('../protocol/ctaphid').CtapHid} ctap  a channel that has
   *        already been through init()
   *
   * The CHANNEL IS REUSED rather than re-allocated per call. The firmware
   * keeps ten channel records and never frees one (ctaphid.cpp:67), so a
   * client that calls init() before each operation exhausts them and then
   * gets somebody else's.
   */
  constructor(ctap) {
    if (!ctap) throw new Error('FidoAdmin needs a CtapHid');
    this.ctap = ctap;
  }

  /** The authenticator's own description of itself. */
  async getInfo(opts = {}) {
    const info = await this.ctap.getInfo(opts);
    if (!(info instanceof Map)) throw new Error('getInfo returned no CBOR map');
    return info;
  }

  /**
   * Is a PIN already set?
   *
   * getInfo's options map carries `clientPin`: absent means the authenticator
   * has no PIN support, false means supported but unset, true means set. That
   * three-way answer is what decides setPin against changePin - the firmware
   * answers CTAP2_ERR_NOT_ALLOWED for a setPin on a key that has one
   * (ctap.cpp:2255) and CTAP2_ERR_PIN_NOT_SET for the reverse (ctap.cpp:2271),
   * so guessing wastes a round trip and muddies the error a user sees.
   */
  async pinState(opts = {}) {
    const info = await this.getInfo(opts);
    const options = info.get(INFO.OPTIONS);
    const value = options instanceof Map ? options.get('clientPin') : undefined;
    return {
      supported: value !== undefined,
      set: value === true,
      protocols: info.get(INFO.PIN_PROTOCOLS) || [],
      info,
    };
  }

  /** One clientPin subcommand. */
  async _clientPin(params, opts) {
    return this.ctap.send(CTAP2_CMD.CLIENT_PIN, cbor.encode(params), opts);
  }

  /**
   * Attempts remaining before FIDO2 locks permanently.
   *
   * Free: it takes no PIN, touches no counter, and needs no user presence.
   * Everything below calls it first for that reason.
   */
  async getRetries(opts = {}) {
    return clientpin.readRetries(await this._clientPin(clientpin.retriesParams(), opts));
  }

  /**
   * A fresh platform key pair and the shared secret for ONE attempt.
   *
   * Never cached. See the header: the authenticator throws its half away on
   * every PIN failure, so a shared secret is good for exactly one try and
   * reusing one spends a second attempt discovering that.
   */
  async _agree(opts) {
    const platformKey = clientpin.newPlatformKey();
    const response = await this._clientPin(clientpin.keyAgreementParams(), opts);
    const authenticatorKey = clientpin.readKeyAgreement(response);
    return {
      platformKey,
      secret: clientpin.sharedSecret(platformKey.secretKey, authenticatorKey.uncompressed),
    };
  }

  /**
   * Refuse to spend the last life without being told to.
   *
   * A caller that has a PIN it believes in can pass `allowLastAttempt`. The
   * default is to stop at one remaining, because the usual reason to be at
   * one is that the PIN in hand is wrong.
   */
  async _guard(opts) {
    const retries = await this.getRetries(opts);
    if (retries <= 0) {
      throw new Error('this key has no FIDO2 attempts left; its FIDO2 side is locked');
    }
    if (retries === 1 && !opts.allowLastAttempt) {
      throw new Error(
        'one FIDO2 attempt remains - a wrong PIN now locks the key permanently. ' +
          'Pass allowLastAttempt if that is understood.',
      );
    }
    return retries;
  }

  /**
   * Set a PIN on a key that has none.
   *
   * No attempt is spent by a setPin: there is no current PIN to be wrong
   * about. The state check is still done first, because a setPin against a
   * key that HAS a PIN is a caller error worth naming rather than a bare
   * CTAP2_ERR_NOT_ALLOWED.
   */
  async setPin(newPin, opts = {}) {
    const state = await this.pinState(opts);
    if (!state.supported) throw new Error('this authenticator does not support a PIN');
    if (state.set) {
      throw new Error('a FIDO2 PIN is already set on this key; use changePin');
    }

    const { platformKey, secret } = await this._agree(opts);
    await this._clientPin(clientpin.setPinParams({ secret, platformKey, newPin }), opts);
    return true;
  }

  /**
   * Change a PIN, proving the current one. THIS SPENDS AN ATTEMPT if wrong.
   */
  async changePin(currentPin, newPin, opts = {}) {
    const state = await this.pinState(opts);
    if (!state.set) throw new Error('no FIDO2 PIN is set on this key; use setPin');

    const before = await this._guard(opts);
    const { platformKey, secret } = await this._agree(opts);
    try {
      await this._clientPin(
        clientpin.changePinParams({ secret, platformKey, currentPin, newPin }),
        opts,
      );
    } catch (e) {
      throw await this._describe(e, before, opts);
    }
    return true;
  }

  /**
   * Exchange the PIN for a token, which is what credential management and a
   * PIN-protected makeCredential authenticate with.
   *
   * The token lives until the device reboots or the PIN changes; a caller
   * keeps it for the session rather than asking for the PIN again.
   */
  async getPinToken(pin, opts = {}) {
    const before = await this._guard(opts);
    const { platformKey, secret } = await this._agree(opts);
    try {
      const response = await this._clientPin(
        clientpin.pinTokenParams({ secret, platformKey, pin }),
        opts,
      );
      return clientpin.readPinToken(response, secret);
    } catch (e) {
      throw await this._describe(e, before, opts);
    }
  }

  /**
   * Turn a CTAP2 status into something with the remaining count in it.
   *
   * "CTAP2 error 0x31" tells a user nothing and tells them nothing about the
   * thing that matters, which is how many tries are left. The count is
   * re-read AFTER the failure, because that is the number the next attempt
   * will face.
   */
  async _describe(error, before, opts) {
    if (!(error instanceof Ctap2Error)) return error;

    let after = null;
    try {
      after = await this.getRetries(opts);
    } catch { /* the count is a nicety; the original error is not */ }

    const spent = after !== null && after < before;
    const tail = after === null
      ? ''
      : ` ${after} attempt${after === 1 ? '' : 's'} left${spent ? ' (one was just spent)' : ''}.`;

    const wrapped = new Error(`${error.message}.${tail}`);
    wrapped.cause = error;
    wrapped.code = error.code;
    wrapped.retries = after;
    return wrapped;
  }

  /** One credential-management subcommand. */
  async _credMgmt(params, opts) {
    return this.ctap.send(
      CTAP2_CMD.CREDENTIAL_MANAGEMENT, cbor.encode(params), opts,
    );
  }

  /**
   * How many resident credentials the key holds, and how many more fit.
   *
   * Ask this FIRST. Every other credential-management subcommand answers
   * success with an EMPTY BODY when there are none stored (ctap.cpp:1754),
   * which a caller cannot tell from a malformed reply; metadata is the one
   * that still answers properly, so it is what turns "nothing came back" into
   * "there is nothing there".
   */
  async credentialCount(pinToken, opts = {}) {
    return credmgmt.readMetadata(
      await this._credMgmt(credmgmt.metadataParams(pinToken), opts),
    );
  }

  /**
   * Every resident credential on the key, grouped by the site that owns it.
   *
   * ONE PASS, and it has to be. The enumeration cursors are function statics
   * shared by every channel (ctap.cpp:1736-1741), so this walks the relying
   * parties to completion, collecting their hashes, and only then walks each
   * one's credentials - interleaving the two walks moves two cursors that do
   * not know about each other.
   *
   * A `*Next` without its `*Begin` answers CTAP2_ERR_NO_CREDENTIALS rather
   * than starting again, and any failure clears the flag, so a walk that
   * breaks cannot be resumed - only restarted.
   *
   * @returns {Promise<Array<{id, name, rpIdHash, credentials: Array}>>}
   */
  async listCredentials(pinToken, opts = {}) {
    const { stored } = await this.credentialCount(pinToken, opts);
    if (!stored) return [];

    /* ---- the relying parties, first and completely ---- */
    const rps = [];
    let first = credmgmt.readRp(
      await this._credMgmt(credmgmt.rpBeginParams(pinToken), opts),
    );
    if (!first) return [];
    rps.push(first);

    /*
     * The count comes only with the FIRST answer (ctap.cpp:1526-1530), so it
     * is read once and counted down - not expected on every reply.
     */
    const total = first.total === null ? 1 : first.total;
    for (let i = 1; i < total; i += 1) {
      const next = credmgmt.readRp(await this._credMgmt(credmgmt.rpNextParams(), opts));
      if (!next) break;
      rps.push(next);
    }

    /* ---- then each site's credentials ---- */
    const out = [];
    for (const rp of rps) {
      const credentials = [];
      const begun = credmgmt.readCredential(
        await this._credMgmt(credmgmt.rkBeginParams(pinToken, rp.rpIdHash), opts),
      );
      if (begun) {
        credentials.push(begun);
        const count = begun.total === null ? 1 : begun.total;
        for (let i = 1; i < count; i += 1) {
          const next = credmgmt.readCredential(
            await this._credMgmt(credmgmt.rkNextParams(), opts),
          );
          if (!next) break;
          credentials.push(next);
        }
      }
      out.push({ id: rp.id, name: rp.name, rpIdHash: rp.rpIdHash, credentials });
    }
    return out;
  }

  /**
   * Delete one resident credential.
   *
   * @param {Map} credentialId  the descriptor from listCredentials, unchanged
   *
   * IRREVERSIBLE, and the device asks for nothing: no button, no second
   * thought. The account that credential belongs to stops recognising this
   * key, and if it was the only second factor that account may be
   * unreachable. A caller is expected to have shown the user which site and
   * which user name it belongs to before getting here.
   *
   * The descriptor is passed through rather than rebuilt, and should come
   * from a listing taken immediately before - the cursors are shared, so an
   * index or a stale copy can name a different credential than the one a
   * person was looking at.
   */
  async deleteCredential(pinToken, credentialId, opts = {}) {
    await this._credMgmt(credmgmt.rkDeleteParams(pinToken, credentialId), opts);
    return true;
  }

  /**
   * Erase the FIDO2 key space and every resident credential.
   *
   * @param {string} confirmation  must equal RESET_CONFIRMATION
   *
   * ONE BUTTON PRESS is the only thing between this and a wiped
   * authenticator. The spec asks for a reset to be refused more than ten
   * seconds after powerup; this firmware does not implement that window
   * (ctap.cpp:2417-2424), so there is no accidental-command protection at the
   * device end at all and the protection has to live here.
   *
   * Every passkey on the key stops working. Accounts where it is the only
   * second factor become unreachable. Nothing in this library calls it.
   */
  async reset(confirmation, opts = {}) {
    if (confirmation !== RESET_CONFIRMATION) {
      throw new Error(
        `fido reset needs the exact confirmation "${RESET_CONFIRMATION}"; it erases ` +
          'every resident credential and regenerates the key space, and one button ' +
          'press is the only other thing standing in the way',
      );
    }
    await this.ctap.send(CTAP2_CMD.RESET, new Uint8Array(0), {
      /* A finger has to land, so the presence wait is the long one. */
      presenceTimeoutMs: 30000,
      ...opts,
    });
    return true;
  }
}

module.exports = { FidoAdmin, INFO, RESET_CONFIRMATION };
