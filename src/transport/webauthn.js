/*
 * webauthn.js - the tunnel's ctap, run by a BROWSER instead of by CTAPHID.
 *
 * WHY THIS EXISTS. A web page cannot reach an OnlyKey any other way. RawHID is
 * not exposed to pages, WebHID prompts and is blocklisted for FIDO usage pages,
 * and WebUSB cannot claim an interface the OS already owns. What a page CAN do
 * is run a WebAuthn ceremony - `navigator.credentials.get()` - and the browser
 * carries that to the key over the FIDO interface on the page's behalf. That
 * is the whole reason the tunnel exists (see src/protocol/tunnel.js and
 * src/protocol/ctap.js): the request is smuggled in as an `allowCredentials`
 * ID, the answer comes back in the assertion's signature, and the web app has
 * always talked to the device this way.
 *
 * So this is not a new protocol. It is the same object tunnel.js already
 * drives - anything with `getAssertion(params) -> Promise<Map>` - backed by the
 * browser rather than by protocol/ctaphid.js. tunnel.send() cannot tell the
 * two apart, which is the point: every tunnelled operation the library has
 * (the derives, the vault, the X-Wing pair) works in a browser the moment a
 * host hands it one of these instead of a CtapHid.
 *
 * WHAT A BROWSER WILL NOT DO, and each of these shapes the code below:
 *
 *   It will not take a clientDataHash. A page supplies a CHALLENGE; the
 *   browser wraps it in clientDataJSON with the page's own origin and hashes
 *   that itself. The 32 bytes tunnel.js puts at params key 2 therefore have
 *   nowhere to go and are ignored - see the note in getAssertion.
 *
 *   It will not let the page choose any rpId. It must be a registrable suffix
 *   of the page's own origin, which is why only a page hosted on one of the
 *   trusted origins in ctap.js RP_IDS can use the vendor extension at all.
 *
 *   It will not say WHY a ceremony failed. Cancelled, timed out and "no
 *   credential matched" are all NotAllowedError, deliberately, so a page
 *   cannot probe which credentials exist. The mapping below says as much as
 *   can honestly be said and no more.
 *
 * NOTHING HERE TOUCHES A GLOBAL. `credentials` is injected - in a browser the
 * host passes `navigator.credentials` - for the same reason randomness is
 * injected everywhere else in this library: reaching for `navigator` would
 * fail at require() time in Node and in Hermes, and would make this file
 * untestable without faking the world. And no Node built-in is required, so
 * the file bundles for a browser as it stands.
 */
'use strict';

const { randomBytes: nobleRandomBytes } = require('../vendor/exports/@noble/hashes/utils.js');
const { RP_ID } = require('../protocol/ctap');

/**
 * How long the browser is asked to wait for the ceremony, by default.
 *
 * The same order as the CTAPHID path: long enough for a person to find the key
 * and touch it. The browser treats it as a hint and clamps it to its own
 * range, so this is the upper bound a page asks for, not a guarantee.
 */
const DEFAULT_TIMEOUT_MS = 60000;

/**
 * WebAuthn's floor for a challenge is 16 bytes. 32 matches the size of the
 * clientDataHash it stands in for.
 */
const CHALLENGE_BYTES = 32;

/**
 * An error from the browser's ceremony, with a code a host can branch on.
 *
 * `code` is ours rather than the DOMException's name, because the useful
 * distinction is not always the one the browser made - see TIMEOUT below.
 * The original is kept as `cause`.
 */
class WebAuthnError extends Error {
  constructor(code, message, cause) {
    super(message);
    this.name = 'WebAuthnError';
    this.code = code;
    if (cause !== undefined) this.cause = cause;
  }
}

/**
 * Turn whatever credentials.get() threw into something that names a cause.
 *
 * @param {*} err          what the browser threw
 * @param {number} elapsed how long the ceremony ran, in ms
 * @param {number} timeout what the browser was asked to wait
 * @param {string} rpId
 */
function mapError(err, elapsed, timeout, rpId) {
  const name = err && err.name;

  if (name === 'NotAllowedError') {
    /*
     * The browser folds a timeout into NotAllowedError, so the only evidence
     * that one happened is the clock. A ceremony that ran its whole timeout
     * and then failed timed out; one that failed early was cancelled, refused
     * by the user, or refused by the browser (no key, wrong origin for this
     * rpId in some browsers, a page without focus). Saying "timed out" for the
     * early case would send someone looking for a slow key that answered.
     */
    if (elapsed >= timeout) {
      return new WebAuthnError(
        'TIMEOUT',
        `the WebAuthn ceremony timed out after ${elapsed} ms - nobody touched `
        + 'the key, or no key was connected. Browsers report this as '
        + 'NotAllowedError; the timing is what says it was a timeout.',
        err,
      );
    }
    return new WebAuthnError(
      'NOT_ALLOWED',
      'the browser refused the WebAuthn ceremony (NotAllowedError): it was '
      + 'cancelled, the page did not have focus, or no connected key answered. '
      + 'Browsers deliberately do not say which.',
      err,
    );
  }

  if (name === 'AbortError') {
    return new WebAuthnError(
      'ABORTED',
      'the WebAuthn ceremony was aborted by its AbortSignal before the key answered',
      err,
    );
  }

  if (name === 'TimeoutError') {
    return new WebAuthnError('TIMEOUT', `the WebAuthn ceremony timed out after ${elapsed} ms`, err);
  }

  if (name === 'SecurityError') {
    /*
     * The one refusal that is the PAGE's fault rather than the user's: the
     * rpId is not a registrable suffix of this page's origin. Named, because
     * it is the first thing that goes wrong when the web app is served from
     * anywhere but a trusted origin - and retrying cannot fix it.
     */
    return new WebAuthnError(
      'SECURITY',
      `the browser will not assert rpId "${rpId}" from this page's origin - it `
      + 'must be a registrable suffix of the origin, so the page has to be '
      + 'served from a trusted OnlyKey origin (see RP_IDS in protocol/ctap.js).',
      err,
    );
  }

  const detail = err && err.message ? `: ${err.message}` : '';
  return new WebAuthnError('FAILED', `the WebAuthn ceremony failed (${name || 'unknown'})${detail}`, err);
}

/** The keyhandle out of a CTAP2 getAssertion params Map - see ctap.assertionParams. */
function keyhandleOf(params) {
  const allow = params && typeof params.get === 'function' ? params.get(3) : null;
  const first = Array.isArray(allow) && allow.length ? allow[0] : null;
  const id = first && typeof first.get === 'function' ? first.get('id') : null;
  if (!(id instanceof Uint8Array) || !id.length) {
    throw new TypeError(
      'getAssertion params carry no allowList credential id - build them with '
      + 'protocol/ctap.js assertionParams()',
    );
  }
  return id;
}

/**
 * A ctap for tunnel.js, backed by the browser's WebAuthn.
 *
 * @param {object} options
 * @param {{get: function}} options.credentials  navigator.credentials, injected
 * @param {string} [options.rpId]  the rpId to assert. When given it is the ONE
 *   source of truth and a tunnel asking for a different one is refused; when
 *   omitted, the tunnel's own rpId (params key 1) is used.
 * @param {number} [options.timeoutMs]  default ceremony timeout; a per-call
 *   opts.timeoutMs (tunnel.send forwards it) wins
 * @param {function} [options.randomBytes]  (n) => Uint8Array, for the challenge
 * @param {function} [options.now]  () => ms, injectable so a test can pin time
 * @param {function} [options.beforeRequest]  async () => void, awaited before
 *   EVERY credentials.get(). A page's gate: wait for document focus (a
 *   request issued into an unfocused page does not reject - it hangs until
 *   the device gives up), or ask for the user gesture Safari demands. If it
 *   rejects, nothing is sent and the call fails with code NOT_ISSUED.
 */
function createWebAuthnCtap({
  credentials,
  rpId,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  randomBytes = nobleRandomBytes,
  now = () => Date.now(),
  beforeRequest = null,
} = {}) {
  if (!credentials || typeof credentials.get !== 'function') {
    throw new TypeError(
      'createWebAuthnCtap needs credentials with a get() - navigator.credentials '
      + 'in a browser. It is injected, never read from a global.',
    );
  }

  return {
    rpId: rpId || null,

    /**
     * One tunnelled round trip.
     *
     * @param {Map} params  from ctap.assertionParams: 1 rpId, 2 clientDataHash,
     *   3 allowList
     * @param {object} [opts]
     * @param {number} [opts.timeoutMs]
     * @param {AbortSignal} [opts.signal]  to cancel the ceremony
     * @returns {Promise<Map>}  2 = authenticatorData, 3 = signature - the shape
     *   ctap.decodeAssertion reads, the same one CtapHid returns
     */
    async getAssertion(params, opts = {}) {
      const id = keyhandleOf(params);

      /*
       * TWO PLACES NAME AN rpId, and they must not disagree. The tunnel puts
       * one in the params; this object may have been built with another. The
       * browser only asserts one, and it is the one that reaches
       * webcryptcheck() - so a disagreement means the tunnel believes it is
       * talking as one origin while the device hears another. Refused at the
       * first call, where the mismatch is visible, rather than surfacing as a
       * refusal from the device that names nothing.
       */
      const asked = params.get(1);
      if (rpId && asked && asked !== rpId) {
        throw new WebAuthnError(
          'RPID_MISMATCH',
          `the tunnel asked for rpId "${asked}" but this WebAuthn ctap asserts `
          + `"${rpId}". Configure one: pass the same rpId to both (for okcrypto, `
          + 'plugins.config = { okcrypto: { rpIds: [...] } }), or omit it here.',
        );
      }
      const effectiveRpId = rpId || asked || RP_ID;

      /*
       * params key 2, the clientDataHash, IS IGNORED - and that is not a loss.
       *
       * Over CTAPHID the host sends the 32-byte hash itself. A page cannot: it
       * supplies a challenge, and the BROWSER builds clientDataJSON from it
       * (type, challenge, the page's origin) and hashes that. There is no API
       * that takes a precomputed hash; only native platform authenticator APIs
       * do. What the hash was for - making every ceremony unique so a captured
       * one cannot be replayed - is exactly what a fresh random challenge does,
       * so that is what is sent.
       *
       * If a later step ever needs the hash the device actually saw, it is
       * sha256(response.clientDataJSON), readable after the fact.
       */
      const challenge = Uint8Array.from(randomBytes(CHALLENGE_BYTES));

      const timeout = opts.timeoutMs || timeoutMs;
      const publicKey = {
        challenge,
        rpId: effectiveRpId,
        allowCredentials: [{
          type: 'public-key',
          id: Uint8Array.from(id),
          /*
           * usb only. The OnlyKey is a USB authenticator; offering hybrid or
           * internal would let a browser pop a phone/QR flow for a credential
           * that is really a smuggled request and can only be answered by the
           * key.
           */
          transports: ['usb'],
        }],
        /*
         * discouraged, because the tunnel is not an authentication. Asking for
         * UV would make the browser demand a FIDO2 PIN for every derive - a PIN
         * that has nothing to do with the device PIN the OnlyKey actually
         * checks.
         */
        userVerification: 'discouraged',
        timeout,
      };

      /*
       * onKeepAlive (which tunnel.send forwards) is not used: the browser owns
       * the ceremony and shows its own "touch your key" prompt, and it exposes
       * no keepalive to the page.
       */
      const request = { publicKey };
      if (opts.signal) request.signal = opts.signal;

      if (beforeRequest) {
        try {
          await beforeRequest();
        } catch (err) {
          throw new WebAuthnError(
            'NOT_ISSUED',
            `the request was not sent: ${err && err.message ? err.message : err}`,
            err,
          );
        }
      }

      const started = now();
      let assertion;
      try {
        assertion = await credentials.get(request);
      } catch (err) {
        throw mapError(err, now() - started, timeout, effectiveRpId);
      }

      const response = assertion && assertion.response;
      if (!response || !response.signature) {
        throw new WebAuthnError(
          'NO_ASSERTION',
          'the browser resolved the WebAuthn ceremony without an assertion signature',
        );
      }

      return new Map([
        [2, new Uint8Array(response.authenticatorData)],
        [3, new Uint8Array(response.signature)],
      ]);
    },
  };
}

module.exports = {
  createWebAuthnCtap,
  WebAuthnError,
  DEFAULT_TIMEOUT_MS,
  CHALLENGE_BYTES,
};
