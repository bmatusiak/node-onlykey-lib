/*
 * transport/webauthn - the tunnel's ctap, run by a browser.
 *
 * There is no browser here, so `credentials` is a fake that records the
 * request it was handed and answers the way navigator.credentials.get() does:
 * a PublicKeyCredential whose response carries ArrayBuffers. What these pin is
 * the CONTRACT between the two sides - that the keyhandle the browser is asked
 * to offer is byte for byte what ctap.encodeRequest produced, and that what
 * comes back is the Map ctap.decodeAssertion reads - because a mistake at that
 * seam would only ever show up on a real page in front of a real key.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { createWebAuthnCtap, WebAuthnError } = require('../src/transport/webauthn');
const ctap = require('../src/protocol/ctap');
const tunnel = require('../src/protocol/tunnel');
const { MSG } = require('../src/protocol/msg');
const { fromLatin1, toLatin1 } = require('../src/bytes');

const fixedRandom = (n) => new Uint8Array(n).fill(0x5a);

/** An ArrayBuffer holding exactly these bytes, as a browser hands back. */
function buffer(bytes) {
  return Uint8Array.from(bytes).buffer;
}

/** authData: 32-byte rpIdHash, 1 flag byte, 4-byte counter. */
function authData(counter = 7) {
  const a = new Uint8Array(37);
  new DataView(a.buffer).setUint32(33, counter, false);
  return a;
}

/**
 * A fake navigator.credentials.
 *
 * @param {function} answer  (request) => {signature, authenticatorData} or throws
 */
function fakeCredentials(answer) {
  const seen = [];
  return {
    seen,
    async get(request) {
      seen.push(request);
      const { signature, authenticatorData = authData() } = await answer(request);
      return {
        type: 'public-key',
        rawId: buffer(request.publicKey.allowCredentials[0].id),
        response: {
          authenticatorData: buffer(authenticatorData),
          signature: buffer(signature),
          clientDataJSON: buffer(fromLatin1('{}')),
        },
      };
    },
  };
}

/** A DOMException-shaped error; Node has DOMException, but only the name matters. */
function domError(name) {
  const err = new Error(`${name} from the browser`);
  err.name = name;
  return err;
}

const SAMPLE = { cmd: MSG.OKCONNECT, opt1: 1, opt2: 2, opt3: 3, data: fromLatin1('hi') };

function sampleParams(rpId = ctap.RP_ID) {
  return ctap.assertionParams(ctap.encodeRequest(SAMPLE), {
    rpId,
    clientDataHash: new Uint8Array(32).fill(0x11),
  });
}

/* ------------------------------------------------------------ the request */

test('the browser is asked to offer exactly the encoded keyhandle', async () => {
  const credentials = fakeCredentials(() => ({ signature: [0x00] }));
  const webauthn = createWebAuthnCtap({ credentials, randomBytes: fixedRandom });

  await webauthn.getAssertion(sampleParams());

  assert.equal(credentials.seen.length, 1);
  const { publicKey } = credentials.seen[0];
  assert.equal(publicKey.allowCredentials.length, 1);
  const allowed = publicKey.allowCredentials[0];
  assert.equal(allowed.type, 'public-key');
  assert.deepEqual(allowed.transports, ['usb']);
  assert.deepEqual(
    Uint8Array.from(allowed.id), ctap.encodeRequest(SAMPLE),
    'the keyhandle is the request - one byte off and the firmware ignores it',
  );
  assert.equal(publicKey.userVerification, 'discouraged');
});

test("the tunnel's rpId passes through to the browser", async () => {
  const credentials = fakeCredentials(() => ({ signature: [0x00] }));
  const webauthn = createWebAuthnCtap({ credentials, randomBytes: fixedRandom });

  await webauthn.getAssertion(sampleParams('apps.onlykey.io'));
  assert.equal(credentials.seen[0].publicKey.rpId, 'apps.onlykey.io');
});

test('a configured rpId is used, and a tunnel disagreeing with it is refused', async () => {
  /*
   * The browser asserts ONE rpId. Two configured ones that differ mean the
   * tunnel thinks it is one origin while the device hears another - refused
   * before anything reaches the browser.
   */
  const credentials = fakeCredentials(() => ({ signature: [0x00] }));
  const webauthn = createWebAuthnCtap({
    credentials, rpId: 'apps.onlykey.io', randomBytes: fixedRandom,
  });

  await webauthn.getAssertion(sampleParams('apps.onlykey.io'));
  assert.equal(credentials.seen[0].publicKey.rpId, 'apps.onlykey.io');

  await assert.rejects(
    webauthn.getAssertion(sampleParams('apps.crp.to')),
    (err) => err instanceof WebAuthnError && err.code === 'RPID_MISMATCH',
  );
  assert.equal(credentials.seen.length, 1, 'the mismatch never reached the browser');
});

test('the challenge is fresh randomness, not the ignored clientDataHash', async () => {
  const credentials = fakeCredentials(() => ({ signature: [0x00] }));
  const webauthn = createWebAuthnCtap({ credentials, randomBytes: fixedRandom });

  await webauthn.getAssertion(sampleParams());
  const { challenge } = credentials.seen[0].publicKey;
  assert.deepEqual(Uint8Array.from(challenge), new Uint8Array(32).fill(0x5a));
  assert.equal('clientDataHash' in credentials.seen[0].publicKey, false);
});

test('without an injected randomBytes the challenge still comes from a CSPRNG', async () => {
  const credentials = fakeCredentials(() => ({ signature: [0x00] }));
  const webauthn = createWebAuthnCtap({ credentials });

  await webauthn.getAssertion(sampleParams());
  await webauthn.getAssertion(sampleParams());
  const [a, b] = credentials.seen.map((r) => Uint8Array.from(r.publicKey.challenge));
  assert.equal(a.length, 32);
  assert.notDeepEqual(a, b, 'two ceremonies, two challenges');
});

test('the timeout is the default, and a per-call timeoutMs wins', async () => {
  const credentials = fakeCredentials(() => ({ signature: [0x00] }));
  const webauthn = createWebAuthnCtap({ credentials, timeoutMs: 12345, randomBytes: fixedRandom });

  await webauthn.getAssertion(sampleParams());
  await webauthn.getAssertion(sampleParams(), { timeoutMs: 999 });
  assert.equal(credentials.seen[0].publicKey.timeout, 12345);
  assert.equal(credentials.seen[1].publicKey.timeout, 999);
});

test('an AbortSignal is handed to the browser', async () => {
  const credentials = fakeCredentials(() => ({ signature: [0x00] }));
  const webauthn = createWebAuthnCtap({ credentials, randomBytes: fixedRandom });
  const controller = new AbortController();

  await webauthn.getAssertion(sampleParams(), { signal: controller.signal });
  assert.equal(credentials.seen[0].signal, controller.signal);
});

/* ----------------------------------------------------------- the response */

test('the answer comes back as the Map decodeAssertion reads', async () => {
  const payload = fromLatin1('UNLOCKEDv3.0.5');
  const credentials = fakeCredentials(() => ({
    signature: [0x00, ...payload],
    authenticatorData: authData(42),
  }));
  const webauthn = createWebAuthnCtap({ credentials, randomBytes: fixedRandom });

  const assertion = await webauthn.getAssertion(sampleParams());
  assert.ok(assertion instanceof Map);
  assert.ok(assertion.get(2) instanceof Uint8Array);
  assert.ok(assertion.get(3) instanceof Uint8Array);

  const decoded = ctap.decodeAssertion(assertion);
  assert.equal(decoded.status, 'CTAP1_SUCCESS');
  assert.equal(toLatin1(decoded.data), 'UNLOCKEDv3.0.5');
  assert.equal(decoded.count, 42);
});

test('a device status other than success decodes by name', async () => {
  const credentials = fakeCredentials(() => ({ signature: [0x23] }));
  const webauthn = createWebAuthnCtap({ credentials, randomBytes: fixedRandom });

  const decoded = ctap.decodeAssertion(await webauthn.getAssertion(sampleParams()));
  assert.equal(decoded.status, 'CTAP2_ERR_USER_ACTION_PENDING');
  assert.equal(decoded.data, null);
});

/* ------------------------------------------------------------- the errors */

test('NotAllowedError before the timeout is a refusal, not a timeout', async () => {
  const credentials = fakeCredentials(() => { throw domError('NotAllowedError'); });
  let t = 1000;
  const webauthn = createWebAuthnCtap({
    credentials, timeoutMs: 60000, randomBytes: fixedRandom, now: () => (t += 10),
  });

  await assert.rejects(webauthn.getAssertion(sampleParams()), (err) => {
    assert.ok(err instanceof WebAuthnError);
    assert.equal(err.code, 'NOT_ALLOWED');
    assert.equal(err.cause.name, 'NotAllowedError');
    assert.match(err.message, /cancelled/);
    return true;
  });
});

test('NotAllowedError after the whole timeout is reported as a timeout', async () => {
  /* The browser folds a timeout into NotAllowedError; the clock tells them apart. */
  const credentials = fakeCredentials(() => { throw domError('NotAllowedError'); });
  const times = [1000, 1000 + 5000];
  const webauthn = createWebAuthnCtap({
    credentials, timeoutMs: 5000, randomBytes: fixedRandom, now: () => times.shift(),
  });

  await assert.rejects(webauthn.getAssertion(sampleParams()), (err) => {
    assert.equal(err.code, 'TIMEOUT');
    assert.match(err.message, /timed out after 5000 ms/);
    return true;
  });
});

test('AbortError and SecurityError are named for what they mean', async () => {
  for (const [name, code, pattern] of [
    ['AbortError', 'ABORTED', /aborted/],
    ['SecurityError', 'SECURITY', /registrable suffix/],
    ['TimeoutError', 'TIMEOUT', /timed out/],
    ['UnknownError', 'FAILED', /UnknownError/],
  ]) {
    const credentials = fakeCredentials(() => { throw domError(name); });
    const webauthn = createWebAuthnCtap({ credentials, randomBytes: fixedRandom });
    await assert.rejects(webauthn.getAssertion(sampleParams()), (err) => {
      assert.equal(err.code, code, name);
      assert.match(err.message, pattern);
      return true;
    });
  }
});

test('a ceremony that resolves with nothing is an error, not a crash', async () => {
  const credentials = { get: async () => null };
  const webauthn = createWebAuthnCtap({ credentials, randomBytes: fixedRandom });
  await assert.rejects(
    webauthn.getAssertion(sampleParams()),
    (err) => err.code === 'NO_ASSERTION',
  );
});

test('no credentials, no ctap - and it never reaches for a global', () => {
  assert.throws(() => createWebAuthnCtap(), /injected, never read from a global/);
  assert.throws(() => createWebAuthnCtap({ credentials: {} }), TypeError);
});

test('params without a keyhandle are refused before the browser is asked', async () => {
  const credentials = fakeCredentials(() => ({ signature: [0x00] }));
  const webauthn = createWebAuthnCtap({ credentials, randomBytes: fixedRandom });
  await assert.rejects(webauthn.getAssertion(new Map([[1, ctap.RP_ID]])), TypeError);
  assert.equal(credentials.seen.length, 0);
});

/* ------------------------------------------------------------- end to end */

test('createTunnel drives it end to end: request in the keyhandle, answer in the signature', async () => {
  /*
   * The fake plays the browser AND the firmware: it decodes the keyhandle the
   * way is_extension_request() does and echoes the payload back reversed, so a
   * request that arrived mangled cannot produce the expected answer.
   */
  const credentials = fakeCredentials((request) => {
    const id = Uint8Array.from(request.publicKey.allowCredentials[0].id);
    assert.deepEqual(Array.from(id.subarray(4, 8)), ctap.MAGIC);
    const data = id.subarray(ctap.HEADER, ctap.HEADER + id[9]);
    return { signature: [0x00, id[0], ...Array.from(data).reverse()] };
  });

  const bound = tunnel.createTunnel(
    createWebAuthnCtap({ credentials, randomBytes: fixedRandom }),
    { randomBytes: fixedRandom },
  );

  const answer = await bound.send({ cmd: MSG.OKPING, data: fromLatin1('abc') }, { timeoutMs: 1500 });
  assert.equal(answer.status, 'CTAP1_SUCCESS');
  assert.equal(answer.data[0], MSG.OKPING, 'the command byte reached the device');
  assert.equal(toLatin1(answer.data.subarray(1)), 'cba');

  const { publicKey } = credentials.seen[0];
  assert.equal(publicKey.rpId, ctap.RP_ID, 'the tunnel default rpId reached the browser');
  assert.equal(publicKey.timeout, 1500, "tunnel.send's timeoutMs reached the browser");
});

/* ------------------------------------------------------ the page's gate */

test('beforeRequest is awaited before every request', async () => {
  /*
   * A page's gate - document focus, Safari's user gesture. A request issued
   * into an unfocused page does not reject; it hangs until the device gives
   * up, which is why the gate runs first rather than as error handling.
   */
  const order = [];
  const credentials = fakeCredentials(() => { order.push('get'); return { signature: [0x00] }; });
  const webauthn = createWebAuthnCtap({
    credentials,
    randomBytes: fixedRandom,
    beforeRequest: async () => { order.push('gate'); },
  });
  await webauthn.getAssertion(sampleParams());
  await webauthn.getAssertion(sampleParams());
  assert.deepEqual(order, ['gate', 'get', 'gate', 'get']);
});

test('a gate that says no sends nothing, and says why', async () => {
  const credentials = fakeCredentials(() => ({ signature: [0x00] }));
  const webauthn = createWebAuthnCtap({
    credentials,
    randomBytes: fixedRandom,
    beforeRequest: async () => { throw new Error('page lost focus'); },
  });
  await assert.rejects(() => webauthn.getAssertion(sampleParams()), (err) => {
    assert.ok(err instanceof WebAuthnError);
    assert.equal(err.code, 'NOT_ISSUED');
    assert.match(err.message, /page lost focus/);
    return true;
  });
  assert.equal(credentials.seen.length, 0);
});
