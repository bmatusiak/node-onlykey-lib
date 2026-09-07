/*
 * node-onlykey-lib - the OnlyKey client protocol, one library, any GUI.
 *
 * What is NOT here is deliberate.
 *
 * `crypto` is reachable only as `node-onlykey-lib/crypto`, and `crypto/pgp`
 * only as its own subpath. An earlier version exposed `crypto` here behind a
 * lazy getter, which works in Node - `require` inside a getter defers both
 * resolution and execution - but does nothing in a React Native bundle. Metro
 * resolves `require()` statically wherever it appears, so the getter deferred
 * only evaluation while @noble/post-quantum shipped in the bundle regardless.
 * Measured, not assumed: ML-KEM was in a bundle whose entry point imported
 * nothing but `bytes`, `protocol` and `device`. Keeping the subtree out of this
 * module's dependency graph is the only thing that actually keeps it out.
 *
 * `session` is absent for a different reason: it holds the transit key.
 * Rectify restricts the service to the `device` and `okcrypto` plugins through
 * setup.allowed, and leaving it out of both this barrel and package.json's
 * exports map is what stops a consumer stepping around that with a deep
 * require. Consume it as a Rectify service or not at all.
 */
'use strict';

module.exports = {
  bytes: require('./bytes'),
  protocol: require('./protocol'),
  transport: require('./transport'),
  device: require('./device'),
};
