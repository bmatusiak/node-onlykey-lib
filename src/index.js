/*
 * node-onlykey-lib - the OnlyKey client protocol, one library, any GUI.
 *
 * `crypto` is a lazy getter. Reaching it pulls in @noble/post-quantum, and a
 * caller that only wants to set a PIN should not pay for ML-KEM at load.
 *
 * `session` is NOT exported, here or in package.json's exports map, and that
 * is deliberate. It holds the transit key. Rectify restricts it to the
 * `device` and `okcrypto` plugins via setup.allowed, and leaving it out of the
 * exports map is what stops a consumer from stepping around that with a deep
 * require. Consume it as a Rectify service or not at all.
 */
'use strict';

module.exports = {
  bytes: require('./bytes'),
  protocol: require('./protocol'),
  transport: require('./transport'),
  device: require('./device'),

  get crypto() {
    return require('./crypto');
  },
};
