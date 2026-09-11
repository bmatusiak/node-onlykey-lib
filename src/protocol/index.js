/*
 * The wire protocol: what an OnlyKey message is, independent of how it travels.
 *
 * The four modules stay namespaced. `msg` and `ctap` both carry a status-ish
 * table and both have an encoder, so flattening them wholesale would make which
 * one you got depend on require order.
 *
 * The constant TABLES are re-exported flat on top of that, because they do not
 * collide and because almost every caller wants them: a transport needs IFACE,
 * and anything building a frame needs MSG. Reaching those through
 * `protocol.msg.MSG` reads as though there were some other MSG to distinguish
 * it from, and there is not.
 */
'use strict';

const msg = require('./msg');
const okmsg = require('./okmsg');
const ctap = require('./ctap');
const chunk = require('./chunk');
const cbor = require('./cbor');
const ctaphid = require('./ctaphid');
const cose = require('./cose');
const clientpin = require('./clientpin');
const tunnel = require('./tunnel');
const challenge = require('./challenge');
const bridge = require('./bridge');

module.exports = {
  msg,
  okmsg,
  ctap,
  chunk,
  cbor,
  ctaphid,
  cose,
  clientpin,
  tunnel,
  challenge,
  bridge,

  MSG: msg.MSG,
  FIELD: msg.FIELD,
  IFACE: msg.IFACE,
  KEYTYPE: msg.KEYTYPE,
  KEYACTION: msg.KEYACTION,
  messageId: msg.messageId,
  fieldId: msg.fieldId,
};
