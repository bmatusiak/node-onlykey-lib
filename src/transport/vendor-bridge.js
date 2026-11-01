'use strict';
/*
 * vendor-bridge.js - the WebAuthn tunnel over the VENDOR interface (firmware plugin vendor_bridge, OKVENDORBRIDGE 0xFD).
 *
 * Brad, 2026-10-31: "i need to use vendor api instead of ctap for desktop, so i need to bridge the vendor api to use
 * ctap". The tunnel's requests - the transit key, the derives, the composite halves, the derived-key signs, OKPING's
 * poll - are read only on the key's CTAP path. A desktop has the vendor interface (and on Windows reaches CTAP only
 * through Windows' WebAuthn). The vendor_bridge plugin takes the very credential ID the tunnel would put in a
 * getAssertion, over vendor reports, and answers [status][output] - the bytes the assertion's signature would hold.
 *
 * So this is a ctap for okcrypto (plugins.config.okcrypto.ctap): getAssertion(params) sends the credential ID over the
 * vendor interface and hands back a Map {2: authData, 3: signature} that protocol/ctap.js decodeAssertion reads as it
 * reads a browser's. Nothing above it changes.
 *
 * The rpId is the KEY's: vendor_bridge acts as ctap_bridge's configurable site (Brad: "we should use the rpid set in
 * the plugin that is configurable") - params' rpId is not sent. A host whose rpIds name another site derives as that
 * site everywhere else, so the desktop names the key's site (the one its own WebAuthn path used).
 *
 * IN THE LANE: okcrypto calls getAssertion while it holds the key's lane (src/transport/lane.js), so this uses only a
 * raw write and a listener - taking the lane here would wait for itself.
 *
 * Request: reports [FF FF FF FF][0xFD][index | 0x80 on the last][58 bytes of: length u16 LE . credential ID].
 * Answer: reports [0xFD][index | 0x80 last] - the first [len u16 LE] then data from byte 4, the rest data from byte 2.
 * A refusal is a text report: "VB site" (none set), "VB req" (malformed), "VB order".
 */
const okmsg = require('../protocol/okmsg');
const { IFACE } = require('../protocol/msg');

const OKVENDORBRIDGE = 0xfd;
const CHUNK = 58;

function frames(credentialId) {
  const len = credentialId.length;
  const body = new Uint8Array(2 + len);
  body[0] = len & 0xff;
  body[1] = (len >> 8) & 0xff;
  body.set(credentialId, 2);
  const out = [];
  for (let at = 0, index = 0; at < body.length; at += CHUNK, index++) {
    const last = at + CHUNK >= body.length;
    const payload = new Uint8Array(CHUNK);
    payload.set(body.subarray(at, at + CHUNK));
    out.push(okmsg.build({ msg: OKVENDORBRIDGE, slot: index | (last ? 0x80 : 0), payload }));
  }
  return out;
}

/**
 * A ctap for okcrypto over the vendor interface of `transport` (a USB or embedded transport: on(report), write).
 * @param {object} transport
 * @param {{timeoutMs?: number}} [o] - how long one request may wait for its answer (a press, a CTAP operation pending)
 */
function createVendorBridgeCtap(transport, { timeoutMs = 60000 } = {}) {
  return {
    vendorBridge: true,
    async getAssertion(params, opts = {}) {
      const allow = params.get(3);
      const id = allow && allow[0] && (allow[0].get ? allow[0].get('id') : allow[0].id);
      if (!id || !id.length) throw new Error('vendor-bridge: the request has no credential ID');
      const credentialId = Uint8Array.from(id);
      if (credentialId.length > 256) throw new Error(`vendor-bridge: a credential ID of ${credentialId.length} bytes (256 at most)`);
      const wait = opts.timeoutMs || timeoutMs;
      const answer = await new Promise((resolve, reject) => {
        let total = -1;
        let data = null;
        let got = 0;
        let next = 0;
        const done = (fn, v) => { clearTimeout(timer); off(); fn(v); };
        const timer = setTimeout(() => done(reject, Object.assign(new Error(`vendor-bridge: no answer in ${wait} ms`), { code: 'ETIMEDOUT' })), wait);
        const off = transport.on('report', (event) => {
          if (event.iface !== IFACE.VENDOR) return;
          const r = event.data;
          if (r[0] !== OKVENDORBRIDGE) {
            const t = okmsg.text(r);
            if (/^VB (site|req|order)$/.test(t)) done(reject, Object.assign(new Error(`vendor-bridge: the key said "${t}"`), { code: 'EKEYREFUSED', keyText: t }));
            return; /* another conversation's report cannot be here (the lane); a stray is not ours */
          }
          const index = r[1] & 0x7f;
          if (index !== next) return done(reject, new Error(`vendor-bridge: answer report ${index} where ${next} was due`));
          next++;
          let start = 2;
          if (index === 0) {
            total = r[2] | (r[3] << 8);
            data = new Uint8Array(total);
            start = 4;
          }
          const n = Math.min(64 - start, total - got);
          data.set(r.subarray(start, start + n), got);
          got += n;
          if (r[1] & 0x80) {
            if (got !== total) return done(reject, new Error(`vendor-bridge: answer ${got} of ${total} bytes`));
            done(resolve, data);
          }
        });
        Promise.resolve()
          .then(async () => { for (const f of frames(credentialId)) await transport.write(IFACE.VENDOR, f); })
          .catch((e) => done(reject, e));
      });
      /* as a browser's assertion, for decodeAssertion: 2 authData (unused by the tunnel), 3 the signature */
      return new Map([[2, new Uint8Array(37)], [3, answer]]);
    },
  };
}

module.exports = { createVendorBridgeCtap, OKVENDORBRIDGE };
