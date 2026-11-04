'use strict';

/*
 * DER, WRITTEN (ITU-T X.690): the few encodings a PrivateKeyInfo (pkcs8.js) and an X.509 certificate (x509.js) need -
 * lengths, a TLV, SEQUENCE, OCTET STRING, NULL, INTEGER, OBJECT IDENTIFIER. One writer, so both encode alike.
 */
const { concat } = require('../bytes');

function derLength(n) {
  if (n < 0x80) return Uint8Array.of(n);
  const out = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v & 0xff);
  return Uint8Array.of(0x80 | out.length, ...out);
}
const tlv = (tag, content) => concat([Uint8Array.of(tag), derLength(content.length), content]);
const sequence = (...items) => tlv(0x30, concat(items));
const octets = (bytes) => tlv(0x04, bytes);
const NULL = Uint8Array.of(0x05, 0x00);

/** A non-negative INTEGER from big-endian bytes, a number or a BigInt. */
function integer(value) {
  let bytes;
  if (typeof value === 'bigint' || typeof value === 'number') {
    let v = BigInt(value);
    const out = [];
    do { out.unshift(Number(v & 0xffn)); v >>= 8n; } while (v > 0n);
    bytes = Uint8Array.from(out);
  } else {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start++;
    bytes = value.subarray(start);
  }
  /* A set high bit would read as negative: DER says lead with a zero. */
  if (bytes[0] & 0x80) bytes = concat([Uint8Array.of(0), bytes]);
  return tlv(0x02, bytes);
}

function oid(dotted) {
  const parts = dotted.split('.').map(Number);
  const out = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    const groups = [];
    let v = part;
    do { groups.unshift(v & 0x7f); v = Math.floor(v / 128); } while (v > 0);
    for (let i = 0; i < groups.length - 1; i++) groups[i] |= 0x80;
    out.push(...groups);
  }
  return tlv(0x06, Uint8Array.from(out));
}

module.exports = { derLength, tlv, sequence, octets, NULL, integer, oid };
