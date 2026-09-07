/*
 * contract.js - what every transport must do, stated once.
 *
 * There are four of these and they have almost nothing in common underneath:
 * an in-process firmware (React Native, via JNI), USB HID over OTG, a TCP
 * socket to a mock, and a WebAuthn tunnel in a browser. What they share is the
 * shape below, and the normalisation rules - which are the part that is easy
 * to get subtly wrong and hard to notice.
 *
 * THE NORMALISATION RULES
 *
 * These come from onlykey-testing/lib/device/hardware.js:351-375,479-516,
 * which is the only implementation proven against both a physical key and an
 * emulated one. Getting them different per transport is how identical code
 * puts different bytes on the wire depending on where it runs.
 *
 *   Report ID. The proven hardware client prepends a zero byte on write. An
 *   in-process bus pads to 64 and does NOT strip a leading report ID. So
 *   payloads at this layer carry NO report ID, and a transport whose platform
 *   needs one adds it on the way out and removes it on the way in.
 *
 *   Padding. Outbound frames are exactly REPORT_SIZE. Inbound, trailing NUL
 *   padding is the device's buffer, not its message - strip it on the SEREMU
 *   text interface only. FIDO and vendor reports keep their full 64 bytes,
 *   because a NUL there can be a real byte.
 */
'use strict';

const { IFACE } = require('../protocol/msg');

/** One vendor report. Not negotiable - the firmware's buffers are this size. */
const REPORT_SIZE = 64;

/**
 * The methods a transport must implement.
 *
 * Kept as a list rather than a base class: a transport is often a thin wrapper
 * over something that already exists (a TurboModule, a socket), and forcing it
 * to extend anything just adds a layer.
 */
const REQUIRED = [
  'open',
  'close',
  'isOpen',
  /** write(iface, bytes) - fire and forget. */
  'write',
  /**
   * request({iface, data, timeoutMs}) - write and wait for the reply.
   *
   * A single method rather than write-then-wait at the caller, because the
   * subscription has to be in place BEFORE the write goes out. A fast device
   * answers before a caller that writes first can start listening, and the
   * reply is lost with no error - just a timeout somewhere unrelated.
   */
  'request',
  'on',
];

/**
 * Check a transport before anything depends on it.
 *
 * Called by the transport plugin at registration, so a missing method is a
 * build-time failure naming the transport, rather than a TypeError thrown
 * from inside a poll loop twenty seconds later.
 */
function assertTransport(transport, name = 'transport') {
  if (!transport || typeof transport !== 'object') {
    throw new TypeError(`${name} must be an object`);
  }
  const missing = REQUIRED.filter((m) => typeof transport[m] !== 'function');
  if (missing.length) {
    throw new TypeError(
      `${name} is missing ${missing.join(', ')} - see src/transport/contract.js`,
    );
  }
  return transport;
}

/**
 * Strip trailing NULs from a device string.
 *
 * hidprint() memsets its buffer and writes only the string, so everything
 * after it is padding and must not reach an assertion. Trailing only: an
 * interior NUL is the device's own byte.
 */
function stripPadding(bytes) {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0x00) end -= 1;
  return bytes.subarray(0, end);
}

/** Pad or truncate to exactly one report. */
function toReport(bytes, size = REPORT_SIZE) {
  if (bytes.length === size) return bytes;
  if (bytes.length > size) {
    throw new RangeError(`frame is ${bytes.length} bytes, one report holds ${size}`);
  }
  const out = new Uint8Array(size);
  out.set(bytes, 0);
  return out;
}

/**
 * Add the leading report ID some platforms require.
 *
 * hidapi on Linux and chrome.hid both want it; an in-process bus does not.
 * A transport calls this only if its platform needs it - never at a higher
 * layer, or the two disagree.
 */
function withReportId(bytes, reportId = 0x00) {
  const out = new Uint8Array(bytes.length + 1);
  out[0] = reportId;
  out.set(bytes, 1);
  return out;
}

module.exports = {
  IFACE,
  REPORT_SIZE,
  REQUIRED,
  assertTransport,
  stripPadding,
  toReport,
  withReportId,
};
