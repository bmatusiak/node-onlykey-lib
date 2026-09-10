/*
 * usbDescriptors.js - what an OnlyKey looks like on a USB bus.
 *
 * These are facts about the DEVICE, not about any platform, which is why they
 * are here rather than in the Android sources that first needed them. A second
 * platform - iOS, a desktop host, a Node CLI over hidapi - reads this table
 * instead of transcribing it out of the firmware again. Transcription is what
 * produced the defect this file exists to prevent; see below.
 *
 * Everything here is read from the firmware's own descriptors:
 * `OnlyKey-Firmware/.../usb_desc.h` and `usb_desc.c`, the `USB_ONLYKEY` block.
 *
 * ## THE PROBLEM THIS SOLVES
 *
 * The device exposes several HID interfaces. Three of them are IDENTICAL in
 * interface class, subclass, protocol and endpoint width - the only thing that
 * separates them is the HID USAGE PAGE in their report descriptors. An Android
 * transport tried to pick the right one by scoring those attributes, which
 * produced a three-way tie broken by descriptor order. It happened to land on
 * the right interface, by luck, and nothing said so.
 *
 * So: identify by usage page, and REFUSE when that is not available. A guess
 * here sends the vendor protocol to the security-key interface, where every
 * request times out and the error blames the device.
 *
 * ## WHY THE INTERFACE NUMBERS ARE THE LIBRARY'S IFACE NUMBERS
 *
 * `IFACE` in ../protocol/msg.js is 0 keyboard, 1 FIDO, 2 vendor, 3 SEREMU -
 * deliberately the same numbers the firmware assigns, so a transport can pass
 * them through unchanged. That correspondence is a convenience, not a law: a
 * transport must still MAP by usage page, because a device that enumerated in
 * another order would still be that device.
 */
'use strict';

const { IFACE } = require('../protocol/msg');

/**
 * HID usage page and usage per interface, from `usb_desc.c`'s report
 * descriptors.
 *
 * The two RawHID interfaces carry vendor-defined pages (`0xFF00` and above),
 * which is what makes them look alike to anything that does not read them.
 *
 * `endpointIn`/`endpointOut` are the maximum packet sizes the firmware asks
 * for, in bytes. Note SEREMU is ASYMMETRIC - 64 in, 32 out - which is a real
 * constraint on writes and not a typo.
 */
const INTERFACES = [
  {
    iface: IFACE.KEYBOARD,
    name: 'keyboard',
    usagePage: 0x0001,
    usage: 0x06,
    endpointIn: 8,
    endpointOut: 0,     // device -> host only
    required: true,
    /*
     * REQUIRED because capturing it is a goal, not a side effect: a host that
     * does not claim it lets the key type into whatever window has focus
     * instead of into the app.
     */
  },
  {
    iface: IFACE.FIDO,
    name: 'fido',
    usagePage: 0xf1d0,  // FIDO Alliance
    usage: 0x01,
    endpointIn: 64,
    endpointOut: 64,
    required: true,
  },
  {
    iface: IFACE.VENDOR,
    name: 'vendor',
    usagePage: 0xffab,
    usage: 0x02,
    endpointIn: 64,
    endpointOut: 64,
    required: true,
    /*
     * The one that carries almost everything: the PIN bracket, slots, labels,
     * preferences, key loading, restore. A transport that claims only FIDO can
     * speak the security-key protocol and nothing else.
     */
  },
  {
    iface: IFACE.SEREMU,
    name: 'seremu',
    usagePage: 0xffc9,
    usage: 0x04,
    endpointIn: 64,
    endpointOut: 32,
    required: false,
    /*
     * OPTIONAL, and its absence is meaningful rather than a fault: SEREMU is
     * compiled out of a production build, so a production key enumerates three
     * interfaces and a developer key four.
     */
  },
];

const BY_IFACE = new Map(INTERFACES.map((d) => [d.iface, d]));

/** VID and PID the firmware declares. `usb_desc.h`, the USB_ONLYKEY block. */
const VENDOR_ID = 0x1d50;
const PRODUCT_ID = 0x60fc;

/**
 * The control transfer that fetches a report descriptor.
 *
 * Returned as data rather than performed, because performing it is
 * platform-specific and this package does not reach for a bus. The fields are
 * the standard GET_DESCRIPTOR request from the USB spec, aimed at an interface:
 *
 *   requestType 0x81  IN | standard | recipient INTERFACE
 *   request     0x06  GET_DESCRIPTOR
 *   value       0x2200  descriptor type 0x22 (REPORT), index 0
 *   index       the bInterfaceNumber being asked about
 *
 * The device answers this: `usb_dev.c` handles the request and `usb_desc.c`
 * keys its lookup on exactly `{value: 0x2200, index: bInterfaceNumber}`. It
 * also clamps the reply to the requested length, so asking for more than the
 * descriptor holds returns the true length rather than stalling.
 */
function reportDescriptorRequest(interfaceNumber, length = 256) {
  return {
    requestType: 0x81,
    request: 0x06,
    value: (0x22 << 8) | 0x00,
    index: interfaceNumber,
    length,
  };
}

/**
 * The usage page and usage at the head of a HID report descriptor.
 *
 * Walks HID SHORT ITEMS rather than matching a byte prefix. A prefix match
 * works on today's descriptors and breaks the first time an item is inserted
 * ahead of the usage - a Report ID, say - which is the kind of change that
 * arrives in a firmware update rather than in a code review.
 *
 * A short item's first byte is `bTag << 4 | bType << 2 | bSize`, where bSize is
 * the DATA LENGTH INDEX: 0, 1 and 2 mean that many bytes, and 3 means four.
 * The two items wanted:
 *
 *   Usage Page  bType 1 (global), bTag 0  -> prefixes 0x05, 0x06, 0x07
 *   Usage       bType 2 (local),  bTag 0  -> prefixes 0x09, 0x0a, 0x0b
 *
 * Long items (prefix 0xfe) are skipped by their own length byte. Returns nulls
 * for whatever was not found, so a caller can tell "no usage page" from "usage
 * page zero".
 */
function parseUsage(bytes) {
  const data = Uint8Array.from(bytes || []);
  let usagePage = null;
  let usage = null;

  let i = 0;
  while (i < data.length) {
    const prefix = data[i];

    /* Long item: 0xfe, then a length byte, then a tag byte, then the data. */
    if (prefix === 0xfe) {
      const size = data[i + 1] || 0;
      i += 3 + size;
      continue;
    }

    const sizeIndex = prefix & 0x03;
    const size = sizeIndex === 3 ? 4 : sizeIndex;
    const tagType = prefix & 0xfc;

    let value = 0;
    for (let b = 0; b < size; b++) value |= (data[i + 1 + b] || 0) << (8 * b);

    /* Global usage page (tag 0, type 1) and local usage (tag 0, type 2). */
    if (tagType === 0x04 && usagePage === null) usagePage = value;
    else if (tagType === 0x08 && usage === null) usage = value;

    if (usagePage !== null && usage !== null) break;
    i += 1 + size;
  }

  return { usagePage, usage };
}

/**
 * Which IFACE a report descriptor belongs to, or null when nothing matches.
 *
 * Null is not a failure to be papered over. A caller that cannot identify an
 * interface must leave it alone and say so - see the module header.
 */
function identify({ usagePage, usage }) {
  const found = INTERFACES.find(
    (d) => d.usagePage === usagePage && d.usage === usage);
  return found ? found.iface : null;
}

/** The descriptor for one IFACE, or undefined. */
function describe(iface) {
  return BY_IFACE.get(iface);
}

/**
 * Check a set of identified interfaces before a session is built on it.
 *
 * Three ways to be wrong, and all three are silent if unchecked: a required
 * interface missing, the same one claimed twice, or an interface identified by
 * something other than its usage page. Returns a list of complaints, empty when
 * the set is usable.
 *
 * @param {Array<{iface: number, identifiedBy?: string}>} found
 */
function problems(found) {
  const out = [];
  const seen = new Map();

  for (const entry of found || []) {
    const desc = BY_IFACE.get(entry.iface);
    if (!desc) {
      out.push(`interface ${entry.iface} is not one this device has`);
      continue;
    }
    if (seen.has(entry.iface)) {
      out.push(
        `two interfaces both identified as ${desc.name} - one of them is `
        + 'something else, and sending to it would time out with no error');
    }
    seen.set(entry.iface, entry);

    if (entry.identifiedBy && entry.identifiedBy !== 'usagePage') {
      out.push(
        `${desc.name} was identified by ${entry.identifiedBy} rather than its `
        + 'usage page, which is a guess - see usbDescriptors.js');
    }
  }

  for (const desc of INTERFACES) {
    if (desc.required && !seen.has(desc.iface)) {
      out.push(`the ${desc.name} interface is required and was not found`);
    }
  }

  return out;
}

module.exports = {
  INTERFACES,
  VENDOR_ID,
  PRODUCT_ID,
  reportDescriptorRequest,
  parseUsage,
  identify,
  describe,
  problems,
};
