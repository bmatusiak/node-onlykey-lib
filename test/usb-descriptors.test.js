/*
 * What an OnlyKey looks like on a USB bus.
 *
 * The descriptor bytes below are COPIED FROM THE FIRMWARE, not from the module
 * under test - `usb_desc.c`'s `keyboard_report_desc`, `rawhid_report_desc`,
 * `rawhid_report_desc2` and `seremu_report_desc`. That is the point: the parser
 * is checked against the thing it will meet, so an error would have to be made
 * twice, in two files, in different notations.
 *
 * The interesting property is not that it parses these. It is that the four
 * interfaces are otherwise INDISTINGUISHABLE - same class, same subclass, same
 * protocol, and three of them the same endpoint width - so this is the only
 * information that tells them apart.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const usb = require('../src/transport/usbDescriptors');
const { IFACE } = require('../src/protocol/msg');

/* ------------------------------------------------ the firmware's own bytes */

/** usb_desc.c:188 - Usage Page (Generic Desktop), Usage (Keyboard). */
const KEYBOARD = [
  0x05, 0x01,
  0x09, 0x06,
  0xa1, 0x01,
  0x05, 0x07,   // a SECOND usage page, which must not win
  0x19, 0xe0,
];

/** usb_desc.c:384 - RAWHID_USAGE_PAGE 0xF1D0, RAWHID_USAGE 0x01. */
const FIDO = [
  0x06, 0xd0, 0xf1,
  0x09, 0x01,
  0xa1, 0x01,
  0x09, 0x20,
];

/** usb_desc.c:405 - RAWHID_USAGE_PAGE2 0xFFAB, RAWHID_USAGE2 0x02. */
const VENDOR = [
  0x06, 0xab, 0xff,
  0x09, 0x02,
  0xa1, 0x01,
  0x09, 0x20,
];

/** usb_desc.c:363 - Usage Page 0xFFC9, Usage 0x04. */
const SEREMU = [
  0x06, 0xc9, 0xff,
  0x09, 0x04,
  0xa1, 0x5c,
  0x75, 0x08,
];

/* ------------------------------------------------------------------ tests */

test('every interface is identified from the firmware\'s own descriptor', () => {
  assert.equal(usb.identify(usb.parseUsage(KEYBOARD)), IFACE.KEYBOARD);
  assert.equal(usb.identify(usb.parseUsage(FIDO)), IFACE.FIDO);
  assert.equal(usb.identify(usb.parseUsage(VENDOR)), IFACE.VENDOR);
  assert.equal(usb.identify(usb.parseUsage(SEREMU)), IFACE.SEREMU);
});

test('the two RawHID interfaces differ ONLY in their usage page', () => {
  // This is the whole reason the module exists. An Android transport scored
  // class, subclass, protocol and endpoint width, tied three ways, and took
  // whichever came first in the descriptor. It was right by luck.
  const fido = usb.describe(IFACE.FIDO);
  const vendor = usb.describe(IFACE.VENDOR);

  assert.equal(fido.endpointIn, vendor.endpointIn);
  assert.equal(fido.endpointOut, vendor.endpointOut);
  assert.notEqual(fido.usagePage, vendor.usagePage);
});

test('the FIRST usage page wins, not the last', () => {
  // The keyboard descriptor sets Generic Desktop, then Key Codes four items
  // later. Taking the last would identify the keyboard as usage page 7, which
  // is nothing, and the interface would be left unclaimed.
  assert.equal(usb.parseUsage(KEYBOARD).usagePage, 0x0001);
});

test('a Report ID ahead of the usage does not break identification', () => {
  // The reason this walks HID items instead of matching a byte prefix. Nothing
  // in today's descriptors does this; a firmware update easily could, and a
  // prefix match would fail by identifying nothing rather than loudly.
  const withReportId = [0x85, 0x01].concat(VENDOR);
  assert.equal(usb.identify(usb.parseUsage(withReportId)), IFACE.VENDOR);
});

test('a four-byte usage page is read whole', () => {
  // bSize 3 means FOUR data bytes, not three - the one place the encoding is
  // not the obvious one.
  const wide = [0x07, 0xab, 0xff, 0x00, 0x00, 0x09, 0x02];
  assert.equal(usb.parseUsage(wide).usagePage, 0xffab);
  assert.equal(usb.identify(usb.parseUsage(wide)), IFACE.VENDOR);
});

test('nothing recognisable identifies as null, not as a guess', () => {
  assert.equal(usb.identify(usb.parseUsage([])), null);
  assert.equal(usb.identify(usb.parseUsage([0x06, 0x00, 0x99, 0x09, 0x01])), null);

  // Absent is distinguishable from zero, so a caller can tell "no usage page"
  // from "usage page 0".
  assert.equal(usb.parseUsage([]).usagePage, null);
  assert.equal(usb.parseUsage([0x05, 0x00]).usagePage, 0);
});

/* ------------------------------------------------------------- the checks */

const at = (iface, identifiedBy = 'usagePage') => ({ iface, identifiedBy });
const ALL = [
  at(IFACE.KEYBOARD), at(IFACE.FIDO), at(IFACE.VENDOR), at(IFACE.SEREMU),
];

test('a full developer key has no problems', () => {
  assert.deepEqual(usb.problems(ALL), []);
});

test('a production key is fine WITHOUT the debug interface', () => {
  // Three interfaces rather than four is a build, not a fault. Requiring
  // SEREMU would refuse every production key.
  const production = ALL.filter((e) => e.iface !== IFACE.SEREMU);
  assert.deepEqual(usb.problems(production), []);
});

test('a missing required interface is named, not inferred', () => {
  const noVendor = ALL.filter((e) => e.iface !== IFACE.VENDOR);
  const said = usb.problems(noVendor);
  assert.equal(said.length, 1);
  assert.match(said[0], /vendor interface is required/);

  // The keyboard is required too, because CAPTURING it is a goal - a host that
  // does not claim it lets the key type into whatever window has focus.
  const noKeyboard = ALL.filter((e) => e.iface !== IFACE.KEYBOARD);
  assert.match(usb.problems(noKeyboard)[0], /keyboard interface is required/);
});

test('two interfaces claiming to be the same one is refused', () => {
  // Last-wins here sends the vendor protocol to the security-key interface,
  // where every request times out and the message blames the device.
  const twice = ALL.concat([at(IFACE.VENDOR)]);
  assert.match(usb.problems(twice)[0], /two interfaces both identified as vendor/);
});

test('an interface identified by anything but its usage page is a guess', () => {
  const guessed = ALL.map(
    (e) => (e.iface === IFACE.FIDO ? at(IFACE.FIDO, 'order') : e));
  assert.match(usb.problems(guessed)[0], /identified by order rather than/);
});

/* --------------------------------------------------------- the request */

test('the report-descriptor request is the one the device answers', () => {
  // usb_dev.c handles requestType 0x81, and usb_desc.c keys its lookup on
  // exactly {value: 0x2200, index: bInterfaceNumber}. These are not free
  // choices - a different recipient or descriptor type gets a stall.
  const req = usb.reportDescriptorRequest(2);
  assert.equal(req.requestType, 0x81);
  assert.equal(req.request, 0x06);
  assert.equal(req.value, 0x2200);
  assert.equal(req.index, 2);

  // Over-asking is safe: the device clamps its reply to the true length.
  assert.equal(usb.reportDescriptorRequest(1).length, 256);
});

test('the ids are the ones the firmware declares', () => {
  assert.equal(usb.VENDOR_ID, 0x1d50);
  assert.equal(usb.PRODUCT_ID, 0x60fc);
});

test('SEREMU is asymmetric - 64 in, 32 OUT', () => {
  // Not a typo, and it is a real constraint: a write longer than 32 bytes does
  // not fit one report, and this interface's writes are not padded.
  const seremu = usb.describe(IFACE.SEREMU);
  assert.equal(seremu.endpointIn, 64);
  assert.equal(seremu.endpointOut, 32);

  // The keyboard has no OUT endpoint at all - it is device to host only.
  assert.equal(usb.describe(IFACE.KEYBOARD).endpointOut, 0);
});
