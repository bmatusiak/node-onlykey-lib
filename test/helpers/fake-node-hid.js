/*
 * A stand-in for the node-hid MODULE, so the desktop pipe is tested without a
 * bus - and without node-hid installed at all.
 *
 * Faithful to the two hidapi behaviours cli/transport-hid.js exists to handle:
 *
 *   - A WRITE carries a leading report ID byte, which hidapi consumes. The
 *     fake records the raw array and refuses a write whose first byte is not 0
 *     (as a device with no numbered reports would be sent garbage), then hands
 *     the remaining 64 bytes to the firmware.
 *
 *   - A READ arrives as the report alone, 64 bytes, report ID already
 *     stripped - unless `readWithReportId` asks for the 65-byte shape a
 *     platform could deliver, to prove the pipe copes with it.
 *
 * `firmware` is test/helpers/fake-firmware.js (or any pipe): its device-bound
 * stream is re-emitted as node-hid 'data' events, which is exactly the path a
 * real key's reports take.
 *
 * NOTHING HERE TOUCHES USB. The whole point is that no test can.
 */
'use strict';

const { EventEmitter } = require('events');
const { IFACE, DIR } = require('../../src/transport/contract');

const ONLYKEY = { vendorId: 0x1d50, productId: 0x60fc };

/** The four interfaces of one key, as hidapi enumerates them. */
function onlykeyInterfaces(prefix = 'key1', { usagePages = true } = {}) {
  const page = (p) => (usagePages ? p : 0);
  return [
    { ...ONLYKEY, path: `${prefix}-if0`, interface: 0, usagePage: page(0x0001), usage: usagePages ? 0x06 : 0, serialNumber: '1000000000' },
    { ...ONLYKEY, path: `${prefix}-if1`, interface: 1, usagePage: page(0xf1d0), usage: usagePages ? 0x01 : 0, serialNumber: '1000000000' },
    { ...ONLYKEY, path: `${prefix}-if2`, interface: 2, usagePage: page(0xffab), usage: usagePages ? 0x02 : 0, serialNumber: '1000000000' },
    { ...ONLYKEY, path: `${prefix}-if3`, interface: 3, usagePage: page(0xffc9), usage: usagePages ? 0x04 : 0, serialNumber: '1000000000' },
  ];
}

/**
 * @param {object} [opts]
 * @param {object[]} [opts.devices]  what HID.devices() lists
 * @param {object} [opts.firmware]   a pipe that answers vendor writes
 * @param {boolean} [opts.readWithReportId] deliver reads as 65 bytes, ID first
 * @param {string} [opts.openError]  make `new HID(path)` throw this
 */
function fakeNodeHid({ devices = onlykeyInterfaces(), firmware = null, readWithReportId = false, openError = null } = {}) {
  const opened = [];

  class HID extends EventEmitter {
    constructor(path) {
      super();
      if (openError) throw new Error(openError);
      this.path = path;
      this.writes = [];
      this.closed = false;
      opened.push(this);
      this.off = firmware
        ? firmware.on('stream', (event) => {
          if (event.dir !== DIR.OUT || event.iface !== IFACE.VENDOR || this.closed) return;
          const report = readWithReportId
            ? Buffer.concat([Buffer.from([0]), Buffer.from(event.bytes)])
            : Buffer.from(event.bytes);
          /* hidapi's read thread delivers on its own turn, never inside write(). */
          setImmediate(() => { if (!this.closed) this.emit('data', report); });
        })
        : null;
    }

    write(array) {
      if (this.closed) throw new Error('Cannot write to hid device');
      const raw = Array.from(array);
      this.writes.push(raw);
      if (raw[0] !== 0x00) throw new Error(`report ID ${raw[0]} - this device has no numbered reports`);
      if (firmware) firmware.write(IFACE.VENDOR, Uint8Array.from(raw.slice(1)));
      return raw.length;
    }

    close() {
      this.closed = true;
      if (this.off) this.off();
    }
  }

  return {
    HID,
    devices: () => devices.map((d) => ({ ...d })),
    /** Every device object the code under test opened, in order. */
    opened,
  };
}

module.exports = { fakeNodeHid, onlykeyInterfaces };
