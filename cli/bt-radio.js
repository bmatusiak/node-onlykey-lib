'use strict';
/*
 * THIS COMPUTER'S BLUETOOTH RADIO: its version, and whether onlykey-js --ble supports it.
 *
 *   node cli/bt-radio.js        prints the radio and the verdict; exit 1 when it is not supported
 *   require('…/cli/bt-radio')   checkRadio() for the CLI (`onlykey-js --ble pair` asks it first)
 *
 * WHY A MINIMUM (ZBOX, 2026-10-20; Brad: "we need a way to tell users there is no support for
 * bt4"). The ZBOX's Intel radio is Bluetooth 4.0 (HCI version 6). The phone pairs with Secure
 * Connections, whose classic-link key needs AES-CCM encryption on the classic link - a 4.1
 * feature - so the kernel refused every classic connect ("Invalid security: Missing AES-CCM
 * usage"), the phone's keyboard never connected, and the phone retried every 15 s while the LE
 * link onlykey-js uses went unanswered. With Secure Connections turned off it can be made to
 * pair, but only with two pairings in a set order, and each failed try made Android drop the
 * bond. A night of that is not something to hand a user. The Pi 4 (5.0) and NITRO16 (5.4) work.
 * 5.0 is what is proven; 4.1 and 4.2 are untested, and "no support for bt4" draws the line.
 *
 * HOW IT IS READ - no root, no Bluetooth stack loaded:
 *   Linux    `btmgmt info`: each controller's "version N" is its HCI version.
 *   Windows  the radio's device property {A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 4, its LMP version
 *            (the same set's 2 is the maker - 70 = MediaTek on NITRO16's RZ616, how the keys
 *            were confirmed; 6 is the HCI version, equal to 4 there).
 * HCI and LMP versions number Bluetooth releases the same way (6 = 4.0 … 9 = 5.0 … 13 = 5.4).
 * A radio that cannot be read is reported as unknown and not refused: no number, no verdict.
 */
const { execFile } = require('child_process');

const MIN_VERSION = 9; /* Bluetooth 5.0 */
const NAMES = { 0: '1.0b', 1: '1.1', 2: '1.2', 3: '2.0', 4: '2.1', 5: '3.0', 6: '4.0', 7: '4.1', 8: '4.2', 9: '5.0', 10: '5.1', 11: '5.2', 12: '5.3', 13: '5.4', 14: '6.0' };
const nameOf = (v) => NAMES[v] || `version ${v}`;

/** `btmgmt info` -> [{index, address, version}] (one per controller). */
function parseBtmgmt(text) {
  const out = [];
  let index = null;
  for (const line of String(text || '').split('\n')) {
    const h = line.match(/^hci(\d+):/);
    if (h) { index = Number(h[1]); continue; }
    const m = line.match(/\baddr ([0-9A-F:]{17}) version (\d+)\b/i);
    if (m) out.push({ index, address: m[1].toUpperCase(), version: Number(m[2]) });
  }
  return out;
}

/** The PowerShell query's output (one number per radio) -> [{version}]. */
function parseWindows(text) {
  return String(text || '').split(/\r?\n/).map((l) => l.trim()).filter((l) => /^\d+$/.test(l)).map((l) => ({ version: Number(l) }));
}

const WINDOWS_QUERY = "$k = '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 4'; "
  + 'Get-PnpDevice -Class Bluetooth -Status OK -ErrorAction SilentlyContinue | ForEach-Object { '
  + '$p = Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName $k -ErrorAction SilentlyContinue; '
  + 'if ($p -and $null -ne $p.Data) { [string]$p.Data } }';

const run = (file, args) => new Promise((resolve) => {
  execFile(file, args, { timeout: 15000, windowsHide: true }, (err, stdout) => resolve(err && !stdout ? null : String(stdout || '')));
});

/**
 * Read the radios. exec(file, args) -> stdout or null is injected by tests.
 * -> {platform, radios: [{version, name, index?, address?}], source} ; radios empty = unknown.
 */
async function readRadios({ platform = process.platform, exec = run } = {}) {
  if (platform === 'linux') {
    const text = await exec('btmgmt', ['info']);
    return { platform, source: 'btmgmt info', radios: parseBtmgmt(text).map((r) => ({ ...r, name: nameOf(r.version) })) };
  }
  if (platform === 'win32') {
    const text = await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WINDOWS_QUERY]);
    return { platform, source: 'the radio\'s LMP version (device properties)', radios: parseWindows(text).map((r) => ({ ...r, name: nameOf(r.version) })) };
  }
  return { platform, source: null, radios: [] };
}

/**
 * The verdict. ok: false only when every radio read is older than the minimum. A newer radio
 * beside an old one (a USB dongle next to the built-in) is ok, with a note to make it the one
 * Bluetooth uses.
 */
function judge(read) {
  const min = nameOf(MIN_VERSION);
  const radios = read.radios || [];
  if (!radios.length) {
    return { ok: true, known: false, message: `this computer's Bluetooth version could not be read (${read.source || read.platform}); onlykey-js --ble needs Bluetooth ${min} or newer` };
  }
  const label = (r) => `Bluetooth ${r.name}${r.index !== null && r.index !== undefined ? ` (hci${r.index}${r.address ? ` ${r.address}` : ''})` : ''}`;
  const good = radios.filter((r) => r.version >= MIN_VERSION);
  const old = radios.filter((r) => r.version < MIN_VERSION);
  if (!good.length) {
    return {
      ok: false, known: true, radios,
      message: `this computer's Bluetooth radio is ${old.map(label).join(', ')} - not supported: onlykey-js --ble needs Bluetooth ${min} or newer. `
        + 'A USB Bluetooth 5 adapter works (on Linux, make it the default controller).',
    };
  }
  if (old.length) {
    return { ok: true, known: true, radios, message: `${good.map(label).join(', ')} is supported; ${old.map(label).join(', ')} is not - make sure Bluetooth uses the newer one` };
  }
  return { ok: true, known: true, radios, message: `${good.map(label).join(', ')} - supported` };
}

/** readRadios + judge. */
async function checkRadio(opts = {}) {
  const read = await readRadios(opts);
  return { ...judge(read), platform: read.platform, source: read.source };
}

module.exports = { MIN_VERSION, NAMES, nameOf, parseBtmgmt, parseWindows, readRadios, judge, checkRadio };

if (require.main === module) {
  checkRadio().then((r) => {
    process.stdout.write(`${r.ok ? '' : 'NOT SUPPORTED: '}${r.message}\n`);
    process.exit(r.ok ? 0 : 1);
  });
}
