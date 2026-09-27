#!/usr/bin/env node
/*
 * freeze-kit-vectors.js - record onlykey-testing's outputs as this library's
 * test vectors.
 *
 *   node scripts/freeze-kit-vectors.js [kit-commit]      (default: adac782)
 *
 * WHY FROZEN. The cbor, ctaphid and transit modules here were ported from the
 * test kit's, which had run against a physical key, so the kit was the oracle:
 * each test required ../onlykey-testing/lib/device/*.js and compared bytes
 * live. That cannot last:
 *
 *   - The kit is moving ONTO this library ("one lib, any GUI - the test CLI is
 *     a UI"). Once it uses these modules, a live cross-check compares the
 *     library with itself and proves nothing.
 *   - It already broke: the kit replaced box() with transit v2's seal/open
 *     (f207db9, 2026-09-22), and "box matches onlykey-testing" has failed since
 *     - a test of the kit's API rather than of this library.
 *
 * So the kit's implementations are run ONCE, at a pinned commit, on the inputs
 * in test/vectors/cases.js, and their outputs are written to
 * test/vectors/kit-reference.json with the commit they came from. The tests
 * compare against that file and never load the kit.
 *
 * adac782 is the last kit commit whose transit.js still exports box(); cbor.js
 * and ctap2.js there are the implementations the ports were made from.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const cases = require('../test/vectors/cases');

const LIB = path.resolve(__dirname, '..');
const KIT = path.resolve(LIB, '..', 'onlykey-testing');
const commit = process.argv[2] || 'adac782';
const OUT = path.join(LIB, 'test', 'vectors', 'kit-reference.json');

const git = (...args) => execFileSync('git', ['-C', KIT, ...args],
  { encoding: 'utf8', windowsHide: true }).trim();

const full = git('rev-parse', `${commit}^{commit}`);

/*
 * The kit's lib/ at that commit, unpacked INSIDE the kit checkout so its own
 * relative requires (./waits, ./cbor) work, and bare ones walk up to the
 * kit's node_modules. @noble/ciphers is optional there, so this library's copy
 * is on NODE_PATH as the fallback - beforenm() needs it.
 */
const tmp = fs.mkdtempSync(path.join(KIT, '.freeze-'));
try {
  const files = git('ls-tree', '-r', '--name-only', full, 'lib').split('\n').filter(Boolean);
  for (const f of files) {
    const dest = path.join(tmp, f);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, execFileSync('git', ['-C', KIT, 'show', `${full}:${f}`], { windowsHide: true }));
  }
  process.env.NODE_PATH = [path.join(KIT, 'node_modules'), path.join(LIB, 'node_modules')]
    .join(path.delimiter);
  require('module').Module._initPaths();

  const kit = (m) => require(path.join(tmp, 'lib', 'device', m));
  const kcbor = kit('cbor.js');
  const kctap = kit('ctap2.js');
  const ktransit = kit('transit.js');
  const transit = require('../src/session/transit');
  const V = transit.VECTORS;

  const hex = (b) => Buffer.from(b).toString('hex');
  const out = {
    source: {
      repo: 'onlykey-testing',
      commit: full,
      date: git('log', '-1', '--format=%ad', '--date=short', full),
      files: ['lib/device/cbor.js', 'lib/device/ctap2.js', 'lib/device/transit.js'],
      note: 'Outputs of the kit\'s own implementations on test/vectors/cases.js. ' +
        'Regenerate with scripts/freeze-kit-vectors.js; do not hand-edit.',
    },
    cbor: {},
    ctaphid: {},
    transit: {},
  };

  for (const [what, value] of cases.CBOR_CASES) {
    out.cbor[what] = hex(kcbor.encode(value instanceof Uint8Array ? Buffer.from(value) : value));
  }

  const BROADCAST_CID = Buffer.from([0xff, 0xff, 0xff, 0xff]);
  const CBOR_CMD = 0x10;
  for (const len of cases.CTAPHID_LENGTHS) {
    out.ctaphid[len] = kctap.frame(BROADCAST_CID, CBOR_CMD,
      Buffer.from(cases.ctaphidPayload(len))).map(hex);
  }

  const key = Buffer.alloc(32, cases.BOX_KEY_BYTE);
  out.transit.box = {};
  for (const n of cases.BOX_LENGTHS) {
    out.transit.box[n] = hex(ktransit.box(key, Buffer.alloc(n, cases.BOX_DATA_BYTE)));
  }
  out.transit.connectPayloadFrom5 = hex(ktransit.connectPayload(
    Buffer.alloc(32, cases.CONNECT_PK_BYTE), { when: cases.CONNECT_WHEN }).subarray(5));

  if (ktransit.probe().ok) {
    const crypto = require('crypto');
    const priv = crypto.createPrivateKey({
      key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'),
        Buffer.from(V.aliceSecret, 'hex')]),
      format: 'der', type: 'pkcs8',
    });
    out.transit.beforenm = hex(ktransit.beforenm(Buffer.from(V.bobPublic, 'hex'), priv));
    ktransit.selfTest();
    out.transit.kitSelfTest = 'passed';
  } else {
    out.transit.beforenm = null;
    out.transit.kitSelfTest = 'not run: @noble/ciphers unavailable';
  }

  fs.writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n');
  console.log(`froze onlykey-testing@${full.slice(0, 7)} (${out.source.date}) -> ` +
    `${path.relative(LIB, OUT)}: ${Object.keys(out.cbor).length} cbor, ` +
    `${Object.keys(out.ctaphid).length} ctaphid, ${Object.keys(out.transit.box).length} box` +
    `${out.transit.beforenm ? ', beforenm' : ''}`);
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
