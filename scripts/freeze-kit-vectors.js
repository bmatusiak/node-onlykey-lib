#!/usr/bin/env node
/*
 * freeze-kit-vectors.js - record onlykey-testing's outputs as this library's
 * test vectors.
 *
 *   node scripts/freeze-kit-vectors.js [v1-commit] [v2-commit]
 *                                        (defaults: adac782, 9eb1de6)
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
 * So the kit's implementations are run ONCE, at pinned commits, on the inputs
 * in test/vectors/cases.js, and their outputs are written to
 * test/vectors/kit-reference.json with the commits they came from. The tests
 * compare against that file and never load the kit.
 *
 * TWO COMMITS, because the kit's transit changed format. v1 (box) is recorded
 * from adac782, the last kit commit that still has it - and every release
 * before firmware 3.0.5 still speaks it. v2 (session/seal/open) is recorded
 * from 9eb1de6 (the owner's kit main on 2026-09-27), whose transit.js has run
 * against the device; cbor and ctap2 come from the v1 commit, as before.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const cases = require('../test/vectors/cases');

const LIB = path.resolve(__dirname, '..');
const KIT = path.resolve(LIB, '..', 'onlykey-testing');
const V1 = process.argv[2] || 'adac782';
const V2 = process.argv[3] || '9eb1de6';
const OUT = path.join(LIB, 'test', 'vectors', 'kit-reference.json');

const git = (...args) => execFileSync('git', ['-C', KIT, ...args],
  { encoding: 'utf8', windowsHide: true }).trim();
const hex = (b) => Buffer.from(b).toString('hex');

/*
 * The kit's lib/ at a commit, unpacked INSIDE the kit checkout so its own
 * relative requires (./waits, ./cbor) work, and bare ones walk up to the
 * kit's node_modules. @noble/ciphers is optional there, so this library's copy
 * is on NODE_PATH as the fallback - beforenm() needs it.
 */
const temps = [];
function extract(commit) {
  const full = git('rev-parse', `${commit}^{commit}`);
  const tmp = fs.mkdtempSync(path.join(KIT, '.freeze-'));
  temps.push(tmp);
  for (const f of git('ls-tree', '-r', '--name-only', full, 'lib').split('\n').filter(Boolean)) {
    const dest = path.join(tmp, f);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, execFileSync('git', ['-C', KIT, 'show', `${full}:${f}`], { windowsHide: true }));
  }
  return {
    full,
    date: git('log', '-1', '--format=%ad', '--date=short', full),
    load: (m) => require(path.join(tmp, 'lib', 'device', m)),
  };
}

try {
  process.env.NODE_PATH = [path.join(KIT, 'node_modules'), path.join(LIB, 'node_modules')]
    .join(path.delimiter);
  require('module').Module._initPaths();

  const v1 = extract(V1);
  const v2 = extract(V2);
  const kcbor = v1.load('cbor.js');
  const kctap = v1.load('ctap2.js');
  const ktransit = v1.load('transit.js');
  const ktransit2 = v2.load('transit.js');
  const transit = require('../src/session/transit');
  const V = transit.VECTORS;

  const out = {
    source: {
      repo: 'onlykey-testing',
      commit: v1.full,
      date: v1.date,
      files: ['lib/device/cbor.js', 'lib/device/ctap2.js', 'lib/device/transit.js'],
      transitV2: { commit: v2.full, date: v2.date, files: ['lib/device/transit.js'] },
      note: 'Outputs of the kit\'s own implementations on test/vectors/cases.js. ' +
        'Regenerate with scripts/freeze-kit-vectors.js; do not hand-edit.',
    },
    cbor: {},
    ctaphid: {},
    transit: {},
    transitV2: {},
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
    const priv = crypto.createPrivateKey({
      key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'),
        Buffer.from(V.aliceSecret, 'hex')]),
      format: 'der', type: 'pkcs8',
    });
    out.transit.beforenm = hex(ktransit.beforenm(Buffer.from(V.bobPublic, 'hex'), priv));
    if (!ktransit.selfTest().ok) throw new Error('the kit\'s transit selfTest() failed');
    out.transit.kitSelfTest = 'passed';
  } else {
    out.transit.beforenm = null;
    out.transit.kitSelfTest = 'not run: @noble/ciphers unavailable';
  }

  /*
   * v2 host -> device: one session, successive seals - so the recorded
   * frames also pin the counter advancing 0, 1, 2, ...
   */
  const v2key = Buffer.alloc(32, cases.V2_KEY_BYTE);
  const sess = ktransit2.session(v2key);
  out.transitV2.seal = cases.V2_SEAL_LENGTHS.map((n) =>
    hex(ktransit2.seal(sess, Buffer.alloc(n, cases.V2_DATA_BYTE))));

  /*
   * v2 device -> host: the kit has no device-side seal, so each frame is built
   * here from the firmware's rule (okcrypto_transit_seal: IV = [0][ctr BE][0x7],
   * AES-256-GCM) and the KIT's open() must return the plaintext before it is
   * recorded - the kit's decryptor is the oracle for the frame.
   */
  out.transitV2.open = cases.V2_OPEN_FRAMES.map(({ counter, length }) => {
    const iv = Buffer.alloc(12);
    iv.writeUInt32BE(counter >>> 0, 1);
    const plain = Buffer.alloc(length, cases.V2_DATA_BYTE);
    const c = crypto.createCipheriv('aes-256-gcm', v2key, iv);
    const ct = Buffer.concat([c.update(plain), c.final()]);
    const head = Buffer.alloc(4);
    head.writeUInt32BE(counter >>> 0, 0);
    const frame = Buffer.concat([head, ct, c.getAuthTag()]);
    if (!ktransit2.open(v2key, frame).equals(plain)) {
      throw new Error(`the kit's open() disagrees with the frame for counter ${counter}`);
    }
    return { counter, frame: hex(frame), plaintext: hex(plain) };
  });

  fs.writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n');
  console.log(`froze onlykey-testing@${v1.full.slice(0, 7)} (${v1.date}) + ` +
    `transit v2 @${v2.full.slice(0, 7)} (${v2.date}) -> ${path.relative(LIB, OUT)}: ` +
    `${Object.keys(out.cbor).length} cbor, ${Object.keys(out.ctaphid).length} ctaphid, ` +
    `${Object.keys(out.transit.box).length} box${out.transit.beforenm ? ', beforenm' : ''}, ` +
    `${out.transitV2.seal.length} v2 seal, ${out.transitV2.open.length} v2 open`);
} finally {
  for (const t of temps) fs.rmSync(t, { recursive: true, force: true });
}
