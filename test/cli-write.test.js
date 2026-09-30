/*
 * cli/index.js - onlykey-js's WRITE commands, driven through main() against the
 * fake firmware.
 *
 * Two things are pinned for every command: the FRAME that reaches the key
 * (message, slot, field, payload - so python's field mapping, including its
 * non-obvious addchar numbering, is checked byte for byte), and the LINES a
 * person sees, which are python-onlykey's where python's are not a bug. A
 * command line that is wrong must be refused before a key is opened, so those
 * tests pass a `start` that throws.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { PassThrough } = require('node:stream');

const { main, COMMANDS, parseSlot } = require('../cli/index');
const { promptSecret } = require('../cli/prompt');
const { startDesktop } = require('../cli/desktop');
const { fakeFirmware } = require('./helpers/fake-firmware');
const { IFACE } = require('../src/transport/contract');
const { MSG, FIELD } = require('../src/protocol/msg');
const { fromHex, toLatin1 } = require('../src/bytes');

const NO_DEVICE = { start: () => { throw new Error('opened a device'); } };

/** Run one command line over a fake key; collect stdout, stderr, prompts and the code. */
async function run(argv, firmwareOpts = {}, extra = {}) {
  const out = [];
  const err = [];
  const asked = [];
  const answers = (extra.answers || []).slice();
  const firmware = fakeFirmware(firmwareOpts);
  const code = await main(argv, {
    out: (line) => out.push(line),
    err: (line) => err.push(line),
    prompt: async (question) => { asked.push(question); return answers.shift(); },
    readFile: extra.readFile || (async () => { throw new Error('no such file'); }),
    start: extra.start || ((opts) => startDesktop({ ...opts, pipe: firmware })),
  });
  return { code, out, err, asked, firmware };
}

/** The vendor frames of one message id the command sent. */
function sent(firmware, msg) {
  return firmware.writes
    .filter((w) => w.iface === IFACE.VENDOR && w.data[4] === msg)
    .map((w) => w.data);
}

/** [slot, field, ...payload] of an OKSETSLOT frame, payload up to its first NUL. */
function slotWrite(frame) {
  const payload = [];
  for (let i = 7; i < frame.length && frame[i] !== 0; i++) payload.push(frame[i]);
  return { slot: frame[5], field: frame[6], payload: Uint8Array.from(payload) };
}

/* ------------------------------------------------------------ usage */

test('python\'s slot names: 1a-6b are 1-12, green1a-purple3b are 1-24, numbers as given', () => {
  assert.deepEqual(['1a', '6a', '1b', '6b', '2B'].map(parseSlot), [1, 6, 7, 12, 8]);
  assert.deepEqual(['green1a', 'green1b', 'blue1a', 'purple3b'].map(parseSlot), [1, 4, 7, 24]);
  assert.equal(parseSlot('17'), 17);
  for (const bad of ['0', '25', '7a', 'red1a', 'x']) assert.throws(() => parseSlot(bad), /not a slot/);
});

test('a bad command line is refused before any key is opened, with the usage line', async () => {
  const cases = [
    [['setslot'], /needs a slot and a field/],
    [['setslot', '1a', 'colour', 'x'], /"colour" is not a slot field/],
    [['setslot', '9z', 'label', 'x'], /"9z" is not a slot/],
    [['setslot', '1a', 'label', 'My', 'Bank'], /takes one value, got 2 - quote/],
    [['setslot', '1a', 'label', 'seventeen-chars-x'], /17 characters, the device stores 16/],
    [['setslot', '1a', 'delay1', '12'], /single digit/],
    [['setslot', '1a', 'password', 'hunter2'], /shell history/],
    [['setslot', 'ECC3', 'rsakeylabel', 'x'], /is not a key slot/],
    [['setslot', '17', 'ecckeylabel', 'x'], /1-16/],
    [['setslot', '5', 'rsakeylabel', 'x'], /1-4/],
    [['wipeslot'], /one slot/],
    [['idletimeout', 'ten'], /one number/],
    [['genkey', 'HMAC1', 'x', 'd'], /ECC1-ECC16/],
    [['genkey', 'ECC1', 'h', 'd'], /genkey makes/],
    [['genkey', 'ECC1', 'x'], /needs the key's use/],
    [['genkey', 'ECC1', 'x', 'q'], /features must be/],
    [['setkey', 'ECC1', 'm', 'd', 'ab'], /made on the key with genkey/],
    [['setkey', 'RSA1', 'x', 'd', 'ab'], /RSA slot takes type 1-4/],
    [['setkey', 'ECC1', 'x', 'd', 'abcd'], /takes 32 bytes \(64 hex characters\); got 2/],
    [['setkey', 'ECC1', 'x', 'd', 'zz'], /not hex/],
    [['setkey', 'HMAC1', 'label', 'x'], /has no label/],
    [['loadkey'], /takes a key file/],
    [['loadkey', 'k.asc', 'auto', 'd'], /give features with a named slot/],
    [['wipekey', 'ECC17'], /not a key slot/],
  ];
  for (const [argv, why] of cases) {
    const r = await run(argv, {}, NO_DEVICE);
    assert.equal(r.code, 2, argv.join(' '));
    assert.match(r.err[0], why, argv.join(' '));
    assert.match(r.err.at(-1), new RegExp(`^Usage: onlykey-js ${argv[0]} `), argv.join(' '));
    assert.deepEqual(r.out, [], argv.join(' '));
  }
});

test('every write is marked [writes] in help, and no write command runs on a locked key', async () => {
  const help = await run(['help'], {}, NO_DEVICE);
  const writes = Object.entries(COMMANDS).filter(([, c]) => c.writes).map(([n]) => n);
  assert.ok(writes.length >= 20, writes.join(' '));
  for (const name of writes) {
    assert.ok(help.out.some((l) => l.startsWith(`  ${name} `) && l.endsWith('[writes]')), name);
  }

  for (const argv of [['setslot', '1a', 'label', 'x'], ['wipeslot', '1a'], ['genkey', 'ECC1', 'x', 's'],
    ['wipekey', 'ECC1'], ['idletimeout', '5']]) {
    const r = await run(argv, { pin: '1234567' });
    assert.equal(r.code, 1, argv.join(' '));
    assert.match(r.err[0], /locked\. Enter your PIN/, argv.join(' '));
    assert.equal(sent(r.firmware, MSG.OKSETSLOT).length + sent(r.firmware, MSG.OKSETPRIV).length
      + sent(r.firmware, MSG.OKWIPESLOT).length + sent(r.firmware, MSG.OKWIPEPRIV).length, 0);
  }
});

/* ------------------------------------------------------------ setslot */

test('setslot label: one OKSETSLOT, field 1, the text; prints the key\'s answer as python does', async () => {
  const r = await run(['setslot', '1b', 'label', 'GitHub']);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.out, ['Successfully set Label']);
  const writes = sent(r.firmware, MSG.OKSETSLOT).map(slotWrite);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].slot, 7, '1b is slot 7');
  assert.equal(writes[0].field, FIELD.LABEL);
  assert.equal(toLatin1(writes[0].payload), 'GitHub');
  assert.equal(r.firmware.isRunning(), false, 'the key was released');
});

test('setslot maps python\'s field names to the wire, addchar numbering included', async () => {
  const expect = [
    ['url', 'example.com', FIELD.URL, 'example.com'],
    ['addchar1', '2', FIELD.NEXTKEY4, '2'],
    ['addchar2', '1', FIELD.NEXTKEY1, '1'],
    ['addchar3', '2', FIELD.NEXTKEY2, '2'],
    ['addchar4', '1', FIELD.NEXTKEY5, '1'],
    ['addchar5', '2', FIELD.NEXTKEY3, '2'],
    ['delay1', '3', FIELD.DELAY1, '3'],
    ['delay2', '4', FIELD.DELAY2, '4'],
    ['delay3', '5', FIELD.DELAY3, '5'],
    ['username', ' me ', FIELD.USERNAME, ' me '],
    ['2fa', 'g', FIELD.TFATYPE, 'g'],
  ];
  for (const [type, value, field, payload] of expect) {
    const r = await run(['setslot', 'green2a', type, value]);
    assert.equal(r.code, 0, `${type}: ${r.err.join(' ')}`);
    const [w] = sent(r.firmware, MSG.OKSETSLOT).map(slotWrite);
    assert.equal(w.slot, 2, type);
    assert.equal(w.field, field, type);
    /* ASCII digits, as python and the desktop app send them: '3' is 0x33, not 3. */
    assert.equal(toLatin1(w.payload), payload, type);
  }

  /* typespeed is the one raw byte (python's int()). */
  const r = await run(['setslot', '3', 'typespeed', '7']);
  const [w] = sent(r.firmware, MSG.OKSETSLOT).map(slotWrite);
  assert.equal(w.field, FIELD.TYPESPEED);
  assert.deepEqual([...w.payload], [7]);
});

test('setslot password, gkey and totpkey are prompted for, never read from argv', async () => {
  let r = await run(['setslot', '2', 'password'], {}, { answers: ['s3cret pass'] });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.asked, ['Password: ']);
  let [w] = sent(r.firmware, MSG.OKSETSLOT).map(slotWrite);
  assert.equal(w.field, FIELD.PASSWORD);
  assert.equal(toLatin1(w.payload), 's3cret pass', 'surrounding text kept as typed');

  /* Unpadded base32 - python's b32decode refuses this length. */
  r = await run(['setslot', '2', 'gkey'], {}, { answers: ['jbsw y3dp ehpk 3pxp'] });
  assert.equal(r.code, 0, r.err.join('\n'));
  [w] = sent(r.firmware, MSG.OKSETSLOT).map(slotWrite);
  assert.equal(w.field, FIELD.TFAUSERNAME);
  assert.deepEqual([...w.payload], [...fromHex('48656c6c6f21deadbeef')]);

  r = await run(['setslot', '2', 'totpkey'], {}, { answers: ['abc123'] });
  [w] = sent(r.firmware, MSG.OKSETSLOT).map(slotWrite);
  assert.equal(w.field, FIELD.TFAUSERNAME);
  assert.equal(toLatin1(w.payload), 'abc123', 'python sends the characters (from_ascii)');

  r = await run(['setslot', '2', 'password'], {}, { answers: [''] });
  assert.equal(r.code, 2);
  assert.match(r.err[0], /no password was entered; nothing was written/);
  assert.equal(sent(r.firmware, MSG.OKSETSLOT).length, 0);
});

test('setslot ecckeylabel and rsakeylabel land on the key label indexes, as python\'s +28 and +24', async () => {
  let r = await run(['setslot', '3', 'ecckeylabel', 'ssh']);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(slotWrite(sent(r.firmware, MSG.OKSETSLOT)[0]).slot, 31);
  r = await run(['setslot', 'RSA2', 'rsakeylabel', 'work']);
  assert.equal(slotWrite(sent(r.firmware, MSG.OKSETSLOT)[0]).slot, 26);
});

test('a refusal prints the key\'s sentence on stdout, as python does, and exits 1', async () => {
  const r = await run(['setslot', '1a', 'label', 'x'], { slotError: 'Error not in config mode' });
  assert.equal(r.code, 1);
  assert.deepEqual(r.out, ['Error not in config mode']);
  assert.match(r.err[0], /needs config mode/);
});

test('wipeslot sends a whole-slot wipe (no field byte) and prints the answer', async () => {
  const r = await run(['wipeslot', 'purple3b']);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.out, ['Successfully wiped slot']);
  const [frame] = sent(r.firmware, MSG.OKWIPESLOT);
  assert.equal(frame[5], 24);
  assert.equal(frame[6], 0, 'no field: the whole slot');
});

/* ------------------------------------------------------------ settings */

test('every python settings command names a preference the library has', async () => {
  const firmware = fakeFirmware({ version: 'v3.0.5-prodc' });
  const app = await startDesktop({ pipe: firmware });
  try {
    await app.services.device.connect();
    const names = new Set(app.services.device.preferences().map((p) => p.name));
    const settings = Object.entries(COMMANDS).filter(([, c]) => c.preference);
    assert.deepEqual(settings.map(([n]) => n).sort(), [
      'backupkeymode', 'derivedkeymode', 'hmackeymode', 'idletimeout', 'keylayout', 'keytypespeed',
      'ledbrightness', 'lockbutton', 'storedkeymode', 'sysadminmode', 'touchsense', 'webagentderivemode',
      'webcryptpolicy', 'webderivemode', 'wipemode',
    ]);
    for (const [name, cmd] of settings) assert.ok(names.has(cmd.preference), `${name} -> ${cmd.preference}`);
  } finally {
    await app.destroy();
  }
});

test('idletimeout writes field 11 on the global slot as one byte', async () => {
  const r = await run(['idletimeout', '30']);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.out, ['Successfully set Label'], 'the fake\'s one acknowledgement');
  const [w] = sent(r.firmware, MSG.OKSETSLOT).map(slotWrite);
  assert.equal(w.field, FIELD.LOCKOUT);
  assert.equal(w.slot, 0, 'the library\'s global slot; python uses 1, which set_slot ignores for settings');
  assert.deepEqual([...w.payload], [30]);
});

test('a value outside the library\'s range is a usage error and writes nothing', async () => {
  const r = await run(['touchsense', '1']);
  assert.equal(r.code, 2);
  assert.match(r.err[0], /touchSense must be an integer 2\.\.100/);
  assert.equal(sent(r.firmware, MSG.OKSETSLOT).length, 0);
});

test('a one-way setting needs --yes; with it, it is written', async () => {
  let r = await run(['wipemode', '2']);
  assert.equal(r.code, 2);
  assert.match(r.err[0], /wipemode cannot be undone once written\..*--yes/);
  assert.equal(sent(r.firmware, MSG.OKSETSLOT).length, 0);

  r = await run(['wipemode', '2', '--yes']);
  assert.equal(r.code, 0, r.err.join('\n'));
  const [w] = sent(r.firmware, MSG.OKSETSLOT).map(slotWrite);
  assert.equal(w.field, FIELD.WIPEMODE);
  assert.deepEqual([...w.payload], [2]);
});

test('webagentderivemode and webcryptpolicy are refused by version below 3.0.5, nothing written', async () => {
  for (const argv of [['webagentderivemode', '1'], ['webcryptpolicy', '1', '--yes']]) {
    const r = await run(argv, { version: 'v3.0.4-prodc' });
    assert.equal(r.code, 1, argv.join(' '));
    assert.match(r.err[0], /needs firmware 3\.1\.0 or later/);
    assert.equal(sent(r.firmware, MSG.OKSETSLOT).length, 0);
  }
  const r = await run(['webderivemode', '2'], { version: 'v3.0.5-prodc' });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(slotWrite(sent(r.firmware, MSG.OKSETSLOT)[0]).field, 30);
});

test('settime prints the status line the key answers the clock with', async () => {
  const r = await run(['settime'], { version: 'v3.1.0-prodc' });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.out, ['UNLOCKEDv3.1.0-prodc']);
  assert.equal(sent(r.firmware, MSG.OKCONNECT).length, 1, 'the connect IS the set-time');
});

/* ------------------------------------------------------------ keys */

test('genkey x/n/s: the all-FF trigger with the type and use bits, python\'s 32 bytes of it', async () => {
  const r = await run(['genkey', 'ECC1', 'x', 's']);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.out, ['Successfully set ECC Key']);
  const [frame] = sent(r.firmware, MSG.OKSETPRIV);
  assert.equal(frame[5], 101);
  assert.equal(frame[6], 0x41, 'Ed25519 | signature');
  assert.deepEqual([...frame.subarray(7, 39)], new Array(32).fill(0xff));
  assert.equal(r.firmware.generations, 1);
});

test('genkey c is refused below 3.0.5, where the key would be the constant trigger', async () => {
  let r = await run(['genkey', 'ECC2', 'c', 'd'], { version: 'v3.0.4-prodc' });
  assert.equal(r.code, 1);
  assert.match(r.err[0], /cannot generate a Curve25519 key.*Nothing was written/);
  assert.equal(sent(r.firmware, MSG.OKSETPRIV).length, 0);

  r = await run(['genkey', 'ECC2', 'c', 'b'], { version: 'v3.0.5-prodc' });
  assert.equal(r.code, 0, r.err.join('\n'));
  const [frame] = sent(r.firmware, MSG.OKSETPRIV);
  assert.equal(frame[5], 102);
  assert.equal(frame[6], 0x04 | 0x80 | 0x20, 'Curve25519 | backup | decryption');
});

test('genkey m generates a post-quantum key on 3.0.5 and says what came back; refused on 3.0.4', async () => {
  const pub = new Uint8Array(1184).map((_, i) => (i * 7 + 3) & 0xff);
  let r = await run(['genkey', 'ECC3', 'm'], { version: 'v3.0.5-prodc', generates: { 103: pub } });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.out, ['Successfully generated ML-KEM-768 key in ECC3 (public key 1184 bytes)']);

  r = await run(['genkey', 'ECC3', 'm', 'd'], { version: 'v3.0.4-prodc' });
  assert.equal(r.code, 1);
  assert.match(r.err[0], /no post-quantum keys/);
  assert.equal(sent(r.firmware, MSG.OKSETPRIV).length, 0);
});

test('setkey ECC: the key from argv (with a history note) or from the prompt', async () => {
  const hex = '11'.repeat(32);
  let r = await run(['setkey', 'ECC4', 'n', 'd', hex]);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.out, ['Successfully set ECC Key']);
  assert.match(r.err[0], /shell history/);
  let [frame] = sent(r.firmware, MSG.OKSETPRIV);
  assert.equal(frame[5], 104);
  assert.equal(frame[6], 0x22, 'P-256 | decryption');
  assert.deepEqual([...frame.subarray(7, 39)], new Array(32).fill(0x11));

  r = await run(['setkey', 'ECC4', 's'], {}, { answers: ['22'.repeat(32)] });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.asked, ['Key (hex): ']);
  assert.deepEqual(r.err, []);
  [frame] = sent(r.firmware, MSG.OKSETPRIV);
  assert.equal(frame[6], 0x03, 'secp256k1, no use bits');
});

test('setkey HMAC and RSA: the right slot, type and length; HMAC says it drops the press', async () => {
  let r = await run(['setkey', 'HMAC1', 'h'], {}, { answers: ['ab'.repeat(20)] });
  assert.equal(r.code, 0, r.err.join('\n'));
  const [frame] = sent(r.firmware, MSG.OKSETPRIV);
  assert.equal(frame[5], 130, 'HMAC1 is slot 130, python\'s numbering');
  assert.equal(frame[6], 9);
  assert.match(r.err.join('\n'), /clears the button-press requirement/);

  r = await run(['setkey', 'RSA2', '2', 'd'], {}, { answers: ['5a'.repeat(256)] });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.out, ['Successfully set RSA Key']);
  const frames = sent(r.firmware, MSG.OKSETPRIV);
  assert.ok(frames.length > 1, 'an RSA key is chunked');
  assert.ok(frames.every((f) => f[5] === 2 && f[6] === 0x22));
});

test('setkey <slot> label names a key slot', async () => {
  const r = await run(['setkey', 'ECC16', 'label', 'age key']);
  assert.equal(r.code, 0, r.err.join('\n'));
  const [w] = sent(r.firmware, MSG.OKSETSLOT).map(slotWrite);
  assert.equal(w.slot, 44);
  assert.equal(toLatin1(w.payload), 'age key');
});

test('wipekey prints the wipe and the label clear, as python does; HMAC has no label', async () => {
  let r = await run(['wipekey', 'ECC2']);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.out, ['Successfully wiped ECC Key', 'Successfully set Label']);
  assert.equal(sent(r.firmware, MSG.OKWIPEPRIV)[0][5], 102);
  assert.equal(slotWrite(sent(r.firmware, MSG.OKSETSLOT)[0]).slot, 30);

  r = await run(['wipekey', 'HMAC2']);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.out, ['Successfully wiped ECC Key']);
  assert.equal(sent(r.firmware, MSG.OKWIPEPRIV)[0][5], 129);
  assert.equal(sent(r.firmware, MSG.OKSETSLOT).length, 0);
});

/* ------------------------------------------------------------ loadkey */

const openpgp = require('../src/crypto/pgp');

async function pgpKey(opts, passphrase) {
  const { privateKey } = await openpgp.generateKey({
    ...opts, userIDs: [{ name: 'CLI Test', email: 'cli@example.test' }], passphrase, format: 'armored',
  });
  return privateKey;
}

test('loadkey auto: python\'s lines, signing to slot 102 then decryption to slot 101', async () => {
  const armored = await pgpKey({ type: 'ecc', curve: 'ed25519' }, 'correct horse');
  const r = await run(['loadkey', 'me.asc'], {}, {
    readFile: async (file) => { assert.equal(file, 'me.asc'); return armored; },
    answers: ['correct horse'],
  });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.asked, ['Passphrase: '], 'asked because the key is locked');
  assert.deepEqual(r.out, [
    'Found 2 key(s):',
    '  [0] Primary Key - ECC 32 bytes',
    '  [1] Subkey - ECC 32 bytes',
    'Loading ECC key to slot 102...',
    'Successfully set ECC Key',
    'Loading ECC key to slot 101...',
    'Successfully set ECC Key',
  ]);
  const frames = sent(r.firmware, MSG.OKSETPRIV);
  assert.deepEqual(frames.map((f) => [f[5], f[6]]), [[102, 0x41], [101, 0x21]]);
});

test('loadkey to a named slot: the primary key, with the use given; RSA defaults to d as python', async () => {
  const RSA = require('./fixtures/rsa-2048.json');
  const r = await run(['loadkey', 'rsa.asc', 'RSA3'], {}, { readFile: async () => RSA.privateKey });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.deepEqual(r.asked, [], 'an unlocked key file is not asked about');
  assert.deepEqual(r.out, [
    'Found 2 key(s):',
    '  [0] Primary Key - RSA 2048 bits',
    '  [1] Subkey - RSA 2048 bits',
    'Multiple keys found. Loading primary key to slot 3.',
    'Loading RSA 2048 key to slot 3...',
    'Successfully set RSA Key',
  ]);
  assert.ok(sent(r.firmware, MSG.OKSETPRIV).every((f) => f[5] === 3 && f[6] === 0x22));
});

test('loadkey refuses a mismatched slot, an ECC key with no use, and a file that is not a key', async () => {
  const armored = await pgpKey({ type: 'ecc', curve: 'p256' });
  let r = await run(['loadkey', 'k.asc', 'RSA1', 'd'], {}, { readFile: async () => armored, ...NO_DEVICE });
  assert.equal(r.code, 2);
  assert.match(r.err[0], /the primary key is ECC; name an ECC1-ECC16 slot/);

  r = await run(['loadkey', 'k.asc', 'ECC5'], {}, { readFile: async () => armored, ...NO_DEVICE });
  assert.equal(r.code, 2);
  assert.match(r.err[0], /needs its use/);

  r = await run(['loadkey', 'k.asc', 'ECC5', 's'], {}, { readFile: async () => armored });
  assert.equal(r.code, 0, r.err.join('\n'));
  const [frame] = sent(r.firmware, MSG.OKSETPRIV);
  assert.deepEqual([frame[5], frame[6]], [105, 0x42]);

  r = await run(['loadkey', 'k.asc'], {}, { readFile: async () => 'not a key', ...NO_DEVICE });
  assert.equal(r.code, 1);
  assert.match(r.err[0], /is not an armored PGP private key/);
});

/* ------------------------------------------------------------ the prompt */

test('prompt: with no terminal, one line is read from stdin and nothing is printed', async () => {
  const input = new PassThrough();
  const written = [];
  const output = { write: (s) => written.push(s) };
  const answer = promptSecret('Password: ', { input, output });
  input.write('pa ss\r\nnext line\n');
  assert.equal(await answer, 'pa ss');
  assert.deepEqual(written, [], 'no prompt text into a pipe');

  const input2 = new PassThrough();
  const answer2 = promptSecret('Key: ', { input: input2, output });
  input2.end('no newline');
  assert.equal(await answer2, 'no newline');
});
