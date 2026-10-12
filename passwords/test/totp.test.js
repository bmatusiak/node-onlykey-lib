'use strict';

/*
 * Authenticator codes (passwords/src/totp.js) against the RFCs' own test vectors: RFC 4226
 * Appendix D (HOTP) and RFC 6238 Appendix B (TOTP, SHA1/256/512, 8 digits).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const { totp: t, manager: m } = require('../src');
const { memoryStore } = require('../../src/crypto/vault_store');

const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const SEED = {
  SHA1: ascii('12345678901234567890'),
  SHA256: ascii('12345678901234567890123456789012'),
  SHA512: ascii('1234567890123456789012345678901234567890123456789012345678901234'),
};
/* the SHA1 seed in base32, as a site would show it */
const SEED_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

test('RFC 4226 Appendix D: HOTP-SHA1, counters 0 to 9', () => {
  const want = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  want.forEach((code, c) => assert.equal(t.hotp(SEED.SHA1, c), code));
});

test('RFC 6238 Appendix B: TOTP, 8 digits, 30 s, SHA1 / SHA256 / SHA512', () => {
  const rows = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  for (const [time, s1, s256, s512] of rows) {
    const counter = Math.floor(time / 30);
    assert.equal(t.hotp(SEED.SHA1, counter, { digits: 8, algo: 'SHA1' }), s1, `SHA1 at ${time}`);
    assert.equal(t.hotp(SEED.SHA256, counter, { digits: 8, algo: 'SHA256' }), s256, `SHA256 at ${time}`);
    assert.equal(t.hotp(SEED.SHA512, counter, { digits: 8, algo: 'SHA512' }), s512, `SHA512 at ${time}`);
  }
});

test('an entry\'s code from its base32 setup key, with the seconds left', () => {
  const r = t.codeOf({ secret: SEED_B32.toLowerCase().match(/.{1,4}/g).join(' '), digits: 8 }, 59 * 1000);
  assert.deepEqual(r, { code: '94287082', remaining: 1, counter: 1 });
  assert.equal(t.codeOf({ type: 'hotp', secret: SEED_B32, counter: 1 }).code, '287082');
});

test('Steam: 5 characters from its alphabet, the same for the same moment', () => {
  const a = t.codeOf({ secret: SEED_B32, encoder: 'steam' }, 1_700_000_000_000).code;
  assert.match(a, /^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
  assert.equal(t.codeOf({ secret: SEED_B32, encoder: 'steam' }, 1_700_000_000_000).code, a);
});

test('an otpauth:// link: issuer, account and settings', () => {
  const r = t.parseOtpauth(`otpauth://totp/GitHub:brad%40example.com?secret=${SEED_B32}&issuer=GitHub&digits=6&period=30&algorithm=SHA1`);
  assert.equal(r.issuer, 'GitHub');
  assert.equal(r.account, 'brad@example.com');
  assert.deepEqual(r.totp, { type: 'totp', secret: SEED_B32, digits: 6, algo: 'SHA1', period: 30, issuer: 'GitHub' });
  assert.equal(t.parseOtpauth(`otpauth://totp/Steam:me?secret=${SEED_B32}&issuer=Steam`).totp.encoder, 'steam');
  assert.throws(() => t.parseOtpauth('https://github.com'), /otpauth/);
});

test('a bad setup key or setting is refused', () => {
  assert.throws(() => t.shapeTotp({ secret: '' }), /setup key/);
  assert.throws(() => t.shapeTotp({ secret: 'ABC1' }), /base32/);
  assert.throws(() => t.shapeTotp({ secret: 'GEZDGNBV' }), /too short/);
  assert.throws(() => t.shapeTotp({ secret: SEED_B32, digits: 5 }), /6, 7 or 8/);
  assert.throws(() => t.shapeTotp({ secret: SEED_B32, algo: 'MD5' }), /algo/);
  assert.throws(() => t.shapeTotp({ secret: SEED_B32, period: 5 }), /period/);
});

test('in the store: an authenticator entry, or a code attached to a login - sealed like a password', async () => {
  const raw = memoryStore();
  const a = await m.openManager({ store: m.prefixedStore(raw, 'p/'), key: new Uint8Array(32).fill(1), randomBytes: (n) => new Uint8Array(nodeCrypto.randomBytes(n)) });
  const own = await a.put({ kind: 'totp', title: 'GitHub 2FA', totp: { secret: SEED_B32 } });
  assert.equal(own.totp.secret, SEED_B32);
  const login = await a.put({ kind: 'login', title: 'GitHub', username: 'brad', password: 'p', totp: { secret: SEED_B32 } });
  assert.equal(login.totp.period, 30);
  assert.equal([...raw._map.values()].join('').includes(SEED_B32), false, 'the setup key is stored in the clear');
  await assert.rejects(a.put({ kind: 'totp', title: 'no key' }), /needs its setup key/);
  await assert.rejects(a.put({ kind: 'note', title: 'n', totp: { secret: SEED_B32 } }), /login or an authenticator/);
});

test('Steam: the same codes as steam-totp computes them (its algorithm, done here with node:crypto)', () => {
  /* steam-totp 2.1.2 generateAuthCode: HMAC-SHA1(secret, floor(t/30) as 8 bytes), dynamic
     truncation, then 5 characters of 23456789BCDFGHJKMNPQRTVWXY, dividing by 26 as a float */
  const raw = nodeCrypto.createHash('sha1').update('steam-test-secret').digest();
  const reference = (t) => {
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(0, 0);
    buf.writeUInt32BE(Math.floor(t / 30), 4);
    const h = nodeCrypto.createHmac('sha1', raw).update(buf).digest();
    const s = h[19] & 0x0f;
    let full = h.readUInt32BE(s) & 0x7fffffff;
    let code = '';
    for (let i = 0; i < 5; i += 1) {
      code += '23456789BCDFGHJKMNPQRTVWXY'.charAt(full % 26);
      full /= 26;
    }
    return code;
  };
  const b32 = (() => {
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (const byte of raw) bits += byte.toString(2).padStart(8, '0');
    return bits.match(/.{1,5}/g).map((g) => A[parseInt(g.padEnd(5, '0'), 2)]).join('');
  })();
  for (const t of [0, 59, 1_000_000_007, 1_700_000_000, 2_000_000_000]) {
    assert.equal(require('../src').totp.codeOf({ secret: b32, encoder: 'steam' }, t * 1000).code, reference(t), `at ${t}`);
  }
  /* the same secret as a .maFile holds it: shared_secret = base64 of the 20 bytes */
  const shared = raw.toString('base64');
  assert.match(shared, /^[A-Za-z0-9+/]{27}=$/);
  const { totp } = require('../src');
  assert.equal(totp.shapeTotp({ secret: shared, encoder: 'steam' }).secret, b32, 'base64 shared_secret -> the base32 kept');
  for (const t of [0, 1_700_000_000]) {
    assert.equal(totp.codeOf(totp.shapeTotp({ secret: shared, encoder: 'steam' }), t * 1000).code, reference(t), `base64 at ${t}`);
  }
  /* only Steam reads base64: the same text for an ordinary code is refused, not guessed */
  assert.throws(() => totp.shapeTotp({ secret: shared }), /not base32/);
});
