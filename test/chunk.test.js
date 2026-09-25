/*
 * Each test here reproduces a specific failure that was measured against real
 * hardware. They are not "does the happy path work" tests - the happy path was
 * never the problem. Every one of these bugs presented as something other than
 * its own cause.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const chunk = require('../src/protocol/chunk');
const ctap = require('../src/protocol/ctap');
const { fromLatin1 } = require('../src/bytes');

const ok = (data) => ({ status: 'CTAP1_SUCCESS', code: 0, data, error: null, count: null });
const pending = (data) => ({
  status: 'CTAP2_ERR_USER_ACTION_PENDING', code: 0x23, data, error: null, count: null,
});
const withError = (error) => ({
  status: 'CTAP1_SUCCESS', code: 0, data: null, error, count: null,
});

/* ---- request chunking --------------------------------------------------- */

test('a payload is split at 228 bytes with the final flag on the last chunk', async () => {
  const sent = [];
  await chunk.sendChunked({
    cmd: 0xed,
    slot: 2,
    payload: new Uint8Array(500),
    send: async (m) => { sent.push(m); return ok(null); },
  });
  assert.equal(sent.length, 3, '500 bytes is 228 + 228 + 44');
  assert.deepEqual(sent.map((m) => m.data.length), [228, 228, 44]);
  assert.deepEqual(sent.map((m) => m.opt2), [0, 0, 1], 'only the last is final');
});

test('an exactly-228-byte payload is one final chunk', async () => {
  const sent = [];
  await chunk.sendChunked({
    cmd: 0xed,
    payload: new Uint8Array(228),
    send: async (m) => { sent.push(m); return ok(null); },
  });
  assert.equal(sent.length, 1);
  assert.equal(sent[0].opt2, 1);
});

test('an empty payload still sends one final chunk', async () => {
  // The device needs opt2 to prime the challenge; a loop that never runs
  // leaves it waiting forever.
  const sent = [];
  await chunk.sendChunked({
    cmd: 0xed,
    payload: new Uint8Array(0),
    send: async (m) => { sent.push(m); return ok(null); },
  });
  assert.equal(sent.length, 1);
  assert.equal(sent[0].opt2, 1);
});

test('packetnum is monotonic ACROSS operations, never reset', async () => {
  // The bug this prevents: onlykey-pgp.js:250 resets to 0 on the final packet.
  // The firmware drops opt3 <= its high-water mark SILENTLY and clears that
  // mark only on a 5s timer, so a second operation inside that window loses
  // its first chunks and fails much later as "incorrect challenge".
  chunk._resetPacketCounter(0);
  const seen = [];
  const send = async (m) => { seen.push(m.opt3); return ok(null); };

  await chunk.sendChunked({ cmd: 0xed, payload: new Uint8Array(300), send });
  await chunk.sendChunked({ cmd: 0xf0, payload: new Uint8Array(100), send });

  assert.deepEqual(seen, [1, 2, 3], 'the second operation continues the sequence');
  for (let i = 1; i < seen.length; i++) {
    assert.ok(seen[i] > seen[i - 1], 'opt3 must strictly increase');
  }
});

test('packetnum wraps to 1, not 0, because 0 means unset to the firmware', () => {
  chunk._resetPacketCounter(254);
  assert.equal(chunk.nextPacketNum(), 255);
  assert.equal(chunk.nextPacketNum(), 1, 'wrapping to 0 would read as unset');
});

test('chunks are sealed individually when a seal is supplied', async () => {
  const sent = [];
  await chunk.sendChunked({
    cmd: 0xed,
    payload: new Uint8Array(300).fill(0xaa),
    seal: (c) => c.map((b) => b ^ 0xff),
    send: async (m) => { sent.push(m); return ok(null); },
  });
  assert.equal(sent[0].data[0], 0x55, 'each chunk is sealed on its own');
});

/* ---- response polling --------------------------------------------------- */

test('a non-SUCCESS payload is refused even though it looks like data', async () => {
  // THE measured bug: a poll during the button challenge is answered
  // USER_ACTION_PENDING carrying 71 bytes of uninitialised firmware stack. An
  // implementation that classifies by content accepts it as the answer.
  const stack = new Uint8Array(71).fill(0x41);
  let polls = 0;
  const result = await chunk.pollForResponse({
    expected: 64,
    intervalMs: 1,
    poll: async () => {
      polls += 1;
      return polls < 3 ? pending(stack) : ok(new Uint8Array(64).fill(7));
    },
  });
  assert.equal(result.data.length, 64);
  assert.ok(result.data.every((b) => b === 7), 'the stack garbage was not accepted');
});

test('a short chunk that is not the tail is discarded, not reassembled', async () => {
  // Measured: the device advanced its cursor a full 512 while shipping only 71
  // bytes per assertion. The result was real bytes in the wrong places, which
  // no length check would catch - only a shape check.
  let polls = 0;
  const result = await chunk.pollForResponse({
    expected: 1024,
    intervalMs: 1,
    poll: async () => {
      polls += 1;
      if (polls === 1) return ok(new Uint8Array(512).fill(1));
      if (polls === 2) return ok(new Uint8Array(71).fill(0xff));
      return ok(new Uint8Array(512).fill(2));
    },
  });
  assert.equal(result.data.length, 1024);
  assert.equal(result.data[600], 2, 'the 71-byte chunk was rejected');
});

test('an incorrect-challenge error is transient, not terminal', async () => {
  // It is emitted in the legitimate window between the last digit being
  // consumed and the result being computed. Treating it as terminal aborts an
  // operation that was about to succeed.
  let polls = 0;
  const result = await chunk.pollForResponse({
    expected: 32,
    intervalMs: 1,
    poll: async () => {
      polls += 1;
      if (polls < 3) return withError('Error incorrect challenge was entered');
      return ok(new Uint8Array(32).fill(9));
    },
  });
  assert.equal(result.data.length, 32);
});

test('a confirmation timeout IS terminal', async () => {
  await assert.rejects(
    chunk.pollForResponse({
      expected: 32,
      intervalMs: 1,
      poll: async () => withError('Error Timeout occured while waiting for confirmation'),
    }),
    /Timeout occur/,
  );
});

test('from 3.0.5 an incorrect challenge ends the poll instead of spending the budget', async () => {
  // Same reply as the transient test above; only the flag differs. On 3.0.5
  // the string means nothing is staged and nothing will be.
  let polls = 0;
  await assert.rejects(
    chunk.pollForResponse({
      expected: 32,
      intervalMs: 1,
      challengeErrorIsFinal: true,
      poll: async () => {
        polls += 1;
        if (polls < 3) return withError('Error incorrect challenge was entered');
        return ok(new Uint8Array(32).fill(9));
      },
    }),
    (err) => err.kind === 'challenge',
  );
  assert.equal(polls, 1, 'polled on past a final answer');
});

test('a FIDO2-path device error carries the same kind as a vendor one', async () => {
  // One lib, both transports: a GUI switching on err.kind must not have to
  // know which interface the operation happened to use.
  await assert.rejects(
    chunk.pollForResponse({
      expected: 32,
      intervalMs: 1,
      poll: async () => withError('Error confirmation window closed before the button was pressed'),
    }),
    (err) => err.kind === 'confirmationClosed'
      && err.deviceText === 'Error confirmation window closed before the button was pressed'
      && err.message === err.deviceText,
  );
});

test('the no-progress budget is re-armed by each chunk, not by total time', async () => {
  // A 3309-byte ML-DSA signature needs ~52 ceremonies; a total cap stops a
  // healthy operation part-way. This run exceeds the budget in total elapsed
  // time while never actually stalling.
  let polls = 0;
  const result = await chunk.pollForResponse({
    expected: 1536,
    intervalMs: 1,
    noProgressBudgetMs: 60,
    poll: async () => {
      polls += 1;
      await new Promise((r) => { setTimeout(r, 40); });
      return ok(new Uint8Array(512).fill(polls));
    },
  });
  assert.equal(result.data.length, 1536, 'steady progress must not time out');
});

test('a genuine stall inside the budget does fail', async () => {
  await assert.rejects(
    chunk.pollForResponse({
      expected: 512,
      intervalMs: 5,
      noProgressBudgetMs: 40,
      poll: async () => pending(null),
    }),
    /no-progress budget/,
  );
});

test('the response is opened ONCE over the concatenation', async () => {
  // The box is one keystream from offset 0. Opening per chunk restarts it and
  // corrupts everything past the first chunk.
  const opens = [];
  let polls = 0;
  await chunk.pollForResponse({
    expected: 1024,
    intervalMs: 1,
    open: (whole) => { opens.push(whole.length); return whole; },
    poll: async () => {
      polls += 1;
      return ok(new Uint8Array(512).fill(polls));
    },
  });
  assert.deepEqual(opens, [1024], 'opened once, over the whole thing');
});

test('an ASCII status message is returned rather than treated as data', async () => {
  const result = await chunk.pollForResponse({
    intervalMs: 1,
    poll: async () => ok(fromLatin1('UNLOCKEDv3.0.4')),
  });
  assert.equal(result.message, 'UNLOCKEDv3.0.4');
  assert.equal(result.data, null);
});

/* ---- the tunnel keyhandle ----------------------------------------------- */

test('the keyhandle carries the real length, not the padded size', () => {
  const kh = ctap.encodeRequest({ cmd: 0xed, opt1: 2, opt2: 1, opt3: 7, data: [1, 2, 3] });
  assert.equal(kh.length, 26, '10 header + 16 minimum data');
  assert.deepEqual(Array.from(kh.subarray(0, 4)), [0xed, 2, 1, 7]);
  assert.deepEqual(Array.from(kh.subarray(4, 8)), ctap.MAGIC);
  assert.equal(kh[9], 3, 'the REAL payload length');
  assert.deepEqual(Array.from(kh.subarray(10, 13)), [1, 2, 3]);
});

test('an oversized keyhandle is rejected with a pointer to chunking', () => {
  assert.throws(
    () => ctap.encodeRequest({ cmd: 1, data: new Uint8Array(246) }),
    /Chunk the request/,
  );
});

test('decodeAssertion tolerates a signature that is only a status byte', () => {
  // Dereferencing this unguarded is how the shipped client stranded its
  // promise, leaving a WebAuthn prompt on screen forever.
  const out = ctap.decodeAssertion(new Map([[3, Uint8Array.from([0x23])]]));
  assert.equal(out.status, 'CTAP2_ERR_USER_ACTION_PENDING');
  assert.equal(out.data, null);
});

test('the status table names the codes polling depends on', () => {
  assert.equal(ctap.STATUS[0x00], 'CTAP1_SUCCESS');
  assert.equal(ctap.STATUS[0x23], 'CTAP2_ERR_USER_ACTION_PENDING');
  assert.equal(ctap.STATUS[0x24], 'CTAP2_ERR_OPERATION_PENDING');
  assert.equal(ctap.STATUS[0x18], 'CTAP2_ERR_EXTENSION_NOT_SUPPORTED');
  assert.equal(ctap.statusName(0x99), '0x99', 'unknown codes degrade readably');
});

test('a device error string is extracted from the signature', () => {
  const text = fromLatin1('Error not in config mode ');
  const sig = new Uint8Array(1 + text.length);
  sig.set([0x00], 0);
  sig.set(text, 1);
  const out = ctap.decodeAssertion(new Map([[3, sig]]));
  assert.equal(out.error, 'Error not in config mode');
});
