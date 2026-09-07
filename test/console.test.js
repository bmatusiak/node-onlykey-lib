/*
 * DeviceConsole - waiting on what the device says.
 *
 * The classic PIN flow has no replies to correlate: the device announces its
 * state by printing, and the host advances by matching text. That makes the
 * console a protocol component, so its edges are pinned here rather than only
 * exercised through the PIN sequence.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { DeviceConsole } = require('../src/device/console');
const pin = require('../src/device/pin');

test('a line that arrived BEFORE the wait still satisfies it', async () => {
  /*
   * The race this exists to close. The device can print between the write that
   * provoked it and the caller's wait, and a wait that only watched future
   * text would miss a line already in the buffer and then time out against a
   * device that answered correctly.
   *
   * Same hazard as writing before subscribing on the vendor interface, which
   * is why request() exists - here it is text rather than a report.
   */
  const console_ = new DeviceConsole();
  console_.push('Enter PIN\n');

  assert.match(await console_.waitFor(pin.PROMPTS.enter, { timeoutMs: 50 }), /Enter PIN/);
});

test('a line that arrives after the wait satisfies it too', async () => {
  const console_ = new DeviceConsole();
  const pending = console_.waitFor(pin.PROMPTS.storing, { timeoutMs: 500 });
  console_.push('Storing PIN\n');
  assert.match(await pending, /Storing PIN/);
});

test('clear() stops stale text from satisfying the next step', async () => {
  /*
   * The firmware prints the same words more than once in a bracket - "Enter
   * PIN" for the primary and again for the confirmation - so without clearing,
   * the next wait is satisfied instantly by the previous step's output and the
   * host runs ahead of the device.
   */
  const console_ = new DeviceConsole();
  console_.push('Enter PIN\n');
  console_.clear();

  await assert.rejects(
    () => console_.waitFor(pin.PROMPTS.enter, { timeoutMs: 40 }),
    /timed out/,
  );
});

test('a reject pattern fails the wait with the device its own words', async () => {
  const console_ = new DeviceConsole();
  const pending = console_.waitFor(pin.PROMPTS.storing, {
    reject: [pin.ERRORS.tooShort],
    timeoutMs: 500,
  });
  console_.push('Error PIN is not between 7 - 10 digits\n');

  await assert.rejects(() => pending, /Error PIN is not between 7 - 10 digits/);
});

test('a reject already in the buffer fails immediately', async () => {
  const console_ = new DeviceConsole();
  console_.push("Error PINs Don't Match\n");
  await assert.rejects(
    () => console_.waitFor(pin.PROMPTS.matched, {
      reject: [pin.ERRORS.mismatch],
      timeoutMs: 40,
    }),
    /PINs Don't Match/,
  );
});

test('waitForCount needs every occurrence, not the first', async () => {
  // One printed acknowledgement per digit. Returning on the first leaves the
  // rest of the burst in flight.
  const console_ = new DeviceConsole();
  const pending = console_.waitForCount(pin.DIGIT_ACK, 3, { timeoutMs: 500 });

  console_.push('password appended with 1\n');
  console_.push('password appended with 2\n');
  let settled = false;
  pending.then(() => { settled = true; });
  await new Promise((r) => setImmediate(r));
  assert.equal(settled, false, 'two of three is not enough');

  console_.push('password appended with 3\n');
  assert.equal(await pending, 3);
});

test('a timeout names what it was waiting for and shows the tail', async () => {
  // A bare "timed out" against a device that printed something unexpected is
  // very hard to diagnose from a phone.
  const console_ = new DeviceConsole();
  console_.push('Error something else entirely\n');

  const err = await console_.waitFor(pin.PROMPTS.matched, { timeoutMs: 30 }).catch((e) => e);
  assert.match(err.message, /Both PINs Match/, 'says what it wanted');
  assert.match(err.message, /something else entirely/, 'and what it got');
});

test('the buffer is capped, keeping the most recent text', async () => {
  // A long session must not grow without end, and it is the TAIL that matters:
  // the prompt being waited on is always the newest thing printed.
  const console_ = new DeviceConsole({ limit: 32 });
  console_.push('x'.repeat(100));
  console_.push('Enter PIN');

  assert.equal(console_.text.length, 32);
  assert.match(await console_.waitFor(pin.PROMPTS.enter, { timeoutMs: 50 }), /Enter PIN/);
});

test('detaching fails anything still waiting rather than leaving it hung', async () => {
  const console_ = new DeviceConsole();
  const pending = console_.waitFor(pin.PROMPTS.enter, { timeoutMs: 5000 });
  console_.detach();
  await assert.rejects(() => pending, /detached while waiting/);
});

test('attach is idempotent, so a second attach does not double-count', async () => {
  // Two subscriptions would append every line twice, and waitForCount would
  // then be satisfied by half the digits.
  let subscriptions = 0;
  const transport = {
    on() {
      subscriptions++;
      return () => { subscriptions--; };
    },
  };
  const console_ = new DeviceConsole();
  console_.attach(transport).attach(transport);
  assert.equal(subscriptions, 1);
  console_.detach();
  assert.equal(subscriptions, 0);
});
