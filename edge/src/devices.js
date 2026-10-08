'use strict';

/**
 * YOUR DEVICES AND THE LOGS THEY OFFER (Brad, 2026-10-08) - the lib's side, no I/O, so the
 * phone and the computer sort a log the same way.
 *
 *   "pairing and sync is all app stuff, not firmware"
 *   "if it has the private ecc key to sign the block, then i want the log"
 *   "lets say we make a hardkey with the backup, and the log gets created on the computer"
 *   "we should hold these blocks in the app until approved and merged"
 *   a device gives "its own name for its device fingerprint in the block" - its NAMETAG -
 *   and "find a way to fix multi names for the same device".
 *
 * A LOG is another device's chain as offered: its links up to its key's signed checkpoint,
 * and its latest owner STATEMENT (grants.verifyStatement): device id + checkpoint key + seq +
 * nametag, signed with the owner key every device made from the same backup shares. Every
 * log offered is KEPT; this module only says what it is:
 *
 *   mine-known  the owner signature verifies and the fingerprint is already one of yours
 *   mine-new    the owner signature verifies, the fingerprint is new: "A device made with your
 *               OnlyKey appeared - is it yours?" (yes: a hard key restored from the backup,
 *               say; no: someone else holds your OnlyKey secret - a LEAK)
 *   forged      not signed by your owner key, or the statement does not name the key that
 *               signed the chain: never merged, kept as evidence against the computer that
 *               sent it
 *
 * Separately, `check` is the chain itself under that device's own checkpoint key
 * (sync.anchorCheck): ok, or an alarm (bad-checkpoint, rollback, changed, tampered).
 */
const { toHex } = require('../../src/bytes');
const chain = require('./chain');
const grants = require('./grants');
const sync = require('./sync');

const hex = (b) => toHex(Uint8Array.from(b));

/**
 * The nametag a device goes by, from every statement of its own seen so far: the one with
 * the highest seq names it; the others are its history ("previously"). A statement that
 * does not verify under `ownerKey` is not counted. -> {nametag, seq, previously: [nametag]} | null
 */
function nametagOf(statements, ownerKey) {
  const good = (statements || []).filter((s) => grants.verifyStatement(s, ownerKey));
  if (!good.length) return null;
  const order = (s) => (s.seq === null || s.seq === undefined ? -1 : s.seq);
  const sorted = [...good].sort((a, b) => order(b) - order(a));
  const previously = [];
  for (const s of sorted.slice(1)) if (s.nametag !== sorted[0].nametag && !previously.includes(s.nametag)) previously.push(s.nametag);
  return { nametag: sorted[0].nametag, seq: sorted[0].seq ?? null, previously };
}

/**
 * Sort one offered log.
 * @param {object} o
 * @param {{deviceId, publicKey, records, checkpoint, statement}} o.log
 *   records: [{link, head, reveal?}] of that device's chain; checkpoint: {seq, head, signature}
 *   from its key; statement: {deviceId, publicKey, seq, nametag, signature}
 * @param {Uint8Array} o.ownerKey   THIS device's own owner public key (X||Y)
 * @param {Array<{deviceId: string}>} [o.known]  your devices (deviceId hex)
 * @param {Array<{seq, head}>} [o.merged]  the points of that chain this device merged before
 * -> {class, deviceId (hex), nametag, check}
 */
function classify({ log, ownerKey, known = [], merged = [] }) {
  const id = hex(log.deviceId);
  const st = log.statement || null;
  const names = st && hex(st.deviceId) === id && hex(st.publicKey) === hex(log.publicKey) && hex(chain.deviceIdOf(Uint8Array.from(log.publicKey))) === id;
  const owned = Boolean(names && grants.verifyStatement(st, ownerKey));
  const check = sync.anchorCheck({ records: log.records || [], publicKey: Uint8Array.from(log.publicKey), checkpoint: log.checkpoint, anchors: merged });
  let kind = 'forged';
  if (owned) kind = known.some((k) => String(k.deviceId).toLowerCase() === id) ? 'mine-known' : 'mine-new';
  return { class: kind, deviceId: id, nametag: owned ? st.nametag : null, check };
}

/**
 * Your devices list after a statement of one of them (yes to "is it yours?", or a newer
 * statement of a known one): one entry per fingerprint, its nametag history kept.
 * -> a new list; `devices` is not changed
 */
function remember(devices, statement, { at = Date.now() } = {}) {
  const id = hex(statement.deviceId);
  const entry = { seq: statement.seq ?? null, nametag: statement.nametag, signature: hex(statement.signature) };
  const out = (devices || []).map((d) => ({ ...d, statements: [...(d.statements || [])] }));
  let d = out.find((x) => x.deviceId === id);
  if (!d) {
    d = { deviceId: id, publicKey: hex(statement.publicKey), since: at, statements: [] };
    out.push(d);
  }
  if (!d.statements.some((s) => s.signature === entry.signature)) d.statements.push(entry);
  return out;
}

/** A device's stored statements as verifyStatement takes them. */
function statementsOf(device) {
  const { fromHex } = require('../../src/bytes');
  return (device.statements || []).map((s) => ({
    deviceId: fromHex(device.deviceId), publicKey: fromHex(device.publicKey), seq: s.seq, nametag: s.nametag, signature: fromHex(s.signature),
  }));
}

module.exports = { classify, nametagOf, remember, statementsOf };
