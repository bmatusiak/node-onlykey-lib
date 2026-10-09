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

/*
 * FULL CARDS FOR YOUR OTHER DEVICES (Brad, 2026-10-09: "full cards, i want to see them in the
 * budget history list"). A budget's words - reason, scopes with identity names, lifetime - live
 * only on the phone that opened it; the chain holds their hash (the grant-create subject). An
 * OPENING travels with that device's log, and is kept only when grants.verifyBudgetOpening
 * proves it against the log itself: the grant-create link, the head before it, and the key's
 * checkpoint signature from the press. Words that were made up do not match the subject.
 *
 *   opening: {grantId, reason, scopes: [{op, slot, cap, identity?}], uses, lifetime, genesis
 *             (hex), signature (hex), opened? (ms, the opening phone's clock), from? (who asked)}
 * -> the openings that check, as given (unknown fields dropped)
 */
function checkOpenings({ deviceId, publicKey, records, openings }) {
  const chainLib = require('./chain');
  const grants = require('./grants');
  const receipts = require('./receipts');
  const { fromHex } = require('../../src/bytes');
  const id = Uint8Array.from(deviceId);
  const pub = Uint8Array.from(publicKey);
  const bySeq = new Map(records.map((r) => [chainLib.decodeLink(r.link).seq, r]));
  const out = [];
  for (const o of Array.isArray(openings) ? openings : []) {
    try {
      if (!o || !Number.isInteger(o.grantId) || typeof o.reason !== 'string' || o.reason.length > 4096 || !Array.isArray(o.scopes)
        || o.scopes.length < 1 || o.scopes.length > 4 || !Number.isInteger(o.uses)) continue;
      const scopes = o.scopes.map((s) => ({ op: s.op, slot: s.slot, cap: s.cap, ...(s.identity ? { identity: String(s.identity) } : {}) }));
      const open = records.map((r) => chainLib.decodeLink(r.link)).find((f) => f.op === require('./codes').OP.GRANT_CREATE && f.grantId === o.grantId);
      if (!open) continue;
      const link = bySeq.get(open.seq);
      const prevHead = open.seq === 0 ? chainLib.genesis(id) : bySeq.get(open.seq - 1) && bySeq.get(open.seq - 1).head;
      if (!prevHead) continue;
      const v = grants.verifyBudgetOpening({
        deviceId: id, publicKey: pub, link: link.link, prevHead, head: link.head, signature: fromHex(String(o.signature)),
        scopes, reasonHash: receipts.messageHash(o.reason), genesis: fromHex(String(o.genesis)), uses: o.uses, lifetime: o.lifetime || 0,
      });
      if (!v.ok) continue;
      out.push({
        grantId: o.grantId, reason: o.reason, scopes, uses: o.uses, lifetime: o.lifetime || 0, genesis: String(o.genesis).toLowerCase(),
        signature: String(o.signature).toLowerCase(), ...(Number.isFinite(o.opened) ? { opened: o.opened } : {}), ...(typeof o.from === 'string' ? { from: o.from.slice(0, 64) } : {}),
      });
    } catch { /* not an opening of this log */ }
  }
  return out;
}

/*
 * A DEVICE'S NOTES, as they travel with its log (Brad, 2026-10-09: "all the data i see on the a13
 * should be just like on the pixel"): the intent each use was for and each receipt's message, by
 * seq - the words the chain holds only as hashes (the intent welded into the use's link, the
 * message hash in the receipt link). Every screen checks them against those hashes when it draws
 * them, so here they are only bounded and shaped: {reasons: {seq: text}, messages: {seq: text}}.
 */
function shapeNotes(notes) {
  const out = { reasons: {}, messages: {}, seen: {} };
  if (!notes || typeof notes !== 'object') return out;
  for (const [kind, max] of [['reasons', 280], ['messages', 1024]]) {
    const src = notes[kind] && typeof notes[kind] === 'object' ? notes[kind] : {};
    for (const [k, v] of Object.entries(src).slice(-2000)) {
      const seq = Number(k);
      if (Number.isInteger(seq) && seq >= 0 && typeof v === 'string' && v.length <= max) out[kind][seq] = v;
    }
  }
  /* when that device first stored each link (ITS clock - links carry no time), so its log reads the same everywhere */
  const seen = notes.seen && typeof notes.seen === 'object' ? notes.seen : {};
  for (const [k, v] of Object.entries(seen).slice(-2000)) {
    const seq = Number(k);
    if (Number.isInteger(seq) && seq >= 0 && Number.isFinite(v) && v > 0) out.seen[seq] = v;
  }
  return out;
}

/*
 * A LOG IS COMPLETE BEFORE IT ENTERS ANOTHER DATA STORE (Brad, 2026-10-09: "dont use shortcut to
 * validate syncd data, before mergering into another data store"; "a data store must contain all
 * info about the usage of the credental, including the result"). Every use of the credential,
 * checked against the chain itself - nothing taken on the sender's word:
 *   - every budget opened in the log: its opening words, proved (checkOpenings);
 *   - every use that carries an intent: the intent's words, matching the hash welded into its link;
 *   - every use that owes a result: its RESULT - a receipt whose message matches the receipt's
 *     hash, or a waive. A use still waiting, missing its receipt, or with a receipt alarm is not
 *     complete yet.
 * -> {ok: true} | {ok: false, missing: [why, ...]} (at most 20 reasons)
 */
function completeness({ deviceId, publicKey, records, openings, notes }) {
  const chainLib = require('./chain');
  const grants = require('./grants');
  const receipts = require('./receipts');
  const { OP } = require('./codes');
  const { toHex: hex } = require('../../src/bytes');
  const shaped = shapeNotes(notes);
  const missing = [];
  const decoded = records.map((r) => ({ r, f: chainLib.decodeLink(r.link) }));
  const proved = new Set(checkOpenings({ deviceId, publicKey, records, openings }).map((o) => o.grantId));
  for (const { f } of decoded) {
    if (f.op === OP.GRANT_CREATE && !proved.has(f.grantId)) missing.push(`budget ${f.grantId}: its opening words did not arrive or do not match #${f.seq}`);
  }
  for (const { f } of decoded) {
    const intent = f.intent instanceof Uint8Array && f.intent.some((b) => b !== 0) ? f.intent : null;
    if (!intent) continue;
    const text = shaped.reasons[f.seq];
    if (text === undefined) missing.push(`#${f.seq}: its intent did not arrive`);
    else if (hex(grants.intentOf(text)) !== hex(intent)) missing.push(`#${f.seq}: its intent does not match the chain`);
  }
  const paired = receipts.pairReceipts(records.map((r) => ({ link: r.link, head: r.head })), shaped.messages);
  for (const u of paired.uses) {
    if (u.status === 'no-receipt-owed') continue;
    if (u.status === 'waived' || u.status === 'waived-unlisted') continue;
    if (u.status !== 'receipted') { missing.push(`#${u.seq}: no result (${u.status})`); continue; }
    if (u.message === null || u.message === undefined) missing.push(`#${u.seq}: the message of receipt #${u.receipt.seq} ${u.messageStatus === 'mismatch' ? 'does not match the chain' : 'did not arrive'}`);
  }
  for (const o of paired.orphans) missing.push(`#${o.seq}: a receipt that answers no use (${o.reason})`);
  return missing.length ? { ok: false, missing: missing.slice(0, 20) } : { ok: true };
}

module.exports = { classify, nametagOf, remember, statementsOf, checkOpenings, shapeNotes, completeness };
