'use strict';

/**
 * edge/src/agents.js - THE AGENT IDENTITIES, a certified list kept in the identity bucket (Brad, 2026-10-30: "a plural
 * multi identity section, like nametag, certified/signed/approved, named/labeled, so a agent can pick from a list, and
 * it can just create new ones"; "sync-able in edge, not in the blockchain but in the edge bucket"; "no rename for
 * agents, after certified"; "i dont want 2 agent ident with the same label"; a revocation archives, never deletes).
 *
 * Store `edge-agents` (`edge-agents-test`), one entry per label:
 *   {card: certify.record('agent', creation info, certification), certs: {gpg?: {armored, fingerprint, signPublic}},
 *    revoked?: certify.record('revoke', {label, created}, certification)}
 * Every entry is checked against the owner keys READ from the key (certify.verify) before it is listed as usable. Pure:
 * no storage and no key here - hosts read the store, hand it in, and write what this returns.
 *
 * Messages on the paired channel / the desktop host / the MCP (as EDGE_IDENTITY_SET/GET before them):
 *   {type: 'EDGE_AGENT_LIST', v: 1, nonce}                 -> {ok, agents: [{label, created, expires, kinds, status}]}
 *   {type: 'EDGE_AGENT_GET', v: 1, nonce, label}           -> {ok, agent: {card, certs}} - no label: refused, "pick one"
 *   {type: 'EDGE_AGENT_CREATE', v: 1, nonce, info}         -> the person approves; the key certifies (a press) -> {ok, agent}
 */
const { randomBytes } = require('../../src/vendor/exports/@noble/ciphers/utils.js');
const { toHex } = require('../../src/bytes');
const certify = require('./certify');
const grants = require('./grants');

const LIST_TYPE = 'EDGE_AGENT_LIST';
const GET_TYPE = 'EDGE_AGENT_GET';
const CREATE_TYPE = 'EDGE_AGENT_CREATE';
const TYPES = [LIST_TYPE, GET_TYPE, CREATE_TYPE];
const store = (net) => (net === 'test' ? 'edge-agents-test' : 'edge-agents');

/*
 * THE FIRST CARD FROM TODAY'S RECORD (edge/src/identity.js): the same labels and the certificate's own created time, so
 * the derived gpg key and its fingerprint stay what GitHub already verifies - a new card, not a new key.
 */
function infoFromRecord(record, label) {
  return certify.agentCard({
    label, created: record.cert.created, expires: record.expires,
    derive: { ssh: record.ssh, gpg: record.gpgUid }, committer: record.committer || null,
  });
}
function certsFromRecord(record) {
  return { gpg: { armored: record.cert.armored, fingerprint: record.cert.fingerprint.toUpperCase(), signPublic: record.cert.signPublic.toLowerCase() } };
}

/**
 * The list as a host shows it: each entry checked. status: 'usable' | 'expired' | 'revoked' | 'unverified' (not this
 * owner's, or malformed - never given to an agent).
 * @param {Object<string, string>} entries the store's live keys -> values (JSON)
 * @param {Uint8Array} ownerKey @param {Uint8Array} ownerKeyPq read from the key
 * @param {number} [now] seconds
 */
function list(entries, ownerKey, ownerKeyPq, now = Math.floor(Date.now() / 1000)) {
  const out = [];
  for (const [label, text] of Object.entries(entries || {})) {
    let e;
    try { e = JSON.parse(text); } catch (_) { continue; }
    const card = e && e.card;
    const ok = card && card.kind === 'agent' && card.thing && card.thing.label === label && certify.verify(card, ownerKey, ownerKeyPq);
    let status = ok ? 'usable' : 'unverified';
    if (ok && e.revoked && e.revoked.thing && e.revoked.thing.label === label && e.revoked.thing.created === card.thing.created
      && certify.verify(e.revoked, ownerKey, ownerKeyPq)) status = 'revoked';
    else if (ok && card.thing.expires && card.thing.created + card.thing.expires <= now) status = 'expired';
    out.push({
      label, status, created: card && card.thing ? card.thing.created : null, expires: card && card.thing ? card.thing.expires : null,
      kinds: card && card.thing && card.thing.derive ? Object.keys(card.thing.derive) : [], entry: e,
    });
  }
  return out.sort((a, b) => a.label.localeCompare(b.label));
}

/** One usable identity by label -> {card, certs}; throws naming why not (missing, revoked, expired, unverified). */
function pick(entries, label, ownerKey, ownerKeyPq, now) {
  if (!label) throw Object.assign(new Error('edge: pick an agent identity by its label'), { code: 'EAGENT_PICK' });
  const it = list(entries, ownerKey, ownerKeyPq, now).find((x) => x.label === label);
  if (!it) throw Object.assign(new Error(`edge: no agent identity "${label}"`), { code: 'EAGENT_NONE' });
  if (it.status !== 'usable') throw Object.assign(new Error(`edge: the agent identity "${label}" is ${it.status}`), { code: 'EAGENT_UNUSABLE' });
  return { card: it.entry.card, certs: it.entry.certs || {} };
}

/** A label already taken (any status - a revoked one stays taken): creating it again is refused. */
function taken(entries, label) {
  return Object.prototype.hasOwnProperty.call(entries || {}, String(label).trim());
}

/*
 * MAY THIS BUDGET OPEN UNDER THIS AGENT CARD? Every scope on a derived code names one of the card's derivation labels
 * (ssh://user@host, or gpg://<user id>) - the agent's keys are derived from exactly those. The hosts enforce it; the key,
 * later (certify.keyEnforces).
 */
function budgetAllowed(card, scopes) {
  let info;
  try { info = certify.agentCard(card && card.thing); } catch (e) { return { ok: false, why: e.message }; }
  const names = [info.derive.ssh, info.derive.gpg !== undefined ? `gpg://${info.derive.gpg}` : undefined].filter(Boolean);
  for (const s of scopes || []) {
    if (!names.includes(String(s.identity || ''))) return { ok: false, why: `scope on slot ${s.slot} names "${s.identity || 'no identity'}", not this card's` };
  }
  return { ok: true };
}

/* the messages */
const isHex = (s, n) => typeof s === 'string' && s.length === n * 2 && /^[0-9a-f]+$/i.test(s);
function buildList({ nonce = randomBytes(16) } = {}) { return { type: LIST_TYPE, v: 1, nonce: toHex(nonce) }; }
function buildGet({ label, nonce = randomBytes(16) }) { return { type: GET_TYPE, v: 1, nonce: toHex(nonce), label: String(label || '') }; }
function buildCreate({ info, nonce = randomBytes(16) }) { return { type: CREATE_TYPE, v: 1, nonce: toHex(nonce), info: certify.agentCard(info) }; }
function verify(msg, { seen } = {}) {
  if (!msg || !TYPES.includes(msg.type) || msg.v !== 1 || !isHex(msg.nonce, 16)) return { ok: false, reason: 'malformed' };
  if (msg.type === CREATE_TYPE) { try { certify.agentCard(msg.info); } catch (e) { return { ok: false, reason: e.message }; } }
  if (seen && seen.has(msg.nonce.toLowerCase())) return { ok: false, reason: 'replayed' };
  return { ok: true };
}
/* the subjects an agent card's scopes name, as budgets stage them (grants.identityLabel) */
const scopeLabels = (card) => budgetNames(card).map((n) => grants.identityLabel(n));
function budgetNames(card) {
  const d = (card && card.thing && card.thing.derive) || {};
  return [d.ssh, d.gpg !== undefined ? `gpg://${d.gpg}` : undefined].filter(Boolean);
}

module.exports = {
  LIST_TYPE, GET_TYPE, CREATE_TYPE, TYPES, store, infoFromRecord, certsFromRecord, list, pick, taken, budgetAllowed,
  budgetNames, scopeLabels, buildList, buildGet, buildCreate, verify,
};
