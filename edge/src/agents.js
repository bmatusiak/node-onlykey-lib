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
/*
 * certs: the public certificates made from the card (today the gpg one, made on the key by the computer that asks -
 * edge setup), travelling beside it: {gpg: {armored, fingerprint, signPublic}}. A card naming a gpg user ID needs it.
 */
function buildCreate({ info, certs = {}, nonce = randomBytes(16) }) {
  return { type: CREATE_TYPE, v: 1, nonce: toHex(nonce), info: certify.agentCard(info), certs: cleanCerts(certs) };
}
function cleanCerts(certs) {
  const g = certs && certs.gpg;
  if (!g) return {};
  if (typeof g.armored !== 'string' || !/^[0-9A-Fa-f]{40}$/.test(String(g.fingerprint || '')) || !/^[0-9a-fA-F]{64}$/.test(String(g.signPublic || ''))) {
    throw new TypeError('agents: certs.gpg is {armored, fingerprint (40 hex), signPublic (64 hex)}');
  }
  return { gpg: { armored: g.armored, fingerprint: g.fingerprint.toUpperCase(), signPublic: g.signPublic.toLowerCase() } };
}
function verify(msg, { seen } = {}) {
  if (!msg || !TYPES.includes(msg.type) || msg.v !== 1 || !isHex(msg.nonce, 16)) return { ok: false, reason: 'malformed' };
  if (msg.type === CREATE_TYPE) {
    let info;
    try { info = certify.agentCard(msg.info); cleanCerts(msg.certs); } catch (e) { return { ok: false, reason: e.message }; }
    if (info.derive.gpg !== undefined && !(msg.certs && msg.certs.gpg)) return { ok: false, reason: 'a card naming a gpg user ID comes with its gpg certificate' };
  }
  if (seen && seen.has(msg.nonce.toLowerCase())) return { ok: false, reason: 'replayed' };
  return { ok: true };
}
/* the subjects an agent card's scopes name, as budgets stage them (grants.identityLabel) */
const scopeLabels = (card) => budgetNames(card).map((n) => grants.identityLabel(n));
function budgetNames(card) {
  const d = (card && card.thing && card.thing.derive) || {};
  return [d.ssh, d.gpg !== undefined ? `gpg://${d.gpg}` : undefined].filter(Boolean);
}

/*
 * A CARD IN THE SHAPE THE CLI SIGNS WITH (its ssh agent, gpg shim and committer - edge/cli, the record `edge setup` once
 * kept): the derivation labels, the committer and the gpg certificate, read from the certified card and the certificate
 * beside it. The card's created time is the certificate's, so the gpg key it derives is the one the certificate names.
 */
function recordFromCard(card, certs = {}) {
  const t = certify.agentCard(card && card.thing);
  const g = certs && certs.gpg;
  return {
    ...(t.derive.ssh ? { ssh: t.derive.ssh } : {}),
    ...(t.derive.gpg !== undefined ? { gpgUid: t.derive.gpg } : {}),
    committer: t.committer,
    expires: t.expires,
    ...(g ? { cert: { armored: g.armored, fingerprint: g.fingerprint, created: t.created, expires: t.expires, signPublic: g.signPublic } } : {}),
    label: t.label,
  };
}

/*
 * THE HOST'S ANSWERS, ONE FOR EVERY HOST (the desktop app, the phone, the web app, this computer for a key on USB - Brad,
 * 2026-11-03: "the ai agent creates the card over cli/mcp, providing the label it wants, the keys it wants to use for
 * future budgets"): LIST and GET from the store, checked against the owner keys read from the key; CREATE shown to the
 * person (approve), then certified by the key at a press and written beside the chain. Pure - the host hands in its store,
 * its owner keys, its sheet and its key:
 *   entries()          the store's live entries (label -> JSON), or null when no bucket is open
 *   owner()            {ownerKey, ownerKeyPq} read from the key, or null
 *   approve(ask)       ask = {label, derive, committer, expires, fingerprint} -> true when the person approves
 *   certifyAgent(info) the key's certify at a press -> the card record
 *   write(label, entry)
 *   now                seconds (tests); else the clock
 * -> the answer to send back.
 */
async function answer(msg, { entries, owner, approve, certifyAgent, write, now }) {
  const e = await entries();
  if (!e) return { ok: false, refusal: 'invalid', detail: 'no identity bucket is open on this device - log in first' };
  if (msg.type === LIST_TYPE || msg.type === GET_TYPE) {
    const o = await owner();
    if (!o) return { ok: false, refusal: 'invalid', detail: "the key's owner keys could not be read - is it unlocked?" };
    if (msg.type === LIST_TYPE) {
      return { ok: true, agents: list(e, o.ownerKey, o.ownerKeyPq, now).map(({ label, status, created, expires, kinds }) => ({ label, status, created, expires, kinds })) };
    }
    try {
      return { ok: true, agent: pick(e, msg.label, o.ownerKey, o.ownerKeyPq, now) };
    } catch (err) {
      return { ok: false, refusal: 'invalid', detail: err.message };
    }
  }
  const info = certify.agentCard(msg.info);
  if (taken(e, info.label)) return { ok: false, refusal: 'invalid', detail: `"${info.label}" is already an agent identity's label (a revoked one stays taken)` };
  const certs = cleanCerts(msg.certs);
  const yes = await approve({ label: info.label, derive: info.derive, committer: info.committer, expires: info.expires, fingerprint: certs.gpg ? certs.gpg.fingerprint : null });
  if (!yes) return { ok: false, refusal: 'declined' };
  const card = await certifyAgent(info);
  await write(info.label, { card, certs });
  return { ok: true, agent: { label: info.label, created: info.created, expires: info.expires, kinds: Object.keys(info.derive) } };
}

module.exports = {
  LIST_TYPE, GET_TYPE, CREATE_TYPE, TYPES, store, infoFromRecord, certsFromRecord, list, pick, taken, budgetAllowed,
  budgetNames, scopeLabels, buildList, buildGet, buildCreate, verify, recordFromCard, answer,
};
