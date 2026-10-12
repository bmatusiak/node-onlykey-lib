'use strict';

/**
 * REFRESH (GUEST-BOOK-SPEC.md, "Key discovery sources" and the pinning rule): every source of
 * every key, fetched again by its exact handle, one at a time.
 *
 * Per source the result is written on the source (lastChecked, lastResult); the pinned key itself
 * changes only by a merge of the SAME key (merge.js). A different key is held on the key as
 * `pending` for the person - and when two sources serve two different keys, both wait there, as a
 * conflict, never merged. A source that stops serving the key marks it `missing`; a network or
 * server failure marks it `error`; neither touches the key, which stays usable.
 *
 * A body carrying a PRIVATE key is refused like any other way in (formats.js): `error`, nothing kept.
 */

const formats = require('./formats');
const { classify } = require('./merge');
const { fetchSource, FETCHABLE } = require('./sources');

const HISTORY_MAX = 20;

/**
 * One contact refreshed. Pure apart from fetchFn: returns the new contact (the caller saves it).
 * @param {object} contact
 * @param {{fetchFn: Function, openpgp?: any, now?: () => Date}} deps
 * @returns {Promise<{contact: object, changes: string[]}>}
 */
async function refreshContact(contact, { fetchFn, openpgp, now = () => new Date() }) {
  const at = now().toISOString();
  const changes = [];
  const keys = [];
  for (const key of contact.keys) {
    let next = { ...key, sources: key.sources.map((s) => ({ ...s })) };
    const candidates = [];
    for (const source of next.sources) {
      if (!FETCHABLE.includes(source.kind)) continue;
      source.lastChecked = at;
      const got = await fetchSource(source, fetchFn);
      if (got.status !== 'ok') {
        source.lastResult = got.status;
        continue;
      }
      let found;
      try {
        found = (await formats.detectAll(got.body, { openpgp })).found;
      } catch (e) {
        source.lastResult = 'error';
        continue;
      }
      const sameFormat = found.filter((f) => f.format === next.format);
      const same = sameFormat.find((f) => f.fingerprint === next.fingerprint);
      if (same) {
        const r = await classify(next, same, { openpgp });
        source.lastResult = r.result === 'same' ? 'same' : 'updated';
        if (r.text) {
          next = { ...next, text: r.text, updatedAt: at, info: { ...(next.info || {}), ...(r.result === 'revoked' ? { revoked: true } : {}) } };
          changes.push(`${contact.name}: ${next.label || next.format} ${r.result}`);
        }
      } else if (sameFormat.length && source.kind !== 'github') {
        /* another key where this one was: held for the person (GitHub lists many SSH keys - a key
           it no longer lists is missing, not replaced) */
        source.lastResult = 'changed';
        candidates.push({ ...sameFormat[0], source: { kind: source.kind, handle: source.handle } });
      } else {
        source.lastResult = 'missing';
      }
    }
    if (candidates.length) {
      const fps = [...new Set(candidates.map((c) => c.fingerprint))];
      next.pending = {
        at,
        conflict: fps.length > 1,
        candidates: fps.map((fp) => {
          const c = candidates.find((x) => x.fingerprint === fp);
          return { fingerprint: fp, text: c.text, label: c.label, source: c.source };
        }),
      };
      changes.push(`${contact.name}: ${next.label || next.format} changed - waiting for you`);
    }
    keys.push(next);
  }
  const history = changes.length ? [...changes.map((what) => ({ at, what })), ...(contact.history || [])].slice(0, HISTORY_MAX) : contact.history || [];
  return { contact: { ...contact, keys, history }, changes };
}

/**
 * Every contact, one after another with a small delay (a burst would hit each source at once),
 * skipping contacts checked within `skipWithinMs`. Stops between contacts when `signal` aborts.
 * @param {object[]} contacts
 * @param {{fetchFn: Function, openpgp?: any, now?: () => Date, delayMs?: number, skipWithinMs?: number, signal?: {aborted: boolean}, onContact?: (c: object) => void}} [opts]
 * @returns {Promise<{contacts: object[], changes: string[]}>}
 */
async function refreshAll(contacts, { fetchFn, openpgp, now = () => new Date(), delayMs = 500, skipWithinMs = 0, signal, onContact } = {}) {
  const out = [];
  const changes = [];
  let first = true;
  for (const c of contacts) {
    const last = Math.max(0, ...c.keys.flatMap((k) => k.sources.map((s) => (s.lastChecked ? Date.parse(s.lastChecked) : 0))));
    if ((signal && signal.aborted) || (skipWithinMs && now().getTime() - last < skipWithinMs)) {
      out.push(c);
      continue;
    }
    if (!first && delayMs) await new Promise((res) => setTimeout(res, delayMs));
    first = false;
    const r = await refreshContact(c, { fetchFn, openpgp, now });
    out.push(r.contact);
    changes.push(...r.changes);
    if (onContact) onContact(r.contact);
  }
  return { contacts: out, changes };
}

/* ---- the person's answer to a pending change ------------------------------------------- */

const stampHistory = (contact, at, what) => [{ at, what }, ...(contact.history || [])].slice(0, HISTORY_MAX);

/**
 * Accept the new key: it replaces the pin. A verified mark does not carry over to a key nobody
 * has checked (spec: "accepting a pending key on a verified contact clears its verified mark").
 */
function acceptPending(contact, keyId, fingerprint, now = () => new Date()) {
  const at = now().toISOString();
  return {
    ...contact,
    keys: contact.keys.map((k) => {
      if (k.id !== keyId || !k.pending) return k;
      const c = k.pending.candidates.find((x) => x.fingerprint === fingerprint);
      if (!c) throw new Error('guestbook: that key is not one waiting here');
      const { pending, ...rest } = k;
      return { ...rest, text: c.text, fingerprint: c.fingerprint, label: c.label || k.label, verified: false, updatedAt: at };
    }),
    history: stampHistory(contact, at, 'a new key accepted'),
  };
}

/** Keep the current key; the waiting one is dropped (the next refresh may bring it back). */
function keepCurrent(contact, keyId, now = () => new Date()) {
  const at = now().toISOString();
  return {
    ...contact,
    keys: contact.keys.map((k) => {
      if (k.id !== keyId) return k;
      const { pending, ...rest } = k;
      return rest;
    }),
    history: stampHistory(contact, at, 'kept the current key'),
  };
}

/** Keep the current key and stop asking the sources that served the other one. */
function keepAndRemoveSources(contact, keyId, now = () => new Date()) {
  const at = now().toISOString();
  return {
    ...contact,
    keys: contact.keys.map((k) => {
      if (k.id !== keyId || !k.pending) return k;
      const bad = k.pending.candidates.map((c) => `${c.source.kind}:${c.source.handle}`);
      const { pending, ...rest } = k;
      return { ...rest, sources: k.sources.filter((s) => !bad.includes(`${s.kind}:${s.handle}`)) };
    }),
    history: stampHistory(contact, at, 'kept the current key, removed the source'),
  };
}

module.exports = { refreshContact, refreshAll, acceptPending, keepCurrent, keepAndRemoveSources };
