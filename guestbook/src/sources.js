'use strict';

/**
 * WHERE GUEST BOOK KEYS COME FROM (GUEST-BOOK-SPEC.md, "Key discovery sources").
 *
 * Two kinds of call, on purpose:
 *   lookup   ADD: a search, run when a person presses Look up - Keybase's user search (up to 5
 *            matches), Proton's key server, a GitHub user's .keys, any https URL;
 *   fetch    REFRESH: the SAME identity again, by its exact handle - never a search, so a refresh
 *            can only ever see the key it pinned or a change to it.
 *
 * Nothing here runs by itself: ok-rn is air-gapped by default (ok-rn src/keySearch.ts, where the
 * add lookups came from), and the network is touched only by something a person does. `fetchFn`
 * is passed in (tests hand in a fake). Every body is limited to 1 MB and must come over https -
 * a redirect that lands on http is an error, not a key.
 */

const { MAX_TEXT } = require('./formats');

const KEYBASE_SEARCH = 'https://keybase.io/_/api/1.0/user/user_search.json?q=';
const KEYBASE_KEY = (user) => `https://keybase.io/${encodeURIComponent(user)}/pgp_keys.asc`;
const PROTONMAIL = 'https://api.protonmail.ch/pks/lookup?op=get&search=';
const GITHUB_KEYS = (user) => `https://github.com/${encodeURIComponent(user)}.keys`;
/* how many Keybase matches to fetch keys for - each is one more request */
const KEYBASE_MAX = 5;
/* the kinds a refresh can fetch again; paste, qr and connect have nothing to go back to */
const FETCHABLE = ['keybase', 'protonmail', 'github', 'url'];

/** A Proton address as the key server wants it: a bare name means @protonmail.com (as the web app does). */
const protonAddress = (raw) => (!raw.startsWith('0x') && !raw.includes('@') ? `${raw}@protonmail.com` : raw);

/**
 * One GET, held to the rules: https only (also after redirects), 1 MB at most.
 * @returns {Promise<{ok: boolean, status: number, body: string}>}
 */
async function getText(fetchFn, url) {
  if (!/^https:\/\//i.test(url)) throw new Error('only https:// - a key fetched in the clear is anyone\'s');
  const res = await fetchFn(url);
  if (res.url && !/^https:\/\//i.test(res.url)) throw new Error(`${url} redirected to ${res.url} - not https, refused`);
  const body = res.ok ? await res.text() : '';
  if (body.length > MAX_TEXT) throw new Error(`${url} served more than 1 MB - not a key`);
  return { ok: !!res.ok, status: res.status, body };
}

/**
 * ADD: a person's search. -> [{label, body, source: {kind, handle}, where}], each body still to be
 * read by formats.detectAll (it holds one or more keys; a GitHub .keys body holds every SSH key).
 */
async function lookup(kind, query, fetchFn) {
  const q = String(query || '').trim();
  if (!q) throw new Error('type a name, address, username or URL to look up');
  if (kind === 'keybase') {
    const res = await getText(fetchFn, KEYBASE_SEARCH + encodeURIComponent(q));
    if (!res.ok) throw new Error(`Keybase search answered ${res.status}`);
    let list = [];
    try {
      const body = JSON.parse(res.body);
      list = Array.isArray(body && body.list) ? body.list : [];
    } catch {
      throw new Error('Keybase answered with something that is not its JSON');
    }
    const users = list.map((e) => e && e.keybase).filter((k) => k && k.username).slice(0, KEYBASE_MAX);
    const out = [];
    for (const user of users) {
      const key = await getText(fetchFn, KEYBASE_KEY(user.username));
      if (!key.ok || !key.body.trim()) continue; /* a user without a PGP key is a 404 here */
      out.push({
        label: user.full_name ? `${user.username} (${user.full_name})` : user.username,
        body: key.body,
        source: { kind: 'keybase', handle: user.username },
        where: KEYBASE_KEY(user.username),
      });
    }
    return out;
  }
  if (kind === 'protonmail') {
    const address = protonAddress(q);
    const where = PROTONMAIL + encodeURIComponent(address);
    const res = await getText(fetchFn, where);
    if (!res.ok) {
      if (res.status === 404) return [];
      throw new Error(`Proton's key server answered ${res.status}`);
    }
    return [{ label: address, body: res.body, source: { kind: 'protonmail', handle: address }, where }];
  }
  if (kind === 'github') {
    const user = q.replace(/^@/, '');
    const where = GITHUB_KEYS(user);
    const res = await getText(fetchFn, where);
    if (!res.ok) {
      if (res.status === 404) return [];
      throw new Error(`GitHub answered ${res.status}`);
    }
    return res.body.trim() ? [{ label: `github.com/${user}`, body: res.body, source: { kind: 'github', handle: user }, where }] : [];
  }
  if (kind === 'url') {
    const res = await getText(fetchFn, q);
    if (!res.ok) throw new Error(`${q} answered ${res.status}`);
    return [{ label: q, body: res.body, source: { kind: 'url', handle: q }, where: q }];
  }
  throw new Error(`not a source to look up: ${kind}`);
}

/**
 * REFRESH: the source's exact handle, fetched again.
 * -> {status: 'ok', body} | {status: 'missing'} (the source no longer serves anything there)
 *  | {status: 'error', message} (network, server, size, http). Never throws.
 */
async function fetchSource(source, fetchFn) {
  if (!source || !FETCHABLE.includes(source.kind)) return { status: 'error', message: 'this source cannot be fetched again' };
  const url =
    source.kind === 'keybase'
      ? KEYBASE_KEY(source.handle)
      : source.kind === 'protonmail'
        ? PROTONMAIL + encodeURIComponent(protonAddress(source.handle))
        : source.kind === 'github'
          ? GITHUB_KEYS(source.handle)
          : source.handle;
  try {
    const res = await getText(fetchFn, url);
    if (res.status === 404 || (res.ok && !res.body.trim())) return { status: 'missing' };
    if (!res.ok) return { status: 'error', message: `${url} answered ${res.status}` };
    return { status: 'ok', body: res.body };
  } catch (e) {
    return { status: 'error', message: String((e && e.message) || e) };
  }
}

module.exports = { FETCHABLE, KEYBASE_MAX, lookup, fetchSource };
