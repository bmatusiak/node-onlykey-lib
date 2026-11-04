'use strict';
/*
 * AGENT CARDS FOR TESTS (lib d67c64f: every budget is asked under an agent card - edge/src/approve.js cardOf). A test card
 * is certified the real way (edge.certifyAgent, a press) by the fake key's OWNER keys - the same on every fake made from
 * one backup (fake-edge-key OWNER_SECRET) - on a fake key of its own, so the chain a test budgets on gets no certify link
 * and the seqs it asserts stay where they were. cardOfFor is a host's cardOf: agents.pick, checked with those owner keys.
 */
const { agents } = require('../../src');
const { fakeKey, edgeOver } = require('./fake-edge-key');

/* the certifier: another device of the same backup (its own Edge salt, the same owner key) */
const CERTIFIER_SECRET = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 11) & 0xff);
let certifier = null;
const certifierEdge = () => (certifier ??= edgeOver(fakeKey({ secret: CERTIFIER_SECRET })));

/**
 * A certified card for the derivation labels a test budgets under.
 * @param {{label?: string, ssh?: string, gpg?: string, slots?: number[], agent?: string|null, committer?: {name: string, email: string}|null, created?: number, expires?: number}} [o]
 *   ssh 'ssh://user@host'; gpg the user ID (a scope names it as 'gpg://<user id>'); created / expires: a card made from an
 *   identity keeps its certificate's (agents.infoFromRecord); slots: stored sign slots; agent: the MCP agent id it is bound to
 */
async function testCard({ label = 'test agent', ssh, gpg, slots, agent = null, committer = null, created = 1760000000, expires = 0 } = {}) {
  const derive = { ...(ssh ? { ssh } : {}), ...(gpg !== undefined ? { gpg } : {}) };
  return certifierEdge().certifyAgent({ label, created, expires, derive, slots, agent, committer });
}

/** A host's cardOf over these cards - a usable card by label, or a throw naming why not (as the hosts answer). */
function cardOfFor(...cards) {
  const store = Object.fromEntries(cards.map((c) => [c.thing.label, JSON.stringify({ card: c, certs: {} })]));
  return async (label) => {
    const e = certifierEdge();
    return agents.pick(store, label, await e.ownerPublicKey(), await e.publicKeyPq('owner')).card;
  };
}

/** A cardOf whose one card (`label`) covers these scopes' identities - one ssh and one gpg at most, as a card holds. */
async function cardOfScopes(scopes, label = 'agent') {
  const ids = scopes.map((s) => String(s.identity || ''));
  const ssh = ids.find((i) => i.startsWith('ssh://'));
  const gpg = ids.find((i) => i.startsWith('gpg://'));
  return cardOfFor(await testCard({ label, ssh, gpg: gpg ? gpg.slice('gpg://'.length) : undefined }));
}

module.exports = { testCard, cardOfFor, cardOfScopes };
