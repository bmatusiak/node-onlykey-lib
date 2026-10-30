'use strict';

/**
 * edge/cli/nametag.js - "my device name": the nametag of one device of an identity (Brad, 2026-10-24:
 * "i should be able to set the nametag for key1 and change it too, and the desktop app i should be able
 * to set it in the edge manage popup"). One function for every host - the CLI's `edge name`, the desktop
 * app's Edge Management.
 *
 * Set: the key CERTIFIES the nametag at a press (edge.statement -> edge.certify; Brad, 2026-10-30: "change
 * nametag to certify") - one link on the chain, then its owner key and ML-DSA-65 twin sign the device id, its
 * checkpoint keys, that link's seq and the nametag's hash (grants.certifyDigest). It is checked here with the owner keys it names (grants.verifyStatement), and the owner key
 * must be THIS identity's (its id is the identity home's) - then it is kept in the identity's `devices`
 * store, by device id. Another device of the identity checks the same statement with its own owner keys:
 * that is how a phone or a hard key of yours is recognised, under its name, when logs are offered.
 */

const path = require('path');
const bucketHome = require('../../bucket/cli/home');
const { grants } = require('../src');
const { identityIdOf } = require('../src/identity-id');
const { toHex } = require('../../src/bytes');

const devices = (home) => bucketHome.kv(bucketHome.edgeAt(home, 'devices'));

/* a statement's bytes as hex, for the store */
const BYTE_FIELDS = ['deviceId', 'publicKey', 'publicKeyPq', 'ownerKey', 'ownerKeyPq', 'signature', 'signaturePq'];
const toStored = (st) => Object.fromEntries(Object.entries(st).map(([k, v]) => [k, BYTE_FIELDS.includes(k) ? toHex(v) : v]));

/** the name kept for one device of this identity, or null */
function getName(home, deviceIdHex) {
  const t = devices(home).getItem(deviceIdHex);
  if (!t) return null;
  try { const r = JSON.parse(t); return { nametag: r.nametag, at: r.at }; } catch (_) { return null; }
}

/** every device of this identity with a name kept here: [{deviceId, nametag, at}] */
function listNames(home) {
  const kv = devices(home);
  return kv.keys().map((k) => { const n = getName(home, k); return n ? { deviceId: k, ...n } : null; }).filter(Boolean);
}

/**
 * Name this device: the key signs the statement, it is checked, it is kept.
 * @param {{edge: object, home: string, nametag: string, now?: () => number}} o
 * @returns {Promise<{deviceId: string, nametag: string, at: number}>}
 */
async function setName({ edge, home, nametag, now = Date.now }) {
  grants.nametagHash(nametag); /* throws for an empty or too long one, before the key is asked */
  const st = await edge.statement(String(nametag).trim());
  if (!grants.verifyStatement(st, st.ownerKey, st.ownerKeyPq)) throw new Error('edge: the key\'s statement does not verify with the owner keys it names - nothing kept');
  if (identityIdOf(st.ownerKeyPq) !== path.basename(home)) throw new Error('edge: the key\'s owner key is not this identity\'s - nothing kept');
  const rec = { nametag: st.nametag, at: now(), statement: toStored(st) };
  const deviceId = toHex(st.deviceId);
  devices(home).setItem(deviceId, JSON.stringify(rec));
  /* named: its log can now be offered to the identity's other devices */
  const log = await offerOwnLog({ edge, home }).catch((e) => ({ kept: false, why: e.message }));
  return { deviceId, nametag: rec.nametag, at: rec.at, log };
}

/* the kept statement of one device, back as the bytes copy.keepLog checks */
function statementOf(home, deviceIdHex) {
  const t = devices(home).getItem(deviceIdHex);
  if (!t) return null;
  try {
    const s = JSON.parse(t).statement;
    if (!s) return null;
    const { fromHex } = require('../../src/bytes');
    return Object.fromEntries(Object.entries(s).map(([k, v]) => [k, BYTE_FIELDS.includes(k) && typeof v === 'string' ? fromHex(v) : v]));
  } catch (_) { return null; }
}

/**
 * A HARD KEY'S LOG, READY TO OFFER to the other devices of its identity (Brad, 2026-10-24: "each team
 * knows the budget history if using the same key identity"). A phone's log is kept to offer by the pull
 * of edge sync (agent.js: its statement + its checkpoint -> copy.keepLog); a hard key has no phone to
 * pull, so this computer does the same with the SAME function, from the key's own statement (its name,
 * setName) and its checkpoint now. keepLog's checks decide - the statement names this device, the chain
 * verifies, every use is complete - and say why not.
 * @returns {Promise<{kept: boolean, why?: string}>}
 */
async function offerOwnLog({ edge, home }) {
  const copy = require('./copy');
  const { publicKey, deviceId } = await edge.publicKey();
  const statement = statementOf(home, toHex(deviceId));
  if (!statement) return { kept: false, why: 'this device has no name yet (onlykey-js edge name)' };
  const c = copy.load(home, deviceId);
  const checkpoint = await edge.checkpoint();
  return copy.keepLog(home, { deviceId, publicKey, publicKeyPq: c.publicKeyPq || (await edge.publicKeyPq('checkpoint')), records: c.links, checkpoint, statement });
}

module.exports = { getName, listNames, setName, offerOwnLog };
