'use strict';

/**
 * edge/src/forks.js - EVERY RESTORE IS A FORK (Brad, 2026-10-31: "when i restore a backup, it should be depicted as a
 * fork"; "the idea of a device salt id is for me to track backups being used with edge"; "if a stolen backup happens,
 * and it gets used and syncs with mcp, the backup's usage can be seen, and a fork on the same backup is a yellow flag").
 *
 * A backup carries the key's Edge state but not its device salt, so a restored key gets a new device id and starts its
 * own chain with a CONTINUE link (R28) at the next seq after the backup's head; its subject commits to the backup point:
 * SHA256("OKEDGE-CONTINUE-v1" || old device id || old seq || old head || debts) (chain.continueSubject). Two restores of
 * one backup continue the same point, so they carry the SAME subject - which is all the yellow flag needs: nothing about
 * the parent has to be held. The parent is named when its copy is here (copy.checkContinue recomputes the subject).
 *
 * Pure: hosts hand in the chains they hold (their own copy and every merged one) and draw what this returns.
 */
const chain = require('./chain');
const { OP } = require('./codes');
const { checkContinue } = require('./copy');
const { toHex, fromHex } = require('../../src/bytes');

const idHex = (id) => (typeof id === 'string' ? id.toLowerCase() : toHex(id));
const asLinks = (links) => (links || []).map((e) => (e instanceof Uint8Array ? { link: e } : e));

/**
 * @param {Array<{deviceId: string|Uint8Array, links: Array<{link: Uint8Array, head?: Uint8Array}>}>} chains newest data
 *   each host holds, any order
 * @returns {{
 *   chains: Array<{deviceId: string, start: 'original'|'fork'|'partial', forkSeq: number|null, point: string|null, parent: string|null}>,
 *   points: Array<{point: string, seq: number, parent: string|null, forks: string[], flag: boolean}>
 * }}
 *   start: 'original' - the chain from its genesis (seq 0); 'fork' - it begins with a CONTINUE (a restored backup);
 *   'partial' - this host holds it only from a later link, so where it began is not known here.
 *   points: the backup points forks continue from, one per subject; flag: more than one fork of the same point.
 */
function forkTree(chains) {
  const list = (chains || []).map((c) => ({ deviceId: idHex(c.deviceId), links: asLinks(c.links) }))
    .filter((c) => c.links.length);
  const out = [];
  const byPoint = new Map();
  for (const c of list) {
    const first = chain.decodeLink(c.links[0].link);
    if (first.op === OP.CONTINUE) {
      const point = toHex(first.subject);
      /* the parent: any chain held here whose head and debts at the seq before give this subject */
      let parent = null;
      for (const p of list) {
        if (p.deviceId === c.deviceId) continue;
        if (checkContinue(c.links[0].link, { deviceId: fromHex(p.deviceId), links: p.links }).ok) { parent = p.deviceId; break; }
      }
      out.push({ deviceId: c.deviceId, start: 'fork', forkSeq: first.seq, point, parent });
      const g = byPoint.get(point) || { point, seq: first.seq, parent, forks: [] };
      if (!g.parent && parent) g.parent = parent;
      g.forks.push(c.deviceId);
      byPoint.set(point, g);
    } else {
      out.push({ deviceId: c.deviceId, start: first.seq === 0 ? 'original' : 'partial', forkSeq: null, point: null, parent: null });
    }
  }
  const points = [...byPoint.values()].map((g) => ({ ...g, forks: g.forks.sort(), flag: g.forks.length > 1 })).sort((a, b) => a.seq - b.seq);
  return { chains: out, points };
}

module.exports = { forkTree };
