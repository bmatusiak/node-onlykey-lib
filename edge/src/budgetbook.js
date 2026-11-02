'use strict';

/**
 * THE APPROVING HOST'S BUDGET BOOK (the structure track S4 step 7, 2026-11-02): what a host keeps of each budget it
 * approved on a key - the request (reason, scopes, uses), the opening's genesis and the checkpoint signature its press
 * answered with (R27: grants.verifyBudgetOpening), when it was opened and for how long, and the host's own marks on it
 * (endedAt, dismissed, continued, which computer asked). Also your other devices' checked openings (edgeDevices).
 *
 * It was the ok-edge app's alone, read and written as raw storage keys in fifteen places; here it is one book over the
 * host's store - the app's AsyncStorage, later the CLI's home (its local host) - with the SAME keys, so nothing moves:
 *
 *   <prefix><deviceIdHex>.<grantId>  ->  the record as JSON
 *
 *   createBudgetBook({kv, prefix})   kv: {getItem, setItem, getAllKeys?, getMany?} (sync or async; strings);
 *                                    prefix: () => string - the net's own (the app's edgeKey('budgets.'))
 *     get(dev, grantId) -> record | null
 *     put(dev, grantId, record)
 *     patch(dev, grantId, fields) -> the record after, or null when there was none (nothing written)
 *     list(dev, {keys?}) -> [{grantId, record}] by grantId - keys: the store's keys read once already (a refresh
 *                           reads them once for all its lists)
 *     key(dev, grantId) -> the store key
 *
 * Pure: no I/O of its own. Records are plain JSON; a record that does not parse reads as none.
 */

/**
 * @param {{kv: {getItem: (k: string) => any, setItem: (k: string, v: string) => any, getAllKeys?: () => any, getMany?: (keys: string[]) => any}, prefix: () => string}} o
 * @returns {{key: (dev: string, grantId: number) => string, get: (dev: string, grantId: number) => Promise<any>, put: (dev: string, grantId: number, record: any) => Promise<void>,
 *   patch: (dev: string, grantId: number, fields: any) => Promise<any>, list: (dev: string, opts?: {keys?: readonly string[] | string[] | null}) => Promise<Array<{grantId: number, record: any}>>}}
 */
function createBudgetBook({ kv, prefix }) {
  for (const fn of ['getItem', 'setItem']) {
    if (!kv || typeof kv[fn] !== 'function') throw new TypeError(`budget book: the host store needs ${fn}()`);
  }
  if (typeof prefix !== 'function') throw new TypeError('budget book: prefix is a function (the net decides it)');
  const devOf = (dev) => String(dev).toLowerCase();
  const key = (dev, grantId) => `${prefix()}${devOf(dev)}.${grantId}`;
  const parse = (raw) => {
    if (raw === null || raw === undefined) return null;
    try { return JSON.parse(raw); } catch { return null; }
  };
  const allKeys = async () => {
    if (typeof kv.getAllKeys !== 'function') throw new TypeError('budget book: list() needs the store\'s getAllKeys()');
    return kv.getAllKeys();
  };
  const readMany = async (keys) => {
    if (typeof kv.getMany === 'function') return kv.getMany(keys);
    const out = {};
    for (const k of keys) out[k] = await kv.getItem(k);
    return out;
  };
  return {
    key,
    async get(dev, grantId) { return parse(await kv.getItem(key(dev, grantId))); },
    async put(dev, grantId, record) { await kv.setItem(key(dev, grantId), JSON.stringify(record)); },
    async patch(dev, grantId, fields) {
      const was = parse(await kv.getItem(key(dev, grantId)));
      if (!was) return null;
      const now = { ...was, ...fields };
      await kv.setItem(key(dev, grantId), JSON.stringify(now));
      return now;
    },
    async list(dev, { keys = null } = {}) {
      const p = `${prefix()}${devOf(dev)}.`;
      const mine = (keys || await allKeys()).filter((k) => k.startsWith(p) && /^\d+$/.test(k.slice(p.length)));
      if (!mine.length) return [];
      const got = await readMany(mine);
      return Object.entries(got)
        .map(([k, raw]) => ({ grantId: Number(k.slice(p.length)), record: parse(raw) }))
        .filter((e) => e.record)
        .sort((a, b) => a.grantId - b.grantId);
    },
  };
}

module.exports = { createBudgetBook };
