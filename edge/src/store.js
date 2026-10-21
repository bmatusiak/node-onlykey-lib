'use strict';

/**
 * THE COMPUTER'S OWN EDGE STATE, per key: which budget this computer last held on each key
 * (audit F8, 2026-10-20). It was one `budget` in agent.json per Edge folder, so a command to
 * a second phone - or each `edge sync --all` child - failed to resume it and saved null, and
 * the next `edge exec` on the first phone said "no budget" while the budget was still live.
 * Keyed by the key's device_id (edge.publicKey().deviceId): a budget lives on one key's chain.
 *
 * Over a host store with the lib's seam (src/crypto/vault_store.js): getItem / setItem /
 * removeItem, sync or async, string values. The CLI hands in a file in the Edge home; the
 * desktop app its own store. Pure - no I/O here.
 */
const PREFIX = 'okedge.pointer.budget.';

function assertStore(kv) {
  for (const fn of ['getItem', 'setItem', 'removeItem']) {
    if (!kv || typeof kv[fn] !== 'function') throw new TypeError(`edge store: the host store needs ${fn}()`);
  }
}

const keyOf = (deviceId) => {
  const hex = typeof deviceId === 'string' ? deviceId : Array.from(deviceId || [], (b) => b.toString(16).padStart(2, '0')).join('');
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new TypeError('edge store: a device id is 16 bytes');
  return PREFIX + hex.toLowerCase();
};

function createPointerStore(kv) {
  assertStore(kv);
  return {
    /**
     * The budget (its grant id, as the client gave it - a number) this computer holds on
     * that key, or null. Kept as JSON so the id comes back as it went in: stored as text,
     * "21" never matched the key's live budget 21 and a live budget read as gone
     * (Pixel, 2026-10-20).
     */
    async budget(deviceId) {
      const v = await kv.getItem(keyOf(deviceId));
      if (v === null || v === undefined) return null;
      try { return JSON.parse(v); } catch { return null; }
    },
    /** Remember it, or forget it (null). */
    async setBudget(deviceId, grantId) {
      if (grantId !== null && grantId !== undefined) await kv.setItem(keyOf(deviceId), JSON.stringify(grantId));
      else await kv.removeItem(keyOf(deviceId));
    },
  };
}

/** For tests and for hosts with nothing else: a Map. */
function memoryStore() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    removeItem: (k) => { m.delete(k); },
  };
}

module.exports = { createPointerStore, memoryStore };
