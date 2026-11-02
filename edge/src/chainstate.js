'use strict';

/**
 * ONE CHAIN STATE PER KEY (the structure track S4 step 9, 2026-11-02; APP.md; Brad, 2026-10-07: "unify the state of the
 * block chain in memory so ui and bluetooth dont need to constantly hammer verifying ... 1 complete check, both
 * bluetooth and ui or anything else can just ask for validity"; "a lot easier to manage and save, and watch events on
 * it"). On a Galaxy A13 one agent request once ran four full checks of 10-16 s each, on the thread that answers
 * Bluetooth: three verify paths, each with its own state.
 *
 * Every asker asks validity(): the answer from memory when nothing changed (the host says so - the same head, the same
 * stored copy), else ONE check - and never a second one while one runs for that key. Every check records its answer
 * here and it is told: 'checked' (every check), 'changed' (the verdict's kind changed), 'sealed' (a budget's end sealed
 * a block). In memory only: nothing "verified" is stored (BLOCKS.md 2a rule 4). The check itself is the host's (the
 * ok-edge app's sync: the key's head, the copy, the verdict); this keeps the answers.
 *
 *   createChainState()
 *     on(event, fn) -> unsubscribe            'checked' | 'changed' | 'sealed'; a listener that throws breaks nothing
 *     current(id) -> answer | null            no I/O
 *     record(id, {view, lastSeen, sealed, path, ms}) -> answer     a check's result (the host's sync calls it)
 *     validity(id, {unchanged, check}) -> Promise<answer>
 *         unchanged(prev) -> Promise<boolean>   the host's quick test that nothing changed since prev
 *         check() -> Promise<any>               the host's check; it records
 *     forget(id)                              the next validity checks again
 *
 *   answer: {deviceId, view, head: {seq, head} | null, ok, path, at, ms}
 *     head: the head the copy verified through NOW - what Approve / resume hand the key (R27) - only from a check that
 *           vouched for it (verified, or a gap beneath a confirmed checkpoint) and only when the copy's last verified
 *           head is the key's head this check saw; a tampered copy offers none, an older sync's lastSeen is not it
 *     ok:   verified, with that head
 */

/**
 * @returns {{on: (ev: 'checked' | 'changed' | 'sealed', fn: (a: any) => void) => () => void, current: (id: string) => any,
 *   record: (id: string, r: {view: any, lastSeen: {seq: number, head: Uint8Array} | null, sealed?: boolean, path?: string | null, ms?: number}) => any,
 *   validity: (id: string, o: {unchanged: (prev: any) => Promise<boolean>, check: () => Promise<any>}) => Promise<any>,
 *   forget: (id: string) => void}}
 */
function createChainState() {
  const answers = new Map();
  const asking = new Map();
  const listeners = { checked: new Set(), changed: new Set(), sealed: new Set() };
  const idOf = (id) => String(id).toLowerCase();

  function emit(ev, a) {
    for (const fn of [...listeners[ev]]) {
      try { fn(a); } catch (e) { if (typeof console !== 'undefined') console.warn(`[edge] chain state: a '${ev}' listener threw: ${String(e)}`); }
    }
  }

  function on(ev, fn) {
    if (!listeners[ev]) throw new TypeError(`chain state: no event '${ev}' (checked | changed | sealed)`);
    listeners[ev].add(fn);
    return () => { listeners[ev].delete(fn); };
  }

  function current(id) {
    return answers.get(idOf(id)) || null;
  }

  function record(id, { view, lastSeen, sealed = false, path = null, ms = 0 }) {
    const key = idOf(id);
    const prev = answers.get(key);
    const vouched = view.verdict.kind === 'verified' || view.verdict.kind === 'gap';
    const head = vouched && lastSeen && view.headSeq !== null && view.headSeq !== undefined && lastSeen.seq === view.headSeq
      ? { seq: lastSeen.seq, head: lastSeen.head } : null;
    const a = { deviceId: key, view, head, ok: view.verdict.kind === 'verified' && head !== null, path, at: Date.now(), ms };
    answers.set(key, a);
    emit('checked', a);
    if (!prev || prev.view.verdict.kind !== view.verdict.kind) emit('changed', a);
    if (sealed) emit('sealed', a);
    return a;
  }

  function validity(id, { unchanged, check }) {
    const key = idOf(id);
    const running = asking.get(key);
    if (running) return running;
    const p = (async () => {
      const t0 = Date.now();
      const prev = answers.get(key);
      if (prev && prev.head && (await unchanged(prev))) {
        const a = { ...prev, path: 'skipped', at: Date.now(), ms: Date.now() - t0 };
        answers.set(key, a);
        return a;
      }
      await check();
      return answers.get(key) || null;
    })().finally(() => asking.delete(key));
    asking.set(key, p);
    return p;
  }

  function forget(id) {
    answers.delete(idOf(id));
  }

  return { on, current, record, validity, forget };
}

module.exports = { createChainState };
