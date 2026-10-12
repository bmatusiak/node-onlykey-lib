/**
 * One contact refreshed. Pure apart from fetchFn: returns the new contact (the caller saves it).
 * @param {object} contact
 * @param {{fetchFn: Function, openpgp?: any, now?: () => Date}} deps
 * @returns {Promise<{contact: object, changes: string[]}>}
 */
export function refreshContact(contact: object, { fetchFn, openpgp, now }: {
    fetchFn: Function;
    openpgp?: any;
    now?: () => Date;
}): Promise<{
    contact: object;
    changes: string[];
}>;
/**
 * Every contact, one after another with a small delay (a burst would hit each source at once),
 * skipping contacts checked within `skipWithinMs`. Stops between contacts when `signal` aborts.
 * @param {object[]} contacts
 * @param {{fetchFn: Function, openpgp?: any, now?: () => Date, delayMs?: number, skipWithinMs?: number, signal?: {aborted: boolean}, onContact?: (c: object) => void}} [opts]
 * @returns {Promise<{contacts: object[], changes: string[]}>}
 */
export function refreshAll(contacts: object[], { fetchFn, openpgp, now, delayMs, skipWithinMs, signal, onContact }?: {
    fetchFn: Function;
    openpgp?: any;
    now?: () => Date;
    delayMs?: number;
    skipWithinMs?: number;
    signal?: {
        aborted: boolean;
    };
    onContact?: (c: object) => void;
}): Promise<{
    contacts: object[];
    changes: string[];
}>;
/**
 * Accept the new key: it replaces the pin. A verified mark does not carry over to a key nobody
 * has checked (spec: "accepting a pending key on a verified contact clears its verified mark").
 */
export function acceptPending(contact: any, keyId: any, fingerprint: any, now?: () => Date): any;
/** Keep the current key; the waiting one is dropped (the next refresh may bring it back). */
export function keepCurrent(contact: any, keyId: any, now?: () => Date): any;
/** Keep the current key and stop asking the sources that served the other one. */
export function keepAndRemoveSources(contact: any, keyId: any, now?: () => Date): any;
