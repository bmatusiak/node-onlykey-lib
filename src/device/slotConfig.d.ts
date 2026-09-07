export namespace ENCODING {
    let TEXT: string;
    let DIGIT: string;
    let BYTE: string;
    let HEX: string;
}
/**
 * The fields of a slot, IN WIRE ORDER.
 *
 * The order is data, not decoration. The original's insertion order into
 * `fieldMap` is the order its scan finds them, and one dependency rides on it:
 * TFATYPE must be written before TFAUSERNAME, because the device needs to know
 * which kind of second factor it is being given before it is given the seed.
 * The original arranges this with a `currentSlot.mode` flag set on a previous
 * pass; here the order alone is sufficient, which is one fewer thing to keep
 * in step.
 */
export const SLOT_FIELDS: ({
    name: string;
    field: number;
    encoding: string;
    maxLength: number;
} | {
    name: string;
    field: number;
    encoding: string;
    maxLength?: undefined;
})[];
export const FIELD_BY_NAME: Map<string, {
    name: string;
    field: number;
    encoding: string;
    maxLength: number;
} | {
    name: string;
    field: number;
    encoding: string;
    maxLength?: undefined;
}>;
/**
 * Whether the value is trimmed before it is sent.
 *
 * Asymmetric on purpose (OnlyKeyWizard.js:991-997): URL, password and username
 * keep their surrounding whitespace because a leading or trailing space can be
 * significant in a credential; everything else is trimmed. Getting this
 * backwards silently changes a stored password.
 */
export const KEEP_WHITESPACE: Set<string>;
/**
 * One report holds 64 bytes; header, message id, slot and field take 7.
 *
 * The original has no length check anywhere - sendMessage stops at the buffer
 * end - so an over-long value is silently cut and the slot holds a truncated
 * password that the user believes they set. The HTML maxlength attributes were
 * the only guard, and they never ran: the submit button is type="button" with
 * an onclick, so constraint validation never fires.
 */
export const MAX_CONTENT: 57;
export function encodeValue(spec: any, value: any): Uint8Array<ArrayBufferLike>;
/**
 * Turn a slot description into the ordered writes it becomes.
 *
 * Pure: it sends nothing and touches no device, so the whole encoding table
 * can be tested without one. `writeSlot` below is the part that needs a
 * transport.
 *
 * @param {object} values  keyed by the names in SLOT_FIELDS
 * @param {number} slot    the device's slot number
 * @returns {Array<{name, field, data}>}
 */
export function planSlotWrites(values: object, slot: number): Array<{
    name: any;
    field: any;
    data: any;
}>;
/**
 * Build the TOTP field pair from a base32 seed.
 *
 * Returns both fields, because writing the seed without the type leaves the
 * device with a secret and no idea what to do with it. The order in
 * SLOT_FIELDS puts the type first.
 */
export function totpFields(base32Seed: any): {
    tfaType: string;
    totpKey: Uint8Array<ArrayBuffer>;
};
/** Build the Yubikey field pair. Same reasoning as totpFields. */
export function yubikeyFields(credential: any): {
    tfaType: string;
    yubikey: Uint8Array<ArrayBufferLike>;
};
/** Wipe one field, or the whole slot when no field is named. */
export function wipeMessage(slot: any, fieldName?: null): Uint8Array<ArrayBufferLike>;
