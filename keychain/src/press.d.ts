export const PRESS_BYTES: 69;
/** the press record of a slot-128 derive: OKCONNECT */
export const DERIVE_OPCODE: 228;
export const DERIVE_SLOT: 128;
/** bytes (Uint8Array) or hex -> {transport, opcode, slot, subject, label} or null (not a v1 record) */
export function decodePress(rec: any): {
    transport: string;
    opcode: any;
    slot: any;
    subject: string;
    label: string | null;
    mode: string | null;
} | null;
/** "press_end": bytes or hex -> {result} (1 entered, 0 timed out, -2 wrong button, -1 cancelled) */
export function decodePressEnd(rec: any): {
    result: any;
} | null;
/**
 * The 3-digit code a derive's gate waits for, from its record's subject (hex): bytes 0, 15 and
 * 31 of the hash, mod 6, plus one (a soft key is not a DUO, whose buttons are 3).
 */
export function codeOf(subject: any, buttons?: number): number[];
/**
 * The Key Chain entries whose label is this one -> {listed, name}. listed: some entry has it; name:
 * the first that has a name (gpg://…, ssh://…). An entry the firmware recorded on its own holds
 * only the hash - listed, unnamed - until a computer's list with the text is merged in.
 */
export function nameOfLabel(list: any, label: any): {
    listed: boolean;
    name: string | null;
};
