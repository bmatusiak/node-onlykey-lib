export const PRESS_BYTES: 69;
/** bytes (Uint8Array) or hex -> {transport, opcode, slot, subject, label} or null (not a v1 record) */
export function decodePress(rec: any): {
    transport: string;
    opcode: any;
    slot: any;
    subject: string;
    label: string | null;
} | null;
/**
 * The Key Chain entries whose label is this one -> {listed, name}. listed: some entry has it; name:
 * the first that has a name (gpg://…, ssh://…). An entry the firmware recorded on its own holds
 * only the hash - listed, unnamed - until a computer's list with the text is merged in.
 */
export function nameOfLabel(list: any, label: any): {
    listed: boolean;
    name: string | null;
};
