/**
 * Digits are BUTTON NUMBERS, not a keypad.
 *
 * The device has six touch buttons, so a PIN digit is 1-6. The firmware
 * rejects anything outside 7-10 digits with
 * "Error PIN is not between 7 - 10 digits".
 *
 * Verified empirically: provisioning a soft key with 1234561 succeeds and the
 * PIN survives a restart.
 */
export const MIN_DIGITS: 7;
export const MAX_DIGITS: 10;
export const BUTTONS: 6;
/**
 * Validate the DUO PIN set.
 *
 * WHICH DIGITS: any numeral 0-9, 7 to 16 of them. Settled from the firmware
 * rather than from the two clients, which disagree: a DUO's PIN is TYPED into
 * the message body, and okcore.cpp:978 copies it out as bytes
 * (`memcpy(password.guess, (ID+18), 16)`) and hashes it by strlen with no
 * digit check at all. The 1-6 rule belongs to the button-press path
 * (okcore.cpp:2415, "is not a button 1-6") that a DUO never takes for its
 * PIN. The desktop wizard's "numerals only" is the right constraint; its
 * button-numbered variant elsewhere is the Classic's.
 *
 * Policy from OnlyKeyWizard.js:1435-1449, with two corrections.
 *
 * The original enforces no MAXIMUM in JavaScript - the 16-character cap is
 * only an HTML maxlength attribute. Since the wire format gives each PIN a
 * 16-byte slot, a 17th character silently overflows into the next PIN. That is
 * enforced here.
 *
 * The original also checks `pin3.match(/\D/g)` without the `pin3 &&` guard its
 * neighbours have. Harmless on an empty string, but asymmetric.
 */
export const DUO_PIN_BYTES: 16;
export namespace PROMPTS {
    let enter: RegExp;
    let storing: RegExp;
    let confirm: RegExp;
    let matched: RegExp;
}
export namespace ERRORS {
    let tooShort: RegExp;
    let mismatch: RegExp;
}
/**
 * One print per DIGIT, so a first-match wait returns after the first one.
 * Counting them is the only way to know a whole burst was consumed.
 */
export const DIGIT_ACK: RegExp;
/**
 * The classic PIN bracket.
 *
 * The same message id drives every transition, and what it means depends on
 * where the state machine already is. The wizard tracks this with
 * `pendingMessages[msgId] = !pendingMessages[msgId]` - a toggle, where an odd
 * count means "entry is open". Sending one too many or too few silently
 * advances past a step rather than erroring, which is why the sequence has to
 * wait for each prompt rather than assume it.
 *
 * Six transitions per PIN:
 *
 *   OKPIN  -> "Enter PIN"        open entry
 *   digits -> one ack per digit
 *   OKPIN  -> "Storing PIN"      close entry
 *   OKPIN  -> "Confirm PIN"      open confirmation
 *   digits -> one ack per digit
 *   OKPIN  -> "Both PINs Match"  close confirmation
 *
 * Transcribed from onlykey-testing/lib/fixtures/states/initialized.js, which
 * drives it against both real and emulated devices.
 */
export const PIN_SEQUENCE: ({
    send: boolean;
    expect: string;
    label: string;
    digits?: undefined;
    reject?: undefined;
} | {
    digits: boolean;
    label: string;
    send?: undefined;
    expect?: undefined;
    reject?: undefined;
} | {
    send: boolean;
    expect: string;
    reject: string[];
    label: string;
    digits?: undefined;
})[];
/**
 * Where to return to when a PIN step fails.
 *
 * From goBackOnError (OnlyKeyWizard.js:1174-1189): always the ENTER step of
 * the failing pair, never the confirm step - re-confirming a PIN the device
 * has already rejected cannot succeed.
 */
export const RECOVERY_STEP: {
    [MSG.OKPIN]: string;
    [MSG.OKPINSEC]: string;
    [MSG.OKPINSD]: string;
};
/**
 * How to empty the device's PIN buffer, given how many digits are already in it.
 *
 * THE BUFFER CANNOT BE CLEARED. There is no message for it: the firmware's
 * `clearPinEntry` APPENDS before it resets, so asking for a clear leaves a digit
 * behind. The only clean way back to empty is the firmware's own ROLLOVER -
 * `pass_keypress` starts at 1 and the tenth press takes the else branch, which
 * calls `password.reset()` and sets it back to 1 (OnlyKey.ino:964-989).
 *
 * So "start over" is not a command, it is PADDING: press the rest of the way to
 * ten and let the firmware reset itself.
 *
 * ## Which button to pad with, and which never to
 *
 * NEVER BUTTON 3. A press is a press and 3 is the lock gesture. Button 6 is the
 * default here, and a single repeated digit also makes an accidental match on
 * somebody's real PIN vanishingly unlikely - padding with a varied sequence
 * could spell one.
 *
 * A caller on a device with fewer buttons passes its own; a DUO does not need
 * this at all, because its PIN travels in the message body and never enters a
 * button buffer.
 *
 * ## What it costs
 *
 * One session attempt of the three allowed, and it sets `firsttime`, so the
 * EEPROM failed-login counter ticks up once this boot. Both are reset by the
 * next successful unlock. That is the price of the only clean reset there is.
 *
 * @param {number} entered digits already in the buffer
 * @param {object} [opts]
 * @param {number} [opts.button] which button to pad with
 * @returns {number[]} the buttons to press, in order. Empty when there is
 *   nothing to do - an empty buffer, or one already at the rollover.
 */
export function rolloverPresses(entered: number, { button }?: {
    button?: number | undefined;
}): number[];
/**
 * Validate a classic PIN.
 * @returns {string[]} problems, empty when acceptable
 */
export function validatePin(pin: any, { confirm }?: {
    confirm?: null | undefined;
}): string[];
export function validateDuoPins({ pin, pinConfirm, selfDestruct, selfDestructConfirm }: {
    pin: any;
    pinConfirm: any;
    selfDestruct?: string | undefined;
    selfDestructConfirm?: string | undefined;
}): {
    ok: boolean;
    primary: string[];
    selfDestruct: string[];
};
/**
 * Encode DUO PINs for the wire.
 *
 * Three things carry meaning and none of them are obvious:
 *
 *   Digits are ASCII: 48 + the digit, so '1' is 49.
 *
 *   A leading 0xFF means SET; its absence means VERIFY. Same message id either
 *   way, so this sentinel is the only thing distinguishing them - and it
 *   shifts every slot boundary by one.
 *
 *   Multiple PINs each occupy a fixed 16-byte slot. A SINGLE PIN - the unlock
 *   path - is sent at its natural length, unpadded. That asymmetry is the
 *   discriminator between unlocking and provisioning at the buffer level.
 *
 * An absent middle PIN is 16 zero bytes: the DUO has no second profile PIN,
 * and the original reaches that by passing an empty array through a
 * `typeof !== 'string'` check. Passed as '' here.
 */
export function encodeDuoPins(pins: any, { set }?: {
    set?: boolean | undefined;
}): Uint8Array<any>;
/** The DUO PIN message. Always OKPIN, in both directions. */
export function duoPinMessage(pins: any, opts: any): Uint8Array<ArrayBufferLike>;
/** The message for one step of a PIN kind. */
export function pinMessage(kind?: string): Uint8Array<ArrayBufferLike>;
import { MSG } from "../protocol/msg";
