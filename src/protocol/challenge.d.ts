/**
 * The three buttons the device is about to ask for.
 *
 * @param {Uint8Array} packet the accumulated payload, exactly as the firmware
 *   assembled it in `packet_buffer`
 * @param {object} [opts]
 * @param {boolean} [opts.duo=false] the hardware is an OnlyKey DUO, which takes
 *   mod 3 rather than mod 6 because it has half the buttons. Getting this wrong
 *   yields digits in 1..6 for a device that can only produce 1..3, so two
 *   thirds of them are unpressable.
 * @returns {number[]} three button numbers, each 1..6 (or 1..3 on a DUO)
 */
export function challengeDigits(packet: Uint8Array, opts?: {
    duo?: boolean | undefined;
}): number[];
/** The buttons a standard OnlyKey has. A DUO has three - see below. */
export const BUTTONS: 6;
export const DUO_BUTTONS: 3;
