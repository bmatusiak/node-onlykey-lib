export namespace PREFERENCES {
    namespace lockout {
        let field: number;
        let max: number;
        let unit: string;
        let label: string;
        let requires: string;
    }
    namespace typeSpeed {
        let field_1: number;
        export { field_1 as field };
        let max_1: number;
        export { max_1 as max };
        let label_1: string;
        export { label_1 as label };
        let requires_1: string;
        export { requires_1 as requires };
    }
    namespace keyboardLayout {
        let field_2: number;
        export { field_2 as field };
        let max_2: number;
        export { max_2 as max };
        let label_2: string;
        export { label_2 as label };
        let requires_2: string;
        export { requires_2 as requires };
    }
    namespace ledBrightness {
        let field_3: number;
        export { field_3 as field };
        let max_3: number;
        export { max_3 as max };
        let label_3: string;
        export { label_3 as label };
        let requires_3: string;
        export { requires_3 as requires };
    }
    namespace lockButton {
        let field_4: number;
        export { field_4 as field };
        let max_4: number;
        export { max_4 as max };
        let label_4: string;
        export { label_4 as label };
        let requires_4: string;
        export { requires_4 as requires };
    }
    namespace derivedChallengeMode {
        let field_5: number;
        export { field_5 as field };
        let max_5: number;
        export { max_5 as max };
        let label_5: string;
        export { label_5 as label };
        let requires_5: string;
        export { requires_5 as requires };
        export { USER_INPUT_MODES as section };
        export let bits: {
            0: string;
            3: string;
        };
        export let note: string;
    }
    namespace storedChallengeMode {
        let field_6: number;
        export { field_6 as field };
        let max_6: number;
        export { max_6 as max };
        let label_6: string;
        export { label_6 as label };
        let requires_6: string;
        export { requires_6 as requires };
        export { USER_INPUT_MODES as section };
    }
    namespace webAgentDeriveMode {
        let field_7: number;
        export { field_7 as field };
        let max_7: number;
        export { max_7 as max };
        let label_7: string;
        export { label_7 as label };
        let requires_7: string;
        export { requires_7 as requires };
        export { USER_INPUT_MODES as section };
        export let choices: {
            0: string;
            1: string;
            2: string;
        };
        let note_1: string;
        export { note_1 as note };
    }
    namespace webcryptPolicy {
        let field_8: number;
        export { field_8 as field };
        let max_8: number;
        export { max_8 as max };
        let label_8: string;
        export { label_8 as label };
        let requires_8: string;
        export { requires_8 as requires };
        export let oneWay: boolean;
        let bits_1: {
            0: string;
            1: string;
        };
        export { bits_1 as bits };
        export let unwritten: number;
        let note_2: string;
        export { note_2 as note };
    }
    namespace modKeyMode {
        let field_9: number;
        export { field_9 as field };
        let max_9: number;
        export { max_9 as max };
        let label_9: string;
        export { label_9 as label };
        let requires_9: string;
        export { requires_9 as requires };
    }
    namespace hmacChallengeMode {
        let field_10: number;
        export { field_10 as field };
        let max_10: number;
        export { max_10 as max };
        let label_10: string;
        export { label_10 as label };
        let requires_10: string;
        export { requires_10 as requires };
        let choices_1: {
            0: string;
            1: string;
        };
        export { choices_1 as choices };
        let note_3: string;
        export { note_3 as note };
    }
    namespace touchSense {
        let field_11: number;
        export { field_11 as field };
        export let min: number;
        let max_11: number;
        export { max_11 as max };
        let label_11: string;
        export { label_11 as label };
        let requires_11: string;
        export { requires_11 as requires };
        let note_4: string;
        export { note_4 as note };
    }
    namespace wipeMode {
        let field_12: number;
        export { field_12 as field };
        let max_12: number;
        export { max_12 as max };
        let label_12: string;
        export { label_12 as label };
        let requires_12: string;
        export { requires_12 as requires };
        let oneWay_1: boolean;
        export { oneWay_1 as oneWay };
        let note_5: string;
        export { note_5 as note };
    }
    namespace backupKeyMode {
        let field_13: number;
        export { field_13 as field };
        let max_13: number;
        export { max_13 as max };
        let label_13: string;
        export { label_13 as label };
        let requires_13: string;
        export { requires_13 as requires };
        let oneWay_2: boolean;
        export { oneWay_2 as oneWay };
        let note_6: string;
        export { note_6 as note };
    }
    namespace secProfileMode {
        let field_14: number;
        export { field_14 as field };
        let max_14: number;
        export { max_14 as max };
        let label_14: string;
        export { label_14 as label };
        let requires_14: string;
        export { requires_14 as requires };
        export let silent: boolean;
        let note_7: string;
        export { note_7 as note };
    }
}
export namespace USER_INPUT_ENUM_ROWS {
    export namespace derivedChallengeMode_1 {
        let max_15: number;
        export { max_15 as max };
        let bits_2: undefined;
        export { bits_2 as bits };
        let choices_2: {
            0: string;
            1: string;
        };
        export { choices_2 as choices };
        let note_8: string;
        export { note_8 as note };
    }
    export { derivedChallengeMode_1 as derivedChallengeMode };
    export namespace storedChallengeMode_1 {
        let max_16: number;
        export { max_16 as max };
        let choices_3: {
            0: string;
            1: string;
        };
        export { choices_3 as choices };
        let note_9: string;
        export { note_9 as note };
    }
    export { storedChallengeMode_1 as storedChallengeMode };
}
/**
 * What fields 21, 22 and 30 become at firmware 3.0.5 - applied over the rows
 * above by preferences(), never instead of them.
 *
 * An OVERLAY rather than a second table, because only the SHAPE changes:
 * the field number, the gate and the label are the same settings either way,
 * and duplicating them is how two descriptions of one byte drift apart.
 *
 * `max` drops from 255 to the largest value the firmware will take, and the
 * bitmask is replaced outright - `bits: undefined` rather than omitted,
 * because a spread leaves an untouched key in place and a stale `bits` would
 * have the screen draw toggles beside the choices.
 *
 * "NONE" IS ON FIELD 30 ONLY. Production firmware refuses 2 on 21 and 22
 * ("Error unsupported user input mode" unless built with OK_ALLOW_NO_PRESS,
 * okcore.cpp:1789-1833 at 3.1.0) and fails a stale one closed to the
 * challenge code, so offering it there could only produce an error the user
 * cannot act on - the notes say why it is missing rather than leaving it
 * silently absent. Field 30 takes 2 on every build (see its row), and its row
 * is already this shape, so it has no entry here.
 *
 * WHAT A NEW KEY STARTS ON is in each note because the key cannot report any
 * of these back: a GUI has nothing to show as "current", and the first-use
 * default (OnlyKey.ino:425-437 at 3.1.0: 21, 22 and 30 all Button Press - "no
 * challenge code required for OnlyKey Agent") is the one thing a user can be
 * told for certain. v3.0.4 does the same for 21 and 22 (OnlyKey.ino:430-433
 * at v3.0.4-prod writes 1 - bit 0, the press), so a GUI's section heading may
 * say it for every line.
 */
/**
 * Fields that DO NOT EXIST before 3.0.5, as against 21 and 22, which exist
 * everywhere and only change shape.
 *
 * v3.0.4's set_slot() has no `case 30` or `case 31` (libraries@c8804e3); both
 * fall to `default: return;` (okcore.cpp:2125) and the key sends NOTHING - no
 * error, no success. sendField() then retries into silence and the caller
 * ends with "unknown", on a write that was never going to land. Offering the
 * row at all is the bug: a v3.0.4 user saw "Browser permissions" (now
 * "Webcrypt Access") and a derive
 * mode, set them, and nothing happened.
 *
 * Gated on userInputModeEnum because that capability IS the 3.0.5 line - both
 * fields arrived with the enum (97c8353, 720abfe) - and a second capability
 * with the same bound would be two names for one fact. An unknown version
 * (locked) hides them, the same safe direction as the reshaping: a row that
 * reappears on unlock costs nothing, a write into silence costs a confused
 * user.
 */
export const ENUM_ONLY_PREFERENCES: Set<string>;
export namespace INPUT_CHOICE {
    let challenge: string;
    let press: string;
    let none: string;
}
export const USER_INPUT_MODES: "User Input Modes";
/**
 * One row, in the shape THIS firmware reads it.
 *
 * The static row with the 3.0.5 enum overlay applied when the capabilities say
 * the fields are enums (see USER_INPUT_ENUM_ROWS for why an overlay). Unknown
 * capabilities - null, or a locked device's `version: null` - give the legacy
 * shape, the same safe direction preferences() has always taken.
 *
 * Returned for an ENUM-ONLY row on any firmware: whether to OFFER it is
 * preferenceRows()'s decision, and whether to REFUSE a write to it is
 * setPreference's; this only says what it looks like.
 *
 * @param {string} name
 * @param {object|null} [capabilities]  version.capabilities(...) or session.capabilities
 * @returns {object|null} `{ name, field, max, ... }`, or null for an unknown name
 */
export function preferenceRow(name: string, capabilities?: object | null): object | null;
/**
 * Every row this firmware has, each in its shape - what a settings screen
 * draws. The rows that do not exist before 3.0.5 are left out unless the
 * capabilities say the enum line (ENUM_ONLY_PREFERENCES says why).
 *
 * @param {object|null} [capabilities]
 * @returns {object[]}
 */
export function preferenceRows(capabilities?: object | null): object[];
