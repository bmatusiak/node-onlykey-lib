/** The standard command byte, and the preview one this firmware also takes. */
export const COMMAND: 10;
export const COMMAND_PREVIEW: 65;
export namespace PARAM {
    let SUB_COMMAND: number;
    let SUB_COMMAND_PARAMS: number;
    let PIN_PROTOCOL: number;
    let PIN_AUTH: number;
}
export namespace SUB {
    let METADATA: number;
    let RP_BEGIN: number;
    let RP_NEXT: number;
    let RK_BEGIN: number;
    let RK_NEXT: number;
    let RK_DELETE: number;
}
export namespace SUB_PARAM {
    let RP_ID_HASH: number;
    let CREDENTIAL_ID: number;
}
export namespace RESP {
    export let EXISTING_RESIDENT_CREDENTIALS: number;
    export let MAX_POSSIBLE_REMAINING: number;
    export let RP: number;
    let RP_ID_HASH_1: number;
    export { RP_ID_HASH_1 as RP_ID_HASH };
    export let TOTAL_RPS: number;
    export let USER: number;
    let CREDENTIAL_ID_1: number;
    export { CREDENTIAL_ID_1 as CREDENTIAL_ID };
    export let PUBLIC_KEY: number;
    export let TOTAL_CREDENTIALS: number;
    export let CRED_PROTECT: number;
}
/**
 * The bytes a credMgmt pinAuth is computed over.
 *
 * The subcommand byte, then the subCommandParams map EXACTLY as encoded
 * (ctap.cpp:1607, hashing `{cmd, subCommandParamsCborCopy}` for
 * `size + 1` bytes). The firmware keeps the raw span from the parser
 * (ctap_parse.cpp:1086-1095), so what it hashes is the bytes that arrived -
 * not a re-encoding. Two encoders that disagree by one integer width would
 * produce a valid HMAC of a different message, and the counter would pay for
 * it.
 *
 * Commands with no params hash one byte: the subcommand.
 */
export function pinAuthMessage(subCommand: any, paramsBytes?: null): Uint8Array<ArrayBuffer>;
/**
 * Build one credential-management request.
 *
 * @param {number} subCommand    SUB.*
 * @param {Uint8Array} pinToken  from clientpin.readPinToken
 * @param {Map} [params]         subCommandParams, or null
 *
 * The params map is encoded ONCE and both sent and authenticated from those
 * same bytes, which is the whole point - see pinAuthMessage.
 */
export function request(subCommand: number, pinToken: Uint8Array, params?: Map<any, any>): Map<number, number>;
/** How many resident credentials are stored, and how many more fit. */
export function metadataParams(pinToken: any): Map<number, number>;
/** Start walking the relying parties. */
export function rpBeginParams(pinToken: any): Map<number, number>;
/** The next relying party. NO pinAuth - the walk is already authenticated. */
export function rpNextParams(): Map<number, number>;
/**
 * Start walking the credentials of one relying party.
 *
 * @param {Uint8Array} rpIdHash  SHA-256 of the rpId, 32 bytes. It comes back
 *                               from the RP walk (RESP.RP_ID_HASH), which is
 *                               where a caller should get it - hashing an
 *                               rpId by hand is how a client ends up walking
 *                               a site it only thinks it named.
 */
export function rkBeginParams(pinToken: any, rpIdHash: Uint8Array): Map<number, number>;
/** The next credential. NO pinAuth. */
export function rkNextParams(): Map<number, number>;
/**
 * Delete one credential, BY ID.
 *
 * @param {Map} credentialId  the descriptor exactly as it came back from the
 *                            credential walk (RESP.CREDENTIAL_ID) - a map of
 *                            `id` and `type`
 *
 * By id and never by index, and re-read immediately before: the enumeration
 * cursors are firmware statics shared across channels, so an index from an
 * earlier pass can name a different credential by the time it is used. This
 * one is irreversible and there is no confirmation at the device.
 */
export function rkDeleteParams(pinToken: any, credentialId: Map<any, any>): Map<number, number>;
/**
 * @returns {{stored: number, remaining: number}}
 *
 * ZERO IS AN ANSWER, not a failure. A key with no resident credentials
 * returns success with an empty body for every OTHER subcommand
 * (ctap.cpp:1754) - metadata is the exception that still answers properly,
 * which is why it is the right thing to ask first.
 */
export function readMetadata(response: any): {
    stored: number;
    remaining: number;
};
/**
 * One relying party from the walk.
 *
 * @returns {{id: string, name: string, rpIdHash: Uint8Array, total: number|null}|null}
 *
 * `total` is present only on the FIRST answer of a walk (ctap.cpp:1526-1530
 * adds it when rp_count > 0), so a caller counts down from it rather than
 * expecting it every time.
 */
export function readRp(response: any): {
    id: string;
    name: string;
    rpIdHash: Uint8Array;
    total: number | null;
} | null;
/**
 * One credential from the walk.
 *
 * @returns {{user: Map|null, credentialId: Map|null, publicKey: Map|null,
 *            total: number|null, credProtect: number|null}|null}
 *
 * `credentialId` is handed back as the MAP it arrived as, because that is
 * what a delete has to send back. Rebuilding it from its parts is how a
 * client deletes something it did not mean to.
 */
export function readCredential(response: any): {
    user: Map<any, any> | null;
    credentialId: Map<any, any> | null;
    publicKey: Map<any, any> | null;
    total: number | null;
    credProtect: number | null;
} | null;
/** The readable name of a credential's user, for a list on a screen. */
export function describeUser(user: any): string;
