/** What is_extension_request() looks for at offset 4. */
export const MAGIC: number[];
export const HEADER: 10;
/** is_extension_request() ignores anything with a shorter data region. */
export const MIN_DATA: 16;
/** HEADER + payload must fit one byte. */
export const MAX_PAYLOAD: 245;
/**
 * The relying-party id, and it is NOT a hosting detail.
 *
 * okcrypto_hkdf() folds the RPID into the key derivation
 * (okcrypto.cpp:245 `const char rpid[] = "onlyagent.app"`, checked against the
 * incoming appid at device.cpp:112). The same OnlyKey at a different origin
 * therefore derives DIFFERENT KEYS, with no error at any layer - it surfaces
 * much later as "no identity matched any of the recipients".
 *
 * The browser client never sets this: both `rpId` and the appid extension are
 * commented out, so WebAuthn falls back to the page origin, which happens to
 * be onlyagent.app only because BUILD.sh writes that CNAME. This library
 * drives CTAP2 directly and so must state it. Overriding it is deliberate and
 * loud for that reason.
 */
export const RP_ID: "onlyagent.app";
/**
 * CTAP status codes, transcribed from onlykey.extra.js:245-292.
 *
 * The full table, not the 9-entry CTAP1 subset in onlykey-testing's tunnel.js:
 * the polling loop keys off the *names* CTAP1_SUCCESS,
 * CTAP2_ERR_USER_ACTION_PENDING and CTAP2_ERR_EXTENSION_NOT_SUPPORTED, and a
 * short table renders those as a bare hex string that no branch matches.
 *
 * Byte 0 of the signature is a CTAP1/U2F code, not the CTAP2 code the
 * surrounding assertion carries.
 */
export const STATUS: {
    0: string;
    1: string;
    2: string;
    3: string;
    4: string;
    5: string;
    6: string;
    10: string;
    11: string;
    16: string;
    17: string;
    18: string;
    19: string;
    20: string;
    21: string;
    22: string;
    23: string;
    24: string;
    25: string;
    32: string;
    33: string;
    34: string;
    35: string;
    36: string;
    37: string;
    38: string;
    39: string;
    40: string;
    41: string;
    42: string;
    43: string;
    44: string;
    45: string;
    46: string;
    47: string;
    48: string;
    49: string;
    50: string;
    51: string;
    52: string;
    53: string;
    54: string;
    55: string;
    56: string;
    57: string;
};
/** The only status that carries a payload. See chunk.js for why that matters. */
export const SUCCESS: "CTAP1_SUCCESS";
export function statusName(code: any): any;
/**
 * Encode a vendor request as a fake credential ID.
 *
 *   [0]      cmd
 *   [1..3]   opt1, opt2, opt3
 *   [4..7]   8C 27 90 F6   the vendor magic
 *   [8]      0
 *   [9]      the REAL payload length, not the padded size
 *   [10..]   payload, zero-padded so the data region is at least 16 bytes
 */
export function encodeRequest({ cmd, opt1, opt2, opt3, data }: {
    cmd: any;
    opt1?: number | undefined;
    opt2?: number | undefined;
    opt3?: number | undefined;
    data: any;
}): Uint8Array<ArrayBuffer>;
/**
 * Decode a CTAP2 getAssertion response.
 *
 * @param {Map} assertion  the decoded CBOR map: 2 = authData, 3 = signature
 * @returns {{status: string, code: number, data: Uint8Array|null,
 *            error: string|null, count: number|null}}
 *
 * The whole answer rides in the signature: byte 0 is the status, the rest is
 * the payload. `data` is null when the signature is just the status byte -
 * and that is not a rare case. Dereferencing it unguarded inside a .then() is
 * how the shipped client stranded its promise, leaving a WebAuthn prompt on
 * screen forever (onlykey-api.js:295-303).
 */
export function decodeAssertion(assertion: Map<any, any>): {
    status: string;
    code: number;
    data: Uint8Array | null;
    error: string | null;
    count: number | null;
};
/** CTAP2 authenticatorGetAssertion parameters for a tunnelled request. */
export function assertionParams(credentialId: any, { rpId, clientDataHash }?: {
    rpId?: string | undefined;
}): Map<number, any>;
