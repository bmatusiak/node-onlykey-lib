export class FidoAdmin {
    /**
     * @param {import('../protocol/ctaphid').CtapHid} ctap  a channel that has
     *        already been through init()
     *
     * The CHANNEL IS REUSED rather than re-allocated per call. The firmware
     * keeps ten channel records and never frees one (ctaphid.cpp:67), so a
     * client that calls init() before each operation exhausts them and then
     * gets somebody else's.
     */
    constructor(ctap: import("../protocol/ctaphid").CtapHid);
    ctap: import("../protocol/ctaphid").CtapHid;
    /** The authenticator's own description of itself. */
    getInfo(opts?: {}): Promise<Map<any, any>>;
    /**
     * Is a PIN already set?
     *
     * getInfo's options map carries `clientPin`: absent means the authenticator
     * has no PIN support, false means supported but unset, true means set. That
     * three-way answer is what decides setPin against changePin - the firmware
     * answers CTAP2_ERR_NOT_ALLOWED for a setPin on a key that has one
     * (ctap.cpp:2255) and CTAP2_ERR_PIN_NOT_SET for the reverse (ctap.cpp:2271),
     * so guessing wastes a round trip and muddies the error a user sees.
     */
    pinState(opts?: {}): Promise<{
        supported: boolean;
        set: boolean;
        protocols: any;
        info: Map<any, any>;
    }>;
    /** One clientPin subcommand. */
    _clientPin(params: any, opts: any): Promise<any>;
    /**
     * Attempts remaining before FIDO2 locks permanently.
     *
     * Free: it takes no PIN, touches no counter, and needs no user presence.
     * Everything below calls it first for that reason.
     */
    getRetries(opts?: {}): Promise<number>;
    /**
     * A fresh platform key pair and the shared secret for ONE attempt.
     *
     * Never cached. See the header: the authenticator throws its half away on
     * every PIN failure, so a shared secret is good for exactly one try and
     * reusing one spends a second attempt discovering that.
     */
    _agree(opts: any): Promise<{
        platformKey: {
            secretKey: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
            publicKey: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
            coseKey: Map<number, any>;
        };
        secret: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
    }>;
    /**
     * Refuse to spend the last life without being told to.
     *
     * A caller that has a PIN it believes in can pass `allowLastAttempt`. The
     * default is to stop at one remaining, because the usual reason to be at
     * one is that the PIN in hand is wrong.
     */
    _guard(opts: any): Promise<number>;
    /**
     * Set a PIN on a key that has none.
     *
     * No attempt is spent by a setPin: there is no current PIN to be wrong
     * about. The state check is still done first, because a setPin against a
     * key that HAS a PIN is a caller error worth naming rather than a bare
     * CTAP2_ERR_NOT_ALLOWED.
     */
    setPin(newPin: any, opts?: {}): Promise<boolean>;
    /**
     * Change a PIN, proving the current one. THIS SPENDS AN ATTEMPT if wrong.
     */
    changePin(currentPin: any, newPin: any, opts?: {}): Promise<boolean>;
    /**
     * Exchange the PIN for a token, which is what credential management and a
     * PIN-protected makeCredential authenticate with.
     *
     * The token lives until the device reboots or the PIN changes; a caller
     * keeps it for the session rather than asking for the PIN again.
     */
    getPinToken(pin: any, opts?: {}): Promise<Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>>;
    /**
     * Turn a CTAP2 status into something with the remaining count in it.
     *
     * "CTAP2 error 0x31" tells a user nothing and tells them nothing about the
     * thing that matters, which is how many tries are left. The count is
     * re-read AFTER the failure, because that is the number the next attempt
     * will face.
     */
    _describe(error: any, before: any, opts: any): Promise<any>;
    /**
     * Erase the FIDO2 key space and every resident credential.
     *
     * @param {string} confirmation  must equal RESET_CONFIRMATION
     *
     * ONE BUTTON PRESS is the only thing between this and a wiped
     * authenticator. The spec asks for a reset to be refused more than ten
     * seconds after powerup; this firmware does not implement that window
     * (ctap.cpp:2417-2424), so there is no accidental-command protection at the
     * device end at all and the protection has to live here.
     *
     * Every passkey on the key stops working. Accounts where it is the only
     * second factor become unreachable. Nothing in this library calls it.
     */
    reset(confirmation: string, opts?: {}): Promise<boolean>;
}
export namespace INFO {
    let VERSIONS: number;
    let EXTENSIONS: number;
    let AAGUID: number;
    let OPTIONS: number;
    let MAX_MSG_SIZE: number;
    let PIN_PROTOCOLS: number;
}
/**
 * The word a caller has to pass to reset(). Not a boolean: a stray `true`
 * is one keystroke, and this is the one call that cannot be undone.
 */
export const RESET_CONFIRMATION: "ERASE MY CREDENTIALS";
