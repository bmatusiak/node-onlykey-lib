/**
 * usb_desc.h interface numbers. The firmware routes replies by these, so they
 * are protocol, not an implementation detail.
 *
 * SEREMU is the debug console and exists only on a DEBUG build - such a device
 * enumerates four interfaces, a production one three. That is what makes the
 * build detectable rather than merely assumed.
 *
 * The per-value casts are so the generated .d.ts says `KEYBOARD: 0` rather than
 * `KEYBOARD: number`. Without them every consumer's interface argument widens to
 * `number` and passing 7 typechecks.
 */
export type Iface = 0 | 1 | 2 | 3;
export namespace MSG {
    let OKPIN: number;
    let OKPINSD: number;
    let OKPINSEC: number;
    let OKCONNECT: number;
    let OKGETLABELS: number;
    let OKSETSLOT: number;
    let OKWIPESLOT: number;
    let OKGETPUBKEY: number;
    let OKSIGN: number;
    let OKWIPEPRIV: number;
    let OKSETPRIV: number;
    let OKDECRYPT: number;
    let OKRESTORE: number;
    let OKGETRESPONSE: number;
    let OKPING: number;
    let OKFWUPDATE: number;
    let OKHMAC: number;
    let OKWEBAUTHN: number;
}
export namespace MSG_ALIASES {
    import OKSETPIN = MSG.OKPIN;
    export { OKSETPIN };
    import OKSETSDPIN = MSG.OKPINSD;
    export { OKSETSDPIN };
    import OKSETPIN2 = MSG.OKPINSEC;
    export { OKSETPIN2 };
    import OKSETTIME = MSG.OKCONNECT;
    export { OKSETTIME };
}
/** Reverse lookup, for turning a captured byte back into something readable. */
export const MSG_NAMES: {};
export namespace PIN_KIND {
    import primary = MSG.OKPIN;
    export { primary };
    import secondary = MSG.OKPINSEC;
    export { secondary };
    import selfDestruct = MSG.OKPINSD;
    export { selfDestruct };
}
export namespace FIELD {
    let LABEL: number;
    let USERNAME: number;
    let NEXTKEY2: number;
    let DELAY2: number;
    let PASSWORD: number;
    let NEXTKEY3: number;
    let DELAY3: number;
    let TFATYPE: number;
    let TFAUSERNAME: number;
    let YUBIAUTH: number;
    let LOCKOUT: number;
    let WIPEMODE: number;
    let TYPESPEED: number;
    let KBDLAYOUT: number;
    let URL: number;
    let NEXTKEY1: number;
    let DELAY1: number;
    let NEXTKEY4: number;
    let NEXTKEY5: number;
    let BACKUPKEYMODE: number;
    let derivedchallengeMode: number;
    let storedchallengeMode: number;
    let SECPROFILEMODE: number;
    let LEDBRIGHTNESS: number;
    let LOCKBUTTON: number;
    let hmacchallengeMode: number;
    let modkeyMode: number;
    let TOUCHSENSE: number;
    let YUBIANDHMAC: number;
    let webAgentDeriveMode: number;
}
export namespace FIELD_ALIASES {
    import DERIVEDCHALLENGEMODE = FIELD.derivedchallengeMode;
    export { DERIVEDCHALLENGEMODE };
    import STOREDCHALLENGEMODE = FIELD.storedchallengeMode;
    export { STOREDCHALLENGEMODE };
    import HMACCHALLENGEMODE = FIELD.hmacchallengeMode;
    export { HMACCHALLENGEMODE };
    import MODKEYMODE = FIELD.modkeyMode;
    export { MODKEYMODE };
    import WEBAGENTDERIVEMODE = FIELD.webAgentDeriveMode;
    export { WEBAGENTDERIVEMODE };
}
export namespace KEY_TYPE_MODIFIER {
    let Backup: number;
    let Signature: number;
    let Decryption: number;
}
export namespace KEYTYPE {
    let NACL: number;
    let P256R1: number;
    let P256K1: number;
    let CURVE25519: number;
}
export namespace KEYACTION {
    let DERIVE_PUBLIC_KEY: number;
    let DERIVE_SHARED_SECRET: number;
    let DERIVE_PUBLIC_KEY_REQ_PRESS: number;
    let DERIVE_SHARED_SECRET_REQ_PRESS: number;
}
export namespace IFACE {
    let KEYBOARD: 0;
    let FIDO: 1;
    let VENDOR: 2;
    let SEREMU: 3;
}
/** Resolve a message by name (either spelling) or by number. */
export function messageId(msg: any): any;
/** Resolve a field by name (exact, then upper-case alias) or by number. */
export function fieldId(field: any): any;
