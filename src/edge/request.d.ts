export const TYPE: "EDGE_REQUEST";
export const REGISTER_TYPE: "EDGE_REGISTER";
export const MAX_REQUEST_USES: 300;
export const MAX_LIFETIME_MINUTES: number;
export const REFUSALS: readonly string[];
export function body({ agent, nonce, reason, scopes, lifetime, continue: cont }: {
    agent: any;
    nonce: any;
    reason: any;
    scopes: any;
    lifetime: any;
    continue: any;
}): Uint8Array<any>;
/**
 * The agent side: a signed request. signer: {publicKey: 32 bytes,
 * sign(bytes) -> 64 bytes (sync or async)} - the agent service's own key.
 */
export function build({ signer, reason, scopes, lifetime, continueOf, nonce }: {
    signer: any;
    reason: any;
    scopes: any;
    lifetime: any;
    continueOf?: null | undefined;
    nonce?: (Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) | undefined;
}): Promise<{
    continue?: undefined;
    type: string;
    v: number;
    agent: string;
    nonce: string;
    reason: string;
    scopes: any;
    lifetime: any;
}>;
export function signerFromSecret(secret: any): {
    publicKey: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
    sign: (bytes: any) => Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
};
/**
 * The app side, first: is it a request from a registered agent, signed, and
 * new? registered: agent public keys (hex) the person registered with a press;
 * seen: the nonces already taken (a Set the app keeps). -> {ok} or {ok: false,
 * reason: 'malformed' | 'unregistered' | 'bad-signature' | 'replayed'}. An app
 * DROPS these - it answers nothing.
 */
export function verify(msg: any, { registered, seen }: {
    registered: any;
    seen: any;
}): {
    ok: boolean;
    reason: string;
} | {
    ok: boolean;
    reason?: undefined;
};
/**
 * The app side, second: is the request one a budget may be? Caps (each >= 1,
 * together <= 300, D4), the lifetime (1 minute .. 24 hours), the ops, and an
 * identity on every derived code (R11a) that parses. -> {ok} or {ok: false, reason}.
 */
export function check(msg: any): {
    ok: boolean;
    reason: any;
    uses?: undefined;
} | {
    ok: boolean;
    uses: number;
    reason?: undefined;
};
export function grantScopes(msg: any): any;
export function reasonHash(reason: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/**
 * What the approval sheet shows: the text, the names, the caps, the lifetime,
 * who asks. ownIdentities: the person's own identity names (ok-rn's list,
 * starting with ssh://bmatusiak@localhost) - a scope naming one is marked own,
 * and the sheet shows a red warning and asks a second confirm (Brad, 2026-10-03).
 */
export function view(msg: any, { ownIdentities, covered }?: {
    ownIdentities?: never[] | undefined;
    covered?: never[] | undefined;
}): {
    agent: any;
    reason: any;
    lifetime: any;
    uses: any;
    scopes: any;
    ownWarning: any;
    continues: any;
    covered: any[];
};
export function sameScopes(a: any, b: any): any;
export function registerBody({ agent, nonce, name }: {
    agent: any;
    nonce: any;
    name: any;
}): Uint8Array<any>;
/** The agent side: ask to be registered, under a name the person reads. */
export function buildRegister({ signer, name, nonce }: {
    signer: any;
    name: any;
    nonce?: (Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) | undefined;
}): Promise<{
    type: string;
    v: number;
    agent: string;
    name: string;
    nonce: string;
}>;
/** The app side: a registration signed by the key it names, and new. -> {ok} or {ok: false, reason} */
export function verifyRegister(msg: any, { seen }?: {}): {
    ok: boolean;
    reason: string;
} | {
    ok: boolean;
    reason?: undefined;
};
export function fingerprint(agentHex: any): string;
export const PEER_TYPE: "EDGE_PEER_ADD";
export function peerBody({ peer, nonce, name }: {
    peer: any;
    nonce: any;
    name: any;
}): Uint8Array<any>;
/** The place's side: ask the phone to add it, under a name the person reads. signer: peerSignerFromSecret. */
export function buildPeerAdd({ signer, name, nonce }: {
    signer: any;
    name: any;
    nonce?: (Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) | undefined;
}): Promise<{
    type: string;
    v: number;
    peer: string;
    name: string;
    nonce: string;
}>;
/** The app's side: signed by the key it names, and new. -> {ok} or {ok: false, reason} */
export function verifyPeerAdd(msg: any, { seen }?: {}): {
    ok: boolean;
    reason: string;
} | {
    ok: boolean;
    reason?: undefined;
};
export function peerSignerFromSecret(secret: any): {
    publicKey: Uint8Array<ArrayBuffer>;
    sign: (bytes: any) => Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
};
