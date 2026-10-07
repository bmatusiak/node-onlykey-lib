export const LABEL_TYPES: Readonly<{
    p256: 1;
    secp256k1: 2;
    x25519: 3;
}>;
export const AGENT_TYPES: Readonly<{
    ed25519: 1;
    p256: 2;
}>;
/**
 * @param {any} okcrypto the okcrypto service (app.services.okcrypto)
 * @param {{scheme: 'label'|'ssh'|'gpg', label: string, type: string,
 *   version?: 1|2, requirePress?: boolean, comment?: string, now?: () => Date}} spec
 * @returns {Promise<{kind: 'derived', scheme: string, label: string, type: string,
 *   version?: number, publicKey: Uint8Array, artifacts: object, created: string}>}
 */
export function derivePublic(okcrypto: any, spec: {
    scheme: "label" | "ssh" | "gpg";
    label: string;
    type: string;
    version?: 1 | 2;
    requirePress?: boolean;
    comment?: string;
    now?: () => Date;
}): Promise<{
    kind: "derived";
    scheme: string;
    label: string;
    type: string;
    version?: number;
    publicKey: Uint8Array;
    artifacts: object;
    created: string;
}>;
