/**
 * Parse an OpenSSH private key (the armoured text) into sshpk's shape.
 *
 * @param {string} text  "-----BEGIN OPENSSH PRIVATE KEY-----" … "-----END …"
 * @returns {{type: 'ed25519'|'ecdsa'|'rsa', curve?: string, comment: string, part: object}}
 */
export function parsePrivateKey(text: string): {
    type: "ed25519" | "ecdsa" | "rsa";
    curve?: string;
    comment: string;
    part: object;
};
