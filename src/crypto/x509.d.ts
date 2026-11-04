/**
 * The certificate, signed: DER bytes.
 * @param {object} o
 * @param {Uint8Array} o.modulus      the RSA key's modulus (big-endian), as the key answers it
 * @param {number} [o.exponent]       65537
 * @param {{CN: string, O?: string, OU?: string, C?: string}} o.subject  also its issuer (self-signed)
 * @param {Date} [o.notBefore]        now
 * @param {number} [o.days]           how long it is valid: 30 years (Google Play asks an app's key to outlast 2033)
 * @param {'sha256'|'sha512'} [o.hash] sha512 for a key over 3072 bits, else sha256
 * @param {Uint8Array} [o.serial]     16 random bytes
 * @param {(digest: Uint8Array) => Promise<Uint8Array>|Uint8Array} o.sign  the key's PKCS#1 v1.5 signature over this digest
 * @returns {Promise<Uint8Array>}
 */
export function selfSigned({ modulus, exponent, subject, notBefore, days, hash, serial, sign }: {
    modulus: Uint8Array;
    exponent?: number | undefined;
    subject: {
        CN: string;
        O?: string;
        OU?: string;
        C?: string;
    };
    notBefore?: Date | undefined;
    days?: number | undefined;
    hash?: "sha256" | "sha512" | undefined;
    serial?: Uint8Array<ArrayBufferLike> | undefined;
    sign: (digest: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}): Promise<Uint8Array>;
/** DER -> PEM ("CERTIFICATE"), 64 characters a line */
export function toPem(der: any): string;
/** SubjectPublicKeyInfo for an RSA key: {rsaEncryption, NULL} and RSAPublicKey {n, e} */
export function rsaPublicKeyInfo(modulus: any, exponent?: number): Uint8Array<ArrayBuffer>;
export function name(n: any): Uint8Array<ArrayBuffer>;
export namespace OID {
    let rsaEncryption: string;
    let sha256WithRSAEncryption: string;
    let sha512WithRSAEncryption: string;
    let countryName: string;
    let organizationName: string;
    let organizationalUnitName: string;
    let commonName: string;
}
