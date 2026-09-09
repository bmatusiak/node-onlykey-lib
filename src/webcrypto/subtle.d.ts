export function createSubtle(): {
    digest(algorithm: any, data: any): Promise<any>;
    importKey(format: any, keyData: any, algorithm: any, extractable: any, usages: any): Promise<{
        type: any;
        algorithm: any;
        extractable: any;
        usages: any;
        _material: any;
    }>;
    exportKey(format: any, key: any): Promise<any>;
    generateKey(algorithm: any, extractable: any, usages: any): Promise<{
        type: any;
        algorithm: any;
        extractable: any;
        usages: any;
        _material: any;
    } | {
        privateKey: {
            type: any;
            algorithm: any;
            extractable: any;
            usages: any;
            _material: any;
        };
        publicKey: {
            type: any;
            algorithm: any;
            extractable: any;
            usages: any;
            _material: any;
        };
    }>;
    encrypt(algorithm: any, key: any, data: any): Promise<any>;
    decrypt(algorithm: any, key: any, data: any): Promise<any>;
    sign(algorithm: any, key: any, data: any): Promise<any>;
    verify(algorithm: any, key: any, signature: any, data: any): Promise<any>;
    deriveBits(algorithm: any, key: any, length: any): Promise<any>;
    wrapKey(format: any, key: any, wrappingKey: any, wrapAlgorithm: any): Promise<any>;
    unwrapKey(format: any, wrapped: any, unwrappingKey: any, unwrapAlgorithm: any, unwrappedKeyAlgorithm: any, extractable: any, usages: any): Promise<{
        type: any;
        algorithm: any;
        extractable: any;
        usages: any;
        _material: any;
    }>;
};
/**
 * Put the shim on `globalThis.crypto.subtle`, if there is nothing better there.
 *
 * @param {object} [opts]
 * @param {boolean} [opts.force=false] replace a real SubtleCrypto. Almost
 *   always wrong: a platform's own implementation is more complete and better
 *   tested than this one. Provided for tests that want to exercise the shim
 *   where a real one exists.
 * @returns {{installed: boolean, reason: string}}
 */
export function install({ force }?: {
    force?: boolean | undefined;
}): {
    installed: boolean;
    reason: string;
};
export const HASHES: {
    'SHA-1': {
        outputLen: number;
        blockLen: number;
        canXOF: boolean;
    } & import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).HashInfo & {
        (msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array>): import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
        create(): import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).Hash<any>;
    } & ((msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array<ArrayBufferLike>>>) => Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) & {
        outputLen: number;
        blockLen: number;
        canXOF: boolean;
        oid?: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array> | undefined;
        create: () => import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).Hash<any>;
    };
    'SHA-224': {
        outputLen: number;
        blockLen: number;
        canXOF: boolean;
    } & import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).HashInfo & {
        (msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array>): import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
        create(): import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA224;
    } & ((msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array<ArrayBufferLike>>>) => Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) & {
        outputLen: number;
        blockLen: number;
        canXOF: boolean;
        oid?: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array> | undefined;
        create: () => import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA224;
    };
    'SHA-256': {
        outputLen: number;
        blockLen: number;
        canXOF: boolean;
    } & import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).HashInfo & {
        (msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array>): import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
        create(): import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA256;
    } & ((msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array<ArrayBufferLike>>>) => Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) & {
        outputLen: number;
        blockLen: number;
        canXOF: boolean;
        oid?: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array> | undefined;
        create: () => import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA256;
    };
    'SHA-384': {
        outputLen: number;
        blockLen: number;
        canXOF: boolean;
    } & import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).HashInfo & {
        (msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array>): import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
        create(): import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA384;
    } & ((msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array<ArrayBufferLike>>>) => Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) & {
        outputLen: number;
        blockLen: number;
        canXOF: boolean;
        oid?: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array> | undefined;
        create: () => import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA384;
    };
    'SHA-512': {
        outputLen: number;
        blockLen: number;
        canXOF: boolean;
    } & import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).HashInfo & {
        (msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array>): import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
        create(): import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA512;
    } & ((msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array<ArrayBufferLike>>>) => Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) & {
        outputLen: number;
        blockLen: number;
        canXOF: boolean;
        oid?: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array> | undefined;
        create: () => import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA512;
    };
};
export const CURVES: {
    'P-256': {
        curve: import("@noble/curves/abstract/weierstrass.js", { with: { "resolution-mode": "import" } }).ECDSA;
        bytes: number;
        hash: {
            outputLen: number;
            blockLen: number;
            canXOF: boolean;
        } & import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).HashInfo & {
            (msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array>): import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
            create(): import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA256;
        } & ((msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array<ArrayBufferLike>>>) => Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) & {
            outputLen: number;
            blockLen: number;
            canXOF: boolean;
            oid?: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array> | undefined;
            create: () => import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA256;
        };
        crv: string;
    };
    'P-384': {
        curve: import("@noble/curves/abstract/weierstrass.js", { with: { "resolution-mode": "import" } }).ECDSA;
        bytes: number;
        hash: {
            outputLen: number;
            blockLen: number;
            canXOF: boolean;
        } & import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).HashInfo & {
            (msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array>): import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
            create(): import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA384;
        } & ((msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array<ArrayBufferLike>>>) => Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) & {
            outputLen: number;
            blockLen: number;
            canXOF: boolean;
            oid?: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array> | undefined;
            create: () => import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA384;
        };
        crv: string;
    };
    'P-521': {
        curve: import("@noble/curves/abstract/weierstrass.js", { with: { "resolution-mode": "import" } }).ECDSA;
        bytes: number;
        hash: {
            outputLen: number;
            blockLen: number;
            canXOF: boolean;
        } & import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).HashInfo & {
            (msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array>): import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
            create(): import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA512;
        } & ((msg: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TArg<Uint8Array<ArrayBufferLike>>>) => Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>) & {
            outputLen: number;
            blockLen: number;
            canXOF: boolean;
            oid?: import("@noble/hashes/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array> | undefined;
            create: () => import("@noble/hashes/sha2.js", { with: { "resolution-mode": "import" } })._SHA512;
        };
        crv: string;
    };
};
