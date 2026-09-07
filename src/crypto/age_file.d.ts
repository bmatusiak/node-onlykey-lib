export function sealFileKey(sharedSecret: any, enc: any, fileKey: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function openFileKey(sharedSecret: any, enc: any, sealedFileKey: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function encryptAgeFile(plaintext: any, { ciphertext, sharedSecret }: {
    ciphertext: any;
    sharedSecret: any;
}): Uint8Array<any>;
export function decryptAgeFile(fileBytes: any, deriveSharedSecret: any): Promise<Uint8Array<any>>;
