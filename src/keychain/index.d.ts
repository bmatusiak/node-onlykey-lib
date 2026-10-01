export declare let tag: typeof import("./tag");
declare let _export: {
    encryptedPgp: (privateKey: import("../vendor/openpgp/openpgp").PrivateKey, passphrase: string, { confirm, openpgp }?: {
        confirm?: string | null;
        openpgp: any;
    }) => Promise<string>;
    encryptedPem: typeof import("../crypto/pkcs8").encryptedPem;
};
export { _export as export };
export declare let generate: typeof import("./generate");
