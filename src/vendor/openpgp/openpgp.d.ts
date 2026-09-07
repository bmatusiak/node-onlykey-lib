/*
 * Hand-written, unlike every other .d.ts in this package.
 *
 * The rest are generated from JSDoc by `npm run types`. This one cannot be:
 * openpgp.js is a 1.2 MB generated bundle with no JSDoc, and tsc infers
 * `declare var openpgp: {}` from it - which types the whole PGP surface as an
 * empty object and makes every property access an error under `strict`.
 *
 * Because a .d.ts sitting next to a .js takes precedence as the type source,
 * this file also stops the generator from overwriting it. Do not delete it
 * expecting `npm run types` to produce something better.
 *
 * It covers the surface this library uses, not all of OpenPGP.js. Add to it
 * when you use more; an unlisted member is a compile error rather than a
 * silent `any`, which is the point.
 */

declare namespace openpgp {
  /* ------------------------------------------------------ hardware hooks */

  /**
   * Return `null` or `undefined` from any hook to fall through to the software
   * path. `ecdh` and `mlkemDecaps` fire only for keys built by
   * `createHardwarePrivateKey`; `signer` fires unconditionally whenever it is
   * registered, which is why `generateCompositeKey` clears hooks before
   * generating - a stale signer would hijack the new key's self-signature.
   */
  interface HardwareHooks {
    signer?: (
      algo: number,
      data: Uint8Array,
      keyMaterial?: unknown,
    ) => Promise<Uint8Array | null | undefined>;
    decryptor?: (
      algo: number,
      data: Uint8Array,
    ) => Promise<Uint8Array | null | undefined>;
    /** Classical half of composite decryption; gets the sender's 32-byte point. */
    ecdh?: (
      algo: number,
      ephemeralPublicKey: Uint8Array,
    ) => Promise<Uint8Array | null | undefined>;
    /** Post-quantum half; gets the 1088-byte ML-KEM-768 ciphertext. */
    mlkemDecaps?: (
      algo: number,
      mlkemCipherText: Uint8Array,
    ) => Promise<Uint8Array | null | undefined>;
  }

  function setHardwareHooks(hooks: HardwareHooks): void;
  function clearHardwareHooks(): void;

  /**
   * Builds a PrivateKey from a real PublicKey - correct fingerprint, key id and
   * algorithm - whose secret packets are marked decrypted with placeholder
   * params tagged `isHardwareBacked`. This is what lets ordinary
   * `decrypt()`/`sign()` route through the hooks with no packet surgery.
   */
  function createHardwarePrivateKey(publicKey: PublicKey): PrivateKey;

  /* --------------------------------------------------------------- keys */

  interface Key {
    getKeyID(): unknown;
    getFingerprint(): string;
    armor(): string;
    toPublic(): PublicKey;
    getUserIDs(): string[];
  }
  interface PublicKey extends Key {}
  interface PrivateKey extends Key {
    isDecrypted(): boolean;
  }

  function readKey(options: {
    armoredKey?: string;
    binaryKey?: Uint8Array;
  }): Promise<Key>;
  function readKeys(options: {
    armoredKeys?: string;
    binaryKeys?: Uint8Array;
  }): Promise<Key[]>;
  function readPrivateKey(options: {
    armoredKey?: string;
    binaryKey?: Uint8Array;
  }): Promise<PrivateKey>;
  function decryptKey(options: {
    privateKey: PrivateKey;
    passphrase: string | string[];
  }): Promise<PrivateKey>;
  function generateKey(options: Record<string, unknown>): Promise<{
    privateKey: string | PrivateKey;
    publicKey: string | PublicKey;
    revocationCertificate: string;
  }>;
  function revokeKey(options: Record<string, unknown>): Promise<unknown>;

  /* ----------------------------------------------------------- messages */

  interface Message<T = unknown> {
    getText(): string;
    getLiteralData(): Uint8Array | null;
    armor(): string;
  }

  function createMessage(options: {
    text?: string;
    binary?: Uint8Array;
    filename?: string;
    date?: Date;
    format?: string;
  }): Promise<Message>;
  function readMessage(options: {
    armoredMessage?: string;
    binaryMessage?: Uint8Array;
  }): Promise<Message>;
  function createCleartextMessage(options: {text: string}): Promise<unknown>;
  function readCleartextMessage(options: {
    cleartextMessage: string;
  }): Promise<unknown>;

  function encrypt(options: Record<string, unknown>): Promise<string | Uint8Array>;
  function decrypt(options: Record<string, unknown>): Promise<{
    data: string | Uint8Array;
    signatures: unknown[];
    filename?: string;
  }>;
  function sign(options: Record<string, unknown>): Promise<string | Uint8Array>;
  function verify(options: Record<string, unknown>): Promise<{
    data: string | Uint8Array;
    signatures: unknown[];
  }>;

  function armor(type: number, body: unknown): string;
  function unarmor(input: string): Promise<unknown>;

  /* -------------------------------------------------------------- enums */

  /**
   * `pqc_mlkem_x25519` is 35 and `pqc_mldsa_ed25519` is 30, per IANA and
   * draft-ietf-openpgp-pqc-10. The fork as received used 105 and 107, from the
   * private-use range. The algorithm id is an input to the key combiner, so
   * these values are load-bearing, not labels - see VENDORED.md and
   * test/openpgp-vendor.test.js, which pins them.
   */
  const enums: {
    publicKey: {
      pqc_mlkem_x25519: 35;
      pqc_mldsa_ed25519: 30;
      [name: string]: number;
    };
    symmetric: Record<string, number>;
    hash: Record<string, number>;
    compression: Record<string, number>;
    curve: Record<string, string | number>;
    [group: string]: unknown;
  };

  const config: Record<string, unknown>;
}

export = openpgp;
