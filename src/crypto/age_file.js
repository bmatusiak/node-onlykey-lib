// age v1 file format (age-encryption.org/v1), scoped to exactly one
// recipient stanza type: "mlkem768x25519" (the derived X-Wing feature this
// app implements). Not a general age library - matches derived_xwing.py's
// scope note.
//
// HPKE cipher suite for the mlkem768x25519 stanza (see xwing.py's
// seal_file_key/open_file_key, ported here byte-for-byte):
//   KEM: X-Wing (0x647a), KDF: HKDF-SHA256 (0x0001), AEAD: ChaCha20-Poly1305 (0x0003)
//
// STREAM body encryption follows the age spec directly (not project-
// specific): 64KiB chunks, ChaCha20-Poly1305 with an 11-byte big-endian
// counter + 1-byte "last chunk" flag as the 12-byte nonce, a payload key
// derived via HKDF-SHA256(file_key, salt=16-byte random stream nonce,
// info="payload"), and a header HMAC keyed by
// HKDF-SHA256(file_key, salt="", info="header") covering everything from
// the magic line through the literal "---" (no trailing space/MAC/newline).

const { extract: hkdfExtract, expand: hkdfExpand } = require('@noble/hashes/hkdf.js');
const { sha256 } = require('@noble/hashes/sha2.js');
const { hmac } = require('@noble/hashes/hmac.js');
const { chacha20poly1305 } = require('@noble/ciphers/chacha.js');
const { randomBytes } = require('@noble/ciphers/utils.js');
const { utf8ToBytes, toBase64, fromBase64 } = require('../bytes');

const CHUNK_SIZE = 64 * 1024;
const TAG_LEN = 16;
const FILE_KEY_LEN = 16;
const MAGIC_LINE = 'age-encryption.org/v1';
const STANZA_TYPE = 'mlkem768x25519';

// ---- HPKE (RFC 9180) for the X-Wing cipher suite, ported from xwing.py ---
const HPKE_MODE_BASE = 0x00;
const KEM_ID = 0x647a; // X-Wing
const KDF_ID = 0x0001; // HKDF-SHA256
const AEAD_ID = 0x0003; // ChaCha20-Poly1305
const N_SECRET = 32;
const N_K = 32;
const N_N = 12;

function utf8(s) {
    return utf8ToBytes(s);
}

function concatBytes(...arrays) {
    const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
    let offset = 0;
    for (const a of arrays) {
        out.set(a, offset);
        offset += a.length;
    }
    return out;
}

function i2osp(n, length) {
    const out = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--) {
        out[i] = n & 0xff;
        n = Math.floor(n / 256);
    }
    return out;
}

const SUITE_ID_HPKE = concatBytes(utf8('HPKE'), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(AEAD_ID, 2));
const SUITE_ID_KEM = concatBytes(utf8('KEM'), i2osp(KEM_ID, 2));
const EMPTY = new Uint8Array(0);

function labeledExtract(salt, label, ikm, suiteId) {
    const labeledIkm = concatBytes(utf8('HPKE-v1'), suiteId, label, ikm);
    return hkdfExtract(sha256, labeledIkm, salt);
}

function labeledExpand(prk, label, info, length, suiteId) {
    const labeledInfo = concatBytes(i2osp(length, 2), utf8('HPKE-v1'), suiteId, label, info);
    return hkdfExpand(sha256, prk, labeledInfo, length);
}

function hpkeExtractAndExpand(sharedSecret, kemContext) {
    const prk = labeledExtract(EMPTY, utf8('shared_secret'), sharedSecret, SUITE_ID_KEM);
    return labeledExpand(prk, utf8('context'), kemContext, N_SECRET, SUITE_ID_KEM);
}

function hpkeKeyScheduleBase(sharedSecret, info) {
    const pskIdHash = labeledExtract(EMPTY, utf8('psk_id_hash'), EMPTY, SUITE_ID_HPKE);
    const infoHash = labeledExtract(EMPTY, utf8('info_hash'), info, SUITE_ID_HPKE);
    const ksContext = concatBytes(Uint8Array.of(HPKE_MODE_BASE), pskIdHash, infoHash);
    const secret = labeledExtract(sharedSecret, utf8('secret'), EMPTY, SUITE_ID_HPKE);
    const key = labeledExpand(secret, utf8('key'), ksContext, N_K, SUITE_ID_HPKE);
    const baseNonce = labeledExpand(secret, utf8('base_nonce'), ksContext, N_N, SUITE_ID_HPKE);
    return { key, baseNonce };
}

// enc: 1120-byte X-Wing ciphertext (kem_context). fileKey: 16 bytes.
// Returns the 32-byte sealed file key (16 plaintext + 16 tag).
function sealFileKey(sharedSecret, enc, fileKey) {
    const hpkeSs = hpkeExtractAndExpand(sharedSecret, enc);
    const { key, baseNonce } = hpkeKeyScheduleBase(hpkeSs, EMPTY);
    return chacha20poly1305(key, baseNonce).encrypt(fileKey);
}

// Returns the 16-byte file key, or throws on a bad tag (wrong shared secret).
function openFileKey(sharedSecret, enc, sealedFileKey) {
    const hpkeSs = hpkeExtractAndExpand(sharedSecret, enc);
    const { key, baseNonce } = hpkeKeyScheduleBase(hpkeSs, EMPTY);
    return chacha20poly1305(key, baseNonce).decrypt(sealedFileKey);
}

// ---- base64 (standard alphabet, unpadded, per the age spec) --------------
function b64NoPad(bytes) {
    return toBase64(bytes).replace(/=+$/, '');
}

function b64Decode(str) {
    return fromBase64(str);
}

function wrapBase64Lines(b64) {
    let out = '';
    for (let i = 0; i < b64.length; i += 64) {
        out += b64.slice(i, i + 64) + '\n';
    }
    // Disambiguating empty line when the body is an exact multiple of 64
    // base64 chars (including zero-length) - same rule as the STREAM
    // last-chunk case below, so a truncated body can't be mistaken for a
    // complete one.
    if (b64.length === 0 || b64.length % 64 === 0) {
        out += '\n';
    }
    return out;
}

// ---- STREAM (age spec, not project-specific) ------------------------------
function chunkNonce(counter, isLast) {
    const nonce = new Uint8Array(12);
    for (let i = 10; i >= 0; i--) {
        nonce[i] = counter & 0xff;
        counter = Math.floor(counter / 256);
    }
    nonce[11] = isLast ? 1 : 0;
    return nonce;
}

function streamEncrypt(payloadKey, plaintext) {
    const parts = [];
    if (plaintext.length === 0) {
        const cipher = chacha20poly1305(payloadKey, chunkNonce(0, true));
        parts.push(cipher.encrypt(EMPTY));
    } else {
        let offset = 0;
        let counter = 0;
        while (offset < plaintext.length) {
            const remaining = plaintext.length - offset;
            const takeLen = Math.min(remaining, CHUNK_SIZE);
            const chunk = plaintext.subarray(offset, offset + takeLen);
            offset += takeLen;
            const isLast = offset >= plaintext.length && takeLen < CHUNK_SIZE;
            const cipher = chacha20poly1305(payloadKey, chunkNonce(counter, isLast));
            parts.push(cipher.encrypt(chunk));
            counter++;
        }
        if (plaintext.length % CHUNK_SIZE === 0) {
            // Exact multiple of the chunk size - an extra empty final
            // chunk (flag=1) is required so a truncation can't look like
            // a clean end-of-stream.
            const cipher = chacha20poly1305(payloadKey, chunkNonce(counter, true));
            parts.push(cipher.encrypt(EMPTY));
        }
    }
    return concatBytes(...parts);
}

function streamDecrypt(payloadKey, data) {
    if (data.length === 0) {
        throw new Error('malformed age payload: empty STREAM body');
    }
    const parts = [];
    let offset = 0;
    let counter = 0;
    while (offset < data.length) {
        const remaining = data.length - offset;
        const isLast = remaining <= CHUNK_SIZE + TAG_LEN;
        const takeLen = isLast ? remaining : CHUNK_SIZE + TAG_LEN;
        if (takeLen < TAG_LEN) {
            throw new Error('malformed age payload: truncated STREAM chunk');
        }
        const chunkCt = data.subarray(offset, offset + takeLen);
        offset += takeLen;
        const cipher = chacha20poly1305(payloadKey, chunkNonce(counter, isLast));
        parts.push(cipher.decrypt(chunkCt)); // throws 'invalid tag' on failure
        counter++;
    }
    return concatBytes(...parts);
}

// ---- header parsing ---------------------------------------------------
function findHeaderLines(bytes) {
    const lines = [];
    let offset = 0;
    for (;;) {
        const nl = bytes.indexOf(0x0a, offset);
        if (nl === -1) throw new Error('malformed age header: missing newline');
        const text = String.fromCharCode(...bytes.subarray(offset, nl));
        lines.push({ text, start: offset });
        offset = nl + 1;
        if (text.startsWith('--- ')) {
            return { headerEndOffset: offset, lines };
        }
    }
}

function parseHeader(bytes) {
    const { headerEndOffset, lines } = findHeaderLines(bytes);
    if (lines.length === 0 || lines[0].text !== MAGIC_LINE) {
        throw new Error('not an age file: bad magic line');
    }
    const stanzas = [];
    let i = 1;
    while (i < lines.length && !lines[i].text.startsWith('--- ')) {
        const line = lines[i];
        if (!line.text.startsWith('-> ')) {
            throw new Error(`malformed age header: expected a stanza line, got: ${line.text}`);
        }
        const args = line.text.slice(3).split(' ');
        const type = args[0];
        const typeArgs = args.slice(1);
        i++;
        let bodyB64 = '';
        while (i < lines.length && !lines[i].text.startsWith('-> ') && !lines[i].text.startsWith('--- ')) {
            bodyB64 += lines[i].text;
            i++;
        }
        stanzas.push({ type, args: typeArgs, body: b64Decode(bodyB64) });
    }
    if (i >= lines.length) throw new Error('malformed age header: missing MAC line');
    const macLine = lines[i];
    const headerNoMac = bytes.subarray(0, macLine.start + 3); // up to and including the literal "---"
    const mac = b64Decode(macLine.text.slice(4));
    return { stanzas, headerNoMac, mac, headerEndOffset };
}

function computeHeaderMac(fileKey, headerNoMac) {
    const key = hkdfExpand(sha256, hkdfExtract(sha256, fileKey, EMPTY), utf8('header'), 32);
    return hmac(sha256, key, headerNoMac);
}

function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

// Builds a full age v1 file for a single mlkem768x25519 recipient.
// ciphertext: 1120-byte X-Wing ciphertext (from xwingEncapsHost). sharedSecret:
// its matching 32-byte X-Wing shared secret. Returns a Uint8Array.
function encryptAgeFile(plaintext, { ciphertext, sharedSecret }) {
    const fileKey = randomBytes(FILE_KEY_LEN);
    const sealedFileKey = sealFileKey(sharedSecret, ciphertext, fileKey);

    const recipientLine = `-> ${STANZA_TYPE} ${b64NoPad(ciphertext)}\n`;
    const bodyLines = wrapBase64Lines(b64NoPad(sealedFileKey));
    const headerNoMacText = MAGIC_LINE + '\n' + recipientLine + bodyLines + '---';
    const headerNoMac = utf8(headerNoMacText);

    const mac = computeHeaderMac(fileKey, headerNoMac);
    const header = concatBytes(headerNoMac, utf8(' ' + b64NoPad(mac) + '\n'));

    const streamNonce = randomBytes(16);
    const payloadKey = hkdfExpand(sha256, hkdfExtract(sha256, fileKey, streamNonce), utf8('payload'), 32);
    const body = streamEncrypt(payloadKey, plaintext);

    return concatBytes(header, streamNonce, body);
}

// Decrypts a full age v1 file containing (at least) one mlkem768x25519
// stanza. deriveSharedSecret(ciphertext) is called with the full 1120-byte
// X-Wing ciphertext from the stanza and must return (sync or async) the
// 32-byte combined X-Wing shared secret for this file's recipient - the
// caller already knows pk_X/mlkem_seed for the label and is expected to
// use ctXOf(ciphertext) to get the 32 bytes the device's
// DERIVE_SHARED_SECRET call needs, then call splitDecapsulate() itself
// (it needs the *full* ciphertext too, for the ML-KEM half - not just
// ct_X). Returns the decrypted plaintext as a Uint8Array.
async function decryptAgeFile(fileBytes, deriveSharedSecret) {
    const bytes = fileBytes instanceof Uint8Array ? fileBytes : new Uint8Array(fileBytes);
    const { stanzas, headerNoMac, mac, headerEndOffset } = parseHeader(bytes);

    const stanza = stanzas.find((s) => s.type === STANZA_TYPE);
    if (!stanza) {
        throw new Error(`no ${STANZA_TYPE} recipient stanza in this age file`);
    }
    const ciphertext = b64Decode(stanza.args[0]);
    const sealedFileKey = stanza.body;

    const sharedSecret = await deriveSharedSecret(ciphertext);
    const fileKey = openFileKey(sharedSecret, ciphertext, sealedFileKey);

    const expectedMac = computeHeaderMac(fileKey, headerNoMac);
    if (!timingSafeEqual(expectedMac, mac)) {
        throw new Error('age header MAC verification failed');
    }

    const streamNonce = bytes.subarray(headerEndOffset, headerEndOffset + 16);
    const body = bytes.subarray(headerEndOffset + 16);
    const payloadKey = hkdfExpand(sha256, hkdfExtract(sha256, fileKey, streamNonce), utf8('payload'), 32);
    return streamDecrypt(payloadKey, body);
}

module.exports = {
    sealFileKey,
    openFileKey,
    encryptAgeFile,
    decryptAgeFile,
};
