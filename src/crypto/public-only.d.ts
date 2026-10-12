/**
 * PUBLIC ONLY: the one guard for lists that must never hold a private key.
 *
 * Key Chain's list (keychain/src/list.js) and Guest Book (guestbook/) both hold other people's or
 * your own PUBLIC keys and nothing else (Brad, 2026-10-12, for Guest Book: "guest book is only for
 * public output, it should not contain or show any private keys"). One rule, shared, so the two
 * can never drift apart: a field a private key travels under, or text only a private key carries,
 * is refused before it is stored.
 */
export const PRIVATE_FIELDS: string[];
export const PRIVATE_TEXT: RegExp;
/**
 * Throws when `value` (an object walked deeply, or a string) carries private key material.
 * @param {unknown} value
 * @param {string} where - the path named in the message
 * @param {string} [holder] - what refuses it, named in the message
 */
export function refusePrivate(value: unknown, where: string, holder?: string): void;
/** True when the text carries private key material (the same test, for a caller that explains it itself). */
export function isPrivateText(text: any): boolean;
