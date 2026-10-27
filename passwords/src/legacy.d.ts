/**
 * THE OLD SINGLE-PASSWORD VAULT, BROUGHT IN (PASSWORD-MANAGER-SPEC.md "Data model"): each old
 * record was sealed under its own `vault:<serviceId>` key, so the caller opens each one with the
 * key (okcrypto.deviceVault.load - one derive per site, as before) and this re-seals what it got
 * as a `login` entry, its password sealed under the entry's own press (seal, inner.js) - a store
 * keeps no secret outside one. The old store is left as it is.
 *
 * Only records made on firmware with the hardened derive open (3.1.0+): an older firmware
 * derived another key. A record that does not open is counted, never guessed at.
 */
/**
 * -> {imported, failed: [{serviceId, reason}]}
 * legacy:   the old vault_store (list()) - its serviceId is the site name the person typed
 * openOne:  async (serviceId) => the password text (the caller's device derive)
 * manager:  an open store (openStore)
 * seal:     async (entry) => the entry with its password sealed (the caller's touch derive)
 */
export function importLegacy({ legacy, openOne, manager, seal }: {
    legacy: any;
    openOne: any;
    manager: any;
    seal: any;
}): Promise<{
    imported: number;
    failed: {
        serviceId: any;
        reason: string;
    }[];
}>;
