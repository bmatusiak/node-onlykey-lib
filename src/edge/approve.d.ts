/**
 * @param {object} msg an EDGE_REQUEST
 * @param {object} o
 * @param {object} o.edge the Edge device service (plugins/edge) for THIS app's key
 * @param {string[]} o.registered agent public keys (hex) registered with a press
 * @param {Set<string>} o.seen nonces already taken (the caller keeps it)
 * @param {string[]} [o.ownIdentities] the person's own identity names
 * @param {(view: object) => Promise<'approve'|'decline'>} o.ask the screen
 * @param {() => Promise<{ok: boolean, head: Uint8Array}>} o.verifyCopy R27: the
 *   app's copy checked; head = the key's head it verified up to
 * @param {() => void} [o.onPress] told when the key waits for the press
 * @param {number} [o.timeoutMs] the press wait (the key's own is 25 s)
 * @returns {Promise<{ok: true, budget: object} | {ok: false, refusal: string} | {dropped: string}>}
 *   dropped: nothing is answered to the agent (unsigned, unregistered, replayed)
 */
export function approveRequest(msg: object, { edge, registered, seen, ownIdentities, ask, verifyCopy, onPress, timeoutMs }: {
    edge: object;
    registered: string[];
    seen: Set<string>;
    ownIdentities?: string[] | undefined;
    ask: (view: object) => Promise<"approve" | "decline">;
    verifyCopy: () => Promise<{
        ok: boolean;
        head: Uint8Array;
    }>;
    onPress?: (() => void) | undefined;
    timeoutMs?: number | undefined;
}): Promise<{
    ok: true;
    budget: object;
} | {
    ok: false;
    refusal: string;
} | {
    dropped: string;
}>;
