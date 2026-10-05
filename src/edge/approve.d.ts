/**
 * @param {object} msg an EDGE_REQUEST
 * @param {object} o
 * @param {object} o.edge the Edge device service (plugins/edge) for THIS app's key
 * @param {string[]} o.registered agent public keys (hex) registered with a press
 * @param {Set<string>} o.seen nonces already taken (the caller keeps it)
 * @param {string[]} [o.ownIdentities] the person's own identity names
 * @param {(view: object) => Promise<'approve'|'decline'|'timeout'|'copy_unverified'>} o.ask the screen
 *   ('timeout': nobody answered the sheet; 'copy_unverified': the sheet could
 *   not offer Approve, the app's copy did not verify)
 * @param {() => Promise<{ok: boolean, head: Uint8Array}>} o.verifyCopy R27: the
 *   app's copy checked; head = the key's head it verified up to
 * @param {(grantId: number) => ({agent: string, scopes: object[]} | null)} [o.budgetOf]
 *   a continue: the app's own record of the budget it continues (who asked,
 *   which scopes) - null when the app never opened it
 * @param {(msg: object) => Promise<object[]>|object[]} [o.coverOf] the live
 *   budgets that already cover what this request names (view().covered)
 * @param {() => void} [o.onPress] told when the key waits for the press
 * @param {number} [o.timeoutMs] the press wait (the key's own is 25 s)
 * @returns {Promise<{ok: true, budget: object} | {ok: false, refusal: string} | {dropped: string}>}
 *   dropped: nothing is answered to the agent (unsigned, unregistered, replayed)
 */
export function approveRequest(msg: object, { edge, registered, seen, ownIdentities, ask, verifyCopy, budgetOf, coverOf, onPress, timeoutMs }: {
    edge: object;
    registered: string[];
    seen: Set<string>;
    ownIdentities?: string[] | undefined;
    ask: (view: object) => Promise<"approve" | "decline" | "timeout" | "copy_unverified">;
    verifyCopy: () => Promise<{
        ok: boolean;
        head: Uint8Array;
    }>;
    budgetOf?: ((grantId: number) => ({
        agent: string;
        scopes: object[];
    } | null)) | undefined;
    coverOf?: ((msg: object) => Promise<object[]> | object[]) | undefined;
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
/**
 * An agent asks to be registered (EDGE_REGISTER, mcp-service.md 4.7a): signed
 * by the key it names, new, the person's Yes on the sheet, then a PHYSICAL
 * press - the key links it (AGENT_ADD, subject grants.agentSubject). Like a
 * known peer (R20). -> {ok: true, agent, name, seq} | {ok: false, refusal} | {dropped}
 *
 * @param {object} msg an EDGE_REGISTER
 * @param {object} o
 * @param {object} o.edge the Edge device service for THIS app's key
 * @param {string[]} [o.registered] agent keys (hex) already registered
 * @param {Set<string>} o.seen nonces already taken
 * @param {(view: {agent: string, name: string, fingerprint: string}) => Promise<'approve'|'decline'|'timeout'>} o.ask the sheet
 * @param {() => void} [o.onPress] told when the key waits for the press
 * @param {number} [o.timeoutMs] the press wait
 * @returns {Promise<any>}
 */
export function approveRegister(msg: object, { edge, registered, seen, ask, onPress, timeoutMs }: {
    edge: object;
    registered?: string[] | undefined;
    seen: Set<string>;
    ask: (view: {
        agent: string;
        name: string;
        fingerprint: string;
    }) => Promise<"approve" | "decline" | "timeout">;
    onPress?: (() => void) | undefined;
    timeoutMs?: number | undefined;
}): Promise<any>;
/**
 * R20 (okedge sync phase 2, P2a): a place that keeps copies asks to be added
 * (EDGE_PEER_ADD) - signed by the key it names, new, the person's Yes on the
 * sheet, then a PHYSICAL press; the key adds it to ITS list and links it
 * (peer-add, subject grants.peerSubject). The key's list is the truth - a sync
 * goes only to places on it - so "already" is read from the key, not the app.
 * -> {ok: true, peer, name, seq, index} | {ok: true, already} | {ok: false, refusal} | {dropped}
 *
 * @param {object} msg an EDGE_PEER_ADD
 * @param {object} o
 * @param {object} o.edge the Edge device service for THIS app's key
 * @param {Set<string>} o.seen nonces already taken
 * @param {(view: {peer: string, name: string, fingerprint: string}) => Promise<'approve'|'decline'|'timeout'>} o.ask the sheet
 * @param {() => void} [o.onPress] told when the key waits for the press
 * @param {number} [o.timeoutMs] the press wait
 * @returns {Promise<any>}
 */
export function approvePeerAdd(msg: object, { edge, seen, ask, onPress, timeoutMs }: {
    edge: object;
    seen: Set<string>;
    ask: (view: {
        peer: string;
        name: string;
        fingerprint: string;
    }) => Promise<"approve" | "decline" | "timeout">;
    onPress?: (() => void) | undefined;
    timeoutMs?: number | undefined;
}): Promise<any>;
/**
 * okedge sync phase 2 (Brad, 2026-10-05): links a place that keeps copies
 * offers for THIS phone's copy. The caller has already merged them and checked
 * the merged copy verifies (R27 - it needs the copy store); this is the consent:
 * the place must be on the KEY's peer list, then the sheet, Yes, a PHYSICAL
 * press, and the key writes the `sync` link (subject sync.syncSubject). Only
 * after that link may the caller keep the merged copy.
 * -> {ok: true, seq, count} | {ok: false, refusal, detail?}
 *
 * @param {object} o
 * @param {string} o.peer the place's key, X || Y hex
 * @param {string} o.name the name it gave (shown, never trusted)
 * @param {Array<{link: Uint8Array}>} o.added the links that would be added, in seq order
 * @param {Uint8Array} o.head the phone copy's head after the merge (its newest link's head)
 * @param {Uint8Array|null} [o.keychainHash] SHA256 of the merged Key Chain list, when one moved
 * @param {object} o.edge the Edge device service for THIS app's key
 * @param {(view: {peer: string, name: string, fingerprint: string, count: number, ranges: number[][]}) => Promise<'approve'|'decline'|'timeout'>} o.ask
 * @param {() => void} [o.onPress]
 * @param {number} [o.timeoutMs]
 * @returns {Promise<any>}
 */
export function approveSync({ peer, name, added, head, keychainHash, edge, ask, onPress, timeoutMs }: {
    peer: string;
    name: string;
    added: Array<{
        link: Uint8Array;
    }>;
    head: Uint8Array;
    keychainHash?: Uint8Array<ArrayBufferLike> | null | undefined;
    edge: object;
    ask: (view: {
        peer: string;
        name: string;
        fingerprint: string;
        count: number;
        ranges: number[][];
    }) => Promise<"approve" | "decline" | "timeout">;
    onPress?: (() => void) | undefined;
    timeoutMs?: number | undefined;
}): Promise<any>;
/**
 * R15c (2026-10-03): is this agent registered - is its AGENT_ADD link, made at
 * a press, in the app's VERIFIED copy of the chain? The app's own list of
 * agents is a convenience; only the link counts. An agent in storage without
 * one (planted, or kept from before the press) is refused, unread.
 *
 * @param {Array<{fields: object, verified: boolean}>} rows the copy's links,
 *   decoded, each with whether R27 verified it (the app's copy view)
 * @param {string} agentHex the agent's key (hex)
 * @returns {number|null} the seq of its verified agent-add link, or null
 */
export function agentInCopy(rows: Array<{
    fields: object;
    verified: boolean;
}>, agentHex: string): number | null;
