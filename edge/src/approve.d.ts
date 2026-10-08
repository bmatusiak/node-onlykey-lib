/**
 * @param {object} msg an EDGE_REQUEST
 * @param {object} o
 * @param {object} o.edge the Edge device service (edge/plugin) for THIS app's key
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
