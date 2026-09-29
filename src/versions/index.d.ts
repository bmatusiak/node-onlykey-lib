export const REPOS: string[];
/** Every named release, newest first as the table lists them. */
export function list(): string[];
/**
 * A release's pinned commits, or null for a named-but-not-cut release (the
 * working tree). Throws on an unknown release or a half-pinned row.
 * @returns {{libraries: string, 'OnlyKey-Firmware': string, file?: string}|null}
 */
export function pinsFor(version: any): {
    libraries: string;
    "OnlyKey-Firmware": string;
    file?: string;
} | null;
/** The recorded compatibility of a release (see the header). */
export function compatibilityOf(version: any): any;
/**
 * The OKCONNECT status a SIGNED Classic build of the release reports: '-prod'
 * on the x.y.z line; the beta line has no build suffix. (A DEBUG build reports
 * '-test', which capabilities() reads as the development tree.)
 */
export function signedStatus(version: any): string;
/** What the compatibility row SHOULD say, from capabilities() today. */
export function expectedCompatibility(version: any): {
    status: string;
    unreleased: boolean;
    capabilities: {
        gestures: {
            backup: {
                button: number;
                lo: number;
                hi: number | null;
                ticks: number;
            };
            slotLabels: {
                button: number;
                lo: number;
                hi: null;
                ticks: number;
            };
            keyLabels: {
                button: number;
                lo: number;
                hi: null;
                ticks: number;
            };
        };
        okconnectLayout: string;
        challengeFormula: string;
        pollDelayMultiplier: number;
        firmwareUpdateOverUsb: any;
        postQuantum: boolean;
        vendorOrigin: boolean;
        hmacSha1: boolean;
        debugConsole: boolean | null;
        slots: number;
        profiles: number;
        touchFreeDerive: string;
        deriveReqPress: boolean;
        transitV2: boolean;
        backupDigest: boolean;
        unknownSlotIsSilent: boolean;
        webDerive: boolean;
        staleFadeGuard: boolean;
        pressModeDefaulted: boolean;
        xwingDeviceCustody: boolean;
        userInputModeEnum: boolean;
        curve25519Keygen: boolean;
        deviceVault: boolean;
        challengeErrorIsFinal: boolean;
        xwingDerive: boolean;
        agentDerivation: boolean;
        agentDerivationV2: boolean;
        presenceTest: string;
        configModeGesture: {
            button: any;
            ticks: any;
        };
        duoSupported: boolean;
        consolePress: boolean;
        buttons: number;
    };
};
export { TABLE };
