/**
 * HID usage page and usage per interface, from `usb_desc.c`'s report
 * descriptors.
 *
 * The two RawHID interfaces carry vendor-defined pages (`0xFF00` and above),
 * which is what makes them look alike to anything that does not read them.
 *
 * `endpointIn`/`endpointOut` are the maximum packet sizes the firmware asks
 * for, in bytes. Note SEREMU is ASYMMETRIC - 64 in, 32 out - which is a real
 * constraint on writes and not a typo.
 */
export const INTERFACES: ({
    iface: 0;
    name: string;
    usagePage: number;
    usage: number;
    endpointIn: number;
    endpointOut: number;
    required: boolean;
} | {
    iface: 1;
    name: string;
    usagePage: number;
    usage: number;
    endpointIn: number;
    endpointOut: number;
    required: boolean;
} | {
    iface: 2;
    name: string;
    usagePage: number;
    usage: number;
    endpointIn: number;
    endpointOut: number;
    required: boolean;
} | {
    iface: 3;
    name: string;
    usagePage: number;
    usage: number;
    endpointIn: number;
    endpointOut: number;
    required: boolean;
})[];
/** VID and PID the firmware declares. `usb_desc.h`, the USB_ONLYKEY block. */
export const VENDOR_ID: 7504;
export const PRODUCT_ID: 24828;
/**
 * The control transfer that fetches a report descriptor.
 *
 * Returned as data rather than performed, because performing it is
 * platform-specific and this package does not reach for a bus. The fields are
 * the standard GET_DESCRIPTOR request from the USB spec, aimed at an interface:
 *
 *   requestType 0x81  IN | standard | recipient INTERFACE
 *   request     0x06  GET_DESCRIPTOR
 *   value       0x2200  descriptor type 0x22 (REPORT), index 0
 *   index       the bInterfaceNumber being asked about
 *
 * The device answers this: `usb_dev.c` handles the request and `usb_desc.c`
 * keys its lookup on exactly `{value: 0x2200, index: bInterfaceNumber}`. It
 * also clamps the reply to the requested length, so asking for more than the
 * descriptor holds returns the true length rather than stalling.
 */
export function reportDescriptorRequest(interfaceNumber: any, length?: number): {
    requestType: number;
    request: number;
    value: number;
    index: any;
    length: number;
};
/**
 * The usage page and usage at the head of a HID report descriptor.
 *
 * Walks HID SHORT ITEMS rather than matching a byte prefix. A prefix match
 * works on today's descriptors and breaks the first time an item is inserted
 * ahead of the usage - a Report ID, say - which is the kind of change that
 * arrives in a firmware update rather than in a code review.
 *
 * A short item's first byte is `bTag << 4 | bType << 2 | bSize`, where bSize is
 * the DATA LENGTH INDEX: 0, 1 and 2 mean that many bytes, and 3 means four.
 * The two items wanted:
 *
 *   Usage Page  bType 1 (global), bTag 0  -> prefixes 0x05, 0x06, 0x07
 *   Usage       bType 2 (local),  bTag 0  -> prefixes 0x09, 0x0a, 0x0b
 *
 * Long items (prefix 0xfe) are skipped by their own length byte. Returns nulls
 * for whatever was not found, so a caller can tell "no usage page" from "usage
 * page zero".
 */
export function parseUsage(bytes: any): {
    usagePage: number | null;
    usage: number | null;
};
/**
 * Which IFACE a report descriptor belongs to, or null when nothing matches.
 *
 * Null is not a failure to be papered over. A caller that cannot identify an
 * interface must leave it alone and say so - see the module header.
 */
export function identify({ usagePage, usage }: {
    usagePage: any;
    usage: any;
}): 0 | 1 | 3 | 2 | null;
/** The descriptor for one IFACE, or undefined. */
export function describe(iface: any): {
    iface: 0;
    name: string;
    usagePage: number;
    usage: number;
    endpointIn: number;
    endpointOut: number;
    required: boolean;
} | {
    iface: 1;
    name: string;
    usagePage: number;
    usage: number;
    endpointIn: number;
    endpointOut: number;
    required: boolean;
} | {
    iface: 2;
    name: string;
    usagePage: number;
    usage: number;
    endpointIn: number;
    endpointOut: number;
    required: boolean;
} | {
    iface: 3;
    name: string;
    usagePage: number;
    usage: number;
    endpointIn: number;
    endpointOut: number;
    required: boolean;
} | undefined;
/**
 * Check a set of identified interfaces before a session is built on it.
 *
 * Three ways to be wrong, and all three are silent if unchecked: a required
 * interface missing, the same one claimed twice, or an interface identified by
 * something other than its usage page. Returns a list of complaints, empty when
 * the set is usable.
 *
 * @param {Array<{iface: number, identifiedBy?: string}>} found
 */
export function problems(found: Array<{
    iface: number;
    identifiedBy?: string;
}>): string[];
