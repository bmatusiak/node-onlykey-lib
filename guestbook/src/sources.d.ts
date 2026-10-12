export const FETCHABLE: string[];
export const KEYBASE_MAX: 5;
/**
 * ADD: a person's search. -> [{label, body, source: {kind, handle}, where}], each body still to be
 * read by formats.detectAll (it holds one or more keys; a GitHub .keys body holds every SSH key).
 */
export function lookup(kind: any, query: any, fetchFn: any): Promise<{
    label: any;
    body: string;
    source: {
        kind: string;
        handle: any;
    };
    where: string;
}[]>;
/**
 * REFRESH: the source's exact handle, fetched again.
 * -> {status: 'ok', body} | {status: 'missing'} (the source no longer serves anything there)
 *  | {status: 'error', message} (network, server, size, http). Never throws.
 */
export function fetchSource(source: any, fetchFn: any): Promise<{
    status: string;
    message: string;
    body?: undefined;
} | {
    status: string;
    message?: undefined;
    body?: undefined;
} | {
    status: string;
    body: string;
    message?: undefined;
}>;
