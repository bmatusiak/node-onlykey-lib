# Proposal: one shared OnlyKey protocol library

*To: the OnlyKey Team. From: Brad. Draft, 2026-09-28.*

Hi OnlyKey Team,

The OnlyKey protocol and crypto are currently implemented several times over:

- the desktop app: `OnlyKeyComm.js` in the classic app, and `src/api/device` in the 5.7 rewrite;
- the web app's built-in `onlykey-fido2`;
- python-onlykey;
- lib-agent.

Each copy drifts. Since 2026-09-07 there have been **at least 77 protocol-touching commits** across those repos, and each change has to be made, and tested, in every copy that implements it.

One example: FIDO2 transit v2 is already implemented three separate times: in the web app (`onlykey.extra.js`), in node-onlykey-lib and in the test kit. Each copy has to be kept identical to the firmware by hand.

I've been building **node-onlykey-lib** as a single JavaScript implementation to end that drift:

- **One tested library.** It has over 900 tests, including vectors frozen from your implementations. A version matrix tests it against every firmware release from v0.2-beta.8 to the upcoming 3.1.0.
- **Each app keeps its own transport.** That's chrome.hid in the desktop app, WebAuthn in the browser and USB on Android. Only the protocol and crypto are shared.
- **Adopting it is a plugin swap.** Adapters keep each app's current API.
- **One vendored crypto set.** @noble and openpgp live in one place, where they're audited and upgraded once for everything.
- **It follows your work.** A watch script lists every new protocol commit in your repos, so the library keeps up while you keep building.

The phone app and the test kit already run on it. The web app is moving onto it next.

## Two questions

1. **Where should new protocol work go from now on?** Ideally new protocol features land in the shared library, or I port them there with your code as the reference.
2. **Which desktop app line is the future?** The 5.7 rewrite is being built on trustcrypto/OnlyKey-App, while 5.6.0 and 6.0.0 shipped on the classic app. I'd like to port the line that will ship. The rewrite's device layer and tests make it the natural fit, but it would need the 5.6.0 fields (30 and 31).

Thanks,
Brad
