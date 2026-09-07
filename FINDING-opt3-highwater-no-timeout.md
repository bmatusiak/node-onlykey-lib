# The opt3 duplicate-suppression mark has no timeout, so an aborted request wedges the channel

**Severity:** medium
**Status:** the library avoids it by construction; the firmware side is worth a
follow-up
**Applies to:** `libraries/fido2/ok_extension.cpp` as patched by commit
`71d7224`, plus any client that restarts its packet counter

## What I expected to find, and why that was wrong

The plan for this library recorded that `onlykey-pgp.js:250` —
`if (finalPacket) packetnum = 0;` — "resets to 0 and is the bug", with
`onlykey-3rd-party.js`'s never-reset counter as the correct version.

Against the firmware in this workspace that is **not right**, and the reason is
worth keeping. `ok_extension.cpp:471` does:

```c
// opt2 marked this the final chunk, so the message is complete
// and the next one must start from a clean high-water mark.
if (opt2) last_request_opt3 = 0;
```

`opt2` is the client's `finalPacket` and `opt3` is its `packetnum`. So the
client's per-operation reset is **coordinated** with a firmware reset, not
fighting it. On the happy path both sides return to zero together and the next
operation starts cleanly at 1.

The defect is real but sits somewhere else.

## The actual defect

`ok_extension.cpp:432-434`, the inbound guard:

```c
if (!last_request_opt3) last_request_opt3 = opt3; // first packet
else if (opt3 <= last_request_opt3) return 0;     // duplicate packet
```

`last_request_opt3` is cleared in exactly one place — line 471, reached only
when a request completes with `opt2` set. **Nothing else ever clears it.** It
is a file-scope `static` (`:156`), so `wipetasks()` cannot reach it, and
`grep` confirms the only writes are `:156`, `:433`, `:446`, `:456`, `:471`.

So if a multi-chunk request is abandoned partway — host crash, cable pull, a
user cancelling at the button prompt, a timeout — the mark is left at whatever
chunk got furthest, permanently.

What happens next depends on how many chunks the *next* request has:

- **Longer than the stale mark:** its early chunks are silently discarded
  (`return 0` — no error, no serial print, nothing on the wire), the device
  hashes a short buffer, and the user is asked for challenge digits computed
  over bytes the host never sent. It fails as `incorrect challenge was
  entered`. The final chunk does set `opt2`, so the mark clears and the
  *following* operation works. One sacrificial failure.

- **Shorter than or equal to the stale mark:** *every* chunk hits
  `return 0` at line 434 — which returns **before** line 471. The mark is
  never cleared. The next request is shorter too, so it also fails. The
  channel is wedged until reboot.

That second case is the one that matters, and it has no self-healing path.

## This is a side effect of fixing a worse bug

Commit `71d7224` moved this state out of `packet_buffer_details[3]`, which
`okcore.cpp`'s `process_packets()` was overwriting with two random bytes
(`RNG2(packet_buffer_details + 3, 2)`) — two meanings on one byte, the random
one winning. That was strictly worse: a *random* 0-255 threshold applied to
every request. The fix is right.

But the old location was incidentally zeroed by `wipetasks()` on a 5-second
timer, which meant the failure always healed itself within five seconds. The
commit message notes this as the reason the classic RSA path never noticed the
bug. Moving to a dedicated `static` removed that accidental recovery along
with the corruption. Net: much rarer, but no longer self-healing.

## Suggested firmware follow-up

Give the mark the timeout it lost — clear `last_request_opt3` from the same
`wipetasks()` timer that used to clear it by accident, so an abandoned request
cannot outlive the session that abandoned it. That restores the old
self-healing without restoring the aliasing.

Not filed as a defect in this library's scope; recorded here because the
library's chunker is built around it.

## What this library does

`src/protocol/chunk.js` keeps **one process-global `packetCounter`**,
monotonic, never reset per operation, wrapping 255 → 1. Polls go out with
`opt3 = 0`, which the firmware reads as unset.

A monotonic counter cannot produce the wedge: its `opt3` is always greater
than any mark a previous operation left behind, so the stale mark is
overwritten on the first chunk rather than rejecting it. This is the right
behaviour against **both** the patched firmware and the pre-`71d7224` random
-threshold version, which is why the library does it regardless of which
firmware is on the other end.

The one residual gap is the wrap: if a stale mark sits at 250 and the counter
wraps to 1, the same wedge appears. It needs ~250 chunked operations inside one
abandoned request's lifetime, so it is recorded rather than worked around.

Related: the response-side mark `large_resp_buffer_last_opt3`
(`ok_extension.cpp:102`, `:506-521`) has the same shape, guarding polls rather
than requests.
