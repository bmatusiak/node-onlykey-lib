# A failed PIN attempt cannot be reliably cleared from the host

**Severity:** medium (a wrong PIN locks a user out of retrying until reboot)
**Status:** measured on an emulated device; firmware is read-only here
**Applies to:** `OnlyKey-Firmware/OnlyKey/OnlyKey.ino:694` and `:914`

## What happens

Every button press appends to the guessed password, unconditionally:

```c
   password.append(button_selected);          // :694
   if (unlocked || password.profile1hashevaluate() || ...) {   // :697
```

`profile1hashevaluate()` hashes the WHOLE accumulated buffer, so a wrong
attempt does not slide out of a window — it stays. The correct PIN typed
afterwards hashes to something else entirely and also fails, and so does every
attempt after that.

The device's own way out is a long press, 220 lines further down the same
function:

```c
   else if (((onlykeyhw==OK_HW_DUO && duration >= 180 && button_selected=='1')
          || (onlykeyhw!=OK_HW_DUO && duration >= 72 && button_selected=='6'))
          && !isfade) {                        // :914
```

Two properties make that unreliable from a host:

1. It is the **last branch of a long else-if chain**, so anything earlier that
   matches wins.
2. It is guarded on **`!isfade`** — and a locked device is pulsing its LED for
   much of the time, because `Task taskInitialized(1000, sendInitialized)`
   (`:213`) keeps announcing itself.

Since the append at `:694` already happened, a clear gesture that loses the
`!isfade` race does not merely fail to clear — it **adds another digit**.

## Measured

On a Samsung SM-S136DL running the emulated firmware, with a 7-digit PIN:

```
send "6!\n"        (the clear gesture)
send "1234561\n"   (the correct PIN)

-> appends: 8
-> "Number of keys entered for this passcode = 7"
-> "Number of keys entered for this passcode = 8"
-> UNLOCKED seen: false
```

Eight appends for a seven-digit PIN. The buffer held `61234561`.

The same PIN, sent immediately after a firmware restart:

```
-> UNLOCKED seen: true
```

So the PIN was right the whole time; the clear gesture was the problem.

## Consequence for a host

There is no reliable host-side recovery from a mistyped PIN. The buffer is RAM,
so restarting the firmware clears it — but on this platform the firmware thread
only exits through the AIRCR trap, so that means restarting the app process.

A user who mistypes on a phone therefore has to restart the app, and nothing
tells them so: the device simply stops accepting the right PIN.

## What this library does

`device.clearPinEntry()` sends the gesture and its documentation says plainly
that it is unreliable and why. `device.unlock()`'s timeout message names both
possibilities — a wrong PIN, or a poisoned buffer — because from the host they
are genuinely indistinguishable: a wrong digit produces no message at all.

## Suggested firmware follow-up

Move the reset out of the `!isfade` guard, or reset on a dedicated gesture that
does not also append. A host-visible "clear" would be better still: the whole
difficulty is that the only way to affect this buffer is to add to it.
