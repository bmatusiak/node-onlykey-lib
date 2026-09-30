#!/usr/bin/env bash
#
# Get a Linux (BlueZ) host ready to reach an ok-rn phone over Bluetooth LE -
# the same state a Windows PC reaches by pairing once in Settings.
#
#   scripts/ble-linux-connect.sh "Pixel 6a"          check, pair if needed, prefer LE
#   scripts/ble-linux-connect.sh "Pixel 6a" --fix    also apply the one-time host fixes (sudo)
#   scripts/ble-linux-connect.sh "Pixel 6a" --repair forget the phone here and pair again
#
# WHY A SCRIPT, AND WHY THESE STEPS. Every step below is something the first
# Linux run (a Raspberry Pi 4, BlueZ 5.82, 2026-09-29) tripped over, in order:
#
#  1. THE ADAPTER CAN BE SOFT-BLOCKED. rfkill left hci0 off; `power on` then
#     fails with a bare org.bluez.Error.Failed and noble reports "poweredOff".
#     Unblocking needs root.
#
#  2. THE HOST MUST STAY DUAL-MODE. The phone is BOTH a classic Bluetooth
#     keyboard (HID, BR/EDR) and an LE vendor pipe to the same computer, as it
#     is on Windows. `ControllerMode = le` makes the LE side easy and the
#     keyboard impossible - the phone then retries the host every 3 s forever.
#
#  3. BUT THEN BLUEZ PICKS CLASSIC FOR A CONNECT. Device1.Connect() chooses the
#     transport itself and, for a dual-mode phone bonded on both, it chooses
#     BR/EDR - so an LE GATT client hangs. Windows asks for LE explicitly; the
#     BlueZ equivalent is Device1.PreferredBearer = "le", which exists only
#     when bluetoothd runs with `Experimental = true`, and only on a device
#     BlueZ knows is dual-mode (one paired while the host was LE-only is not).
#
#  4. THE BOND MUST BE ON BOTH ENDS. A "Just Works" pair left keys on the host
#     that the phone never stored - it did not list the host, refused its
#     connections, and asked to pair again. Numeric comparison (an agent with a
#     display that answers "yes", the owner accepting the same number on the
#     phone) gave a bond both sides keep, for both transports (LE SC + CTKD).
#
#  5. THE PHONE ROTATES ITS ADDRESS. It advertises from resolvable private
#     addresses, so a scan lists it several times; after bonding BlueZ resolves
#     it to the identity address. Stale per-address entries are removed before
#     a pair so the pair targets the phone as it is now.
#
# This prepares the LINK only. Talking to the key is onlykey-js's job.
set -u

NAME="${1:-}"
shift || true
FIX=0; REPAIR=0
for a in "$@"; do
  case "$a" in
    --fix) FIX=1 ;;
    --repair) REPAIR=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
if [ -z "$NAME" ]; then
  echo "usage: $0 \"<phone name, e.g. Pixel 6a>\" [--fix] [--repair]" >&2
  exit 2
fi

CONF=/etc/bluetooth/main.conf
say()  { printf '%s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
bt()   { bluetoothctl "$@" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }

command -v bluetoothctl >/dev/null || fail "bluetoothctl not found - install bluez"

# ---- 1. the adapter: soft-blocked, powered -------------------------------
blocked=0
for r in /sys/class/rfkill/rfkill*; do
  [ -r "$r/type" ] && [ "$(cat "$r/type")" = bluetooth ] && [ "$(cat "$r/soft")" = 1 ] && blocked=1 && RF="$r"
done
if [ "$blocked" = 1 ]; then
  if [ "$FIX" = 1 ]; then
    sudo sh -c "echo 0 > $RF/soft" || fail "could not unblock $RF"
    say "unblocked $RF"
  else
    fail "Bluetooth is soft-blocked ($RF). Fix: sudo sh -c 'echo 0 > $RF/soft'   (or rerun with --fix)"
  fi
fi
bt show | grep -q 'Powered: yes' || bt power on >/dev/null
bt show | grep -q 'Powered: yes' || fail "the adapter will not power on - see: bluetoothctl show"
say "adapter: powered"

# ---- 2 + 3. dual-mode, Experimental (for PreferredBearer) ----------------
mode_le=0; exp_on=0
grep -qE '^[[:space:]]*ControllerMode[[:space:]]*=[[:space:]]*le' "$CONF" 2>/dev/null && mode_le=1
grep -qE '^[[:space:]]*Experimental[[:space:]]*=[[:space:]]*true' "$CONF" 2>/dev/null && exp_on=1
if [ "$mode_le" = 1 ] || [ "$exp_on" = 0 ]; then
  if [ "$FIX" = 1 ]; then
    sudo sed -i 's/^[[:space:]]*ControllerMode[[:space:]]*=[[:space:]]*le/#ControllerMode = dual/; s/^#\?[[:space:]]*Experimental[[:space:]]*=.*/Experimental = true/' "$CONF" \
      || fail "could not edit $CONF"
    grep -qE '^Experimental = true' "$CONF" || fail "no Experimental line in $CONF - add 'Experimental = true' under [General]"
    sudo systemctl restart bluetooth || fail "could not restart bluetooth"
    sleep 2
    say "bluetoothd: dual-mode, Experimental on (restarted)"
  else
    [ "$mode_le" = 1 ] && say "NEEDS FIX: $CONF has ControllerMode = le - the phone's classic keyboard cannot connect"
    [ "$exp_on" = 0 ] && say "NEEDS FIX: $CONF lacks 'Experimental = true' - BlueZ cannot be told to prefer LE"
    fail "rerun with --fix (uses sudo), or edit $CONF and: sudo systemctl restart bluetooth"
  fi
else
  say "bluetoothd: dual-mode, Experimental on"
fi

# ---- 4 + 5. the bond -------------------------------------------------------
paired_addr() { bt devices Paired | grep -iF "$NAME" | head -1 | cut -d' ' -f2; }
ADDR="$(paired_addr)"

if [ -n "$ADDR" ] && [ "$REPAIR" = 1 ]; then
  say "removing the existing pairing with $NAME ($ADDR) - forget this computer on the phone too"
  bt remove "$ADDR" >/dev/null
  ADDR=""
fi

if [ -z "$ADDR" ]; then
  # Stale entries from the phone's rotating addresses would make `pair` aim at
  # an address it no longer answers on.
  for a in $(bt devices | grep -iF "$NAME" | cut -d' ' -f2); do bt remove "$a" >/dev/null; done
  say "scanning for \"$NAME\" (8 s)..."
  bluetoothctl --timeout 8 scan le >/dev/null 2>&1
  TARGET="$(bt devices | grep -iF "$NAME" | tail -1 | cut -d' ' -f2)"
  [ -n "$TARGET" ] || fail "\"$NAME\" not seen - is Bluetooth on in ok-rn and the phone nearby?"
  say ">>> ACCEPT THE PAIRING REQUEST ON THE PHONE NOW - check the number matches the one printed here"
  # The agent answers "yes" to the host's side of numeric comparison; the
  # owner's tap on the phone is the other side. 35 s is time to read and tap.
  (echo "agent KeyboardDisplay"; sleep 1; echo "default-agent"; echo "pairable on"; echo "scan le"; sleep 4
   echo "pair $TARGET"; sleep 5; echo "yes"; sleep 35; echo "scan off"; echo "pairable off"; echo "quit") \
    | bluetoothctl 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr '\r' '\n' \
    | grep -aoE 'Confirm passkey [0-9]+|Pairing successful|Failed to pair[^[]*' | sort -u
  ADDR="$(paired_addr)"
  [ -n "$ADDR" ] || fail "not paired - accept the request on the phone and rerun; if the phone already lists this computer, forget it there and rerun with --repair"
fi
say "paired: $NAME = $ADDR"

bt trust "$ADDR" >/dev/null
# PreferredBearer is what makes a later Connect() go LE, the way WinRT does.
if bt info "$ADDR" | grep -q 'PreferredBearer'; then
  bt bearer "$ADDR" le >/dev/null
else
  say "NOTE: no PreferredBearer on this device - it was paired while the host was LE-only; rerun with --repair"
fi

# ---- status ---------------------------------------------------------------
say "---"
bt info "$ADDR" | grep -E 'Name:|Paired|Bonded|Trusted|Connected|PreferredBearer' | sed 's/^[[:space:]]*//'
say "---"
say "ready: the link is prepared. The phone's keyboard (if targeted at this computer) connects over classic;"
say "onlykey-js talks to the key over LE."
