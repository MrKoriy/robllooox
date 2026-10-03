#!/bin/bash
# resign_adhoc.sh — make RobloxPlayer 0.739 injectable (ad-hoc re-sign), reproducibly.
#
# What it does (same procedure that worked on 0.735, verified on 0.736):
#   1. Checks client version — refuses to run on an already-adhoc binary (idempotent).
#   2. Backs up the original binary ONCE (originals are not re-downloadable offline).
#   3. codesign --remove-signature  → strip official signature + hardened runtime.
#   4. codesign -s - --deep         → ad-hoc sign, no entitlements → DYLD_INSERT works.
#   5. Optional: quarantine attribute is NOT re-added; Gatekeeper stays quiet locally.
#
# Usage:
#   tools/resign_adhoc.sh            # check + resign if needed
#   tools/resign_adhoc.sh --force    # resign even if already adhoc
#   tools/resign_adhoc.sh --restore  # restore original from backup
#
# After this: ./launch_inject.sh  and lldb attach work again on 0.739.
set -euo pipefail

BIN="/Applications/Roblox.app/Contents/MacOS/RobloxPlayer"
BACKUP="$HOME/roblox_backups/RobloxPlayer.orig-741"

if [[ ! -f "$BIN" ]]; then
  echo "[-] $BIN not found"; exit 1
fi

restore() {
  if [[ -f "$BACKUP" ]]; then
    cp "$BACKUP" "$BIN"
    codesign -s - --deep "$BIN" 2>/dev/null || true
    echo "[+] restored original + re-signed adhoc (still injectable)"
  else
    echo "[-] no backup at $BACKUP"; exit 1
  fi
}

[[ "${1:-}" == "--restore" ]] && { restore; exit 0; }

# --- idempotency check: is it already adhoc? -------------------------------
sig_team=$(codesign -dv "$BIN" 2>&1 | grep -i "TeamIdentifier=" || true)
echo "[*] $sig_team"
if echo "$sig_team" | grep -q "TeamIdentifier=not set" && [[ "${1:-}" != "--force" ]]; then
  echo "[=] already ad-hoc signed — nothing to do (use --force to redo)"
  exit 0
fi

# --- version stamp ----------------------------------------------------------
ver=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" \
      /Applications/Roblox.app/Contents/Info.plist 2>/dev/null || echo "?")
echo "[*] client version: $ver"

# --- one-time backup --------------------------------------------------------
if [[ ! -f "$BACKUP" ]]; then
  cp "$BIN" "$BACKUP"
  echo "[+] backup saved: $BACKUP"
else
  echo "[*] backup already exists: $BACKUP (keeping)"
fi

# --- kill running client (Roblox ignores SIGTERM) ---------------------------
pgrep -x RobloxPlayer >/dev/null && {
  echo "[*] killing running RobloxPlayer"
  pkill -9 -x RobloxPlayer || true
  sleep 1
}

# --- the actual resign ------------------------------------------------------
codesign --remove-signature "$BIN"
codesign -s - --deep "$BIN"
echo "[+] re-signed ad-hoc"

# --- verify -----------------------------------------------------------------
codesign -dv "$BIN" 2>&1 | grep -i "TeamIdentifier=" || true
codesign -v "$BIN" && echo "[+] signature valid"
echo "[i] now run: ./launch_inject.sh"
echo "[!] NOTE: watch for auto-update (~/Library/Roblox/Temp/Roblox.zip) — re-run this script if the client refreshes."
