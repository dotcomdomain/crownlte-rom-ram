#!/bin/bash
# Generate the T3 stage DTS files from tee-t3dbg (06a6cf36) and build them.
# Each stage adds only the blob pins it needs (UUID from the MCLF header at
# offset 24, SHA-256 over the whole vendor file). Usage: mkdts-t3.sh <ko-dir>
set -euo pipefail
K=/mnt/ssd/host-builds/kernel-upgrade
D=$K/panel-bright-work/dtb
REG=$K/rom-ram/testroot/vendor/app/mcRegistry
BASE=$D/exynos9810-crownlte-romram-tee-t3dbg.dts
KO=$1
test "$(sha256sum < "$D/exynos9810-crownlte-romram-tee-t3dbg.dtb" | cut -c1-64)" = 06a6cf368377650dfe0a9a03cff67802a8363b7fcc4b25ff0af6a1153468204f
mkdir -p "$KO/arch/arm64/boot/dts/exynos"

pin() {  # <file> -> "uuid bytes  sha bytes" as DTS byte string
  local f=$REG/$1
  printf '%s  %s' "$(xxd -s 24 -l 16 -p "$f" | sed 's/../& /g;s/ $//')" \
                  "$(sha256sum "$f" | cut -c1-64 | sed 's/../& /g;s/ $//')"
}
KM=ffffffff00000000000000000000003e.tlbin
GK=08130000000000000000000000000000.tlbin
SEC=FFFFFFFF000000000000000000000001.drbin
TIMA=ffffffffd0000000000000000000000a.tlbin
CM=ffffffffd00000000000000000000016.tlbin

gen() {  # <stage> <comment> <trustlet files> <driver files>
  local st=$1 note=$2 tl=$3 drv=$4 out=$D/exynos9810-crownlte-romram-tee-$1.dts props f sep
  props="\t\t/* $note */\n\t\tsamsung,tee-trustlet-allow = ["
  sep=
  for f in $tl; do props+="$sep$(pin "$f")"; sep="\n\t\t\t\t\t      "; done
  props+="];\n"
  if [ -n "$drv" ]; then
    props+="\t\tsamsung,tee-driver-allow = ["
    sep=
    for f in $drv; do props+="$sep$(pin "$f")"; sep="\n\t\t\t\t\t    "; done
    props+="];\n"
  fi
  # Insert after the (two-line) samsung,tee-session-allow property of t3dbg.
  awk -v add="$(printf "$props")" '
    { print }
    /08 05 05 00 00 00 00 00 00 00 00 00 00 00 00 00\];/ { print add; n++ }
    END { if (n != 1) exit 1 }' "$BASE" > "$out"
  KSRC=$K/tee KO=/dev/shm/build-tee3 "$K/rom-ram/src/build-dtb.sh" "$out" \
    "$KO/arch/arm64/boot/dts/exynos/exynos9810-crownlte-romram-tee-$st.dtb" >/dev/null
  diff -u "$BASE" "$out" > "$out.diff" || true
}
gen t3a0 "T3a-0: keymaster TA ($KM) by open-trustlet only; no secure driver loads" "$KM" ""
gen t3a1 "T3a-1: same pins as T3a-0 (stage differs only in the ramdisk client)" "$KM" ""
gen t3a2 "T3a-2: keymaster TA + sec/TIMA/CryptoManager drivers (VaultKeeper NOT pinned)" "$KM" "$SEC $TIMA $CM"
gen t3b0 "T3b-0: gatekeeper TA ($GK) by open-trustlet only; no secure driver loads" "$GK" ""
gen t3b1 "T3b-1: gatekeeper TA + CryptoManager driver only" "$GK" "$CM"
cd "$KO/arch/arm64/boot/dts/exynos" && sha256sum exynos9810-crownlte-romram-tee-t3[ab]*.dtb
