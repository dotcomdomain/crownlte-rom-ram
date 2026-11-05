#!/bin/bash
# Compile a DTS against the kernel tree with the exact cpp/dtc command kbuild
# used for the q47 combined DTB (arch/arm64/boot/dts/exynos/.*.dtb.cmd).
# Usage: build-dtb.sh <dts> <out.dtb>
# Env: KSRC (kernel worktree), KO (kernel build dir that has scripts/dtc/dtc).
set -euo pipefail
K=/mnt/ssd/host-builds/kernel-upgrade
KSRC=${KSRC:-$K/integration}
KO=${KO:-$K/build/romram-6.12.93}
DTS=$(realpath "$1"); OUT=$2
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
clang-18 -E -nostdinc -I"$KSRC/scripts/dtc/include-prefixes" \
  -I"$KSRC/arch/arm64/boot/dts/exynos" -undef -D__DTS__ -x assembler-with-cpp \
  -o "$TMP/pre.dts" "$DTS"
"$KO/scripts/dtc/dtc" -o "$OUT" -b 0 -i"$(dirname "$DTS")" \
  -i"$KSRC/arch/arm64/boot/dts/exynos/" -i"$KSRC/scripts/dtc/include-prefixes" \
  -Wno-unique_unit_address -Wno-unit_address_vs_reg -Wno-avoid_unnecessary_addr_size \
  -Wno-alias_paths -Wno-graph_child_address -Wno-simple_bus_reg -Wno-unit_address_format \
  "$TMP/pre.dts"
sha256sum "$OUT"
