#!/bin/bash
# crownlte ROM-in-RAM diagnostic ramdisk build (gekko; scratch in /dev/shm).
# Usage: build.sh <build-dir>   (build-dir must not exist)
set -euo pipefail
SRC=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
B=$1
K=/mnt/ssd/host-builds/kernel-upgrade
P=$K/backups-20261103/partitions
TR=$K/rom-ram/testroot
test ! -e "$B"
mkdir -p "$B"
cd "$B"
exec > >(tee build.log) 2>&1

# 0. SHA256 helper reused verbatim from Codex rom-read.h (hardware-tested 2026-10-16).
{
  echo '/* SPDX-License-Identifier: GPL-2.0 */'
  echo '/* SHA-256 reused verbatim from diagnostic-init-rom-exec-fix1-20261016-build/rom-read.h */'
  echo '#ifndef ROMRAM_SHA256_H'
  echo '#define ROMRAM_SHA256_H'
  echo '#include <errno.h>'; echo '#include <stdint.h>'
  echo '#include <stdio.h>'
  echo '#include <string.h>'
  sed -n '/^struct rom_sha {/,/^struct rom_part {/p' /root/kernel-upgrade/diagnostic-init-rom-exec-fix1-20261016-build/rom-read.h | sed '$d'
  echo '#endif'
} > romram-sha256.h
cp "$SRC"/init.c "$SRC"/romram.h "$SRC"/romram-host-test.c "$SRC"/gen_payload.py .
cp -r "$SRC"/templates .
if [ "${TEE_T2:-0}" = 1 ]; then cp "$SRC"/tee-t2-run.c "$SRC"/t2-seccomp-fixture.c .; fi
# TEE_T3=<stage> (needs TEE_T2=1): stage runner + one dedicated client.
case "${TEE_T3:-}" in
  '') ;;
  a0|a1|a2) T3_CLIENT=km ;;
  b0|b1) T3_CLIENT=gk ;;
  *) echo "TEE_T3 must be a0|a1|a2|b0|b1"; exit 1 ;;
esac
if [ -n "${TEE_T3:-}" ]; then
  test "${TEE_T2:-0}" = 1
  cp "$SRC"/tee-t3-run.c "$SRC"/t3-seccomp-fixture.c .
  cp -r "$SRC"/t3 .
fi

# 1. Composite read-only root from the partition backups (as the phone mounts them).
if ! mountpoint -q "$TR"; then
  mkdir -p "$TR"
  mount -o ro,loop,noload "$P/SYSTEM.img" "$TR"
  mount -o ro,loop,noload "$P/VENDOR.img" "$TR/vendor"
  mount -o ro,loop,noload "$P/ODM.img" "$TR/odm"
fi

# 2. Payload.
DEADLINE=${DEADLINE:-600} python3 gen_payload.py "$TR" payload

# 3. Host test of the manifest verifier against the real images (+ negatives).
gcc -std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
    -fno-omit-frame-pointer romram-host-test.c -o romram-host-test
M=payload/crownlte/manifest.txt
python3 - "$M" <<'EOF'
import sys
lines = open(sys.argv[1]).read().splitlines()
def w(name, ls): open(name, 'w').write('\n'.join(ls) + '\n')
i = next(k for k, l in enumerate(lines) if l.startswith('F ') and ' keep /vendor/etc/init/' in l)
bad = lines[:]; f = bad[i].split(' '); f[1] = '0' * 64; bad[i] = ' '.join(f); w('neg-sha.txt', bad)
i = next(k for k, l in enumerate(lines) if l.startswith('F ') and '/system/etc/init/' in l and ' keep ' in l)
w('neg-unknown.txt', lines[:i] + lines[i + 1:])
w('neg-absent.txt', lines + ['A /system/etc/init/hw/init.rc'])
EOF
./romram-host-test "$M" "$TR" payload/crownlte/sanitized neg-sha.txt neg-unknown.txt neg-absent.txt > host-test.log
cat host-test.log | grep -v '^  log:'

# 4. Static PID1.
T2_CFLAGS=()
if [ "${TEE_T2:-0}" = 1 ]; then
  test "${DEADLINE:-600}" = 600
  T2_CFLAGS=(-DRR_TEE_T2)
  if [ -n "${TEE_T3:-}" ]; then T2_CFLAGS+=(-DRR_TEE_T3); fi
fi
aarch64-linux-gnu-gcc "${T2_CFLAGS[@]}" -static -std=gnu11 -Os -Wall -Wextra -Werror -Wno-format-truncation init.c -o init
aarch64-linux-gnu-readelf -h -l init > init-readelf.txt
if grep -q INTERP init-readelf.txt; then echo "init is dynamic"; exit 1; fi

# 5. Reproducible initramfs: /init + /crownlte payload.
mkdir rootfs
cp init rootfs/init; chmod 0755 rootfs/init
cp -r payload/crownlte rootfs/crownlte
if [ "${TEE_T2:-0}" = 1 ]; then
  gcc -I. -O1 -Wall -Wextra -Werror -Wno-unused-function t2-seccomp-fixture.c -o t2-seccomp-fixture
  ./t2-seccomp-fixture | tee t2-seccomp-fixture.log
  aarch64-linux-gnu-gcc -static -Os -Wall -Wextra -Werror tee-t2-run.c -o tee-t2-run
  cp tee-t2-run rootfs/crownlte/tee-t2-run
fi
T3_SUMS=()
if [ -n "${TEE_T3:-}" ]; then
  # Bionic link inputs: libc.so/libdl.so of the verified SYSTEM image's runtime APEX.
  mkdir bionic
  unzip -p "$TR/system/apex/com.android.runtime.apex" apex_payload.img > bionic/rt.img
  debugfs -R 'dump /lib64/bionic/libc.so bionic/libc.so' bionic/rt.img
  debugfs -R 'dump /lib64/bionic/libdl.so bionic/libdl.so' bionic/rt.img
  rm bionic/rt.img
  printf '%s  %s\n' cbfa5f1675a5c009860223c0bdc042e6b3a1f65460419eff3f170f27dc796e9f bionic/libc.so \
    29d52f966a5fe42d412566402459b5a657f6fc73f859c94f6d2256bcbba8345c bionic/libdl.so | sha256sum -c
  EXP=()
  if [ "$T3_CLIENT" = km ]; then EXP=(-Wl,--export-dynamic-symbol=mc*); fi
  clang-18 --target=aarch64-linux-android30 -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffreestanding -nostdinc -isystem "$(clang-18 -print-resource-dir)/include" -fPIE \
    -fno-stack-protector -ffixed-x18 -fno-exceptions -fno-asynchronous-unwind-tables \
    -fuse-ld=lld -nostdlib -pie -Wl,--dynamic-linker=/system/bin/linker64 -Wl,-z,now \
    -Wl,-z,relro -Wl,-z,noexecstack -Wl,--hash-style=gnu -Wl,--no-undefined -Wl,--build-id=none \
    "${EXP[@]}" "t3/crownlte-t3-$T3_CLIENT.c" bionic/libc.so bionic/libdl.so -o t3-client
  llvm-readelf-18 -h -l -d --dyn-syms t3-client > t3-client-readelf.txt
  grep -q 'Requesting program interpreter: /system/bin/linker64' t3-client-readelf.txt
  test "$(grep -c '(NEEDED)' t3-client-readelf.txt)" = 2
  grep -q 'Shared library: \[libc.so\]' t3-client-readelf.txt
  grep -q 'Shared library: \[libdl.so\]' t3-client-readelf.txt
  grep -q 'FLAGS_1.*PIE' t3-client-readelf.txt
  if grep -qE 'TEXTREL|RUNPATH|RPATH' t3-client-readelf.txt; then echo "t3-client: TEXTREL/RPATH"; exit 1; fi
  NMC=$(awk '$7!="UND" && $5=="GLOBAL" && $8 ~ /^mc[A-Z]/' t3-client-readelf.txt | wc -l)
  if [ "$T3_CLIENT" = km ]; then test "$NMC" = 9; else test "$NMC" = 0; fi
  T3_SHA=$(sha256sum t3-client | cut -c1-64)
  echo "t3-client ($T3_CLIENT) sha256 $T3_SHA"
  T3_DEFS=(-DT3_STAGE="\"$TEE_T3\"" -DT3_CLIENT_SHA="\"$T3_SHA\"")
  gcc -I. -O2 -Wall -Wextra -Werror -Wno-unused-function "${T3_DEFS[@]}" t3-seccomp-fixture.c -o t3-seccomp-fixture
  ./t3-seccomp-fixture | tee t3-seccomp-fixture.log
  aarch64-linux-gnu-gcc -static -Os -Wall -Wextra -Werror -I. "${T3_DEFS[@]}" tee-t3-run.c -o tee-t3-run
  cp tee-t3-run rootfs/crownlte/tee-t3-run
  cp t3-client rootfs/crownlte/t3-client
  T3_SUMS=(tee-t3-run.c t3-seccomp-fixture.c t3/* bionic/libc.so bionic/libdl.so tee-t3-run t3-client)
fi
chmod 0644 rootfs/crownlte/* rootfs/crownlte/sanitized/*
chmod 0755 rootfs/crownlte/probe.sh rootfs/crownlte/init_user0.sh rootfs/crownlte rootfs/crownlte/sanitized
chmod 0444 rootfs/crownlte/empty
find rootfs -exec touch -h -d @0 {} +
(cd rootfs; find . -mindepth 1 | LC_ALL=C sort | sed 's|^\./||' | (echo .; cat) |
   cpio -o -H newc --reproducible --owner=0:0 2>/dev/null) | gzip -n -9 > diagnostic-initramfs.cpio.gz
(cd rootfs; find . -type f | LC_ALL=C sort | xargs sha256sum) > rootfs-SHA256SUMS
sha256sum init.c romram.h romram-sha256.h gen_payload.py templates/* init diagnostic-initramfs.cpio.gz \
  payload/crownlte/manifest.txt "${T3_SUMS[@]}" > SHA256SUMS
cat SHA256SUMS
echo BUILD-OK
