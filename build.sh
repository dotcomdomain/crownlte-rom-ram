#!/bin/bash
# crownlte ROM-in-RAM diagnostic ramdisk build (gekko, /mnt/ssd only).
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

# 1. Composite read-only root from the partition backups (as the phone mounts them).
if ! mountpoint -q "$TR"; then
  mkdir -p "$TR"
  mount -o ro,loop,noload "$P/SYSTEM.img" "$TR"
  mount -o ro,loop,noload "$P/VENDOR.img" "$TR/vendor"
  mount -o ro,loop,noload "$P/ODM.img" "$TR/odm"
fi

# 2. Payload.
DEADLINE=${DEADLINE:-300} python3 gen_payload.py "$TR" payload

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
aarch64-linux-gnu-gcc -static -std=gnu11 -Os -Wall -Wextra -Werror -Wno-format-truncation init.c -o init
aarch64-linux-gnu-readelf -h -l init > init-readelf.txt
if grep -q INTERP init-readelf.txt; then echo "init is dynamic"; exit 1; fi

# 5. Reproducible initramfs: /init + /crownlte payload.
mkdir rootfs
cp init rootfs/init; chmod 0755 rootfs/init
cp -r payload/crownlte rootfs/crownlte
chmod 0644 rootfs/crownlte/* rootfs/crownlte/sanitized/*
chmod 0755 rootfs/crownlte/probe.sh rootfs/crownlte/init_user0.sh rootfs/crownlte rootfs/crownlte/sanitized
chmod 0444 rootfs/crownlte/empty
find rootfs -exec touch -h -d @0 {} +
(cd rootfs; find . -mindepth 1 | LC_ALL=C sort | sed 's|^\./||' | (echo .; cat) |
   cpio -o -H newc --reproducible --owner=0:0 2>/dev/null) | gzip -n -9 > diagnostic-initramfs.cpio.gz
(cd rootfs; find . -type f | LC_ALL=C sort | xargs sha256sum) > rootfs-SHA256SUMS
sha256sum init.c romram.h romram-sha256.h gen_payload.py templates/* init diagnostic-initramfs.cpio.gz \
  payload/crownlte/manifest.txt > SHA256SUMS
cat SHA256SUMS
echo BUILD-OK
