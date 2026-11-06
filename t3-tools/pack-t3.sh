#!/bin/bash
# Pack the five T3 stages (loader + RECOVERY image), then drop shim-src/shim-out.
set -euo pipefail
K=/mnt/ssd/host-builds/kernel-upgrade
KO=$K/panel-bright-work/ko-tee-t3pin
IMG=$(sha256sum "$KO/arch/arm64/boot/Image" | cut -c1-64)
KSRC_DESC="crownlte-tee-3 fa72731b5 (blob-pinned guard on 566ee45af)"
cd "$K"
pack() {  # <stage> <build-n> <purpose>
  local st=$1 b=$2 purpose=$3
  local dtb=exynos9810-crownlte-romram-tee-$st.dtb
  local dsha rsha
  dsha=$(sha256sum "$KO/arch/arm64/boot/dts/exynos/$dtb" | cut -c1-64)
  rsha=$(sha256sum "rom-ram/build-$b/diagnostic-initramfs.cpio.gz" | cut -c1-64)
  env KO="$KO" DTB_NAME="$dtb" SHIM=bbea9590ba9bf57c673cee723e4e6817c08cdea7 \
      RAMDISK="rom-ram/build-$b/diagnostic-initramfs.cpio.gz" RAMDISK_SHA256="$rsha" \
      PURPOSE="$purpose" \
      KERNEL_SOURCE="$KSRC_DESC (Image ${IMG:0:8}, DTB tee-$st ${dsha:0:8} = tee-t3dbg 06a6cf36 + stage pins)" \
      python3 rom-ram/pack-rom-ram.py "rom-ram/pack-romram-tee-$st" "$dsha" > "/dev/shm/t3work/pack-$st.json"
  git -C /root/kernel-upgrade/boot-shim/crownlte worktree remove --force "$K/rom-ram/pack-romram-tee-$st/shim-src"
  rm -rf "$K/rom-ram/pack-romram-tee-$st/shim-out"
  echo "pack-romram-tee-$st: $(ls "rom-ram/pack-romram-tee-$st" | tr '\n' ' ') recovery $(sha256sum "rom-ram/pack-romram-tee-$st/recovery.img" | cut -c1-64)"
}
COMMON="kernel blob guard fa72731b5; FSD2+DebugSession session allow as T2j; daemon private user node; real HALs masked container-wide (software keymaster); client uid 1000 in own mount ns with exact seccomp; EFS RAM copy ro, hidden from the client; /dev/bsg RO-masked; no RPMB proxy; deadline 600"
pack t3a0 20 "TEE T3a-0 (build-20): keymaster TA ffff..3e open+close only via crownlte-t3-km; trustlet pin KM only; no driver loads; $COMMON"
pack t3a1 21 "TEE T3a-1 (build-21): keymaster TA open + addRngEntropy(32 B) + close via crownlte-t3-km; trustlet pin KM only; no driver loads; $COMMON"
pack t3a2 22 "TEE T3a-2 (build-22): daemon -r sec 01/TIMA d..0a/CryptoManager d..16 (pinned; VaultKeeper not); keymaster open + configure(os_version 160000, patchlevel 202608; props checked) + addRngEntropy + close; $COMMON"
pack t3b0 23 "TEE T3b-0 (build-23): gatekeeper TA 0813.. open+close only via crownlte-t3-gk (libMcClient, no HAL, no TCI command); trustlet pin GK only; no driver loads; $COMMON"
pack t3b1 24 "TEE T3b-1 (build-24) *** SEPARATE APPROVAL: sends ONE gatekeeper VERIFY (cmd 2) *** fake uid 0x7ffffff0, synthetic handle, random password, 15 s bound, no gk_context write; daemon -r CryptoManager d..16 only (pinned); TA-side failure-record update would need SRPMB (absent on 6.12); $COMMON"
