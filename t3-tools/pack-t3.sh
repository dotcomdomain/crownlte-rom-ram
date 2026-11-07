#!/bin/bash
# Pack the five T3 stages and T2j (loader + RECOVERY image) with the S1 kernel,
# then drop shim-src/shim-out. Replaces the superseded packs in place: each old
# pack is removed only if its manifest names the expected old Image.
set -euo pipefail
K=/mnt/ssd/host-builds/kernel-upgrade
KO=$K/panel-bright-work/ko-tee-t3s1
IMG=$(sha256sum "$KO/arch/arm64/boot/Image" | cut -c1-64)
KSRC_DESC="crownlte-tee-3 22a6b88cc (registry guard S1 on fa72731b5)"
SHIM=bbea9590ba9bf57c673cee723e4e6817c08cdea7
mkdir -p /dev/shm/t3work
cd "$K"
pack() {  # <pack> <dtb-stage> <ramdisk build-n> <old Image sha> <purpose> <kernel_source>
  local p=$1 dst=$2 b=$3 old=$4 purpose=$5 ksrc=$6
  local dtb=exynos9810-crownlte-romram-tee-$dst.dtb W=rom-ram/pack-romram-tee-$p
  local dsha rsha
  if [ -e "$W" ]; then
    python3 -c "import json,sys; sys.exit(json.load(open('$W/manifest.json'))['Image_sha256'] != '$old')"
    rm -rf "$W"
  fi
  dsha=$(sha256sum "$KO/arch/arm64/boot/dts/exynos/$dtb" | cut -c1-64)
  rsha=$(sha256sum "rom-ram/build-$b/diagnostic-initramfs.cpio.gz" | cut -c1-64)
  env KO="$KO" DTB_NAME="$dtb" SHIM=$SHIM \
      RAMDISK="rom-ram/build-$b/diagnostic-initramfs.cpio.gz" RAMDISK_SHA256="$rsha" \
      PURPOSE="$purpose" KERNEL_SOURCE="$ksrc (Image ${IMG:0:8}, DTB tee-$dst ${dsha:0:8})" \
      python3 rom-ram/pack-rom-ram.py "$W" "$dsha" > "/dev/shm/t3work/pack-$p.json"
  git -C /root/kernel-upgrade/boot-shim/crownlte worktree remove --force "$K/$W/shim-src"
  rm -rf "$K/$W/shim-out"
  echo "pack-romram-tee-$p: $(ls "$W" | tr '\n' ' ') recovery $(sha256sum "$W/recovery.img" | cut -c1-64)"
}
T3OLD=a466abe215a07834072cd4188c0f18a16180359ef22e15d61a13b9655ea60334
T2OLD=dabc09eba0254e1ff90ab6e369f294994a4a43534f4328c1bb72ba19f068d84e
COMMON="kernel 22a6b88cc (blob guard + registry guard: unpinned UUIDs SWd selection only); FSD2+DebugSession session allow as T2j; daemon private user node, no io_uring; real HALs masked container-wide (software keymaster); client uid 1000 in own mount ns + own pid ns with fresh /proc (hidepid=invisible), exact seccomp (no io_uring/clone ns); EFS RAM copy ro, hidden from the client; /dev/bsg RO-masked; no RPMB proxy; deadline 600"
T3K="$KSRC_DESC, ramdisk tee-t3 452c728"
pack t3a0 t3a0 25 $T3OLD "TEE T3a-0 (build-25): keymaster TA ffff..3e open+close only via crownlte-t3-km; trustlet pin KM only; no driver loads; $COMMON" "$T3K"
pack t3a1 t3a1 26 $T3OLD "TEE T3a-1 (build-26): keymaster TA open + addRngEntropy(32 B) + close via crownlte-t3-km; trustlet pin KM only; no driver loads; $COMMON" "$T3K"
pack t3a2 t3a2 27 $T3OLD "TEE T3a-2 (build-27): daemon -r sec 01/TIMA d..0a/CryptoManager d..16 (pinned; VaultKeeper not); keymaster open + configure(os_version 160000, patchlevel 202608; props checked) + addRngEntropy + close; $COMMON" "$T3K"
pack t3b0 t3b0 28 $T3OLD "TEE T3b-0 (build-28): gatekeeper TA 0813.. open+close only via crownlte-t3-gk (libMcClient, no HAL, no TCI command); trustlet pin GK only; no driver loads; $COMMON" "$T3K"
pack t3b1 t3b1 29 $T3OLD "TEE T3b-1 (build-29) *** SEPARATE APPROVAL: sends ONE gatekeeper VERIFY (cmd 2) *** fake uid 0x7ffffff0, synthetic handle, random password, 15 s bound, no gk_context write; daemon -r CryptoManager d..16 only (pinned); TA-side failure-record update would need SRPMB (absent on 6.12); $COMMON" "$T3K"
pack t2j t3dbg 17 $T2OLD "TEE T2 v5 (T2j), repacked with the S1 kernel: session guard allows FSD2 07050501..20 + DebugSession 08050500..00, both now by SWd selection only (daemon not asked for a blob); admin loads refused; daemon private user node; EFS RAM copy ro; deadline 600" "$KSRC_DESC"
rm -rf /dev/shm/t3work
