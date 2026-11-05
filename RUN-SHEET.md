# Run sheet: crownlte ROM-in-RAM diagnostic (q-romram, 2026-11-04)

Image: gekko `/mnt/ssd/host-builds/kernel-upgrade/rom-ram/pack-romram-20261104/recovery.img`
sha256 `829f8f183b394605526e8bf771f587b771af2e0ad19abbfb196feffa0145e8a4` (68,149,248 bytes).
Windows copy: `C:\Users\Patrick\tools\trial-romram-20261104\recovery.img`.

| input | sha256 |
|---|---|
| kernel Image (integration 31caf697c, build/integration-android-6.12.93; same as q25) | a3f7f56f71320edb30dad1fde1258c5dc2a885a3722271f9d4bcfc190ce2af8c |
| DTB exynos9810-crownlte-delayed-ufs-diag.dtb (same as q25; has crownlte,read-only-diagnostic, bootargs "panic=30 ro") | 7767600a4df2f6c04a04d88aa19266b6abb8143d3be8cc1d8a5834a039ef928d |
| ramdisk rom-ram/build-1/diagnostic-initramfs.cpio.gz (reproducible) | 7806c3592d3374cae23fdbfad94b3c9a142639883066944ea7bc40694c2fb88b |
| shim 3a3284e (INFORM normal fix) | loader 7bd73971fb484e1d0b96e0257f25c8da74a020d218e3006157350a6f4b0f94b8 |
| restore image (bright RECOVERY) | 8763860c11a272cb6c341f2fc561e38adb5ea621a16ef7a5b083d9b6d28a8a0e |

## Before
- The phone must still run the Lineage build in the 2026-11-03 backups. The ROM stage checks SYSTEM/VENDOR/ODM
  partition sizes and the sha256 of 139 files (all init rc files, build.prop files, fstab, /system/bin/init,
  sepolicy cil). After an OTA it refuses to start Lineage init and logs `verify MISMATCH`/`UNKNOWN`. Nothing breaks,
  but the payload has to be regenerated: `rom-ram/src/build.sh <new dir>`.
- Hang risk is higher than in kernel-only trials, because Lineage userspace pokes much more hardware. Have Odin and
  bright-recovery.tar ready (RECOVERY-LOOP lesson).
- Flash RECOVERY and boot recovery with the usual procedure. The kernel, DTB and shim are the q25 ones.

## Serial (COM4, 1d6b:0104), exact frames, in order
1. Open the port. Send `CROWNLTE-UFS-READY-1\n`. The cached log starts flowing.
2. Wait for `UFS readiness snapshot complete; probe remains held` **and for it to arrive on the host**.
   Then send `CROWNLTE-UFS-PROBE-1\n`. In this trial the UFS probe is intended: it is the read-only guarded probe.
3. Send `CROWNLTE-ROMRAM-START-1\n`. It may follow PROBE right away. PID1 latches it and starts the ROM stage
   only after `UFS probe child reaped status=0 ok=1`.
   - Any other byte, or a wrong order, disables the UFS and ROM stages for this boot. Logging continues, and the
     restart still happens at 300 s.
   - The ROM stage refuses to start later than 240 s after PID1 start.
   - Do not close the port between the frames. EOF or a read error after READY also disables the stage.
4. Keep reading until the phone resets. Afterwards PID1 ignores all input.

## Timeline (PID1 clock, from /init start)
- `default restart planned after 300s (source=1 ...)`: deadline read from /crownlte/deadline_seconds.
  It is clamped to 60–900 s and enforced by the independent timer child. The container is killed at 275 s.
- About 1–3 s: `USB result stage=gadget-bound`, `serial open errno=0`.
- After PROBE: `UFS probe bind end errno=0`. The SCSI scan then adds sda… and the guard logs
  `diagnostic rejects SCSI opcode` lines if anything tries to write.
- After START: `crownlte-romram:` stage lines, in this order:
  `UFS host bound with crownlte,read-only-diagnostic`, `found N sd* nodes; SYSTEM=sda18 VENDOR=sda19 ODM=sdaX`,
  `BLKROSET=1 verified on all N sd* nodes`, three `mount ... ext4 ro noload`,
  `manifest verified: 139 files hashed`, five `rc overlay ...` lines, `masked dir/file ...` lines,
  `container /proc/cmdline: ...`, and finally `exec /system/bin/init selinux_setup`.
  A failure prints `ROM stage STOPPED stage=<name> errno=<n>`, then
  `ROMRAM container reaped ... exited=1 code=1`. Nothing is retried.
- Lineage init: `init: ...` kernel-log lines. SELinux policy is compiled on the device with secilc,
  because there is no precompiled_sepolicy. Allow 10–40 s.
  Then come the markers `crownlte-romram: Lineage init second stage reached early-init`, `on fs (mount_all disarmed...)`,
  `post-fs-data reached`, `init_user0 begin/end rc=`, `derive_classpath running/stopped`, `zygote-start reached`,
  `zygote running`, and `sys.boot_completed=1`.
- `L;` lines are logcat (`-b all -v threadtime`) and `P;` lines are probe snapshots every 10 s:
  getprop (init.svc.*, apexd.*, keystore.*, odsign.*, crypto), enforce, meminfo, plus ps and df every 30 s.
- `P;CROWNLTE-BYPASS ...` means a diagnostic bypass fired (see below). The thing it bypassed is a blocker in its own
  right and should be reported as one.
- 275 s: `ROMRAM deadline teardown ... SIGKILL`. 300 s: timer restart, normal boot to Lineage.
- Every 15 s: an `alive` line with `cache_dropped` / `kmsg_lost` counters. The printk ring is only 128 KiB, so
  non-zero `kmsg_lost` means kernel lines were lost during floods. logcat still has them.

## Reading the container exit
`ROMRAM container reaped ... exited/signaled`:
- `signaled=1 signal=1` (SIGHUP): Lineage init requested a reboot (RESTART/RESTART2) inside the PID namespace.
  Look just above for `init: ... reboot` / `sys.powerctl` / `reboot_on_failure` / `critical process ... crashed`.
  In a namespace this only kills the namespace. The phone keeps running until 300 s.
- `signal=2` (SIGINT): Lineage asked for power-off or halt.
- `signal=9` with `killed=1`: our 275 s teardown, so the boot was still in progress.
- `exited=1`: the ROM stage refused, before init ran.

## Diagnostic deviations from a real boot (all logged)
- First-stage init is emulated by the namespace child. Lineage's own `/system/bin/init selinux_setup` and
  `second_stage` run unmodified.
- androidboot.* come from a substituted container /proc/cmdline: hardware=samsungexynos9810,
  selinux=permissive (the build is userdebug), init_rc=/dev/crownlte/init.diag.rc, mode=normal,
  verifiedbootstate=orange, flash.locked=0, debug_level=0x4f4c, boot_devices=11120000.ufs, and placeholder
  serialno/bootloader. These were not captured from SBoot, so they are not the phone's real values.
- init.diag.rc imports init.rc plus the same five rc dirs as the default boot-script loader. It adds the probe and
  logcat services, and in `on fs` it sets `ro.crypto.state=unencrypted` and triggers `nonencrypted`, which is what
  mount_all would publish for an unencrypted /data.
- rc overlays:
  - vendor `init.samsungexynos9810.rc`: `mount_all` and `swapon_all` commented out.
  - `cppreopts.rc`: postinstall `mount_all`/`umount_all` commented out.
  - `init.rc`: `init_user0` replaced by `vdc --wait cryptfs init_user0`, bounded to 60 s and without
    reboot-to-recovery.
  - `vendor_flash_recovery.rc` and `misctrl.rc` replaced by empty files.
- Bypasses: `keystore.module_hash.sent=true` after 40 s of apexd activated/ready. `odsign.key.done=1` and
  `odsign.verification.done=1` after 60 s each. To disable them, remove /crownlte/bypass_enabled and rebuild.
- EFS, USERDATA, CACHE, PERSISTENT, CPEFS and MISC are never mounted or opened. /data is a 1.5 GiB tmpfs, /cache a
  64 MiB tmpfs, /dev a 512 MiB tmpfs.

## Expected next-blocker candidates (rough order)
1. SELinux setup: secilc compile/load of the A16 policy on 6.12, or `restorecon` of init_exec on the read-only fs.
   Any fatal error makes init reboot, which shows as a namespace SIGHUP.
2. Early-init `reboot_on_failure`/`critical` services: boringssl self-tests, apexd-bootstrap (loop, dm-verity,
   BLK_DEV_WRITE_MOUNTED), linkerconfig, ueventd coldboot, servicemanager/hwservicemanager.
3. keystore2 on keymaster@3.0/Trustonic (no /dev/mobicore): `keystore.module_hash.sent` never set (bypassed after
   40 s), or keystore2 `critical` crash loop → namespace reboot.
4. vold `init_user0` with the FBE fstab against a tmpfs /data (rc logged, not fatal here). vold itself is
   `reboot_on_failure`.
5. **derive_classpath**, the previous crash, now on a kernel with SECCOMP, USERFAULTFD, TMPFS_XATTR and IKCONFIG.
   Look for `derive_classpath stopped` and a tombstone or `F DEBUG` lines in `L;`.
6. art_boot / odsign / odrefresh (keystore-dependent; possibly long dex2oat into RAM).
7. netbpfload/bpfloader `reboot_on_failure` (eBPF feature checks on 6.12).
8. zygote → system_server, then SurfaceFlinger/HWC without Mali or DECON fbdev (`critical` → namespace reboot).
   lmkd needs PSI (present).

## After the run (integrator)
- Save the full serial log. Split it into kernel/PID1 records, `L;` and `P;` with
  `grep -a '^L;'` / `grep -a '^P;'`.
- In Lineage: `/sys/fs/pstore/` as usual. Lineage-in-RAM cannot write /dev/pmsg0 (shadowed), so pmsg keeps the
  kernel tail.
- Restore bright RECOVERY (8763860c) and wait for boot=booted as usual.

---

# v4 (q47 kernel, no fbcon/VT): ROM-in-RAM on the hardware-verified display kernel (2026-11-04)

Supersedes v3 (`pack-romram-20261104c`, recovery ff972eac). The v3 sections above (frames, timeline, container
exit codes, deviations, blocker list) still apply. This section covers only the differences and the new display
milestones.

Image: gekko `rom-ram/pack-romram-20261104d/recovery.img`
sha256 `2fc2756aa4fd4f88002232c0c30a4c04a94ee76622d98409abb11bb9e1533fcf` (68,149,248 bytes).
Windows: `C:\Users\Patrick\tools\trial-romram-20261104\v4-q47\recovery.img` (+ manifest.json, hash verified).

| input | sha256 |
|---|---|
| kernel Image: crownlte-display-flipfix e39c11f1e (= q47 source), q47 config with CONFIG_VT=n, build/romram-6.12.93 | f5e46ef73342ab0181c34a7929cb49e893da1460cc4bb20db407514104a21e28 |
| .config (snapshot build/romram-6.12.93/v4/config) | 69518817c3e0abac54223269d59d01366e2a4f5d5fecf2481b6cb8ed4f1dec39 |
| DTB exynos9810-crownlte-romram.dtb (rom-ram src 6b2bfb5 dts/, on top of the q47 combined DTS 4530f0c5) | 8c5ec543fd753e7addc3bc37777765a5628a8dc109e7f1c99882507a234bc18a |
| ramdisk rom-ram/build-3/diagnostic-initramfs.cpio.gz (src 6b2bfb5) | cd8dbf8c14bc97e6fed91d9a736bda7585d17d37553bf2307ba2926779e36298 |
| shim bbea959 (loader) | 42a66811f0b7adcf24706e7291bacbca86963f4c35946f8136db61012a107d5d |
| restore image (bright RECOVERY) | 8763860c11a272cb6c341f2fc561e38adb5ea621a16ef7a5b083d9b6d28a8a0e |

## What changed vs v3
- Kernel: q25 integration 31caf697c (Image a3f7f56f) -> crownlte-display-flipfix e39c11f1e. This is the q45/q47
  hardware-verified set: ACPM DVFS/cpufreq/devfreq/TMU, PMIC+RTC read-only (RTC read latch), watchdog + restart
  guard, DECON stage 2 adopt with WIN_CONFIG and a verified active IDMA base, panel brightness 44700 at 1 s, Mali
  r38p1 with the runtime G3D domain, SoC ADC + MAX77705 read-only battery, MCT broadcast. The TEE and touch drivers
  are built, but their DT nodes are disabled.
- Config vs q47: `VT` y->n. This also drops FRAMEBUFFER_CONSOLE, VT_CONSOLE(_SLEEP), VT_HW_CONSOLE_BINDING,
  DUMMY_CONSOLE, CONSOLE_TRANSLATIONS and the FONTS menu (FONT_TER16x32 goes; FONT_AUTOSELECT/8x16 stay).
  Reason: fbcon printk with IRQs off cost 20-130 ms per line (in q46 the brightness window took 4.9 s and the MCT
  probe was refused). 4.9 had no VT.
  Config vs v3 (taken from the v3 image's IKCONFIG): only additions (cpuidle + MCT broadcast + menu governor,
  NO_HZ_IDLE, DPU fbdev + panel RO backlight, IIO + EXYNOS_ADC, MAX77705 battery RO, Mali midgard r38p1,
  SEC_TS touch driver) plus the VT/fbcon removal. Nothing ROM-RAM needs was lost. Binder/binderfs, memfd, dm, loop,
  erofs/f2fs/ext4, SELinux, seccomp, userfaultfd, PSI, dma-buf heaps, sync_file, uhid and evdev are unchanged.
- DTB vs q47 combined (4530f0c5): removed `samsung,decon-selftest` (HWC owns WIN_CONFIG), `samsung,cpuidle-selftest`
  (+soak), `samsung,mali-selftest` (+selftest-khz), `samsung,cpufreq-selftest` and `samsung,devfreq-selftest`. The
  model string is new. The decompiled diff shows nothing else.
  Kept:
  - UFS `crownlte,read-only-diagnostic` (held first probe + SCSI write guard). The UFS node is identical to v3
    apart from phandle numbers, and drivers/ufs is unchanged since 31caf697c.
  - Stage 2 adopt + `samsung,fb-takeover`, and brightness 44700 at 1000 ms.
  - Watchdog `samsung,start-at-boot`, 30 s, pinged by the kernel. No expiry test.
  - Read-only reports: MCT at 86 s, TMU, PMIC/RTC at 106 s, ADC at 104 s, battery at 107 s.
  - TEE, touch, DPU SysMMU and the handover helper stay disabled; bootargs stay `panic=30 ro`.
  **C2 cpuidle is OFF (WFI only).** The driver arms C2 only from the staged self-test or from
  `samsung,c2-boot-cpus`, and the boot path is always refused. cpuidle/ links before clocksource/, so when cpuidle
  probes, the MCT broadcast is not ready yet. Big-only C2 without the self-test needs a kernel change (arm once the
  MCT is ready, or from a late initcall).
- Ramdisk: only `/init` changed (src 6b2bfb5). Without a console tty, the kernel cannot open /dev/console for PID1.
  fds 0-2 then start closed, and the kmsg/serial fds could become stdio (announce() writes every line to fd 2).
  PID1 now pins fds 0-2 to /dev/null. Everything else is byte-identical to v3: the payload, the manifest (139 files,
  5b3170e6), the rc overlays (uncrypt EMPTY, mount_all disarmed, ...), the TEE refusal and all ROM-stage checks.

## How to run
Same procedure and frames as v3. Capture to a separate output file:
```
powershell -ExecutionPolicy Bypass -File C:\Users\Patrick\tools\trial-romram-20261104\romram-capture.ps1 -Out C:\Users\Patrick\tools\trial-romram-20261104\v4-q47\serial-romram-v4.bin
```
The script runs 330 s by default. It sends READY, then PROBE + CROWNLTE-ROMRAM-START-1 after `probe remains held`.
The run takes about 5.5 min, followed by the normal Lineage boot. Someone should watch the screen, because the
display result can only be judged visually.

## Expected milestones (serial, in order)
Kernel, first seconds (printk time):
- `adopted: win.. dpp.. IDMA format .. at 0xcc000000`, `fb0 takeover: ... latched after .. us`,
  `adopt mode ready: TE irq N, fb0 window owned`. No `decon selftest:` line should appear.
- `panel-bright: start at 1.0xx s`, then `panel-bright: RESULT PASS ... brightness 44700, read-back ...`.
  No console prints with IRQs off any more, so the window should stay well under 1 s (q47: 718 ms). On the panel,
  the flicker should stop at about 1 s.
- `exynos9810-mct-bc: tick broadcast device registered` and `exynos9810-cpuidle: registered: ... C2 disarmed on
  every CPU`. No `cpuidle selftest: scheduled` line should appear.
- `watchdog active, reset enabled ...`, `mali exynos9810: GPU_ID ...` and `G3D power control "runtime"`.
  No `mali selftest: armed` line should appear. Then `diagnostic first probe held for USB host`.
- "Warning: unable to open an initial console." is expected (no VT).

PID1:
- New: `crownlte-diag: no /dev/console (errno=19, kernel without VT); stdio pinned to /dev/null fd0=1 fd1=1 fd2=1`.
- Then the v3 sequence: gadget bound, `probe remains held`, PROBE, `UFS probe child reaped status=0 ok=1`, and the
  ROM stage (`Trustonic TEE absent`, `BLKROSET=1 verified`, 3 ro mounts, `manifest verified: 139 files`, overlays,
  masks, `exec /system/bin/init selinux_setup`).

Lineage (markers from init.diag.rc, then `L;` logcat and `P;` probe lines):
- secilc + policy load (10-40 s), `second stage reached early-init`, `on fs`, `post-fs-data`, `zygote-start`.
- Display (new in v4), read from `L;`/`P;` and the kernel lines:
  1. ueventd creates `/dev/graphics/fb0` and `/dev/mali0`. `P;` getprop shows `init.svc.vendor.hwcomposer-3`
     (HWC3 slsi), `init.svc.vendor.gralloc-2-0` and `init.svc.surfaceflinger` = running.
  2. HWC opens fb0. Blank/power-mode requests are accepted and ignored (`blank N ignored (adopt mode, no panel
     driver)`), so Android cannot switch the panel off. Vsync comes from TE.
  3. WIN_CONFIG commits. Likely blocker: gralloc (libion_exynos, via /dev/dma_heap) hands out scattered system-heap
     buffers, and without the DPU SysMMU the driver refuses them. The kernel logs `buffer not contiguous (segment
     N); needs the DPU SysMMU` and `win.. rejected (...)`. A rejected config is not applied, so the panel keeps the
     last good frame (the SBoot image). This is a known, safe outcome. The fix is the dpu-iommu work (q28).
  4. If commits are accepted (contiguous/CMA buffers): `init.svc.bootanim=running` and the boot animation shows on
     the panel.
- `sys.boot_completed=1` is the stretch goal. `P;CROWNLTE-BYPASS ...` lines mark keystore/odsign blockers, as in v3.
- Kernel read-only reports interleave at about 86 s (MCT) and 104-107 s (ADC, battery, TMU, PMIC/RTC). They are
  harmless.
- adb: **not expected.** PID1's ACM gadget owns the only UDC, so Android's `write /config/usb_gadget/g1/UDC` fails
  (EBUSY) and the serial link stays up. All observation goes over serial (`L;`, `P;`, kernel).
- Touch: disabled, so there is no input.

## Success levels
1. Kernel, PID1 and the ROM stage reach `exec /system/bin/init selinux_setup` with `Trustonic TEE absent`, and the
   write guard rejects nothing unexpected.
2. Lineage reaches zygote/system_server (`zygote running`).
3. surfaceflinger + HWC are running, fb0 is opened, and WIN_CONFIG attempts are visible (accepted, or rejected with
   the reason).
4. The boot animation shows on the panel (needs contiguous buffers) and/or `sys.boot_completed=1`.
The panel flicker stopping at about 1 s is a pass on its own (owner-visible).

## Abort / return path
- Normal: container SIGKILL at 275 s, then the independent timer restarts at 300 s through the watchdog restart
  guard (`restart: armed for 30 s and no longer petted`). Shim bbea959 then boots normally into Lineage (4.9, BOOT).
- Kernel hang: the CL0 watchdog (30 s, pinged by the kernel) resets the phone. Android cannot open /dev/watchdog*
  (shadowed). After a panic, `panic=30` reboots.
- Stuck with no reset: hold Power + Volume Down for about 10 s. If the phone loops into RECOVERY, use Odin with
  bright-recovery.tar.
- After return: save the serial log and read `/sys/fs/pstore/` as usual. Restore bright RECOVERY (8763860c) and
  wait for boot=booted (~8 min) before the next reboot.
- Never run this with a TEE-enabled DTB. The ROM stage refuses it anyway (`Trustonic TEE present` /
  `DT /tee status=okay`).

---

# v6: keymaster without the TEE, TEE clients off, fb0 colours fixed (2026-11-04)

Builds on v5 (`pack-romram-20261104e`, recovery c8cf058d: UFS LRB fix 900d76030). The v3/v4 sections above still
apply. This section covers only the differences.

Image: gekko `rom-ram/pack-romram-20261104f/recovery.img`
sha256 `db96d05d8fa314d4ec0c7da9acd2c15c5a230a6c2f33a91421df02a4ded942c3` (68,149,248 bytes).
Windows: `C:\Users\Patrick\tools\trial-romram-20261104\v6\recovery.img` (+ manifest.json, hash verified).

| input | sha256 |
|---|---|
| kernel Image: crownlte-display-flipfix 550660610 (900d76030 + fb0 format fix), config = v4 (VT=n), build/romram-6.12.93 (snapshot v6/) | 1d98cee711f8f2acc0fddb629aa882ca01d0fa269636dfbcfa1a8164c3b0a654 |
| .config (unchanged since v4) | 69518817c3e0abac54223269d59d01366e2a4f5d5fecf2481b6cb8ed4f1dec39 |
| DTB exynos9810-crownlte-romram.dtb (unchanged since v4) | 8c5ec543fd753e7addc3bc37777765a5628a8dc109e7f1c99882507a234bc18a |
| ramdisk rom-ram/build-4/diagnostic-initramfs.cpio.gz (src 34fcf4c) | 2a4263f0c67e720f5b194c808fdb9d029bcece72a5b080682db9d3bb450051ac |
| payload manifest (152 entries, 146 files hashed) | d727af14e82eb8644ba653ab753edb18755b55ce4d56ffc6b01e0e345cf22c9a |
| shim bbea959 (loader) | 19865d47b276c07bd176c2a0002196cdb04f1783c721b58b2f0c7533a24b9c11 |
| restore image (bright RECOVERY) | 8763860c11a272cb6c341f2fc561e38adb5ea621a16ef7a5b083d9b6d28a8a0e |

## What changed vs v5
- **Keymaster without the TEE.** The v5 block was keystore2 (`critical`), which builds its mandatory TEE security
  level through km_compat. km_compat blocked in HIDL `getService()` for the declared keymaster@3.0, whose MDFPP
  module could not open the TEE. `android.security.maintenance` never registered, so vold's earlyBootEnded never
  returned.
  v6 masks `/vendor/lib64/hw/keystore.mdfpp.so` (the module selected by `ro.hardware.keystore=mdfpp`; it loads
  libkeymaster2_mdfpp -> libkeymaster_helper_vendor -> libMcClient). `hw_get_module_by_class("keystore")` then
  fails, and the stock keymaster@3.0-impl uses its built-in SoftKeymasterDevice. km_compat (system) uses that
  insecure HAL as the TEE device. This is the stock software path; both log strings are in the shipped binaries.
  The vendor.keymaster-3-0 service therefore still runs, but as pure software. Keys exist only in keystore2's
  database on the tmpfs /data.
- **TEE clients disabled** with EMPTY rc overlays: `mobicore` (mcDriverDaemon), `vendor.gatekeeper-1-0`,
  `vendor.drm-widevine-hal-1-2`, `vendor.wvkprov_server_hal` and `vendor.fingerprint-default`. `libMcClient.so`
  (lib64 + lib) is EMPTY as well, so any client that is still left fails to load instead of calling the TEE. No
  enabled service links it.
- **VINTF:** the drm/widevine, gatekeeper and widevine-keyprovisioning HALs are removed from
  `/vendor/etc/vintf/manifest.xml`, and the fingerprint HAL from its fragment, so gatekeeperd and system_server do
  not wait for them. keymaster@3.0 stays declared.
- **init.rc:** `exec vdc keymaster earlyBootEnded` -> `exec_background`, so a slow HAL can never block boot again.
- **Deadline 600 s** (was 300). The container is killed at 575 s.
- New kmsg markers for keymaster, keystore2, module hash, HWC3, surfaceflinger, bootanim and system_server. Probe
  lines also show `service.bootanim.*` and `sys.system_server.*`.
- **Kernel, fb0 colours (550660610):**
  - Cause: SBoot scans the boot buffer with IDMA format 0 (ARGB8888, bytes A,R,G,B). The takeover committed the
    4.9 default DPP BGRA_8888, which produced the blue background and pink logo.
  - Fix: adopt now records the SBoot format, and the takeover (and the self-test restore) keep it. fb0 reports the
    matching fb_bitfield layout. The buffer is not rewritten, so the panel should not change at the takeover.
  - The A/B self-test buffers keep BGRA_8888.

## Why it is safe
- `init.c` and `romram.h` are byte-identical to v4/v5. The SCSI write guard check, BLKROSET on every sd* node, the
  TEE refusal (`/dev/mobicore*`, mcd binding, DT /tee) and the read-only mounts are unchanged.
- The overlays still disarm mount_all/swapon_all; uncrypt, misctrl and vendor_flash_recovery stay EMPTY.
  init_user0 is still bounded, and nothing writes misc/BCB or any partition. The generator still refuses unhandled
  storage-mutating rc lines.
- Every file the overlays replace or mask is sha256-verified before init runs (146 files). A changed vendor or
  system image means `verify MISMATCH` and no Lineage start.
- v6 only removes TEE contact. The TEE is absent anyway (DT /tee disabled; the ROM stage refuses otherwise). Now no
  TEE daemon starts, no TA client library can load, and keymaster never tries the secure world. The software
  keymaster writes nothing outside the tmpfs /data, so there is no key upgrade or rewrap that 4.9 could see.

## How to run
Same frames as before. Capture longer:
```
powershell -ExecutionPolicy Bypass -File C:\Users\Patrick\tools\trial-romram-20261104\romram-capture.ps1 -Seconds 630 -Out C:\Users\Patrick\tools\trial-romram-20261104\v6\serial-romram-v6.bin
```
The run takes about 10.5 min, followed by the normal Lineage boot. Watch the screen.

## Expected milestones
Kernel:
- `adopted: win.. dpp.. IDMA format 0 at 0xcc000000; fb0 keeps it (DPP format 0)`.
- `fb0 takeover: ... DPP format 0 (SBoot IDMA format 0 kept) ...: 0, latched ...`. **On the panel, the SBoot logo
  keeps its original colours.** No blue background or pink logo.
- `panel-bright: RESULT PASS` at about 1 s (flicker stops). UFS as in v5: sda + sdb..sde.

PID1 / ROM stage:
- `default restart planned after 600s ... container SIGKILL at 575s`.
- `BLKROSET=1 verified on all 31 sd* nodes`, `Trustonic TEE absent`, `manifest verified: 146 files hashed`.
- 11 `rc overlay ... -> empty` lines (5 new: fingerprint, widevine, gatekeeper, mobicore, wvkprov; plus
  keystore.mdfpp.so and both libMcClient.so) and 5 `-> replace` lines (init.rc, init.samsungexynos9810.rc,
  cppreopts.rc, 2 VINTF files).

Lineage (`crownlte-romram:` kmsg markers and `L;` logcat):
- `L; ... android.hardware.keymaster@3.0-impl: Could not find any keystore module, using software-only
  implementation.` and the marker `keymaster@3.0 HAL running (software-only, no TEE module)`.
- In keystore2: `No secure Keymaster implementation found, but device offers insecure Keymaster HAL. Using as
  default.`, then `keystore2 running`. The `vdc keymaster earlyBootEnded` background exec exits with status 0.
- Absent: `TeeMcDaemon`, `starting service 'mobicore'`, `mkdir /efs/TEE`, `keymaster_tee`, `nwd_tz_open`.
- `keystore.module_hash.sent=true`, or `P;CROWNLTE-BYPASS keystore.module_hash.sent` after 40 s (init waits on it
  before class main).
- `zygote-start reached`, `zygote running`, `system_server started`.
- `HWC3 (vendor.hwcomposer-3) running`, `surfaceflinger running`, `bootanim running`. On the kernel side, fb0 is
  opened and the WIN_CONFIG commits follow. They are either accepted (boot animation on the panel) or rejected
  with `buffer not contiguous (segment N); needs the DPU SysMMU` / `win.. rejected`. When rejected, the panel keeps
  the SBoot logo, now in the right colours.
- Expected, harmless: gatekeeperd `Could not find Gatekeeper device, which makes me very sad.`
- Stretch: `sys.boot_completed=1`.

Likely next blockers:
- keystore2 still refuses the software device. Watch for a keystore2 panic plus a namespace SIGHUP: it is
  `critical`, so 4 crashes reboot the namespace only.
- system_server pieces that need gatekeeper/fingerprint (LockSettings, biometrics). The HALs are now undeclared, so
  these should fail fast instead of hanging.
- odsign/odrefresh (bypassed after 60 s), netbpfload, and the display buffer path above.
- No adb (PID1's ACM owns the UDC). Touch is off.

## Success levels
1. Past `vdc keymaster earlyBootEnded`, with keystore2 running on the software keymaster.
2. zygote and system_server start.
3. surfaceflinger + HWC3 running, fb0 WIN_CONFIG attempts logged (accepted or rejected with the reason). Mali in
   use: `G3D domain on` lines from the runtime power domain.
4. Boot animation on the panel and/or `sys.boot_completed=1`.
Panel colours correct after takeover: pass on its own (owner-visible).

## Abort / return path
Unchanged, with the new times:
- The container is killed at 575 s, and the timer restarts the phone at 600 s via the watchdog restart guard. The
  shim then boots normal Lineage (4.9).
- The 30 s watchdog and `panic=30` cover kernel hangs. Otherwise hold Power + Volume Down; use Odin with
  bright-recovery.tar if it loops into RECOVERY.
- Afterwards restore bright RECOVERY (8763860c) and wait for boot=booted.

---

# v7: 32-bit time syscalls, thermal-isp-0 stub, /dev/input (2026-11-04)

Builds on v6 (recovery db96d05d, ran 2026-11-04 21:11-21:23). The earlier sections still apply. This section
covers only the differences.

Image: gekko `rom-ram/pack-romram-20261104g/recovery.img`
sha256 `22aef45a620679f5ec6df2c910622721f8d4c5df648974cc405ceab31aa2e197` (68,149,248 bytes).
Windows: `C:\Users\Patrick\tools\trial-romram-20261104\v7\recovery.img` (+ manifest.json, hash verified).

| input | sha256 |
|---|---|
| kernel Image: crownlte-display-flipfix 8dc0a362b, v6 config + COMPAT_32BIT_TIME=y, build/romram-6.12.93 (snapshot v7/) | 05b3d3f38235d9ddf977a5c6fed8c0ec90cfc73fa44355334637aee946552f82 |
| .config | 5d0e8bc9b0fa8bb254d5b174d2d30179323ec6582f771646d8ad585c19954884 |
| DTB exynos9810-crownlte-romram.dtb (src a38f49e) | a6a888a8b7c92b1242949e43a74791c6ff492407595dd65fcfa3698e223f3ac4 |
| ramdisk rom-ram/build-5/diagnostic-initramfs.cpio.gz (src a38f49e) | 623bb9dbe480f6ac818c49562790eff55c4fafa16128ebd3cbb00760fc697b9b |
| payload manifest (unchanged since v6) | d727af14e82eb8644ba653ab753edb18755b55ce4d56ffc6b01e0e345cf22c9a |
| shim bbea959 (loader) | c74f6841352ce15b70472b0a827835841f408afe7ba33ff5276ce9f12a07d15f |

The display agent's WIN_CONFIG fix is **not** included. HWC frames will still be rejected (`win0 rejected (state 2
fmt 6 idma 4 ...): -22`).

## v6 findings and v7 fixes
1. **32-bit zygote crash loop (the main blocker). Kernel config, not a CPU or JIT problem.**
   - `CONFIG_COMPAT_32BIT_TIME` was off (crownlte defconfig since 4c9c96c18), so 32-bit tasks got ENOSYS for
     futex, clock_gettime past the vDSO, nanosleep, ppoll, pselect6, utimensat, timerfd_* and others.
   - zygote_secondary's ART logged `futex wait failed ...: Function not implemented` (117,912 lines, most of the
     180 MB log) and `Failed to get thread cpu time: Function not implemented`, then aborted.
   - Its abort path also uses futex, so it recursed until the "Jit thread pool" stack hit its guard page:
     `SEGV_ACCERR` at `0xda3d0ff8`, a 32-bit address ending in `ff8`. That is the 8 SIGSEGV + 54 SIGABRT
     zygote_secondary deaths.
   - Each death restarted zygote (64-bit) via onrestart, and with it audioserver, cameraserver, media, netd,
     wificond and vendor.audio-hal (~60 cycles each).
   - system_server (pid 361) never ran SystemServer: it sat in `waitForSecondaryZygote` ("Got error connecting
     to zygote" every 50 ms) until the cascade SIGKILLed it. `sys.system_server.start_count` was never set and
     `sys.boot_completed` was **not** reached.
   - Fix: f950da396 drops the `# CONFIG_COMPAT_32BIT_TIME is not set` line (default y with COMPAT, as in GKI).
     `__arm64_sys_futex_time32`, `clock_gettime32`, `nanosleep_time32` and `ppoll_time32` are now present in
     System.map. Config delta vs v6: exactly `COMPAT_32BIT_TIME n -> y`.
   - Ruled out: the M3/A55 CPU-feature mismatch, JIT memfd dual-mapping, userfaultfd, MTE/PAC and the compat vDSO.
     Every failing call is a time32 syscall that returned ENOSYS.
2. **Vibrator HAL** (`android.hardware.vibrator-service.samsung`, 63 SIGABRT): its `Vibrator()` constructor runs
   `std::filesystem::directory_iterator("/dev/input")`. There is no input device (no gpio-keys/touch), so ueventd
   never created the directory. Fix: init.diag.rc creates an empty `/dev/input` at early-init.
   gpio-keys for vol up/down, Bixby and power (4.9: alive-bank EINT pins) is left for a hardware-tested step.
3. **Thermal HAL** (`android.hardware.thermal-service.pixel`, 60 SIGABRT): `Could not find thermal-isp-0 in CDEV
   sysfs` -> `Failed to initialize throttling map` -> abort. thermal_info_config.json wants:
   - sensors BIG, LITTLE, G3D, ISP, ac, battery: all present (TMU zones; `ac`/`battery` from max77705-ro-battery);
   - cdevs thermal-cpufreq-0/1, thermal-gpufreq-0: present;
   - cdev **thermal-isp-0: missing**.
   Fix: 8dc0a362b adds an opt-in stub cooling device to the ACPM TMU driver. It has a single state 0, refuses any
   other state, touches no hardware and is not bound to any zone. The ROM-RAM DTB sets
   `samsung,stub-cooling-device = "thermal-isp-0"` on tmu-isp. The base diagnostic DTBs are unchanged
   (combined 4530f0c5).
4. Not addressed, not boot-blocking:
   - vendor.camera.provider (32-bit): SIGSEGV after "static information is NULL" (no camera sensors);
   - RIL/cpboot (no modem), wificond (no wifi), audio HAL routes;
   - HWC WIN_CONFIG rejects (display agent).

## How to run
Same as v6 (600 s deadline):
```
powershell -ExecutionPolicy Bypass -File C:\Users\Patrick\tools\trial-romram-20261104\romram-capture.ps1 -Seconds 630 -Out C:\Users\Patrick\tools\trial-romram-20261104\v7\serial-romram-v7.bin
```

## Expected milestones
- Kernel: `exynos9810-tmu 10074000.tmu-isp: stub cooling device thermal-isp-0 = cooling_deviceN, max_state 0`.
  N is probably 1: the TMU sensors probe (~0.32 s) before cpufreq (~0.44 s), so the cpufreq devices move to 2/3.
  This is harmless; thermal_symlinks and the HAL go by name.
- Everything that passed in v6 again: colours kept, brightness PASS, 146 files verified, software keymaster,
  keystore2, HWC3, surfaceflinger, bootanim.
- New markers: `zygote_secondary (32-bit) running` (and it stays running), `thermal HAL running`,
  `vibrator HAL running`, `system_server started`.
- Absent: `futex wait failed`, `Function not implemented` from zygote, `ThermalHAL could not be initialized`,
  `directory_iterator ... /dev/input`, the zygote/audioserver/netd restart cascade.
- system_server boot phases in `L;` (`SystemServerTiming`, `ActivityManager: System now ready`), then
  `sys.boot_completed=1` (marker `crownlte-romram: sys.boot_completed=1`).
- The panel shows the SBoot logo in correct colours. bootanim is running, but its frames are rejected until the
  WIN_CONFIG fix lands.

Likely next blockers:
- system_server services whose HALs are missing or crashing (camera provider, audio, sensors, wifi);
- LockSettings with no gatekeeper (fails fast now);
- odsign/odrefresh (bypassed after 60 s);
- the `updatable_crashing` path if an updatable service keeps exiting.

## Abort / return path
Unchanged from v6: container SIGKILL at 575 s, restart at 600 s, watchdog/panic fallbacks, then restore bright
RECOVERY (8763860c).
