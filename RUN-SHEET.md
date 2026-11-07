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

---

# v9: /dev/ashmem through a C ashmem driver (2026-11-05)

Builds on v8 (owner-packed, recovery 34aa0385 = v7 + display 4e8632cae AFBC/bounce). The DTB and ramdisk are
unchanged since v7. Only the kernel differs.

Image: gekko `rom-ram/pack-romram-20261104i/recovery.img`
sha256 `d7e1b46db521ea60c7fda1efed433059350ebab023b9b12b37234db126e8534f` (68,149,248 bytes).
Windows: `C:\Users\Patrick\tools\trial-romram-20261104\v9\recovery.img` (+ manifest.json, hash verified).

| input | sha256 |
|---|---|
| kernel Image: crownlte-display-flipfix 314998e83/ab8a0940e (v8 source + C ashmem), config = v8 + STAGING + ASHMEM_C, build/romram-6.12.93 (snapshot v9/) | 79ac61fa1d6f998adbe6e09bf855ca76c074e963c768ad700f89ee19c9e72be6 |
| .config | cc02f2ea7b8d7cf8d57c2a8140afb2a3f2433a0071da5cf77577b9fde75b4b4f |
| DTB (as v7/v8) | a6a888a8b7c92b1242949e43a74791c6ff492407595dd65fcfa3698e223f3ac4 |
| ramdisk build-5 (as v7/v8) | 623bb9dbe480f6ac818c49562790eff55c4fafa16128ebd3cbb00760fc697b9b |
| shim bbea959 (loader) | 1a7a34d6ea6e011506802276eb375fb06d252ae1ea946f9acd2f34390b5761a8 |

## Root cause and choice
In v8, system_server died every ~5 s right after InitBeforeStartServices with `Failed to create ashmem: No such
file or directory` (ApplicationSharedMemory.nativeCreate), after libcutils logged `Unable to stat ashmem device`.
android16-6.12 only has the Rust ashmem (`CONFIG_ASHMEM depends on SHMEM && RUST`), so there was no /dev/ashmem.

- **(a) userspace only: not possible.** The Lineage system libcutils.so (disassembled `has_memfd_support()`) uses
  memfd only if `GetBoolProperty("sys.use_memfd", false)` is true **and** a test memfd (MFD_CLOEXEC |
  MFD_ALLOW_SEALING, F_SEAL_FUTURE_WRITE, ftruncate) answers `ioctl(ASHMEM_GET_SIZE)` with the page size.
  Otherwise it opens `/dev/ashmem<boot_id>` (fallback `/dev/ashmem`). On 6.12 that memfd ioctl exists only under
  CONFIG_ASHMEM, through the Rust `ashmem_memfd_ioctl()` hook in mm/shmem.c. Setting sys.use_memfd would still end
  at /dev/ashmem.
- **(b) chosen: C ashmem driver**, `drivers/staging/android/ashmem_c.c`, `CONFIG_ASHMEM_C` (depends on
  SHMEM && !ASHMEM), commit 314998e83. It is the mainline-staging/ACK (≤ android15-6.6) C driver: one
  ashmem_mutex, preallocated ranges, a shrinker that drops the lock around the punch-hole, ASHMEM_GET_FILE_ID and
  fdinfo as in ACK.
  - 6.12 updates: shrinker_alloc/register/free, vm_flags_clear, read_iter via vfs_iter_read,
    mm_get_unmapped_area, and the 32-bit GET_FILE_ID writes a compat_ulong_t.
  - mmap keeps the upstream shmem_zero_setup()/vma_set_anonymous() + vma_set_file() sequence; 6.12
    __mmap_region() explicitly supports ->mmap replacing vm_file.
  - The 4.9 crownlte driver was a cross-reference only: its split-lock variant reads asma->file/size unlocked.
  - checkpatch --strict: 0 errors, 1 warning (non-const runtime copy of the shmem fops, as upstream). W=1
    clang-18 compile clean, full build 0 warnings.
  - Also enabled in crownlte_android_defconfig (ab8a0940e), so the real Lineage kernel gets it too.
- (c) Rust toolchain: not needed.

Config delta vs v8: `STAGING n -> y`, `ASHMEM_C y`. Every other staging driver stays n.

## How to run
As v6/v7 (600 s deadline):
```
powershell -ExecutionPolicy Bypass -File C:\Users\Patrick\tools\trial-romram-20261104\romram-capture.ps1 -Seconds 630 -Out C:\Users\Patrick\tools\trial-romram-20261104\v9\serial-romram-v9.bin
```
Note: `C:\Users\Patrick\tools\run-trial.sh` refuses to start trials after 2026-11-05 06:10 (owner deadline 06:30).
Do not edit it while a trial is running.

## Expected milestones
- Kernel: `ashmem: initialized (C driver, /dev/ashmem minor N)`.
- ueventd creates `/dev/ashmem<boot_id>` (rule `/dev/ashmem* 0666 root root`, sepolicy ashmem_device /
  ashmem_libcutils_device; permissive anyway).
- Absent: `Unable to stat ashmem device`, `Failed to create ashmem`, the ~5 s system_server restart loop.
- Everything that passed in v8 again: 32-bit zygote stable, surfaceflinger, HWC3, bootanim with the AFBC bounce
  copies (`win0: scattered buffer (... AFBC) copied to 0xed000000`).
- system_server gets past InitBeforeStartServices: `SystemServerTiming` StartServices, bootstrap/core/other
  services, `ActivityManager: System now ready`. Then the stretch goal: `crownlte-romram: sys.boot_completed=1`
  and bootanim exit (`bootanim exit requested`), after which the launcher would be next.
- Likely next blockers: system_server services whose HALs are missing (camera, audio, sensors, wifi, gatekeeper /
  LockSettings), PackageManager first-boot scan time in RAM (dexopt), and odsign (bypassed after 60 s).

## Abort / return path
Unchanged: container SIGKILL at 575 s, restart at 600 s, watchdog/panic fallbacks, then restore bright RECOVERY
(8763860c).

---

# v10: real FRP block for PersistentDataBlockService, as a verified RAM copy (2026-11-05)

Builds on v9 (recovery d7e1b46d, ran 22:06-22:18). The kernel (79ac61fa) and DTB (a6a888a8) are unchanged. Only
the ROM stage (ramdisk) changed.

Image: gekko `rom-ram/pack-romram-20261104j/recovery.img`
sha256 `be1f1b4c6cf8ada6a03dd32c294003f900257e37f8b90fd01bf754f2a4b42fde` (68,149,248 bytes).
Windows: `C:\Users\Patrick\tools\trial-romram-20261104\v10\recovery.img` (+ manifest.json, hash verified).

| input | sha256 |
|---|---|
| kernel Image (as v9; build/romram-6.12.93/v9/) | 79ac61fa1d6f998adbe6e09bf855ca76c074e963c768ad700f89ee19c9e72be6 |
| DTB (as v7-v9) | a6a888a8b7c92b1242949e43a74791c6ff492407595dd65fcfa3698e223f3ac4 |
| ramdisk rom-ram/build-6 (src f057a31) | 6615c508a263f48cd863b77fa0dcaa76aa7fcafbe6a76b7f15abf47db5c7e4fa |
| /init (PID1 + ROM stage) | 8c7545800448d2d5ef0ef705281338c7ecb5de4c61ebb6373fd705cb23accb33 |
| payload manifest (unchanged) | d727af14e82eb8644ba653ab753edb18755b55ce4d56ffc6b01e0e345cf22c9a |
| shim bbea959 (loader) | 2e63b23eefad84597d40ce74d00de1fee2fbf81f2fc813a84afdaa0054c7e382 |

## v9 finding
system_server died 33x in boot phase 500: `IllegalStateException: Service PersistentDataBlockService init timeout`.
The chain was:
1. `/dev/block/persistent: open failed: ENOENT`;
2. "persistent partition not readable" / "Formatting FRP partition..." / "failed to format block";
3. onStart never signalled, so phase 500 waited 10 s and threw.

`ro.frp.pst=/dev/block/persistent` (vendor build.prop). init.samsungexynos9810.rc creates it `on init` as a symlink
to `/dev/block/platform/11120000.ufs/by-name/PERSISTENT`. That target never existed: the ROM stage hides the UFS from
Android (masks `/sys/devices/platform/soc@0/11120000.ufs`, `/sys/bus/scsi`, the scsi/bsg classes), so ueventd sees
no sd* devices and creates no by-name links. Every other service phase-500 service completed.

## What v10 does for FRP (not a bypass)
- **Untouched:** `ro.frp.pst`, PersistentDataBlockService and its FRP logic. The service reads the device's real
  FRP block and decides FRP state with stock code.
- **ROM stage (`rr_frp_setup`, romram.h):**
  1. Find exactly one partition named PERSISTENT among the scanned UFS nodes (`rr_blocks`). BLKROSET=1 is already
     set and verified on every sd* node.
  2. Open it `O_RDONLY`. Check it is the expected block device, `BLKROGET == 1`, and 4 KiB ≤ size ≤ 4 MiB
     (the backup is 524288 bytes).
  3. Read 1: sha256 of the partition. Read 2: copy into `/crownlte-frp/persistent.img`. That is a private tmpfs
     outside the container root: after the chroot Android cannot reach it, and only the loop device holds it.
     The copy is re-hashed and must match.
  4. Attach the copy **read-write** to a free loop device (LOOP_CONFIGURE, file name `crownlte-frp-ram-copy`, no
     autoclear). Read 3: sha256 through the loop device must match.
  5. Create only `/dev/block/platform/11120000.ufs/by-name/PERSISTENT` in the container (0660 system:system, as the
     vendor ueventd rule), pointing at that loop. init's own symlink then makes `/dev/block/persistent` work.
- **Writes** by the service (format, OEM-unlock bit, FRP data) go into the RAM copy and are gone at the restart.
  The real PERSISTENT is never opened writable; BLKRO and the SCSI write guard are unchanged.
- **Failure handling:** on any failure the node is just absent (v9 behaviour), never a fake or empty block. The log
  says `FRP: /dev/block/persistent NOT provided: step ...`.
- **Not exposed (listed on purpose):**
  - `by-name/RADIO`: cbd/cpboot-daemon, modem boot; no modem driver.
  - `by-name/MISC`: kcmdlinectrl; misc/BCB must never be touched.
  - `/dev/block/steady` (init symlink to STEADY): no reader seen.
  - PARAM and everything else.
- **Host test on gekko:**
  - Setup: the 2026-11-03 PERSISTENT backup behind a read-only loop, private mount namespace, test paths.
  - Hashes: 3x sha256 `81e8d623…` (= backup). Header: PDB magic `19901873`, data_len 77, OEM-unlock byte 1.
  - Node: `brw-rw---- 1000 1000 7,4`.
  - A 4 KiB write through the node changed only the RAM copy. The source stayed `81e8d623…`, and a write to it
    failed with EPERM.

Note: this device has OEM unlocking enabled (last byte 1). On unlocked devices, stock PersistentDataBlockService may
format the block at boot. Under 4.9 that write goes to the real partition; here it goes to the RAM copy. Either FRP
outcome the service reaches (active or not) is the device's real one.

## How to run
As v6-v9:
```
powershell -ExecutionPolicy Bypass -File C:\Users\Patrick\tools\trial-romram-20261104\romram-capture.ps1 -Seconds 630 -Out C:\Users\Patrick\tools\trial-romram-20261104\v10\serial-romram-v10.bin
```
`C:\Users\Patrick\tools\run-trial.sh` refuses to start trials after 2026-11-05 06:10. Do not edit it during a trial.

## Expected milestones
- ROM stage, after `BLKROSET=1 verified on all 31 sd* nodes`:
  - `FRP: real PERSISTENT (sdaN, 524288 bytes) sha256=... read read-only (BLKRO=1), copied to a private RAM tmpfs
    and verified 3x`
  - `FRP: RAM copy attached read-write as loopN (7:N, ...); ... by-name/PERSISTENT -> loopN (0660 system:system)`
    (N is probably 0: the APEXes take the next loops)
  - `FRP: PDB header magic=19901873 data_len=... oem_unlock_byte=...`
- First probe (`P;`): `--- frp ro.frp.pst=/dev/block/persistent`, the symlink and `brw-rw---- system system 7, N`.
- Kernel, everything from v9: `ashmem: initialized (C driver ...)`, colours kept, brightness PASS, AFBC bounce.
- system_server: no `/dev/block/persistent: open failed`, no `PersistentDataBlockService init timeout`.
  `OnBootPhase_500` completes, followed by phases 520/550/600: `ActivityManager: System now ready`, then
  `crownlte-romram: sys.boot_completed=1` and `bootanim exit requested`.
- Possible next blockers (not visible in v9 because it died at 500):
  - the setup wizard stopping at FRP if FRP is active (acceptable for a diag boot);
  - LockSettings/gatekeeper (no gatekeeper HAL: credential checks fail fast);
  - missing HALs (camera, audio, wifi, USB gadget HAL: handled, logged as "service not found");
  - the PackageManager/dexopt first-boot time in RAM.

## Abort / return path
Unchanged: container SIGKILL at 575 s, restart at 600 s, watchdog/panic fallbacks, then restore bright RECOVERY
(8763860c). The loop device and the RAM copy disappear with the restart.

---

# v11: undeclare absent Lineage HALs and the fingerprint feature (2026-11-05)

Builds on v10 (recovery be1f1b4c, ran 22:27-22:38). The kernel (79ac61fa) and DTB (a6a888a8) are unchanged. Only
the payload overlays changed. Code under review: rom-ram src `75d4c56..4903522` (one commit, `gen_payload.py`).
No kernel commits.

Image: gekko `rom-ram/pack-romram-20261104k/recovery.img`
sha256 `d888449d502362c969287cecf583361b09ec6bbaa5a0e993ce8c6bdcc78f3759` (68,149,248 bytes).
Windows: `C:\Users\Patrick\tools\trial-romram-20261104\v11\recovery.img` (+ manifest.json, hash verified).

| input | sha256 |
|---|---|
| kernel Image (as v9/v10) | 79ac61fa1d6f998adbe6e09bf855ca76c074e963c768ad700f89ee19c9e72be6 |
| DTB (as v7-v10) | a6a888a8b7c92b1242949e43a74791c6ff492407595dd65fcfa3698e223f3ac4 |
| ramdisk rom-ram/build-7 (src 4903522; reproducible) | 18767af1219dff8e8087c49114a70b8553c345e9fed3f73bfd394833213a5049 |
| /init (unchanged since v10) | 8c7545800448d2d5ef0ef705281338c7ecb5de4c61ebb6373fd705cb23accb33 |
| payload manifest (153 entries, 148 hashed) | 999770c65483f52b1e7123cc074a1f3d3ef10583d8ba84209dd7c02dbd037c11 |
| shim bbea959 (loader) | 662216b31cd47426f0125fe2b2ccb52f69ce2c60100ce8215042aaaf0885d366 |

## v10 findings
- FRP worked: stock PersistentDataBlockService read the real block and logged "FRP secret matched, FRP
  deactivated". Phases 480/500/520 passed and "System now ready" was reached.
- **Watchdog kills (~90 s):** the main thread was stuck in `waitForDeclaredService(vendor.lineage.touch.IGloveMode/default)`
  (InputMethodManagerService.updateTouchSensitivity -> LineageHardwareManager). `vendor.touch-hal` runs but
  registers nothing without `/sys/class/sec/tsp/cmd`, because touch is off in the DT. servicemanager logged
  ~1,000 failed lazy starts.
- **Second permanent wait:** system_server thread 981 (FingerprintService/FingerprintSensorConfigurations) waited
  for `android.hardware.biometrics.fingerprint.virtualhal.IVirtualHal/virtual` (~1,000 lazy-start failures).
  FingerprintService adds a "virtual" instance; with no real IFingerprint declared (its HAL is a TEE client,
  undeclared since v6) it maps to IVirtualHal/virtual, which this build does not ship.
- Every other AIDL instance system_server queried resolved: IHealth, ILights, IMemtrack, IPower, IThermal, IUsb,
  IVibrator, IWifi, ISupplicant (lazy), ISystemSuspend, IStats, lineage IChargingControl/IFastCharge, ... No HIDL
  wait persisted (sensors/audio resolved after one retry).
- **Not yet queried, same failure mode:** `vendor.lineage.livedisplay` (Samsung exynos impl). It runs but registers
  nothing: each interface needs a `/sys/class/mdnie/mdnie/*` node, and there is no mdnie driver on 6.12.
  LiveDisplayService/LineageHardwareService would block on it next.

## v11 changes (RAM overlay only; each one listed)
| item | change | reason |
|---|---|---|
| `/vendor/etc/vintf/manifest.xml` | drop `<hal>` vendor.lineage.touch (IGloveMode, ITouchscreenGesture) | touch hardware off; declared, never registered -> main-thread Watchdog |
| same | drop `<hal>` vendor.lineage.livedisplay (IDisplayColorCalibration, IDisplayModes, IReadingEnhancement, ISunlightEnhancement) | no mdnie on 6.12; would be the next stall |
| `vendor.lineage.touch-service.samsung.rc` | EMPTY | undeclared service must not try to register |
| `vendor.lineage.livedisplay-service.samsung-exynos.rc` | EMPTY | same |
| `/vendor/etc/permissions/android.hardware.fingerprint.xml` | drop `<feature name="android.hardware.fingerprint"/>` (now `<permissions></permissions>`) | SystemServer then does not start FingerprintService, so no IVirtualHal wait. This is what a device without a usable fingerprint sensor declares |

LineageHardwareManager reports the touch/livedisplay features as unsupported (not declared -> no wait). The
generator asserts each removal matches exactly once and that every XML still parses. All replacements are
sha256-verified before init runs. Unchanged: FRP (rr_frp_setup), TEE refusal and keymaster, storage guards,
init.c, romram.h, kernel, DTB.

## How to run
As v6-v10:
```
powershell -ExecutionPolicy Bypass -File C:\Users\Patrick\tools\trial-romram-20261104\romram-capture.ps1 -Seconds 630 -Out C:\Users\Patrick\tools\trial-romram-20261104\v11\serial-romram-v11.bin
```
`C:\Users\Patrick\tools\run-trial.sh` refuses to start trials after 2026-11-05 06:10. Do not edit it during a trial.

## Expected milestones
- ROM stage:
  - `manifest verified: 148 files hashed`;
  - `rc overlay` lines now include `vendor.lineage.touch-service.samsung.rc -> empty`,
    `vendor.lineage.livedisplay-service.samsung-exynos.rc -> empty` and
    `/vendor/etc/permissions/android.hardware.fingerprint.xml -> replace`;
  - the FRP lines as in v10.
- No `init.svc.vendor.touch-hal` or `init.svc.vendor.livedisplay-hal-samsung-exynos` in the probe getprop.
- No `IGloveMode` or `IVirtualHal` lazy-start spam, no `StartFingerprintSensor`, no Watchdog `Blocked in handler on
  main thread`.
- system_server: "System now ready", then `systemRunning` completes, then boot phase 1000. Watch for
  `crownlte-romram: sys.boot_completed=1` and `bootanim exit requested`. After that, the launcher/setup wizard
  should be on screen via the AFBC bounce path.
- Possible next blockers:
  - another system_server waiter (look for `Waited one second for` / Watchdog traces);
  - SystemUI/launcher crashes on missing HALs (camera, audio);
  - the setup wizard.

## Abort / return path
Unchanged: container SIGKILL at 575 s, restart at 600 s, watchdog/panic fallbacks, then restore bright RECOVERY
(8763860c).

---

# v14: linear HWC client target (ro.vendor.ddk.set.afbc=0) on display kernel 15b1c256c (2026-11-05)

Builds on v11 (recovery d888449d: sys.boot_completed=1, SystemUI and launcher3 up) and the owner's v12/v13
display-kernel runs, in which the panel was black during keyguard. q48 proved that every window/channel reaches the
panel, so the suspect is AFBC decoding of the HWC client target.

Image: gekko `rom-ram/pack-romram-20261105a/recovery.img`
sha256 `d8a47b079d79492b53c34fe9e97587da003cfcd3b8194ca5aad9fa72518b3ca0` (68,149,248 bytes).
Windows: `C:\Users\Patrick\tools\trial-romram-20261104\v14\recovery.img` (+ manifest.json, hash verified).

| input | sha256 |
|---|---|
| kernel Image: crownlte-display-flipfix 15b1c256c (display agent; in Sol review; not rebuilt), snapshot build/romram-6.12.93/v14/ | b65ff284d67252c0d4647353d383d4b650cdd318e48c22f4cececa4ecd96b8d6 |
| .config (= v9) | cc02f2ea7b8d7cf8d57c2a8140afb2a3f2433a0071da5cf77577b9fde75b4b4f |
| DTB (as v7-v11) | a6a888a8b7c92b1242949e43a74791c6ff492407595dd65fcfa3698e223f3ac4 |
| ramdisk rom-ram/build-8 (src ed0813d) | 18279f131d7441c25cd8bc8d1b7dfc9afecb814e74765dace9056f4361da74be |
| /init (unchanged since v10) | 8c7545800448d2d5ef0ef705281338c7ecb5de4c61ebb6373fd705cb23accb33 |
| payload manifest (153 entries, 149 hashed, 7 replacements) | ae90ab38d936d5faf471fd0ba1bdd4d27dac68fa7e67e22e303e5245c57fcf9d |
| vendor build.prop: original (verified) / replacement | 00aa1914... / c218ba0d1dab4badf233e5e29ca7bbd789baaaa0f8695e8eb4dee3053f409a4c |
| shim bbea959 (loader) | 9e8b9e345a489b7c109e8de6f686703e649d5fff90493fd4bc7bdf98292e7aa3 |

## Change (rom-ram src e8c5f72..ed0813d; no kernel commits from this agent)
- **gen_payload.py, PROP_SET:** `/vendor/build.prop` (already a sha256-verified `keep` entry) becomes a replacement
  that differs only in line 70: `ro.vendor.ddk.set.afbc=1` -> `=0`. The ROM stage bind-mounts it read-only over
  the original before init, so init's first and only value is 0. The generator refuses unless:
  - the key is defined exactly once in that file with the expected old value;
  - exactly those lines change;
  - no other prop file init loads (system, system_ext, product, prop.default, vendor default.prop, odm) defines
    the key. Today it exists only at vendor/build.prop:70.
- **Readers of the property:** libexynosdisplay.so (HWC, client composition) and gralloc.universal9810.so (64/32-bit),
  plus libGrallocMapperCamera.so.
- **Evidence lines:**
  - `probe.sh` (first probe): `--- afbc ro.vendor.ddk.set.afbc=0`;
  - `init.diag.rc`: kmsg `crownlte-romram: ro.vendor.ddk.set.afbc=0`.
- **Unchanged:** init.c and romram.h (FRP RAM copy, TEE refusal, storage guards), all v6-v11 overlays.

Checks run:
- The ramdisk build passes the host verifier (positive + 3 negatives).
- Manifest delta vs v11: only `/vendor/build.prop keep -> replace:prop_a338da37ac40683d.prop` and its `R` line.
- `diff` of the original vs replacement: exactly 1 changed line (70).
- Negative test: a wrong expected old value aborts generation (`PROP ... line is 'ro.vendor.ddk.set.afbc=1', expected ...=9`).
- Image, DTB and ramdisk are each embedded once; IKCONFIG = the v14 snapshot config; the Windows copy hash matches.

## How to run
As v6-v11 (600 s):
```
powershell -ExecutionPolicy Bypass -File C:\Users\Patrick\tools\trial-romram-20261104\romram-capture.ps1 -Seconds 630 -Out C:\Users\Patrick\tools\trial-romram-20261104\v14\serial-romram-v14.bin
```
`C:\Users\Patrick\tools\run-trial.sh` refuses to start trials after 2026-11-05 06:10. Do not edit it during a trial.

## Expected milestones
- ROM stage:
  - `manifest verified: 149 files hashed`;
  - `rc overlay /vendor/build.prop -> replace`;
  - the FRP lines as in v10/v11.
- kmsg `crownlte-romram: ro.vendor.ddk.set.afbc=0`; first probe `--- afbc ro.vendor.ddk.set.afbc=0`.
- DECON bounce lines: the HWC client target arrives with `comp 0` (linear, no AFBC).
- Boot as in v11 (sys.boot_completed=1, SystemUI, launcher3), with the keyguard/launcher **visible** on the panel
  instead of black. Colours should be right with the 15b1c256c format-layout fix.
- If it is still black with `comp 0`, AFBC is ruled out and the problem is in the linear bounce or the format path.

## Abort / return path
Unchanged: container SIGKILL at 575 s, restart at 600 s, watchdog/panic fallbacks, then restore bright RECOVERY
(8763860c).

## TEE T2 (build-only, 2026-11-06)

Opt in with `TEE_T2=1 DEADLINE=600 ./build.sh /dev/shm/<fresh-build-dir>`.
Without TEE_T2 the original ramdisk is byte-identical at the same deadline;
TEE refusal remains. Final artifacts: `rom-ram/build-11` and
`rom-ram/pack-romram-tee-t2/recovery.img`. See `src/TEE-T2-REPORT.md`.

This is the restricted daemon-only T2 stage: **no vendor -r preloads** and no
secure driver/TA loads (seccomp denies MobiCore LOAD_DRIVER/LOAD_CHECK).
It tests daemon/admin-device startup and auth-token reads, not vendor driver
initialization or keymaster. All other TEE clients remain masked. No T3.

For a separately authorized hardware trial, use the existing ROM-RAM serial
capture procedure and its exact READY -> PROBE -> START frames; keep capture
through the independent 600 s deadline restart. No phone action was performed
when preparing this pack. Do not substitute older ramdisks or enable TA clients.
The fallback T1 kernel lacks panel L2 recovery; use serial evidence.

Expected evidence, not hardware results:
- K; `T2 PASS TEE present; UFS guard DT and host binding verified`
- K; `T2 PASS EFS RAM copy ro,noload bytes=... sha256=...`
- K; `T2 PASS forbidden blocks hidden; FRP real partition never opened`
- P; `T2 PASS userspace audit ready; software keymaster masks retained`
- P; `T2 daemon start ... uid=1000 no-preload`, followed by strace evidence
  of successful `/dev/mobicore` open; no successful user-session device opens.
- P; registry before/poll/after, failed writes including EROFS/EACCES/EPERM,
  passive session/counter snapshots if debugfs files exist, McDaemon logcat.
- P; `T2 daemon exit status=...` or signal, then supervisor status. Nonzero
  exit, failed exec, trace failure or absent successful admin open is NOT PASS.
- K; the independent timer restart at 600 s. The T1 selftest may no longer
  say PASS after a daemon creates a client: its zero-client invariant is T1-only.

There is no exported UFS guard counter in this kernel. The audit explicitly
reports unavailable; `diagnostic rejects SCSI opcode` on K; is a ratelimited
lower bound, not a precise counter. Never read trustonic crashdump or active_cpu.
Do not treat absent EFS-write errors as proof that all daemon paths executed.

## ADB over USB NCM (ADB=1, build-only, 2026-11-06)

Branch `romram-adb` 899632d on tee-t2 3259275. Opt-in: `ADB=1 ADB_PUBKEY=<adbkey.pub> ./build.sh <fresh dir>`
(`ADB_ROOT=1` additionally, for `adb root`). Without ADB the ramdisk is byte-identical to tee-t2
(72195507..., checked). TEE_T2 paths are unchanged. ADB together with TEE_T2 compiles but was not
built or run.

| artifact | sha256 |
|---|---|
| host public key `rom-ram/adb-host-key/adbkey.pub` (derived offline with `adb pubkey` from the Windows PC key; the private key never left the PC) | c1082a43... (file); installed line 9b66ffa1... |
| ramdisk ADB=1 `rom-ram/build-18` | 4fe8d2d1afc693fb2be4008714b86db1c2a7da197572c495a80a216a68f6620e |
| ramdisk ADB=1 ADB_ROOT=1 `rom-ram/build-19` | fd11f8fe97f61ec660ef536725a69696c41edd2d1db1e8e5008574b0664909c9 |
| kernel Image (same as T2i, crownlte-tee-3 566ee45af), `panel-bright-work/ko-adb1` (hard link) | dabc09eba0254e1ff90ab6e369f294994a4a43534f4328c1bb72ba19f068d84e |
| DTB `exynos9810-crownlte-romram-adb1-teeoff.dtb` = T2i tee-t3fsd2 (ca9545b4) with `tee/status = "disabled"` and a new model string only (dtc round-trip of ca9545b4 is byte-exact; diff in `panel-bright-work/dtb/...adb1-teeoff.dts.diff`) | 052c23f3a5c503f717d593002e390a9295a28b84ce44ca3b7294a1a6a579f2da |
| `rom-ram/pack-romram-adb1/recovery.img` (ADB=1) | b696c32c34e5524012d7869b25fee08a8fdb5f2acd593838dbce026dfaaf5bde |
| `rom-ram/pack-romram-adb1-root/recovery.img` (ADB=1 ADB_ROOT=1) | f37517066d85082db442d9fe1c6915d1f20099660ec7ffa777c8756fd7309e9a |
| shim bbea9590, parent a8198be0, restore 8763860c (as T2i) | |

Why not the T2i DTB unchanged: it has `tee { status = "okay" }`. Without TEE_T2 the ROM stage
refuses a live TEE (`ROM stage STOPPED stage=tee-must-be-off`), so Lineage and adbd would never start.

### Design
- PID1's gadget `crownlte_diag` (VID/PID 1d6b:0104 unchanged) gets `ncm.usb0` linked **after**
  `acm.usb0`: ACM stays interfaces 0/1 (ttyGS0, same frames), NCM is 2/3. Device class EF/02/01 (IAD
  composite), so Windows loads usbccgp and binds the in-box usbser (ACM) and UsbNcm
  (`USB\Class_02&SubClass_0d&Prot_00`, in `C:\Windows\INF\usbncm.inf` on the test PC). New serial
  `crownlte-romram-adb`, so Windows makes a fresh device node. **The COM number will probably not be 4.**
  `romram-capture.ps1` now finds the present 1d6b:0104 port (prefers MI_00), falls back to COM4, and
  prints `port COMn`. `-Port COMn` forces a port. The old copy is `romram-capture.ps1.pre-adb`.
- Netdev `crownadb0` (no tethering/ethernet regex matches it). Phone MAC 02:43:52:4e:39:44, Windows
  adapter MAC 02-43-52-4E-39-48. NCM can never block the log port. On any NCM setup error, or after two
  UDC bind failures with NCM linked, PID1 drops NCM and binds ACM-only (`ADB NCM dropped ...`).
- Container `/dev/crownlte/adb.sh`, started at post-fs-data as root/su:
  - Installs the public key line into RAM `/data/misc/adb/adb_keys` (system:shell 0640,
    `restorecon` gives adb_keys_file).
  - Sets crownadb0 up with `fe80::1/64` (nodad) and `169.254.42.1/16`. No DHCP, router or DNS is
    offered, so Windows routing and DNS are untouched.
  - Adds `169.254.0.0/16` and `fe80::/64 dev crownadb0` to netd's `local_network` table 97. netd
    deletes the kernel's `lookup main` rule at start (AOSP RouteController::Init, read in source); its
    rule 20000 `fwmark 0x0/0x10000 lookup local_network` serves unmarked replies. Init flushes rules,
    not tables.
  - Re-checks every 10 s, repairs, and reports `ADB REPAIR ...` if anything changed the link.
  - Never touches configfs, the UDC, block devices or mounts.
- init.diag.rc (ADB only), at post-fs-data:
  - `service.adb.tcp.port=5555`.
  - `persist.sys.usb.config=adb`: this build has no default, and then AdbService turns adb off.
  - Keepalive `on property:init.svc.adbd=stopped && ro.boot.crownlte_adb=1 -> start adbd`, because
    `sys.usb.config=none` runs `stop adbd`.
  - Every adbd state change is logged as `crownlte-romram: ADB init.svc.adbd=...`.
- Root: this Lineage "userdebug" build ships **`ro.debuggable=0`** (system/build.prop:89). adbd
  checks that, so on the ADB=1 pack `adb root` answers `adbd cannot run as root in production builds`.
  The ADB_ROOT=1 pack changes exactly that line through the verified PROP_SET overlay. Other
  ro.debuggable=1 effects in the rc files:
  - `start console`, which fails because there is no /dev/console.
  - `chmod` of /data/misc/trace (RAM).
  - The llkd variant, but llkd stays off.
  - `clean_scratch_files` needs dynamic_partitions, which is absent here.

### How to run
1. `run-trial.sh <dir> 630 <trial dir>\romram-capture.ps1`, exactly as for T2: READY -> PROBE ->
   START, 600 s deadline, container SIGKILL at 575 s. `<dir>` is `trial-romram-20261104\adb1` (or
   `adb1-root`).
2. When the reboot starts, run in a second window
   `powershell -ExecutionPolicy Bypass -File C:\Users\Patrick\tools\trial-romram-20261104\romram-adb.ps1`
   (add `-Root` on the adb1-root pack). It waits up to 540 s for the adapter and port, then:
   - probes `[fe80::1%<ifIndex>]:5555`, then `169.254.42.1:5555` once Windows has an APIPA address;
   - runs `adb connect` and uses `-s <serial>` for every command;
   - runs `id`, `uname -a` and a few getprops.
   It needs no admin rights and never opens a COM port. Manual fallback:
   `adb connect [fe80::1%N]:5555`, where N is the ifIndex of the adapter with MAC 02-43-52-4E-39-48
   (`Get-NetAdapter`).

### Expected PASS lines (not yet seen on hardware)
- Capture: `port COMn at ...`, `READY sent`, `PROBE + ROMRAM-START sent`.
- K: `crownlte-diag: ADB NCM bound with ACM: ifname=crownadb0 dev_addr=02:43:52:4e:39:44 host_addr=02:43:52:4e:39:48 class=EF/02/01 serial=crownlte-romram-adb`.
  This comes before `USB result stage=gadget-bound` and `serial open errno=0`.
- K: `crownlte-romram: ADB payload: adb.sh and adb_keys (public key) copied ...` (before `exec /system/bin/init`).
- P: `ADB start ...`, then `ADB PASS key installed: -rw-r----- 1 system shell u:object_r:adb_keys_file:s0 ... lines=1`.
- P: `ADB PASS link crownadb0 up: crownadb0 UP 169.254.42.1/16 fe80::1/64 ...`.
- K: `ADB init.svc.adbd=running`. Then P: `ADB PASS adbd listening on tcp 5555`.
- Helper: `PASS tcp [fe80::1%N]:5555 answers`, `PASS adb device ...`, `id: uid=2000(shell) ...`
  (`uid=0(root)` after `-Root` on adb1-root). Then P: `ADB PASS host connected to tcp 5555 (established=1)`.
- P: `ADB status ...` every 30 s. Healthy is `rule20000=1`, `listen>=1`, `link=up/carrier=1`.
  At ~70 s an `--- ADB detail` block dumps `ip rule` and table 97.

### How to verify
- In the adb shell:
  - `getprop ro.boot.crownlte_adb` gives 1.
  - `ip -br addr show crownadb0`, `ip rule`, `ip route show table 97`.
  - `ls /dev/block`: no sd* nodes, same as every ROM-RAM run.
  - `cat /proc/mounts | grep -E ' / | /data '`: ro root, tmpfs /data.
- Serial must keep flowing (K/L/P) while adb is in use, until the 600 s restart, which must still
  happen. Then the phone boots normally. Restore bright RECOVERY as usual.
- Not PASS:
  - `ADB NCM dropped` or `not in the bound gadget`.
  - `ADB REPAIR` lines that repeat. Something keeps reconfiguring the link; note what changed.
  - `unauthorized` in the helper: key not taken. Check `ADB PASS key installed`.
  - Repeated `ADB init.svc.adbd=stopped/running` flips: UsbDeviceManager is toggling sys.usb.config.

### Rules for the adb session
- Root in the container is the same root the rc services already have. The UFS SCSI write guard,
  BLKROSET, storage masks and tmpfs /data are unchanged, and they remain the backstop.
- Still never run anything that writes storage or partitions: no `dd of=`, mkfs, `adb remount`,
  `disable-verity`, sideload/flash, or `adb reboot <target>`. A plain `adb reboot` only ends the PID
  namespace. Lineage is then gone until the outer restart.

### Open risks (untested on hardware)
1. Composite ACM+NCM on dwc3 and the Windows enumeration (usbccgp + usbser + UsbNcm against Linux
   f_ncm). The fallback is ACM-only, logged. If UsbNcm fails, RNDIS (also in-box) would be the next try.
2. The netd routing rule is read from AOSP main source, not checked on this build. If `rule20000=0`
   or SYN-ACKs never leave, an own `ip rule` is the fix.
3. UsbDeviceManager may toggle `sys.usb.config` none/adb. Each toggle restarts adbd, the keepalive
   covers it, and TCP sessions drop and need `adb connect` again.
4. adbd's dual-stack listen (libcutils socket_inaddr_any_server) is not verified. IPv4 needs the
   Windows APIPA address (can take about a minute).
5. Windows getaddrinfo parses `fe80::1%17` with the scope (checked on the test PC). The end-to-end
   `adb connect` to a scoped address is untested.
6. ADB_ROOT side effects beyond the list above. Any adb host on this USB link has key-authorized
   access. The key is the test PC key.

### ADB security notes (Sol R1 S1-S3, 2026-11-06)
- The storage and sysfs masks are NOT a security boundary against the root adb shell (ADB_ROOT=1). Root in the container can mknod block nodes, clear BLKROSET, unmount masks or mount a fresh sysfs, and so can READ real partitions including EFS. Writes are still refused by the kernel UFS SCSI write guard (the backstop). Acceptable only because the adb session is the operators own diagnostic channel; never treat ADB_ROOT packs as containment for untrusted code.
- Default-build identity: compare the default builds by rebuilding with ADB unset and running cmp on diagnostic-initramfs.cpio.gz; record both full hashes and the build flags when claiming identity.
- templates/adb.sh "ESTABLISHED" only means a TCP peer connected, not that adb authenticated. The authenticated PASS is the Windows helper's adb shell check.

## EFS_RO_DIR: read-only RAM copies of selected EFS files (build-only, 2026-11-07)

Why: the B1-hal trial (2026-11-07) showed `android.hardware.bluetooth@1.0-service` aborting with
"Open: No Bluetooth Address!" because ROM-RAM never mounts EFS, so `/efs/bluetooth/bt_addr` is
missing. This option is off by default. Builds without it differ only in `init` (unused code) and
`probe.sh` (an extra block that only runs when `/dev/crownlte/efs-ro.sh` exists).

Input: `EFS_RO_DIR=<dir>` holding `MANIFEST` and the files it names. Keep the dir outside git,
mode 0700. On gekko: `rom-ram/efs-ro/` (bt_addr and wifi.mac.info copied read-only from the phone's 4.9 Lineage).

    D <path under efs, or .> <owner> <group> <mode> [<label>]
    F <path under efs> <owner> <group> <mode> <sha256> <file in dir> [<label>]

Build time (`gen_payload.py`):
- Every file must match its sha256 and be 1..4096 bytes. At most 16 entries.
- `D .` comes first. Each parent needs an earlier D line. Paths are plain names only (no `.`/`..`).
- Owners come from a fixed AID table. Modes must be <= 0777.
- An optional label must equal what plat+vendor file_contexts give `/mnt/vendor/efs/<path>`.
- Refused together with TEE_T2, which mounts a real EFS copy at the same place.
- Output: `/crownlte/efs-ro/list` plus `f0..fN` (0400 in the cpio), `/crownlte/efs-ro.sh`
  (templates/efs-ro.sh), a payload-id suffix, and an `on fs` block plus the `crownlte_efs_ro`
  service appended to init.diag.rc.
- The host test populates and re-checks the list into an empty directory and must refuse a
  wrong-sha list. Its temp dirs are deleted.
- File bytes are never printed.

Boot (PID1, `romram.h` step 5e, before the switch to Lineage init):
1. Mount a tmpfs at `/mnt/vendor/efs` (64 KiB, 64 inodes, nosuid/nodev/noexec).
2. Check each payload file's size and sha256, write it with O_EXCL, set owner/group/mode, then
   re-hash the copy.
3. Remount read-only (MS_REMOUNT|MS_RDONLY) and require ST_RDONLY.
4. Re-check every entry (type, owner, mode, sha256).
5. Copy efs-ro.sh to the container's RAM `/dev/crownlte/efs-ro.sh` (0755).
6. Log exactly one line: `crownlte-romram: efs-ro: N files, sha ok`.

Any failure stops the ROM stage (`stage=efs-ro-*`), like any other manifest failure. The EFS partition is never opened.

Lineage init:
- The EFS_RO `on fs` block in init.diag.rc runs first, because init parses this file before its
  imports. It runs `exec_start crownlte_efs_ro`: init blocks until `efs-ro.sh` exits (fix round
  2026-11-07, Sol R1 #1; before that the init built-ins failed open). The script (su domain):
  1. requires exactly one tmpfs mount at `/mnt/vendor/efs`, first option `ro`, plus
     nosuid/nodev/noexec;
  2. `mount -o remount,rw,nosuid,nodev,noexec`, checks `rw`;
  3. `restorecon -R /mnt/vendor/efs` (labels need the loaded policy; labels set before policy
     load do not survive on tmpfs);
  4. `mount -o remount,ro,nosuid,nodev,noexec`, then requires the step-1 flags again (the kernel
     prints `ro` when `__mnt_is_readonly`, the same test that sets ST_RDONLY) and a new-file
     write refused with EROFS ("Read-only file system");
  5. sets `crownlte.efs_ro=ok` (read back), logs
     `K: crownlte-romram: efs-ro PASS labels restored; ... verified` and exits 0.
  Any failed step logs `efs-ro FAIL stage=<step>` (priority 3), tries a best-effort ro remount
  and exits 1. The service has `reboot_on_failure reboot,crownlte-efs-ro`, so a non-zero exit or a
  failed start makes init reboot: the PID namespace ends (`signaled=1 signal=1`, namespace gone,
  no retry) and the outer deadline restarts the phone. The init queue is cleared, so the rest of
  `on fs` (including the vendor bind) never runs on a writable efs. A hang blocks init until the
  deadline. After `exec_start` the action runs `wait_for_prop crownlte.efs_ro ok`, so a helper
  that never ran (for example an init parse error in the service block, which turns `exec_start`
  into a logged error) also blocks init until the deadline instead of failing open.
- Then the vendor's own `on fs` runs `mount none /mnt/vendor/efs /efs bind`. That line was never
  disarmed. Until now it failed with ENOENT. Now /efs is the same read-only mount, as on the phone.
- The vendor's restorecon/chown/chmod/mkdir on efs then find correct labels or fail with EROFS.
  Harmless.
- The rw window is inside the blocking helper (init runs nothing else meanwhile). It is RAM only.

Artifacts (gekko rom-ram/, build-only, UNTESTED on the phone):
- build-31 (src 39f2eaf, ramdisk 68acee0d...): first EFS_RO build. Its pack
  `pack-romram-bt-b1-hal-r2-efs` (recovery b1f34213...) is SUPERSEDED (Sol R1: the ro remount
  failed open and the probe could report a false PASS); deleted on gekko, a copy is on the PC.
- build-32 (src 46a3670, same flags: `ADB=1 ADB_ROOT=1 ADB_PUBKEY=... EFS_RO_DIR=...`, absolute
  paths in build-32/BUILD-CMD.txt): ramdisk
  `82771399d5af1ff8afc6b575ef8edddd57d5ea5cc30db67084e7a05ec848f3fa`. Differs from build-31 only
  in `init`, `init.diag.rc`, `probe.sh` and the new `efs-ro.sh`; manifest c623622e and efs-ro
  list 430a4c99 unchanged.
- `pack-romram-bt-b1-hal-r2-efs2`: same inputs as the old efs pack (Image c08c45b8, DTB
  romram-bt-b1 adedcd7d, shim bbea959, parent a8198be0) except the ramdisk (build-32). recovery
  `f2a8ee3d2a7d1fe75a682dd662a4a46b38247d2a53ff44a414d8570c498e9721`, mode 0600 (contains the
  MACs). Restore RECOVERY 8763860c afterwards.

Expected (build-31/build-32 EFS set):

| path | owner | mode | label |
|---|---|---|---|
| `/mnt/vendor/efs` = `/efs` | radio:system | 0771 | efs_file |
| `bluetooth/` | system:bluetooth | 0770 | bluetooth_efs_file |
| `bluetooth/bt_addr` | system:bluetooth | 0640 | bluetooth_efs_file |
| `wifi/` | wifi:wifi | 0755 | wifi_efs_file |
| `wifi/.mac.info` | wifi:wifi | 0644 | wifi_efs_file |

PASS lines:
- K: `crownlte-romram: efs-ro: 2 files, sha ok` (before `exec /system/bin/init`).
- K: `crownlte-romram: efs-ro PASS labels restored; /mnt/vendor/efs ro,nosuid,nodev,noexec verified
  (1 tmpfs mount, write refused with EROFS: u:object_r:efs_file:s0 /mnt/vendor/efs)`.
- K: `efs-ro crownlte.efs_ro=ok; vendor on fs may proceed`.
- P (probe n=6, ~60 s): `--- efs-ro`, two `tmpfs ... ro,` mount lines (/mnt/vendor/efs and /efs),
  `ls -laRZ` with the table above, and
  `efs-ro PASS: /mnt/vendor/efs: ro, write refused EROFS; /efs: ro, write refused EROFS`.
  The probe requires both mounts (exactly one tmpfs each, first option `ro`) and EROFS on both.
- logcat: `get_local_address: Trying /efs/bluetooth/bt_addr` with no "No Bluetooth Address!" and no SIGABRT.

Not PASS:
- `stage=efs-ro-*` in the STOPPED line (PID1, before Lineage init).
- `efs-ro FAIL stage=...` from the helper, then a namespace SIGHUP: `reboot_on_failure` ended
  the ROM stage on purpose. Look at the stage name.
- `efs-ro FAIL: ...` from the probe (a mount missing, not `ro`, or writable).
- `efs-ro INCONCLUSIVE: ...`: the write was refused, but not with EROFS (for example ENOSPC or
  EACCES), so it does not prove read-only.
- An `rw` efs mount line.
- `restorecon` labels left as `tmpfs` (the helper checks the restorecon exit status, not each label).

Limits:
- The root adb shell (ADB_ROOT=1) can remount the tmpfs rw. It is RAM only and is gone at the
  next boot. The UFS SCSI write guard stays the backstop.
- The MAC values are in the ramdisk (and thus the RECOVERY image). Do not publish those images.
