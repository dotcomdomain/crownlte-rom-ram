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
