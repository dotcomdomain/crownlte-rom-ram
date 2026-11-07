# TEE T3 build report (2026-11-06)

Build host only (gekko). No phone access, no flashing, no key operations, no RPMB, no
excluded sandbox/VM access. Scratch in /dev/shm, kernel -j3 foreground with LLVM 18.
Design followed: `roadmap/tee-t3-design.md` (T3a-0/1/2, T3b-0/1). Run sheet: section
"TEE T3" in `src/RUN-SHEET.md` (also appended to `rom-ram/RUN-SHEET.md`).

## Review fixes S1/S2 (2026-11-07) — supersede the Image, ramdisks and packs below

Two review blockers fixed. Kernel `crownlte-tee-3` **22a6b88cc** (on fa72731b5), ramdisk
branch `tee-t3` **452c728** (on 334746b). The DTBs are unchanged (no DT change needed).
The sections further down describe the first T3 build. Where they give an Image, ramdisk,
tee-t3-run or pack hash, the table at the end of this section replaces it.

**S1 (kernel): OPEN_SESSION / GP open-session mapped unchecked daemon bytes.** The UUID
allow list checked only the *requested* UUID. `tee_object_get()` then took whatever the
daemon returned for GET_TRUSTLET (another signed blob, an SP object) and mapped it. With
the session guard on, the object now comes from `mc_registry_object()` (new
`registry_guard.h`), called after the UUID allow list:
- UUID **with** a pin in `samsung,tee-trustlet-allow`: the daemon bytes are taken only if they
  are a plain MCLF system trustlet (no SP object, no driver type), the header UUID equals the
  *requested* UUID (new verdict `uuid not the requested uuid`), and SHA-256 matches a pin for
  that UUID. A fetch error is returned as is, with no fallback to SWd selection.
- UUID **without** a pin (FSD2 07050501..20, DebugSession 08050500..00, i.e. every T2/T3 DTB):
  **SWd selection only** (`tee_object_select`, a bare header with the UUID). The daemon is
  never asked. Without TA-auth support the request is refused.
- Without `samsung,tee-session-guard`: same code path as before (registry, then SWd
  selection on ENOENT). open-trustlet and LOAD_DRIVER: unchanged (`want_uuid` NULL).
- Logs: `tee session-guard: open-session-registry|gp-open-session-registry uuid=.. gp=.. by
  comm[pid]: SWd selection only (no pin, daemon not asked)`, or `... type= len= sha256= ...:
  allowed`, or `... blob_uuid=.. ...: REFUSED (<reason>)` / `REFUSED (registry fetch error N)`.
- Behaviour change for T2j/T3: FSD2/DebugSession were already SWd built-ins. The daemon has
  no `07050501...20` / `08050500...00` file in `/vendor/app/mcRegistry` and the /data registries
  are empty tmpfs, so before this fix the daemon answered ENOENT and the kernel fell back to
  SWd selection. That is inferred, not observed: no phone log of these opens exists. The only
  difference now is that the daemon is not asked at all.
- `tests/blob-guard-fixture.c` drives `mc_registry_object()` itself, with a stub daemon
  (`tee_object_get`) and a stub SWd selection that count calls, allocations and frees. It
  covers valid KM/GK blobs (legacy and GP), another pinned and correctly signed blob for the
  wrong UUID, a KM body carrying the GK UUID, byte flips, ±1 length, bad magic, retyped SP or
  driver, a driver blob, the SP object, 75/0-byte blobs, daemon ENOENT/EPIPE (no fallback),
  and unpinned FSD2/DebugSession/KM. In the unpinned cases the daemon must not be called,
  even though it would have answered with a valid KM blob. Also no TA auth. Result:
  **`blob guard fixture: PASS (77 checks, 0 failures)`**, clean under ASan/UBSan. Mutations:
  without the requested-UUID check 3 checks fail; with the pin-based source choice removed,
  7 fail.
- Build: clang FORTIFY_SOURCE could not bound the new pin loop, so the loop now also stops
  at `MC_PIN_MAX`. Image **e4a5a04e36fcd7bb57111619f9f2304f0997f99f65127fd52d859fe5059e0669**
  (incremental `/dev/shm/build-tee3`, -j3, no warnings), copied to
  `panel-bright-work/ko-tee-t3s1` with the unchanged DTBs.

**S2 (ramdisk): socket rule bypass through io_uring; other processes visible in /proc.**
- Client filter (123 insns, was 88): `io_uring_setup/enter/register` -> ENOSYS. These are
  the IORING_OP_SOCKET path that never runs the filtered `socket()`. Also `clone3` -> ENOSYS,
  `clone` with any CLONE_NEW* flag -> EPERM (fork, threads and vfork pass), and
  `process_vm_readv`, `pidfd_open`, `pidfd_getfd` plus the new mount API (`open_tree`,
  `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`) -> EPERM.
- Daemon filter (42/44 insns): io_uring -> ENOSYS too. mcDriverDaemon, libMcClient and the
  keymaster libraries import neither `syscall` nor io_uring symbols. The pinned bionic
  `libc.so` has no `svc` with 425-427 or 435.
- Client `/proc`: the client now runs in its **own pid namespace**. Its pid 1 is the runner
  (root, not dumpable). In the private client mount namespace, pid 1 detaches the container
  `/proc` (hidepid=2,gid=3009, which shows every uid 1000 process) and mounts a procfs of the
  new pid namespace with `hidepid=invisible` and no readproc gid. It then re-applies the
  container masks (substituted `/proc/cmdline`, empty `sysrq-trigger`/`bootconfig`) and checks
  mountinfo: exactly one proc mount, at `/proc`, `hidepid=invisible`, and only pid 1 listed.
  The client runs as **pid 2**, so `alarm()` and default signals still work. pid 1 reaps it
  and passes the status on, and if pid 1 dies the kernel kills the namespace. Any failure:
  `T3 FAIL ...; client NOT started`.
- `t3-seccomp-fixture`: io_uring ENOSYS for the daemon (both variants) and the client, clone3,
  clone with CLONE_NEW* flags vs fork/pthread/vfork flags, and the new deny entries:
  **`PASS (0 failures; insns daemon=42 daemon+drv=44 client=123; 2^24 'M' cmds x3)`**. Without
  the client io_uring rule, 6 checks fail.
- New `t3-pidns-fixture` (run by build.sh as root under `unshare --mount --propagation private`;
  the fixture also makes its own namespace MS_PRIVATE). It runs the runner's own
  `client_pidns()` with a uid 1000 probe, plus a dumpable uid 1000 sleeper outside the
  namespace as the alias target. Control: **without** isolation `/proc/<sleeper>/root` is
  reachable, so the alias exists on this host. **With** isolation the probe is pid 2, sees only
  its own pid, no `/proc/1`, no `/proc/<sleeper>` or its `root`, one proc mount with
  `hidepid=invisible`, and a masked `sysrq-trigger`. `/proc/self/exe` and `/proc/self/status`
  still work, as the bionic linker and the HAL need. Exit status 7 and a default SIGALRM pass
  through pid 1. **`t3 pidns fixture: PASS`** in every build. With the pid namespace removed,
  the probe fails 8 checks. The host `/proc` was checked unchanged afterwards.
- Template: `open-session-registry` / `gp-open-session-registry` refusals count as fatal blob
  refusals.
- Regression: `TEE_T2=1` without TEE_T3 = e6c0c93d and default = 72195507, both still
  byte-identical.

**T2j repacked** with the S1 Image (same ramdisk build-17 e6c0c93d, same DTB tee-t3dbg 06a6cf36):
FSD2/DebugSession now by SWd selection only.

| pack | ramdisk (rom-ram/build-N) | tee-t3-run | DTB | recovery.img |
|---|---|---|---|---|
| t3a0 | build-25 718c8a2df77709bb66f1a56ad90858da95ed7f2389e922a2b45c743977223aa7 | e35c9001... | 91e4ebcc | b1c0667c219979d29f493f2500f441eb510c503bc34921adba701a7626bed8d4 |
| t3a1 | build-26 2fd18c0fd512e39ad271b6a4785653d75bda4ad5bd0a21a0374b0daf7ba7c782 | f8e7cc86... | 91e4ebcc | 831cebe48bf8c85ea7b0048d6780c070e3efa695c581c56cd68eace25d09a6d2 |
| t3a2 | build-27 e747370157ec1db3d57f21b1a34cf33c09ea548d6a56da4c42f6e27f8f92c805 | fd4ee611... | 0fd173cf | a5fcf993b91da1803c8177a1fa55dff666e991226776f0ff0a31fa869e8cb5fd |
| t3b0 | build-28 7a57eebb8b3ee7d2790c35db1a5f707c98c567586b354638c2ddd375c467d3e6 | 4b9f6b97... | 5f637991 | d15283a53893dbe81cff8dbc9688cfc74e737a90837a116f8daf59af9df75e6f |
| t3b1 | build-29 23caa24f6ee6f36b019f4d8be9ae3ef3b489e1686872e030c1f65f66925d9821 | e93db0bd... | 1a40fcf7 | bc96070a1699ec9f5fa1be71b2a16f46dba50d1b7e1e0ec574014604f394c4b4 |
| t2j | build-17 e6c0c93d2a4249e1252922a61d16a99b523cfb89fb608227357ec8daf5023dc9 | (T2 runner) | 06a6cf36 | 8f68d8439dda6f8308ddb75a55f70873bb449d6a6d3e931284fb64ce85e03982 |

All six: Image e4a5a04e, shim bbea9590, parent a8198be0, restore 8763860c. The clients are
unchanged (km 41a08643..., gk b8aee112...). The packs were rebuilt in place by
`t3-tools/pack-t3.sh`. Each old pack was removed only after its manifest showed the expected
old Image (a466abe2 / dabc09eb). Superseded recovery images: t3a0 a76a1c97, t3a1 8f67ef51,
t3a2 d06b126e, t3b0 d831d685, t3b1 9e7e2d38, t2j 8f5f1a31. Their inputs are still on disk
(ko-tee-t3pin, ko-tee-t3, build-17, build-20..24). shim-src worktrees and shim-out were removed.

Still untested after S1/S2 (in addition to the list at the end):
- Kernel registry path at runtime: the fixture runs the real decision function, but the
  `client.c` wiring, `mc_guard_registry_object()` logging and `g_ctx.f_ta_auth` on this SWd
  are only compiled. If FSD2/DebugSession fail to start now, look for the
  `open-session-registry ... SWd selection only` line and the daemon's FSD2 log.
- Client pid namespace on the phone: `unshare(CLONE_NEWPID)`, the procfs mount with
  `hidepid=invisible` and the binds onto `/proc/cmdline` and `/proc/sysrq-trigger` under the
  container's SELinux domain for the runner, and strace -f across the new pid namespace. All
  of this was tested on gekko only (x86, no SELinux enforcement on that path). If the phone
  refuses any step, the client is not started (`T3 FAIL ... client NOT started`).
- Whether anything in the vendor HAL path needs other processes' `/proc` entries (none
  expected; `/proc/self` works).

## What was built

**Kernel** `crownlte-tee-3` **fa72731b5** "blob-pinned guard for open-trustlet and admin
LOAD_DRIVER (T3)", on 566ee45af:
- `blob_guard.h`: pure decision function over the kernel's own `struct tee_object` copy
  (the buffer later mapped for the SWd, so no TOCTOU): SP trustlet (header_length != 0)
  -> refused; < 76 bytes -> refused; MCLF magic; service type must be 3 (open-trustlet)
  or 1 (LOAD_DRIVER); UUID and SHA-256 over the whole copy must match one
  `[uuid(16) sha256(32)]` pin (<= 4 per list) from `samsung,tee-trustlet-allow` /
  `samsung,tee-driver-allow`.
- `client_open_trustlet` (user and kernel clients) and admin `LOAD_DRIVER` -> `load_driver()`
  call it after the copy, before `client_add_session`/`client_cbuf_create`. Refusal frees
  the copy and returns -EPERM.
- No pin list for a path -> refused **before** any user data is read, with the exact
  pre-T3 log line (`mc_blob_guard_precheck` -> `mc_session_guard(NULL, ...)`). So the
  T2/T2j DTBs behave as before, and so does the T3a-0/1/b0 daemon LOAD_DRIVER path.
  Without `samsung,tee-session-guard` nothing changes at all. Malformed list -> allows
  nothing (pr_err). `LOAD_CHECK` stays refused unconditionally while guarded.
- Every decision logged: `tee session-guard: <what> uuid=.. type=.. len=.. sha256=<32 bytes>
  by comm[pid]: allowed | REFUSED (<reason>)`; pins logged at probe. New read-only
  params `mcDrvModule.trustlet_pins` / `driver_pins` next to `session_guard`.
- Kconfig: TRUSTONIC_TEE selects CRYPTO_LIB_SHA256 (already =y).
- Host fixture `MobiCoreDriver/tests/blob-guard-fixture.c` (the same header, OpenSSL
  SHA-256): the 6 real vendor blobs, 1-byte flips (header-adjacent, middle, last),
  truncation/extension, SP header, retyped header, bad magic, changed UUID, spliced
  header, short blobs, empty lists, wrong path, DT list sizes:
  **`blob guard fixture: PASS (47 checks, 0 failures)`** (ASan/UBSan).
- Image a466abe215a07834072cd4188c0f18a16180359ef22e15d61a13b9655ea60334, incremental
  build in /dev/shm/build-tee3 of exactly the committed sources (built just before the
  commit; banner `6.12.93-crownlte-diag+ ... #4 ... 23:25:11`), no warnings. Copy in
  `panel-bright-work/ko-tee-t3pin`.

**DTBs** (`panel-bright-work/dtb/exynos9810-crownlte-romram-tee-t3{a0,a1,a2,b0,b1}.dts`,
generated by `src/t3-tools/mkdts-t3.sh` from tee-t3dbg 06a6cf36; compiled with
build-dtb.sh into ko-tee-t3pin):

| stage | sha256 | trustlet pins | driver pins |
|---|---|---|---|
| t3a0, t3a1 (identical bytes) | 91e4ebcc4df8f3ce8636b64587a08b8402f29b4986c2c77e5061d6cf8af5e08e | KM | none |
| t3a2 | 0fd173cf1278c4b46dd16ac8da2bcdaad007ac0daa2c376548d2a2dc00b6a094 | KM | sec 01, TIMA d..0a, CM d..16 |
| t3b0 | 5f6379911e2b1bfb649e32ff6930c83d623c17e334866bd028fc9f05de48c3d8 | GK | none |
| t3b1 | 1a40fcf7868d916608e52ac4ea732abd23facb3dd70502dd678067048241262d | GK | CM d..16 |

`src/t3-tools/verify-dtb.py`: decompiled diff against 06a6cf36 = only the added pin
properties; every pin re-derived from the vendor file: **`dtb verify: PASS`**.

**Ramdisk** branch `tee-t3` (on tee-t2 3259275), opt-in `TEE_T2=1 TEE_T3=<stage>`:
- `tee-t3-run.c` (static, root): `check` (stage file == compiled stage, guard on, DT pin
  bytes exact for the stage, sysfs pin counts, blob/daemon/client hashes, container masks
  still empty, no /dev/bsg entries, no sg/bsg/sd/ufs-srpmb char/block nodes in /dev),
  `daemon` (T2 v5 + `-r` of exactly the stage's pinned drivers; LOAD_DRIVER allowed in
  seccomp only then), `client` (private mount ns; see below), `supervise` (bounded strace,
  own process group, time/size/SIGTERM stop).
- Client namespace: private user node (uid 1000), `/dev/mobicore` (admin) and
  `/dev/socket/property_service` masked by an empty mode-0000 file, `/efs` and
  `/mnt/vendor/efs` replaced by an empty RO tmpfs, only the stage's libraries unmasked
  and hash-verified (KM: keystore.mdfpp, libkeymaster2_mdfpp, helper, libMcClient; GK:
  libMcClient), `/vendor/bin` = RO tmpfs holding only the hash-verified client, uid/gid
  1000 + drmrpc, NO_NEW_PRIVS, RLIMIT_CORE 0, seccomp (88 insns): 'M' ioctls only VERSION,
  HAS_SESSIONS, OPEN_TRUSTLET, CLOSE, NOTIFY, WAIT, MAP, UNMAP, ERR (no OPEN_SESSION, GP or
  admin); sockets only AF_UNIX/SOCK_DGRAM; EPERM for mount/umount2/pivot_root/chroot/
  ptrace/setns/unshare/bpf/module/kexec/reboot/swap/perf/process_vm_writev/
  open_by_handle_at/socketpair/key*/mknodat; other arch -> kill. The client adds its own
  no-execve/execveat layer as its first action.
- `t3/crownlte-t3-km.c`: dlopen keystore.mdfpp.so, checks HMI tag / api 0x0200 / id,
  open, [a2: configure], [a1, a2: add_rng_entropy 32 B getrandom, wiped], close. a2 reads
  `ro.build.version.release` / `ro.build.version.security_patch`, parses them like AOSP,
  and aborts before any TEE call unless they give 160000 / 202608. The executable exports
  the 9 libMcClient functions the helper imports. bionic binds the dlopen'ed HAL to them
  first, so every TEE call is logged (`T3 tee ...`) and forwarded. The open-trustlet
  wrapper passes only the KM TA (len 767845, UUID, type 3, spid 0xfffffffe). Waits are
  clamped to <= 40 s. Only TCI word 0 (command id) is logged.
- `t3/crownlte-t3-gk.c`: libMcClient directly (HAL never loaded). b0: open/close, no command.
  b1: one verify, TCI exactly as `gatekeeper.exynos9810.so` TEE_Verify (file VA
  0x2c78-0x3360): cmd 2, uid 0x7ffffff0, challenge 0, handle at WSM+0, password at +0x800
  (16 random bytes), CLOCK_BOOTTIME ms, token out +0xc00 (len in 0, as the HIDL impl),
  context +0x400 left zero (as with missing gk_context files), wait 15000 ms. Prints
  ta_ret / retry_timeout / reenroll / token_len only. The WSM is wiped and nothing is opened
  for writing.
- Both clients are bionic PIE executables (no NDK on gekko): clang-18
  `--target=aarch64-linux-android30`, freestanding, own `_start` -> `__libc_init` (bionic
  only reads `structors->fini_array`; checked by disassembly), linked against libc.so/
  libdl.so dumped from the SYSTEM image's runtime APEX (sha256 pinned in build.sh),
  `-z now --no-undefined`. build.sh checks INTERP /system/bin/linker64, exactly NEEDED
  libc.so+libdl.so, PIE, no TEXTREL/RPATH, 9 exported mc* (KM) / 0 (GK).
- `templates/tee-t3.sh`: /dev/block + /dev/bsg + /dev/sg* refusal, `check`, daemon start,
  waits for `TEE is ready` and for the expected allowed driver loads (blob-path guard
  refusals fatal; open-session refusals reported), property `vendor.sys.mobicoredaemon.enable`
  set by the runner only if the daemon did not, client, logcat/kmsg (re-printed with `T3 `),
  whole-trace totals, daemon stop, `T3 RESULT stage=<s> PASS|FAIL`.
- PID1 (`-DRR_TEE_T3`): copies tee-t3.sh, stage file, runner and client (hashed copies) and
  mounts an empty RO tmpfs on `/rom/dev/bsg` before ueventd. The sysfs bsg/scsi_generic/UFS
  masks were already there.
- `t3-seccomp-fixture.c`: daemon (both variants) and client programs over all 2^24 'M'
  cmds plus socket/deny/allow/arch cases: **`t3 seccomp fixture: PASS (0 failures; insns
  daemon=35 daemon+drv=37 client=88; 2^24 'M' cmds x3)`**. T2 fixture still PASS.
- Regression: `TEE_T2=1` without TEE_T3 = e6c0c93d (T2j build-17, byte-identical); default
  build = 72195507 (byte-identical to before).

## Artifacts

| stage | ramdisk (rom-ram/build-N) | tee-t3-run | t3-client | loader | recovery.img |
|---|---|---|---|---|---|
| t3a0 | build-20 aa4a08ed8d75fee7f03ba73a7338d8736c29e04552f0754d2362cda2c216b3eb | d85e9501... | km 41a08643... | 598e9ddb... | a76a1c975ce07bfe9abf5f18795e367f0ca6afec2660937072fc906ffae30ace |
| t3a1 | build-21 bbc7dd61ada3306050b54997acbbec80cd107497e513fc5bcd19aedfa0097b0d | 376190bc... | km 41a08643... | abd9bf8d... | 8f67ef519994a55df7bb650d57e292755713aac89c34361633708f5f57de0ec0 |
| t3a2 | build-22 dd4a6d0c70b69fcc4bba339eb9232a875e588707fe55133362b56dbe3dbe0868 | dc27be0d... | km 41a08643... | 746b6a5f... | d06b126ea01f12ba2c154a2debe399af240fced45dc944417164fdad3b87b6b1 |
| t3b0 | build-23 7b3bb2cbc69cd149e235ab777550e11c25e0b8207507b1c846c1dddc8c12d4f5 | 7e4a5262... | gk b8aee112... | f0267c10... | d831d685767d5b72cfa0d12e83a41c2d6778d72fe4ffca974d4bee67123c33a4 |
| t3b1 | build-24 8c380f63f4bc7625a2678d59533013a83b1c5ba2ce0709f0d8c55e3242a65a24 | fd1560b3... | gk b8aee112... | 398a4f28... | 9e7e2d38c5b67436e7f653fc58749e7d8cba8a0b3fd6ef416e79d7d2fb94443b |

Full client hashes: km 41a086437e13fcdca6adf666f2ff5acebeaf108e84df0083c6dde647f16b4f11,
gk b8aee112c6fe2bd50692b12c3baf54b8ba67c6b6d1afa4bc024a6f263fc1a26f. All packs: Image
a466abe2, shim bbea9590, parent a8198be0, restore 8763860c, 68149248 bytes, header bytes
changed [8, 595]. Every source/output hash is in `build-N/SHA256SUMS` and
`pack-romram-tee-<stage>/manifest.json`. The b1 manifest purpose starts with
`*** SEPARATE APPROVAL: sends ONE gatekeeper VERIFY (cmd 2) ***`.

Pins (= design Appendix A, re-derived from the mounted vendor image):
KM 40dbc984ecd447995b7a0021a1e0c8e621573089422fe74814b42d5c84211ea7,
GK 5062a6b0d27a8ebd891f51abd11533247bc6c6009c5f5ace0b98ffdbd07c3f57,
sec 7f64cbdd78e2da8cb5f2d8b951b1cb3c7e5a3e15badc1263883bb9c973f21caf,
TIMA a78e0c874a99d79e96af5c464d093ae41f31f07e885c7de30cb4effab0d64fa8,
CM baa9a8cd23afa8db5afec1a21a3f38fef3e2ae96776868b093740a7864667a1e.

## Deviations from the design

1. Design §7's example `tee-trustlet-allow` has a wrong KM digest tail
   (`... 14 b4 22 fe 7f 5d 4e a7`). The DTB uses the real digest (Appendix A, `...4814b42d5c84211ea7`).
2. Client seccomp allows `socket(AF_UNIX, SOCK_DGRAM)` and `connect` (design: refuse both)
   so that liblog reaches logd and the HAL's logcat lines exist. Stream/seqpacket/inet/
   netlink sockets are refused, so property set (stream) is impossible, and the
   property_service socket is also masked.
3. execve: the runner's filter must allow the one exec of the client; the client then
   installs its own no-execve/execveat filter as its first action (design: "execve after
   start-up").
4. "Bind-mounted at /vendor/bin/crownlte-t3-km": a bind target cannot be created on the RO
   vendor mount, so the client namespace gets a tmpfs on /vendor/bin (remounted RO) holding
   only that file (bind of the hash-verified copy).
5. Stricter than the design: the client namespace hides /efs and /mnt/vendor/efs entirely
   and masks the admin node. In T2/T3, /mnt/vendor/efs is a RO bind of the /efs RAM copy
   (design said "does not exist").
6. Added: libMcClient interposition in the KM client (per-call logging, KM-only
   open-trustlet, 40 s wait cap), sysfs pin counts, DT pin byte check in the runner, the
   PID1 /dev/bsg RO mask, and the split of fatal (blob) vs reported (session) guard refusals.
7. T3a-0 and T3a-1 share the same DTB bytes (91e4ebcc); the stages differ in the ramdisk only.
8. T3b-1 handle: AOSP `password_handle_t` v2 (58 bytes, random user_id/salt/HMAC,
   hardware_backed=1). Samsung's exact handle format was not confirmed. If the TA rejects it
   before the failure-record path, T3b-1 answers less of the T4 question (see ta_ret).
9. romram-adb was NOT merged. It is still under review, and "ADB together with TEE_T2"
   was never built or run. T3 evidence stays on the proven P;/K; serial path. romram-adb
   is a fast-forward of tee-t2, so adding it later is a clean merge plus `ADB=1` rebuilds.
10. No NDK on gekko: the bionic clients are built freestanding (see above) instead of
    with the NDK clang.

## Untested (nothing ran on hardware or an emulator)

- Kernel guard at runtime (decision logic is host-tested; hooks, DT parsing, logging and
  `sha256()` only compiled). Hash time of the 767 KB KM TA is expected to be a few ms.
- The bionic clients have never executed: the custom `_start`/`__libc_init` path, vendor
  linker-namespace selection from the tmpfs `/vendor/bin`, SELinux (su domain) for that
  exec, and whether bionic binds the HAL's mc* imports to the executable (if not, the
  client says `km WARN libMcClient interposition inactive` and still works).
- Whether the KM TA opens/accepts add_rng without the drivers (a0/a1) or before
  configure (a1). The design expects TIMA/CM errors there.
- Whether the daemon sets `vendor.sys.mobicoredaemon.enable` itself under seccomp/uid 1000
  (the runner sets it otherwise), and `dmesg` access from the container shell (if absent,
  the stage fails closed: no load/open counts).
- The 6.12 driver's handling of the vendor libMcClient (ioctl encodings match exactly:
  0xc0284d01, 0xc0284d05, 0x40284d06, 0x400c4d04, 0xc0084d07, 0x80604d09, 0x4d02/03/08).
- strace on a NO_NEW_PRIVS + seccomp tracee that changes uid (worked for the T2 daemon).
- T3b-1 handle format, TCI auth-token length 0, TA behaviour without SRPMB.

## Residual risks

- SWd state: TAs/drivers may write SWd RAM (ICCC/Trustboot on configure, as 4.9 does on
  every boot). Loaded drivers stay loaded until reboot. A wedged SWd (TA restart loop,
  SRPMB retry) is bounded on the NWd side (client alarm 60 s, supervisor 90 s/420 s,
  kill of the process groups, 600 s PID1 restart). RAM-only. A reboot clears it.
- RPMB: no NWd SRPMB proxy (ufs-srpmb not ported), `/dev/bsg` RO-masked, no sg driver,
  sysfs SCSI masks, UFS SCSI write guard. The sec driver (a2) starts its SRPMB client: a
  pending SWd->NWd SRPMB IRQ with no handler is a spurious-IRQ risk only (watch K;).
- b1: the GK TA will try to read, and possibly update, the failure record for uid 0x7ffffff0.
  It cannot reach RPMB. A FSD2 "kinibi partition" fallback hits the RO /efs copy (EROFS).
  This is a write attempt by the TA, harmless to the owner's lock screen (fake uid).
- No key material: no key is generated/imported/exported; entropy and the WSM (incl. any
  auth token) are wiped. Only return codes, lengths, TCI command ids and public blob
  digests are logged.
- Root in the container is not an adversary (as T2). The masks/namespace contain the
  vendor code, not a hostile root.
- KM `configure` binds the TA instance to 160000/202608 for this boot only (stateless key
  blobs; no keys exist in this boot).
