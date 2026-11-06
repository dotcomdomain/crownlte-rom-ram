# TEE T2 build report ? 2026-11-06

Build host only: root@10.0.1.7 (gekko). No phone commands, flashing, key
operations, RPMB commands or excluded project/VM access. Branch tee-t2, based
on adf8f25f892aa82127ee0b5755f0603025c69727.

## Scope and safety enforcement

- gen_payload.py: opt-in TEE_T2=1; requires DEADLINE=600; pins daemon and strace
  in the verified file manifest, adds only the T2 supervisor service. Original
  mobicore.rc remains empty. All keymaster module/libMcClient, gatekeeper,
  fingerprint, Widevine service/VINTF masks remain. Software keymaster as before.
- romram.h (RR_TEE_T2 compile branch): requires explicit DT tee status okay/ok,
  a char /dev/mobicore and bound mcd/tee; existing UFS guard DT property plus
  bound UFS host check precedes partition access. Pack pins the known T1 Image,
  with diagnostic-RO compiled in (host config and guard message checked).
  No runtime destructive write test is used to verify the guard.
- Only SYSTEM/VENDOR/ODM and EFS block nodes can be opened by T2 setup. It skips
  the old all-sd BLKROSET pass and never calls rr_frp_setup. USERDATA, CACHE,
  PERSISTENT, CPEFS, MISC, KEYSTORAGE and PARAM are never opened. Whole disks
  are not opened. Enumeration only reads sysfs metadata for other nodes.
- EFS: unique PARTNAME, 64 MiB bound, O_RDONLY/O_NOFOLLOW and matching device
  major:minor, BLKROSET/GET. Reads EFS bytes once into private tmpfs, hashes only
  the copy, attaches an explicitly read-only loop, mounts ext4 ro,noload on
  /efs and binds RO to /mnt/vendor/efs. The real EFS device is NEVER mounted.
  No other daemon-read partition was identified. Failure aborts container.
- /data (both mcRegistry layouts, debugsession, TbStorage) is tmpfs. Vendor
  registry remains on the read-only VENDOR mount. /dev/block is a read-only
  empty tmpfs; the EFS loop node/image are outside the chroot. Existing sysfs
  UFS/SCSI masks prevent normal ueventd recreation of storage devices.
- /dev/mobicore-user is occupied by a RO regular-file bind before init, so
  ueventd cannot replace it and no user TA session ioctl can reach the driver.
  Root is not considered an adversarial actor; normal sanitized Lineage init
  and vendor binaries are the scope of the namespace design.
- tee-t2-run.c: supervisor traces a uid/gid 1000 daemon (no supplementary
  groups, no_new_privs). Seccomp permits only GET_DRIVER_REQUEST, GET_INFO,
  LOAD_TOKEN MobiCore ioctl numbers; every other MobiCore ioctl gets EPERM.
  Thus accidental LOAD_DRIVER/LOAD_CHECK fails even without vendor -r arguments.
  This intentionally excludes the four vendor preloads below: opaque secure
  code has not been audited for key/RPMB side effects. This is a restricted T2
  daemon-start/auth-token trial, NOT validation of those secure drivers.
  The user-session node and absent secure driver loads prevent keymaster,
  gatekeeper/fingerprint TA sessions. No ufs-srpmb driver is ported; the pinned
  UFS guard rejects data-out/nonallowlisted SCSI before DMA/submission.
- templates/tee-t2.sh: bounded strace plus 5-second polling on existing P;
  channel. Write buffers are raw pointers (avoid logging token content).
  Records successful and failed file/device opens, write-related syscalls,
  EROFS/EACCES/EPERM, registry directory metadata before/after, passive debugfs
  structs_counters/sessions/last_mcp_commands, and McDaemon-tag logcat.
  Never reads crashdump (can issue SMC) or writes secure OS control nodes.
  Trace size stop threshold 8 MiB, hard RLIMIT_FSIZE 16 MiB, 450-second
  supervisor ceiling; kills/reaps trace process group on exit/failure. strace
  propagates daemon status, or a signal/bounded-stop is explicitly reported.
  Registry listings are bounded, so large directories can be truncated.
- Independent outer PID1 600-second restart is unchanged. No sync/recovery
  BCB writes. No background host build: all builds ran foreground with LLVM18
  PATH. All scratch work and shim compilation were in /dev/shm.

## Static daemon interface and path analysis

Evidence: verified vendor/etc/init/mobicore.rc, readelf NEEDED, strings from
mcDriverDaemon, and 4.9 MobiCoreDriver admin.c/user.c/public headers. The 4.9
repo contains the kernel interface, not the proprietary daemon source. These
are candidate paths/functions, not a claim of observed runtime writes.

Vendor init normally exports MC_AUTH_TOKEN_PATH=/efs, mkdirs /efs/TEE and
/mnt/vendor/efs/TEE and starts daemon with these -r files:
FFFFFFFF000000000000000000000001.drbin,
ffffffffd0000000000000000000000a.tlbin,
ffffffffd00000000000000000000016.tlbin,
ffffffffd00000000000000000000045.drbin in /vendor/app/mcRegistry.
T2 suppresses these mkdir actions and does not preload any of these files.

All literal storage roots found in daemon strings:
- /efs, /efs/TEE, /efs/prov: auth token read/backup/rename and provisioning;
  every write/rename/unlink/mkdir fails on the RO copy (including the alias).
- /data/vendor/mcRegistry, /data/misc/mcRegistry: private registry, SO root/SP/
  trustlet/data containers, TA blob store, registry migration/update/cleanup;
  all writes land in tmpfs. Container suffixes include .spcont, .tlcont,
  .datacont, .tabin; fixed names 00000000.authtokcont, 00000000.rootcont;
  migration marker /.migration-done is appended to a registry root.
- /TbStorage: storage-folder suffix; creates/opens/removes per-TA storage files.
  At a /data registry root this is tmpfs. If interpreted as an absolute root
  path it fails on the RO SYSTEM root. Exact dynamic names require runtime trace.
- /data/local/tmp/debugsession: debug path, tmpfs; no real data exposed.
- /vendor/app/mcRegistry and /system/app/mcRegistry: registry search roots,
  read-only images; attempted writes fail EROFS.
- /dev/mobicore (admin requests/token), /dev/mobicore-user (session node, masked),
  /dev/t-base-tui (not exposed by this kernel), debugfs trustonic_tee/crashdump
  (not mounted at its normal path). Kernel admin LOAD_DRIVER creates sessions;
  seccomp specifically blocks it. LOAD_TOKEN remains allowed for auth-token read.
- Log tags found: McDaemon.UPDT, McDaemon.SWd, McDaemon.Server, McDaemon.FSD2.

NEEDED: liblog.so, libc++.so, libc.so, libm.so, libdl.so; no dynamic libMcClient
requirement, so keeping libMcClient masked does not disable this daemon.
No additional partition read path was identified. Proprietary code and dynamic
filenames mean this static list is not exhaustive proof; runtime trace is needed.

## Validation and remaining risks

T2 compiles with -Wall -Wextra -Werror; ASAN/UBSAN manifest positive and three
negative tests pass. bash syntax and Python compilation pass. Exhaustive offline
ioctl type/number fixture passes for seccomp jump layout (65536 cases + arch and
non-ioctl cases). Default old/new builds at DEADLINE=600 have BYTE-IDENTICAL
compressed ramdisks (cmp), stronger than behavioural comparison.
Packer hash checks, ARM64 magic/banner, shim compilation, loader size and
independent recovery reparse pass. No runtime tests on phone or emulator.

Open risks: daemon may require the suppressed vendor preloads or inaccessible
user node and exit; this pack cannot establish driver-load T2 PASS. EFS copy
mount may reject an unclean filesystem (no replay/fallback allowed). strace
ptrace and vendor linker/SELinux behaviour are untested. Debugfs may be absent;
passive files then report unavailable. No UFS guard counter exists in this
kernel; ratelimited K; rejection logs are a lower bound only. Polling may miss
short-lived directory changes; strace is the write-attempt evidence. Bounded
trace/audit can truncate output; a bounded kill is not successful completion.
T1 kernel lacks panel L2 recovery; serial is required. Secure-world firmware is
opaque; this stage deliberately cannot load additional opaque drivers/TAs.

## Artifacts and exact hashes

build-11/diagnostic-initramfs.cpio.gz:
082298fe69c90bcd551241a694608d5d0155749d5b0850ab3bc6ac40e0e4b850
pack-romram-tee-t2/recovery.img:
fadf05102a4fffc948ac817c6790261d6e64f3cd1610dce8dd1c0c89789581eb
Kernel Image:
53a285e7a31c6551cf0ccd0a1086c72bf4016df59ffdafe5301bbc52a7c90eb4
DTB:
fbd215b0072f782d1ab15f737b69cda94d288f5826bfca734a1a48046deb6b70
Payload manifest:
904d00e0a616eed1088dd03bc7c677d1784e227f3a62f48edf5b6943e1fbafda
Loader:
590d9328c55ca41b1ff2cbcbf5520efe0601210dc0b6404eaf7ab598eb8eeae9

All source/config/parent input hashes: pack manifest.json, build-11/SHA256SUMS
and INPUT-SHA256SUMS.json.

Kernel selection: 233829a14 is not descended from 22e97b5d2; its v23a DTB has
TEE interrupt flags 0, not rising-edge 1. Per requested fallback, use exact T1
Image/DTB; no new v23a-based DTB or full kernel worktree was created. The IRQ fix
is DT-only; driver sources match, but this pack intentionally uses the stated
fallback rather than synthesizing a new combination.
