/* SPDX-License-Identifier: GPL-2.0 */
/*
 * crownlte TEE T3 runner (static, root, started by tee-t3.sh). Extends the T2
 * runner (tee-t2-run.c, unchanged) for the stages of tee-t3-design.md:
 *
 *   a0 a1 a2  keymaster TA via the dedicated client crownlte-t3-km
 *   b0 b1     gatekeeper TA via the dedicated client crownlte-t3-gk
 *
 * Modes:
 *   check              pre-flight: stage file == compiled stage, kernel guard
 *                      on, DT pin lists byte-exact for this stage, pin counts,
 *                      vendor blob hashes, container masks, no /dev/bsg|sg*.
 *   supervise TAG SECS TRACE ARGS...
 *                      bounded strace of "tee-t3-run ARGS..." (own process
 *                      group; time, trace-size and SIGTERM stop it).
 *   daemon             T2 daemon (private user node, uid 1000, no_new_privs,
 *                      seccomp) plus -r preloads of exactly the pinned drivers
 *                      of this stage; LOAD_DRIVER allowed only then.
 *   client             private mount namespace for the stage client, then
 *                      uid 1000 + seccomp + exec of the client.
 *
 * Every line on stdout starts with "T3 " (stdout is /dev/crownlte/probe.txt).
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <grp.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <dirent.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include "romram-sha256.h"

#ifndef T3_STAGE
#error "build with -DT3_STAGE=\"a0|a1|a2|b0|b1\""
#endif
#ifndef T3_CLIENT_SHA
#error "build with -DT3_CLIENT_SHA=\"<sha256 of t3-client>\""
#endif

#define T3(...) printf("T3 " __VA_ARGS__)
#define T3E(...) fprintf(stderr, "T3 " __VA_ARGS__)

/* aarch64 syscall numbers (asm-generic); the fixture runs on the build host. */
#define T3_NR_ioctl		29
#define T3_NR_mknodat		33
#define T3_NR_umount2		39
#define T3_NR_mount		40
#define T3_NR_pivot_root	41
#define T3_NR_chroot		51
#define T3_NR_unshare		97
#define T3_NR_kexec_load	104
#define T3_NR_init_module	105
#define T3_NR_delete_module	106
#define T3_NR_ptrace		117
#define T3_NR_reboot		142
#define T3_NR_socket		198
#define T3_NR_socketpair	199
#define T3_NR_add_key		217
#define T3_NR_request_key	218
#define T3_NR_keyctl		219
#define T3_NR_swapon		224
#define T3_NR_swapoff		225
#define T3_NR_perf_event_open	241
#define T3_NR_open_by_handle_at	265
#define T3_NR_setns		268
#define T3_NR_process_vm_writev	271
#define T3_NR_finit_module	273
#define T3_NR_bpf		280
#define T3_NR_kexec_file_load	294
#ifdef __aarch64__
_Static_assert(T3_NR_ioctl == __NR_ioctl && T3_NR_socket == __NR_socket &&
	       T3_NR_mount == __NR_mount && T3_NR_umount2 == __NR_umount2 &&
	       T3_NR_ptrace == __NR_ptrace && T3_NR_unshare == __NR_unshare &&
	       T3_NR_setns == __NR_setns && T3_NR_bpf == __NR_bpf &&
	       T3_NR_mknodat == __NR_mknodat && T3_NR_socketpair == __NR_socketpair &&
	       T3_NR_pivot_root == __NR_pivot_root && T3_NR_chroot == __NR_chroot &&
	       T3_NR_kexec_load == __NR_kexec_load && T3_NR_kexec_file_load == __NR_kexec_file_load &&
	       T3_NR_init_module == __NR_init_module && T3_NR_finit_module == __NR_finit_module &&
	       T3_NR_delete_module == __NR_delete_module && T3_NR_reboot == __NR_reboot &&
	       T3_NR_swapon == __NR_swapon && T3_NR_swapoff == __NR_swapoff &&
	       T3_NR_perf_event_open == __NR_perf_event_open &&
	       T3_NR_process_vm_writev == __NR_process_vm_writev &&
	       T3_NR_open_by_handle_at == __NR_open_by_handle_at && T3_NR_keyctl == __NR_keyctl &&
	       T3_NR_add_key == __NR_add_key && T3_NR_request_key == __NR_request_key,
	       "aarch64 syscall numbers");
#endif

/* MobiCore ioctls (6.12 public mc_admin.h / mc_user.h). */
#define MC_GET_DRIVER_REQUEST	0x80204d00u	/* admin */
#define MC_GET_INFO		0x80084d01u
#define MC_LOAD_DRIVER		0x40184d02u
#define MC_LOAD_TOKEN		0x40184d03u
#define MC_LOAD_CHECK		0x40184d04u
#define MC_OPEN_SESSION		0xc0404d00u	/* user node */
#define MC_OPEN_TRUSTLET	0xc0284d01u
#define MC_CLOSE		0x00004d02u
#define MC_NOTIFY		0x00004d03u
#define MC_WAIT			0x400c4d04u
#define MC_MAP			0xc0284d05u
#define MC_UNMAP		0x40284d06u
#define MC_ERR			0xc0084d07u
#define MC_HAS_SESSIONS		0x00004d08u
#define MC_VERSION		0x80604d09u

/* ------------------------------------------------------------ pins */
struct t3_blob {
	const char *file;	/* in /vendor/app/mcRegistry */
	const char *sha;
	unsigned char uuid[16];
};
static const struct t3_blob KM = {"ffffffff00000000000000000000003e.tlbin",
	"40dbc984ecd447995b7a0021a1e0c8e621573089422fe74814b42d5c84211ea7",
	{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x3e}};
static const struct t3_blob GK = {"08130000000000000000000000000000.tlbin",
	"5062a6b0d27a8ebd891f51abd11533247bc6c6009c5f5ace0b98ffdbd07c3f57",
	{0x08, 0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
static const struct t3_blob SEC = {"FFFFFFFF000000000000000000000001.drbin",
	"7f64cbdd78e2da8cb5f2d8b951b1cb3c7e5a3e15badc1263883bb9c973f21caf",
	{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}};
static const struct t3_blob TIMA = {"ffffffffd0000000000000000000000a.tlbin",
	"a78e0c874a99d79e96af5c464d093ae41f31f07e885c7de30cb4effab0d64fa8",
	{0xff, 0xff, 0xff, 0xff, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a}};
static const struct t3_blob CM = {"ffffffffd00000000000000000000016.tlbin",
	"baa9a8cd23afa8db5afec1a21a3f38fef3e2ae96776868b093740a7864667a1e",
	{0xff, 0xff, 0xff, 0xff, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16}};

/* Vendor client libraries (tee-t3-design.md Appendix A). */
struct t3_file { const char *path, *sha; };
static const struct t3_file KM_LIBS[] = {
	{"/vendor/lib64/hw/keystore.mdfpp.so", "9f3f1567ccf9a24e00b111b9a08fc885147e497a964f2a0a0729fb6fc423f02b"},
	{"/vendor/lib64/libkeymaster2_mdfpp.so", "24e981206e9fd001f07ba76a3f7c39781b142f796e6f69d0a5202edba87def12"},
	{"/vendor/lib64/libkeymaster_helper_vendor.so", "b79741c2de3c925aa63f7768a9dfe145788b5167da19c09f90058d51603049f6"},
	{"/vendor/lib64/libMcClient.so", "3606fe238f5a93d89578139c346d08840a7d2745dcc2ebecef048a5ef4e669d1"},
	{NULL, NULL},
};
static const struct t3_file GK_LIBS[] = {
	{"/vendor/lib64/libMcClient.so", "3606fe238f5a93d89578139c346d08840a7d2745dcc2ebecef048a5ef4e669d1"},
	{NULL, NULL},
};
#define DAEMON_SHA "c7f6275bfa7715c4eb927f16123e90d6ad9bafeae8c7e5f03e8f720da8875073"

struct t3_stage {
	const char *name;
	const char *client;			/* basename under /vendor/bin */
	const struct t3_blob *trustlet;		/* the one pinned TA */
	const struct t3_blob *drivers[4];	/* pinned = preloaded, in this order */
	const struct t3_file *libs;		/* unmasked in the client namespace */
	const char *what;
};
static const struct t3_stage STAGES[] = {
	{"a0", "crownlte-t3-km", &KM, {NULL}, KM_LIBS, "keymaster TA open/close; no drivers"},
	{"a1", "crownlte-t3-km", &KM, {NULL}, KM_LIBS, "keymaster TA open, addRngEntropy, close; no drivers"},
	{"a2", "crownlte-t3-km", &KM, {&SEC, &TIMA, &CM, NULL}, KM_LIBS,
	 "drivers sec/TIMA/CryptoManager; keymaster open, configure(160000, 202608), addRngEntropy, close"},
	{"b0", "crownlte-t3-gk", &GK, {NULL}, GK_LIBS, "gatekeeper TA open/close only; no command; no drivers"},
	{"b1", "crownlte-t3-gk", &GK, {&CM, NULL}, GK_LIBS,
	 "driver CryptoManager; gatekeeper TA + ONE verify (fake uid 0x7ffffff0, bounded 15 s)"},
};
static const struct t3_stage *st;

static int ndrivers(const struct t3_stage *s)
{
	int n = 0;

	while (n < 4 && s->drivers[n])
		n++;
	return n;
}

/* ------------------------------------------------------------ helpers */
static int read_text(const char *path, char *buf, size_t n)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t r;

	if (fd < 0)
		return -1;
	r = read(fd, buf, n - 1);
	close(fd);
	if (r < 0)
		return -1;
	buf[r] = 0;
	return (int)r;
}

static int read_bin(const char *path, unsigned char *buf, size_t n)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t r;

	if (fd < 0)
		return -1;
	r = read(fd, buf, n);
	close(fd);
	return (int)r;
}

/* sha256 hex of a regular file (no symlinks), -1 on error */
static int sha_file(const char *path, char hex[65], unsigned long long *size)
{
	static unsigned char buf[65536];
	struct rom_sha s;
	struct stat sb;
	ssize_t r;
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

	if (fd < 0)
		return -1;
	if (fstat(fd, &sb) || !S_ISREG(sb.st_mode)) {
		close(fd);
		return -1;
	}
	rom_sha_init(&s);
	*size = 0;
	while ((r = read(fd, buf, sizeof(buf))) > 0) {
		rom_sha_update(&s, buf, (size_t)r);
		*size += (unsigned long long)r;
	}
	close(fd);
	if (r < 0)
		return -1;
	rom_sha_hex(&s, hex);
	return 0;
}

static int check_sha(const char *path, const char *want)
{
	char hex[65];
	unsigned long long size = 0;

	if (sha_file(path, hex, &size)) {
		T3("FAIL cannot hash %s errno=%d\n", path, errno);
		return -1;
	}
	if (strcmp(hex, want)) {
		T3("FAIL %s sha256 %s != pinned %s\n", path, hex, want);
		return -1;
	}
	T3("verified %s bytes=%llu sha256=%s\n", path, size, hex);
	return 0;
}

static int blob_path(const struct t3_blob *b, char *out, size_t n)
{
	return snprintf(out, n, "/vendor/app/mcRegistry/%s", b->file) >= (int)n ? -1 : 0;
}

static int hexval(char c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

/* DT pin bytes = uuid(16) + sha256(32) */
static void pin_bytes(const struct t3_blob *b, unsigned char out[48])
{
	memcpy(out, b->uuid, 16);
	for (int i = 0; i < 32; i++)
		out[16 + i] = (unsigned char)(hexval(b->sha[2 * i]) << 4 | hexval(b->sha[2 * i + 1]));
}

/* No storage pass-through nodes may exist: /dev/bsg/ (SCSI generic over bsg,
 * the RPMB W-LU path) and /dev/sg* (CHR_DEV_SG is off; checked anyway). */
static int no_scsi_passthrough(void)
{
	DIR *d;
	struct dirent *e;
	int bad = 0, n = 0;

	d = opendir("/dev/bsg");
	if (d) {
		while ((e = readdir(d)))
			if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
				T3("FAIL /dev/bsg/%s exists\n", e->d_name);
				bad++;
			}
		closedir(d);
	} else if (errno != ENOENT) {
		T3("FAIL cannot list /dev/bsg errno=%d\n", errno);
		return -1;
	}
	d = opendir("/dev");
	if (!d) {
		T3("FAIL cannot list /dev errno=%d\n", errno);
		return -1;
	}
	while ((e = readdir(d))) {
		n++;
		if (!strncmp(e->d_name, "sg", 2) || !strncmp(e->d_name, "bsg", 3) ||
		    !strncmp(e->d_name, "sd", 2) || !strcmp(e->d_name, "ufs-srpmb")) {
			struct stat sb;
			char p[300];

			snprintf(p, sizeof(p), "/dev/%s", e->d_name);
			if (!lstat(p, &sb) && (S_ISCHR(sb.st_mode) || S_ISBLK(sb.st_mode))) {
				T3("FAIL storage pass-through node %s exists\n", p);
				bad++;
			}
		}
	}
	closedir(d);
	if (bad || n < 3)
		return -1;
	return 0;
}

/* ------------------------------------------------------------ seccomp */
struct t3_prog {
	struct sock_filter f[128];
	unsigned n;
};
static void ins(struct t3_prog *p, unsigned short code, unsigned k, unsigned char jt, unsigned char jf)
{
	if (p->n < sizeof(p->f) / sizeof(p->f[0]))
		p->f[p->n] = (struct sock_filter){code, jt, jf, k};
	p->n++;
}
static void ret(struct t3_prog *p, unsigned k)
{
	ins(p, BPF_RET | BPF_K, k, 0, 0);
}
static void if_eq_ret(struct t3_prog *p, unsigned k, unsigned r)
{
	ins(p, BPF_JMP | BPF_JEQ | BPF_K, k, 0, 1);
	ret(p, r);
}
static void ld(struct t3_prog *p, unsigned off)
{
	ins(p, BPF_LD | BPF_W | BPF_ABS, off, 0, 0);
}
/* "if (nr == X) { ...block that always returns... }" */
static unsigned begin_nr(struct t3_prog *p, unsigned nr)
{
	ld(p, offsetof(struct seccomp_data, nr));
	ins(p, BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 0);
	return p->n - 1;
}
static int end_nr(struct t3_prog *p, unsigned at)
{
	unsigned skip = p->n - at - 1;

	if (skip > 255 || p->n > sizeof(p->f) / sizeof(p->f[0]))
		return -1;
	p->f[at].jf = (unsigned char)skip;
	return 0;
}
static void arch_check(struct t3_prog *p)
{
	ld(p, offsetof(struct seccomp_data, arch));
	ins(p, BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0);
	ret(p, SECCOMP_RET_KILL_PROCESS);
}
/* ioctl block: exact 'M' allow list, any other 'M' (type byte 0x4d) -> EPERM */
static void mc_ioctls(struct t3_prog *p, const unsigned *allow, unsigned n)
{
	ld(p, offsetof(struct seccomp_data, args[1]));	/* low 32 bits (LE) */
	for (unsigned i = 0; i < n; i++)
		if_eq_ret(p, allow[i], SECCOMP_RET_ALLOW);
	ins(p, BPF_ALU | BPF_AND | BPF_K, 0xff00, 0, 0);
	if_eq_ret(p, 0x4d00, SECCOMP_RET_ERRNO | EPERM);
	ret(p, SECCOMP_RET_ALLOW);
}

/* Daemon: the T2 v3 list; LOAD_DRIVER only in stages with pinned drivers.
 * LOAD_CHECK, OPEN_TRUSTLET and all GP_* stay refused. */
static int build_daemon_filter(struct t3_prog *p, int load_driver)
{
	unsigned allow[16] = {MC_GET_DRIVER_REQUEST, MC_GET_INFO, MC_LOAD_TOKEN, MC_VERSION,
			      MC_HAS_SESSIONS, MC_OPEN_SESSION, MC_CLOSE, MC_NOTIFY, MC_WAIT,
			      MC_MAP, MC_UNMAP, MC_ERR};
	unsigned n = 12, at;

	if (load_driver)
		allow[n++] = MC_LOAD_DRIVER;
	p->n = 0;
	arch_check(p);
	at = begin_nr(p, T3_NR_ioctl);
	mc_ioctls(p, allow, n);
	if (end_nr(p, at))
		return -1;
	ret(p, SECCOMP_RET_ALLOW);
	return p->n <= sizeof(p->f) / sizeof(p->f[0]) ? 0 : -1;
}

/* Client: user-node session ioctls only (no OPEN_SESSION, no GP, no admin);
 * sockets only AF_UNIX/SOCK_DGRAM (liblog); no mount/ptrace/namespace/module/
 * key/bpf/mknod syscalls. execve stays possible for the one exec of the
 * client; the client then adds its own no-exec layer (t3-bionic.h). */
static int build_client_filter(struct t3_prog *p)
{
	static const unsigned allow[] = {MC_VERSION, MC_HAS_SESSIONS, MC_OPEN_TRUSTLET, MC_CLOSE,
					 MC_NOTIFY, MC_WAIT, MC_MAP, MC_UNMAP, MC_ERR};
	static const unsigned deny[] = {
		T3_NR_mount, T3_NR_umount2, T3_NR_pivot_root, T3_NR_chroot, T3_NR_ptrace,
		T3_NR_setns, T3_NR_unshare, T3_NR_bpf, T3_NR_init_module, T3_NR_finit_module,
		T3_NR_delete_module, T3_NR_kexec_load, T3_NR_kexec_file_load, T3_NR_reboot,
		T3_NR_swapon, T3_NR_swapoff, T3_NR_perf_event_open, T3_NR_process_vm_writev,
		T3_NR_open_by_handle_at, T3_NR_socketpair, T3_NR_keyctl, T3_NR_add_key,
		T3_NR_request_key, T3_NR_mknodat,
	};
	unsigned at;

	p->n = 0;
	arch_check(p);
	at = begin_nr(p, T3_NR_ioctl);
	mc_ioctls(p, allow, sizeof(allow) / sizeof(allow[0]));
	if (end_nr(p, at))
		return -1;
	at = begin_nr(p, T3_NR_socket);
	ld(p, offsetof(struct seccomp_data, args[0]));
	ins(p, BPF_JMP | BPF_JEQ | BPF_K, 1 /* AF_UNIX */, 1, 0);
	ret(p, SECCOMP_RET_ERRNO | EPERM);
	ld(p, offsetof(struct seccomp_data, args[1]));
	ins(p, BPF_ALU | BPF_AND | BPF_K, 0xf /* SOCK_TYPE_MASK */, 0, 0);
	if_eq_ret(p, 2 /* SOCK_DGRAM */, SECCOMP_RET_ALLOW);
	ret(p, SECCOMP_RET_ERRNO | EPERM);
	if (end_nr(p, at))
		return -1;
	ld(p, offsetof(struct seccomp_data, nr));
	for (unsigned i = 0; i < sizeof(deny) / sizeof(deny[0]); i++)
		if_eq_ret(p, deny[i], SECCOMP_RET_ERRNO | EPERM);
	ret(p, SECCOMP_RET_ALLOW);
	return p->n <= sizeof(p->f) / sizeof(p->f[0]) ? 0 : -1;
}

static int install(struct t3_prog *p)
{
	struct sock_fprog prog = {(unsigned short)p->n, p->f};

	return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

/* ------------------------------------------------------------ check */
static int guard_state(void)
{
	char g[8] = {0}, n[16];
	int tl, drv;

	if (read_text("/sys/module/mcDrvModule/parameters/session_guard", g, sizeof(g)) < 1 || g[0] != 'Y') {
		T3("FAIL kernel TEE session guard not active\n");
		return -1;
	}
	if (read_text("/sys/module/mcDrvModule/parameters/trustlet_pins", n, sizeof(n)) < 1)
		return T3("FAIL kernel has no blob guard (trustlet_pins missing)\n"), -1;
	tl = atoi(n);
	if (read_text("/sys/module/mcDrvModule/parameters/driver_pins", n, sizeof(n)) < 1)
		return T3("FAIL kernel has no blob guard (driver_pins missing)\n"), -1;
	drv = atoi(n);
	T3("kernel guard on, trustlet_pins=%d driver_pins=%d\n", tl, drv);
	if (tl != 1 || drv != ndrivers(st)) {
		T3("FAIL pin counts for stage %s must be trustlet=1 driver=%d\n", st->name, ndrivers(st));
		return -1;
	}
	return 0;
}

static int dt_pins(void)
{
	static const char *base = "/sys/firmware/devicetree/base/tee/";
	unsigned char got[4 * 48 + 1], want[4 * 48];
	char path[256];
	int n, nd = ndrivers(st);

	snprintf(path, sizeof(path), "%ssamsung,tee-trustlet-allow", base);
	pin_bytes(st->trustlet, want);
	n = read_bin(path, got, sizeof(got));
	if (n != 48 || memcmp(got, want, 48)) {
		T3("FAIL DT samsung,tee-trustlet-allow is not exactly the %s pin (%d bytes)\n", st->trustlet->file, n);
		return -1;
	}
	snprintf(path, sizeof(path), "%ssamsung,tee-driver-allow", base);
	for (int i = 0; i < nd; i++)
		pin_bytes(st->drivers[i], want + 48 * i);
	n = read_bin(path, got, sizeof(got));
	if (nd ? (n != 48 * nd || memcmp(got, want, (size_t)(48 * nd))) : !(n < 0 && errno == ENOENT)) {
		T3("FAIL DT samsung,tee-driver-allow does not match stage %s (%d bytes, want %d)\n",
		   st->name, n, 48 * nd);
		return -1;
	}
	T3("DT pins exact: trustlet %s, %d driver(s)\n", st->trustlet->file, nd);
	return 0;
}

static int masked_in_container(const char *path)
{
	struct stat sb;

	if (lstat(path, &sb) || !S_ISREG(sb.st_mode) || sb.st_size != 0) {
		T3("FAIL %s is not the empty container mask\n", path);
		return -1;
	}
	return 0;
}

static int do_check(void)
{
	char stage[8] = {0}, path[256];

	T3("STAGE %s: %s\n", st->name, st->what);
	if (read_text("/dev/crownlte/tee_t3", stage, sizeof(stage)) < 2 || strncmp(stage, st->name, 2) ||
	    (stage[2] && stage[2] != '\n')) {
		T3("FAIL stage file /dev/crownlte/tee_t3 does not say %s\n", st->name);
		return 1;
	}
	if (guard_state() || dt_pins() || no_scsi_passthrough())
		return 1;
	if (blob_path(st->trustlet, path, sizeof(path)) || check_sha(path, st->trustlet->sha))
		return 1;
	for (int i = 0; i < ndrivers(st); i++)
		if (blob_path(st->drivers[i], path, sizeof(path)) || check_sha(path, st->drivers[i]->sha))
			return 1;
	if (check_sha("/vendor/bin/mcDriverDaemon", DAEMON_SHA) || check_sha("/dev/crownlte/t3-client", T3_CLIENT_SHA))
		return 1;
	/* The real HALs stay masked for the whole container (software keymaster). */
	if (masked_in_container("/vendor/lib64/hw/keystore.mdfpp.so") ||
	    masked_in_container("/vendor/lib64/libMcClient.so") ||
	    masked_in_container("/vendor/lib/libMcClient.so") ||
	    masked_in_container("/dev/mobicore-user"))
		return 1;
	T3("PASS pre-flight stage=%s (guard, DT pins, blob hashes, masks, no bsg/sg)\n", st->name);
	return 0;
}

/* ------------------------------------------------------------ namespaces */
static int t3_read_devt(const char *path, unsigned *ma, unsigned *mi)
{
	char b[32] = {0};

	return (read_text(path, b, sizeof(b)) > 0 && sscanf(b, "%u:%u", ma, mi) == 2) ? 0 : -1;
}

static int bind_ro(const char *src, const char *dst)
{
	if (mount(src, dst, NULL, MS_BIND, NULL) ||
	    mount(NULL, dst, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL))
		return -1;
	return 0;
}

/* Private namespace + private tmpfs DIR holding the real user node (uid 1000). */
static int private_user_node(const char *dir)
{
	char node[256];
	unsigned ama, ami, uma, umi;

	if (t3_read_devt("/sys/class/trustonic_tee/mobicore/dev", &ama, &ami) ||
	    t3_read_devt("/sys/class/trustonic_tee/mobicore-user/dev", &uma, &umi) ||
	    uma != ama || umi == ami) {
		T3("FAIL user node: bad devt\n");
		return -1;
	}
	snprintf(node, sizeof(node), "%s/mobicore-user", dir);
	if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
		return -1;
	if ((mkdir(dir, 0700) && errno != EEXIST) ||
	    mount("tmpfs", dir, "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=0711,size=64k"))
		return -1;
	if (mknod(node, S_IFCHR | 0600, makedev(uma, umi)) || chown(node, 1000, 1000))
		return -1;
	if (umount2("/dev/mobicore-user", MNT_DETACH) || mount(node, "/dev/mobicore-user", NULL, MS_BIND, NULL))
		return -1;
	T3("user node %u:%u private to this namespace\n", uma, umi);
	return 0;
}

static void close_extra_fds(void)
{
	for (int fd = 3; fd < 1024; fd++)
		close(fd);
}

static int drop_to_system(const gid_t *groups, size_t ng)
{
	if (setgroups(ng, groups) || setgid(1000) || setuid(1000) ||
	    getuid() != 1000 || geteuid() != 1000 || getgid() != 1000)
		return -1;
	return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
}

static int do_daemon(void)
{
	struct t3_prog p;
	char paths[4][256];
	char *argv[12];
	int a = 0, nd = ndrivers(st);

	if (private_user_node("/dev/crownlte/t3-dnode")) {
		perror("T3 daemon namespace");
		return 124;
	}
	argv[a++] = "mcDriverDaemon";
	for (int i = 0; i < nd; i++) {
		if (blob_path(st->drivers[i], paths[i], sizeof(paths[i])))
			return 124;
		argv[a++] = "-r";
		argv[a++] = paths[i];
	}
	argv[a] = NULL;
	if (build_daemon_filter(&p, nd > 0))
		return 125;
	close_extra_fds();
	if (drop_to_system(NULL, 0) || install(&p))
		return 125;
	setenv("MC_AUTH_TOKEN_PATH", "/efs", 1);
	T3("daemon exec uid=1000 preloads=%d load_driver=%s\n", nd, nd ? "allowed (kernel pins)" : "refused");
	for (int i = 0; i < nd; i++)
		T3("daemon -r %s\n", paths[i]);
	execv("/vendor/bin/mcDriverDaemon", argv);
	perror("T3 daemon exec");
	return 127;
}

static int empty_ro_dir(const char *path)
{
	struct stat sb;

	if (lstat(path, &sb))
		return errno == ENOENT ? 0 : -1;
	if (!S_ISDIR(sb.st_mode))
		return -1;
	return mount("tmpfs", path, "tmpfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k,mode=0555");
}

static int do_client(void)
{
	static const gid_t drmrpc[] = {1026};
	const char *dir = "/dev/crownlte/t3-cns";
	char empty[256], target[256], path[256];
	struct t3_prog p;
	int fd;

	if (guard_state() || dt_pins() || no_scsi_passthrough())
		return 124;
	if (private_user_node(dir))
		goto fail;
	/* The admin node and the property service are not reachable from here. */
	snprintf(empty, sizeof(empty), "%s/empty", dir);
	fd = open(empty, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0000);
	if (fd < 0 || close(fd))
		goto fail;
	if (bind_ro(empty, "/dev/mobicore"))
		goto fail;
	if (bind_ro(empty, "/dev/socket/property_service")) {
		T3("FAIL cannot mask /dev/socket/property_service errno=%d\n", errno);
		goto fail;
	}
	/* No EFS at all for the client: gk_context/DAK/TEE files cannot be read or written. */
	if (empty_ro_dir("/efs") || empty_ro_dir("/mnt/vendor/efs"))
		goto fail;
	/* Unmask exactly this stage's libraries, then verify the real bytes. */
	for (const struct t3_file *f = st->libs; f->path; f++) {
		struct stat sb;

		if (!lstat(f->path, &sb) && S_ISREG(sb.st_mode) && sb.st_size == 0 &&
		    umount2(f->path, MNT_DETACH)) {
			T3("FAIL cannot unmask %s errno=%d\n", f->path, errno);
			goto fail;
		}
		if (check_sha(f->path, f->sha))
			goto fail;
	}
	if (blob_path(st->trustlet, path, sizeof(path)) || check_sha(path, st->trustlet->sha))
		goto fail;
	/* /vendor/bin becomes a read-only tmpfs holding only the verified client,
	 * so the vendor linker namespace applies to it. */
	if (check_sha("/dev/crownlte/t3-client", T3_CLIENT_SHA))
		goto fail;
	if (mount("tmpfs", "/vendor/bin", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=64k"))
		goto fail;
	snprintf(target, sizeof(target), "/vendor/bin/%s", st->client);
	fd = open(target, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0755);
	if (fd < 0 || close(fd) || bind_ro("/dev/crownlte/t3-client", target) ||
	    mount(NULL, "/vendor/bin", NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL))
		goto fail;
	if (check_sha(target, T3_CLIENT_SHA))
		goto fail;
	if (build_client_filter(&p))
		goto fail;
	{
		struct rlimit core = {0, 0};

		setrlimit(RLIMIT_CORE, &core);
	}
	close_extra_fds();
	if (drop_to_system(drmrpc, 1) || install(&p))
		goto fail;
	T3("client exec %s %s uid=1000 groups=drmrpc seccomp=client(%u insns)\n", target, st->name, p.n);
	fflush(stdout);
	execl(target, st->client, st->name, (char *)NULL);
	T3("FAIL client exec errno=%d\n", errno);
	return 127;
fail:
	T3("FAIL client namespace setup errno=%d; client NOT started\n", errno);
	return 124;
}

/* ------------------------------------------------------------ supervise */
static volatile sig_atomic_t stop_req;
static void on_term(int sig)
{
	(void)sig;
	stop_req = 1;
}

static int do_supervise(int argc, char **argv)
{
	const char *tag = argv[2], *trace = argv[4];
	int secs = atoi(argv[3]);
	char *args[16];
	int a = 0, status = 0, bounded = 0, reaped = 0;
	struct sigaction sa;
	pid_t child;
	time_t start;

	if (secs <= 0 || secs > 540 || argc - 5 > 4) {
		T3("FAIL supervise usage\n");
		return 2;
	}
	args[a++] = "strace";
	args[a++] = "-f";
	args[a++] = "-y";
	args[a++] = "-s";
	args[a++] = "0";
	args[a++] = "-e";
	args[a++] = "trace=file,ioctl,write,pwrite64,writev,fsync,close,socket,connect,mount,umount2,unshare,execve";
	args[a++] = "-o";
	args[a++] = (char *)trace;
	args[a++] = "/dev/crownlte/tee-t3-run";
	for (int i = 5; i < argc; i++)
		args[a++] = argv[i];
	args[a] = NULL;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	child = fork();
	if (child < 0)
		return 125;
	if (!child) {
		struct rlimit limit = {16 * 1024 * 1024, 16 * 1024 * 1024};

		if (setpgid(0, 0) || setrlimit(RLIMIT_FSIZE, &limit))
			_exit(125);
		execv("/system/bin/strace", args);
		_exit(127);
	}
	(void)setpgid(child, child);
	T3("%s start trace_pid=%d bound=%ds trace=%s\n", tag, child, secs, trace);
	start = time(NULL);
	for (;;) {
		struct stat sb;
		pid_t got = waitpid(child, &status, WNOHANG);

		if (got == child) {
			reaped = 1;
			break;
		}
		if (got < 0 && errno != EINTR)
			break;
		if (stop_req || (!stat(trace, &sb) && sb.st_size >= 8 * 1024 * 1024) ||
		    time(NULL) - start >= secs) {
			bounded = stop_req ? 2 : 1;
			break;
		}
		usleep(200000);
	}
	/* Always kill/reap the whole trace group, including descendants. */
	kill(-child, SIGKILL);
	if (!reaped && waitpid(child, &status, 0) != child)
		return 125;
	if (WIFEXITED(status))
		T3("%s exit status=%d bounded=%d%s\n", tag, WEXITSTATUS(status), bounded,
		   bounded == 2 ? " (stopped by runner)" : "");
	else if (WIFSIGNALED(status))
		T3("%s exit signal=%d bounded=%d%s\n", tag, WTERMSIG(status), bounded,
		   bounded == 2 ? " (stopped by runner)" : "");
	return WIFEXITED(status) && !bounded ? WEXITSTATUS(status) : 125;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	for (unsigned i = 0; i < sizeof(STAGES) / sizeof(STAGES[0]); i++)
		if (!strcmp(STAGES[i].name, T3_STAGE))
			st = &STAGES[i];
	if (!st) {
		T3("FAIL unknown compiled stage\n");
		return 2;
	}
	if (argc == 2 && !strcmp(argv[1], "check"))
		return do_check();
	if (argc == 2 && !strcmp(argv[1], "daemon"))
		return do_daemon();
	if (argc == 2 && !strcmp(argv[1], "client"))
		return do_client();
	if (argc >= 6 && !strcmp(argv[1], "supervise"))
		return do_supervise(argc, argv);
	T3("FAIL usage: tee-t3-run check|daemon|client|supervise TAG SECS TRACE ARGS...\n");
	return 2;
}
