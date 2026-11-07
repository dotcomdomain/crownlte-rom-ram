/* SPDX-License-Identifier: GPL-2.0 */
/* Host test for tee-t3-run.c's seccomp programs, run through a classic-BPF
 * interpreter (as t2-seccomp-fixture.c). Uses the runner's own builders.
 *  - daemon, both variants: every ioctl cmd with type byte 'M' (2^24) is
 *    refused except the exact list (+LOAD_DRIVER only when drivers are pinned);
 *  - client: exact 9-cmd user-node list (no OPEN_SESSION, GP or admin), only
 *    AF_UNIX/SOCK_DGRAM sockets, the deny list returns EPERM, the rest passes;
 *  - io_uring_setup/enter/register: ENOSYS for daemon and client (io_uring
 *    ops such as IORING_OP_SOCKET would bypass the socket rule); client
 *    clone3 ENOSYS, clone with any CLONE_NEW* flag EPERM, fork/thread/vfork
 *    clone flags allowed;
 *  - wrong arch kills. Built and run by build.sh for TEE_T3.
 *  The client /proc isolation (pid namespace, fresh procfs) is exercised for
 *  real by t3-pidns-fixture.c. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define main t3_runner_main
#include "tee-t3-run.c"
#undef main

static struct t3_prog cur;

static uint32_t run(const struct seccomp_data *d)
{
	uint32_t A = 0;

	for (unsigned pc = 0; pc < cur.n;) {
		const struct sock_filter *i = &cur.f[pc];

		switch (i->code) {
		case BPF_LD | BPF_W | BPF_ABS: memcpy(&A, (const char *)d + i->k, 4); pc++; break;
		case BPF_ALU | BPF_AND | BPF_K: A &= i->k; pc++; break;
		case BPF_JMP | BPF_JEQ | BPF_K: pc += 1 + (A == i->k ? i->jt : i->jf); break;
		case BPF_RET | BPF_K: return i->k;
		default: return 0xdead;
		}
	}
	return 0xbeef;
}

static uint32_t call(uint32_t arch, int nr, uint64_t a0, uint64_t a1)
{
	struct seccomp_data d;

	memset(&d, 0, sizeof(d));
	d.arch = arch;
	d.nr = nr;
	d.args[0] = a0;
	d.args[1] = a1;
	return run(&d);
}

static int fails;
#define EXPECT(cond, ...) do { if (!(cond)) { if (fails++ < 10) printf("FAIL " __VA_ARGS__); } } while (0)
#define EPERM_RET (SECCOMP_RET_ERRNO | EPERM)
#define ENOSYS_RET (SECCOMP_RET_ERRNO | ENOSYS)

/* io_uring (IORING_OP_SOCKET/OPENAT/... bypass the filtered syscalls): ENOSYS */
static void expect_no_io_uring(const char *name)
{
	static const int nr[] = {T3_NR_io_uring_setup, T3_NR_io_uring_enter, T3_NR_io_uring_register};

	for (unsigned i = 0; i < 3; i++) {
		EXPECT(call(AUDIT_ARCH_AARCH64, nr[i], 0, 0) == ENOSYS_RET, "%s io_uring nr %d\n", name, nr[i]);
		EXPECT(call(AUDIT_ARCH_AARCH64, nr[i], 16, 0xffffffffffffffffull) == ENOSYS_RET,
		       "%s io_uring nr %d args\n", name, nr[i]);
	}
}

static void mspace(const char *name, const uint32_t *allow, unsigned n)
{
	for (uint64_t c = 0; c < (1ull << 32); c += 0x10000)
		for (unsigned nr = 0; nr < 256; nr++) {
			uint32_t cmd = (uint32_t)c | 0x4d00 | nr;
			int want = 0;

			for (unsigned k = 0; k < n; k++)
				want |= cmd == allow[k];
			/* high half of the 64-bit register must not matter */
			EXPECT((call(AUDIT_ARCH_AARCH64, T3_NR_ioctl, 3, cmd | 0xffffffff00000000ull) ==
				SECCOMP_RET_ALLOW) == want, "%s cmd %#x\n", name, cmd);
			if (!want)
				EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_ioctl, 3, cmd) == EPERM_RET,
				       "%s cmd %#x not EPERM\n", name, cmd);
		}
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_ioctl, 1, 0x5401) == SECCOMP_RET_ALLOW, "%s TCGETS\n", name);
	EXPECT(call(0xc000003e, T3_NR_ioctl, 3, allow[0]) == SECCOMP_RET_KILL_PROCESS, "%s x86 arch\n", name);
	EXPECT(call(0x40000028, 56, 0, 0) == SECCOMP_RET_KILL_PROCESS, "%s arm32 arch\n", name);
}

int main(void)
{
	static const uint32_t daemon_allow[] = {
		0x80204d00, 0x80084d01, 0x40184d03, 0x80604d09, 0x00004d08, 0xc0404d00,
		0x4d02, 0x4d03, 0x400c4d04, 0xc0284d05, 0x40284d06, 0xc0084d07, 0x40184d02};
	static const uint32_t client_allow[] = {
		0x80604d09, 0x00004d08, 0xc0284d01, 0x4d02, 0x4d03, 0x400c4d04, 0xc0284d05,
		0x40284d06, 0xc0084d07};
	static const int denied[] = {
		T3_NR_mount, T3_NR_umount2, T3_NR_pivot_root, T3_NR_chroot, T3_NR_ptrace, T3_NR_setns,
		T3_NR_unshare, T3_NR_bpf, T3_NR_init_module, T3_NR_finit_module, T3_NR_delete_module,
		T3_NR_kexec_load, T3_NR_kexec_file_load, T3_NR_reboot, T3_NR_swapon, T3_NR_swapoff,
		T3_NR_perf_event_open, T3_NR_process_vm_writev, T3_NR_open_by_handle_at,
		T3_NR_socketpair, T3_NR_keyctl, T3_NR_add_key, T3_NR_request_key, T3_NR_mknodat,
		/* S2: cross-process memory/fd, new mount API */
		T3_NR_process_vm_readv, T3_NR_pidfd_open, T3_NR_pidfd_getfd, T3_NR_open_tree,
		T3_NR_move_mount, T3_NR_fsopen, T3_NR_fsconfig, T3_NR_fsmount, T3_NR_fspick,
		T3_NR_mount_setattr};
	/* clone flags: fork (SIGCHLD), bionic pthread_create, posix_spawn vfork */
	static const uint64_t clone_ok[] = {17, 0x3d0f00, 0x4111, 17 | 1ull << 32};
	static const uint32_t clone_ns[] = {0x20000, 0x02000000, 0x04000000, 0x08000000,
					    0x10000000, 0x20000000, 0x40000000};
	/* aarch64: openat 56, close 57, read 63, write 64, mmap 222, clone 220, execve 221,
	 * connect 203, getrandom 278, prctl 167, exit_group 94, futex 98 */
	static const int passed[] = {56, 57, 63, 64, 222, 220, 221, 203, 278, 167, 94, 98};
	unsigned sizes[3];

	/* daemon without pinned drivers: T2 v3 list exactly (LOAD_DRIVER refused) */
	if (build_daemon_filter(&cur, 0))
		return printf("t3 seccomp fixture: FAIL (daemon program)\n"), 1;
	sizes[0] = cur.n;
	mspace("daemon", daemon_allow, 12);
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_ioctl, 3, MC_LOAD_DRIVER) == EPERM_RET, "daemon LOAD_DRIVER\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_mount, 0, 0) == SECCOMP_RET_ALLOW, "daemon other syscall\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_socket, 2, 1) == SECCOMP_RET_ALLOW, "daemon socket\n");
	expect_no_io_uring("daemon");

	/* daemon with pinned drivers: + LOAD_DRIVER, LOAD_CHECK still refused */
	if (build_daemon_filter(&cur, 1))
		return printf("t3 seccomp fixture: FAIL (daemon+drv program)\n"), 1;
	sizes[1] = cur.n;
	mspace("daemon+drv", daemon_allow, 13);
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_ioctl, 3, MC_LOAD_CHECK) == EPERM_RET, "daemon+drv LOAD_CHECK\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_ioctl, 3, MC_OPEN_TRUSTLET) == EPERM_RET, "daemon OPEN_TRUSTLET\n");
	expect_no_io_uring("daemon+drv");

	/* client */
	if (build_client_filter(&cur))
		return printf("t3 seccomp fixture: FAIL (client program)\n"), 1;
	sizes[2] = cur.n;
	mspace("client", client_allow, 9);
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_ioctl, 3, MC_OPEN_SESSION) == EPERM_RET, "client OPEN_SESSION\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_ioctl, 3, MC_LOAD_DRIVER) == EPERM_RET, "client LOAD_DRIVER\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_ioctl, 3, MC_GET_DRIVER_REQUEST) == EPERM_RET, "client admin\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_ioctl, 3, 0x40084d14) == EPERM_RET, "client GP\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_socket, 1, 2) == SECCOMP_RET_ALLOW, "unix dgram\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_socket, 1, 2 | 0x80000 | 0x800) == SECCOMP_RET_ALLOW,
	       "unix dgram cloexec nonblock\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_socket, 1, 1) == EPERM_RET, "unix stream\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_socket, 1, 1 | 0x80000) == EPERM_RET, "unix stream cloexec\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_socket, 1, 5) == EPERM_RET, "unix seqpacket\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_socket, 2, 2) == EPERM_RET, "inet dgram\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_socket, 10, 1) == EPERM_RET, "inet6 stream\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_socket, 16, 2) == EPERM_RET, "netlink\n");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_socket, 1ull << 32 | 1, 2) == SECCOMP_RET_ALLOW,
	       "family high bits ignored (int)\n");
	for (unsigned i = 0; i < sizeof(denied) / sizeof(denied[0]); i++)
		EXPECT(call(AUDIT_ARCH_AARCH64, denied[i], 0, 0) == EPERM_RET, "client nr %d not denied\n", denied[i]);
	for (unsigned i = 0; i < sizeof(passed) / sizeof(passed[0]); i++)
		EXPECT(call(AUDIT_ARCH_AARCH64, passed[i], 0, 0) == SECCOMP_RET_ALLOW, "client nr %d not allowed\n",
		       passed[i]);
	EXPECT(call(0xc000003e, T3_NR_socket, 1, 2) == SECCOMP_RET_KILL_PROCESS, "client x86\n");
	/* S2: io_uring would open stream/INET sockets without socket() */
	expect_no_io_uring("client");
	EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_clone3, 0, 0) == ENOSYS_RET, "client clone3\n");
	for (unsigned i = 0; i < sizeof(clone_ok) / sizeof(clone_ok[0]); i++)
		EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_clone, clone_ok[i], 0) == SECCOMP_RET_ALLOW,
		       "client clone %#llx\n", (unsigned long long)clone_ok[i]);
	for (unsigned i = 0; i < sizeof(clone_ns) / sizeof(clone_ns[0]); i++) {
		EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_clone, clone_ns[i] | 17, 0) == EPERM_RET,
		       "client clone ns %#x\n", clone_ns[i]);
		EXPECT(call(AUDIT_ARCH_AARCH64, T3_NR_clone, clone_ns[i] | 0x3d0f00, 0) == EPERM_RET,
		       "client clone thread+ns %#x\n", clone_ns[i]);
	}

	printf("t3 seccomp fixture: %s (%d failures; insns daemon=%u daemon+drv=%u client=%u; 2^24 'M' cmds x3)\n",
	       fails ? "FAIL" : "PASS", fails, sizes[0], sizes[1], sizes[2]);
	return !!fails;
}
