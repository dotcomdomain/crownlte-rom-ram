/* SPDX-License-Identifier: GPL-2.0 */
/* Host test: run tee-t2-run.c's seccomp program through a classic-BPF interpreter.
 * Every ioctl cmd with type byte 'M' (2^24) must be refused except the exact T2
 * allowlist; arch mismatch kills; non-'M' ioctls and other syscalls pass.
 * Built and run by build.sh for TEE_T2=1 (cc -I<src>). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
static struct sock_filter cap[64];
static unsigned capn;
static int fake_prctl(int o, unsigned long m, struct sock_fprog *p)
{
	(void)o;
	if (m != SECCOMP_MODE_FILTER)
		return 0;
	if (p->len > 64)
		return -1;
	capn = p->len;
	memcpy(cap, p->filter, p->len * sizeof(*cap));
	return 0;
}
#define prctl(a, b, c, ...) fake_prctl((a), (unsigned long)(b), (struct sock_fprog *)(c))
#define main t2_main
#include "tee-t2-run.c"
#undef main
#undef prctl
static uint32_t run(const struct seccomp_data *d)
{
	uint32_t A = 0;
	for (unsigned pc = 0; pc < capn;) {
		const struct sock_filter *i = &cap[pc];
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
static void mk(struct seccomp_data *d, uint32_t arch, int nr, uint64_t a1)
{
	memset(d, 0, sizeof(*d));
	d->arch = arch;
	d->nr = nr;
	d->args[1] = a1;
}
int main(void)
{
	static const uint32_t allow[] = {0x80204d00, 0x80084d01, 0x40184d03, 0x80604d09, 0x00004d08,
					 0xc0404d00, 0x4d02, 0x4d03, 0x400c4d04, 0xc0284d05, 0x40284d06, 0xc0084d07};
	static const uint32_t deny[] = {0x40184d02, 0x40184d04, 0xc0284d01, 0x40084d14, 0xc0e04d18};
	struct seccomp_data d;
	int fails = 0;
	if (restrict_tee() || !capn) {
		printf("t2 seccomp fixture: FAIL (no program)\n");
		return 1;
	}
	for (uint64_t c = 0; c < (1ull << 32); c += 0x10000)
		for (unsigned nr = 0; nr < 256; nr++) {
			uint32_t cmd = (uint32_t)c | 0x4d00 | nr;
			int want = 0;
			for (unsigned k = 0; k < sizeof(allow) / sizeof(allow[0]); k++)
				want |= cmd == allow[k];
			mk(&d, AUDIT_ARCH_AARCH64, __NR_ioctl, cmd | 0xffffffff00000000ull);
			if ((run(&d) == SECCOMP_RET_ALLOW) != want && fails++ < 5)
				printf("mismatch %#x\n", cmd);
		}
	for (unsigned k = 0; k < sizeof(deny) / sizeof(deny[0]); k++) {
		mk(&d, AUDIT_ARCH_AARCH64, __NR_ioctl, deny[k]);
		if (run(&d) != (SECCOMP_RET_ERRNO | EPERM))
			fails++;
	}
	mk(&d, AUDIT_ARCH_AARCH64, __NR_ioctl, 0x5401);
	if (run(&d) != SECCOMP_RET_ALLOW)
		fails++;
	mk(&d, 0xc000003e, __NR_ioctl, 0x80204d00);
	if (run(&d) != SECCOMP_RET_KILL_PROCESS)
		fails++;
	mk(&d, AUDIT_ARCH_AARCH64, __NR_openat, 0);
	if (run(&d) != SECCOMP_RET_ALLOW)
		fails++;
	printf("t2 seccomp fixture: %s (%d failures, %u insns, 2^24 'M' cmds)\n",
	       fails ? "FAIL" : "PASS", fails, capn);
	return !!fails;
}
