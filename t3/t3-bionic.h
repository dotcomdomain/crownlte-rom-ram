/* SPDX-License-Identifier: GPL-2.0 */
/*
 * crownlte T3 test clients: the few bionic (Android libc) declarations they
 * use. No NDK on the build host: the clients are compiled freestanding with
 * clang-18 --target=aarch64-linux-android and linked against libc.so/libdl.so
 * extracted from the verified SYSTEM image's runtime APEX (build.sh pins
 * their SHA-256 and checks that every undefined symbol is exported there).
 * Values below are the arm64 bionic/asm-generic ABI.
 */
#ifndef T3_BIONIC_H
#define T3_BIONIC_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

typedef long ssize_t;
struct timespec { long tv_sec; long tv_nsec; };

int dprintf(int fd, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int snprintf(char *s, size_t n, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
void *memset(void *s, int c, size_t n);
void *memcpy(void *d, const void *s, size_t n);
int memcmp(const void *a, const void *b, size_t n);
int strcmp(const char *a, const char *b);
size_t strlen(const char *s);
int open(const char *path, int flags, ...);
ssize_t read(int fd, void *buf, size_t n);
int close(int fd);
void *malloc(size_t n);
void free(void *p);
int posix_memalign(void **p, size_t align, size_t n);
ssize_t getrandom(void *buf, size_t n, unsigned flags);
int clock_gettime(int clk, struct timespec *ts);
unsigned alarm(unsigned seconds);
int prctl(int option, ...);
unsigned getuid(void);
unsigned getgid(void);
int *__errno(void);
void exit(int status) __attribute__((noreturn));
int __system_property_get(const char *name, char *value);	/* PROP_VALUE_MAX 92 */
void *dlopen(const char *path, int flags);
void *dlsym(void *handle, const char *sym);
char *dlerror(void);

#define errno (*__errno())
#define O_RDONLY	0
#define O_NOFOLLOW	0100000
#define O_CLOEXEC	02000000
#define RTLD_NOW	2
#define RTLD_NOLOAD	4
#define CLOCK_BOOTTIME	7
#define PROP_VALUE_MAX	92

/* Every line goes to stdout = /dev/crownlte/probe.txt = "P;" on serial. */
#define T3(...) dprintf(1, "T3 " __VA_ARGS__)

/*
 * Second, client-installed seccomp layer (the runner's filter is already
 * active and NO_NEW_PRIVS is set): after start-up no execve/execveat at all.
 */
struct t3_sock_filter { uint16_t code; uint8_t jt, jf; uint32_t k; };
struct t3_sock_fprog { unsigned short len; struct t3_sock_filter *filter; };
static inline int t3_no_exec(void)
{
	static struct t3_sock_filter f[] = {
		{0x20, 0, 0, 4},		/* ld arch */
		{0x15, 1, 0, 0xc00000b7},	/* AUDIT_ARCH_AARCH64 */
		{0x06, 0, 0, 0x80000000},	/* KILL_PROCESS */
		{0x20, 0, 0, 0},		/* ld nr */
		{0x15, 2, 0, 221},		/* __NR_execve */
		{0x15, 1, 0, 281},		/* __NR_execveat */
		{0x06, 0, 0, 0x7fff0000},	/* ALLOW */
		{0x06, 0, 0, 0x00050000 | 1},	/* ERRNO | EPERM */
	};
	struct t3_sock_fprog p = {sizeof(f) / sizeof(f[0]), f};

	if (prctl(38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0))
		return -1;
	return prctl(22 /* PR_SET_SECCOMP */, 2 /* SECCOMP_MODE_FILTER */, &p);
}

/*
 * Entry point: bionic's crtbegin_dynamic equivalent. __libc_init (dynamic
 * executables) only reads structors->fini_array (offset 16; NULL = none);
 * the extra zeroed slots cover later bionic layouts.
 */
int main(int argc, char **argv);
struct t3_structors { void (**preinit)(void); void (**init)(void); void (**fini)(void); void *pad[5]; };
void __libc_init(void *raw, void (*onexit)(void), int (*slingshot)(int, char **, char **),
		 const struct t3_structors *s) __attribute__((noreturn));
static int t3_slingshot(int argc, char **argv, char **envp)
{
	(void)envp;
	return main(argc, argv);
}
__attribute__((used, noreturn)) void t3_start_main(void *raw)
{
	static const struct t3_structors s;

	__libc_init(raw, 0, t3_slingshot, &s);
}
__asm__(".text\n.globl _start\n.type _start,%function\n_start:\n"
	"\tmov x29, #0\n\tmov x30, #0\n\tmov x0, sp\n\tb t3_start_main\n"
	".size _start, .-_start\n");

static inline uint64_t t3_boottime_ms(void)
{
	struct timespec ts = {0, 0};

	if (clock_gettime(CLOCK_BOOTTIME, &ts))
		return 0;
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static inline int t3_random(void *buf, size_t n)
{
	return getrandom(buf, n, 0) == (ssize_t)n ? 0 : -1;
}

/* Kinibi t-base 400 libMcClient ABI (LP64), checked against the vendor HALs. */
typedef uint32_t mcResult_t;
typedef struct { uint32_t sessionId; uint32_t deviceId; } mcSessionHandle_t;
typedef struct { uint32_t sVirtualAddr; uint32_t sVirtualLen; } mcBulkMap_t;
#define MC_DRV_OK		0
#define MC_DRV_ERR_UNKNOWN	6
#define MC_DEVICE_ID_DEFAULT	0

struct t3_mc {
	mcResult_t (*openDevice)(uint32_t);
	mcResult_t (*closeDevice)(uint32_t);
	mcResult_t (*openTrustlet)(mcSessionHandle_t *, uint32_t, uint8_t *, uint32_t, uint8_t *, uint32_t);
	mcResult_t (*closeSession)(mcSessionHandle_t *);
	mcResult_t (*notify)(mcSessionHandle_t *);
	mcResult_t (*waitNotification)(mcSessionHandle_t *, int32_t);
	mcResult_t (*map)(mcSessionHandle_t *, void *, uint32_t, mcBulkMap_t *);
	mcResult_t (*unmap)(mcSessionHandle_t *, void *, mcBulkMap_t *);
	mcResult_t (*getSessionErrorCode)(mcSessionHandle_t *, int32_t *);
};

/* Resolve the real libMcClient entry points (already loaded or loads it). */
static inline int t3_mc_resolve(struct t3_mc *mc, int flags)
{
	void *h = dlopen("/vendor/lib64/libMcClient.so", flags);
	void **slot = (void **)mc;
	static const char *const names[] = {
		"mcOpenDevice", "mcCloseDevice", "mcOpenTrustlet", "mcCloseSession", "mcNotify",
		"mcWaitNotification", "mcMap", "mcUnmap", "mcGetSessionErrorCode",
	};

	if (!h) {
		T3("FAIL dlopen libMcClient.so: %s\n", dlerror());
		return -1;
	}
	for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		slot[i] = dlsym(h, names[i]);
		if (!slot[i]) {
			T3("FAIL dlsym %s: %s\n", names[i], dlerror());
			return -1;
		}
	}
	return 0;
}
#endif
