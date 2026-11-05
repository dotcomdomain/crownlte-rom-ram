/* SPDX-License-Identifier: GPL-2.0 */
/*
 * crownlte ROM-in-RAM diagnostic PID1 (RECOVERY trial image).
 *
 * Reused from diagnostic-init-delayed-ufs-20261016 (hardware-tested):
 *   - independent restart timer child forked before any mount or I/O,
 *   - USB ACM gadget "crownlte_diag" (1d6b:0104) carrying /dev/kmsg,
 *   - exact-frame serial handshake; UFS first probe held until the host asks.
 * Reused from diagnostic-android-adb-20261017: Lineage init runs in its own
 * PID + mount namespace (+ cgroup namespace), owned and killed by this PID1.
 *
 * Changes for the ROM-in-RAM trial:
 *   - deadline is configurable (/crownlte/deadline_seconds, default 300 s,
 *     clamped to 60..900 s); the timer child still owns the only restart;
 *   - third host frame CROWNLTE-ROMRAM-START-1 starts the ROM stage
 *     (romram.h) once the read-only UFS probe child exited 0;
 *   - container is SIGKILLed CONTAINER_MARGIN seconds before the restart;
 *   - logcat/probe text files written by the container to its RAM /dev are
 *     forwarded over the same serial stream ("L;" and "P;" line prefixes);
 *   - larger log cache, faster drain (printk ring is only 128 KiB).
 *
 * This process never opens a block device and never writes to storage.
 * The ROM stage child opens UFS block devices read-only (BLKROSET) and mounts
 * SYSTEM/VENDOR/ODM read-only; see romram.h.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int kmsg = -1;
static char history[4 * 1024 * 1024];
static size_t history_len;
static unsigned long long deadline_sample_elapsed_ms;
static int deadline_sample_valid;
static int timer_wait_previous_error;

#define DEADLINE_DEFAULT 300
#define DEADLINE_MIN 60
#define DEADLINE_MAX 900
#define CONTAINER_MARGIN 25     /* container SIGKILL this long before restart */
#define START_LATEST_MARGIN 60  /* refuse a ROM start this close to restart */
static unsigned int deadline_seconds = DEADLINE_DEFAULT;
static int deadline_source;     /* 0 default, 1 file, -errno file error */

static int announce(const char *fmt, ...)
{
        char buf[1024];
        va_list ap;
        int n;
        va_start(ap, fmt);
        n = vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (n < 0)
                return -EINVAL;
        if ((size_t)n >= sizeof(buf))
                n = sizeof(buf) - 1;
        dprintf(STDERR_FILENO, "crownlte-diag: %s\n", buf);
        if (kmsg >= 0) {
                int written = dprintf(kmsg, "<6>crownlte-diag: %s\n", buf);
                return written < 0 ? -errno :
                       written == n + (int)strlen("<6>crownlte-diag: ") + 1 ? 0 : -EIO;
        }
        return -ENODEV;
}

static int put(const char *path, const char *value)
{
        int fd = open(path, O_WRONLY | O_CLOEXEC);
        ssize_t n;
        int error;
        if (fd < 0)
                return -errno;
        n = write(fd, value, strlen(value));
        error = n < 0 ? -errno : (n == (ssize_t)strlen(value) ? 0 : -EIO);
        close(fd);
        return error;
}

/* Read the optional deadline file from the initramfs. Called before the timer
 * fork; touches nothing but one regular ramdisk file. Any error keeps the
 * compiled default. The value is clamped, so no file can remove the deadline. */
static void load_deadline(void)
{
        char buf[32] = {0};
        int fd = open("/crownlte/deadline_seconds", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        ssize_t n;
        char *end;
        unsigned long v;
        if (fd < 0) {
                deadline_source = errno == ENOENT ? 0 : -errno;
                return;
        }
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) {
                deadline_source = -EIO;
                return;
        }
        buf[n] = 0;
        errno = 0;
        v = strtoul(buf, &end, 10);
        if (errno || end == buf || (*end && *end != '\n')) {
                deadline_source = -EINVAL;
                return;
        }
        if (v < DEADLINE_MIN)
                v = DEADLINE_MIN;
        if (v > DEADLINE_MAX)
                v = DEADLINE_MAX;
        deadline_seconds = (unsigned int)v;
        deadline_source = 1;
}

struct devkmsg_status {
        int write_error, read_error;
        char value[16];
};

static struct devkmsg_status enable_devkmsg(void)
{
        struct devkmsg_status status = {0};
        const char *path = "/proc/sys/kernel/printk_devkmsg";
        int fd;
        ssize_t n;
        status.write_error = put(path, "on\n");
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
                status.read_error = -errno;
                return status;
        }
        n = read(fd, status.value, sizeof(status.value) - 1);
        status.read_error = n < 0 ? -errno : (n ? 0 : -EIO);
        close(fd);
        if (n > 0) {
                status.value[n] = 0;
                status.value[strcspn(status.value, "\n")] = 0;
        }
        return status;
}

static int mk(const char *path)
{
        if (mkdir(path, 0755) && errno != EEXIST)
                return -errno;
        return 0;
}

/* ------------------------------------------------------------------ USB -- */
struct usb_result {
        const char *stage;
        const char *operation;
        int error;
        char udc[256];
};

static int usb_fail(struct usb_result *result, const char *stage,
                    const char *operation, int error)
{
        result->stage = stage;
        result->operation = operation;
        result->error = error;
        return error;
}

static void usb_begin(int trace, const char *operation)
{
        if (trace)
                announce("USB begin op=%s", operation);
}

static void usb_report(const struct usb_result *result,
                       struct usb_result *previous, int *valid)
{
        if (!*valid || result->error != previous->error ||
            strcmp(result->stage, previous->stage) ||
            strcmp(result->operation, previous->operation) ||
            strcmp(result->udc, previous->udc)) {
                announce("USB result stage=%s op=%s errno=%d (%s) udc=%s",
                         result->stage, result->operation, -result->error,
                         result->error ? strerror(-result->error) : "success",
                         result->udc[0] ? result->udc : "none-enumerated");
                *previous = *result;
                *valid = 1;
        }
}

static int gadget(struct usb_result *result, int config_error, int trace)
{
        const char *base = "/sys/kernel/config/usb_gadget/crownlte_diag";
        struct dirent *de;
        DIR *udcs;
        char name[256] = {0}, path[512];
        int error;
        memset(result, 0, sizeof(*result));
        if (config_error)
                return usb_fail(result, "configfs-mount-failed", "mount configfs", config_error);
        usb_begin(trace, "open /sys/class/udc");
        udcs = opendir("/sys/class/udc");
        if (!udcs)
                return usb_fail(result, "udc-directory-open-failed", "opendir /sys/class/udc", -errno);
        errno = 0;
        while ((de = readdir(udcs))) {
                if (de->d_name[0] != '.') {
                        snprintf(name, sizeof(name), "%s", de->d_name);
                        break;
                }
        }
        error = de ? 0 : -errno;
        closedir(udcs);
        if (error)
                return usb_fail(result, "udc-enumeration-failed", "readdir /sys/class/udc", error);
        if (!name[0])
                return usb_fail(result, "udc-enumeration-empty", "readdir /sys/class/udc", -ENODEV);
        snprintf(result->udc, sizeof(result->udc), "%s", name);
#define MAKE(dir) do { \
        usb_begin(trace, "mkdir " dir); \
        error = mk(dir); \
        if (error) return usb_fail(result, "configfs-directory-failed", "mkdir " dir, error); \
} while (0)
        MAKE("/sys/kernel/config/usb_gadget/crownlte_diag");
#define SET(attr, value) do { \
        usb_begin(trace, "write " attr); \
        snprintf(path, sizeof(path), "%s/%s", base, attr); \
        int err = put(path, value); \
        if (err) return usb_fail(result, "configfs-attribute-failed", "write " attr, err); \
} while (0)
        SET("idVendor", "0x1d6b");
        SET("idProduct", "0x0104");
        SET("bDeviceClass", "0x02");
        SET("bDeviceSubClass", "0");
        SET("bDeviceProtocol", "0");
        MAKE("/sys/kernel/config/usb_gadget/crownlte_diag/strings/0x409");
        SET("strings/0x409/serialnumber", "crownlte-source-diagnostic");
        SET("strings/0x409/manufacturer", "Kernel bring-up");
        SET("strings/0x409/product", "Note9 kernel diagnostic serial");
        MAKE("/sys/kernel/config/usb_gadget/crownlte_diag/configs/c.1");
        MAKE("/sys/kernel/config/usb_gadget/crownlte_diag/configs/c.1/strings/0x409");
        SET("configs/c.1/strings/0x409/configuration", "Read-only diagnostic logs");
        SET("configs/c.1/MaxPower", "100");
        MAKE("/sys/kernel/config/usb_gadget/crownlte_diag/functions/acm.usb0");
        usb_begin(trace, "link acm.usb0");
        if (symlink("/sys/kernel/config/usb_gadget/crownlte_diag/functions/acm.usb0",
                    "/sys/kernel/config/usb_gadget/crownlte_diag/configs/c.1/acm.usb0")
            && errno != EEXIST)
                return usb_fail(result, "configfs-link-failed", "symlink acm.usb0", -errno);
        usb_begin(trace, "bind UDC");
        snprintf(path, sizeof(path), "%s/UDC", base);
        error = put(path, name);
        if (error)
                return usb_fail(result, "udc-bind-failed", "write UDC", error);
#undef SET
#undef MAKE
        result->stage = "gadget-bound";
        result->operation = "write UDC";
        return 0;
}

static void report(const char *path)
{
        char buf[4096];
        int fd;
        ssize_t n;
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
                announce("read %s: %s", path, strerror(errno));
                return;
        }
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
                buf[n] = 0;
                announce("%s:\n%s", path, buf);
        }
}

static size_t remember(const char *s, size_t n)
{
        size_t discarded = 0;
        if (n > sizeof(history)) {
                s += n - sizeof(history);
                n = sizeof(history);
        }
        if (history_len + n > sizeof(history)) {
                size_t discard = history_len + n - sizeof(history);
                memmove(history, history + discard, history_len - discard);
                history_len -= discard;
                discarded = discard;
        }
        memcpy(history + history_len, s, n);
        history_len += n;
        return discarded;
}

static int serial_open(int trace)
{
        struct termios tio;
        usb_begin(trace, "open /dev/ttyGS0");
        int fd = open("/dev/ttyGS0", O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0)
                return -1;
        if (!tcgetattr(fd, &tio)) {
                cfmakeraw(&tio);
                tio.c_cflag |= CLOCAL | CREAD;
                tcsetattr(fd, TCSANOW, &tio);
        }
        return fd;
}

/* ---------------------------------------------------------- deadline ----- */
static unsigned long long elapsed_ms(const struct timespec *start)
{
        struct timespec now;
        long long ms;
        if (clock_gettime(CLOCK_MONOTONIC, &now))
                return 0;
        ms = (long long)(now.tv_sec - start->tv_sec) * 1000LL +
             (long long)(now.tv_nsec - start->tv_nsec) / 1000000LL;
        return ms < 0 ? 0 : (unsigned long long)ms;
}

static int deadline_reached(const struct timespec *start)
{
        struct timespec now;
        time_t seconds;
        long nanoseconds;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) {
                deadline_sample_valid = 0;
                return 2;
        }
        if (now.tv_sec < start->tv_sec ||
            (now.tv_sec == start->tv_sec && now.tv_nsec < start->tv_nsec)) {
                deadline_sample_valid = 0;
                return 3;
        }
        seconds = now.tv_sec - start->tv_sec;
        nanoseconds = now.tv_nsec - start->tv_nsec;
        if (nanoseconds < 0) {
                seconds--;
                nanoseconds += 1000000000;
        }
        deadline_sample_elapsed_ms = (unsigned long long)seconds * 1000 +
                                     nanoseconds / 1000000;
        deadline_sample_valid = 1;
        return now.tv_sec - start->tv_sec > (time_t)deadline_seconds ||
               (now.tv_sec - start->tv_sec == (time_t)deadline_seconds &&
                now.tv_nsec >= start->tv_nsec);
}

/* Unchanged ownership model: only this child calls reboot after fork succeeds.
 * Tick bound is a second, clock-independent limit (deadline + 30 s of ticks). */
enum deadline_event_kind { TIMER_STARTED = 1, TIMER_RESTART, TIMER_RETURNED };
enum deadline_reason { TIMER_EXPIRED = 1, TIMER_CLOCK_ERROR, TIMER_BACKWARDS,
                       TIMER_TICK_BOUND, TIMER_SLEEP_ERROR, TIMER_INITIAL_CLOCK_ERROR };
struct deadline_event {
        int kind, reason, error, sample_valid;
        unsigned long long elapsed_ms;
};
_Static_assert(sizeof(struct deadline_event) <= PIPE_BUF, "timer event must fit atomic pipe write");
static void timer_event(int fd, int kind, int reason, int error)
{
        const struct deadline_event event = {
                .kind = kind, .reason = reason, .error = error,
                .sample_valid = deadline_sample_valid,
                .elapsed_ms = deadline_sample_elapsed_ms,
        };
        ssize_t written = write(fd, &event, sizeof(event));
        if (written != (ssize_t)sizeof(event))
                return;
}

static void timer_child(int fd, const struct timespec *start, int clock_failed)
{
        const struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000 };
        const unsigned int max_ticks = (deadline_seconds + 30) * 10;
        unsigned int ticks = 0;
        int reason = 0, error = 0, sample;
        close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
        timer_event(fd, TIMER_STARTED, 0, 0);
        for (;;) {
                if (clock_failed) {
                        error = clock_failed;
                        reason = TIMER_INITIAL_CLOCK_ERROR;
                        break;
                }
                sample = deadline_reached(start);
                error = sample == 2 ? errno : 0;
                if (sample) {
                        reason = sample == 2 ? TIMER_CLOCK_ERROR :
                                 sample == 3 ? TIMER_BACKWARDS : TIMER_EXPIRED;
                        break;
                }
                if (ticks >= max_ticks) {
                        reason = TIMER_TICK_BOUND;
                        break;
                }
                if (nanosleep(&delay, NULL)) {
                        error = errno;
                        reason = TIMER_SLEEP_ERROR;
                        break;
                }
                ticks++;
        }
        timer_event(fd, TIMER_RESTART, reason, error);
        /* Default reboot only; no sync, no recovery command. */
        int result = reboot(RB_AUTOBOOT);
        error = result ? errno : 0;
        timer_event(fd, TIMER_RETURNED, reason, error);
        close(fd);
        int logfd = open("/dev/kmsg", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
        if (logfd >= 0) {
                char text[256];
                int n = snprintf(text, sizeof(text),
                        "<3>crownlte-diag: independent timer restart returned result=%d errno=%d reason=%d elapsed_ms=%llu clock_sample_valid=%d; physical fallback required\n",
                        result, error, reason, deadline_sample_elapsed_ms,
                        deadline_sample_valid);
                if (n > 0 && (size_t)n < sizeof(text)) {
                        ssize_t written = write(logfd, text, n);
                        (void)written;
                }
                close(logfd);
        }
        _exit(0);
}

static pid_t timer_start(int *reader, const struct timespec *start, int clock_failed)
{
        int pipefd[2];
        struct sigaction ignore = { .sa_handler = SIG_IGN };
        pid_t child;
        sigemptyset(&ignore.sa_mask);
        if (sigaction(SIGPIPE, &ignore, NULL))
                return -1;
        if (pipe2(pipefd, O_NONBLOCK | O_CLOEXEC))
                return -1;
        for (int i = 0; i < 2; i++) {
                if (pipefd[i] >= 3)
                        continue;
                int promoted = fcntl(pipefd[i], F_DUPFD_CLOEXEC, 3);
                if (promoted < 0) {
                        int error = errno;
                        close(pipefd[0]); close(pipefd[1]);
                        errno = error;
                        return -1;
                }
                close(pipefd[i]);
                pipefd[i] = promoted;
        }
        child = fork();
        if (child < 0) {
                int error = errno;
                close(pipefd[0]); close(pipefd[1]);
                errno = error;
                return -1;
        }
        if (!child) {
                close(pipefd[0]);
                timer_child(pipefd[1], start, clock_failed);
                _exit(1);
        }
        close(pipefd[1]);
        *reader = pipefd[0];
        return child;
}

static void timer_report(int reader, pid_t child, int *reaped)
{
        struct deadline_event event;
        for (int i = 0; i < 8; i++) {
                ssize_t n = read(reader, &event, sizeof(event));
                if (n != (ssize_t)sizeof(event))
                        break;
                announce("independent timer event=%d reason=%d errno=%d elapsed_ms=%llu clock_sample_valid=%d",
                         event.kind, event.reason, event.error,
                         event.elapsed_ms, event.sample_valid);
                if (event.kind == TIMER_RESTART)
                        announce("diagnostic deadline reached; independent child requesting default restart; physical fallback may be required");
                if (event.kind == TIMER_RETURNED)
                        announce("independent restart syscall returned errno=%d; use physical fallback", event.error);
        }
        if (!*reaped) {
                int status;
                pid_t result = waitpid(child, &status, WNOHANG);
                if (result == child) {
                        *reaped = 1;
                        announce("independent timer child reaped status=%d; no second restart attempt will be made; physical fallback required", status);
                } else if (result < 0 && errno == ECHILD) {
                        *reaped = 1;
                        announce("independent timer child cannot be waited for errno=%d; physical fallback required", ECHILD);
                } else if (result < 0 && errno != EINTR) {
                        int error = errno;
                        if (error != timer_wait_previous_error)
                                announce("independent timer waitpid failed errno=%d; child ownership unchanged", error);
                        timer_wait_previous_error = error;
                } else if (result >= 0) {
                        timer_wait_previous_error = 0;
                }
        }
}

static void timer_start_failed(int error)
{
        int result = reboot(RB_AUTOBOOT);
        int reboot_error = result ? errno : 0;
        announce("independent timer creation failed errno=%d; immediate default restart returned result=%d errno=%d; physical fallback required",
                 error, result, reboot_error);
        for (;;) pause();
}

/* --------------------------------------------------------- handshake ----- */
/* Only these exact frames are accepted, in this order. Input is never a
 * command language. Any other byte disables UFS and ROM stages for the boot. */
#define UFS_READY "CROWNLTE-UFS-READY-1\n"
#define UFS_PROBE "CROWNLTE-UFS-PROBE-1\n"
#define ROM_START "CROWNLTE-ROMRAM-START-1\n"
#define UFS_SNAPSHOT "UFS readiness snapshot complete; probe remains held"
struct ufs_handshake {
        int ready, failed, requested, attempted, start_requested, input_done;
        int snapshot_announced, snapshot_seen, snapshot_sent;
        size_t snapshot_end, line_len;
        char line[64];
        pid_t child;
        int reaped, wait_error, probe_status_ok;
};

static void ufs_fail(struct ufs_handshake *state, const char *reason, int error)
{
        if (!state->failed) {
                state->failed = 1;
                announce("UFS/ROM stage disabled reason=%s errno=%d; no retry", reason, error);
        }
}

static void ufs_input(struct ufs_handshake *state, const char *input, size_t n)
{
        if (state->failed || state->input_done)
                return;
        for (size_t i = 0; i < n; i++) {
                const char *expected = !state->ready ? UFS_READY :
                                       !state->requested ? UFS_PROBE : ROM_START;
                if (state->line_len >= sizeof(state->line) - 1 ||
                    state->line_len >= strlen(expected) ||
                    input[i] != expected[state->line_len]) {
                        ufs_fail(state, "invalid-frame", EPROTO);
                        return;
                }
                state->line[state->line_len++] = input[i];
                if (input[i] != '\n')
                        continue;
                state->line_len = 0;
                if (!state->ready) {
                        state->ready = 1;
                        announce("UFS host ready; cached log forwarding enabled");
                } else if (!state->requested) {
                        if (!state->snapshot_sent) {
                                ufs_fail(state, "probe-before-snapshot-sent", EPROTO);
                                return;
                        }
                        state->requested = 1;
                        announce("UFS probe frame accepted; read-only guarded probe will start");
                } else {
                        state->start_requested = 1;
                        state->input_done = 1;
                        announce("ROMRAM start frame accepted; ROM stage starts after UFS probe child exits 0");
                        return; /* further input is ignored */
                }
        }
}

static void ufs_input_poll(struct ufs_handshake *state, int serial)
{
        char input[64];
        ssize_t n;
        if (serial < 0 || state->failed || state->input_done)
                return;
        n = read(serial, input, sizeof(input));
        if (n > 0)
                ufs_input(state, input, n);
        else if (n < 0 && errno != EAGAIN && errno != EINTR)
                ufs_fail(state, "serial-read", errno);
        else if (!n && state->ready)
                ufs_fail(state, "serial-eof-after-ready", EPIPE);
}

static void ufs_close_inherited(int serial, int reader, int timer_reader)
{
        const int fds[] = { serial, reader, timer_reader, kmsg, 0, 1, 2 };
        for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
                int duplicate = 0;
                if (fds[i] < 0)
                        continue;
                for (size_t j = 0; j < i; j++)
                        if (fds[j] == fds[i])
                                duplicate = 1;
                if (!duplicate)
                        close(fds[i]);
        }
        kmsg = -1;
}

static int ufs_probe_child(int serial, int reader, int timer_reader)
{
        int error;
        ufs_close_inherited(serial, reader, timer_reader);
        kmsg = open("/dev/kmsg", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
        if (kmsg < 0)
                return 1;
        if (announce("UFS probe gate begin path=/sys/module/ufs_exynos9810/parameters/diagnostic_probe value=1"))
                return 1;
        error = put("/sys/module/ufs_exynos9810/parameters/diagnostic_probe", "1\n");
        if (announce("UFS probe gate end errno=%d", -error) || error)
                return 1;
        if (announce("UFS probe bind begin path=/sys/bus/platform/drivers/exynos9810-ufs/bind device=11120000.ufs"))
                return 1;
        error = put("/sys/bus/platform/drivers/exynos9810-ufs/bind", "11120000.ufs\n");
        if (announce("UFS probe bind end errno=%d", -error) || error)
                return 1;
        return 0;
}

static void ufs_start_probe(struct ufs_handshake *state, int serial, int reader,
                            int timer_reader)
{
        if (state->failed || state->attempted || !state->requested)
                return;
        state->attempted = 1;
        state->child = fork();
        if (state->child < 0) {
                ufs_fail(state, "fork", errno);
                return;
        }
        if (!state->child) {
                int result = ufs_probe_child(serial, reader, timer_reader);
                if (kmsg >= 0)
                        close(kmsg);
                _exit(result);
        }
        announce("UFS probe child pid=%ld; independent timer retains sole restart ownership",
                 (long)state->child);
}

static void ufs_reap_probe(struct ufs_handshake *state)
{
        int status;
        pid_t result;
        if (state->child <= 0 || state->reaped)
                return;
        result = waitpid(state->child, &status, WNOHANG);
        if (result == state->child) {
                state->reaped = 1;
                state->probe_status_ok = WIFEXITED(status) && !WEXITSTATUS(status);
                announce("UFS probe child reaped status=%d ok=%d; no retry", status,
                         state->probe_status_ok);
        } else if (result < 0 && errno == ECHILD) {
                state->reaped = 1;
                announce("UFS probe child unavailable errno=%d; no retry", ECHILD);
        } else if (result < 0 && errno != EINTR) {
                int error = errno;
                if (state->wait_error != error)
                        announce("UFS probe wait errno=%d; no retry", error);
                state->wait_error = error;
        }
}

static int mount_virtual(const char *type, const char *path,
                         unsigned long flags, const char *options)
{
        if (mount(type, path, type, flags, options))
                return -errno;
        return 0;
}

/* ------------------------------------------------- ROM stage container -- */
#include "romram-sha256.h"
#include "romram.h"

struct container {
        pid_t pid;
        int started, reaped, killed, wait_error;
        unsigned long long start_ms;
};

static void container_spawn(struct container *c, struct ufs_handshake *ufs,
                            const struct timespec *start)
{
        static char stack_area[1024 * 1024] __attribute__((aligned(16)));
        unsigned long long now = elapsed_ms(start);
        if (c->started || ufs->failed || !ufs->start_requested || !ufs->reaped)
                return;
        c->started = 1; /* exactly one attempt, success or not */
        if (!ufs->probe_status_ok) {
                announce("ROMRAM not started: UFS probe child did not exit 0; no retry");
                return;
        }
        if (now + (unsigned long long)START_LATEST_MARGIN * 1000ULL >
            (unsigned long long)deadline_seconds * 1000ULL) {
                announce("ROMRAM not started: only %llu ms left before restart (need >= %d s)",
                         (unsigned long long)deadline_seconds * 1000ULL - now, START_LATEST_MARGIN);
                return;
        }
        c->pid = clone(romram_child, stack_area + sizeof(stack_area),
                       CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | SIGCHLD, NULL);
        if (c->pid < 0) {
                announce("ROMRAM clone failed errno=%d; no retry", errno);
                return;
        }
        c->start_ms = now;
        announce("ROMRAM container outer_pid=%ld started at %llu ms; SIGKILL at %u s; restart at %u s",
                 (long)c->pid, now, deadline_seconds - CONTAINER_MARGIN, deadline_seconds);
}

static void container_poll(struct container *c, const struct timespec *start)
{
        int status;
        pid_t result;
        if (!c->started || c->pid <= 0 || c->reaped)
                return;
        result = waitpid(c->pid, &status, WNOHANG);
        if (result == c->pid) {
                c->reaped = 1;
                announce("ROMRAM container reaped outer_pid=%ld status=0x%x exited=%d code=%d signaled=%d signal=%d after %llu ms; namespace gone; no retry",
                         (long)c->pid, status, WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                         WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : -1,
                         elapsed_ms(start) - c->start_ms);
                return;
        }
        if (result < 0 && errno == ECHILD) {
                c->reaped = 1;
                announce("ROMRAM container unavailable errno=ECHILD");
                return;
        }
        if (!c->killed && elapsed_ms(start) >=
            (unsigned long long)(deadline_seconds - CONTAINER_MARGIN) * 1000ULL) {
                c->killed = 1;
                int error = kill(c->pid, SIGKILL) ? errno : 0;
                announce("ROMRAM deadline teardown outer_pid=%ld SIGKILL errno=%d (kills whole PID namespace)",
                         (long)c->pid, error);
        }
}

/* Forward text files the container writes into its RAM /dev/crownlte. */
struct forward {
        const char *name;
        char prefix;
        off_t offset;
        size_t partial_len;
        char partial[2048];
        int last_error;
};

static void forward_line(struct forward *f, const char *s, size_t n)
{
        char line[2200];
        if (n > sizeof(line) - 4)
                n = sizeof(line) - 4;
        line[0] = f->prefix;
        line[1] = ';';
        memcpy(line + 2, s, n);
        line[2 + n] = '\n';
        remember(line, n + 3);
}

static void forward_poll(struct forward *f, pid_t pid)
{
        char path[128], buf[65536];
        struct stat st;
        int fd;
        ssize_t n;
        snprintf(path, sizeof(path), "/proc/%ld/root/dev/crownlte/%s", (long)pid, f->name);
        fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
                if (errno != f->last_error && errno != ENOENT)
                        announce("forward %s open errno=%d", f->name, errno);
                f->last_error = errno;
                return;
        }
        f->last_error = 0;
        if (!fstat(fd, &st) && st.st_size < f->offset) {
                announce("forward %s shrank (%lld < %lld); restarting at 0", f->name,
                         (long long)st.st_size, (long long)f->offset);
                f->offset = 0;
                f->partial_len = 0;
        }
        n = pread(fd, buf, sizeof(buf), f->offset);
        close(fd);
        if (n <= 0)
                return;
        f->offset += n;
        for (ssize_t i = 0; i < n; i++) {
                if (buf[i] == '\n' || f->partial_len == sizeof(f->partial)) {
                        forward_line(f, f->partial, f->partial_len);
                        f->partial_len = 0;
                        if (buf[i] == '\n')
                                continue;
                }
                f->partial[f->partial_len++] = buf[i];
        }
}

/* ------------------------------------------------------------- main ----- */
int main(void)
{
        int console, console_error = 0, reader, serial = -1, bound = 0, uname_valid;
        int mount_errors[3], directory_errors[3], config_error;
        struct devkmsg_status devkmsg;
        int usb_previous_valid = 0, serial_previous_error = 0;
        int serial_write_previous_error = 0;
        struct usb_result usb_state = { .stage = "not-attempted", .operation = "none" };
        struct usb_result usb_previous;
        const char *mount_paths[] = { "/proc", "/sys", "/dev" };
        struct timespec start = {0};
        int timer_reader = -1, timer_reaped = 0;
        pid_t timer_pid;
        int clock_failed;
        unsigned long long last_gadget = 0, last_alive = 0, last_devkmsg = 0, last_forward = 0;
        int first = 1;
        size_t sent = 0;
        unsigned long long dropped_total = 0, kmsg_lost = 0;
        char record[8192];
        struct utsname uts;
        struct container box = {0};
        struct forward fwd[2] = {
                { .name = "logcat.txt", .prefix = 'L' },
                { .name = "probe.txt", .prefix = 'P' },
        };

        load_deadline();
        clock_failed = clock_gettime(CLOCK_MONOTONIC, &start) ? errno : 0;
        deadline_sample_elapsed_ms = 0;
        deadline_sample_valid = !clock_failed;
        /* Fork before mounts, console output, proc reads or configfs setup. */
        timer_pid = timer_start(&timer_reader, &start, clock_failed);
        if (timer_pid < 0)
                timer_start_failed(errno);
        struct ufs_handshake ufs = {0};
        directory_errors[0] = mk("/proc");
        directory_errors[1] = mk("/sys");
        directory_errors[2] = mk("/dev");
        mount_errors[0] = mount_virtual("proc", "/proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
        devkmsg = enable_devkmsg();
        mount_errors[1] = mount_virtual("sysfs", "/sys", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
        mount_errors[2] = mount_virtual("devtmpfs", "/dev", MS_NOSUID, "mode=0755");
        console = open("/dev/console", O_RDWR | O_NOCTTY);
        console_error = console < 0 ? errno : 0;
        if (console >= 0) {
                dup2(console, 0); dup2(console, 1); dup2(console, 2);
                if (console > 2) close(console);
        } else {
                /*
                 * v4 kernel has CONFIG_VT=n (as 4.9): no console tty, so the
                 * kernel could not hand PID1 fds 0-2 either. Pin them to
                 * /dev/null before kmsg/serial are opened, so no later fd
                 * becomes stdio (announce() copies every line to fd 2).
                 */
                int null = open("/dev/null", O_RDWR | O_NOCTTY);
                if (null >= 0) {
                        for (int fd = 0; fd < 3; fd++)
                                if (fd != null && fcntl(fd, F_GETFD) < 0)
                                        dup2(null, fd);
                        if (null > 2) close(null);
                }
        }
        kmsg = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
        if (console < 0)
                announce("no /dev/console (errno=%d, kernel without VT); stdio pinned to /dev/null fd0=%d fd1=%d fd2=%d",
                         console_error, fcntl(0, F_GETFD) >= 0, fcntl(1, F_GETFD) >= 0,
                         fcntl(2, F_GETFD) >= 0);
        announce("printk_devkmsg write_errno=%d read_errno=%d mode=%s unlimited_confirmed=%d",
                 -devkmsg.write_error, -devkmsg.read_error,
                 devkmsg.read_error ? "unavailable" : devkmsg.value,
                 !devkmsg.write_error && !devkmsg.read_error &&
                 !strcmp(devkmsg.value, "on"));
        for (int i = 0; i < 3; i++) {
                if (directory_errors[i])
                        announce("mkdir %s: %s", mount_paths[i], strerror(-directory_errors[i]));
                if (mount_errors[i])
                        announce("mount %s: %s", mount_paths[i], strerror(-mount_errors[i]));
        }
        announce("ROMRAM PID1 running; UFS first probe held for host handshake; PID1 never opens block devices");
        announce("independent child pid=%ld owns the sole default restart attempt", (long)timer_pid);
        announce("default restart planned after %us (source=%d: 1 file, 0 default, <0 file error); container SIGKILL at %us; this message is not a restart attempt",
                 deadline_seconds, deadline_source, deadline_seconds - CONTAINER_MARGIN);
        announce("frames: %s then (after snapshot) %s then %s",
                 "CROWNLTE-UFS-READY-1", "CROWNLTE-UFS-PROBE-1", "CROWNLTE-ROMRAM-START-1");
        uname_valid = uname(&uts) == 0;
        if (uname_valid)
                announce("kernel %s %s %s", uts.release, uts.version, uts.machine);
        report("/proc/cmdline"); report("/proc/meminfo");
        report("/crownlte/payload-id");
        config_error = mk("/sys/kernel/config");
        if (config_error)
                announce("mkdir /sys/kernel/config: %s", strerror(-config_error));
        config_error = mount_virtual("configfs", "/sys/kernel/config",
                                     MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
        if (config_error)
                announce("mount /sys/kernel/config: %s", strerror(-config_error));
        reader = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (reader < 0)
                announce("kernel log reader: %s", strerror(errno));
        if (reader < 0 || kmsg < 0 || devkmsg.write_error || devkmsg.read_error ||
            strcmp(devkmsg.value, "on"))
                ufs_fail(&ufs, "logging-unavailable", ENODEV);
        for (;;) {
                ssize_t n;
                unsigned long long now = elapsed_ms(&start);
                if (!clock_failed)
                        (void)deadline_reached(&start);
                timer_report(timer_reader, timer_pid, &timer_reaped);
                if (!bound && (first || now - last_gadget >= 1000)) {
                        last_gadget = now;
                        bound = gadget(&usb_state, config_error, first) == 0;
                        usb_report(&usb_state, &usb_previous, &usb_previous_valid);
                }
                if (serial < 0 && bound && (first || now - last_gadget >= 1000)) {
                        last_gadget = now;
                        serial = serial_open(first);
                        int error = serial < 0 ? errno : 0;
                        if (error != serial_previous_error || (!error && first))
                                announce("serial open errno=%d (%s)", error,
                                         error ? strerror(error) : "success");
                        serial_previous_error = error;
                        sent = 0;
                }
                ufs_input_poll(&ufs, serial);
                /* Drain the 128 KiB printk ring fast; Lineage init is chatty. */
                for (int i = 0; i < 4096 && reader >= 0; i++) {
                        n = read(reader, record, sizeof(record));
                        if (n > 0) {
                                size_t dropped = remember(record, n);
                                dropped_total += dropped;
                                sent = sent > dropped ? sent - dropped : 0;
                                if (dropped && !ufs.attempted)
                                        ufs_fail(&ufs, "history-drop", ENOBUFS);
                                if (ufs.snapshot_announced && !ufs.snapshot_seen &&
                                    memmem(record, n, UFS_SNAPSHOT, strlen(UFS_SNAPSHOT))) {
                                        ufs.snapshot_seen = 1;
                                        ufs.snapshot_end = history_len;
                                }
                        } else if (n < 0 && errno == EPIPE) {
                                kmsg_lost++;
                                if (!ufs.attempted)
                                        ufs_fail(&ufs, "kernel-log-loss", EPIPE);
                                continue;
                        } else if (n < 0 && errno == EAGAIN) {
                                if (!ufs.snapshot_announced) {
                                        ufs.snapshot_announced = 1;
                                        if (announce(UFS_SNAPSHOT))
                                                ufs_fail(&ufs, "snapshot-log-write", EIO);
                                }
                                break;
                        } else if ((n >= 0 || errno != EINTR) && !ufs.attempted) {
                                ufs_fail(&ufs, "kernel-log-read", n < 0 ? errno : EIO);
                                break;
                        } else
                                break;
                }
                if (box.started && box.pid > 0 && !box.reaped && now - last_forward >= 200) {
                        last_forward = now;
                        for (int i = 0; i < 2; i++)
                                forward_poll(&fwd[i], box.pid);
                }
                if (serial >= 0 && ufs.ready) {
                        for (int i = 0; i < 64 && sent < history_len; i++) {
                                n = write(serial, history + sent, history_len - sent);
                                if (n > 0) {
                                        sent += n;
                                        serial_write_previous_error = 0;
                                        if (ufs.snapshot_seen && sent >= ufs.snapshot_end)
                                                ufs.snapshot_sent = 1;
                                        continue;
                                }
                                if (n < 0 && errno != EAGAIN && errno != EINTR) {
                                        int error = errno;
                                        if (error != serial_write_previous_error)
                                                announce("serial write errno=%d (%s); closing serial endpoint",
                                                         error, strerror(error));
                                        serial_write_previous_error = error;
                                        if (!ufs.attempted)
                                                ufs_fail(&ufs, "serial-write", error);
                                        close(serial); serial = -1;
                                }
                                break;
                        }
                }
                /* After the probe stage the snapshot offsets are no longer
                 * used: drop bytes the host already received so the cache
                 * only ever discards unsent data, and rarely memmoves. */
                if (ufs.attempted && sent >= 1024 * 1024) {
                        memmove(history, history + sent, history_len - sent);
                        history_len -= sent;
                        sent = 0;
                }
                ufs_start_probe(&ufs, serial, reader, timer_reader);
                ufs_reap_probe(&ufs);
                container_spawn(&box, &ufs, &start);
                container_poll(&box, &start);
                if (now - last_devkmsg >= 5000) {
                        last_devkmsg = now;
                        char value[16] = {0};
                        int fd = open("/proc/sys/kernel/printk_devkmsg", O_RDONLY | O_CLOEXEC);
                        if (fd >= 0) {
                                ssize_t r = read(fd, value, sizeof(value) - 1);
                                close(fd);
                                if (r > 0 && strncmp(value, "on", 2)) {
                                        int error = put("/proc/sys/kernel/printk_devkmsg", "on\n");
                                        announce("printk_devkmsg was %.*s; rewrite on errno=%d",
                                                 (int)strcspn(value, "\n"), value, -error);
                                }
                        }
                }
                if (first || now - last_alive >= 15000) {
                        last_alive = now;
                        announce("alive elapsed_ms=%llu deadline_s=%u USB stage=%s errno=%d udc=%s ready=%d probe_req=%d probe_ok=%d start_req=%d container=%ld reaped=%d killed=%d cache=%zu sent=%zu cache_dropped=%llu kmsg_lost=%llu kernel=%s",
                                 now, deadline_seconds, usb_state.stage, -usb_state.error,
                                 usb_state.udc[0] ? usb_state.udc : "none", ufs.ready,
                                 ufs.requested, ufs.probe_status_ok, ufs.start_requested,
                                 (long)box.pid, box.reaped, box.killed, history_len, sent,
                                 dropped_total, kmsg_lost,
                                 uname_valid ? uts.release : "unavailable");
                }
                first = 0;
                {
                        /* Short sleep while a backlog exists, else 50 ms. */
                        int backlog = serial >= 0 && ufs.ready && sent < history_len;
                        const struct timespec delay = { .tv_sec = 0,
                                .tv_nsec = backlog ? 2000000 : 50000000 };
                        nanosleep(&delay, NULL);
                }
        }
}
