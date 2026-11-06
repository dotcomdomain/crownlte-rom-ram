/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <grp.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
/* MobiCore admin: GET_REQUEST, GET_INFO and LOAD_TOKEN only. Refuse every
 * driver-load/check ioctl even if the vendor binary changes its startup flow.
 * The user-session node is independently hidden with a RO regular-file bind. */
/* Full encodings, checked against the 6.12 driver's public mc_admin.h/mc_user.h:
 * GET_DRIVER_REQUEST _IOR('M',0,32)=0x80204d00, GET_INFO _IOR('M',1,8)=0x80084d01,
 * LOAD_TOKEN _IOW('M',3,24)=0x40184d03. Refused: LOAD_DRIVER 0x40184d02,
 * LOAD_CHECK 0x40184d04, OPEN_SESSION 0xc0404d00, OPEN_TRUSTLET 0xc0284d01. */
#define T2_MC_GET_DRIVER_REQUEST 0x80204d00u
#define T2_MC_GET_INFO           0x80084d01u
#define T2_MC_LOAD_TOKEN         0x40184d03u
/* T2 v2, user node (daemon only): MC_IO_VERSION _IOR('M',9,96)=0x80604d09 and
 * MC_IO_HAS_SESSIONS _IO('M',8)=0x4d08 are read-only. Still refused: OPEN_SESSION,
 * OPEN_TRUSTLET, CLOSE 0x4d02, NOTIFY 0x4d03, WAIT 0x400c4d04, MAP 0xc0284d05,
 * UNMAP, ERR 0xc0084d07 and all GP_* (20+). */
#define T2_MC_USER_VERSION       0x80604d09u
#define T2_MC_USER_HAS_SESSIONS  0x00004d08u
/* T2 v3: session plumbing on the user node, gated by the KERNEL session guard
 * (DT samsung,tee-session-guard, crownlte-tee-3): OPEN_SESSION 0xc0404d00 reaches
 * the guard, which logs the UUID and refuses unless allow-listed. CLOSE, NOTIFY,
 * WAIT, MAP, UNMAP and ERR only act on sessions/buffers the guard let through.
 * Still refused here: OPEN_TRUSTLET 0xc0284d01 (TA from a buffer), LOAD_DRIVER,
 * LOAD_CHECK and every GP_* (0x40084d14 ...). */
#define T2_MC_USER_OPEN_SESSION  0xc0404d00u
#define T2_MC_USER_CLOSE         0x00004d02u
#define T2_MC_USER_NOTIFY        0x00004d03u
#define T2_MC_USER_WAIT          0x400c4d04u
#define T2_MC_USER_MAP           0xc0284d05u
#define T2_MC_USER_UNMAP         0x40284d06u
#define T2_MC_USER_ERR           0xc0084d07u
static int restrict_tee(void)
{
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_ioctl, 0, 15),
        /* ioctl cmd is an unsigned int: the low 32 bits of args[1] (LE). */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, T2_MC_GET_DRIVER_REQUEST, 13, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, T2_MC_GET_INFO, 12, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, T2_MC_LOAD_TOKEN, 11, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, T2_MC_USER_VERSION, 10, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, T2_MC_USER_HAS_SESSIONS, 9, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, T2_MC_USER_OPEN_SESSION, 8, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, T2_MC_USER_CLOSE, 7, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, T2_MC_USER_NOTIFY, 6, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, T2_MC_USER_WAIT, 5, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, T2_MC_USER_MAP, 4, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, T2_MC_USER_UNMAP, 3, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, T2_MC_USER_ERR, 2, 0),
        /* Every other 'M' ioctl (LOAD_DRIVER, LOAD_CHECK, OPEN_SESSION,
         * OPEN_TRUSTLET, ...) is refused, whatever its size/direction bits. */
        BPF_STMT(BPF_ALU+BPF_AND+BPF_K, 0xff00),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x4d00, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPERM),
    };
    struct sock_fprog program = {sizeof(code)/sizeof(code[0]), code};
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}
/* T2 v2: the daemon must open the user node (T2e: "Permission denied opening user
 * device" -> exit). The container keeps its masked /dev/mobicore-user; only this
 * process tree gets a private mount namespace with the real node bound over the
 * mask. Opening/mmap of the node only create NWd client state; the seccomp filter
 * still refuses every session/trustlet/map/notify ioctl. */
static int t2_read_devt(const char *path, unsigned *ma, unsigned *mi)
{
    char b[32] = {0};
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t n;
    if (fd < 0) return -1;
    n = read(fd, b, sizeof(b) - 1);
    close(fd);
    return (n > 0 && sscanf(b, "%u:%u", ma, mi) == 2) ? 0 : -1;
}
static int private_user_node(void)
{
    char g[4] = {0};
    int gfd = open("/sys/module/mcDrvModule/parameters/session_guard", O_RDONLY | O_CLOEXEC);
    if (gfd < 0 || read(gfd, g, sizeof(g) - 1) < 1 || g[0] != 'Y') {
        if (gfd >= 0) close(gfd);
        fprintf(stderr, "T2 FAIL kernel TEE session guard not active; daemon NOT started\n");
        return -1;
    }
    close(gfd);
    printf("T2 kernel TEE session guard: on\n");
    const char *dir = "/dev/crownlte/t2-node", *node = "/dev/crownlte/t2-node/mobicore-user";
    unsigned ama, ami, uma, umi;
    if (t2_read_devt("/sys/class/trustonic_tee/mobicore/dev", &ama, &ami) ||
        t2_read_devt("/sys/class/trustonic_tee/mobicore-user/dev", &uma, &umi) ||
        uma != ama || umi == ami) { fprintf(stderr, "T2 user node: bad devt\n"); return -1; }
    if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) return -1;
    if ((mkdir(dir, 0700) && errno != EEXIST) ||
        mount("tmpfs", dir, "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=0700,size=64k")) return -1;
    if (mknod(node, S_IFCHR | 0600, makedev(uma, umi)) || chown(node, 1000, 1000)) return -1;
    /* Drop the container's read-only mask in THIS namespace only, then bind the node. */
    if (umount2("/dev/mobicore-user", MNT_DETACH) ||
        mount(node, "/dev/mobicore-user", NULL, MS_BIND, NULL)) return -1;
    printf("T2 user node private to daemon: %u:%u\n", uma, umi);
    return 0;
}
int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    if (argc == 2 && !strcmp(argv[1], "daemon")) {
        /* No inherited root capabilities, no privileged exec, no supplementary groups. */
        if (private_user_node()) { perror("T2 private user node"); return 124; }
        if (setgroups(0, NULL) || setgid(1000) || setuid(1000) ||
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || restrict_tee()) return 125;
        setenv("MC_AUTH_TOKEN_PATH", "/efs", 1);
        /* Deliberately no -r preload: no opaque secure driver/TA until reviewed. */
        execl("/vendor/bin/mcDriverDaemon", "mcDriverDaemon", (char *)NULL);
        perror("T2 daemon exec"); return 127;
    }
    pid_t child = fork();
    if (child < 0) return 125;
    if (!child) {
        struct rlimit limit = {16*1024*1024, 16*1024*1024};
        if (setpgid(0, 0) || setrlimit(RLIMIT_FSIZE, &limit)) _exit(125);
        execl("/system/bin/strace", "strace", "-f", "-y", "-s", "0",
              "-e", "trace=file,ioctl,write,pwrite64,writev,fsync,close",
              "-o", "/dev/crownlte/tee-t2.strace",
              "/dev/crownlte/tee-t2-run", "daemon", (char *)NULL);
        _exit(127);
    }
    (void)setpgid(child, child);
    printf("T2 daemon start trace_pid=%d uid=1000 no-preload\n", child);
    int status = 0, bounded = 0, reaped = 0;
    time_t start = time(NULL);
    for (int i = 0; i < 450; i++) {
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child) { reaped = 1; break; }
        if (got < 0) break;
        struct stat st;
        if ((!stat("/dev/crownlte/tee-t2.strace", &st) && st.st_size >= 8*1024*1024) ||
            time(NULL) - start >= 450) { bounded = 1; break; }
        sleep(1);
    }
    /* Always reap/kill the entire trace group, including descendants on tracer failure. */
    kill(-child, SIGKILL);
    if (!reaped && waitpid(child, &status, 0) != child) return 125;
    if (WIFEXITED(status)) printf("T2 daemon exit status=%d bounded=%d (strace propagated status)\n", WEXITSTATUS(status), bounded);
    else if (WIFSIGNALED(status)) printf("T2 daemon exit signal=%d bounded=%d\n", WTERMSIG(status), bounded);
    return 0;
}
