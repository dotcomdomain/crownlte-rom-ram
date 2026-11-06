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
/* MobiCore admin: GET_REQUEST, GET_INFO and LOAD_TOKEN only. Refuse every
 * driver-load/check ioctl even if the vendor binary changes its startup flow.
 * The user-session node is independently hidden with a RO regular-file bind. */
static int restrict_tee(void)
{
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_ioctl, 0, 7),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_STMT(BPF_ALU+BPF_AND+BPF_K, 0xffff),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x4d00, 4, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x4d01, 3, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x4d03, 2, 0),
        BPF_STMT(BPF_ALU+BPF_AND+BPF_K, 0xff00),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x4d00, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO | EPERM),
    };
    struct sock_fprog program = {sizeof(code)/sizeof(code[0]), code};
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}
int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    if (argc == 2 && !strcmp(argv[1], "daemon")) {
        /* No inherited root capabilities, no privileged exec, no supplementary groups. */
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
        execl("/system/bin/strace", "strace", "-f", "-y", "-s", "128",
              "-e", "trace=file,ioctl,write,pwrite64,writev,fsync,close",
              "-e", "raw=write,pwrite64,writev", "-o", "/dev/crownlte/tee-t2.strace",
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
