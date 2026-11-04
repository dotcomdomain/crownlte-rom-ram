/* SPDX-License-Identifier: GPL-2.0 */
/*
 * crownlte ROM-in-RAM stage: the namespace child that plays first-stage init.
 *
 * Runs as PID 1 of a new PID + mount + UTS namespace created by the outer
 * diagnostic PID1, after the host sent CROWNLTE-ROMRAM-START-1 and the guarded
 * UFS probe returned 0. It:
 *   1. requires the UFS host to carry crownlte,read-only-diagnostic (SCSI
 *      command guard: every write/unmap/sync/security-out CDB is rejected in
 *      ufshcd_queuecommand before submission);
 *   2. sets BLKROSET on every UFS disk and partition (sd*), verifies BLKROGET;
 *   3. finds SYSTEM/VENDOR/ODM by GPT PARTNAME, checks their sizes, mounts them
 *      ext4 MS_RDONLY "noload" (no journal replay) as / , /vendor, /odm;
 *   4. verifies every init rc file Lineage init will parse against the payload
 *      manifest (sha256, size, symlink targets, no unknown files) and
 *      bind-mounts the sanitized copies (mount_all/swapon_all/init_user0
 *      disarmed, recovery flasher and misc writer removed) read-only on top;
 *   5. builds RAM-only /dev, /data, /cache, /mnt, /debug_ramdisk,
 *      /second_stage_resources; a fresh proc with a substituted /proc/cmdline
 *      (androidboot.* values) and a masked /proc/sysrq-trigger; a fresh sysfs
 *      with the UFS host, its driver bind/unbind, the UFS module parameters,
 *      the SCSI bus/classes, USB role/typec classes and /sys/power/{state,
 *      wakeup_count,mem_sleep,disk} hidden;
 *   6. switches root (MS_MOVE + chroot) and execs /system/bin/init
 *      selinux_setup exactly like first-stage init would.
 * Any failed check before exec exits non-zero; nothing is retried.
 * Inside the namespace, reboot(2) only kills the namespace (pid_ns reboot),
 * so Lineage init cannot reboot the phone; the outer timer owns the restart.
 */
#ifndef CROWNLTE_ROMRAM_H
#define CROWNLTE_ROMRAM_H
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define RR_MAX_ENTRIES 1024
#define RR_MAX_WALKS 16
#define RR_MAX_REPL 32
#define RR_PATH 512

struct rr_entry {
        char type;              /* F file, L symlink, D directory */
        char path[RR_PATH];
        char sha[65];
        unsigned long long size;
        char action[96];        /* keep | replace | empty */
        char repl[96];
        char target[RR_PATH];
        int visited;
};
struct rr_part { char name[16]; unsigned long long bytes; char mountpoint[64]; };
struct rr_repl { char name[64]; char sha[65]; unsigned long long size; };
struct rr_manifest {
        struct rr_part parts[3];
        int nparts;
        char walks[RR_MAX_WALKS][RR_PATH];
        int nwalks;
        struct rr_entry e[RR_MAX_ENTRIES];
        int n;
        struct rr_repl r[RR_MAX_REPL];
        int nrepl;
        unsigned files_hashed, replaced, emptied;
};

static void rr_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static int rr_sha_fd(int fd, char hex[65], unsigned long long *size)
{
        static char buf[65536];
        struct rom_sha s;
        ssize_t n;
        *size = 0;
        rom_sha_init(&s);
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
                rom_sha_update(&s, buf, (size_t)n);
                *size += (unsigned long long)n;
        }
        if (n < 0)
                return -errno;
        rom_sha_hex(&s, hex);
        return 0;
}

static int rr_parse(struct rr_manifest *m, const char *path)
{
        static char text[512 * 1024];
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        size_t used = 0;
        ssize_t n;
        char *line, *next;
        memset(m, 0, sizeof(*m));
        if (fd < 0)
                return -errno;
        while ((n = read(fd, text + used, sizeof(text) - 1 - used)) > 0)
                used += (size_t)n;
        close(fd);
        if (n < 0)
                return -EIO;
        if (used >= sizeof(text) - 1)
                return -EOVERFLOW;
        text[used] = 0;
        for (line = text; line && *line; line = next) {
                next = strchr(line, '\n');
                if (next)
                        *next++ = 0;
                if (!*line || *line == '#')
                        continue;
                if (line[0] == 'P') {
                        struct rr_part *p;
                        if (m->nparts >= 3) return -E2BIG;
                        p = &m->parts[m->nparts++];
                        if (sscanf(line, "P %15s %llu %63s", p->name, &p->bytes, p->mountpoint) != 3)
                                return -EINVAL;
                } else if (line[0] == 'W') {
                        if (m->nwalks >= RR_MAX_WALKS) return -E2BIG;
                        if (sscanf(line, "W %511s", m->walks[m->nwalks]) != 1) return -EINVAL;
                        m->nwalks++;
                } else if (line[0] == 'R') {
                        struct rr_repl *r;
                        if (m->nrepl >= RR_MAX_REPL) return -E2BIG;
                        r = &m->r[m->nrepl++];
                        if (sscanf(line, "R %64s %llu %63s", r->sha, &r->size, r->name) != 3)
                                return -EINVAL;
                } else if (line[0] == 'F' || line[0] == 'L' || line[0] == 'D' || line[0] == 'A') {
                        struct rr_entry *e;
                        if (m->n >= RR_MAX_ENTRIES) return -E2BIG;
                        e = &m->e[m->n++];
                        e->type = line[0];
                        if (e->type == 'D' || e->type == 'A') {
                                if (sscanf(line + 1, " %511s", e->path) != 1) return -EINVAL;
                        } else if (e->type == 'L') {
                                if (sscanf(line, "L %511s %511s", e->path, e->target) != 2) return -EINVAL;
                        } else {
                                char action[96];
                                if (sscanf(line, "F %64s %llu %95s %511s", e->sha, &e->size, action, e->path) != 4)
                                        return -EINVAL;
                                if (!strncmp(action, "replace:", 8)) {
                                        snprintf(e->action, sizeof(e->action), "replace");
                                        snprintf(e->repl, sizeof(e->repl), "%s", action + 8);
                                } else if (!strcmp(action, "keep") || !strcmp(action, "empty")) {
                                        snprintf(e->action, sizeof(e->action), "%s", action);
                                } else
                                        return -EINVAL;
                        }
                        if (e->path[0] != '/') return -EINVAL;
                } else
                        return -EINVAL;
        }
        return m->nparts == 3 && m->nwalks > 0 && m->n > 0 ? 0 : -EINVAL;
}

static struct rr_entry *rr_find(struct rr_manifest *m, const char *path)
{
        for (int i = 0; i < m->n; i++)
                if (!strcmp(m->e[i].path, path))
                        return &m->e[i];
        return NULL;
}

static int rr_check_file(struct rr_manifest *m, struct rr_entry *e, int fd)
{
        char hex[65];
        unsigned long long size;
        int error = rr_sha_fd(fd, hex, &size);
        if (error) {
                rr_log("verify read %s errno=%d", e->path, -error);
                return error;
        }
        m->files_hashed++;
        if (size != e->size || strcmp(hex, e->sha)) {
                rr_log("verify MISMATCH %s size=%llu sha=%s expected size=%llu sha=%s",
                       e->path, size, hex, e->size, e->sha);
                return -EBADMSG;
        }
        return 0;
}

/* Walk one directory without following symlinks; every entry must be known. */
static int rr_walk(struct rr_manifest *m, int dfd, const char *cpath, int depth)
{
        DIR *dir;
        struct dirent *de;
        int error = 0;
        if (depth > 8)
                return -ELOOP;
        dir = fdopendir(dfd);
        if (!dir) {
                error = -errno;
                close(dfd);
                return error;
        }
        while (!error && (de = readdir(dir))) {
                char child[RR_PATH];
                struct stat st;
                struct rr_entry *e;
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
                        continue;
                if ((size_t)snprintf(child, sizeof(child), "%s/%s", cpath, de->d_name) >= sizeof(child)) {
                        error = -ENAMETOOLONG;
                        break;
                }
                if (fstatat(dirfd(dir), de->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
                        error = -errno;
                        break;
                }
                e = rr_find(m, child);
                if (!e) {
                        rr_log("verify UNKNOWN entry %s mode=0%o", child, (unsigned)st.st_mode);
                        error = -ENOENT;
                        break;
                }
                if (e->visited) {
                        error = -EEXIST;
                        break;
                }
                e->visited = 1;
                if (S_ISDIR(st.st_mode) && e->type == 'D') {
                        int sub = openat(dirfd(dir), de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                        error = sub < 0 ? -errno : rr_walk(m, sub, child, depth + 1);
                } else if (S_ISLNK(st.st_mode) && e->type == 'L') {
                        char target[RR_PATH];
                        ssize_t n = readlinkat(dirfd(dir), de->d_name, target, sizeof(target) - 1);
                        if (n < 0)
                                error = -errno;
                        else {
                                target[n] = 0;
                                if (strcmp(target, e->target)) {
                                        rr_log("verify LINK MISMATCH %s -> %s expected %s", child, target, e->target);
                                        error = -EBADMSG;
                                }
                        }
                } else if (S_ISREG(st.st_mode) && e->type == 'F') {
                        int fd = openat(dirfd(dir), de->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                        if (fd < 0)
                                error = -errno;
                        else {
                                error = rr_check_file(m, e, fd);
                                close(fd);
                        }
                } else {
                        rr_log("verify TYPE MISMATCH %s mode=0%o expected %c", child, (unsigned)st.st_mode, e->type);
                        error = -EBADMSG;
                }
        }
        closedir(dir);
        return error;
}

/* root: "" or a prefix such as "/rom" (container) / a host test tree. */
static int rr_verify(struct rr_manifest *m, const char *root, const char *repl_dir)
{
        char path[RR_PATH * 2];
        int error;
        for (int w = 0; w < m->nwalks; w++) {
                struct rr_entry *e = rr_find(m, m->walks[w]);
                int fd;
                if (!e || e->type != 'D')
                        return -EINVAL;
                e->visited = 1;
                snprintf(path, sizeof(path), "%s%s", root, m->walks[w]);
                fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                if (fd < 0) {
                        error = -errno;
                        rr_log("verify walk root %s errno=%d", path, -error);
                        return error;
                }
                error = rr_walk(m, fd, m->walks[w], 0);
                if (error) {
                        rr_log("verify walk %s failed errno=%d", m->walks[w], -error);
                        return error;
                }
        }
        for (int i = 0; i < m->n; i++) {
                struct rr_entry *e = &m->e[i];
                int fd;
                if (e->visited)
                        continue;
                if (e->type == 'A') {
                        /* Must not exist: init would import it unverified. */
                        struct stat st;
                        snprintf(path, sizeof(path), "%s%s", root, e->path);
                        int present = !lstat(path, &st);
                        if (present || errno != ENOENT) {
                                rr_log("verify UNEXPECTED %s present=%d errno=%d", e->path, present, present ? 0 : errno);
                                return -EEXIST;
                        }
                        e->visited = 1;
                        continue;
                }
                if (e->type != 'F') {
                        rr_log("verify MISSING %c %s", e->type, e->path);
                        return -ENOENT;
                }
                snprintf(path, sizeof(path), "%s%s", root, e->path);
                fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                if (fd < 0) {
                        error = -errno;
                        rr_log("verify MISSING file %s errno=%d", e->path, -error);
                        return error;
                }
                error = rr_check_file(m, e, fd);
                close(fd);
                if (error)
                        return error;
                e->visited = 1;
        }
        for (int i = 0; i < m->nrepl; i++) {
                struct rr_entry tmp = {0};
                int fd;
                tmp.type = 'F';
                snprintf(tmp.path, sizeof(tmp.path), "%s/%s", repl_dir, m->r[i].name);
                snprintf(tmp.sha, sizeof(tmp.sha), "%s", m->r[i].sha);
                tmp.size = m->r[i].size;
                fd = open(tmp.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                if (fd < 0)
                        return -errno;
                error = rr_check_file(m, &tmp, fd);
                close(fd);
                if (error)
                        return error;
        }
        for (int i = 0; i < m->n; i++) {
                struct rr_entry *e = &m->e[i];
                int found = 0;
                if (strcmp(e->action, "replace"))
                        continue;
                for (int j = 0; j < m->nrepl; j++)
                        if (!strcmp(m->r[j].name, e->repl))
                                found = 1;
                if (!found)
                        return -ENOENT;
        }
        return 0;
}

#ifndef ROMRAM_HOST_TEST
/* ---------------------------------------------------------------- device */
#include <grp.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <linux/fs.h>

#define RR_ROOT "/rom"
#define RR_PAYLOAD "/crownlte"
#define RR_UFS "/sys/bus/platform/devices/11120000.ufs"
#define RR_GUARD RR_UFS "/of_node/crownlte,read-only-diagnostic"
#define AID_READPROC 3009

static int rr_kmsg = -1;
static void rr_log(const char *fmt, ...)
{
        char buf[900];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (rr_kmsg >= 0)
                dprintf(rr_kmsg, "<6>crownlte-romram: %s\n", buf);
}

static int rr_text(const char *path, char *buf, size_t cap)
{
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        ssize_t n, used = 0;
        if (fd < 0)
                return -errno;
        while ((n = read(fd, buf + used, cap - 1 - (size_t)used)) > 0)
                used += n;
        close(fd);
        if (n < 0)
                return -EIO;
        buf[used] = 0;
        return (int)used;
}

static int rr_write(const char *path, const char *data, size_t len, mode_t mode)
{
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, mode);
        ssize_t n;
        if (fd < 0)
                return -errno;
        n = write(fd, data, len);
        close(fd);
        return n == (ssize_t)len ? 0 : -EIO;
}

static int rr_copy(const char *src, const char *dst, mode_t mode)
{
        static char buf[256 * 1024];
        int n = rr_text(src, buf, sizeof(buf));
        if (n < 0)
                return n;
        if ((size_t)n >= sizeof(buf) - 1)
                return -EFBIG;
        return rr_write(dst, buf, (size_t)n, mode);
}

struct rr_blk {
        char name[32];
        unsigned major, minor;
        char partname[40];
        int partition;
};

/* Every sd* node must belong to the UFS host. Returns count or -errno. */
static int rr_scan(struct rr_blk *b, int max)
{
        DIR *dir = opendir("/sys/class/block");
        struct dirent *de;
        int count = 0, error = 0;
        if (!dir)
                return -errno;
        while ((de = readdir(dir))) {
                char path[256], text[1024], real[PATH_MAX];
                struct rr_blk *x;
                if (strncmp(de->d_name, "sd", 2))
                        continue;
                if (count >= max) { error = -E2BIG; break; }
                snprintf(path, sizeof(path), "/sys/class/block/%s", de->d_name);
                if (!realpath(path, real)) { error = -errno; break; }
                if (!strstr(real, "/11120000.ufs/")) {
                        rr_log("block %s is not below 11120000.ufs (%s); refusing", de->d_name, real);
                        error = -EXDEV;
                        break;
                }
                snprintf(path, sizeof(path), "/sys/class/block/%s/uevent", de->d_name);
                if ((error = rr_text(path, text, sizeof(text))) < 0)
                        break;
                error = 0;
                x = &b[count];
                memset(x, 0, sizeof(*x));
                snprintf(x->name, sizeof(x->name), "%s", de->d_name);
                for (char *l = text, *nl; l && *l; l = nl) {
                        nl = strchr(l, '\n');
                        if (nl) *nl++ = 0;
                        if (!strncmp(l, "MAJOR=", 6)) x->major = (unsigned)strtoul(l + 6, NULL, 10);
                        else if (!strncmp(l, "MINOR=", 6)) x->minor = (unsigned)strtoul(l + 6, NULL, 10);
                        else if (!strncmp(l, "PARTNAME=", 9)) snprintf(x->partname, sizeof(x->partname), "%s", l + 9);
                        else if (!strcmp(l, "DEVTYPE=partition")) x->partition = 1;
                }
                count++;
        }
        closedir(dir);
        return error ? error : count;
}

static int rr_roset(const struct rr_blk *x, unsigned long long *bytes)
{
        char node[64];
        struct stat st;
        int fd, one = 1, ro = 0, error = 0;
        snprintf(node, sizeof(node), "/dev/%s", x->name);
        fd = open(node, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0)
                return -errno;
        if (fstat(fd, &st)) error = -errno;
        else if (!S_ISBLK(st.st_mode) || st.st_rdev != makedev(x->major, x->minor)) error = -EXDEV;
        else if (ioctl(fd, BLKROSET, &one)) error = -errno;
        else if (ioctl(fd, BLKROGET, &ro)) error = -errno;
        else if (ro != 1) error = -EROFS;
        else if (bytes && ioctl(fd, BLKGETSIZE64, bytes)) error = -errno;
        close(fd);
        return error;
}

static int rr_ro_mounted(const char *path)
{
        struct statvfs v;
        if (statvfs(path, &v))
                return -errno;
        return (v.f_flag & ST_RDONLY) ? 0 : -EROFS;
}

static int rr_mask_dir(const char *path)
{
        struct stat st;
        if (lstat(path, &st)) {
                rr_log("mask dir %s absent errno=%d (nothing to hide)", path, errno);
                return 0;
        }
        if (!S_ISDIR(st.st_mode))
                return -ENOTDIR;
        if (mount("tmpfs", path, "tmpfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k,mode=0555"))
                return -errno;
        rr_log("masked dir %s", path);
        return 0;
}

static int rr_bind_ro(const char *src, const char *dst)
{
        if (mount(src, dst, NULL, MS_BIND, NULL))
                return -errno;
        if (mount(NULL, dst, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL))
                return -errno;
        return 0;
}

static int rr_mask_file(const char *path)
{
        struct stat st;
        int error;
        if (lstat(path, &st)) {
                rr_log("mask file %s absent errno=%d (nothing to hide)", path, errno);
                return 0;
        }
        error = rr_bind_ro(RR_PAYLOAD "/empty", path);
        if (!error)
                rr_log("masked file %s", path);
        return error;
}

static int rr_mount(const char *src, const char *dst, const char *type,
                    unsigned long flags, const char *opts)
{
        if (mount(src, dst, type, flags, opts))
                return -errno;
        return 0;
}

static struct rr_manifest rr_m;
static struct rr_blk rr_blocks[256];

static int romram_child(void *unused)
{
        char path[RR_PATH * 2], real[PATH_MAX], cmdline[4096], extra[2048];
        const char *stage = "start";
        int error = 0, nblk, idx[3] = { -1, -1, -1 };
        (void)unused;
        if (syscall(SYS_close_range, 0U, ~0U, 0U))
                return 110;
        rr_kmsg = open("/dev/kmsg", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
        if (rr_kmsg < 0)
                return 111;
#define RR_DO(name, expr) do { \
        stage = (name); \
        if ((error = (expr)) < 0) goto out; \
} while (0)
        rr_log("stage begin; inner pid=%ld", (long)getpid());
        if (getpid() != 1) { stage = "inner-pid"; error = -EPERM; goto out; }
        RR_DO("private-root", rr_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
        RR_DO("parse-manifest", rr_parse(&rr_m, RR_PAYLOAD "/manifest.txt"));
        rr_log("manifest: %d entries, %d walks, %d replacements", rr_m.n, rr_m.nwalks, rr_m.nrepl);

        /* 1. The kernel SCSI write guard must be armed for this UFS host. */
        {
                struct stat st;
                stage = "ufs-guard";
                if (stat(RR_GUARD, &st)) { error = -errno; goto out; }
                if (stat(RR_UFS "/driver", &st)) { error = -errno; goto out; }
                rr_log("UFS host bound with crownlte,read-only-diagnostic (SCSI write guard armed)");
        }

        /*
         * 1b. Never run Lineage against a live Trustonic TEE: mcDriverDaemon +
         * keymaster could upgrade or rewrap keys (irreversible for 4.9). Refuse
         * if any TEE device node exists or the TEE driver bound a device.
         */
        {
                static const char *const tee_paths[] = {
                        "/dev/mobicore", "/dev/mobicore-user",
                        "/sys/class/misc/mobicore", "/sys/class/misc/mobicore-user",
                        "/sys/bus/platform/drivers/mcd/tee",
                };
                struct stat st;
                stage = "tee-must-be-off";
                for (unsigned int t = 0; t < sizeof(tee_paths) / sizeof(tee_paths[0]); t++)
                        if (!lstat(tee_paths[t], &st)) {
                                rr_log("Trustonic TEE present (%s); refusing ROM-in-RAM", tee_paths[t]);
                                error = -EPERM;
                                goto out;
                        }
                if (!lstat("/sys/firmware/devicetree/base/tee/status", &st)) {
                        char status[16] = "";
                        int fd = open("/sys/firmware/devicetree/base/tee/status", O_RDONLY | O_CLOEXEC);
                        if (fd >= 0) {
                                ssize_t n = read(fd, status, sizeof(status) - 1);
                                close(fd);
                                if (n > 0) status[n] = 0;
                        }
                        if (!strncmp(status, "okay", 4) || !strncmp(status, "ok", 2)) {
                                rr_log("DT /tee status=%s; refusing ROM-in-RAM", status);
                                error = -EPERM;
                                goto out;
                        }
                } else if (!lstat("/sys/firmware/devicetree/base/tee", &st)) {
                        rr_log("DT /tee node without status (defaults to okay); refusing ROM-in-RAM");
                        error = -EPERM;
                        goto out;
                }
                rr_log("Trustonic TEE absent (no /dev/mobicore*, DT /tee not okay)");
        }

        /* 2. Wait (bounded) for the three partitions, then read-only every sd*. */
        stage = "wait-partitions";
        for (int attempt = 0;; attempt++) {
                int missing = 0;
                nblk = rr_scan(rr_blocks, (int)(sizeof(rr_blocks) / sizeof(rr_blocks[0])));
                if (nblk < 0) { error = nblk; goto out; }
                for (int p = 0; p < 3; p++) {
                        idx[p] = -1;
                        for (int i = 0; i < nblk; i++)
                                if (rr_blocks[i].partition && !strcmp(rr_blocks[i].partname, rr_m.parts[p].name)) {
                                        if (idx[p] >= 0) { stage = "duplicate-partname"; error = -EEXIST; goto out; }
                                        idx[p] = i;
                                }
                        if (idx[p] < 0) missing = 1;
                }
                if (!missing) {
                        /* devtmpfs nodes may lag sysfs: every node must open. */
                        int lag = 0;
                        for (int i = 0; i < nblk; i++) {
                                struct stat st;
                                snprintf(path, sizeof(path), "/dev/%s", rr_blocks[i].name);
                                if (stat(path, &st)) lag = 1;
                        }
                        if (!lag) break;
                }
                if (attempt >= 300) { error = -ETIMEDOUT; goto out; }
                usleep(100000);
        }
        rr_log("found %d sd* nodes; SYSTEM=%s VENDOR=%s ODM=%s", nblk,
               rr_blocks[idx[0]].name, rr_blocks[idx[1]].name, rr_blocks[idx[2]].name);
        stage = "blkroset";
        for (int i = 0; i < nblk; i++) {
                unsigned long long bytes = 0;
                error = rr_roset(&rr_blocks[i], &bytes);
                if (error) {
                        rr_log("BLKROSET %s failed errno=%d", rr_blocks[i].name, -error);
                        goto out;
                }
                for (int p = 0; p < 3; p++)
                        if (idx[p] == i && bytes != rr_m.parts[p].bytes) {
                                rr_log("%s size %llu != expected %llu", rr_m.parts[p].name, bytes, rr_m.parts[p].bytes);
                                stage = "partition-size";
                                error = -EXDEV;
                                goto out;
                        }
        }
        rr_log("BLKROSET=1 verified on all %d sd* nodes", nblk);

        /* 3. Read-only mounts. ext4 "noload": never replay a journal. */
        RR_DO("mkdir-rom", mkdir(RR_ROOT, 0755) && errno != EEXIST ? -errno : 0);
        for (int p = 0; p < 3; p++) {
                char node[64];
                snprintf(node, sizeof(node), "/dev/%s", rr_blocks[idx[p]].name);
                snprintf(path, sizeof(path), "%s%s", RR_ROOT, strcmp(rr_m.parts[p].mountpoint, "/") ? rr_m.parts[p].mountpoint : "");
                rr_log("mount %s (%s) on %s ext4 ro noload", node, rr_m.parts[p].name, path);
                RR_DO("mount-rom", rr_mount(node, path, "ext4", MS_RDONLY, "noload"));
                RR_DO("mount-rom-readonly-check", rr_ro_mounted(path));
        }

        /* 4. rc verification + sanitized overlays (bind, read-only). */
        RR_DO("verify-manifest", rr_verify(&rr_m, RR_ROOT, RR_PAYLOAD "/sanitized"));
        rr_log("manifest verified: %u files hashed, every walked rc entry known", rr_m.files_hashed);
        for (int i = 0; i < rr_m.n; i++) {
                struct rr_entry *e = &rr_m.e[i];
                char src[RR_PATH];
                if (e->type != 'F' || !strcmp(e->action, "keep"))
                        continue;
                if (!strcmp(e->action, "empty"))
                        snprintf(src, sizeof(src), RR_PAYLOAD "/empty");
                else
                        snprintf(src, sizeof(src), RR_PAYLOAD "/sanitized/%s", e->repl);
                snprintf(path, sizeof(path), "%s%s", RR_ROOT, e->path);
                RR_DO("rc-overlay", rr_bind_ro(src, path));
                rr_log("rc overlay %s -> %s", e->path, e->action);
        }

        /* 5a. /dev (RAM) with the nodes first-stage init creates, plus masks. */
        RR_DO("dev-tmpfs", rr_mount("tmpfs", RR_ROOT "/dev", "tmpfs", MS_NOSUID, "mode=0755,size=512m"));
        {
                static const char *dirs[] = { "/dev/pts", "/dev/socket", "/dev/dm-user", "/dev/crownlte" };
                static const struct { const char *p; mode_t m; unsigned ma, mi; } nodes[] = {
                        { "/dev/kmsg", S_IFCHR | 0600, 1, 11 }, { "/dev/random", S_IFCHR | 0666, 1, 8 },
                        { "/dev/urandom", S_IFCHR | 0666, 1, 9 }, { "/dev/ptmx", S_IFCHR | 0666, 5, 2 },
                        { "/dev/null", S_IFCHR | 0666, 1, 3 },
                };
                /* Regular files occupy these names so ueventd cannot create the
                 * real nodes: watchdog stays kernel-petted, the ACM tty stays
                 * ours, pmsg-ramoops evidence is not overwritten. */
                static const char *shadows[] = { "/dev/watchdog", "/dev/watchdog0", "/dev/ttyGS0",
                        "/dev/ttyGS1", "/dev/ttyGS2", "/dev/ttyGS3", "/dev/pmsg0" };
                for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
                        snprintf(path, sizeof(path), RR_ROOT "%s", dirs[i]);
                        RR_DO("dev-mkdir", mkdir(path, 0755) ? -errno : 0);
                }
                RR_DO("devpts", rr_mount("devpts", RR_ROOT "/dev/pts", "devpts", 0, NULL));
                for (size_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
                        snprintf(path, sizeof(path), RR_ROOT "%s", nodes[i].p);
                        RR_DO("dev-mknod", mknod(path, nodes[i].m, makedev(nodes[i].ma, nodes[i].mi)) ? -errno : 0);
                }
                for (size_t i = 0; i < sizeof(shadows) / sizeof(shadows[0]); i++) {
                        snprintf(path, sizeof(path), RR_ROOT "%s", shadows[i]);
                        RR_DO("dev-shadow", rr_write(path, "", 0, 0400));
                }
        }
        RR_DO("payload-rc", rr_copy(RR_PAYLOAD "/init.diag.rc", RR_ROOT "/dev/crownlte/init.diag.rc", 0644));
        RR_DO("payload-probe", rr_copy(RR_PAYLOAD "/probe.sh", RR_ROOT "/dev/crownlte/probe.sh", 0755));
        RR_DO("payload-user0", rr_copy(RR_PAYLOAD "/init_user0.sh", RR_ROOT "/dev/crownlte/init_user0.sh", 0755));
        if (!access(RR_PAYLOAD "/bypass_enabled", F_OK))
                RR_DO("payload-bypass", rr_write(RR_ROOT "/dev/crownlte/bypass_enabled", "1\n", 2, 0644));

        /* androidboot.* for second-stage init; extras first so they win. */
        RR_DO("read-cmdline", rr_text("/proc/cmdline", cmdline, sizeof(cmdline)));
        RR_DO("read-cmdline-extra", rr_text(RR_PAYLOAD "/cmdline-extra", extra, sizeof(extra)));
        cmdline[strcspn(cmdline, "\n")] = 0;
        extra[strcspn(extra, "\n")] = 0;
        {
                char joined[6144];
                int n = snprintf(joined, sizeof(joined), "%s %s\n", extra, cmdline);
                if (n < 0 || (size_t)n >= sizeof(joined)) { stage = "cmdline-join"; error = -E2BIG; goto out; }
                RR_DO("write-cmdline", rr_write(RR_ROOT "/dev/crownlte/cmdline", joined, (size_t)n, 0444));
                rr_log("container /proc/cmdline: %s", joined);
        }

        /* 5b. proc as first-stage mounts it, cmdline substituted, sysrq masked. */
        RR_DO("proc", rr_mount("proc", RR_ROOT "/proc", "proc", 0, "hidepid=2,gid=3009"));
        RR_DO("proc-cmdline", rr_bind_ro(RR_ROOT "/dev/crownlte/cmdline", RR_ROOT "/proc/cmdline"));
        RR_DO("proc-sysrq", rr_mask_file(RR_ROOT "/proc/sysrq-trigger"));
        if (!access("/proc/bootconfig", F_OK))
                RR_DO("proc-bootconfig", rr_mask_file(RR_ROOT "/proc/bootconfig"));

        /* 5c. sysfs + selinuxfs; hide storage control and suspend entry points. */
        RR_DO("sysfs", rr_mount("sysfs", RR_ROOT "/sys", "sysfs", 0, NULL));
        RR_DO("selinuxfs", rr_mount("selinuxfs", RR_ROOT "/sys/fs/selinux", "selinuxfs", 0, NULL));
        stage = "realpath-ufs";
        if (!realpath(RR_UFS, real)) { error = -errno; goto out; }
        snprintf(path, sizeof(path), RR_ROOT "%s", real);
        RR_DO("mask-ufs-device", rr_mask_dir(path));
        stage = "realpath-ufs-driver";
        if (!realpath(RR_UFS "/driver", real)) { error = -errno; goto out; }
        snprintf(path, sizeof(path), RR_ROOT "%s", real);
        RR_DO("mask-ufs-driver", rr_mask_dir(path));
        {
                static const char *dirs[] = { "/sys/module/ufs_exynos9810", "/sys/bus/scsi",
                        "/sys/class/scsi_host", "/sys/class/scsi_device", "/sys/class/scsi_disk",
                        "/sys/class/scsi_generic", "/sys/class/bsg", "/sys/class/typec",
                        "/sys/class/usb_role", "/sys/class/dual_role_usb" };
                static const char *files[] = { "/sys/power/state", "/sys/power/wakeup_count",
                        "/sys/power/mem_sleep", "/sys/power/disk", "/sys/power/autosleep" };
                for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
                        snprintf(path, sizeof(path), RR_ROOT "%s", dirs[i]);
                        RR_DO("mask-dir", rr_mask_dir(path));
                }
                for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
                        snprintf(path, sizeof(path), RR_ROOT "%s", files[i]);
                        RR_DO("mask-file", rr_mask_file(path));
                }
        }

        /* 5d. RAM-only writable state. */
        RR_DO("mnt", rr_mount("tmpfs", RR_ROOT "/mnt", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV, "mode=0755,uid=0,gid=1000"));
        RR_DO("mnt-vendor", mkdir(RR_ROOT "/mnt/vendor", 0755) ? -errno : 0);
        RR_DO("mnt-product", mkdir(RR_ROOT "/mnt/product", 0755) ? -errno : 0);
        RR_DO("debug_ramdisk", rr_mount("tmpfs", RR_ROOT "/debug_ramdisk", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV, "mode=0755,uid=0,gid=0"));
        RR_DO("second_stage_resources", rr_mount("tmpfs", RR_ROOT "/second_stage_resources", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV, "mode=0755,uid=0,gid=0"));
        RR_DO("data", rr_mount("tmpfs", RR_ROOT "/data", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0771,uid=1000,gid=1000,size=1536m"));
        RR_DO("cache", rr_mount("tmpfs", RR_ROOT "/cache", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0770,uid=1000,gid=2001,size=64m"));

        /* 6. Switch root and exec Lineage init's selinux_setup. */
        RR_DO("chdir-rom", chdir(RR_ROOT) ? -errno : 0);
        RR_DO("move-root", rr_mount(".", "/", NULL, MS_MOVE, NULL));
        RR_DO("chroot", chroot(".") ? -errno : 0);
        RR_DO("chdir-root", chdir("/") ? -errno : 0);
        {
                gid_t groups[] = { AID_READPROC };
                RR_DO("setgroups", setgroups(1, groups) ? -errno : 0);
        }
        {
                int in = open("/dev/null", O_RDWR | O_CLOEXEC);
                int log = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
                if (in < 0 || log < 0) { stage = "stdio"; error = -ENODEV; goto out; }
                dup2(in, 0); dup2(log, 1); dup2(log, 2);
        }
        rr_log("exec /system/bin/init selinux_setup (Lineage first-stage handoff emulated)");
        {
                char *const argv[] = { "/system/bin/init", "selinux_setup", NULL };
                char *const envp[] = {
                        "PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin",
                        NULL };
                execve(argv[0], argv, envp);
                stage = "exec-init";
                error = -errno;
        }
out:
        rr_log("ROM stage STOPPED stage=%s errno=%d; namespace exits; no retry", stage, -error);
#undef RR_DO
        return 1;
}
#endif /* !ROMRAM_HOST_TEST */
#endif
