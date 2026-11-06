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
#define AID_SYSTEM 1000

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

/* ------------------------------------------------------------------- FRP */
/*
 * v10: PersistentDataBlockService opens ro.frp.pst (/dev/block/persistent,
 * which init.samsungexynos9810.rc links to by-name/PERSISTENT). The container
 * hides the UFS from ueventd, so no by-name links exist and system_server
 * died in boot phase 500. FRP must not be bypassed and PERSISTENT must never
 * be written, so the service gets the device's REAL FRP block as a RAM copy:
 *  - the real partition is read through its block node, opened O_RDONLY
 *    after BLKROSET=1 was verified on it (the SCSI write guard also
 *    rejects any write to the UFS);
 *  - the bytes go into a private tmpfs outside RR_ROOT, unreachable once
 *    the container chroots (only the loop device keeps the file open);
 *  - read 1 (hash of the partition), read 2 (the copy, re-hashed) and
 *    read 3 (through the loop device) must give the same sha256;
 *  - the loop device is read-write, so whatever the service writes
 *    (format, OEM-unlock bit, ...) lands in RAM and is gone at restart;
 *  - only by-name/PERSISTENT is created in the container. RADIO, MISC,
 *    STEADY, PARAM and every other partition stay invisible.
 * Any failure leaves the node absent (the v9 behaviour), never a fake one.
 */
#include <linux/loop.h>

#define RR_FRP_PART "PERSISTENT"
#define RR_FRP_DIR "/crownlte-frp"
#define RR_FRP_IMG RR_FRP_DIR "/persistent.img"
#define RR_FRP_MAX (4ULL << 20)
#define RR_FRP_BYNAME RR_ROOT "/dev/block/platform/11120000.ufs/by-name"

static int rr_sha_at0(int fd, char hex[65], unsigned long long *size)
{
        if (lseek(fd, 0, SEEK_SET) < 0)
                return -errno;
        return rr_sha_fd(fd, hex, size);
}

static int rr_copy_fd(int in, int out, unsigned long long bytes)
{
        static char buf[65536];
        unsigned long long done = 0;
        while (done < bytes) {
                size_t want = bytes - done < sizeof(buf) ? (size_t)(bytes - done) : sizeof(buf);
                ssize_t n = pread(in, buf, want, (off_t)done);
                if (n < 0 && errno == EINTR)
                        continue;
                if (n < 0)
                        return -errno;
                if (n == 0)
                        return -EIO;
                for (ssize_t w = 0; w < n;) {
                        ssize_t m = pwrite(out, buf + w, (size_t)(n - w), (off_t)(done + (unsigned long long)w));
                        if (m < 0 && errno == EINTR)
                                continue;
                        if (m < 0)
                                return -errno;
                        w += m;
                }
                done += (unsigned long long)n;
        }
        return 0;
}

static int rr_mkdirs(const char *path, mode_t mode)
{
        char tmp[RR_PATH];
        if ((size_t)snprintf(tmp, sizeof(tmp), "%s", path) >= sizeof(tmp))
                return -ENAMETOOLONG;
        for (char *c = tmp + 1; *c; c++) {
                if (*c != '/')
                        continue;
                *c = 0;
                if (mkdir(tmp, mode) && errno != EEXIST)
                        return -errno;
                *c = '/';
        }
        if (mkdir(tmp, mode) && errno != EEXIST)
                return -errno;
        return 0;
}

static int rr_frp_setup(int nblk)
{
        const struct rr_blk *x = NULL;
        const char *what = "find";
        char node[64], loopdev[32], dst[RR_PATH];
        char src_sha[65] = "", img_sha[65] = "", loop_sha[65] = "";
        unsigned long long bytes = 0, n1 = 0, n2 = 0, n3 = 0, lbytes = 0;
        unsigned char hdr[40], last = 0;
        struct stat st;
        int blk = -1, img = -1, ctl = -1, lfd = -1, ro = 0, num = -1, matches = 0, error = 0;

        for (int i = 0; i < nblk; i++)
                if (rr_blocks[i].partition && !strcmp(rr_blocks[i].partname, RR_FRP_PART)) {
                        x = &rr_blocks[i];
                        matches++;
                }
        if (matches != 1) {
                error = matches ? -EEXIST : -ENOENT;
                goto out;
        }

        /* read 1: the real partition, read-only, hashed */
        what = "open-partition";
        snprintf(node, sizeof(node), "/dev/%s", x->name);
        blk = open(node, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (blk < 0) { error = -errno; goto out; }
        what = "check-partition";
        if (fstat(blk, &st)) { error = -errno; goto out; }
        if (!S_ISBLK(st.st_mode) || st.st_rdev != makedev(x->major, x->minor)) { error = -EXDEV; goto out; }
        if (ioctl(blk, BLKROGET, &ro)) { error = -errno; goto out; }
        if (ro != 1) { error = -EROFS; goto out; }
        if (ioctl(blk, BLKGETSIZE64, &bytes)) { error = -errno; goto out; }
        if (bytes < 4096 || bytes > RR_FRP_MAX || bytes % 512) { error = -EFBIG; goto out; }
        what = "hash-partition";
        if ((error = rr_sha_at0(blk, src_sha, &n1))) goto out;
        if (n1 != bytes) { error = -EIO; goto out; }

        /* read 2: copy into a private tmpfs that the container never sees */
        what = "ram-tmpfs";
        if (mkdir(RR_FRP_DIR, 0700) && errno != EEXIST) { error = -errno; goto out; }
        if ((error = rr_mount("tmpfs", RR_FRP_DIR, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                              "mode=0700,size=8m")))
                goto out;
        what = "ram-copy";
        img = open(RR_FRP_IMG, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (img < 0) { error = -errno; goto out; }
        if ((error = rr_copy_fd(blk, img, bytes))) goto out;
        close(blk);
        blk = -1;
        what = "verify-copy";
        if ((error = rr_sha_at0(img, img_sha, &n2))) goto out;
        if (n2 != bytes || strcmp(src_sha, img_sha)) { error = -EBADMSG; goto out; }
        if (pread(img, hdr, sizeof(hdr), 0) != (ssize_t)sizeof(hdr) ||
            pread(img, &last, 1, (off_t)(bytes - 1)) != 1) { error = -EIO; goto out; }

        /* loop device on the RAM copy, read-write: writes stay in RAM */
        what = "loop";
        ctl = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
        if (ctl < 0) { error = -errno; goto out; }
        for (int attempt = 0; attempt < 8 && lfd < 0; attempt++) {
                struct loop_config cfg;
                num = ioctl(ctl, LOOP_CTL_GET_FREE);
                if (num < 0) { error = -errno; goto out; }
                snprintf(loopdev, sizeof(loopdev), "/dev/loop%d", num);
                for (int w = 0; w < 100 && access(loopdev, F_OK); w++)
                        usleep(10000);
                lfd = open(loopdev, O_RDWR | O_CLOEXEC);
                if (lfd < 0) { error = -errno; goto out; }
                memset(&cfg, 0, sizeof(cfg));
                cfg.fd = (__u32)img;
                snprintf((char *)cfg.info.lo_file_name, LO_NAME_SIZE, "crownlte-frp-ram-copy");
                if (!ioctl(lfd, LOOP_CONFIGURE, &cfg))
                        break;
                error = -errno;
                close(lfd);
                lfd = -1;
                if (error != -EBUSY)
                        goto out;
        }
        if (lfd < 0) goto out;
        error = 0;

        /* read 3: through the loop device */
        what = "verify-loop";
        if (ioctl(lfd, BLKGETSIZE64, &lbytes)) { error = -errno; goto out; }
        if (lbytes != bytes) { error = -EXDEV; goto out; }
        if ((error = rr_sha_at0(lfd, loop_sha, &n3))) goto out;
        if (n3 != bytes || strcmp(src_sha, loop_sha)) { error = -EBADMSG; goto out; }
        if (fstat(lfd, &st)) { error = -errno; goto out; }

        /* the node init's "symlink .../by-name/PERSISTENT /dev/block/persistent" targets */
        what = "container-node";
        if ((error = rr_mkdirs(RR_FRP_BYNAME, 0755))) goto out;
        snprintf(dst, sizeof(dst), "%s/%s", RR_FRP_BYNAME, RR_FRP_PART);
        if (mknod(dst, S_IFBLK | 0660, st.st_rdev)) { error = -errno; goto out; }
        if (chown(dst, AID_SYSTEM, AID_SYSTEM) || chmod(dst, 0660)) { error = -errno; goto out; }

        rr_log("FRP: real %s (%s, %llu bytes) sha256=%s read read-only (BLKRO=1), copied to a private RAM tmpfs and verified 3x",
               RR_FRP_PART, x->name, bytes, src_sha);
        rr_log("FRP: RAM copy attached read-write as loop%d (%u:%u, file name crownlte-frp-ram-copy); writes stay in RAM; container /dev/block/platform/11120000.ufs/by-name/%s -> loop%d (0660 system:system)",
               num, major(st.st_rdev), minor(st.st_rdev), RR_FRP_PART, num);
        rr_log("FRP: PDB header magic=%02x%02x%02x%02x data_len=%u oem_unlock_byte=%u (informational; nothing is changed)",
               hdr[32], hdr[33], hdr[34], hdr[35],
               (unsigned)hdr[36] << 24 | (unsigned)hdr[37] << 16 | (unsigned)hdr[38] << 8 | hdr[39], last);
out:
        if (blk >= 0) close(blk);
        if (img >= 0) close(img);
        if (lfd >= 0) close(lfd);
        if (ctl >= 0) close(ctl);
        if (error)
                rr_log("FRP: /dev/block/persistent NOT provided: step %s errno=%d (%d %s partitions; src=%s copy=%s loop=%s); PersistentDataBlockService will fail as in v9",
                       what, -error, matches, RR_FRP_PART, src_sha, img_sha, loop_sha);
        return error;
}


#ifdef RR_TEE_T2
/* Binary-safe copy for T2 payload files larger than rr_copy's 256 KiB text buffer.
 * Streams through rr_copy_fd, then re-hashes source and destination in full. */
#define RR_T2_COPY_MAX (4ULL << 20)
static int rr_t2_copy_bin(const char *src, const char *dst, mode_t mode)
{
        char a[65], b[65];
        unsigned long long na = 0, nb = 0;
        struct stat st;
        int error, in, out;
        in = open(src, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (in < 0)
                return -errno;
        if (fstat(in, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
            (unsigned long long)st.st_size > RR_T2_COPY_MAX) {
                close(in);
                return -EFBIG;
        }
        out = open(dst, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
        if (out < 0) {
                error = -errno;
                close(in);
                return error;
        }
        error = rr_copy_fd(in, out, (unsigned long long)st.st_size);
        if (!error)
                error = rr_sha_at0(in, a, &na);
        if (!error)
                error = rr_sha_at0(out, b, &nb);
        if (!error && (na != (unsigned long long)st.st_size || nb != na || strcmp(a, b)))
                error = -EIO;
        if (!error && fchmod(out, mode))
                error = -errno;
        close(out);
        close(in);
        if (!error)
                rr_log("T2 copied %s (%llu bytes, sha256 %s)", dst, na, a);
        return error;
}
#endif

#ifdef RR_TEE_T2
/* Only EFS is read, once. The real device is never mounted or exposed. */
static int rr_t2_efs(int nblk)
{
        const struct rr_blk *x = NULL;
        int in = -1, out = -1, ctl = -1, loop = -1, error = -ENOENT, ro = 0;
        char node[64], lnode[64], hash[65];
        unsigned long long bytes = 0, hashed = 0;
        struct stat st;
        for (int i = 0; i < nblk; i++)
                if (rr_blocks[i].partition && !strcmp(rr_blocks[i].partname, "EFS")) {
                        if (x) return -EEXIST;
                        x = &rr_blocks[i];
                }
        if (!x) return -ENOENT;
        if ((error = rr_roset(x, &bytes))) return error;
        if (!bytes || bytes > (64ULL << 20)) return -EFBIG;
        if ((error = rr_mkdirs("/crownlte-t2", 0700))) return error;
        if ((error = rr_mount("tmpfs", "/crownlte-t2", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0700,size=65m"))) return error;
        snprintf(node, sizeof(node), "/dev/%s", x->name);
        in = open(node, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (in < 0) { error = -errno; goto done; }
        if (fstat(in, &st) || !S_ISBLK(st.st_mode) || st.st_rdev != makedev(x->major, x->minor) ||
            ioctl(in, BLKROGET, &ro) || ro != 1) { error = -EXDEV; goto done; }
        out = open("/crownlte-t2/efs.img", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        if (out < 0) { error = -errno; goto done; }
        if ((error = rr_copy_fd(in, out, bytes))) goto done;
        close(in); in = -1;
        if ((error = rr_sha_at0(out, hash, &hashed))) goto done;
        if (hashed != bytes) { error = -EIO; goto done; }
        close(out);
        out = open("/crownlte-t2/efs.img", O_RDONLY | O_CLOEXEC);
        if (out < 0) { error = -errno; goto done; }
        ctl = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
        if (ctl < 0) { error = -errno; goto done; }
        int num = ioctl(ctl, LOOP_CTL_GET_FREE);
        if (num < 0) { error = -errno; goto done; }
        snprintf(lnode, sizeof(lnode), "/dev/loop%d", num);
        for (int w = 0; w < 100 && access(lnode, F_OK); w++) usleep(10000);
        loop = open(lnode, O_RDONLY | O_CLOEXEC);
        if (loop < 0) { error = -errno; goto done; }
        struct loop_config cfg = {0};
        cfg.fd = out; cfg.info.lo_flags = LO_FLAGS_READ_ONLY;
        if (ioctl(loop, LOOP_CONFIGURE, &cfg)) { error = -errno; goto done; }
        error = rr_mount(lnode, RR_ROOT "/efs", "ext4", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, "noload");
        if (!error) error = rr_ro_mounted(RR_ROOT "/efs");
        if (!error) rr_log("T2 PASS EFS RAM copy ro,noload bytes=%llu sha256=%s", bytes, hash);
done:
        if (in >= 0) close(in);
        if (out >= 0) close(out);
        if (loop >= 0) close(loop);
        if (ctl >= 0) close(ctl);
        return error;
}
#endif

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

#ifdef RR_TEE_T2
        {
                char status[16]; struct stat st;
                stage = "tee-t2-required";
                if (access(RR_PAYLOAD "/tee_t2", R_OK) ||
                    rr_text("/sys/firmware/devicetree/base/tee/status", status, sizeof(status)) < 0 ||
                    (strcmp(status, "okay") && strcmp(status, "ok")) ||
                    stat("/dev/mobicore", &st) || !S_ISCHR(st.st_mode) ||
                    access("/sys/bus/platform/drivers/mcd/tee", F_OK)) {
                        error = -ENODEV; goto out;
                }
                rr_log("T2 PASS TEE present; UFS guard DT and host binding verified");
        }
#else
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

#endif

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
#ifdef RR_TEE_T2
                /* Never open whole disks or forbidden partitions, even for an ioctl. */
                if (i != idx[0] && i != idx[1] && i != idx[2]) continue;
#endif
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
#ifdef RR_TEE_T2
        rr_log("T2 BLKROSET=1 verified on SYSTEM/VENDOR/ODM only; EFS checked separately");
#else
        rr_log("BLKROSET=1 verified on all %d sd* nodes", nblk);
#endif

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
        /* 5a-frp. Real FRP block as a verified RAM copy (non-fatal, see rr_frp_setup). */
#ifdef RR_TEE_T2
        /* Keep the legacy helper referenced, but never call it in T2. */
        (void)&rr_frp_setup;
        RR_DO("tee-t2-efs-copy", rr_t2_efs(nblk));
#ifdef RR_TEE_T3
        /* T3: stage script, stage name, runner and the one stage client (hashed copies). */
        RR_DO("tee-t3-script", rr_copy(RR_PAYLOAD "/tee-t3.sh", RR_ROOT "/dev/crownlte/tee-t3.sh", 0755));
        RR_DO("tee-t3-stage", rr_copy(RR_PAYLOAD "/tee_t3", RR_ROOT "/dev/crownlte/tee_t3", 0444));
        RR_DO("tee-t3-runner", rr_t2_copy_bin(RR_PAYLOAD "/tee-t3-run", RR_ROOT "/dev/crownlte/tee-t3-run", 0755));
        RR_DO("tee-t3-client", rr_t2_copy_bin(RR_PAYLOAD "/t3-client", RR_ROOT "/dev/crownlte/t3-client", 0755));
        /* No SCSI pass-through (RPMB W-LU) nodes: /dev/bsg is a read-only empty
         * tmpfs before ueventd starts (the sysfs bsg/scsi_generic masks already
         * hide the devices; this also blocks node creation). tee-t3.sh and the
         * runner re-check /dev/bsg and /dev/sg*. */
        RR_DO("tee-t3-bsg-dir", rr_mkdirs(RR_ROOT "/dev/bsg", 0755));
        RR_DO("tee-t3-bsg-mask", rr_mask_dir(RR_ROOT "/dev/bsg"));
#else
        RR_DO("tee-t2-script", rr_copy(RR_PAYLOAD "/tee-t2.sh", RR_ROOT "/dev/crownlte/tee-t2.sh", 0755));
        RR_DO("tee-t2-runner", rr_t2_copy_bin(RR_PAYLOAD "/tee-t2-run", RR_ROOT "/dev/crownlte/tee-t2-run", 0755));
#endif
        /* A read-only regular-file mount permanently occupies the user-session node. */
        RR_DO("tee-t2-no-clients", rr_write(RR_ROOT "/dev/mobicore-user", "", 0, 0000));
        RR_DO("tee-t2-no-clients-mask", rr_mask_file(RR_ROOT "/dev/mobicore-user"));
        /* /dev/block stays a normal container tmpfs: apexd-bootstrap needs loop/dm
         * nodes there (T2c: a RO /dev/block made init reboot at 18 s). Storage
         * nodes cannot appear: the UFS/SCSI sysfs masks below hide them from
         * ueventd, as in every default ROM-RAM run; tee-t2.sh re-checks. */
#else
        (void)rr_frp_setup(nblk);
#endif
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

#ifdef RR_TEE_T2
        RR_DO("tee-t2-efs-alias", rr_mkdirs(RR_ROOT "/mnt/vendor/efs", 0755));
        RR_DO("tee-t2-efs-bind", rr_bind_ro(RR_ROOT "/efs", RR_ROOT "/mnt/vendor/efs"));
        /* /data, including both registry layouts and TbStorage, is already tmpfs. */
        rr_log("T2 PASS UFS/SCSI sysfs masked (storage nodes hidden from ueventd; tee-t2.sh re-checks /dev/block); FRP real partition never opened");
#endif

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
