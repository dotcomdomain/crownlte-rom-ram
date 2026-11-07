/* SPDX-License-Identifier: GPL-2.0 */
/* Host test: run romram.h manifest parsing/verification against the
 * read-only loop-mounted partition backups, plus negative cases.
 * EFS_RO_DIR builds add: efs-ro list populate + check into an empty
 * directory, and a list with a wrong sha256 that must be refused. */
#define _GNU_SOURCE
#define ROMRAM_HOST_TEST
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "romram-sha256.h"
#include "romram.h"

static int verbose = 1;
static void rr_log(const char *fmt, ...)
{
        va_list ap;
        if (!verbose)
                return;
        va_start(ap, fmt);
        printf("  log: ");
        vprintf(fmt, ap);
        printf("\n");
        va_end(ap);
}

static struct rr_manifest m;

static int run(const char *manifest, const char *root, const char *repl)
{
        int e = rr_parse(&m, manifest);
        if (e)
                return e;
        return rr_verify(&m, root, repl);
}

int main(int argc, char **argv)
{
        int fails = 0, e;
        if (argc != 7 && argc != 12) {
                fprintf(stderr, "usage: %s manifest root repl bad-sha bad-unknown bad-absent"
                        " [efs-list efs-src efs-out efs-bad-list efs-bad-out]\n", argv[0]);
                return 2;
        }
        e = run(argv[1], argv[2], argv[3]);
        printf("positive: errno=%d files_hashed=%u entries=%d walks=%d repl=%d\n",
               -e, m.files_hashed, m.n, m.nwalks, m.nrepl);
        if (e) fails++;
        for (int i = 4; i < 7; i++) {
                e = run(argv[i], argv[2], argv[3]);
                printf("negative %s: errno=%d (%s)\n", argv[i], -e, e ? "rejected, ok" : "ACCEPTED, FAIL");
                if (!e) fails++;
        }
        if (argc == 12) {
                unsigned n = 0, n2 = 0;
                e = rr_efs_apply(argv[7], argv[8], argv[9], 0, &n);
                if (!e)
                        e = rr_efs_apply(argv[7], NULL, argv[9], 1, &n2);
                printf("efs-ro positive: errno=%d files=%u checked=%u\n", -e, n, n2);
                if (e || n != n2) fails++;
                e = rr_efs_apply(argv[10], argv[8], argv[11], 0, &n);
                printf("efs-ro negative %s: errno=%d (%s)\n", argv[10], -e, e ? "rejected, ok" : "ACCEPTED, FAIL");
                if (!e) fails++;
        }
        printf("result: %s\n", fails ? "FAIL" : "PASS");
        return fails ? 1 : 0;
}
