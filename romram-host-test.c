/* SPDX-License-Identifier: GPL-2.0 */
/* Host test: run romram.h manifest parsing/verification against the
 * read-only loop-mounted partition backups, plus negative cases. */
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
        if (argc != 7) {
                fprintf(stderr, "usage: %s manifest root repl bad-sha bad-unknown bad-absent\n", argv[0]);
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
        printf("result: %s\n", fails ? "FAIL" : "PASS");
        return fails ? 1 : 0;
}
