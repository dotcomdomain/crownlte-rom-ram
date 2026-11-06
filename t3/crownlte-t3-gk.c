// SPDX-License-Identifier: GPL-2.0
/*
 * crownlte-t3-gk: T3b gatekeeper TA test client (tee-t3-design.md section 8).
 *
 * Talks to the gatekeeper TA through libMcClient directly; the vendor
 * gatekeeper HAL (which rewrites /efs/TEE/gk_context_* on every verify) is
 * never loaded. This client opens no file except the TA blob (read-only) and
 * its libraries; /efs is an empty read-only tmpfs in its namespace.
 *   b0: mcOpenDevice, mcOpenTrustlet(0813...), mcCloseSession, mcCloseDevice.
 *       No TCI command is sent.
 *   b1: as b0 plus exactly ONE verify command (cmd 2) for the fake uid
 *       0x7ffffff0 with a synthetic handle and random password, bounded wait
 *       (15 s, never infinite). The TA-side failure-record update for that
 *       uid needs RPMB (SRPMB), which has no NWd proxy on 6.12.
 * TCI layout from gatekeeper.exynos9810.so TEE_Verify (file VA 0x2c78-0x3360).
 * Only return codes / lengths are logged; the WSM (incl. any auth token) is
 * wiped and never printed.
 */
#include "t3-bionic.h"

#define GK_TA_PATH "/vendor/app/mcRegistry/08130000000000000000000000000000.tlbin"
#define GK_TA_LEN 10741u
#define GK_SPID 0xfffffffdu
#define GK_TCI_LEN 0x50u
#define GK_WSM_LEN 0x1000u
#define GK_FAKE_UID 0x7ffffff0u
#define GK_CMD_VERIFY 2u
#define GK_WAIT_MS 15000

static const uint8_t gk_uuid[16] = {0x08, 0x13};
static struct t3_mc mc;

/* AOSP gatekeeper password_handle_t (packed, 58 bytes), HANDLE_VERSION 2. */
struct __attribute__((packed)) gk_handle {
	uint8_t version;
	uint64_t user_id;
	uint64_t flags;
	uint64_t salt;
	uint8_t signature[32];
	uint8_t hardware_backed;
};
_Static_assert(sizeof(struct gk_handle) == 58, "password_handle_t");

static uint8_t *read_ta(uint32_t *len)
{
	uint8_t *b = malloc(GK_TA_LEN + 1);
	int fd = open(GK_TA_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	size_t n = 0;
	ssize_t r;

	if (!b || fd < 0) {
		T3("FAIL gk open TA blob errno=%d\n", errno);
		return NULL;
	}
	while (n <= GK_TA_LEN && (r = read(fd, b + n, GK_TA_LEN + 1 - n)) > 0)
		n += (size_t)r;
	close(fd);
	if (n != GK_TA_LEN || memcmp(b + 24, gk_uuid, sizeof(gk_uuid)) || b[16] != 3) {
		T3("FAIL gk TA blob unexpected (len=%u)\n", (unsigned)n);
		return NULL;
	}
	*len = (uint32_t)n;
	return b;
}

static int verify_once(mcSessionHandle_t *s, uint32_t *tci)
{
	mcBulkMap_t map = {0, 0};
	struct gk_handle hd;
	uint8_t *wsm = NULL;
	mcResult_t rc, nrc = MC_DRV_ERR_UNKNOWN, wrc = MC_DRV_ERR_UNKNOWN;
	int32_t err = 0;
	int ok = 0;

	if (posix_memalign((void **)&wsm, 4096, GK_WSM_LEN)) {
		T3("FAIL gk wsm alloc\n");
		return -1;
	}
	memset(wsm, 0, GK_WSM_LEN);
	memset(&hd, 0, sizeof(hd));
	hd.version = 2;
	hd.hardware_backed = 1;
	if (t3_random(&hd.user_id, sizeof(hd.user_id)) || t3_random(&hd.salt, sizeof(hd.salt)) ||
	    t3_random(hd.signature, sizeof(hd.signature)) || t3_random(wsm + 0x800, 16)) {
		T3("FAIL gk getrandom\n");
		free(wsm);
		return -1;
	}
	memcpy(wsm, &hd, sizeof(hd));		/* enrolled handle at +0 */
	/* +0x400 / +0x46c: gk_context main/sub (0x6c each) stay zero, as when the files are missing */

	rc = mc.map(s, wsm, GK_WSM_LEN, &map);
	T3("tee mcMap sid=%u len=%u rc=0x%x mapped_len=%u\n", s->sessionId, GK_WSM_LEN, rc, map.sVirtualLen);
	if (rc)
		goto out;

	memset(tci, 0, GK_TCI_LEN);
	tci[0] = GK_CMD_VERIFY;
	tci[4] = GK_FAKE_UID;
	/* tci[6..7] challenge = 0 (plain verify) */
	tci[8] = map.sVirtualAddr;		/* handle */
	tci[9] = sizeof(hd);
	tci[10] = map.sVirtualAddr + 0x800;	/* provided password */
	tci[11] = 16;
	{
		uint64_t ms = t3_boottime_ms();

		memcpy(&tci[12], &ms, sizeof(ms));	/* +0x30 CLOCK_BOOTTIME ms */
	}
	tci[14] = map.sVirtualAddr + 0xc00;	/* auth token out */
	tci[15] = 0;				/* auth_token_length in, as the HIDL impl passes */
	tci[16] = 0;				/* retry timeout out */
	((uint8_t *)tci)[0x44] = 0;		/* request_reenroll */
	tci[18] = map.sVirtualAddr + 0x400;	/* context */

	T3("STAGE b1: sending ONE gatekeeper VERIFY (cmd 2) for fake uid 0x%x, handle_len=%u pw_len=16\n",
	   GK_FAKE_UID, (unsigned)sizeof(hd));
	nrc = mc.notify(s);
	T3("tee mcNotify sid=%u cmd=0x%x rc=0x%x\n", s->sessionId, GK_CMD_VERIFY, nrc);
	if (!nrc) {
		wrc = mc.waitNotification(s, GK_WAIT_MS);
		T3("tee mcWaitNotification sid=%u timeout=%d rc=0x%x\n", s->sessionId, GK_WAIT_MS, wrc);
		if (wrc) {
			rc = mc.getSessionErrorCode(s, &err);
			T3("tee mcGetSessionErrorCode sid=%u rc=0x%x err=%d\n", s->sessionId, rc, err);
		}
	}
	T3("gk verify uid=0x%x notify_rc=0x%x wait_rc=0x%x ta_ret=0x%x retry_timeout=%u reenroll=%u token_len=%u\n",
	   GK_FAKE_UID, nrc, wrc, tci[1], tci[16],
	   ((uint8_t *)tci)[0x44], tci[15]);
	ok = wrc == MC_DRV_OK;
	memset(wsm, 0, GK_WSM_LEN);
	rc = mc.unmap(s, wsm, &map);
	T3("tee mcUnmap sid=%u rc=0x%x\n", s->sessionId, rc);
out:
	memset(wsm, 0, GK_WSM_LEN);
	free(wsm);
	return ok ? 0 : -1;
}

int main(int argc, char **argv)
{
	mcSessionHandle_t s = {0, MC_DEVICE_ID_DEFAULT};
	uint32_t *tci = NULL, len = 0;
	uint8_t *ta;
	mcResult_t rc;
	int stage, fail = 0;

	if (t3_no_exec()) {
		T3("FAIL gk no-exec seccomp layer errno=%d\n", errno);
		return 2;
	}
	if (argc != 2 || (strcmp(argv[1], "b0") && strcmp(argv[1], "b1"))) {
		T3("FAIL gk usage: crownlte-t3-gk b0|b1\n");
		return 2;
	}
	stage = argv[1][1] - '0';
	alarm(60);
	T3("gk client start stage=b%d uid=%u gid=%u\n", stage, getuid(), getgid());
	if (getuid() != 1000) {
		T3("FAIL gk not uid 1000\n");
		return 2;
	}
	if (t3_mc_resolve(&mc, RTLD_NOW))
		return 4;
	ta = read_ta(&len);
	if (!ta || posix_memalign((void **)&tci, 4096, 4096))
		return 4;
	memset(tci, 0, 4096);

	rc = mc.openDevice(MC_DEVICE_ID_DEFAULT);
	T3("tee mcOpenDevice id=0 rc=0x%x\n", rc);
	if (rc) {
		T3("FAIL gk mcOpenDevice\n");
		return 5;
	}
	rc = mc.openTrustlet(&s, GK_SPID, ta, len, (uint8_t *)tci, GK_TCI_LEN);
	T3("tee mcOpenTrustlet spid=0x%x len=%u tci_len=%u rc=0x%x sid=%u\n", GK_SPID, len, GK_TCI_LEN, rc,
	   s.sessionId);
	free(ta);
	if (rc) {
		fail = 1;
	} else {
		T3("gk open rc=0\n");
		if (stage == 1 && verify_once(&s, tci))
			fail = 1;
		rc = mc.closeSession(&s);
		T3("tee mcCloseSession sid=%u rc=0x%x\n", s.sessionId, rc);
		T3("gk close rc=0x%x\n", rc);
		fail |= rc != 0;
	}
	rc = mc.closeDevice(MC_DEVICE_ID_DEFAULT);
	T3("tee mcCloseDevice id=0 rc=0x%x\n", rc);
	memset(tci, 0, 4096);
	if (fail) {
		T3("FAIL gk stage=b%d\n", stage);
		return 6;
	}
	T3("PASS gk stage=b%d%s\n", stage, stage == 1 ? " (verify round trip completed; see ta_ret)" : "");
	return 0;
}
