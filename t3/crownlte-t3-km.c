// SPDX-License-Identifier: GPL-2.0
/*
 * crownlte-t3-km: T3a keymaster TA test client (tee-t3-design.md section 7).
 *
 * Runs as uid 1000 inside the runner's private mount namespace, bind-mounted
 * at /vendor/bin/crownlte-t3-km so that the vendor linker namespace applies.
 * Loads the vendor keymaster2 module (keystore.mdfpp.so) and calls ONLY:
 *   a0: open, close
 *   a1: open, add_rng_entropy(32 random bytes), close
 *   a2: open, configure(OS_VERSION 160000, OS_PATCHLEVEL 202608), add_rng_entropy, close
 * Never generate/import/export/begin/attest/upgrade/delete (keymaster2_device
 * offsets >= 0x98 are not even declared here). No key material exists or is
 * logged: the entropy buffer is wiped and only return codes are printed.
 *
 * The executable exports the nine libMcClient functions the keymaster helper
 * imports. bionic resolves the dlopen'ed HAL against the main executable
 * first, so every TEE call the HAL makes is logged here ("T3 tee ...") and
 * forwarded to the real libMcClient; the open-trustlet wrapper only passes the
 * keymaster TA (UUID + length) and every wait is bounded to 40 s.
 */
#include "t3-bionic.h"

#define T3_EXPORT __attribute__((visibility("default"), used))

/* ---- hardware/libhardware hardware.h + keymaster2.h (LP64 layout) ---- */
struct hw_module_t;
struct hw_device_t {
	uint32_t tag;
	uint32_t version;
	struct hw_module_t *module;
	uint64_t reserved[12];
	int (*close)(struct hw_device_t *device);
};
struct hw_module_methods_t {
	int (*open)(const struct hw_module_t *module, const char *id, struct hw_device_t **device);
};
struct hw_module_t {
	uint32_t tag;
	uint16_t module_api_version;
	uint16_t hal_api_version;
	const char *id;
	const char *name;
	const char *author;
	struct hw_module_methods_t *methods;
	void *dso;
	uint64_t reserved[32 - 7];
};
typedef struct { const uint8_t *data; size_t data_length; } keymaster_blob_t;
typedef struct {
	uint32_t tag;
	union {
		uint32_t enumerated;
		bool boolean;
		uint32_t integer;
		uint64_t long_integer;
		uint64_t date_time;
		keymaster_blob_t blob;
	};
} keymaster_key_param_t;
typedef struct { keymaster_key_param_t *params; size_t length; } keymaster_key_param_set_t;
struct keymaster2_device {
	struct hw_device_t common;
	void *context;
	uint32_t flags;
	int (*configure)(const struct keymaster2_device *dev, const keymaster_key_param_set_t *params);
	int (*add_rng_entropy)(const struct keymaster2_device *dev, const uint8_t *data, size_t len);
	/* generate_key (0x98) and everything after it: intentionally not declared */
};
_Static_assert(sizeof(struct hw_device_t) == 0x78, "hw_device_t");
_Static_assert(offsetof(struct keymaster2_device, configure) == 0x88, "configure at 0x88");
_Static_assert(offsetof(struct keymaster2_device, add_rng_entropy) == 0x90, "add_rng_entropy at 0x90");
_Static_assert(sizeof(keymaster_key_param_t) == 24, "keymaster_key_param_t");
_Static_assert(offsetof(struct hw_module_t, methods) == 0x20, "methods");

#define HARDWARE_MODULE_TAG	0x48574d54u	/* 'HWMT' */
#define HARDWARE_DEVICE_TAG	0x48574454u	/* 'HWDT' */
#define KEYMASTER_MODULE_API_VERSION_2_0 0x0200
#define KM_TAG_OS_VERSION	0x300002c1u	/* KM_UINT | 705 */
#define KM_TAG_OS_PATCHLEVEL	0x300002c2u	/* KM_UINT | 706 */
#define T3_OS_VERSION		160000u		/* ro.build.version.release 16 */
#define T3_OS_PATCHLEVEL	202608u		/* ro.build.version.security_patch 2026-08-01 */

/* Keymaster TA as pinned in the DTB (MCLF header bytes 24..39 + file size). */
static const uint8_t km_uuid[16] = {0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x3e};
#define KM_TA_LEN 767845u
#define KM_SPID 0xfffffffeu

static struct t3_mc real;
static int mc_ready, tee_calls, trustlet_opens;
static uint32_t *km_tci;	/* the helper's TCI (0x10 bytes): only word 0 (command id) is logged */

/* ---- logged libMcClient interposers (the helper's exact import set) ---- */
T3_EXPORT mcResult_t mcOpenDevice(uint32_t id)
{
	mcResult_t rc = mc_ready ? real.openDevice(id) : MC_DRV_ERR_UNKNOWN;

	tee_calls++;
	T3("tee mcOpenDevice id=%u rc=0x%x\n", id, rc);
	return rc;
}

T3_EXPORT mcResult_t mcCloseDevice(uint32_t id)
{
	mcResult_t rc = mc_ready ? real.closeDevice(id) : MC_DRV_ERR_UNKNOWN;

	tee_calls++;
	T3("tee mcCloseDevice id=%u rc=0x%x\n", id, rc);
	return rc;
}

T3_EXPORT mcResult_t mcOpenTrustlet(mcSessionHandle_t *s, uint32_t spid, uint8_t *ta, uint32_t len,
				    uint8_t *tci, uint32_t tci_len)
{
	mcResult_t rc;

	tee_calls++;
	if (!mc_ready || !ta || len != KM_TA_LEN || spid != KM_SPID ||
	    memcmp(ta + 24, km_uuid, sizeof(km_uuid)) || ta[16] != 3) {
		T3("tee mcOpenTrustlet spid=0x%x len=%u tci_len=%u REFUSED by client (not the keymaster TA)\n",
		   spid, len, tci_len);
		return MC_DRV_ERR_UNKNOWN;
	}
	rc = real.openTrustlet(s, spid, ta, len, tci, tci_len);
	trustlet_opens++;
	km_tci = (uint32_t *)(void *)tci;
	T3("tee mcOpenTrustlet spid=0x%x len=%u tci_len=%u rc=0x%x sid=%u\n",
	   spid, len, tci_len, rc, s ? s->sessionId : 0);
	return rc;
}

T3_EXPORT mcResult_t mcCloseSession(mcSessionHandle_t *s)
{
	uint32_t sid = s ? s->sessionId : 0;
	mcResult_t rc = mc_ready ? real.closeSession(s) : MC_DRV_ERR_UNKNOWN;

	tee_calls++;
	T3("tee mcCloseSession sid=%u rc=0x%x\n", sid, rc);
	return rc;
}

T3_EXPORT mcResult_t mcNotify(mcSessionHandle_t *s)
{
	mcResult_t rc;

	tee_calls++;
	if (km_tci)
		T3("tee mcNotify sid=%u cmd=0x%x\n", s ? s->sessionId : 0, km_tci[0]);
	rc = mc_ready ? real.notify(s) : MC_DRV_ERR_UNKNOWN;
	T3("tee mcNotify rc=0x%x\n", rc);
	return rc;
}

T3_EXPORT mcResult_t mcWaitNotification(mcSessionHandle_t *s, int32_t timeout)
{
	int32_t t = (timeout < 0 || timeout > 40000) ? 40000 : timeout;
	mcResult_t rc;

	tee_calls++;
	rc = mc_ready ? real.waitNotification(s, t) : MC_DRV_ERR_UNKNOWN;
	T3("tee mcWaitNotification sid=%u timeout=%d%s rc=0x%x rsp=0x%x\n", s ? s->sessionId : 0,
	   t, t != timeout ? " (clamped)" : "", rc, km_tci ? km_tci[0] : 0);
	return rc;
}

T3_EXPORT mcResult_t mcMap(mcSessionHandle_t *s, void *buf, uint32_t len, mcBulkMap_t *map)
{
	mcResult_t rc = mc_ready ? real.map(s, buf, len, map) : MC_DRV_ERR_UNKNOWN;

	tee_calls++;
	T3("tee mcMap sid=%u len=%u rc=0x%x mapped_len=%u\n", s ? s->sessionId : 0, len, rc,
	   map ? map->sVirtualLen : 0);
	return rc;
}

T3_EXPORT mcResult_t mcUnmap(mcSessionHandle_t *s, void *buf, mcBulkMap_t *map)
{
	mcResult_t rc = mc_ready ? real.unmap(s, buf, map) : MC_DRV_ERR_UNKNOWN;

	tee_calls++;
	T3("tee mcUnmap sid=%u rc=0x%x\n", s ? s->sessionId : 0, rc);
	return rc;
}

T3_EXPORT mcResult_t mcGetSessionErrorCode(mcSessionHandle_t *s, int32_t *err)
{
	mcResult_t rc = mc_ready ? real.getSessionErrorCode(s, err) : MC_DRV_ERR_UNKNOWN;

	tee_calls++;
	T3("tee mcGetSessionErrorCode sid=%u rc=0x%x err=%d\n", s ? s->sessionId : 0, rc,
	   err ? *err : 0);
	return rc;
}

/* ---- the AOSP keymaster parsing of the two properties (exact values) ---- */
static int num(const char **p, int maxd, unsigned *v)
{
	int d = 0;

	*v = 0;
	while (**p >= '0' && **p <= '9' && d < maxd) {
		*v = *v * 10 + (unsigned)(**p - '0');
		(*p)++;
		d++;
	}
	return d ? 0 : -1;
}

/* ^([0-9]{1,2})(\.([0-9]{1,2}))?(\.([0-9]{1,2}))?  -> major*10000 + minor*100 + sub */
static int os_version(const char *s, unsigned *out)
{
	unsigned v[3] = {0, 0, 0};

	if (num(&s, 2, &v[0]))
		return -1;
	for (int i = 1; i < 3 && s[0] == '.' && s[1] >= '0' && s[1] <= '9'; i++) {
		s++;
		num(&s, 2, &v[i]);
	}
	*out = v[0] * 10000 + v[1] * 100 + v[2];
	return 0;
}

/* ^([0-9]{4})-([0-9]{2})-([0-9]{2})$  -> year*100 + month */
static int os_patchlevel(const char *s, unsigned *out)
{
	unsigned y, m, d;

	if (strlen(s) != 10 || num(&s, 4, &y) || *s++ != '-' || num(&s, 2, &m) ||
	    *s++ != '-' || num(&s, 2, &d) || *s)
		return -1;
	*out = y * 100 + m;
	return 0;
}

int main(int argc, char **argv)
{
	struct keymaster2_device *dev = NULL;
	const struct hw_module_t *m;
	int stage, rc, fail = 0;
	void *h;

	if (t3_no_exec()) {
		T3("FAIL km no-exec seccomp layer errno=%d\n", errno);
		return 2;
	}
	if (argc != 2 || (strcmp(argv[1], "a0") && strcmp(argv[1], "a1") && strcmp(argv[1], "a2"))) {
		T3("FAIL km usage: crownlte-t3-km a0|a1|a2\n");
		return 2;
	}
	stage = argv[1][1] - '0';
	alarm(60);	/* hard bound; the runner also kills the process group */
	T3("km client start stage=a%d uid=%u gid=%u\n", stage, getuid(), getgid());
	if (getuid() != 1000) {
		T3("FAIL km not uid 1000\n");
		return 2;
	}

	if (stage == 2) {
		char rel[PROP_VALUE_MAX] = "", spl[PROP_VALUE_MAX] = "";
		unsigned ov = 0, pl = 0;

		__system_property_get("ro.build.version.release", rel);
		__system_property_get("ro.build.version.security_patch", spl);
		rc = os_version(rel, &ov) | os_patchlevel(spl, &pl);
		T3("km props ro.build.version.release=%s ro.build.version.security_patch=%s -> os_version=%u patchlevel=%u\n",
		   rel, spl, ov, pl);
		if (rc || ov != T3_OS_VERSION || pl != T3_OS_PATCHLEVEL) {
			T3("FAIL km property mismatch (want os_version=%u patchlevel=%u); no TEE call made\n",
			   T3_OS_VERSION, T3_OS_PATCHLEVEL);
			return 3;
		}
	}

	h = dlopen("/vendor/lib64/hw/keystore.mdfpp.so", RTLD_NOW);
	if (!h) {
		T3("FAIL km dlopen keystore.mdfpp.so: %s\n", dlerror());
		return 4;
	}
	if (t3_mc_resolve(&real, RTLD_NOW | RTLD_NOLOAD))
		return 4;
	mc_ready = 1;
	m = dlsym(h, "HMI");
	if (!m || m->tag != HARDWARE_MODULE_TAG || m->module_api_version != KEYMASTER_MODULE_API_VERSION_2_0 ||
	    !m->id || strcmp(m->id, "keystore") || !m->methods || !m->methods->open) {
		T3("FAIL km HMI missing or not a keymaster2 keystore module (api=0x%x)\n",
		   m ? m->module_api_version : 0);
		return 4;
	}
	/* getHardwareFeatures equivalent: module header only, no TA round trip. */
	T3("km module id=%s name=%s author=%s module_api=0x%x hal_api=0x%x\n", m->id,
	   m->name ? m->name : "?", m->author ? m->author : "?", m->module_api_version, m->hal_api_version);

	rc = m->methods->open(m, "keymaster", (struct hw_device_t **)&dev);
	T3("km open rc=%d dev=%s trustlet_opens=%d\n", rc, dev ? "yes" : "null", trustlet_opens);
	if (rc || !dev) {
		T3("FAIL km open\n");
		return 5;
	}
	if (dev->common.tag != HARDWARE_DEVICE_TAG) {
		T3("FAIL km device tag 0x%x; not calling anything but close\n", dev->common.tag);
		fail = 1;
	}
	T3("km device version=0x%x flags=0x%x\n", dev->common.version, dev->flags);

	if (!fail && stage == 2) {
		keymaster_key_param_t p[2];
		keymaster_key_param_set_t set = {p, 2};

		memset(p, 0, sizeof(p));
		p[0].tag = KM_TAG_OS_VERSION;
		p[0].integer = T3_OS_VERSION;
		p[1].tag = KM_TAG_OS_PATCHLEVEL;
		p[1].integer = T3_OS_PATCHLEVEL;
		rc = dev->configure(dev, &set);
		T3("km configure os_version=%u patchlevel=%u rc=%d\n", T3_OS_VERSION, T3_OS_PATCHLEVEL, rc);
		fail |= rc != 0;
	}
	if (!fail && stage >= 1) {
		uint8_t e[32];

		if (t3_random(e, sizeof(e))) {
			T3("FAIL km getrandom\n");
			fail = 1;
		} else {
			rc = dev->add_rng_entropy(dev, e, sizeof(e));
			T3("km add_rng_entropy len=%u rc=%d\n", (unsigned)sizeof(e), rc);
			fail |= rc != 0;
		}
		memset(e, 0, sizeof(e));
		__asm__ volatile("" : : "r"(e) : "memory");
	}
	rc = dev->common.close(&dev->common);
	T3("km close rc=%d\n", rc);
	fail |= rc != 0;
	if (!tee_calls)
		T3("km WARN libMcClient interposition inactive: HAL TEE calls not individually logged\n");
	if (fail) {
		T3("FAIL km stage=a%d tee_calls=%d trustlet_opens=%d\n", stage, tee_calls, trustlet_opens);
		return 6;
	}
	T3("PASS km stage=a%d tee_calls=%d trustlet_opens=%d\n", stage, tee_calls, trustlet_opens);
	return 0;
}
