#!/usr/bin/env python3
"""Generate the crownlte ROM-in-RAM payload (/crownlte in the initramfs).

Input: a read-only composite root laid out as on the phone after first-stage
mount: SYSTEM image at ROOT, VENDOR at ROOT/vendor, ODM at ROOT/odm (loop-mounted
read-only from the 2026-11-03 partition backups, which match the phone).

Output (OUT/crownlte):
  manifest.txt      P/W/D/F/L/A/R lines verified by romram.h before init runs
  sanitized/*.rc    disarmed copies, bind-mounted read-only over originals
  init.diag.rc, probe.sh, init_user0.sh, cmdline-extra, deadline_seconds,
  bypass_enabled, empty, payload-id
and OUT/sanitize-report.txt (unified diffs + every dangerous-pattern decision).

The generator refuses to finish if any rc line matches a storage-mutating
pattern that no explicit rule handles.
"""
import difflib, hashlib, os, re, shlex, stat, sys
from pathlib import Path

ROOT = Path(sys.argv[1])
OUT = Path(sys.argv[2])
TEMPLATES = Path(__file__).resolve().parent / 'templates'
DEADLINE = os.environ.get('DEADLINE', '300')
# SHOWCASE=1: probe.sh marks setup complete (RAM /data only) and opens Settings
# About phone, then the Android version page, for photos of the running build.
TEE_T2 = os.environ.get('TEE_T2', '0') == '1'
if TEE_T2 and DEADLINE != '600':
    raise SystemExit('TEE_T2 requires DEADLINE=600')
SHOWCASE = os.environ.get('SHOWCASE', '0') == '1'

PARTS = [('SYSTEM', '/', 'SYSTEM.img'), ('VENDOR', '/vendor', 'VENDOR.img'), ('ODM', '/odm', 'ODM.img')]
BACKUPS = Path('/mnt/ssd/host-builds/kernel-upgrade/backups-20261103/partitions')
WALKS = ['/system/etc/init', '/system/system_ext/etc/init', '/system/product/etc/init', '/vendor/etc/init']
ABSENT = ['/odm/etc/init', '/init.samsungexynos9810.rc', '/init.samsung.rc']
EXTRA_FILES = ['/init.environ.rc', '/system/build.prop', '/vendor/build.prop', '/odm/etc/build.prop',
               '/vendor/etc/fstab.samsungexynos9810', '/system/bin/init', '/system/etc/ueventd.rc',
               '/vendor/etc/ueventd.rc', '/system/etc/selinux/plat_sepolicy.cil',
               '/vendor/etc/selinux/vendor_sepolicy.cil',
               # v6: TEE client chokepoints and VINTF manifests (see EMPTY / VINTF_DROP)
               '/vendor/lib64/hw/keystore.mdfpp.so', '/vendor/lib64/libMcClient.so',
               '/vendor/lib/libMcClient.so', '/vendor/etc/vintf/manifest.xml',
               '/vendor/etc/vintf/manifest/android.hardware.biometrics.fingerprint-service.samsung.xml',
               # v11: feature file whose service would wait for an absent HAL (see FEATURE_DROP)
               '/vendor/etc/permissions/android.hardware.fingerprint.xml']
EMPTY = {
    '/vendor/etc/init/vendor_flash_recovery.rc': 'service runs /vendor/bin/install-recovery.sh (rewrites RECOVERY)',
    '/system/etc/init/misctrl.rc': 'service misctrl (root, writes the misc partition)',
    '/system/etc/init/uncrypt.rc': 'services uncrypt/setup-bcb/clear-bcb (write the misc partition BCB)',
    # v6: Trustonic TEE clients. The ROM stage already refuses to run if a TEE
    # is present; these keep every TEE client from starting at all.
    '/vendor/etc/init/mobicore.rc': 'service mobicore (mcDriverDaemon, Trustonic TEE daemon)',
    '/vendor/etc/init/android.hardware.gatekeeper@1.0-service.rc':
        'service vendor.gatekeeper-1-0 (gatekeeper.exynos9810.so, Trustonic TA client)',
    '/vendor/etc/init/android.hardware.drm@1.2-service.widevine.rc':
        'service vendor.drm-widevine-hal-1-2 (liboemcrypto, Widevine L1 TA client)',
    '/vendor/etc/init/vendor.samsung.hardware.security.widevine.keyprovisioning@1.0-service.rc':
        'service vendor.wvkprov_server_hal (Widevine key provisioning, TEE)',
    '/vendor/etc/init/android.hardware.biometrics.fingerprint-service.samsung.rc':
        'service vendor.fingerprint-default (libbauthserver/libbauthtzcommon, fingerprint TA client)',
    '/vendor/lib64/hw/keystore.mdfpp.so':
        'MDFPP keymaster TA client module (ro.hardware.keystore=mdfpp). Masked, hw_get_module_by_class() '
        'fails and android.hardware.keymaster@3.0-impl logs "Could not find any keystore module, using '
        'software-only implementation."; km_compat then uses that insecure HAL as the TEE device',
    '/vendor/lib64/libMcClient.so': 'Trustonic client library (64-bit): every TEE client fails to load',
    '/vendor/lib/libMcClient.so': 'Trustonic client library (32-bit): every TEE client fails to load',
    # v11: Lineage HALs whose hardware nodes do not exist on 6.12. They keep
    # running but register nothing, so LineageHardwareManager's
    # waitForDeclaredService() blocked system_server's main thread (Watchdog).
    '/vendor/etc/init/vendor.lineage.touch-service.samsung.rc':
        'service vendor.touch-hal (needs /sys/class/sec/tsp/cmd, /sys/class/sec/sec_epen; touch is off in the DT)',
    '/vendor/etc/init/vendor.lineage.livedisplay-service.samsung-exynos.rc':
        'service vendor.livedisplay-hal-samsung-exynos (needs /sys/class/mdnie/mdnie/*; no mdnie driver on 6.12)',
}
# v6: HALs whose services are disabled above are also removed from the device
# VINTF manifest, so nothing blocks in getService()/waitForDeclaredService().
VINTF_DROP = {
    '/vendor/etc/vintf/manifest.xml': ['android.hardware.drm', 'android.hardware.gatekeeper',
                                       'vendor.samsung.hardware.security.widevine.keyprovisioning',
                                       # v11: hardware absent, see EMPTY
                                       'vendor.lineage.touch', 'vendor.lineage.livedisplay'],
    '/vendor/etc/vintf/manifest/android.hardware.biometrics.fingerprint-service.samsung.xml':
        ['android.hardware.biometrics.fingerprint'],
}
# v11: system features whose framework service would wait forever for a HAL
# that cannot exist in this boot. android.hardware.fingerprint makes SystemServer
# start FingerprintService; with no real IFingerprint declared (its HAL is a TEE
# client, disabled since v6) it falls back to the "virtual" instance and waits
# for IVirtualHal/virtual, which this build does not ship. Removing the feature
# is what a device without a usable fingerprint sensor declares.
FEATURE_DROP = {
    '/vendor/etc/permissions/android.hardware.fingerprint.xml': ['android.hardware.fingerprint'],
}
# v14: read-only property overrides, applied by replacing the verified prop
# file in the container. Each key must be defined exactly once in that file,
# with the expected old value, and in no other prop file init loads. The
# replacement differs from the original in exactly those lines.
#  - ro.vendor.ddk.set.afbc 1 -> 0: libexynosdisplay (HWC client target) and
#    gralloc.universal9810 allocate AFBC-compressed buffers when it is 1. The
#    6.12 DPU path shows a black panel with the AFBC client target while the
#    q48 kernel display matrix reaches the panel on every window/channel, so
#    v14 tests the linear (uncompressed) client target.
PROP_SET = {
    '/vendor/build.prop': [('ro.vendor.ddk.set.afbc', '1', '0')],
}
# Other prop files init loads (must not define a PROP_SET key).
PROP_FILES = ['/system/build.prop', '/system/system_ext/etc/build.prop',
              '/system/product/etc/build.prop', '/system/etc/prop.default', '/vendor/default.prop',
              '/vendor/build.prop', '/odm/etc/build.prop', '/vendor/odm/etc/build.prop']
# v6: init.rc execs that would block boot on a TEE-backed HAL run in the background.
BACKGROUND_EXECS = {('/system/bin/vdc', 'keymaster', 'earlyBootEnded')}
DISARM_CMDS = {'mount_all', 'swapon_all', 'umount_all', 'remount_userdata'}
DANGER_BINS = re.compile(r'(install-recovery|flash_recovery|misctrl|e2fsck|fsck|mke2fs|make_f2fs|mkfs|'
                         r'resize2fs|tune2fs|sgdisk|blkdiscard|sload_f2fs|e2fsdroid|uncrypt|^dd$)')
INIT_USER0 = '    exec u:r:su:s0 root root -- /system/bin/sh /dev/crownlte/init_user0.sh'
CMDLINE_EXTRA = ('androidboot.hardware=samsungexynos9810 androidboot.selinux=permissive '
                 'androidboot.init_rc=/dev/crownlte/init.diag.rc androidboot.mode=normal '
                 'androidboot.verifiedbootstate=orange androidboot.flash.locked=0 '
                 'androidboot.serialno=CROWNLTEROMRAM androidboot.bootloader=N960FROMRAMDIAG '
                 'androidboot.debug_level=0x4f4c androidboot.boot_devices=11120000.ufs')

sha = lambda b: hashlib.sha256(b).hexdigest()
report = []


def prop_set(cpath, text):
    # Change 'key=old' to 'key=new'; the key must appear exactly once in cpath.
    lines = text.splitlines(keepends=True)
    out = list(lines)
    for key, old, new in PROP_SET[cpath]:
        hits = [i for i, l in enumerate(lines)
                if l.split('#', 1)[0].strip().split('=', 1)[0].strip() == key]
        if len(hits) != 1:
            raise SystemExit(f'PROP {cpath} {key}: {len(hits)} definitions')
        i = hits[0]
        if lines[i].rstrip('\r\n') != f'{key}={old}':
            raise SystemExit(f'PROP {cpath} {key}: line is {lines[i]!r}, expected {key}={old}')
        out[i] = f'{key}={new}\n'
        report.append(f'{cpath}:{i + 1}: PROP {key}={old} -> {key}={new}')
    changed = [i for i in range(len(lines)) if lines[i] != out[i]]
    if len(changed) != len(PROP_SET[cpath]) or len(out) != len(lines):
        raise SystemExit(f'PROP {cpath}: unexpected change set {changed}')
    return ''.join(out)


def feature_drop(cpath, text):
    # Remove <feature name="X" .../> lines from a permissions file; each exactly once.
    new = text
    for name in FEATURE_DROP[cpath]:
        pat = re.compile(r'[ \t]*<feature\s+name="' + re.escape(name) + r'"\s*/>[ \t]*\n')
        if len(pat.findall(new)) != 1:
            raise SystemExit(f'FEATURE drop {cpath} {name}: not exactly one match')
        new = pat.sub('', new)
        report.append(f'{cpath}: FEATURE drop {name}')
    import xml.dom.minidom
    xml.dom.minidom.parseString(new.encode())
    if '<permissions>' not in new:
        raise SystemExit('FEATURE result lost the permissions element ' + cpath)
    return new


def vintf_drop(cpath, text):
    # Remove whole <hal>...</hal> blocks by <name>; each name exactly once.
    names = VINTF_DROP[cpath]
    hit = {n: 0 for n in names}

    def cut(m):
        nm = re.search(r'<name>\s*([^<\s]+)\s*</name>', m.group(0))
        if nm and nm.group(1) in hit:
            hit[nm.group(1)] += 1
            report.append(f'{cpath}: VINTF drop {nm.group(1)}: ' + ' '.join(m.group(0).split()))
            return ''
        return m.group(0)

    new = re.sub(r'[ \t]*<hal\b[^>]*>.*?</hal>[ \t]*\n', cut, text, flags=re.S)
    for n, c in hit.items():
        if c != 1:
            raise SystemExit(f'VINTF drop {cpath} {n}: {c} matches')
    if '<manifest' not in new or '</manifest>' not in new:
        raise SystemExit('VINTF result lost the manifest element ' + cpath)
    return new


def host(cpath):
    return ROOT / cpath.lstrip('/')


def sanitize(cpath, text):
    """Return (new_text or None, decisions). Raises on unhandled danger."""
    out, changed, decisions = [], False, []
    for no, line in enumerate(text.splitlines(keepends=True), 1):
        s = line.strip()
        if not s or s.startswith('#'):
            out.append(line)
            continue
        try:
            tok = shlex.split(s, comments=False, posix=True)
        except ValueError:
            tok = s.split()
        cmd = tok[0] if tok else ''
        why = None
        if cmd in DISARM_CMDS:
            why = 'disarm ' + cmd
        elif cmd == 'mount' and any(t.startswith('/dev/block') for t in tok[1:]):
            why = 'disarm block-device mount'
        elif cmd == 'write' and len(tok) > 1 and tok[1].startswith('/dev/block'):
            why = 'disarm block-device write'
        elif cmd in ('exec', 'exec_background') and any(DANGER_BINS.search(os.path.basename(t)) for t in tok[1:] if t.startswith('/')):
            why = 'disarm storage tool exec'
        elif cmd == 'exec' and '--' in tok and tuple(tok[tok.index('--') + 1:]) in BACKGROUND_EXECS:
            new = line.replace('exec ', 'exec_background ', 1)
            out.append('    # crownlte-rom-ram: ' + s + ' -> exec_background (TEE-backed HAL must not block boot)\n')
            out.append(new)
            decisions.append(f'{cpath}:{no}: exec -> exec_background: {s}')
            changed = True
            continue
        elif cmd == 'init_user0':
            out.append('    # crownlte-rom-ram: ' + s + ' -> bounded vdc call without reboot-to-recovery\n')
            out.append(INIT_USER0 + '\n')
            decisions.append(f'{cpath}:{no}: replace init_user0 with {INIT_USER0.strip()}')
            changed = True
            continue
        elif cmd == 'service' and len(tok) > 2 and DANGER_BINS.search(os.path.basename(tok[2])):
            if cpath not in EMPTY:
                raise SystemExit(f'UNHANDLED dangerous service {cpath}:{no}: {s}')
            decisions.append(f'{cpath}:{no}: service handled by EMPTY overlay: {s}')
        elif cmd in ('installkey',):
            decisions.append(f'{cpath}:{no}: keep {s} (no-op: ro.crypto.type never set)')
        if why:
            out.append('    # crownlte-rom-ram ' + why + ': ' + s + '\n')
            decisions.append(f'{cpath}:{no}: {why}: {s}')
            changed = True
        else:
            out.append(line)
    return (''.join(out) if changed else None), decisions


def main():
    assert not OUT.exists(), OUT
    pay = OUT / 'crownlte'
    (pay / 'sanitized').mkdir(parents=True)
    lines = ['# crownlte ROM-in-RAM manifest (generated by gen_payload.py)']
    if TEE_T2:
        # Pin the executable and tracing tool in the verified manifest.
        EXTRA_FILES.extend(['/vendor/bin/mcDriverDaemon', '/system/bin/strace'])
    for name, mp, img in PARTS:
        size = (BACKUPS / img).stat().st_size
        lines.append(f'P {name} {size} {mp}')
    for w in WALKS:
        lines.append(f'W {w}')
    repls = {}
    seen = set()

    def add_file(cpath, action_override=None):
        p = host(cpath)
        data = p.read_bytes()
        action = 'keep'
        if cpath in EMPTY:
            action = 'empty'
            report.append(f'{cpath}: EMPTY overlay: {EMPTY[cpath]}')
            if cpath.endswith('.rc'):
                sanitize(cpath, data.decode('utf-8', 'replace'))
        elif cpath in VINTF_DROP or cpath in FEATURE_DROP or cpath in PROP_SET:
            if cpath in VINTF_DROP:
                new = vintf_drop(cpath, data.decode('utf-8'))
                kind, ext = 'vintf_', '.xml'
            elif cpath in FEATURE_DROP:
                new = feature_drop(cpath, data.decode('utf-8'))
                kind, ext = 'feature_', '.xml'
            else:
                new = prop_set(cpath, data.decode('utf-8'))
                kind, ext = 'prop_', '.prop'
            # romram.h reads replacement names with %63s: keep them short
            rname = kind + sha(cpath.encode())[:16] + ext
            report.append(f'{cpath}: replacement sanitized/{rname}')
            (pay / 'sanitized' / rname).write_text(new)
            repls[rname] = new.encode()
            action = 'replace:' + rname
            report.append(''.join(difflib.unified_diff(
                data.decode().splitlines(True), new.splitlines(True), cpath, 'sanitized/' + rname)))
        elif cpath.endswith('.rc') or cpath == '/init.environ.rc':
            new, dec = sanitize(cpath, data.decode('utf-8'))
            report.extend(dec)
            if new is not None:
                rname = cpath.strip('/').replace('/', '_')
                (pay / 'sanitized' / rname).write_text(new)
                repls[rname] = new.encode()
                action = 'replace:' + rname
                report.append(''.join(difflib.unified_diff(
                    data.decode().splitlines(True), new.splitlines(True), cpath, 'sanitized/' + rname)))
        lines.append(f'F {sha(data)} {len(data)} {action} {cpath}')
        seen.add(cpath)

    for w in WALKS:
        for dirpath, dirnames, filenames in os.walk(host(w), followlinks=False):
            dirnames.sort()
            rel = '/' + str(Path(dirpath).relative_to(ROOT))
            lines.append(f'D {rel}')
            for fn in sorted(filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]):
                full = Path(dirpath) / fn
                c = rel + '/' + fn
                st = os.lstat(full)
                if stat.S_ISLNK(st.st_mode):
                    lines.append(f'L {c} {os.readlink(full)}')
                elif stat.S_ISREG(st.st_mode):
                    add_file(c)
                else:
                    raise SystemExit('unexpected type ' + c)
    for c in EXTRA_FILES:
        if c not in seen:
            add_file(c)
    for c in ABSENT:
        assert not os.path.lexists(host(c)), c
        lines.append(f'A {c}')
    for c in EMPTY:
        assert c in seen, 'EMPTY target not found ' + c
    for c in VINTF_DROP:
        assert c in seen, 'VINTF target not found ' + c
    for c in FEATURE_DROP:
        assert c in seen, 'FEATURE target not found ' + c
    assert not set(VINTF_DROP) & set(FEATURE_DROP)
    assert not set(PROP_SET) & (set(VINTF_DROP) | set(FEATURE_DROP))
    for c in PROP_SET:
        assert c in seen, 'PROP target not found ' + c
    keys = {k for v in PROP_SET.values() for k, _, _ in v}
    for f in PROP_FILES:
        if f in PROP_SET or not os.path.lexists(host(f)):
            continue
        for l in host(f).read_text(errors='replace').splitlines():
            k = l.split('#', 1)[0].strip().split('=', 1)[0].strip()
            assert k not in keys, f'PROP key {k} also defined in {f}'
    assert any('exec -> exec_background' in r and 'earlyBootEnded' in r for r in report), \
        'vdc keymaster earlyBootEnded not found'
    # build type must allow androidboot.selinux=permissive
    bp = host('/system/build.prop').read_text()
    assert 'ro.build.type=userdebug' in bp, 'system is not userdebug'
    for name, body in sorted(repls.items()):
        assert len(name) <= 63, 'replacement name too long for romram.h: ' + name
        lines.append(f'R {sha(body)} {len(body)} {name}')
    manifest = ('\n'.join(lines) + '\n').encode()
    (pay / 'manifest.txt').write_bytes(manifest)
    for t in ('init.diag.rc', 'probe.sh', 'init_user0.sh'):
        (pay / t).write_bytes((TEMPLATES / t).read_bytes())
    if TEE_T2:
        (pay / 'tee_t2').write_text('1\n')
        (pay / 'tee-t2.sh').write_bytes((TEMPLATES / 'tee-t2.sh').read_bytes())
        with (pay / 'init.diag.rc').open('a') as f:
            f.write('''
# T2: original mobicore.rc stays empty; no vendor driver preload list.
on post-fs-data
    start crownlte_tee_t2

service crownlte_tee_t2 /system/bin/sh /dev/crownlte/tee-t2.sh
    user root
    group root system log readproc
    seclabel u:r:su:s0
    disabled
    oneshot
''')
    (pay / 'cmdline-extra').write_text(CMDLINE_EXTRA + (' androidboot.crownlte_showcase=1' if SHOWCASE else '') + '\n')
    (pay / 'deadline_seconds').write_text(DEADLINE + '\n')
    (pay / 'bypass_enabled').write_text('1\n')
    (pay / 'empty').write_bytes(b'')
    (pay / 'payload-id').write_text(
        f'crownlte-rom-ram payload; manifest sha256 {sha(manifest)}; deadline {DEADLINE}s; '
        f'bypass enabled; showcase {int(SHOWCASE)}; rc replacements {sorted(repls)}; empties {sorted(EMPTY)}\n')
    (OUT / 'sanitize-report.txt').write_text('\n'.join(report) + '\n')
    n = sum(1 for l in lines if l[:1] in 'FLDA')
    print(f'manifest entries={n} replacements={len(repls)} empties={len(EMPTY)} sha={sha(manifest)}')


main()
