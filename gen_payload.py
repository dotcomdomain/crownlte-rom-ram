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

PARTS = [('SYSTEM', '/', 'SYSTEM.img'), ('VENDOR', '/vendor', 'VENDOR.img'), ('ODM', '/odm', 'ODM.img')]
BACKUPS = Path('/mnt/ssd/host-builds/kernel-upgrade/backups-20261103/partitions')
WALKS = ['/system/etc/init', '/system/system_ext/etc/init', '/system/product/etc/init', '/vendor/etc/init']
ABSENT = ['/odm/etc/init', '/init.samsungexynos9810.rc', '/init.samsung.rc']
EXTRA_FILES = ['/init.environ.rc', '/system/build.prop', '/vendor/build.prop', '/odm/etc/build.prop',
               '/vendor/etc/fstab.samsungexynos9810', '/system/bin/init', '/system/etc/ueventd.rc',
               '/vendor/etc/ueventd.rc', '/system/etc/selinux/plat_sepolicy.cil',
               '/vendor/etc/selinux/vendor_sepolicy.cil']
EMPTY = {
    '/vendor/etc/init/vendor_flash_recovery.rc': 'service runs /vendor/bin/install-recovery.sh (rewrites RECOVERY)',
    '/system/etc/init/misctrl.rc': 'service misctrl (root, writes the misc partition)',
}
DISARM_CMDS = {'mount_all', 'swapon_all', 'umount_all', 'remount_userdata'}
DANGER_BINS = re.compile(r'(install-recovery|flash_recovery|misctrl|e2fsck|fsck|mke2fs|make_f2fs|mkfs|'
                         r'resize2fs|tune2fs|sgdisk|blkdiscard|sload_f2fs|e2fsdroid|^dd$)')
INIT_USER0 = '    exec u:r:su:s0 root root -- /system/bin/sh /dev/crownlte/init_user0.sh'
CMDLINE_EXTRA = ('androidboot.hardware=samsungexynos9810 androidboot.selinux=permissive '
                 'androidboot.init_rc=/dev/crownlte/init.diag.rc androidboot.mode=normal '
                 'androidboot.verifiedbootstate=orange androidboot.flash.locked=0 '
                 'androidboot.serialno=CROWNLTEROMRAM androidboot.bootloader=N960FROMRAMDIAG '
                 'androidboot.debug_level=0x4f4c androidboot.boot_devices=11120000.ufs')

sha = lambda b: hashlib.sha256(b).hexdigest()
report = []


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
            sanitize(cpath, data.decode('utf-8', 'replace'))
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
    # build type must allow androidboot.selinux=permissive
    bp = host('/system/build.prop').read_text()
    assert 'ro.build.type=userdebug' in bp, 'system is not userdebug'
    for name, body in sorted(repls.items()):
        lines.append(f'R {sha(body)} {len(body)} {name}')
    manifest = ('\n'.join(lines) + '\n').encode()
    (pay / 'manifest.txt').write_bytes(manifest)
    for t in ('init.diag.rc', 'probe.sh', 'init_user0.sh'):
        (pay / t).write_bytes((TEMPLATES / t).read_bytes())
    (pay / 'cmdline-extra').write_text(CMDLINE_EXTRA + '\n')
    (pay / 'deadline_seconds').write_text(DEADLINE + '\n')
    (pay / 'bypass_enabled').write_text('1\n')
    (pay / 'empty').write_bytes(b'')
    (pay / 'payload-id').write_text(
        f'crownlte-rom-ram payload; manifest sha256 {sha(manifest)}; deadline {DEADLINE}s; '
        f'bypass enabled; rc replacements {sorted(repls)}; empties {sorted(EMPTY)}\n')
    (OUT / 'sanitize-report.txt').write_text('\n'.join(report) + '\n')
    n = sum(1 for l in lines if l[:1] in 'FLDA')
    print(f'manifest entries={n} replacements={len(repls)} empties={len(EMPTY)} sha={sha(manifest)}')


main()
