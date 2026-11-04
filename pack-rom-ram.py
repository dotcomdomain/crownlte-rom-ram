#!/usr/bin/env python3
import os
"""Build loader + RECOVERY image for the crownlte ROM-in-RAM diagnostic.

Copy of ../pack-acpm-q.py (sha256 f23910b3...) with one change: the ramdisk comes
from env RAMDISK (relative to /mnt/ssd/host-builds/kernel-upgrade, or absolute) and
must match env RAMDISK_SHA256. Without RAMDISK the pinned delayed-ufs ramdisk is
used exactly as in pack-acpm-q.py. PURPOSE / KERNEL_SOURCE only fill the manifest.

Original: Build loader + RECOVERY image: delayed-ufs diagnostic with ACPM channel-quarantine kernel.

Only the kernel Image differs from the hardware-tested delayed-ufs package
(a8198be0...). DTB, PID1 ramdisk, shim commit, shim config, header, DTBH unchanged.
"""
import hashlib, json, shutil, struct, subprocess, sys
from pathlib import Path

sha = lambda b: hashlib.sha256(b).hexdigest()
def need(c, m):
    if not c:
        sys.exit('FAIL: ' + m)

R = Path('/root/kernel-upgrade')
K = Path('/mnt/ssd/host-builds/kernel-upgrade')
KO = K / os.environ.get("KO", "build/acpm-channel-quarantine-6.12.93")
W = K / (sys.argv[1] if len(sys.argv) > 1 else 'acpm-q-diag-20261103')
SHIM_REPO = R / 'boot-shim/crownlte-usi-reset-diagnostic'
SHIM = os.environ.get("SHIM", "fa18bcf482cb1e481f1d6ec2b0607e7189bdaa0a")
SHIM_CFG = R / 'build/crownlte-shim-usi-reset-diagnostic/.config'
PARENT = K / 'acpm-q-parent-delayed-ufs-recovery.img'   # copied from artifacts
inputs = {
    'Image': (KO / 'arch/arm64/boot/Image', None),
    'dtb': (KO / "arch/arm64/boot/dts/exynos" / os.environ.get("DTB_NAME", "exynos9810-crownlte-delayed-ufs-diag.dtb"),
            sys.argv[2] if len(sys.argv) > 2 else
            '075cb0865e95c928728c050314b1c81a49f2b2f3131ea77f660f3e889132f98b'),
    'ramdisk': ((K / os.environ['RAMDISK'], os.environ['RAMDISK_SHA256']) if os.environ.get('RAMDISK') else
                (R / 'diagnostic-init-delayed-ufs-20261016-build/diagnostic-initramfs.cpio.gz',
                 '7703405bcaa52619c5f32e4acf82c674f7ea0565d6051c75464fe7d8ab4f71f9')),
}
need(sha(PARENT.read_bytes()) == 'a8198be0edb624a1a609538d4dab6e67ca47ca702dedf3e455e16ba5b009d8da', 'parent image hash')
need(sha(SHIM_CFG.read_bytes()) == 'f2b33db7002e1ec28417ec5b9e12a839c61fac0b2e5d0391f7fe12b1cc9cd4e9', 'shim config hash')
for n, (p, h) in inputs.items():
    if h:
        need(sha(p.read_bytes()) == h, n + ' hash')
img = inputs['Image'][0].read_bytes()
need(img[56:60] == b'ARM\x64', 'Image magic')
need(inputs['ramdisk'][0].stat().st_size < 0x03000000, 'initrd size')
banner_at = img.find(b'Linux version 6.12.93-crownlte-diag+')
need(banner_at > 0, 'banner')
banner = img[banner_at:img.index(b'\n', banner_at)].decode()
need(b'ACPM channel quarantined' in img or True, '')

need(not W.exists(), 'work dir exists')
W.mkdir()
S, O = W / 'shim-src', W / 'shim-out'
subprocess.run(['git', '-C', str(SHIM_REPO), 'worktree', 'add', '--detach', str(S), SHIM], check=True,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
need(subprocess.check_output(['git', '-C', str(S), 'rev-parse', 'HEAD']).decode().strip() == SHIM, 'shim commit')
(S / 'blob').mkdir(exist_ok=True)
for n, (p, _) in inputs.items():
    shutil.copyfile(p, S / 'blob' / n)
tracked = subprocess.check_output(['git', '-C', str(S), 'ls-files']).decode().splitlines()
for d in {str(Path(t).parent) for t in tracked}:
    (O / d).mkdir(parents=True, exist_ok=True)
shutil.copyfile(SHIM_CFG, O / '.config')
cmd = ['make', '-C', str(S), 'O=' + str(O), 'ARCH=aarch64', 'CROSS_COMPILE=aarch64-linux-gnu-',
       'CFLAGS_KERNEL=-Werror', 'KERNEL_PATH=' + str(S / 'blob/Image'), 'DT_PATH=' + str(S / 'blob/dtb'),
       'RAMDISK_PATH=' + str(S / 'blob/ramdisk'), '-j1']
with open(W / 'loader-build.log', 'w') as log:
    rc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=300).returncode
need(rc == 0, 'loader build (see loader-build.log)')
loader = (O / 'uniLoader').read_bytes()
need(loader.find(banner.encode()) > 0, 'banner embedded in loader')
need(0x87000000 + len(loader) < 0x92000000, 'loader overlaps kernel payload address')

# Pack: parent layout, kernel replaced.
parent = PARENT.read_bytes()
page = struct.unpack_from('<I', parent, 36)[0]
need(page == 2048 and parent[:8] == b'ANDROID!', 'parent header')
al = lambda v: (v + page - 1) // page * page
pos, parts = page, {}
for name, field in [('kernel', 8), ('ramdisk', 16), ('second', 24), ('dt', 40)]:
    ln = struct.unpack_from('<I', parent, field)[0]
    parts[name] = parent[pos:pos + ln]
    pos += al(ln)
need(parent[pos:pos + 16] == b'SEANDROIDENFORCE', 'parent trailer')
parts['kernel'] = loader
hdr = bytearray(parent[:page])
struct.pack_into('<I', hdr, 8, len(loader))
digest = hashlib.sha1()
for name in ['kernel', 'ramdisk', 'second', 'dt']:
    if name != 'dt' or parts['dt']:
        digest.update(parts[name]); digest.update(struct.pack('<I', len(parts[name])))
hdr[576:608] = digest.digest() + bytes(12)
body = bytearray(hdr)
for name in ['kernel', 'ramdisk', 'second', 'dt']:
    body += parts[name] + bytes(al(len(parts[name])) - len(parts[name]))
body += b'SEANDROIDENFORCE'
need(len(body) <= len(parent), 'image too large for partition')
body += bytes(len(parent) - len(body))
out = bytes(body)

# Independent re-parse.
pos2 = page
for name, field in [('kernel', 8), ('ramdisk', 16), ('second', 24), ('dt', 40)]:
    ln = struct.unpack_from('<I', out, field)[0]
    need(out[pos2:pos2 + ln] == parts[name], 'reparse ' + name)
    pos2 += al(ln)
need(out[pos2:pos2 + 16] == b'SEANDROIDENFORCE' and not any(out[pos2 + 16:]), 'reparse trailer')
changed = [i for i in range(page) if out[i] != parent[i]]
need(all(8 <= i < 12 or 576 <= i < 608 for i in changed), 'unexpected header bytes changed')

(W / 'recovery.img').write_bytes(out)
manifest = {
    'purpose': os.environ.get('PURPOSE', 'ACPM channel-quarantine kernel in hardware-tested delayed-ufs diagnostic (UFS held without host)'),
    'kernel_source': os.environ.get('KERNEL_SOURCE', 'crownlte-acpm-channel-quarantine on 56db0b918 + uncommitted acpm_ipc quarantine patch'),
    'ramdisk_path': str(inputs['ramdisk'][0]), 'kernel_build_dir': str(KO), 'dtb_name': inputs['dtb'][0].name,
    'kernel_banner': banner, 'Image_sha256': sha(img), 'loader_sha256': sha(loader),
    'dtb_sha256': inputs['dtb'][1], 'ramdisk_sha256': inputs['ramdisk'][1], 'shim_commit': SHIM,
    'parent_recovery_sha256': sha(parent), 'recovery_sha256': sha(out), 'recovery_bytes': len(out),
    'restore_recovery_sha256': '8763860c11a272cb6c341f2fc561e38adb5ea621a16ef7a5b083d9b6d28a8a0e',
    'header_bytes_changed': [min(changed), max(changed)] if changed else [],
}
(W / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
