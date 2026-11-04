#!/usr/bin/env python3
"""Create rom-ram/pack-rom-ram.py from the integrator's pack-acpm-q.py (unchanged)."""
import hashlib
from pathlib import Path

K = Path('/mnt/ssd/host-builds/kernel-upgrade')
src = (K / 'pack-acpm-q.py').read_bytes()
assert hashlib.sha256(src).hexdigest() == 'f23910b3b3a75227f382a94f2902f468608cf0b21572007164c09c9b59357a65'
s = src.decode()


def rep(a, b):
    global s
    assert s.count(a) == 1, a
    s = s.replace(a, b)


rep('"""Build loader + RECOVERY image: delayed-ufs diagnostic with ACPM channel-quarantine kernel.',
    '"""Build loader + RECOVERY image for the crownlte ROM-in-RAM diagnostic.\n\n'
    'Copy of ../pack-acpm-q.py (sha256 f23910b3...) with one change: the ramdisk comes\n'
    'from env RAMDISK (relative to /mnt/ssd/host-builds/kernel-upgrade, or absolute) and\n'
    'must match env RAMDISK_SHA256. Without RAMDISK the pinned delayed-ufs ramdisk is\n'
    'used exactly as in pack-acpm-q.py. PURPOSE / KERNEL_SOURCE only fill the manifest.\n\n'
    'Original: Build loader + RECOVERY image: delayed-ufs diagnostic with ACPM channel-quarantine kernel.')
rep("""    'ramdisk': (R / 'diagnostic-init-delayed-ufs-20261016-build/diagnostic-initramfs.cpio.gz',
                '7703405bcaa52619c5f32e4acf82c674f7ea0565d6051c75464fe7d8ab4f71f9'),""",
    """    'ramdisk': ((K / os.environ['RAMDISK'], os.environ['RAMDISK_SHA256']) if os.environ.get('RAMDISK') else
                (R / 'diagnostic-init-delayed-ufs-20261016-build/diagnostic-initramfs.cpio.gz',
                 '7703405bcaa52619c5f32e4acf82c674f7ea0565d6051c75464fe7d8ab4f71f9')),""")
rep("""    'purpose': 'ACPM channel-quarantine kernel in hardware-tested delayed-ufs diagnostic (UFS held without host)',
    'kernel_source': 'crownlte-acpm-channel-quarantine on 56db0b918 + uncommitted acpm_ipc quarantine patch',""",
    """    'purpose': os.environ.get('PURPOSE', 'ACPM channel-quarantine kernel in hardware-tested delayed-ufs diagnostic (UFS held without host)'),
    'kernel_source': os.environ.get('KERNEL_SOURCE', 'crownlte-acpm-channel-quarantine on 56db0b918 + uncommitted acpm_ipc quarantine patch'),
    'ramdisk_path': str(inputs['ramdisk'][0]), 'kernel_build_dir': str(KO), 'dtb_name': inputs['dtb'][0].name,""")
out = K / 'rom-ram/pack-rom-ram.py'
assert not out.exists()
out.write_text(s)
out.chmod(0o755)
print(hashlib.sha256(s.encode()).hexdigest(), out)
