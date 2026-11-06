#!/usr/bin/env python3
"""Verify the T3 stage DTBs against tee-t3dbg (06a6cf36): decompiled, the only
difference must be the stage's pin properties, and every pin must be the UUID
(MCLF header bytes 24..39) + SHA-256 of the vendor file it names."""
import hashlib, re, subprocess, sys
from pathlib import Path

K = Path('/mnt/ssd/host-builds/kernel-upgrade')
DTC = '/dev/shm/build-tee3/scripts/dtc/dtc'
KO = K / 'panel-bright-work/ko-tee-t3pin/arch/arm64/boot/dts/exynos'
BASE = K / 'panel-bright-work/dtb/exynos9810-crownlte-romram-tee-t3dbg.dtb'
REG = K / 'rom-ram/testroot/vendor/app/mcRegistry'
KM, GK = 'ffffffff00000000000000000000003e.tlbin', '08130000000000000000000000000000.tlbin'
SEC, TIMA, CM = ('FFFFFFFF000000000000000000000001.drbin', 'ffffffffd0000000000000000000000a.tlbin',
                 'ffffffffd00000000000000000000016.tlbin')
STAGES = {'t3a0': ([KM], []), 't3a1': ([KM], []), 't3a2': ([KM], [SEC, TIMA, CM]),
          't3b0': ([GK], []), 't3b1': ([GK], [CM])}


def dts(p):
    return subprocess.run([DTC, '-I', 'dtb', '-O', 'dts', '-q', str(p)], check=True,
                          capture_output=True, text=True).stdout.splitlines()


def pin(f):
    b = (REG / f).read_bytes()
    return b[24:40] + hashlib.sha256(b).digest()


def prop(lines, name):
    # dtc prints a 4-byte-multiple byte string as big-endian cells <0x.. ..>
    for ln in lines:
        m = re.match(r'\s*' + re.escape(name) + r' = <([0-9a-fx ]+)>;', ln)
        if m:
            return b''.join(int(c, 16).to_bytes(4, 'big') for c in m.group(1).split())
        m = re.match(r'\s*' + re.escape(name) + r' = \[([0-9a-f ]+)\];', ln)
        if m:
            return bytes.fromhex(m.group(1).replace(' ', ''))
    return None


assert hashlib.sha256(BASE.read_bytes()).hexdigest().startswith('06a6cf36')
base = dts(BASE)
ok = True
for st, (tl, drv) in STAGES.items():
    f = KO / f'exynos9810-crownlte-romram-tee-{st}.dtb'
    lines = dts(f)
    added = [l for l in lines if l not in base]
    removed = [l for l in base if l not in lines]
    want_tl = b''.join(pin(x) for x in tl)
    want_drv = b''.join(pin(x) for x in drv)
    got_tl, got_drv = prop(lines, 'samsung,tee-trustlet-allow'), prop(lines, 'samsung,tee-driver-allow')
    good = (not removed and len(added) == (2 if drv else 1) and got_tl == want_tl and
            (got_drv == want_drv if drv else got_drv is None) and
            len(lines) == len(base) + len(added))
    ok &= good
    print(f'{st} {hashlib.sha256(f.read_bytes()).hexdigest()} {"OK" if good else "FAIL"}: '
          f'+{len(added)} -{len(removed)} lines; trustlet pins {len(want_tl) // 48} {tl}; '
          f'driver pins {len(want_drv) // 48} {drv}')
print('dtb verify:', 'PASS' if ok else 'FAIL')
sys.exit(0 if ok else 1)
