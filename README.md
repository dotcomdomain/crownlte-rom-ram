# crownlte ROM-in-RAM initramfs

Initramfs that boots LineageOS 23 from RAM on the Linux 6.12 kernel, without writing to
UFS. It restarts into normal LineageOS after a fixed time.

## Build

```sh
./build.sh <new-build-dir>        # initramfs; needs your SYSTEM/VENDOR/ODM images
./pack-rom-ram.py <pack-dir> ...  # shim + kernel + DTB + initramfs -> recovery.img
```

The scripts use the original build host's paths (`K`, `P`, `SHIM_REPO`, `PARENT`). Edit
them first. Options (`ADB=1`, `ADB_ROOT=1`, `EFS_RO_DIR=`) are in `RUN-SHEET.md`.

Do not publish packed images: they can contain your device's EFS data.
