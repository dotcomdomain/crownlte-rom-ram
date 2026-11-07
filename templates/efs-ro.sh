#!/system/bin/sh
# crownlte ROM-in-RAM, EFS_RO_DIR builds only. Run by init.diag.rc with
# exec_start from the first "on fs" action, before the vendor "on fs" binds
# /mnt/vendor/efs onto /efs. exec_start blocks init until this exits, and the
# service has reboot_on_failure: any non-zero exit (or a failed start) makes
# Lineage init reboot, which only ends the PID namespace (SIGHUP); the outer
# PID1 reaps it and its deadline restarts the phone. Nothing is retried.
#
# PID1 (romram.h step 5e) left /mnt/vendor/efs a read-only RAM tmpfs with
# sha256-verified copies. Labels need the loaded policy, so: remount rw,
# restorecon -R, remount ro, then require that it is really read-only:
#   - exactly one mount at /mnt/vendor/efs, type tmpfs;
#   - first option "ro" (the kernel prints ro when __mnt_is_readonly, the
#     same test that sets ST_RDONLY in statfs/statvfs), plus nosuid,nodev,noexec;
#   - a new file is refused with EROFS ("Read-only file system").
# Only then it sets crownlte.efs_ro=ok, which init.diag.rc waits for after
# exec_start (so a helper that never ran also blocks init until the deadline).
# File contents are never read or printed.
P=/mnt/vendor/efs
T=$P/.crownlte-efs-ro-test
log() { echo "<$1>crownlte-romram: efs-ro $2" > /dev/kmsg; }
fail() {
  log 3 "FAIL stage=$1: $2; ROM stage ends (reboot_on_failure -> namespace exit; deadline restarts)"
  # best effort only, the namespace is about to go away
  mount -o remount,ro,nosuid,nodev,noexec "$P" 2>/dev/null
  exit 1
}
# mounts: prints "<count> <fstype> <options>" for the mount(s) exactly at $P (last wins)
mounts() {
  n=0; t=-; o=-
  while read -r dev mp ty op rest; do
    [ "$mp" = "$P" ] && { n=$((n + 1)); t=$ty; o=$op; }
  done < /proc/self/mounts
  echo "$n $t $o"
}
check_flags() {  # $1 = ro|rw
  set -- "$1" $(mounts)
  [ "$2" = 1 ] || fail "mount-count-$1" "$2 mounts at $P (want 1)"
  [ "$3" = tmpfs ] || fail "mount-type" "$P type $3 (want tmpfs)"
  case ",$4," in
    ",$1,"*) ;;
    *) fail "flags-$1" "$P options $4 (want first option $1)" ;;
  esac
  for f in nosuid nodev noexec; do
    case ",$4," in *",$f,"*) ;; *) fail "flags-$f" "$P options $4 (missing $f)" ;; esac
  done
}

check_flags ro
mount -o remount,rw,nosuid,nodev,noexec "$P" || fail remount-rw "mount rc=$?"
check_flags rw
restorecon -R "$P" || fail restorecon "restorecon rc=$?"
mount -o remount,ro,nosuid,nodev,noexec "$P" || fail remount-ro "mount rc=$?"
check_flags ro
if msg=$(touch "$T" 2>&1); then
  rm -f "$T"
  fail write-test "a new file was created (still writable)"
fi
case "$msg" in
  *"Read-only file system"*) ;;
  *) fail write-test "write refused but not with EROFS: $msg" ;;
esac
setprop crownlte.efs_ro ok || fail setprop "setprop rc=$?"
[ "$(getprop crownlte.efs_ro)" = ok ] || fail setprop "crownlte.efs_ro did not read back ok"
log 6 "PASS labels restored; $P ro,nosuid,nodev,noexec verified (1 tmpfs mount, write refused with EROFS: $(ls -dZ "$P" 2>&1))"
exit 0
