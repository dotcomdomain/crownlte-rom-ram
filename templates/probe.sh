#!/system/bin/sh
# crownlte ROM-in-RAM probe. Output goes to /dev/crownlte/probe.txt (RAM),
# which the outer PID1 forwards to serial as "P;" lines.
# Diagnostic bypasses (only if /dev/crownlte/bypass_enabled exists) set a
# property that init is waiting for, after a fixed grace period, and always
# print a CROWNLTE-BYPASS line first so the real blocker stays visible.
exec >>/dev/crownlte/probe.txt 2>&1
echo "CROWNLTE-PROBE start uptime=$(cat /proc/uptime)"
bypass=0
[ -e /dev/crownlte/bypass_enabled ] && bypass=1
echo "CROWNLTE-PROBE bypass_enabled=$bypass"
# Showcase (only with androidboot.crownlte_showcase=1): once booted, mark
# setup complete in the RAM /data and open About phone, then the Android
# version page (LineageOS version, kernel), for photos of the running build.
if [ "$(getprop ro.boot.crownlte_showcase)" = 1 ]; then
  (
    while [ "$(getprop sys.boot_completed)" != 1 ]; do sleep 2; done
    sleep 15
    echo "CROWNLTE-SHOWCASE start uptime=$(cut -d' ' -f1 /proc/uptime)"
    settings put global device_provisioned 1
    settings put secure user_setup_complete 1
    pm disable-user --user 0 org.lineageos.setupwizard
    settings put system screen_off_timeout 1800000
    svc power stayon true
    input keyevent KEYCODE_WAKEUP
    wm dismiss-keyguard
    sleep 3
    am start -W -a android.settings.DEVICE_INFO_SETTINGS
    echo "CROWNLTE-SHOWCASE about-phone uptime=$(cut -d' ' -f1 /proc/uptime)"
    sleep 120
    am start -W -n 'com.android.settings/.Settings$FirmwareVersionActivity'
    echo "CROWNLTE-SHOWCASE android-version uptime=$(cut -d' ' -f1 /proc/uptime)"
  ) &
fi
ks=0; okd=0; ovd=0; n=0
while true; do
  up=$(cut -d' ' -f1 /proc/uptime)
  echo "=== probe n=$n uptime=$up"
  getprop | grep -E '^\[(init\.svc\.|apexd\.|keystore\.|odsign\.|ro\.crypto\.|sys\.boot|dev\.bootcomplete|vold\.|ro\.boot\.(hardware|mode|selinux|init_rc)|ro\.hardware|sys\.init\.|ro\.boottime\.init|persist\.sys\.boot\.reason|service\.bootanim\.|sys\.system_server\.|sys\.usb\.|ro\.kernel\.version|ro\.build\.type)'
  echo "--- getenforce=$(cat /sys/fs/selinux/enforce 2>&1) loadavg=$(cat /proc/loadavg)"
  grep -E '^(MemTotal|MemFree|MemAvailable|Shmem|SwapTotal|SwapFree):' /proc/meminfo
  if [ $n -eq 0 ]; then
    echo "--- frp ro.frp.pst=$(getprop ro.frp.pst)"
    echo "--- afbc ro.vendor.ddk.set.afbc=$(getprop ro.vendor.ddk.set.afbc)"
    ls -lL /dev/block/persistent 2>&1; ls -l /dev/block/persistent /dev/block/platform/11120000.ufs/by-name 2>&1
  fi
  # EFS_RO_DIR builds (after on fs): mounts, owners, modes, labels; never contents.
  if [ $n -eq 6 ] && grep -q ' /mnt/vendor/efs tmpfs ' /proc/mounts; then
    echo "--- efs-ro"
    grep -E ' /(mnt/vendor/)?efs ' /proc/mounts
    ls -laRZ /mnt/vendor/efs 2>&1
    if msg=$(touch /mnt/vendor/efs/.crownlte-ro-test 2>&1); then
      rm -f /mnt/vendor/efs/.crownlte-ro-test
      echo "efs-ro FAIL: /mnt/vendor/efs is writable"
    else
      echo "efs-ro PASS: /mnt/vendor/efs refuses a new file: $msg"
    fi
  fi
  if [ $((n % 3)) -eq 0 ]; then
    echo "--- ps"
    ps -A -o PID,PPID,S,WCHAN,TIME,NAME 2>&1
    echo "--- df"
    df -h 2>&1
  fi
  if [ $bypass -eq 1 ]; then
    st=$(getprop apexd.status)
    if [ "$st" = activated ] || [ "$st" = ready ]; then
      if [ "$(getprop keystore.module_hash.sent)" != true ]; then
        ks=$((ks + 10))
        if [ $ks -ge 40 ]; then
          echo "CROWNLTE-BYPASS keystore.module_hash.sent=true after ${ks}s of apexd.status=$st (keystore2/KeyMint did not report)"
          setprop keystore.module_hash.sent true
        fi
      fi
    fi
    if [ -n "$(getprop init.svc.odsign)" ] && [ "$(getprop odsign.key.done)" != 1 ]; then
      okd=$((okd + 10))
      if [ $okd -ge 60 ]; then
        echo "CROWNLTE-BYPASS odsign.key.done=1 after ${okd}s (odsign state $(getprop init.svc.odsign))"
        setprop odsign.key.done 1
      fi
    fi
    if [ "$(getprop odsign.key.done)" = 1 ] && [ "$(getprop odsign.verification.done)" != 1 ]; then
      ovd=$((ovd + 10))
      if [ $ovd -ge 60 ]; then
        echo "CROWNLTE-BYPASS odsign.verification.done=1 after ${ovd}s (odsign state $(getprop init.svc.odsign))"
        setprop odsign.verification.done 1
      fi
    fi
  fi
  n=$((n + 1))
  sleep 10
done
