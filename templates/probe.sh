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
ks=0; okd=0; ovd=0; n=0
while true; do
  up=$(cut -d' ' -f1 /proc/uptime)
  echo "=== probe n=$n uptime=$up"
  getprop | grep -E '^\[(init\.svc\.|apexd\.|keystore\.|odsign\.|ro\.crypto\.|sys\.boot|dev\.bootcomplete|vold\.|ro\.boot\.(hardware|mode|selinux|init_rc)|ro\.hardware|sys\.init\.|ro\.boottime\.init|persist\.sys\.boot\.reason|service\.bootanim\.|sys\.system_server\.|sys\.usb\.|ro\.kernel\.version|ro\.build\.type)'
  echo "--- getenforce=$(cat /sys/fs/selinux/enforce 2>&1) loadavg=$(cat /proc/loadavg)"
  grep -E '^(MemTotal|MemFree|MemAvailable|Shmem|SwapTotal|SwapFree):' /proc/meminfo
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
