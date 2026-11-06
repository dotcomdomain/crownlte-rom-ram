#!/system/bin/sh
# crownlte TEE T3 stage runner (tee-t3-design.md). Output goes to
# /dev/crownlte/probe.txt = "P;" lines on serial. RAM only, bounded.
# Every line this stage prints starts with "T3 ".
exec >>/dev/crownlte/probe.txt 2>&1
R=/dev/crownlte/tee-t3-run
STAGE=$(cat /dev/crownlte/tee_t3)
echo "T3 stage $STAGE start; software keymaster/HAL masks retained container-wide"

t3_fail() {
    echo "T3 FAIL $*"
    echo "T3 RESULT stage=$STAGE FAIL"
    exit 125
}

# 1. Storage nodes must be invisible (as T2), plus no SCSI pass-through nodes.
if ! ls -1R /dev/block > /dev/crownlte/t3-devblock.txt 2>&1; then
    head -20 /dev/crownlte/t3-devblock.txt
    t3_fail 'cannot list container /dev/block; daemon NOT started'
fi
sd=$(grep -c '^sd' /dev/crownlte/t3-devblock.txt)
byname=$(grep -c '^by-name' /dev/crownlte/t3-devblock.txt)
bsg=$(ls -A /dev/bsg 2>/dev/null | wc -l)
sg=$(ls -d /dev/sg* /dev/bsg?* 2>/dev/null | wc -l)
echo "T3 container /dev/block: sd* nodes=$sd by-name dirs=$byname; /dev/bsg entries=$bsg; /dev/sg* nodes=$sg"
if [ "$sd" != 0 ] || [ "$byname" != 0 ] || [ "$bsg" != 0 ] || [ "$sg" != 0 ]; then
    ls -lR /dev/block /dev/bsg 2>&1 | head -60
    t3_fail 'storage or SCSI pass-through nodes visible in container; daemon NOT started'
fi

# 2. Pre-flight in C: stage, kernel guard + exact DT pins, blob/daemon/client hashes, masks.
$R check || t3_fail 'pre-flight refused; daemon NOT started'

for d in /data/vendor/mcRegistry /data/misc/mcRegistry /data/local/tmp/debugsession; do
    mkdir -p "$d" || t3_fail "mkdir $d"
    chown system:system "$d"
    chmod 0770 "$d"
done
# Passive debugfs files only (never crashdump): private mount as T2.
mkdir -p /dev/crownlte/t3-debug
mount -t debugfs -o ro,nosuid,nodev,noexec debugfs /dev/crownlte/t3-debug
snapshot() {
    echo "T3 registry $1"
    for d in /efs/TEE /efs/prov /data/vendor/mcRegistry /data/misc/mcRegistry; do
        ls -lanR "$d" 2>&1 | head -60
    done
    for f in structs_counters sessions; do
        p=/dev/crownlte/t3-debug/trustonic_tee/$f
        if [ -r "$p" ]; then echo "T3 passive tee $f"; head -c 4096 "$p"; else echo "T3 passive tee $f unavailable"; fi
    done
}
kmsg_guard() {
    # Every kernel guard decision since boot, re-printed on P; with the T3 prefix.
    dmesg 2>/dev/null | grep 'tee session-guard' | sed 's/^/T3 kmsg /' | tail -40
}
snapshot before
kmsg_guard

# 3. Daemon (T2 v5 + this stage's pinned -r preloads only), bounded and traced.
$R supervise daemon 420 /dev/crownlte/tee-t3-daemon.strace daemon &
dsup=$!
ready=0
for n in $(seq 1 60); do
    sleep 1
    kill -0 "$dsup" 2>/dev/null || break
    if logcat -b all -d -v brief 2>/dev/null | grep -q 'TEE is ready'; then ready=1; break; fi
done
case "$STAGE" in a2) want_loads=3 ;; b1) want_loads=1 ;; *) want_loads=0 ;; esac
# Blob-path refusals (open-trustlet / admin-load-*) are fatal; UUID-path
# (open-session / gp-open-session) refusals are the T2 guard working and are
# reported, as in T2.
blob_refusals() {
    dmesg 2>/dev/null | grep 'tee session-guard' | grep REFUSED | grep -cE 'open-trustlet|admin-load'
}
session_refusals() {
    dmesg 2>/dev/null | grep 'tee session-guard' | grep REFUSED | grep -cE ' (gp-)?open-session '
}
for n in $(seq 1 10); do
    sleep 1
    loads=$(dmesg 2>/dev/null | grep 'tee session-guard: admin-load-driver' | grep -c ': allowed')
    [ "$loads" -ge "$want_loads" ] && break
done
sleep 2
logcat -b all -d -v brief 2>&1 | grep -E 'McDaemon|MobiCore|mcDriver|TEE is ready' | tail -40 | sed 's/^/T3 logcat /'
kmsg_guard
loads=$(dmesg 2>/dev/null | grep 'tee session-guard: admin-load-driver' | grep -c ': allowed')
refused=$(blob_refusals)
echo "T3 daemon ready=$ready driver_loads_allowed=$loads (want $want_loads) blob_refusals=$refused session_refusals=$(session_refusals)"
stop_daemon() {
    kill -TERM "$dsup" 2>/dev/null
    wait "$dsup"
    echo "T3 daemon supervisor status=$?"
}
if [ "$ready" != 1 ] || [ "$loads" != "$want_loads" ] || [ "$refused" != 0 ]; then
    stop_daemon
    snapshot after
    t3_fail "daemon not ready or unexpected driver loads/refusals; client NOT started"
fi

# 4. The keymaster helper waits (7.5 s) for this property; set it if the daemon did not.
prop=$(getprop vendor.sys.mobicoredaemon.enable)
echo "T3 vendor.sys.mobicoredaemon.enable=$prop (set by daemon)"
if [ "$prop" != true ]; then
    setprop vendor.sys.mobicoredaemon.enable true
    echo "T3 vendor.sys.mobicoredaemon.enable=$(getprop vendor.sys.mobicoredaemon.enable) (set by runner)"
fi

# 5. The client: private namespace, uid 1000, exact seccomp, bounded and traced.
[ "$STAGE" = b1 ] && echo 'T3 STAGE b1: the client sends ONE gatekeeper VERIFY command (fake uid 0x7ffffff0)'
$R supervise client 90 /dev/crownlte/tee-t3-client.strace client
cstatus=$?
sleep 3
logcat -b all -d -v brief 2>&1 | grep -E 'keymaster|Keymaster|keystore|MDFPP|McDaemon|McClient|MobiCore|TEE Gatekeeper|gatekeeper' |
    tail -60 | sed 's/^/T3 logcat /'
kmsg_guard

# 6. Whole-trace totals (never truncated): write-type syscalls / write opens.
trace_totals() {
    t=$1
    [ -r "$t" ] || { echo "T3 trace $2 missing"; return; }
    echo "T3 trace $2 lines=$(wc -l < "$t")"
    echo "T3 trace $2 writes to /efs or registry: $(grep -E '^[0-9]+ +(write|pwrite64|writev|fsync)\([0-9]+<[^>]*(/efs|mcRegistry|TbStorage)' "$t" | wc -l)"
    echo "T3 trace $2 successful write-opens: $(grep -E '^[0-9]+ +openat\(.*O_(WRONLY|RDWR|CREAT)' "$t" | grep -vE '= -1 ' | wc -l)"
    grep -E '^[0-9]+ +openat\(.*O_(WRONLY|RDWR|CREAT)' "$t" | grep -vE '= -1 ' | head -20 | sed "s/^/T3 trace $2 wopen /"
    echo "T3 trace $2 EROFS=$(grep -c EROFS "$t") EACCES=$(grep -c EACCES "$t") EPERM=$(grep -c EPERM "$t")"
    echo "T3 trace $2 property_service connects: $(grep -c 'property_service' "$t")"
    grep -E 'mobicore' "$t" | grep -E 'ioctl' | head -60 | sed "s/^/T3 trace $2 /"
}
trace_totals /dev/crownlte/tee-t3-client.strace client

# 7. Stop the daemon, totals, after-snapshot, verdict.
sleep 2
stop_daemon
trace_totals /dev/crownlte/tee-t3-daemon.strace daemon
snapshot after
refused=$(blob_refusals)
case "$STAGE" in
    a*) uuid=ffffffff00000000000000000000003e ;;
    b*) uuid=08130000000000000000000000000000 ;;
esac
opens=$(dmesg 2>/dev/null | grep "tee session-guard: open-trustlet uuid=$uuid type=3 " | grep -c ': allowed')
cpass=$(grep -cE "^T3 PASS (km|gk) stage=$STAGE" /dev/crownlte/probe.txt)
efsw=$(grep -E '^[0-9]+ +(write|pwrite64|writev|fsync)\([0-9]+<[^>]*/efs' /dev/crownlte/tee-t3-client.strace /dev/crownlte/tee-t3-daemon.strace 2>/dev/null | wc -l)
echo "T3 summary stage=$STAGE client_status=$cstatus client_pass=$cpass trustlet_opens_allowed=$opens blob_refusals=$refused session_refusals=$(session_refusals) efs_writes=$efsw"
if [ "$cstatus" = 0 ] && [ "$cpass" -ge 1 ] && [ "$opens" -ge 1 ] && [ "$refused" = 0 ] && [ "$efsw" = 0 ]; then
    echo "T3 RESULT stage=$STAGE PASS"
else
    echo "T3 RESULT stage=$STAGE FAIL"
fi
