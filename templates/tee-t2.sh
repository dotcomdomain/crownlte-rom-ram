#!/system/bin/sh
# Output is forwarded by PID1 on the existing P; channel; RAM only, bounded.
exec >>/dev/crownlte/probe.txt 2>&1
echo 'T2 audit start; polling + strace (failed attempts included; write buffers raw)'
for d in /data/vendor/mcRegistry /data/misc/mcRegistry /data/local/tmp/debugsession; do
    mkdir -p "$d" || exit 125
    chown system:system "$d"
    chmod 0770 "$d"
done
# Never probe arbitrary trustonic debugfs files: crashdump can issue SMCs.
# Mount it privately here only for the three source-audited passive files.
mkdir -p /dev/crownlte/t2-debug
mount -t debugfs -o ro,nosuid,nodev,noexec debugfs /dev/crownlte/t2-debug
snapshot() {
    echo "T2 registry $1"
    for d in /efs/TEE /efs/prov /data/vendor/mcRegistry /data/misc/mcRegistry /vendor/app/mcRegistry; do
        ls -lanR "$d" 2>&1 | head -120
    done
    for f in structs_counters sessions last_mcp_commands; do
        p=/dev/crownlte/t2-debug/trustonic_tee/$f
        if [ -r "$p" ]; then echo "T2 passive tee $f"; head -c 8192 "$p"; else echo "T2 passive tee $f unavailable"; fi
    done
    # This kernel has no exported guard counter: report this honestly and count
    # the ratelimited rejection messages as a lower bound, never as an exact count.
    echo 'T2 UFS guard counters unavailable; diagnostic rejects SCSI lines are in K; channel (ratelimited lower bound)'
}
snapshot before
echo 'T2 PASS userspace audit ready; software keymaster masks retained'
/dev/crownlte/tee-t2-run &
runner=$!
offset=1
for n in $(seq 1 95); do
    sleep 5
    echo "T2 audit poll $n"
    # Drain each byte range once; bound serial output separately from trace storage.
    size=$(stat -c %s /dev/crownlte/tee-t2.strace 2>/dev/null)
    if [ -n "$size" ] && [ "$size" -ge "$offset" ]; then
        tail -c +$offset /dev/crownlte/tee-t2.strace | head -c $((size - offset + 1)) | grep -E 'mobicore|/efs|mcRegistry|TbStorage|EROFS|EACCES|EPERM|exited with|killed by' | head -100
        offset=$((size + 1))
    fi
    logcat -b all -d -t 60 -v brief 2>&1 | grep -E 'McDaemon|MobiCore|mobicore|mcDriver|Trustonic' | head -30
    snapshot poll
    kill -0 "$runner" 2>/dev/null || break
done
wait "$runner"
echo "T2 supervisor exit status=$?"
snapshot after
