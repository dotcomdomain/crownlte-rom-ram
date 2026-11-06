#!/system/bin/sh
# crownlte ROM-in-RAM, ADB=1 only. Container side of adb over USB NCM.
# PID1 owns the USB gadget (ACM ttyGS0 = serial log, NCM = crownadb0); this
# script never touches configfs, the UDC, block devices or mounts. It:
#  - installs the host's adb PUBLIC key into the RAM /data/misc/adb/adb_keys
#    (system:shell 0640, adb_keys_file label);
#  - brings crownadb0 up with fixed link-local addresses: fe80::1/64 and
#    169.254.42.1/16 (Windows reaches them with its own IPv6 link-local or
#    APIPA address; no DHCP server, no router, no DNS);
#  - adds the two connected routes to netd's local_network table (97). netd
#    deletes the kernel's "lookup main" rule at start, so main-table routes are
#    ignored; its rule 20000 "fwmark 0x0/0x10000 lookup local_network" serves
#    unmarked traffic such as adbd's replies. Init() never flushes tables.
#  - re-checks all of it every 10 s and repairs (and reports) any change.
# Output goes to /dev/crownlte/probe.txt (forwarded by PID1 as P; lines).
exec >>/dev/crownlte/probe.txt 2>&1
IF=crownadb0
V4=169.254.42.1
V6=fe80::1
T=97
KEY=/dev/crownlte/adb_keys
DIR=/data/misc/adb
up() { cut -d' ' -f1 /proc/uptime; }
say() { echo "ADB $* uptime=$(up)"; }
say "start if=$IF v4=$V4/16 v6=$V6/64 table=$T port=5555 key_sha256=$(sha256sum $KEY | cut -c1-64)"

# --- key -------------------------------------------------------------------
key_ok=0
keys() {
  line=$(cat $KEY) || return 1
  # let init create /data/misc (and its own /data/misc/adb) first
  [ -d /data/misc ] || return 1
  [ -d $DIR ] || mkdir $DIR || return 1
  chown system:shell $DIR && chmod 2750 $DIR || return 1
  if ! grep -qxF "$line" $DIR/adb_keys 2>/dev/null; then
    [ $key_ok = 1 ] && say "REPAIR key missing from $DIR/adb_keys; appending again"
    echo "$line" >> $DIR/adb_keys || return 1
  fi
  chown system:shell $DIR/adb_keys && chmod 0640 $DIR/adb_keys || return 1
  restorecon $DIR $DIR/adb_keys || return 1
  if [ $key_ok = 0 ]; then
    key_ok=1
    say "PASS key installed: $(ls -lZ $DIR/adb_keys) lines=$(wc -l < $DIR/adb_keys)"
  fi
}

# --- link --------------------------------------------------------------------
net_ok=0
net() {
  [ -d /sys/class/net/$IF ] || return 1
  fix=""
  if [ "$(cat /proc/sys/net/ipv6/conf/$IF/disable_ipv6)" != 0 ]; then
    echo 0 > /proc/sys/net/ipv6/conf/$IF/disable_ipv6 || return 1; fix="$fix ipv6"
  fi
  if [ $(($(cat /sys/class/net/$IF/flags) & 1)) != 1 ]; then   # IFF_UP
    ip link set dev $IF up || return 1; fix="$fix up"
  fi
  if ! ip -4 addr show dev $IF | grep -q "inet $V4/16 "; then
    ip -4 addr add $V4/16 dev $IF || return 1; fix="$fix v4"
  fi
  if ! ip -6 addr show dev $IF | grep -q "inet6 $V6/64 "; then
    ip -6 addr add $V6/64 dev $IF nodad || return 1; fix="$fix v6"
  fi
  if ! ip -4 route show table $T dev $IF | grep -q '^169\.254\.0\.0/16 '; then
    ip -4 route add 169.254.0.0/16 dev $IF table $T || return 1; fix="$fix route4"
  fi
  if ! ip -6 route show table $T dev $IF | grep -q '^fe80::/64 '; then
    ip -6 route add fe80::/64 dev $IF table $T || return 1; fix="$fix route6"
  fi
  if [ $net_ok = 0 ]; then
    net_ok=1
    say "PASS link $IF up: $(ip -br addr show dev $IF | tr -s ' ') mac=$(cat /sys/class/net/$IF/address) routes=table $T (set:$fix)"
  elif [ -n "$fix" ]; then
    say "REPAIR $IF:$fix (something changed the link; re-applied)"
  fi
}

# --- adbd ------------------------------------------------------------------
# /proc/net/tcp{,6}: local port 5555 = 15B3; state 0A = LISTEN, 01 = ESTABLISHED.
tcp() { cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v st=$1 '$2 ~ /:15B3$/ && $4 == st' | wc -l; }
listen_ok=0; peer_ok=0; n=0; wait_net=0
while true; do
  keys || say "FAIL key install (will retry)"
  if ! net; then
    wait_net=$((wait_net + 10))
    [ $((wait_net % 60)) = 10 ] && say "WAIT $IF not configurable yet ($(ls /sys/class/net | tr '\n' ' '))"
  fi
  l=$(tcp 0A); e=$(tcp 01)
  if [ $listen_ok = 0 ] && [ "$l" -gt 0 ]; then
    listen_ok=1; say "PASS adbd listening on tcp 5555 ($(getprop init.svc.adbd), sockets=$l)"
  fi
  if [ $peer_ok = 0 ] && [ "$e" -gt 0 ]; then
    peer_ok=1; say "PASS host connected to tcp 5555 (established=$e)"
  fi
  if [ $((n % 3)) = 0 ]; then
    say "status adbd=$(getprop init.svc.adbd) listen=$l established=$e" \
      "link=$(cat /sys/class/net/$IF/operstate 2>/dev/null)/carrier=$(cat /sys/class/net/$IF/carrier 2>/dev/null)" \
      "usb.config=$(getprop sys.usb.config) usb.state=$(getprop sys.usb.state)" \
      "tcp.port=$(getprop service.adb.tcp.port) debuggable=$(getprop ro.debuggable) adb.secure=$(getprop ro.adb.secure)" \
      "rule20000=$(ip rule | grep -c -E 'lookup (local_network|97)')"
  fi
  if [ $n = 6 ]; then
    echo "--- ADB detail uptime=$(up)"
    ip rule; ip -4 route show table $T; ip -6 route show table $T
    ip addr show dev $IF; ls -lZd $DIR; ls -lZ $DIR
  fi
  n=$((n + 1))
  sleep 10
done
