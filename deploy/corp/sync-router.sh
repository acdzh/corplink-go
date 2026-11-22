#!/usr/bin/env bash
# 把 corp-domains.txt 同步到路由器 dnsmasq：只有这些域名转发给 141，其它域名不受影响。
# 幂等：先删掉所有指向 141 的 corp 转发项，再按表重建；改前备份 /etc/config/dhcp。
set -euo pipefail
cd "$(dirname "$0")"
ROUTER="${ROUTER:-root@10.0.0.1}"
ROUTER_PASS="${ROUTER_PASS:-password}"
UPSTREAM="${UPSTREAM:-10.0.0.141#5335}"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<'REMOTE'
set -e
cp /etc/config/dhcp /etc/config/dhcp.bak.$(date +%Y%m%d-%H%M%S)
# 删掉旧的 corp 转发（只删指向 __UP__ 的，其它 server 项保留）
uci -q show dhcp.@dnsmasq[0].server 2>/dev/null | sed 's/^[^=]*=//' | tr "'" ' ' | tr ' ' '\n' | grep -F '/__UP__' | while read -r s; do
  uci del_list dhcp.@dnsmasq[0].server="$s"
done
REMOTE

python3 - "$TMP" "$UPSTREAM" <<'PY'
import sys
p, up = sys.argv[1], sys.argv[2]
s = open(p, encoding="utf-8").read().replace("__UP__", up)
open(p, "w", encoding="utf-8").write(s)
PY

grep -v '^#' corp-domains.txt | sed '/^$/d' | while read -r d; do
  echo "uci add_list dhcp.@dnsmasq[0].server='/$d/$UPSTREAM'" >> "$TMP"
done

printf '%s\n' 'uci commit dhcp' '/etc/init.d/dnsmasq restart' 'sleep 2' \
  "grep -c '$UPSTREAM' /var/etc/dnsmasq.conf.* 2>/dev/null || true" >> "$TMP"

sshpass -p "$ROUTER_PASS" ssh -o StrictHostKeyChecking=no "$ROUTER" 'cat > /tmp/corp-dns.sh' < "$TMP"
sshpass -p "$ROUTER_PASS" ssh -o StrictHostKeyChecking=no "$ROUTER" 'sh /tmp/corp-dns.sh && rm -f /tmp/corp-dns.sh'
