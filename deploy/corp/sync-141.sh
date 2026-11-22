#!/usr/bin/env bash
# 把 corp-domains.txt 同步到 141 上的 mihomo：
#   1) ruleset/corp.yaml     —— 路由规则 RULE-SET,corp,CorpLink 用
#   2) dns.nameserver-policy —— 这些域名的 DNS 指向 127.0.0.1:10053
# 然后热重载 mihomo。幂等，可重复执行。
set -euo pipefail
cd "$(dirname "$0")"
SSH_HOST="${SSH_HOST:-admin@10.0.0.141}"
SSH_PASS="${SSH_PASS:-2233}"
STACK=/mnt/d/docker/stacks/mihomo/config

grep -v '^#' corp-domains.txt | sed '/^$/d' | sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no "$SSH_HOST" 'cat > /tmp/corp-domains.txt'

sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no "$SSH_HOST" "STACK=$STACK bash -s" <<'REMOTE'
set -e
python3 - "$STACK" <<'PY'
import sys, os
stack = sys.argv[1]
doms = sorted({l.strip() for l in open('/tmp/corp-domains.txt', encoding='utf-8') if l.strip()})
if not doms:
    raise SystemExit('域名表为空')
rs = os.path.join(stack, 'ruleset', 'corp.yaml')
out = ["# corp 内网域名：DNS 走 127.0.0.1:10053，流量走 CorpLink",
       "# 由 deploy/corp/sync-141.sh 生成，勿手改", "payload:"]
out += ["  - '+.%s'" % d for d in doms]
open(rs, 'w', encoding='utf-8').write(chr(10).join(out) + chr(10))
cfg = os.path.join(stack, 'config.yaml')
lines = open(cfg, encoding='utf-8').read().splitlines()
begin = '# >>> corplink corp dns (auto-generated) >>>'
end = '# <<< corplink corp dns <<<'
res, i, inserted = [], 0, False
while i < len(lines):
    line = lines[i]
    if line.strip() == begin:
        i += 1
        while i < len(lines) and lines[i].strip() != end:
            i += 1
        i += 1
        continue
    res.append(line)
    if line.strip() == 'nameserver-policy:' and not inserted:
        res.append('    ' + begin)
        for idx, d in enumerate(doms):
            res.append('    +.%s: %s' % (d, '&corplinkdns' if idx == 0 else '*corplinkdns'))
            if idx == 0:
                res.append('    - 127.0.0.1:10053')
        res.append('    ' + end)
        inserted = True
    i += 1
if not inserted:
    raise SystemExit('config.yaml 里找不到 nameserver-policy')
open(cfg, 'w', encoding='utf-8').write(chr(10).join(res) + chr(10))
print('corp 域名 %d 条已写入 ruleset 与 nameserver-policy' % len(doms))
PY
rm -f /tmp/corp-domains.txt
curl -s -o /dev/null -w "mihomo reload HTTP=%{http_code}\n" --max-time 20 -X PUT "http://127.0.0.1:9090/configs?force=true" -H "Authorization: Bearer 123456" -H "Content-Type: application/json" -d '{"path":"/root/.config/mihomo/config.yaml"}'
REMOTE
