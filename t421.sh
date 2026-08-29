#!/bin/bash
cd "$(dirname "$0")"
if [ -f .t421.pid ]; then kill -9 "$(cat .t421.pid)" 2>/dev/null; rm -f .t421.pid; sleep 1; fi
cat > .t421.toml <<'EOF'
listen = "127.0.0.1"
port = 18700
wwwroot = "./www"
dir_listing = true
access_log = true
auto_reload = false
default_vhost_dir = ""

[auth]
mode = "none"

[vhosts."only.site"]
wwwroot = "./www-vhost"
EOF
nohup ./bin/rfs -c .t421.toml > t421.log 2>&1 &
echo $! > .t421.pid
sleep 2
head -5 t421.log
echo "--- IP 直连 ---"
curl -s -o /dev/null -w 'code=%{http_code}\n' http://127.0.0.1:18700/index.html
echo "--- body ---"
curl -s http://127.0.0.1:18700/index.html
echo "--- 精确 Host 大小写变体 ---"
echo -n "ONLY.SITE => "
curl -s -o /dev/null -w '%{http_code}\n' -H "Host: ONLY.SITE" http://127.0.0.1:18700/index.html
kill -9 "$(cat .t421.pid)" 2>/dev/null
rm -f .t421.pid
echo "--- 服务器日志 ---"
cat t421.log
rm -f t421.log .t421.toml