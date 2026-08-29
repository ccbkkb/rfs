#!/bin/bash
# rfs v0.3.0 新功能专项测试
cd "$(dirname "$0")"
A="Authorization: Bearer test-token-123"
B=http://127.0.0.1:18080
TL=https://127.0.0.1:18443
P=0; F=0
ok(){ P=$((P+1)); echo "  ✔ $1"; }
bad(){ F=$((F+1)); echo "  ✘ FAIL: $1"; }
chk(){ if [ "$2" = "$3" ]; then ok "$1 ($3)"; else bad "$1 期望 $2 实际 $3"; fi; }

echo "== 1. default 目录回落（含 IP 直连安全回落） =="
mkdir -p www/default
echo 'fallback-content' > www/default/fb.txt
echo '<h1>fallback page</h1>' > www/default/index.html
echo 'root-only-secret' > www/rootonly.txt
c=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: unknown.example.com" -H "$A" $B/fb.txt); chk "未知域名回落 200" 200 "$c"
body=$(curl -s -H "Host: unknown.example.com" -H "$A" $B/fb.txt)
[ "$body" = "fallback-content" ] && ok "内容来自 default 目录" || bad "回落内容错误: $body"
c=$(curl -s -o /dev/null -w '%{http_code}' -H "$A" $B/index.html); chk "IP 直连 200" 200 "$c"
body=$(curl -s -H "$A" $B/index.html)
echo "$body" | grep -q "fallback" && ok "IP 直连也走回落（安全）" || bad "IP 直连未走回落: $body"
c=$(curl -s -o /dev/null -w '%{http_code}' -H "$A" $B/rootonly.txt); chk "IP 无法触达 wwwroot 根文件" 404 "$c"

echo "== 2. 自定义错误页 =="
c=$(curl -s -o /dev/null -w '%{http_code} %{content_type}' -H "$A" $B/no-such); chk "404 自定义页" "404 text/html; charset=utf-8" "$c"
b=$(curl -s -H "$A" $B/no-such)
echo "$b" | grep -q "错误码: 404" && ok "占位符 {{code}} 替换" || bad "code 占位符未替换"
echo "$b" | grep -q "信息: 资源不存在" && ok "{{message}} 替换" || bad "message 占位符未替换"

echo "== 3. 全局自定义头 =="
h=$(curl -sI -H "$A" $B/index.html)
echo "$h" | grep -qi "x-cdn-ttl: 300" && ok "X-CDN-TTL: 300" || bad "缺 X-CDN-TTL"
echo "$h" | grep -qi "cache-control: public, max-age=86400" && ok "Cache-Control 覆盖默认" || bad "Cache-Control 未覆盖"
echo "$h" | grep -qi "access-control-allow-origin: \*" && ok "CORS 头" || bad "缺 CORS"
echo "$h" | grep -qi "x-frame-options: DENY" && ok "默认安全头保留" || bad "默认安全头丢失"

echo "== 4. vhost 级覆盖 =="
h=$(curl -sI -H "Host: vhost.local" -u alice:wonderland $B/index.html)
echo "$h" | grep -qi "x-vhost: vhost.local" && ok "vhost 头" || bad "缺 vhost 头"
echo "$h" | grep -qi "cache-control: no-store, vhost-override" && ok "vhost 覆盖 Cache-Control" || bad "vhost 覆盖失败"

echo "== 5. force_https 同端口嗅探 =="
c=$(curl -s -o /dev/null --path-as-is -w '%{http_code}' http://127.0.0.1:18443/index.html); chk "明文→301" 301 "$c"
loc=$(curl -s --path-as-is -o /dev/null -w '%{redirect_url}' http://127.0.0.1:18443/index.html)
echo "$loc" | grep -q "^https://127.0.0.1:18443/index.html" && ok "Location 正确" || bad "Location 错误: $loc"
c=$(curl -sk --retry 2 --retry-all-errors -o /dev/null -w '%{http_code}' -H "$A" https://127.0.0.1:18443/index.html); chk "HTTPS 正常" 200 "$c"
c=$(curl -sk --retry 2 --retry-all-errors -o /dev/null -w '%{http_code}' --http3-only -H "$A" https://127.0.0.1:19443/index.html); chk "H3 正常" 200 "$c"
c=$(curl -sk --http3-only -H "$A" -o /dev/null --retry 2 -w '%{http_code}' https://127.0.0.1:19443/index.html); chk "H3 二次" 200 "$c"

echo ""
echo "v0.3.0 新功能: 通过 $P, 失败 $F"
[ $F -eq 0 ] && echo "ALL PASS" || echo "SOME FAILED"