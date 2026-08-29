#!/bin/bash
# rfs 端到端测试（明文 + TLS/H3 双实例）
cd "$(dirname "$0")"
mkdir -p .t
# 测试证书（自签，不入库，首次运行自动生成）
if [ ! -f test-cert.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout test-key.pem -out test-cert.pem \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:vhost.local,IP:127.0.0.1"
fi
# --- 测试夹具（IP 直连走 default 回落，主用例文件需在 www/default/ 下） ---
mkdir -p www/default/dir
[ -f www/index.html ] || echo '<h1>hello rfs</h1>' > www/index.html
echo '<h1>hello rfs</h1>' > www/default/index.html
echo 'dir listing test' > www/default/dir/hello.txt
BASE=http://127.0.0.1:18080
TLSS=https://127.0.0.1:18443
H3=https://127.0.0.1:19443
AUTH="Authorization: Bearer test-token-123"
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); echo "  ✔ $1"; }
bad(){ FAIL=$((FAIL+1)); echo "  ✘ FAIL: $1"; }
chk(){ if [ "$2" = "$3" ]; then ok "$1 ($3)"; else bad "$1 期望 $2 实际 $3"; fi; }

echo "== 1. GET 下载 =="
code=$(curl -s -o .t/out.html -w '%{http_code}' -H "$AUTH" $BASE/); chk "GET /" 200 "$code"
grep -q "hello rfs" .t/out.html && ok "内容正确" || bad "内容不正确"

echo "== 2. 目录列表 =="
mkdir -p www/default/dir && echo 'dir listing test' > www/default/dir/hello.txt
code=$(curl -s -o .t/list.html -w '%{http_code}' -H "$AUTH" $BASE/dir/); chk "GET /dir/ 列表" 200 "$code"
grep -q "hello.txt" .t/list.html && ok "列表含文件" || bad "列表缺文件"

echo "== 3. PUT 上传（带鉴权） =="
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" -T README.md $BASE/up/readme.md); chk "PUT 上传" 201 "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" -T README.md $BASE/up/readme.md); chk "PUT 覆盖" 200 "$code"

echo "== 4. GET 下载校验 =="
md5_src=$(md5sum README.md | cut -d' ' -f1)
md5_dst=$(curl -s -H "$AUTH" $BASE/up/readme.md | md5sum | cut -d' ' -f1)
[ "$md5_src" = "$md5_dst" ] && ok "md5 一致" || bad "md5 不一致: $md5_src vs $md5_dst"

echo "== 5. Range 断点 =="
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" -H "Range: bytes=0-99" $BASE/up/readme.md); chk "Range 请求" 206 "$code"
len=$(curl -s -H "$AUTH" -H "Range: bytes=0-99" $BASE/up/readme.md | wc -c)
[ "$len" = "100" ] && ok "Range 长度 100" || bad "Range 长度 $len"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" -H "Range: bytes=-50" $BASE/up/readme.md); chk "后缀 Range" 206 "$code"

echo "== 6. ETag/304 =="
etag=$(curl -sI -H "$AUTH" $BASE/up/readme.md | grep -i '^etag:' | tr -d '\r' | cut -d' ' -f2)
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" -H "If-None-Match: $etag" $BASE/up/readme.md); chk "304 缓存" 304 "$code"

echo "== 7. MOVE 移动 =="
code=$(curl -s -o /dev/null -w '%{http_code}' -X MOVE -H "$AUTH" -H "Destination: /up/renamed.md" $BASE/up/readme.md); chk "MOVE" 201 "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" $BASE/up/renamed.md); chk "移动后可达" 200 "$code"

echo "== 8. DELETE 删除 =="
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "$AUTH" $BASE/up/renamed.md); chk "DELETE" 204 "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" $BASE/up/renamed.md); chk "删除后 404" 404 "$code"

echo "== 9. 鉴权 =="
code=$(curl -s -o /dev/null -w '%{http_code}' -T README.md $BASE/up/xxx.md); chk "无鉴权上传 401" 401 "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer wrong" -T README.md $BASE/up/xxx.md); chk "错误令牌 401" 401 "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" -T README.md $BASE/up/xxx.md); chk "正确令牌 201" 201 "$code"
curl -s -X DELETE -H "$AUTH" -o /dev/null $BASE/up/xxx.md

echo "== 10. 目录穿越（--path-as-is 发送原始路径） =="
code=$(curl -s --path-as-is -o /dev/null -w '%{http_code}' -H "$AUTH" "$BASE/../test-plain.toml"); chk ".. 穿越" 403 "$code"
code=$(curl -s --path-as-is -o /dev/null -w '%{http_code}' -H "$AUTH" "$BASE/%2e%2e/test-plain.toml"); chk "编码 .. 穿越" 403 "$code"
code=$(curl -s --path-as-is -o /dev/null -w '%{http_code}' -H "$AUTH" "$BASE/%00"); chk "NUL 字节" 400 "$code"

echo "== 11. 跨站防护 =="
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$AUTH" -H "Origin: https://evil.com" -T README.md $BASE/x.txt); chk "跨站 Origin PUT" 403 "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "$AUTH" -H "Sec-Fetch-Site: cross-site" $BASE/nonexist); chk "cross-site DELETE" 403 "$code"

echo "== 12. 隐藏文件 =="
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" $BASE/.env); chk ".env 隐藏" 404 "$code"

echo "== 13. 大小限制 413 =="
head -c 6000000 /dev/urandom > .t/big.bin
code=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" -T .t/big.bin $BASE/big.bin); chk "超大上传 413" 413 "$code"

echo "== 14. 安全响应头 =="
hdr=$(curl -sI -H "$AUTH" $BASE/)
echo "$hdr" | grep -qi "x-frame-options: DENY" && ok "X-Frame-Options" || bad "缺 X-Frame-Options"
echo "$hdr" | grep -qi "x-content-type-options: nosniff" && ok "nosniff" || bad "缺 nosniff"
echo "$hdr" | grep -qi "content-security-policy" && ok "CSP" || bad "缺 CSP"
echo "$hdr" | grep -qi "server: rfs/" && ok "Server 头" || bad "缺 Server 头"

echo "== 15. HTTPS + HTTP/2 =="
code=$(curl -sk -o .t/h2.html -w '%{http_code}' -H "$AUTH" --http2 $TLSS/); chk "HTTPS H2 GET" 200 "$code"
ver=$(curl -sk -H "$AUTH" --http2 -o /dev/null -w '%{http_version}' $TLSS/)
[ "$ver" = "2" ] && ok "确实走 HTTP/2" || bad "版本 $ver"
echo "== 16. HSTS =="
hdr=$(curl -skI -H "$AUTH" $TLSS/)
echo "$hdr" | grep -qi "strict-transport-security" && ok "HSTS 头" || bad "缺 HSTS"

echo "== 17. HTTP/3 =="
code=$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" --http3-only $H3/); chk "H3 GET" 200 "$code"
code=$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" --http3-only -X DELETE $H3/h3up.md 2>/dev/null)
code=$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" --http3-only -T README.md $H3/h3up.md); chk "H3 PUT 上传" 201 "$code"
code=$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" --http3-only $H3/h3up.md); chk "H3 下载" 200 "$code"
code=$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" --http3-only -H "Range: bytes=0-9" $H3/h3up.md); chk "H3 Range" 206 "$code"
[ "$(curl -sk -H "$AUTH" --http3-only -H "Range: bytes=0-9" $H3/h3up.md | wc -c)" = "10" ] && ok "H3 Range 长度 10" || bad "H3 Range 长度错误"
code=$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" --http3-only -X DELETE $H3/h3up.md); chk "H3 DELETE" 204 "$code"

echo "== 18. 虚拟主机 vhost.local =="
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: vhost.local" $BASE/); chk "vhost basic 401" 401 "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: vhost.local" -u alice:wonderland $BASE/); chk "vhost 放行" 200 "$code"
body=$(curl -s -H "Host: vhost.local" -u alice:wonderland $BASE/)
echo "$body" | grep -q "vhost home" && ok "vhost 根目录正确" || bad "vhost 内容错误: $body"

echo "== 19. vhost 关闭目录列表 =="
mkdir -p www-vhost/up && echo x > www-vhost/up/f.txt
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: vhost.local" -u alice:wonderland $BASE/up/); chk "vhost 列表 403" 403 "$code"

echo ""
echo "结果: 通过 $PASS 项, 失败 $FAIL 项"
[ $FAIL -eq 0 ] && echo "ALL PASS" || echo "SOME FAILED"