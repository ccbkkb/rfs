#!/bin/bash
# 反代 / 伪静态 / 限速 端到端测试（mock 上游 + 两个 rfs 实例；~24 项断言）
cd "$(dirname "$0")"
mkdir -p .t
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); echo "  ✔ $1"; }
bad(){ FAIL=$((FAIL+1)); echo "  ✘ FAIL: $1"; }
chk(){ if [ "$2" = "$3" ]; then ok "$1 ($3)"; else bad "$1 期望 $2 实际 $3"; fi; }
has(){ echo "$2" | grep -q "$3" && ok "$1" || bad "$1（未找到: $3）"; }
hasnot(){ echo "$2" | grep -q "$3" && bad "$1（不应出现: $3）" || ok "$1"; }

# 证书（自签，首次生成）
if [ ! -f test-cert.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout test-key.pem -out test-cert.pem \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi

# 启动 mock 上游
nohup python3 mock_upstream.py > .t/mock.log 2>&1 &
MOCK_PID=$!
sleep 1.2

# 启动两个 rfs 实例
nohup ./bin/rfs -c test-proxy.toml > .t/proxy.log 2>&1 &
PXY_PID=$!
nohup ./bin/rfs -c test-ratelimit.toml > .t/rl.log 2>&1 &
RL_PID=$!
sleep 1.2

B=http://127.0.0.1:18081
R=http://127.0.0.1:18082

echo "== 1. 基础代理 / 前缀剥离 / 查询串 =="
body=$(curl -s "$B/api/hello?x=1")
has "路径与查询串透传" "$body" '"path": "/hello?x=1"'
has "请求头注入 x-injected" "$body" '"x-injected": "yes"'

echo "== 2. 转发头（XFF 覆盖防伪造） =="
body=$(curl -s -H 'X-Forwarded-For: 6.6.6.6' "$B/api/hello")
has "XFF 被覆盖为真实来源" "$body" '"x-forwarded-for": "127.0.0.1"'
hasnot "伪造 XFF 未透传" "$body" '6.6.6.6'
has "X-Forwarded-Proto" "$body" '"x-forwarded-proto": "http"'

echo "== 3. 逐跳头剥离 =="
body=$(curl -s -H 'Connection: x-secret' -H 'x-secret: leak-value' "$B/api/hello")
hasnot "Connection 指定的头被剥离" "$body" 'leak-value'

echo "== 4. 响应头处理 =="
hdrs=$(curl -sI "$B/api/hello" | tr 'A-Z' 'a-z')
has "注入响应头 x-proxied" "$hdrs" 'x-proxied: 1'
hasnot "移除上游敏感头" "$hdrs" 'x-upstream-secret'
has "安全头存在" "$hdrs" 'x-content-type-options'

echo "== 5. 不剥离前缀 =="
body=$(curl -s "$B/keep/abc")
has "路径保持原样" "$body" '"path": "/keep/abc"'

echo "== 6. 伪静态内部重写 -> 反代（链式） =="
body=$(curl -s "$B/p/123")
has "/p/123 -> 上游 /p/123" "$body" '"path": "/p/123"'
body=$(curl -s "$B/legacy/user_a.html")
has "/legacy/x.html -> 上游 /legacy/x" "$body" '"path": "/legacy/user_a"'

echo "== 7. 伪静态跳转 =="
code=$(curl -s -o /dev/null -w '%{http_code}' "$B/old")
chk "302 跳转" 302 "$code"
loc=$(curl -s -o /dev/null -D - "$B/old" | grep -i '^location:' | tr -d '\r' | cut -d' ' -f2)
chk "Location 正确" "/new" "$loc"

echo "== 8. 路径穿越防护（代理路径同样归一化） =="
code=$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "$B/../test.toml")
chk "越根穿越被拒绝" 403 "$code"
body=$(curl -s --path-as-is "$B/x/../api/hello")
has "穿越段先归一化再转发（上游只见 /hello）" "$body" '"path": "/hello"'

echo "== 9. POST 请求体 =="
body=$(curl -s -X POST -d 'hello-proxy' "$B/api/echo")
has "方法透传" "$body" '"method": "POST"'
has "请求体长度透传" "$body" '"body_len": 11'

echo "== 10. HTTPS 上游（自签+显式 tls_verify=false） =="
body=$(curl -s "$B/sec/hello")
has "HTTPS 上游可用" "$body" '"path": "/hello"'

echo "== 11. Host 保持 =="
body=$(curl -s -H 'Host: example.com' "$B/api/hello")
has "Host 原样传给上游" "$body" '"host": "example.com"'

echo "== 12. 限速（rate=1 burst=2） =="
c1=$(curl -s -o /dev/null -w '%{http_code}' "$R/")
c2=$(curl -s -o /dev/null -w '%{http_code}' "$R/")
c3=$(curl -s -o /dev/null -w '%{http_code}' "$R/")
c4=$(curl -s -o /dev/null -w '%{http_code}' "$R/")
chk "第1发 200" 200 "$c1"
chk "第2发 200" 200 "$c2"
chk "第3发 429" 429 "$c3"
chk "第4发 429" 429 "$c4"
ra=$(curl -s -o /dev/null -D - "$R/" | grep -i '^retry-after:' | tr -d '\r' | cut -d' ' -f2)
[ -n "$ra" ] && ok "429 带 Retry-After（$ra）" || bad "429 缺 Retry-After"
sleep 2.2
c5=$(curl -s -o /dev/null -w '%{http_code}' "$R/")
chk "等待补充令牌后恢复 200" 200 "$c5"
sleep 1.2
[ -s .t/rl-test.db ] && ok "限速状态已持久化到文件" || bad "限速状态文件未生成"

# 清理
kill "$PXY_PID" "$RL_PID" "$MOCK_PID" 2>/dev/null
sleep 0.5
kill -9 "$PXY_PID" "$RL_PID" "$MOCK_PID" 2>/dev/null
rm -f .t/rl-test.db .t/rl-test.db.tmp

echo
echo "结果: 通过 $PASS 项, 失败 $FAIL 项"
[ "$FAIL" = 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit "$FAIL"
