#!/bin/bash
# v0.4.1 性能/防护 e2e：小文件缓存命中、HDD 模式、路径穿越爆破封禁
cd "$(dirname "$0")"
mkdir -p www .t
[ -f www/index.html ] || echo '<h1>hello rfs</h1>' > www/index.html

PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); echo "  ✔ $1"; }
bad(){ FAIL=$((FAIL+1)); echo "  ✘ FAIL: $1"; }
chk(){ if [ "$2" = "$3" ]; then ok "$1 ($3)"; else bad "$1 期望 $2 实际 $3"; fi; }
has(){ echo "$2" | grep -qi "$3" && ok "$1" || bad "$1（未找到: $3）"; }

B=http://127.0.0.1:18085

echo "== 0. 配置校验（hdd/cache/defense） =="
check=$(./bin/rfs -c test-defense.toml --check 2>&1)
has "--check 含 hdd=true" "$check" "hdd=true"
has "--check 含 cache=1MB" "$check" "cache=1MB"
has "--check 含 def=true" "$check" "def=true"

echo "== 1. 启动服务 =="
nohup ./bin/rfs -c test-defense.toml > .t/def.log 2>&1 &
SPID=$!
sleep 1.2

echo "== 2. 小文件缓存 =="
h1=$(curl -s -D - -o /dev/null "$B/" | tr 'A-Z' 'a-z')
has "首次请求 x-rfs-cache: miss" "$h1" "x-rfs-cache: miss"
h2=$(curl -s -D - -o /dev/null "$B/" | tr 'A-Z' 'a-z')
has "再次请求 x-rfs-cache: hit" "$h2" "x-rfs-cache: hit"
code=$(curl -s -o /dev/null -w '%{http_code}' "$B/")
chk "缓存命中后仍为 200" 200 "$code"

echo "== 3. HDD 模式（mmap 关闭的流式路径）仍正常 =="
body=$(curl -s "$B/")
has "正文正确" "$body" "hello rfs"

echo "== 4. 路径穿越爆破 → 触发临时封禁 =="
for i in 1 2 3 4 5; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "$B/../x" --max-time 4)
  echo "  第 $i 次穿越: $code"
  [ "$code" = "403" ] && ok "第 $i 次穿越 403" || bad "第 $i 次穿越 期望 403 实际 $code"
done
code=$(curl -s -o /dev/null -w '%{http_code}' "$B/")
chk "封禁后普通请求 403" 403 "$code"

echo "== 5. 日志出现封禁记录 =="
has "日志含“封禁”" "$(cat .t/def.log)" "封禁"

kill "$SPID" 2>/dev/null
sleep 0.3
kill -9 "$SPID" 2>/dev/null
rm -f .t/def.log

echo
echo "结果: 通过 $PASS 项, 失败 $FAIL 项"
[ "$FAIL" = 0 ] && echo "ALL PASS" || echo "SOME FAILED"
exit "$FAIL"
