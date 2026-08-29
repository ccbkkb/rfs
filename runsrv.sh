#!/bin/bash
# 测试进程管理（PID 文件，避免误杀自身）
cd "$(dirname "$0")"
# 测试证书（自签，不入库，首次运行自动生成）
if [ ! -f test-cert.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout test-key.pem -out test-cert.pem \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:vhost.local,IP:127.0.0.1"
fi
case "$1" in
  start)
    for c in test-plain.toml test-tls.toml; do
      if [ -f "pid-${c%.toml}" ] && kill -0 "$(cat pid-${c%.toml})" 2>/dev/null; then
        echo "$c already running pid=$(cat pid-${c%.toml})"
      else
        rm -f "server-${c%.toml}.log"
        nohup ./bin/rfs -c "$c" > "server-${c%.toml}.log" 2>&1 &
        echo $! > "pid-${c%.toml}"
        echo "$c started pid=$!"
      fi
    done
    sleep 2
    ;;
  stop)
    for c in test-plain.toml test-tls.toml; do
      if [ -f "pid-${c%.toml}" ]; then
        kill -TERM "$(cat pid-${c%.toml})" 2>/dev/null
        sleep 6
        kill -9 "$(cat pid-${c%.toml})" 2>/dev/null
        rm -f "pid-${c%.toml}"
        echo "$c stopped"
      fi
    done
    ;;
  restart) $0 stop; $0 start ;;
  *) echo "usage: $0 start|stop|restart";;
esac