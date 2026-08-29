# rfs — 轻量级 Rust 静态文件服务器

**HTTP/1.1 + HTTP/2 + HTTP/3（QUIC）三协议一体**，单二进制、零运行时依赖，可在内存受限的设备上**平替 nginx 的静态文件/上传场景**：更轻、更快、更省资源（空闲 CPU ≈ 0）。

## 特性一览

| 能力 | 说明 |
| --- | --- |
| 文件操作 | `GET/HEAD` 下载（支持 `Range` 断点续传、`ETag`/`Last-Modified`/`304`）、`PUT` 上传（流式 + 原子落盘）、`DELETE` 删除、`MOVE` 移动/重命名 |
| 鉴权 | 全局或按虚拟主机配置：`Bearer` Token / `Basic` Auth / 两者皆可；常量时间比较防时序攻击；写操作默认强制鉴权 |
| TLS | 可选，同一端口同时服务 HTTPS + HTTP/2（ALPN），证书支持 SIGHUP 热重载 |
| HTTP/3 | 可选，基于 QUIC（quinn + h3），自动协商，与 1.x/2 共用同一套业务逻辑 |
| 虚拟主机 | 不同域名（Host 头）绑定不同根目录、不同鉴权、不同安全策略 |
| 安全 | 防跨站（CSRF：写方法校验 Origin / Sec-Fetch-Site）、防目录穿越（%2e%2e、`..`、NUL）、防符号链接逃逸、隐藏点文件、`X-Frame-Options`、`nosniff`、`CSP`、`HSTS`、`Referrer-Policy` |
| 配置 | TOML 启动读取；`SIGHUP` 热重载（失败保留旧配置）；可选 `auto_reload` 秒级自动重载 |
| 抗 OOM | 全链路流式（64KiB 块）、上传先落临时文件、目录列表条目上限、并发连接信号量、请求体空闲超时、头读取超时（防慢速攻击） |
| 低调空闲 | 纯事件驱动异步运行时，空闲时不轮询不忙等 |

## 快速开始

```bash
cargo build --release

# 生成示例配置并启动
./target/release/rfs --gen
./target/release/rfs -c rfs.toml

# 校验配置（不启动）
./target/release/rfs -c rfs.toml --check
```

## 配置

字段见 `rfs --gen` 生成的 `rfs.toml`，要点：

```toml
listen = "0.0.0.0"
port = 8080
wwwroot = "/srv/www"

[auth]                    # 全局鉴权
mode = "bearer"           # none | bearer | basic | any
tokens = ["secret-token"]
# users = { "admin" = "pass" }

[security]
csrf = true               # 防跨站
nosniff = true
hsts = true

[vhosts."files.example.com"]   # 同一进程多站点
wwwroot = "/srv/files"
dir_listing = false
```

运行期控制：

- `kill -HUP <pid>` → 热重载配置与 TLS 证书（原子切换，校验失败保留旧配置）
- `kill -TERM <pid>` / `Ctrl-C` → 优雅退出（等在途请求最多 5 秒）
- 配置 `auto_reload = true` 后，改配置保存即自动生效（1 秒轮询 mtime，开销可忽略）

## API 用法（curl 示例）

```bash
# -------- 下载（支持断点续传、缓存协商） --------
curl http://127.0.0.1:8080/file.bin -o file.bin
curl -H "Range: bytes=0-1023" http://127.0.0.1:8080/file.bin -o part.bin

# -------- 上传 --------
curl -H "Authorization: Bearer secret-token" -T ./big.iso \
     http://127.0.0.1:8080/iso/big.iso
# 上传保护：超过 max_upload_size 返回 413；上传中卡住超过 body_idle_timeout 自动中止并清理临时文件

# -------- 删除（目录非空需 X-Recursive） --------
curl -X DELETE -H "Authorization: Bearer secret-token" http://127.0.0.1:8080/iso/big.iso
curl -X DELETE -H "Authorization: Bearer secret-token" -H "X-Recursive: true" \
     http://127.0.0.1:8080/old-dir

# -------- 移动 / 重命名 --------
curl -X MOVE -H "Authorization: Bearer secret-token" \
     -H "Destination: /iso/renamed.iso" http://127.0.0.1:8080/iso/big.iso

# -------- 目录浏览 --------
curl http://127.0.0.1:8080/iso/
```

跨站保护说明：浏览器发起带 `Origin` / `Sec-Fetch-Site: cross-site` 的写请求会被 403 拒绝；命令行客户端不受影响。

## 安全设计（防 OOM / 防逃逸）

1. **路径归一化**：解码 → 逐段处理，`..` 弹栈、越栈即拒；拒绝 NUL 字节；隐藏 `.` 开头的文件。
2. **符号链接逃逸**：`canonicalize` 后校验前缀必须在站点根目录内，根外一律 403。
3. **上传原子性**：先写同目录 `.rfs-upload-*.part`，流式写入（内存有界），`fsync` 后 `rename` 覆盖；任何错误路径都会清理临时文件。
4. **内存有界**：下载逐块发送（响应通道 16 块上限形成背压）；目录列表最多 `max_listing` 条；并发受 `max_conn` 信号量约束。
5. **慢速攻击防护**：请求头读取 30s 超时；请求体单块空闲 `body_idle_timeout` 超时。
6. **常量时间密码比较**（subtle），Basic 用户名不存在时也会执行一次假比较。

## 性能 / 资源

- 事件驱动 + 多线程 runtime（默认取可用核数），空闲时零轮询，CPU 占用为 0。
- 静态文件由 `tokio::fs` 直接流式读出，无用户态复制缓冲累积。
- 生产建议：`[profile.release]` 已启用 `lto="thin"`、`strip`、`panic="abort"`，二进制约 3~5 MB。

## 与 nginx 的对比定位

- 部署即用：`rfs -c rfs.toml` 一条命令，无 master/worker 进程管理成本。
- 需要的功能（静态、上传、鉴权、虚拟主机、TLS、H3）全都内置；不需要的（rewrite、proxy、lua……）一概不带，攻击面更小。
- 轻量到可以在手机 / 树莓派 / 路由器上跑；空闲内存占用远低于 nginx + OpenSSL 进程组。

## 📖 配置文档

**完整配置参考见 [CONFIG.md](CONFIG.md)**：全部 30+ 配置项说明与默认值、6 个场景示例
（纯静态 / HTTPS+H3+鉴权 / 内网 NAS / 多虚拟主机 / 大文件分发 / 高安全模式）、
TOML 段顺序坑、运行期控制、API 速查与 FAQ。所有示例均经 `--check` 实测验证。

## 目录结构

```
src/
  main.rs     入口、CLI、信号（SIGHUP 重载 / 优雅退出）、自动重载
  config.rs   TOML 配置与运行期站点合璧（虚拟主机继承链）
  material.rs TLS 构建（HTTP2 ALPN / QUIC ALPN 复用同一证书）
  httpd.rs    HTTP/1.1 + HTTP/2（hyper），TLS 可选
  h3srv.rs    HTTP/3（quinn + h3），与 1.x/2 共用核心
  core.rs     协议无关核心：路由、鉴权、CSRF、Range、ETag、流式 IO
  fsops.rs    路径安全、上传临时文件、移动、删除、目录列表
  auth.rs     Bearer/Basic 常量时间校验
  log.rs      零依赖日志
```

## 架构与可靠性细节

1. **流式架构（防 OOM / 防死锁）**：HTTP/1.x 下载时不再把文件灌入有界内存通道，而是由
   hyper 在 `poll_frame` 中**按需直接读取文件**（单请求内存恒定 64KiB）；H3 走同核
   心的默认流式路径。大文件（实测 64MiB）上传/下载内存占用恒定为千字节级，且无
   生产者-消费者握手死锁。
2. **H3 自愈 watchdog**：Android/部分平台下 quinn+h3 存在已知的边缘问题（连接关闭后
   accept 反复报错导致 CPU 自旋，以及 recv-only 流 drop 后 endpoint driver 失活）。
   rfs 内置：①连续 3 次 accept 错误即视为连接终态退出（杜绝空转）；②每 10 秒用独立
   QUIC 客户端自探测，探测失败自动重建 endpoint（同端口，2 秒内恢复）。
3. **上传原子性**：临时文件 → 流式写入 → fsync → 原子 rename；任何错误路径自动清理。
4. **并发与慢速攻击**：信号量限流并发连接，请求头读取 30s 超时，请求体空闲超时可配。
5. **配置热重载**：SIGHUP 或 `auto_reload=true` 秒级自动重载；校验失败保留旧配置；
   TLS 证书同样支持热重载（新建 TLS 接受器）——监听端口变更需重启。

## 测试

```bash
cargo test          # 单元测试（路径归一化 / Range 解析）
sh e2e.sh           # 端到端测试（明文 + TLS/H3 双实例，42 项断言）
```

实测结果（Android/Termux, aarch64）：

| 项目 | 结果 |
| --- | --- |
| e2e 功能测试（下载/上传/移动/删除/鉴权/CSRF/穿越/安全头/H2/H3/vhost） | 42/42 通过 |
| H3 混合压力（PUT+DELETE+GET+Range） | 200+ 请求 0 失败 |
| 64MiB 大文件 上传/下载 md5 校验（HTTP/1.1 与 HTTP/3） | 一致 |
| 空闲 CPU（无请求 10s 采样） | ≈ 0% |
| 二进制体积（release） | ≈ 4.9 MB |

### 与 nginx 同机实测对比（nginx/1.29.4，回环，page cache 全热，v0.2.0）

| 指标 | rfs v0.2.0 | nginx | 说明 |
| --- | --- | --- | --- |
| HTTP/1.1 64MiB 吞吐 | **~1550 MB/s**（峰值 1928） | ~1245 MB/s | **rfs 领先 24%**（v0.2.0 分段 mmap 零拷贝） |
| HTTP/1.1 256MiB 吞吐 | **~1974 MB/s** | - | 窗口制，RSS 峰值仅 11.5MB |
| HTTP/3 64MiB 吞吐 | 158 MB/s | 144 MB/s | rfs 略胜；QUIC 加密为共同瓶颈 |
| 发送 256MiB 时的内存峰值 | **11.5 MB**（窗口制，恒定） | - | 防 RAM 溢出：窗口全局预算硬边界 |
| 空闲 CPU | ≈ 0% | ≈ 0% | 持平 |
| 部署形态 | 单进程单二进制 4.9MB | master+worker 多进程 | rfs 更轻 |
| HTTP/3 开箱 | ✔ 内置 | 需编译带 http_v3 模块 | 多数发行版默认不带 |

> v0.2.0 引入分段 mmap 零拷贝发送（窗口 4MiB、全局预算 256MiB 硬边界、超限自动回退
> read 流式、SIGBUS 兜底），大文件吞吐反超 nginx，同时内存峰值恒定。
> nginx 的优势在代理/缓存/限流等模块生态与数十年生产检验；rfs 的优势在极简部署、
> 内存安全、HTTP/3 开箱即用、自适应自愈与可预算的内存模型。