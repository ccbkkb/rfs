# rfs 配置文件完整参考（CONFIG.md）

> 适用版本：rfs v0.2.0+
> 配置格式：TOML。`rfs --gen` 可生成带注释的示例配置。

---

## 1. 最小可用配置（3 行）

```toml
listen = "0.0.0.0"
port = 8080
wwwroot = "/srv/www"
```

这就够了：HTTP/1.1+2 明文服务、目录浏览开启、写操作要求鉴权（未配置鉴权时返回 401）。
需要上传？加两行：

```toml
[auth]
mode = "bearer"
tokens = ["your-secret-token"]
```

---

## 2. ⚠️ 最重要的 TOML 规则（先读这个，能少踩 90% 的坑）

**TOML 中，裸键（不在任何 `[表]` 下的键）必须写在所有 `[表]` 头之前。**

`[auth]`、`[security]`、`[vhosts."xxx"]` 都是表头。一旦出现表头，
其后的**所有裸键都属于该表**，而不是根配置——serde 会静默忽略未知键，**配置不生效且不报错**。

❌ 错误示例（`port` 会被当成 `security.port` 而失效）：

```toml
[security]
csrf = true

port = 8080        # ← 错！这行属于 [security] 表
```

✅ 正确写法：根级键全部放最前面，最后才是各表：

```toml
port = 8080        # ✔ 根级
wwwroot = "/srv/www"

[security]
csrf = true
```

**写完配置务必 `rfs -c 配置 --check` 校验一次。**

---

## 3. 配置项完整参考

### 3.1 根级：网络

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `listen` | 字符串 | `"0.0.0.0"` | 监听地址；`"127.0.0.1"` 仅本机 |
| `port` | 整数 | `8080` | HTTP/1.1+HTTP/2 端口（配置 TLS 后即 HTTPS 端口） |

### 3.2 根级：站点

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `wwwroot` | 字符串 | **必填** | 默认站点根目录；不存在时自动创建 |
| `dir_listing` | 布尔 | `true` | 目录浏览（无索引文件时列出文件列表）。公网建议关闭 |
| `index_files` | 字符串数组 | `["index.html"]` | 目录默认索引文件，按序匹配 |
| `serve_dotfiles` | 布尔 | `false` | 是否允许访问 `.` 开头的隐藏文件（`.env`、`.git` 等）。**保持 false** |

### 3.3 根级：TLS（可选）

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `tls_cert` | 字符串 | — | PEM 证书路径（含完整证书链） |
| `tls_key` | 字符串 | — | PEM 私钥路径 |
| `force_https` | 布尔 | `false` | **强制 HTTPS（需 TLS）**：同一 TCP 端口做协议嗅探，明文请求 301 到 `https://host[:port]/path`，实现单端口 HTTP+HTTPS 共存。仅 TLS 配置时有效 |

两者**必须同时配置**（都配 → 该端口即 HTTPS，自动支持 HTTP/2；不配 → 明文 HTTP）。
支持 SIGHUP/自动重载热更新证书（重新加载失败时保留旧配置）。

### 3.4 根级：HTTP/3（可选，需要 TLS）

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enable_h3` | 布尔 | `false` | 开启 HTTP/3（QUIC）。**必须同时配置 TLS** |
| `h3_port` | 整数 | `port + 1` | QUIC/UDP 端口（独立于 TCP 端口，这是 QUIC 的标准部署形态） |

### 3.5 根级：鉴权（全局默认）

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `require_auth_write` | 布尔 | `true` | 写操作（PUT/DELETE/MOVE）强制鉴权；`true` 且未配置鉴权时写操作一律 401（防呆：忘配鉴权也不会裸奔） |

`[auth]` 表（可选；不写则所有请求无需鉴权）：

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `mode` | 字符串 | `"none"` | `none` / `bearer` / `basic` / `any`（任意一种通过即可） |
| `tokens` | 字符串数组 | `[]` | bearer 令牌，可配多个；`Authorization: Bearer <token>` |
| `users` | TOML 内联表 | `{}` | basic 用户：`{ "admin" = "password" }`；`Authorization: Basic base64(user:pass)` |

鉴权规则：
- `mode != "none"` 时**所有请求**（含 GET）都要求鉴权；
- `mode = "none"` 时仅写操作受 `require_auth_write` 约束；
- 令牌/密码比较为常量时间（防时序侧信道）。

> ⚠️ 密码/令牌在无 TLS 时明文传输，公网务必开 TLS。

### 3.6 根级：上传

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `max_upload_size` | 整数 | `0` | 单次上传字节上限；`0` 不限。超限返回 413 |
| `mkdir_on_upload` | 布尔 | `true` | PUT 时自动创建缺失的父目录 |
| `sync_on_upload` | 布尔 | `true` | 落盘 fsync 后再原子改名（掉电不丢已确认的上传；高频小文件可关提升性能） |

上传机制：先写同目录 `.rfs-upload-*` 临时文件 → 流式写入（内存恒定）→ fsync → 原子 `rename` 覆盖；失败自动清理临时文件。

### 3.7 根级：性能与防 OOM

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `max_conn` | 整数 | `512` | 最大并发连接数（信号量；超出排队） |
| `body_idle_timeout` | 整数（秒） | `60` | 请求体两块之间的空闲超时（防慢速上传攻击） |
| `io_chunk_size` | 整数 | `262144` | 流式读写块大小（64KiB~4MiB） |
| `max_listing` | 整数 | `10000` | 目录列表单页最大条目数（防超大目录耗内存） |
| `mmap_send` | 布尔 | `true` | ≥1MiB 的大文件走分段 mmap 零拷贝发送（v0.2.0；吞吐反超 nginx sendfile 路径） |
| `mmap_window_mb` | 整数 | `4` | mmap 发送窗口大小（MiB）＝单连接发送时的 RSS 峰值上界 |
| `mmap_budget_mb` | 整数 | `256` | 全进程 mmap 活跃窗口总预算（MiB）＝防 RAM 溢出硬边界；预算耗尽自动回退 read 流式，**服务不中断** |

**内存模型说明**：无论文件多大、多少并发，rfs 的进程 RSS 峰值 ≈ 基础占用 + min(活跃 mmap 窗口, 预算)。
实测：发送 256MiB 文件时进程峰值 RSS 仅 ~11.5MB。请求头读取 30 秒超时（内置，防 slowloris）。

### 3.8 根级：日志

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `log_level` | 字符串 | `"info"` | `debug` / `info` / `warn` / `error` |
| `access_log` | 布尔 | `true` | 访问日志（一行一请求） |
| `auto_reload` | 布尔 | `true` | 配置文件变更自动热重载（1 秒轮询 mtime，开销可忽略）；也可手动 `kill -HUP` |

### 3.9 `[security]` 表（安全头与防跨站）

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `csrf` | 布尔 | `true` | 防跨站：写请求若带 `Origin`/`Sec-Fetch-Site: cross-site` 且与 Host 不同源 → 403。命令行客户端不受影响 |
| `frame_deny` | 布尔 | `true` | `X-Frame-Options: DENY`（防点击劫持） |
| `nosniff` | 布尔 | `true` | `X-Content-Type-Options: nosniff`（防 MIME 嗅探） |
| `csp` | 布尔 | `true` | `Content-Security-Policy: default-src 'none'` |
| `referrer_policy` | 布尔 | `true` | `Referrer-Policy: no-referrer` |
| `hsts` | 布尔 | `true` | TLS 下发送 `Strict-Transport-Security`（明文 HTTP 自动不发送） |
| `hsts_age` | 整数 | `31536000` | HSTS max-age 秒 |
| `hide_version` | 布尔 | `false` | 隐藏 `Server: rfs/x.y.z` 中的版本号 |

### 3.10 未知域名回落（v0.3.0）

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `default_vhost_dir` | 字符串 | `"default"` | 未知域名回落到 `wwwroot/<default_vhost_dir>`（启动时自动创建 + 可读校验）；**设为 `""` 禁用**：未知域名直接返 421 Misdirected Request |

规则（配置了 vhost 时生效；无 vhost 为单站点模式，全部走 wwwroot 根）：
- 域名匹配某 vhost → 该 vhost；
- **IP 直连与其他未匹配 Host 一致** → 回落 `wwwroot/<default_vhost_dir>`（v0.3.1 安全行为：防止经 IP 直连绕过 vhost 隔离与站点级鉴权）；
- 回落禁用（`default_vhost_dir = ""`）→ 未匹配一律 421 Misdirected Request。

> 需要 IP 管理入口？为该 IP 配置一个 vhost（如 `[vhosts."127.0.0.1"]`），或使用单站点模式。

### 3.11 自定义响应头（可选）

```toml
custom_headers = { "X-CDN-TTL" = "300", "Cache-Control" = "public, max-age=86400", "Access-Control-Allow-Origin" = "*" }
```

- 应用于**所有响应**（含错误响应）；`insert` 语义**覆盖同名默认安全头**（如自定义 Cache-Control/CORS）；
- 键须为合法 HTTP 头名（token 字符），值不得含 CR/LF/NUL（防 CRLF 注入），值长 ≤4KiB；
- vhost 级 `[vhosts."x".custom_headers]` **整体覆盖**全局；
- 配合 CDN：`X-CDN-TTL`（CDN 缓存 TTL）、`Cache-Control`（浏览器 TTL）按 CDN 厂商文档配置；
- 跨域上传组合：`[security] csrf = false` + 自定义 CORS 头。

### 3.12 自定义错误页（可选）

```toml
[error_pages]
"404" = "errors/404.html"   # 精确码
"5xx" = "errors/5xx.html"   # 类通配（4xx 同理）
"default" = "errors/all.html"  # 兜底
```

- 路径为 wwwroot 相对路径（自动防穿越）；单个页面 ≤1MiB，启动时预读入内存（零运行时开销）；
- 匹配优先级：精确码 > 类通配（4xx/5xx）> default；
- 动态占位符：`{{code}}`/`{code}` 替换为实际错误码，`{{message}}`/`{message}` 替换为实际错误信息（已 HTML 转义防注入）；
- Content-Type 按扩展名（.html → text/html）；页面缺失/过大（>1MiB）启动报错。

### 3.13 `[vhosts."域名"]` 表（虚拟主机，可选）

同一进程按 `Host` 头服务多个站点。每站点可覆盖：`wwwroot`、`dir_listing`、
`index_files`、`auth`、`require_auth_write`、`max_upload_size`、`mkdir_on_upload`、
`sync_on_upload`、`custom_headers`。未覆盖的项继承全局；未知域名的处理见 3.10。

```toml
[vhosts."files.example.com"]
wwwroot = "/srv/files"
dir_listing = false
[vhosts."files.example.com".auth]
mode = "bearer"
tokens = ["tok1"]
```

> 域名匹配规则：取 `Host` 头去端口后转小写精确匹配。建议配置小写域名。
> ⚠️ vhost 表头之后不可再放根级键（见第 2 节）。

---

## 4. 场景示例

### 4.1 纯静态站（博客/文档，公网，无上传）

```toml
listen = "0.0.0.0"
port = 80
wwwroot = "/srv/blog"
dir_listing = false
index_files = ["index.html"]
auto_reload = true
```

### 4.2 HTTPS + HTTP/3 + Bearer 鉴权的文件服务

```toml
listen = "0.0.0.0"
port = 443
wwwroot = "/srv/files"
tls_cert = "/etc/rfs/fullchain.pem"
tls_key  = "/etc/rfs/key.pem"
enable_h3 = true
h3_port = 443            # H3 可与 443/TCP 同号（QUIC 走 UDP）

[auth]
mode = "bearer"
tokens = ["9f86d081884c7d65"]   # 建议用长随机串：openssl rand -hex 16

[security]
hsts_age = 63072000      # 2 年
```

> `h3_port = 443`：QUIC 走 UDP/443，与 TCP/443 同号，是浏览器友好型部署。

### 4.3 内网匿名读 + 限定写（家庭 NAS）

```toml
listen = "0.0.0.0"
port = 8080
wwwroot = "/srv/nas"
dir_listing = true
require_auth_write = true

[auth]
mode = "basic"
users = { "admin" = "S3cret!pass" }

max_upload_size = 1073741824   # 单文件上限 1GiB
sync_on_upload = false         # 内网追求吞吐可关 fsync
```

读不需要密码？把鉴权收紧到 vhost 上（3.10），默认站点保持 `[auth] mode="none"` + `require_auth_write = true`：匿名可下载，上传/删除必须鉴权。

### 4.4 多虚拟主机

```toml
listen = "0.0.0.0"
port = 80
wwwroot = "/srv/default"
dir_listing = true

[vhosts."static.example.com"]
wwwroot = "/srv/static"
dir_listing = false
index_files = ["index.html"]

[vhosts."dl.example.com"]
wwwroot = "/srv/downloads"
max_upload_size = 2147483648   # 2GiB
[vhosts."dl.example.com".auth]
mode = "any"
tokens = ["dl-token-1"]
users = { "ops" = "pass" }
```

### 4.5 大文件分发节点（镜像站）

```toml
listen = "0.0.0.0"
port = 80
wwwroot = "/srv/mirror"
dir_listing = true
max_listing = 50000

mmap_send = true
mmap_window_mb = 8       # 单连接发送窗口 8MiB
mmap_budget_mb = 512     # 全局窗口预算 512MiB（≈64 个并发 8MiB 窗口）

[auth]
mode = "none"
```

### 4.6 高安全模式（最小信息泄露）

```toml
serve_dotfiles = false
dir_listing = false

[security]
hide_version = true
frame_deny = true
nosniff = true
csp = true
csrf = true
```

---

## 5. 运行期控制

| 操作 | 方式 |
|---|---|
| 启动 | `rfs -c /etc/rfs/rfs.toml` |
| 校验配置（不启动） | `rfs -c 配置 --check` |
| 生成示例配置 | `rfs --gen`（配合 `-c` 指定输出路径） |
| **热重载配置/证书** | `kill -HUP $(pgrep -x rfs)` 或 `auto_reload = true` 后改文件即生效 |
| 优雅退出 | `kill -TERM $(pgrep -x rfs)` 或 Ctrl-C（等在途请求最多 5 秒） |

热重载规则：
- 原子切换：新配置校验通过才生效，失败保留旧配置并打日志；
- 生效范围：鉴权、vhost、安全头、限流参数、目录策略、**TLS 证书**等全部生效；
- 不生效：`listen`/`port`/`h3_port`（监听套接字需重启进程）；
- CLI 覆盖项（`--port` 等）仅影响启动，热重载以配置文件为准。

命令行参数：

```
-c, --config <路径>   配置文件（默认 /etc/rfs/rfs.toml）
--check               校验配置后退出
--gen                 生成示例配置
--port <端口>         覆盖监听端口
--wwwroot <目录>      覆盖根目录
--listen <地址>       覆盖监听地址
-V, --version         版本
-h, --help            帮助
```

---

## 6. API 速查（配合鉴权头）

```
GET/HEAD /path            下载（Range / ETag / 304）
PUT       /path           上传（body 即文件内容；curl -T 文件 URL）
DELETE    /path           删除（目录非空需头 X-Recursive: true）
MOVE      /src            移动/重命名（头 Destination: /dst）
OPTIONS   /               允许的方法
```

curl 示例：

```bash
T="Authorization: Bearer your-token"
curl -H "$T" -T big.bin http://127.0.0.1:8080/big.bin          # 上传
curl -H "$T" -H "Range: bytes=0-1023" -o part http://.../big.bin
curl -X MOVE -H "$T" -H "Destination: /new-name.bin" http://.../big.bin
curl -X DELETE -H "$T" http://.../big.bin
```

---

## 7. 常见问题（FAQ）

**Q1：改了配置怎么不生效？**
九成是第 2 节的 TOML 段顺序问题：裸键写到了某个 `[表]` 后面。把根级键挪到文件最顶部，`--check` 验证。

**Q2：`enable_h3 = true` 启动报"必须配置 tls_cert"？**
HTTP/3 强制要求 TLS（QUIC 内建 TLS1.3）。先配 `tls_cert`/`tls_key`。

**Q3：HTTP 和 HTTPS 能否同端口共存？**
配置了 TLS 的端口就是 HTTPS 端口。需要同时提供明文 HTTP，请再启动一个实例（不同端口/配置文件），或前置代理。

**Q4：上传大文件会占很多内存吗？**
不会。上传流式落盘（64KiB 级缓冲）；下载走 mmap 窗口/流式读，RSS 峰值恒定（实测发送 256MiB 文件进程峰值 ~11.5MB）。

**Q5：目录列表里中文/特殊字符文件名乱码？**
不会。列表 HTML 对文件名做 HTML 转义 + 百分号编码（同时天然防 XSS）。

**Q6：mmap_send 是什么？要关吗？**
v0.2.0 的大文件零拷贝优化（默认开）。若你的文件目录在 NFS 等网络文件系统上、且存在外部截断文件的可能，可设 `mmap_send = false` 回退传统流式；本地盘无需关闭。极端情况下（发送中文件被外部截断）进程会记录日志并以退出码 70 快速退出，请配合 systemd `Restart=always` 或脚本守护。
