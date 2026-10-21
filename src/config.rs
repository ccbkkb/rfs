//! 配置解析与校验
//! 支持 TOML 格式；启动时读取，SIGHUP 热重载（校验失败则保留旧配置）。
use crate::fsops;
use http::Uri;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// 校验自定义响应头：键须为合法 HTTP 头名（token），值不得含 CR/LF/NUL（防 CRLF 注入）
fn validate_headers(h: &HashMap<String, String>) -> Result<(), String> {
    for (k, v) in h {
        let k_ok = !k.is_empty()
            && k.bytes().all(|b| {
                b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
            });
        if !k_ok {
            return Err(format!("头名非法: {k:?}"));
        }
        if v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            return Err(format!("头 {k:?} 的值含非法换行/空字节"));
        }
        if v.len() > 4096 {
            return Err(format!("头 {k:?} 的值过长（>4KiB）"));
        }
    }
    Ok(())
}

fn default_true() -> bool {
    true
}
fn default_auth_mode() -> String {
    "none".to_string()
}
fn default_mmap_window() -> usize {
    4
}
fn default_mmap_budget() -> usize {
    256
}
fn default_fallback_dir() -> String {
    "default".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_index_files() -> Vec<String> {
    vec!["index.html".to_string()]
}
fn default_max_listing() -> usize {
    10000
}

pub const DEFAULT_CONFIG: &str = "/etc/rfs/rfs.toml";

// ---------------- 原始配置（与 TOML 一一对应） ----------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AuthCfg {
    /// none | bearer | basic | any（未配置时默认 none）
    #[serde(default = "default_auth_mode")]
    pub mode: String,
    /// bearer 令牌（可多个，任一匹配即可）
    pub tokens: Vec<String>,
    /// basic 用户名 -> 明文密码（生产环境请使用 htpasswd 风格的哈希，见 README）
    pub users: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecurityCfg {
    /// 防跨站（CSRF）：对写方法校验 Origin / Sec-Fetch-Site，跨站拒绝
    pub csrf: bool,
    /// X-Frame-Options: DENY（防点击劫持）
    pub frame_deny: bool,
    /// X-Content-Type-Options: nosniff（防 MIME 嗅探）
    pub nosniff: bool,
    /// Strict-Transport-Security（在 TLS 下生效）
    pub hsts: bool,
    /// HSTS 有效期秒
    pub hsts_age: u64,
    /// Content-Security-Policy: default-src 'none'
    pub csp: bool,
    /// Referrer-Policy: no-referrer
    pub referrer_policy: bool,
    /// Server 头隐藏版本号
    pub hide_version: bool,
}

impl Default for SecurityCfg {
    fn default() -> Self {
        SecurityCfg {
            csrf: true,
            frame_deny: true,
            nosniff: true,
            hsts: true,
            hsts_age: 31536000,
            csp: true,
            referrer_policy: true,
            hide_version: false,
        }
    }
}

// ---------------- 反向代理 / 伪静态 / 限速（v0.4） ----------------

fn default_proxy_timeout() -> u64 {
    30
}
fn default_xff() -> String {
    "set".to_string()
}
fn default_rl_storage() -> String {
    "file".to_string()
}
fn default_rl_file() -> String {
    "./rfs-rate.db".to_string()
}
fn default_rl_flush() -> u64 {
    10
}
fn default_redis_addr() -> String {
    "127.0.0.1:6379".to_string()
}
fn default_redis_prefix() -> String {
    "rfs:rl:".to_string()
}
fn default_redis_timeout() -> u64 {
    300
}
fn default_rl_max_entries() -> usize {
    65536
}

/// 反向代理路由：路径前缀匹配 `prefix` → 转发到 `upstream`
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyRouteCfg {
    /// 匹配前缀（须以 '/' 开头；边界按路径段对齐，/api 不会匹配 /api2）
    pub prefix: String,
    /// 上游地址：http(s)://host[:port][/base]
    pub upstream: String,
    /// 去掉 prefix 后再拼接上游路径
    pub strip_prefix: bool,
    /// 保留原始 Host 请求头传给上游（默认 true）
    #[serde(default = "default_true")]
    pub preserve_host: bool,
    /// 校验上游 TLS 证书（默认 true；false 仅用于自签内部后端，风险自负）
    #[serde(default = "default_true")]
    pub tls_verify: bool,
    /// 上游请求总超时（秒）
    #[serde(default = "default_proxy_timeout")]
    pub timeout: u64,
    /// 追加/覆盖发给上游的请求头
    #[serde(default)]
    pub set_request_headers: HashMap<String, String>,
    /// 追加/覆盖回给客户端的响应头
    #[serde(default)]
    pub set_response_headers: HashMap<String, String>,
    /// 从上游响应中移除的头（如 "set-cookie"）
    #[serde(default)]
    pub remove_response_headers: Vec<String>,
    /// X-Forwarded-For 处理：set（覆盖）| append（追加）| off
    #[serde(default = "default_xff")]
    pub xff: String,
}

impl Default for ProxyRouteCfg {
    fn default() -> Self {
        ProxyRouteCfg {
            prefix: String::new(),
            upstream: String::new(),
            strip_prefix: false,
            preserve_host: true,
            tls_verify: true,
            timeout: default_proxy_timeout(),
            set_request_headers: HashMap::new(),
            set_response_headers: HashMap::new(),
            remove_response_headers: Vec::new(),
            xff: default_xff(),
        }
    }
}

/// 伪静态/重写：对路径做正则替换（结果必须是 '/' 开头的内部路径，防开放重定向）
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RewriteCfg {
    /// 正则（建议 ^ 锚定；rust regex 为线性时间，无 ReDoS）
    pub pattern: String,
    /// 替换串，支持 $1 等捕获引用
    pub replace: String,
    /// 内部重写时保留原查询串；跳转时附加原查询串
    #[serde(default = "default_true")]
    pub keep_query: bool,
    /// 0 = 内部重写；301/302/307/308 = 对外跳转
    pub redirect: u16,
}

impl Default for RewriteCfg {
    fn default() -> Self {
        RewriteCfg { pattern: String::new(), replace: String::new(), keep_query: true, redirect: 0 }
    }
}

/// 速率限制：rate/burst 可在站点级覆盖；storage 等后端设置仅全局生效
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitCfg {
    /// 补充速率（req/s）；与 burst 同时 >0 时启用
    pub rate: Option<f64>,
    /// 桶容量（突发上限）
    pub burst: Option<f64>,
    /// file | redis
    #[serde(default = "default_rl_storage")]
    pub storage: String,
    #[serde(default = "default_rl_file")]
    pub file: String,
    #[serde(default = "default_rl_flush")]
    pub flush_secs: u64,
    #[serde(default = "default_redis_addr")]
    pub redis_addr: String,
    #[serde(default = "default_redis_prefix")]
    pub redis_prefix: String,
    #[serde(default = "default_redis_timeout")]
    pub redis_timeout_ms: u64,
    /// 后端故障时是否放行（默认 true；安全性要求高可设 false = 故障时拒绝）
    #[serde(default = "default_true")]
    pub fail_open: bool,
    /// 内存中桶表上限（防大量源 IP 导致 OOM）
    #[serde(default = "default_rl_max_entries")]
    pub max_entries: usize,
}

impl Default for RateLimitCfg {
    fn default() -> Self {
        RateLimitCfg {
            rate: None,
            burst: None,
            storage: default_rl_storage(),
            file: default_rl_file(),
            flush_secs: default_rl_flush(),
            redis_addr: default_redis_addr(),
            redis_prefix: default_redis_prefix(),
            redis_timeout_ms: default_redis_timeout(),
            fail_open: true,
            max_entries: default_rl_max_entries(),
        }
    }
}

fn default_small_cache_max_kb() -> usize {
    64
}

/// 应用层防护（DDoS/CC/长连接/路径穿越爆破）
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DefenseCfg {
    /// 总开关（默认开）
    pub enable: bool,
    /// 每 IP 最大并发连接（0=不限）
    pub max_conn_per_ip: usize,
    /// 窗口内违规次数达到该值 → 临时封禁
    pub max_violations: usize,
    /// 违规统计窗口（秒）
    pub violation_window_secs: u64,
    /// 封禁时长（秒）
    pub ban_secs: u64,
    /// HTTP/1 头部读取缓冲上限（KiB），防超大头部攻击
    pub max_header_kb: usize,
    /// 单连接最大请求数（超出后返回 Connection: close；0=不限）
    pub max_requests_per_conn: usize,
}

impl Default for DefenseCfg {
    fn default() -> Self {
        DefenseCfg {
            enable: true,
            max_conn_per_ip: 96,
            max_violations: 30,
            violation_window_secs: 60,
            ban_secs: 300,
            max_header_kb: 64,
            max_requests_per_conn: 1000,
        }
    }
}

fn header_name_ok(k: &str) -> bool {
    !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn validate_route(who: &str, r: &ProxyRouteCfg) -> Result<(), String> {
    if r.prefix.is_empty() || !r.prefix.starts_with('/') || r.prefix.len() > 256 {
        return Err(format!("{who}: prefix 须为 '/' 开头且 ≤256 字节"));
    }
    if r.prefix.contains("//") || r.prefix.split('/').any(|s| s == "..") {
        return Err(format!("{who}: prefix 含非法路径段"));
    }
    let uri: Uri = r.upstream.parse().map_err(|e| format!("{who}: upstream 非法: {e}"))?;
    match uri.scheme_str() {
        Some("http") | Some("https") => {}
        _ => return Err(format!("{who}: upstream 仅支持 http/https（当前数据不支持其他方案）")),
    }
    let auth_ok = uri
        .authority()
        .map(|a| !a.as_str().is_empty() && !a.as_str().contains('@'))
        .unwrap_or(false);
    if !auth_ok {
        return Err(format!("{who}: upstream 缺少主机或含用户信息"));
    }
    if !uri.path().is_empty() && !uri.path().starts_with('/') {
        return Err(format!("{who}: upstream 基路径非法"));
    }
    if !matches!(r.xff.as_str(), "set" | "append" | "off") {
        return Err(format!("{who}: xff 须为 set/append/off"));
    }
    if r.timeout == 0 || r.timeout > 600 {
        return Err(format!("{who}: timeout 须在 1..=600 秒"));
    }
    validate_headers(&r.set_request_headers).map_err(|e| format!("{who}: set_request_headers {e}"))?;
    validate_headers(&r.set_response_headers).map_err(|e| format!("{who}: set_response_headers {e}"))?;
    for k in &r.remove_response_headers {
        if !header_name_ok(k) {
            return Err(format!("{who}: remove_response_headers 含非法头名 {k:?}"));
        }
    }
    Ok(())
}

fn validate_rewrite(who: &str, w: &RewriteCfg) -> Result<(), String> {
    if w.pattern.is_empty() || w.pattern.len() > 512 {
        return Err(format!("{who}: pattern 长度须在 1..=512"));
    }
    regex::Regex::new(&w.pattern).map_err(|e| format!("{who}: pattern 非法: {e}"))?;
    if w.replace.len() > 1024
        || w.replace.contains('\r')
        || w.replace.contains('\n')
        || w.replace.contains('\0')
    {
        return Err(format!("{who}: replace 非法（过长或含换行/空字节）"));
    }
    if !matches!(w.redirect, 0 | 301 | 302 | 307 | 308) {
        return Err(format!("{who}: redirect 只能为 0/301/302/307/308"));
    }
    Ok(())
}

fn validate_ratelimit(who: &str, r: &RateLimitCfg, global: bool) -> Result<(), String> {
    for (name, v) in [("rate", r.rate), ("burst", r.burst)] {
        if let Some(v) = v {
            if !v.is_finite() || v < 0.0 || v > 1_000_000.0 {
                return Err(format!("{who}: {name} 须在 0..=1e6"));
            }
        }
    }
    if global {
        if !matches!(r.storage.as_str(), "file" | "redis") {
            return Err(format!("{who}: storage 须为 file/redis"));
        }
        if r.flush_secs == 0 || r.flush_secs > 3600 {
            return Err(format!("{who}: flush_secs 须在 1..=3600"));
        }
        if r.max_entries < 1024 || r.max_entries > 2_000_000 {
            return Err(format!("{who}: max_entries 须在 1024..=2000000"));
        }
        if r.redis_timeout_ms == 0 || r.redis_timeout_ms > 5000 {
            return Err(format!("{who}: redis_timeout_ms 须在 1..=5000"));
        }
    }
    Ok(())
}

/// 单站点（虚拟主机或默认站点）覆盖项；None 表示继承全局配置
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct VhostCfg {
    pub wwwroot: Option<String>,
    pub dir_listing: Option<bool>,
    pub index_files: Option<Vec<String>>,
    pub auth: Option<AuthCfg>,
    pub require_auth_write: Option<bool>,
    pub max_upload_size: Option<u64>,
    pub mkdir_on_upload: Option<bool>,
    pub sync_on_upload: Option<bool>,
    /// vhost 级自定义响应头（覆盖全局）
    #[serde(default)]
    pub custom_headers: Option<HashMap<String, String>>,
    /// vhost 级反代路由（覆盖全局 routes）
    #[serde(default)]
    pub routes: Option<Vec<ProxyRouteCfg>>,
    /// vhost 级伪静态（覆盖全局 rewrites）
    #[serde(default)]
    pub rewrites: Option<Vec<RewriteCfg>>,
    /// vhost 级限速覆盖（rate/burst）
    #[serde(default)]
    pub ratelimit: Option<RateLimitCfg>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    /// 监听地址
    pub listen: String,
    /// 监听端口
    pub port: u16,
    /// 默认站点根目录（wwwroot）
    pub wwwroot: String,
    /// 站点根目录下的隐含文件是否可见（如 .env）
    pub serve_dotfiles: bool,

    // ---------- TLS ----------
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// 强制 HTTPS：TLS 开启时，明文 HTTP 请求 301 跳转到 https://（需 TLS，显式开启）
    #[serde(default)]
    pub force_https: bool,

    // ---------- HTTP/3 ----------
    pub enable_h3: bool,
    pub h3_port: u16,

    // ---------- 鉴权（全局默认） ----------
    pub auth: AuthCfg,
    /// 写操作（PUT/DELETE/MOVE）强制要求鉴权；默认 true（安全默认）
    #[serde(default = "default_true")]
    pub require_auth_write: bool,

    // ---------- 静态访问 ----------
    #[serde(default = "default_true")]
    pub dir_listing: bool,
    /// 目录下默认索引文件，如 ["index.html"]
    #[serde(default = "default_index_files")]
    pub index_files: Vec<String>,
    /// 单请求上传字节上限；0 = 不限制
    pub max_upload_size: u64,
    #[serde(default = "default_true")]
    pub mkdir_on_upload: bool,
    #[serde(default = "default_true")]
    pub sync_on_upload: bool,

    // ---------- 性能与保护（防 OOM） ----------
    /// 大文件 mmap 零拷贝发送（>=1MiB 文件启用）；关闭则回退 read 流式
    #[serde(default = "default_true")]
    pub mmap_send: bool,
    /// mmap 发送窗口大小 MiB（每次映射字节上限 = 单连接 RSS 峰值上界）
    #[serde(default = "default_mmap_window")]
    pub mmap_window_mb: usize,
    /// 全进程 mmap 活跃窗口总预算 MiB（防 RAM 溢出硬边界；超出自动回退 read 流式）
    #[serde(default = "default_mmap_budget")]
    pub mmap_budget_mb: usize,
    /// 最大并发连接数（信号量，超出则排队）
    pub max_conn: usize,
    /// 读取请求体单块之间的空闲超时秒数（防止慢速攻击拖死连接）
    pub body_idle_timeout: u64,
    /// 流式传输块大小字节
    pub io_chunk_size: usize,
    /// 目录列表单页最大条目数
    #[serde(default = "default_max_listing")]
    pub max_listing: usize,
    /// 未知域名回落目录：wwwroot 下的子目录名（启动时自动创建）；空串 = 禁用（返 421）
    #[serde(default = "default_fallback_dir")]
    pub default_vhost_dir: String,
    /// 自定义响应头（应用于所有响应，可覆盖默认安全头，如 CDN TTL/CORS）
    #[serde(default)]
    pub custom_headers: HashMap<String, String>,
    /// 全局反代路由（vhost.routes 可整体覆盖）
    #[serde(default)]
    pub routes: Vec<ProxyRouteCfg>,
    /// 全局伪静态重写（vhost.rewrites 可整体覆盖）
    #[serde(default)]
    pub rewrites: Vec<RewriteCfg>,
    /// 速率限制（全局默认 + 存储后端设置）
    #[serde(default)]
    pub ratelimit: RateLimitCfg,
    /// HDD 适配模式（默认 false）：关闭 mmap、≥1MiB 顺序读、对文件发 SEQUENTIAL 预读提示
    #[serde(default)]
    pub hdd_mode: bool,
    /// 小文件内存缓存预算（MiB；0=关闭，默认关闭）
    #[serde(default)]
    pub small_cache_mb: usize,
    /// 可缓存的单文件上限（KiB）
    #[serde(default = "default_small_cache_max_kb")]
    pub small_cache_max_kb: usize,
    /// 应用层防护
    #[serde(default)]
    pub defense: DefenseCfg,
    /// 自定义错误页："404"/"4xx"/"5xx"/"default" -> wwwroot 相对路径；
    /// 页内支持 {{code}}/{{message}} 与 {code}/{message} 动态占位符
    #[serde(default)]
    pub error_pages: HashMap<String, String>,

    // ---------- 安全 ----------
    pub security: SecurityCfg,

    // ---------- 虚拟主机 host -> 站点 ----------
    pub vhosts: HashMap<String, VhostCfg>,

    // ---------- 日志 ----------
    /// 日志级别：debug | info | warn | error
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// 访问日志开关
    #[serde(default = "default_true")]
    pub access_log: bool,
    /// 配置文件变更自动热重载（轮询 mtime，间隔 1 秒，开销可忽略）
    #[serde(default = "default_true")]
    pub auto_reload: bool,
}

impl Config {
    pub fn from_file(path: &Path) -> anyhow::Result<Config> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("读取配置文件 {} 失败: {}", path.display(), e))?;
        Config::from_str(&data)
    }

    pub fn from_str(data: &str) -> anyhow::Result<Config> {
        let mut c: Config = toml::from_str(data)
            .map_err(|e| anyhow::anyhow!("配置文件解析失败: {}", e))?;
        c.normalize()?;
        Ok(c)
    }

    /// 修正默认值、校验必填项
    pub fn normalize(&mut self) -> anyhow::Result<()> {
        if self.listen.is_empty() {
            self.listen = "0.0.0.0".into();
        }
        if self.port == 0 {
            self.port = 8080;
        }
        if self.h3_port == 0 {
            self.h3_port = self.port + 1;
        }
        self.wwwroot = self.wwwroot.trim_end_matches('/').to_string();
        if self.wwwroot.is_empty() {
            return Err(anyhow::anyhow!("wwwroot 不能为空"));
        }
        if self.io_chunk_size == 0 || self.io_chunk_size > 4 * 1024 * 1024 {
            self.io_chunk_size = 262144;
        }
        if self.max_listing == 0 {
            self.max_listing = 10000;
        }
        if self.index_files.is_empty() {
            self.index_files = vec!["index.html".into()];
        }
        if self.max_conn == 0 {
            self.max_conn = 512;
        }
        match self.auth.mode.as_str() {
            "none" | "bearer" | "basic" | "any" | "" => {}
            other => return Err(anyhow::anyhow!("auth.mode 非法: {other}（可选 none/bearer/basic/any）")),
        }
        if self.auth.mode.is_empty() {
            self.auth.mode = "none".into();
        }
        if (self.tls_cert.is_some()) != (self.tls_key.is_some()) {
            return Err(anyhow::anyhow!("tls_cert 与 tls_key 必须同时配置"));
        }
        for (host, v) in &self.vhosts {
            if host.trim().is_empty() || host == "*" {
                return Err(anyhow::anyhow!("vhost 名称非法: {host:?}"));
            }
            if let Some(a) = &v.auth {
                match a.mode.as_str() {
                    "none" | "bearer" | "basic" | "any" => {}
                    other => return Err(anyhow::anyhow!("vhost {host} auth.mode 非法: {other}")),
                }
            }
            if let Some(ch) = &v.custom_headers {
                validate_headers(ch).map_err(|e| anyhow::anyhow!("vhost {host} {e}"))?;
            }
            if let Some(rs) = &v.routes {
                for (i, r) in rs.iter().enumerate() {
                    validate_route(&format!("vhost {host} routes[{i}]"), r)
                        .map_err(|e| anyhow::anyhow!(e))?;
                }
            }
            if let Some(ws) = &v.rewrites {
                for (i, w) in ws.iter().enumerate() {
                    validate_rewrite(&format!("vhost {host} rewrites[{i}]"), w)
                        .map_err(|e| anyhow::anyhow!(e))?;
                }
            }
            if let Some(rl) = &v.ratelimit {
                validate_ratelimit(&format!("vhost {host} ratelimit"), rl, false)
                    .map_err(|e| anyhow::anyhow!(e))?;
            }
        }
        if self.force_https && self.tls_cert.is_none() {
            return Err(anyhow::anyhow!("force_https = true 需要同时配置 TLS（tls_cert/tls_key）"));
        }
        // 回落目录名合法性：相对子目录名，禁止绝对路径与 ..
        if !self.default_vhost_dir.is_empty() {
            let d = &self.default_vhost_dir;
            if d.starts_with('/') || d.split('/').any(|seg| seg == ".." || seg == ".") {
                return Err(anyhow::anyhow!("default_vhost_dir 非法: {d:?}（须为 wwwroot 下的相对子目录名）"));
            }
        }
        // 自定义响应头：键/值合法性（防 CRLF 注入）
        validate_headers(&self.custom_headers)
            .map_err(|e| anyhow::anyhow!("custom_headers {e}"))?;
        // 错误页：键格式 + 路径合法性（相对 wwwroot，防穿越）
        for (k, v) in &self.error_pages {
            let ok = k == "default"
                || (k.len() == 3 && k.as_bytes()[1] == b'x' && k.as_bytes()[2] == b'x' && k.as_bytes()[0].is_ascii_digit())
                || (k.len() == 3 && k.as_bytes().iter().all(|b| b.is_ascii_digit()));
            if !ok {
                return Err(anyhow::anyhow!("error_pages 键非法: {k:?}（应为 \"404\" / \"4xx\" / \"default\" 等三位数或 x 通配）"));
            }
            if v.starts_with('/') {
                return Err(anyhow::anyhow!("error_pages[{k}] 必须是 wwwroot 相对路径"));
            }
            if fsops::normalize_path(v).is_err() {
                return Err(anyhow::anyhow!("error_pages[{k}] 路径非法: {v:?}"));
            }
        }
        // 全局反代/伪静态/限速校验
        for (i, r) in self.routes.iter().enumerate() {
            validate_route(&format!("routes[{i}]"), r).map_err(|e| anyhow::anyhow!(e))?;
        }
        for (i, w) in self.rewrites.iter().enumerate() {
            validate_rewrite(&format!("rewrites[{i}]"), w).map_err(|e| anyhow::anyhow!(e))?;
        }
        validate_ratelimit("ratelimit", &self.ratelimit, true).map_err(|e| anyhow::anyhow!(e))?;
        // v0.4.1 性能/防护参数
        if self.small_cache_mb > 4096 {
            return Err(anyhow::anyhow!("small_cache_mb 须在 0..=4096"));
        }
        if self.small_cache_max_kb == 0 || self.small_cache_max_kb > 4096 {
            return Err(anyhow::anyhow!("small_cache_max_kb 须在 1..=4096"));
        }
        if self.defense.max_header_kb < 8 || self.defense.max_header_kb > 1024 {
            return Err(anyhow::anyhow!("defense.max_header_kb 须在 8..=1024"));
        }
        if self.defense.violation_window_secs == 0 || self.defense.violation_window_secs > 86400 {
            return Err(anyhow::anyhow!("defense.violation_window_secs 须在 1..=86400"));
        }
        if self.defense.ban_secs == 0 || self.defense.ban_secs > 86400 {
            return Err(anyhow::anyhow!("defense.ban_secs 须在 1..=86400"));
        }
        if self.defense.max_conn_per_ip > 100_000 {
            return Err(anyhow::anyhow!("defense.max_conn_per_ip 过大（>100000）"));
        }
        Ok(())
    }
}

// ---------------- 运行期站点（合并全局默认后的生效配置） ----------------

#[derive(Debug, Clone)]
pub struct Site {
    pub root: PathBuf,
    /// 该站点的自定义响应头（vhost 覆盖全局；已验证合法性）
    pub custom_headers: Arc<Vec<(String, String)>>,
    pub dir_listing: bool,
    pub index_files: Vec<String>,
    pub auth: AuthPolicy,
    pub require_auth_write: bool,
    pub max_upload_size: u64,
    pub mkdir_on_upload: bool,
    pub sync_on_upload: bool,
    pub serve_dotfiles: bool,
    pub io_chunk_size: usize,
    pub body_idle_timeout: u64,
    pub max_listing: usize,
    /// 反代路由（已编译；按配置顺序前缀匹配）
    pub routes: Arc<Vec<Route>>,
    /// 伪静态重写（已编译）
    pub rewrites: Arc<Vec<Rewrite>>,
    /// 生效的限速策略（None = 关闭）
    pub ratelimit: Option<LimitPolicy>,
}

#[derive(Debug, Clone)]
pub enum AuthPolicy {
    None,
    Bearer(Vec<String>),
    Basic(HashMap<String, String>),
    Any(Vec<String>, HashMap<String, String>),
}

impl AuthPolicy {
    pub fn from_cfg(a: &AuthCfg) -> AuthPolicy {
        match a.mode.as_str() {
            "none" => AuthPolicy::None,
            "bearer" => AuthPolicy::Bearer(a.tokens.clone()),
            "basic" => AuthPolicy::Basic(a.users.clone()),
            _ => AuthPolicy::Any(a.tokens.clone(), a.users.clone()),
        }
    }
}

impl Site {
    /// 合并 VhostCfg -> Site（继承全局默认）
    pub fn resolve(global: &Config, host: Option<&str>) -> (String, Site) {
        let v = host
            .and_then(|h| global.vhosts.get(h))
            .or_else(|| host.and_then(|h| global.vhosts.get(&h.to_lowercase())));
        match v {
            Some(vc) => {
                let root = vc.wwwroot.clone().unwrap_or_else(|| global.wwwroot.clone());
                let auth = match &vc.auth {
                    Some(a) => AuthPolicy::from_cfg(a),
                    None => AuthPolicy::from_cfg(&global.auth),
                };
                let name = host.unwrap_or("default").to_string();
                (
                    name,
                    Site {
                        root: PathBuf::from(root.trim_end_matches('/')),
                        custom_headers: Arc::new(
                            vc.custom_headers
                                .clone()
                                .unwrap_or_else(|| global.custom_headers.clone())
                                .into_iter()
                                .collect(),
                        ),
                        dir_listing: vc.dir_listing.unwrap_or(global.dir_listing),
                        index_files: vc.index_files.clone().unwrap_or_else(|| global.index_files.clone()),
                        auth,
                        require_auth_write: vc.require_auth_write.unwrap_or(global.require_auth_write),
                        max_upload_size: vc.max_upload_size.unwrap_or(global.max_upload_size),
                        mkdir_on_upload: vc.mkdir_on_upload.unwrap_or(global.mkdir_on_upload),
                        sync_on_upload: vc.sync_on_upload.unwrap_or(global.sync_on_upload),
                        serve_dotfiles: global.serve_dotfiles,
                        io_chunk_size: global.io_chunk_size,
                        body_idle_timeout: global.body_idle_timeout,
                        max_listing: global.max_listing,
                        routes: Arc::new(Vec::new()),
                        rewrites: Arc::new(Vec::new()),
                        ratelimit: None,
                    },
                )
            }
            None => (
                host.unwrap_or("default").to_string(),
                Site {
                    root: PathBuf::from(global.wwwroot.trim_end_matches('/')),
                    custom_headers: Arc::new(global.custom_headers.clone().into_iter().collect()),
                    dir_listing: global.dir_listing,
                    index_files: global.index_files.clone(),
                    auth: AuthPolicy::from_cfg(&global.auth),
                    require_auth_write: global.require_auth_write,
                    max_upload_size: global.max_upload_size,
                    mkdir_on_upload: global.mkdir_on_upload,
                    sync_on_upload: global.sync_on_upload,
                    serve_dotfiles: global.serve_dotfiles,
                    io_chunk_size: global.io_chunk_size,
                    body_idle_timeout: global.body_idle_timeout,
                    max_listing: global.max_listing,
                    routes: Arc::new(Vec::new()),
                    rewrites: Arc::new(Vec::new()),
                    ratelimit: None,
                },
            ),
        }
    }
}

// ---------------- 运行期编译物：路由 / 重写 / 限速策略 ----------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XffMode {
    Set,
    Append,
    Off,
}

/// 已编译的反代路由
#[derive(Debug, Clone)]
pub struct Route {
    pub prefix: String,
    #[allow(dead_code)] // 保留原始上游 URI（诊断/未来使用）；转发实际用 upstream_base
    pub upstream: Uri,
    /// scheme://authority[+base]（无尾 '/'），与路径拼接即最终上游 URL
    pub upstream_base: String,
    pub strip_prefix: bool,
    pub preserve_host: bool,
    pub tls_verify: bool,
    pub timeout: Duration,
    pub set_req: Vec<(String, String)>,
    pub set_resp: Vec<(String, String)>,
    /// 小写形式
    pub remove_resp: Vec<String>,
    pub xff: XffMode,
}

impl Route {
    /// 前缀匹配（按路径段对齐：/api 不匹配 /api2）；返回剩余路径（"" 或 "/..."）
    pub fn match_rest<'a>(&self, path: &'a str) -> Option<&'a str> {
        if !path.starts_with(&self.prefix) {
            return None;
        }
        let rest = &path[self.prefix.len()..];
        if !rest.is_empty() && !rest.starts_with('/') && !self.prefix.ends_with('/') {
            return None;
        }
        Some(rest)
    }

    /// 计算转发到上游的路径（不含查询串）
    pub fn forward_path(&self, full_path: &str, rest: &str) -> String {
        if self.strip_prefix {
            if rest.is_empty() {
                "/".to_string()
            } else if rest.starts_with('/') {
                rest.to_string()
            } else {
                format!("/{rest}")
            }
        } else {
            full_path.to_string()
        }
    }
}

/// 已编译的伪静态规则
#[derive(Debug, Clone)]
pub struct Rewrite {
    pub re: regex::Regex,
    pub replace: String,
    pub keep_query: bool,
    pub redirect: u16,
}

impl Rewrite {
    /// 匹配并产生新路径；未匹配（或结果相同）返回 None
    pub fn apply(&self, path: &str) -> Option<String> {
        let out = self.re.replace(path, self.replace.as_str());
        if out.as_ref() == path {
            None
        } else {
            Some(out.into_owned())
        }
    }
}

/// 生效的限速策略（令牌桶：速率 + 突发容量）
#[derive(Debug, Clone, Copy)]
pub struct LimitPolicy {
    pub rate: f64,
    pub burst: f64,
}

fn sorted_map(m: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = m.iter().map(|(k, val)| (k.clone(), val.clone())).collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

/// 编译路由表
pub fn compile_routes(cfgs: &[ProxyRouteCfg]) -> anyhow::Result<Vec<Route>> {
    let mut out = Vec::with_capacity(cfgs.len());
    for (i, r) in cfgs.iter().enumerate() {
        validate_route(&format!("routes[{i}]"), r).map_err(|e| anyhow::anyhow!(e))?;
        let uri: Uri = r
            .upstream
            .parse()
            .map_err(|e| anyhow::anyhow!("routes[{i}] upstream 非法: {e}"))?;
        let mut base = String::new();
        base.push_str(uri.scheme_str().unwrap_or("http"));
        base.push_str("://");
        base.push_str(uri.authority().map(|a| a.as_str()).unwrap_or(""));
        let bp = uri.path().trim_end_matches('/');
        if bp != "/" && !bp.is_empty() {
            base.push_str(bp);
        }
        let xff = match r.xff.as_str() {
            "append" => XffMode::Append,
            "off" => XffMode::Off,
            _ => XffMode::Set,
        };
        out.push(Route {
            prefix: r.prefix.clone(),
            upstream: uri,
            upstream_base: base,
            strip_prefix: r.strip_prefix,
            preserve_host: r.preserve_host,
            tls_verify: r.tls_verify,
            timeout: Duration::from_secs(r.timeout),
            set_req: sorted_map(&r.set_request_headers),
            set_resp: sorted_map(&r.set_response_headers),
            remove_resp: r.remove_response_headers.iter().map(|s| s.to_ascii_lowercase()).collect(),
            xff,
        });
    }
    Ok(out)
}

/// 编译伪静态规则
pub fn compile_rewrites(cfgs: &[RewriteCfg]) -> anyhow::Result<Vec<Rewrite>> {
    let mut out = Vec::with_capacity(cfgs.len());
    for (i, w) in cfgs.iter().enumerate() {
        validate_rewrite(&format!("rewrites[{i}]"), w).map_err(|e| anyhow::anyhow!(e))?;
        let re = regex::Regex::new(&w.pattern)
            .map_err(|e| anyhow::anyhow!("rewrites[{i}] pattern 非法: {e}"))?;
        out.push(Rewrite {
            re,
            replace: w.replace.clone(),
            keep_query: w.keep_query,
            redirect: w.redirect,
        });
    }
    Ok(out)
}

/// 合成站点限速策略（vhost 覆盖全局的 rate/burst）
pub fn compile_limit(global: &RateLimitCfg, vhost: Option<&RateLimitCfg>) -> Option<LimitPolicy> {
    let rate = vhost.and_then(|v| v.rate).or(global.rate)?;
    let burst = vhost.and_then(|v| v.burst).or(global.burst)?;
    if rate > 0.0 && burst > 0.0 && rate.is_finite() && burst.is_finite() {
        Some(LimitPolicy { rate, burst })
    } else {
        None
    }
}

/// 将全局/vhost 的 routes/rewrites/ratelimit 编译进 Site
pub fn attach_extras(site: &mut Site, global: &Config, host: Option<&str>) -> anyhow::Result<()> {
    let v = host
        .and_then(|h| global.vhosts.get(h))
        .or_else(|| host.and_then(|h| global.vhosts.get(&h.to_lowercase())));
    let routes = v.and_then(|v| v.routes.as_deref()).unwrap_or(&global.routes);
    let rewrites = v.and_then(|v| v.rewrites.as_deref()).unwrap_or(&global.rewrites);
    site.routes = Arc::new(compile_routes(routes)?);
    site.rewrites = Arc::new(compile_rewrites(rewrites)?);
    site.ratelimit = compile_limit(&global.ratelimit, v.and_then(|v| v.ratelimit.as_ref()));
    Ok(())
}