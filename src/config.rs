//! 配置解析与校验
//! 支持 TOML 格式；启动时读取，SIGHUP 热重载（校验失败则保留旧配置）。
use crate::fsops;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
                },
            ),
        }
    }
}