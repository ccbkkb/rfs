//! rfs - 轻量级 Rust 静态文件服务器（HTTP/1.1 + HTTP/2 + HTTP/3）
//! 启动：rfs -c rfs.toml
//! 热重载：kill -HUP <pid>（配置/证书原子切换，失败保留旧配置），或配置 auto_reload=true

mod auth;
mod config;
mod core;
mod fsops;
mod h3srv;
mod httpd;
mod log;
mod material;
mod proxy;
mod ratelimit;

use arc_swap::ArcSwap;
use config::{Config, DEFAULT_CONFIG};
use material::Material;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinSet;

const DEFAULT_CONFIG_TEMPLATE: &str = r#"# rfs 配置文件示例
# rfs -c 此文件 即可启动；SIGHUP 热重载（配置与 TLS 证书）
#
# ⚠ 注意：TOML 中裸键必须放在所有 [表]（如 [auth]/[security]/[vhosts]）之前，
#   否则会归入前面的表而失效。下面所有根级键都在最前面。

# 监听地址与端口
listen = "0.0.0.0"
port = 8080
# 默认站点根目录（wwwroot）
wwwroot = "/srv/www"

# ---------- TLS（可选；开启后同一端口同时支持 HTTPS + H2） ----------
# tls_cert = "/etc/rfs/cert.pem"
# tls_key  = "/etc/rfs/key.pem"

# ---------- HTTP/3（可选；需要 TLS） ----------
enable_h3 = false
h3_port = 8443

# ---------- 安全头与跨域（[security] 表见文件下方） ----------
# 令牌/用户写在下方 [auth] 表中
require_auth_write = true   # 写操作（上传/删除/移动）强制鉴权；true 且未配置鉴权时写操作返回 401

# ---------- 静态内容 ----------
dir_listing = true
index_files = ["index.html"]
serve_dotfiles = false      # 是否允许访问 .env 等隐藏文件

# ---------- 上传 ----------
max_upload_size = 0         # 0 = 不限；单位字节
mkdir_on_upload = true      # 上传时自动创建父目录
sync_on_upload = true       # 落盘 fsync 后再原子改名

# ---------- 性能与保护（防 OOM / 防慢速攻击） ----------
max_conn = 512              # 最大并发连接
body_idle_timeout = 60      # 请求体单块间空闲超时（秒）
io_chunk_size = 262144            # 流式块大小（64KiB~4MiB）
max_listing = 10000         # 目录列表单页最大条目数
mmap_send = true            # 大文件 mmap 零拷贝发送（>=1MiB 启用；防 OOM 预算见下）
mmap_window_mb = 4          # mmap 发送窗口 MiB（单连接 RSS 峰值上界）
mmap_budget_mb = 256        # 全进程 mmap 活跃窗口总预算 MiB（超出回退 read 流式）

# ---------- 日志 ----------
log_level = "info"          # debug | info | warn | error
access_log = true           # 访问日志
auto_reload = true          # 配置文件变更自动热重载（轮询间隔 1s，开销可忽略）

# ---------- v0.3.0 新增：未知域名回落 / 自定义头 / 错误页 / 强制HTTPS ----------
default_vhost_dir = "default"   # 未知域名与 IP 直连回落到 wwwroot/default（自动创建）；空串=禁用（返 421）
custom_headers = { }            # 自定义响应头（所有响应；可覆盖默认安全头，如 CDN TTL/CORS）
                                # 例：{ "X-CDN-TTL" = "300", "Cache-Control" = "public, max-age=86400" }
# force_https = true            # TLS 开启时，同端口明文请求 301 跳转到 https://（需配置 TLS）

[error_pages]                   # 自定义错误页（wwwroot 相对路径；{{code}}/{{message}} 会被替换为实际值）
# "404" = "errors/404.html"     # 精确码
# "5xx" = "errors/5xx.html"     # 类通配（4xx/5xx）
# "default" = "errors/all.html" # 默认

# ---------- 鉴权 ----------
[auth]
mode = "none"               # none | bearer | basic | any
tokens = []                 # bearer 令牌，可多个
# users = { "admin" = "admin123" }   # basic 用户名=密码

# ---------- 安全（防跨站/防嗅探/防点击劫持） ----------
[security]
csrf = true                       # 防跨站：写方法校验 Origin/Sec-Fetch-Site
frame_deny = true                 # X-Frame-Options: DENY
nosniff = true                    # X-Content-Type-Options: nosniff
hsts = true                       # TLS 下启用 HSTS
hsts_age = 31536000
csp = true                        # Content-Security-Policy: default-src 'none'
referrer_policy = true
hide_version = false              # Server 头隐藏版本号

# ---------- 虚拟主机：不同域名绑定不同根目录（可选） ----------
# [vhosts."a.example.com"]
# wwwroot = "/srv/a"
# dir_listing = false
# [vhosts."a.example.com".auth]
# mode = "bearer"
# tokens = ["sec123"]
# [vhosts."b.example.com"]
# wwwroot = "/srv/b"
"#;

struct Args {
    config_path: String,
    check: bool,
    gen: bool,
    port: Option<u16>,
    wwwroot: Option<String>,
    listen: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        config_path: DEFAULT_CONFIG.to_string(),
        check: false,
        gen: false,
        port: None,
        wwwroot: None,
        listen: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-V" | "--version" => {
                println!("rfs {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => {
                println!(
                    "rfs {} - 轻量级 Rust 静态文件服务器\n\
                     \n\
                     用法: rfs [选项]\n\
                     \x20 -c, --config <路径>   配置文件（默认 {}）\n\
                     \x20 --check               校验配置后退出\n\
                     \x20 --gen                 生成示例配置（配合 -c 指定输出路径）\n\
                     \x20 --port <端口>         覆盖监听端口\n\
                     \x20 --wwwroot <目录>      覆盖根目录\n\
                     \x20 --listen <地址>       覆盖监听地址\n\
                     \x20 -h, --help            帮助\n\
                     \n\
                     运行期控制：\n\
                     \x20 SIGHUP     热重载配置与 TLS 证书\n\
                     \x20 SIGTERM/SIGINT  优雅退出（等在途请求最多 5 秒）\n\
                     \n\
                     接口：\n\
                     \x20 GET/HEAD  /path            下载（支持 Range/ETag/304 与目录浏览）\n\
                     \x20 PUT       /path            上传（流式，原子落盘）\n\
                     \x20 DELETE    /path            删除（目录非空需 X-Recursive: true）\n\
                     \x20 MOVE      /src             移动/重命名（头 Destination: /dst）\n\
                     \x20 OPTIONS   /                列出允许的方法\n",
                    env!("CARGO_PKG_VERSION"),
                    DEFAULT_CONFIG
                );
                std::process::exit(0);
            }
            "-c" | "--config" => {
                let v = it.next().ok_or("缺少 --config 参数值")?;
                args.config_path = v;
            }
            "--check" => args.check = true,
            "--gen" => args.gen = true,
            "--port" => {
                let v = it.next().ok_or("缺少 --port 参数值")?.parse().map_err(|_| "端口非法")?;
                args.port = Some(v);
            }
            "--wwwroot" => {
                let v = it.next().ok_or("缺少 --wwwroot 参数值")?;
                args.wwwroot = Some(v);
            }
            "--listen" => {
                let v = it.next().ok_or("缺少 --listen 参数值")?;
                args.listen = Some(v);
            }
            other => return Err(format!("未知参数: {other}（-h 查看帮助）")),
        }
    }
    Ok(args)
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("参数错误: {e}");
            std::process::exit(2);
        }
    };

    if args.gen {
        let dest = if args.config_path != DEFAULT_CONFIG {
            args.config_path.clone()
        } else {
            "rfs.toml".to_string()
        };
        if Path::new(&dest).exists() {
            eprintln!("{dest} 已存在，不覆盖");
            std::process::exit(1);
        }
        std::fs::write(&dest, DEFAULT_CONFIG_TEMPLATE).unwrap_or_else(|e| {
            eprintln!("写入 {dest} 失败: {e}");
            std::process::exit(1);
        });
        println!("已生成示例配置 {dest}");
        return;
    }

    let mut cfg = match Config::from_file(Path::new(&args.config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("配置加载失败: {e}\n提示：可用 --gen 生成示例配置文件");
            std::process::exit(1);
        }
    };
    // 显式安装 TLS 加密后端（依赖图里 quinn 会顺带启用 aws-lc-rs，
    // 与 ring 并存时 rustls 无法自动选择，这里手动固定使用 ring）
    let _ = rustls::crypto::ring::default_provider().install_default();

    // quinn/h3 底层日志：默认只输出警告，可用 RUST_LOG=quinn=trace 全量调
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("quinn=warn,quinn_proto=warn,h3=warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();

    // CLI 覆盖
    if let Some(p) = args.port {
        cfg.port = p;
    }
    if let Some(w) = args.wwwroot {
        cfg.wwwroot = w.trim_end_matches('/').to_string();
    }
    if let Some(l) = args.listen {
        cfg.listen = l;
    }

    log::set_level(&cfg.log_level);
    log::set_access(cfg.access_log);

    // mmap 发送的全局预算（防 RAM 溢出硬边界）
    let _ = httpd::mmap_budget_init(cfg.mmap_budget_mb as u64 * 1024 * 1024);
    // SIGBUS 兜底：外部截断正在 mmap 发送的大文件时内核会发 SIGBUS；
    // 快速失败（写 stderr + exit 70）优于未定义行为，配合外部 supervisor 自动重启。
    httpd::install_sigbus_handler();

    let material = match Material::try_new(cfg) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("初始化失败: {e}");
            std::process::exit(1);
        }
    };
    let material = Arc::new(ArcSwap::new(Arc::new(material)));

    if args.check {
        let m = material.load_full();
        println!(
            "配置校验通过: {}\n  HTTP: {}:{}  wwwroot={}  TLS={}  H3={}  vhosts={}\n  max_conn={} chunk={} legs={} auth={} csrf={} routes={} rewrites={} rl={}",
            args.config_path,
            m.cfg.listen,
            m.cfg.port,
            m.cfg.wwwroot,
            m.cfg.tls_cert.is_some(),
            m.cfg.enable_h3,
            m.cfg.vhosts.len(),
            m.cfg.max_conn,
            m.cfg.io_chunk_size,
            m.cfg.max_listing,
            m.cfg.auth.mode,
            m.cfg.security.csrf,
            m.cfg.routes.len(),
            m.cfg.rewrites.len(),
            m.cfg.ratelimit.storage
        );
        return;
    }

    let cfg_clone = material.load_full().cfg.clone();
    let addr: SocketAddr = format!("{}:{}", cfg_clone.listen, cfg_clone.port)
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("监听地址非法: {}:{}", cfg_clone.listen, cfg_clone.port);
            std::process::exit(1);
        });

    let mut tasks: JoinSet<anyhow::Result<()>> = JoinSet::new();
    {
        let m = material.clone();
        tasks.spawn(async move { httpd::run(m, addr).await });
    }
    if cfg_clone.enable_h3 {
        let h3_addr: SocketAddr = format!("{}:{}", cfg_clone.listen, cfg_clone.h3_port)
            .parse()
            .unwrap_or_else(|_| {
                eprintln!("HTTP/3 监听地址非法: {}:{}", cfg_clone.listen, cfg_clone.h3_port);
                std::process::exit(1);
            });
        let m = material.clone();
        tasks.spawn(async move { h3srv::run_h3(m, h3_addr).await });
    }
    if cfg_clone.auto_reload {
        let m = material.clone();
        let p = args.config_path.clone();
        tasks.spawn(async move {
            let mut last = std::fs::metadata(&p).and_then(|x| x.modified()).ok();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let now = std::fs::metadata(&p).and_then(|x| x.modified()).ok();
                if now.is_some() && now != last {
                    last = now;
                    reload(&m, &p);
                }
            }
        });
    }

    log_info!("rfs {} 启动完成，配置 {}", env!("CARGO_PKG_VERSION"), args.config_path);
    log_info!("  控制台: SIGHUP=热重载 SIGTERM/SIGINT=优雅退出");

    // 信号处理任务
    let mut sig_hup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("注册 SIGHUP 失败: {e}");
            std::process::exit(1);
        }
    };
    let mut sig_term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("注册 SIGTERM 失败: {e}");
            std::process::exit(1);
        }
    };
    let mut sig_int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("注册 SIGINT 失败: {e}");
            std::process::exit(1);
        }
    };

    let signal_task = {
        let material = material.clone();
        let p = args.config_path.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sig_term.recv() => {
                        log_info!("收到 SIGTERM，准备退出");
                        return;
                    }
                    _ = sig_int.recv() => {
                        log_info!("收到 SIGINT，准备退出");
                        return;
                    }
                    _ = sig_hup.recv() => reload(&material, &p),
                }
            }
        })
    };

    // 主循环：等待退出信号或监听任务异常退出
    tokio::select! {
        _ = signal_task => {}
        r = tasks.join_next(), if !tasks.is_empty() => {
            match r {
                Some(Ok(Ok(()))) => {}
                Some(Ok(Err(e))) => log_error!("监听任务异常退出: {e}"),
                Some(Err(e)) => log_error!("监听任务被中止: {e}"),
                None => {}
            }
        }
    }

    log_info!("正在等待在途请求完成（最多 5 秒）……");
    tasks.abort_all();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        async {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        },
    )
    .await;
    log_info!("已退出");
}

/// 热重载：校验失败则保留旧配置（日志提示）
fn reload(material: &Arc<ArcSwap<Material>>, path: &str) {
    match Config::from_file(Path::new(path)) {
        Ok(mut cfg) => {
            if let Err(e) = cfg.normalize() {
                log_error!("重载校验失败，保留旧配置: {e}");
                return;
            }
            match Material::try_new(cfg) {
                Ok(new_m) => {
                    log::set_level(&new_m.cfg.log_level);
                    log::set_access(new_m.cfg.access_log);
                    material.store(Arc::new(new_m));
                    log_info!("配置热重载成功（{path}）");
                }
                Err(e) => log_error!("重载失败（TLS 等初始化错误），保留旧配置: {e}"),
            }
        }
        Err(e) => log_error!("重载失败，保留旧配置: {e}"),
    }
}