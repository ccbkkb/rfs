//! 核心请求处理：与具体 HTTP 协议（1.1/2/3）无关
//! HTTP/1.x 与 HTTP/2 通过 [crate::httpd] 适配，HTTP/3 通过 [crate::h3srv] 适配。
//! 内存安全：所有文件内容流式读写（块大小可配，默认 64KiB），绝无整文件进内存；上传先落临时文件再原子改名。

use crate::auth::{self, AuthResult};
use crate::config::{Config, Site};
use crate::fsops::{self, FsError};
use bytes::Bytes;
use http::{HeaderMap, Method};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, OnceLock};

pub const SERVER_NAME: &str = concat!("rfs/", env!("CARGO_PKG_VERSION"));

// ---------------- 流式适配接口 ----------------

pub type BoxFut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

pub trait ReadBody: Send {
    /// 读取下一块请求体；None 表示结束。错误返回后连接将终止。
    fn next(&mut self) -> BoxFut<'_, Result<Option<Bytes>, String>>;
}

pub trait Responder: Send {
    /// 发送响应头（可能被推迟到首次 send_body 时真正发出，见 H3 适配）
    fn headers(&mut self, status: u16, headers: Vec<(String, String)>) -> BoxFut<'_, Result<(), String>>;
    fn send_body(&mut self, b: Bytes) -> BoxFut<'_, Result<(), String>>;
    /// 流式发送文件（正文）。协议适配层可覆盖为按需读取（HTTP/1.x 必须覆盖，
    /// 否则有界通道会在 service 返回前被写满而死锁）；默认实现循环 send_body。
    fn send_file(
        &mut self,
        path: &std::path::Path,
        start: u64,
        len: u64,
        chunk: usize,
        use_mmap: bool,
        _window_size: usize,
    ) -> BoxFut<'_, Result<(), String>> {
        // H3 默认实现：tokio 同步读流式（H3 已用 QUIC 流控反压，无需 mmap）
        let _ = use_mmap;
        let p = path.to_path_buf();
        Box::pin(async move { stream_file_to(&p, start, len, chunk, self).await })
    }
    fn finish(&mut self) -> BoxFut<'_, Result<(), String>>;
}

/// 默认的文件流式发送（供 H3 等覆盖实现使用）
async fn stream_file_to<R: Responder + ?Sized>(
    path: &std::path::Path,
    start: u64,
    len: u64,
    chunk: usize,
    resp: &mut R,
) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut f = tokio::fs::File::open(path).await.map_err(|e| e.to_string())?;
    if start > 0 {
        f.seek(std::io::SeekFrom::Start(start)).await.map_err(|e| e.to_string())?;
    }
    let cap = chunk.max(4096);
    let mut buf = vec![0u8; cap];
    let mut remain = len;
    while remain > 0 {
        let want = remain.min(cap as u64) as usize;
        let n = f.read(&mut buf[..want]).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        resp.send_body(Bytes::copy_from_slice(&buf[..n])).await?;
        remain -= n as u64;
    }
    Ok(())
}

// ---------------- 请求上下文 ----------------

pub struct RequestCtx {
    pub method: Method,
    pub raw_path: String,
    /// 完整请求目标（path + query），用于 301 跳转等
    pub target: String,
    pub host: Option<String>,
    pub headers: HeaderMap,
    /// 对端 IP（HTTP/1.x、H3 均提供；用于限速与转发头）
    pub peer_ip: Option<std::net::IpAddr>,
    pub tls: bool,
}

#[derive(Default)]
pub struct Outcome {
    pub bytes_sent: u64,
}

// ---------------- 安全头 ----------------

pub(crate) fn sec_headers(cfg: &Config, tls: bool, out: &mut Vec<(String, String)>) {
    let s = &cfg.security;
    if s.frame_deny {
        out.push(("x-frame-options".into(), "DENY".into()));
    }
    if s.nosniff {
        out.push(("x-content-type-options".into(), "nosniff".into()));
    }
    if s.csp {
        out.push(("content-security-policy".into(), "default-src 'none'".into()));
    }
    if s.referrer_policy {
        out.push(("referrer-policy".into(), "no-referrer".into()));
    }
    if s.hsts && tls {
        out.push(("strict-transport-security".into(), format!("max-age={}", s.hsts_age)));
    }
    if !s.hide_version {
        out.push(("server".into(), SERVER_NAME.into()));
    }
}

// ---------------- 防跨站（CSRF） ----------------

fn is_mutating(m: &Method) -> bool {
    matches!(*m, Method::PUT | Method::DELETE | Method::POST | Method::PATCH)
}

/// 写方法要求同源：携带 Origin / Sec-Fetch-Site 时校验；无这类头（curl 等）放行。
fn csrf_check(cfg: &Config, ctx: &RequestCtx) -> Result<(), FsError> {
    if !cfg.security.csrf || !is_mutating(&ctx.method) {
        return Ok(());
    }
    let host = ctx.host.as_deref().unwrap_or("");
    let host_only = host.split(':').next().unwrap_or(host);

    if let Some(origin) = ctx.headers.get("origin").and_then(|v| v.to_str().ok()) {
        let origin_host = origin
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .unwrap_or(origin);
        let origin_only = origin_host.split(':').next().unwrap_or(origin_host);
        let ok = origin_only == host_only || origin_only == host;
        if !ok {
            return Err(FsError::Forbidden("跨站请求被拒绝（CSRF 防护）".into()));
        }
    } else if let Some(sfs) = ctx.headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if sfs.eq_ignore_ascii_case("cross-site") {
            return Err(FsError::Forbidden("跨站请求被拒绝（CSRF 防护）".into()));
        }
    }
    Ok(())
}

// ---------------- 主处理 ----------------

pub async fn process<B: ReadBody + 'static, R: Responder>(
    material: &crate::material::Material,
    ctx: &RequestCtx,
    body_in: Option<B>,
    resp: &mut R,
) -> Result<Outcome, ()> {
    let cfg = &material.cfg;
    let mut body_in = body_in;

    // 强制 HTTPS：TLS 开启时，同端口的明文 HTTP 请求 301 跳转到 https://
    if material.force_https && !ctx.tls {
        let host = ctx.host.as_deref().unwrap_or("");
        let host_ok = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b));
        if !host_ok {
            let mut out = vec![
                ("content-type".into(), "text/plain; charset=utf-8".into()),
                ("content-length".into(), "0".into()),
            ];
            sec_headers(cfg, ctx.tls, &mut out);
            resp.headers(400, out).await.map_err(|_| ())?;
            resp.finish().await.map_err(|_| ())?;
            return Ok(Outcome::default());
        }
        let host_only = host_no_port(host);
        let port_part = if cfg.port != 443 {
            format!(":{}", cfg.port)
        } else {
            String::new()
        };
        let loc = format!("https://{host_only}{port_part}{}", ctx.target);
        let mut out = vec![
            ("location".into(), loc),
            ("content-length".into(), "0".into()),
        ];
        sec_headers(cfg, ctx.tls, &mut out);
        resp.headers(301, out).await.map_err(|_| ())?;
        resp.finish().await.map_err(|_| ())?;
        return Ok(Outcome::default());
    }

    if let Err(e) = csrf_check(cfg, ctx) {
        return send_error(material, resp, e, ctx).await;
    }

    // Host -> 站点：
    //  - 无 vhost 配置（单站点模式）：所有 Host 都走 wwwroot 根
    //  - 有 vhost：域名匹配 → 对应站点；未匹配（含 IP 直连）→ 安全回落：
    //    wwwroot/<default_vhost_dir>（禁用时 421）。
    //    安全性：IP 直连不例外，否则可绕过 vhost 隔离与站点级鉴权（v0.3.1）
    let host_key = ctx
        .host
        .as_deref()
        .map(|h| h.split(':').next().unwrap_or(h).to_lowercase())
        .unwrap_or_default();
    let site: Arc<Site> = if material.sites.is_empty() {
        // 单站点模式：无 vhost 概念，全部走 wwwroot 根
        material.default_site.clone()
    } else {
        match material.sites.get(&host_key) {
            Some(s) => s.clone(),
            None => match &material.fallback_site {
                Some(s) => s.clone(),
                None => {
                    let mut out = vec![
                        ("content-type".into(), "text/plain; charset=utf-8".into()),
                        ("content-length".into(), "0".into()),
                    ];
                    sec_headers(cfg, ctx.tls, &mut out);
                    resp.headers(421, out).await.map_err(|_| ())?;
                    resp.finish().await.map_err(|_| ())?;
                    return Ok(Outcome::default());
                }
            },
        }
    };
    let site = &*site;

    // 速率限制（在鉴权前执行，抵御口令爆破与枚举；429 带 Retry-After）
    if let Some(policy) = &site.ratelimit {
        if let Err(retry) = material.ratelimit.check(policy, ctx.peer_ip).await {
            let body = Bytes::from_static(b"429 Too Many Requests\n");
            let mut out = vec![
                ("content-type".into(), "text/plain; charset=utf-8".into()),
                ("content-length".into(), body.len().to_string()),
                ("retry-after".into(), retry.to_string()),
            ];
            sec_headers(cfg, ctx.tls, &mut out);
            resp.headers(429, out).await.map_err(|_| ())?;
            resp.send_body(body.clone()).await.map_err(|_| ())?;
            resp.finish().await.map_err(|_| ())?;
            return Ok(Outcome { bytes_sent: body.len() as u64 });
        }
    }

    // 鉴权：写操作强制鉴权（require_auth_write）或站点配置了鉴权时，所有请求都要验
    let need_auth = (is_mutating(&ctx.method) && site.require_auth_write)
        || !matches!(site.auth, crate::config::AuthPolicy::None);
    if need_auth {
        match auth::check(&site.auth, &ctx.headers) {
            AuthResult::Ok => {}
            _ => return send_401(cfg, resp, &site, ctx).await,
        }
    }

    // 路径归一化（防目录穿越）
    let mut rel = match fsops::normalize_path(&ctx.raw_path) {
        Ok(r) => r,
        Err(e) => return send_error(material, resp, e, ctx).await,
    };

    // 伪静态/重写（内部重写可链式，最多 8 跳；结果必须是合法内部路径）
    if !site.rewrites.is_empty() {
        for _ in 0..8 {
            let path_ct = if rel.is_empty() { "/".to_string() } else { format!("/{rel}") };
            let mut changed = false;
            for rw in site.rewrites.iter() {
                if let Some(newp) = rw.apply(&path_ct) {
                    if !newp.starts_with('/') || newp.starts_with("//") {
                        return send_error(material, resp, FsError::Forbidden("重写结果非法".into()), ctx).await;
                    }
                    let inner = match fsops::normalize_path(&newp) {
                        Ok(x) => x,
                        Err(_) => return send_error(material, resp, FsError::Forbidden("重写结果非法".into()), ctx).await,
                    };
                    if rw.redirect != 0 {
                        let q = if rw.keep_query {
                            ctx.target.split_once('?').map(|(_, q)| format!("?{q}")).unwrap_or_default()
                        } else {
                            String::new()
                        };
                        let loc = format!("/{}{}", crate::proxy::encode_path(&inner), q);
                        let mut out = vec![
                            ("location".into(), loc),
                            ("content-length".into(), "0".into()),
                        ];
                        sec_headers(cfg, ctx.tls, &mut out);
                        resp.headers(rw.redirect, out).await.map_err(|_| ())?;
                        resp.finish().await.map_err(|_| ())?;
                        return Ok(Outcome::default());
                    }
                    rel = inner;
                    changed = true;
                    break;
                }
            }
            if !changed {
                break;
            }
        }
    }

    // 反向代理路由（先于静态处理；不适用点文件策略，因为没有本地文件访问）
    if !site.routes.is_empty() {
        let path_ct = if rel.is_empty() { "/".to_string() } else { format!("/{rel}") };
        for route in site.routes.iter() {
            if route.match_rest(&path_ct).is_some() {
                // 方法白名单：CONNECT/TRACE 等一律拒绝（CONNECT 不在 is_mutating 中、会绕过写鉴权；TRACE 可能回显注入头）
                if !matches!(
                    ctx.method.as_str(),
                    "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
                ) {
                    let mut out = vec![(
                        "allow".into(),
                        "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS".into(),
                    )];
                    sec_headers(cfg, ctx.tls, &mut out);
                    resp.headers(405, out).await.map_err(|_| ())?;
                    resp.finish().await.map_err(|_| ())?;
                    return Ok(Outcome::default());
                }
                return crate::proxy::forward(material, site, route, &rel, ctx, body_in.take(), resp).await;
            }
        }
    }

    // 隐藏点文件
    if !site.serve_dotfiles {
        for seg in rel.split('/') {
            if seg.starts_with('.') && !seg.is_empty() {
                return send_error(material, resp, FsError::NotFound("资源不存在".into()), ctx).await;
            }
        }
    }
    if rel.is_empty() && is_mutating(&ctx.method) {
        return send_error(material, resp, FsError::Forbidden("根目录不允许写操作".into()), ctx).await;
    }

    let m = ctx.method.clone();
    let path = match m.as_str() {
        "GET" | "HEAD" => fsops::resolve(&site.root, &rel, false).await,
        "PUT" => fsops::resolve_write(&site.root, &rel, site.mkdir_on_upload).await,
        _ => fsops::resolve(&site.root, &rel, true).await,
    };
    let path = match path {
        Ok(p) => p,
        Err(e) => return send_error(material, resp, e, ctx).await,
    };

    match m.as_str() {
        "GET" => do_get(material, cfg, &site, &rel, &path, ctx, resp, false).await,
        "HEAD" => do_get(material, cfg, &site, &rel, &path, ctx, resp, true).await,
        "PUT" => do_put(material, cfg, &site, &path, body_in.as_mut(), resp, ctx).await,
        "DELETE" => do_delete(material, cfg, &site, &path, ctx, resp).await,
        "MOVE" => do_move(material, cfg, &site, &path, ctx, resp).await,
        "OPTIONS" => {
            let mut out = vec![
                ("allow".into(), "GET, HEAD, PUT, DELETE, MOVE, OPTIONS".into()),
                ("accept-ranges".into(), "bytes".into()),
            ];
            sec_headers(cfg, ctx.tls, &mut out);
            resp.headers(204, out).await.map_err(|_| ())?;
            resp.finish().await.map_err(|_| ())?;
            Ok(Outcome { bytes_sent: 0 })
        }
        _ => {
            let mut out = vec![("allow".into(), "GET, HEAD, PUT, DELETE, MOVE, OPTIONS".into())];
            sec_headers(cfg, ctx.tls, &mut out);
            resp.headers(405, out).await.map_err(|_| ())?;
            resp.finish().await.map_err(|_| ())?;
            Ok(Outcome { bytes_sent: 0 })
        }
    }
}

// ---------------- GET / HEAD ----------------

async fn do_get<R: Responder>(
    material: &crate::material::Material,
    cfg: &Config,
    site: &Site,
    rel: &str,
    path: &std::path::Path,
    ctx: &RequestCtx,
    resp: &mut R,
    head_only: bool,
) -> Result<Outcome, ()> {
    let meta = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(_) => return send_error(material, resp, FsError::NotFound("资源不存在".into()), ctx).await,
    };

    // 目录：优先索引文件，其次目录列表
    if meta.is_dir() {
        for idx in &site.index_files {
            let p = path.join(idx);
            if let Ok(m) = tokio::fs::metadata(&p).await {
                if m.is_file() {
                    return serve_file(cfg, site, &p, &m, ctx, resp, head_only).await;
                }
            }
        }
        if !site.dir_listing {
            return send_error(material, resp, FsError::Forbidden("目录浏览已关闭".into()), ctx).await;
        }
        let display = fsops::untrusted_display(rel.trim_end_matches('/'));
        let mut entries: Vec<(String, u64, bool)> = Vec::new();
        let mut rd = match tokio::fs::read_dir(path).await {
            Ok(r) => r,
            Err(e) => return send_error(material, resp, FsError::Io(e), ctx).await,
        };
        loop {
            match rd.next_entry().await {
                Ok(Some(e)) => {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.starts_with('.') && !site.serve_dotfiles {
                        continue;
                    }
                    let is_dir = e.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
                    let size = if is_dir { 0 } else { e.metadata().await.map(|m| m.len()).unwrap_or(0) };
                    entries.push((name, size, is_dir));
                    if entries.len() > site.max_listing + 64 {
                        break; // 超大目录截断，防内存膨胀
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        let html = fsops::listing_html(&mut entries, &display, site.max_listing);
        let len = html.len() as u64;
        let mut out = vec![
            ("content-type".into(), "text/html; charset=utf-8".into()),
            ("content-length".into(), len.to_string()),
            ("cache-control".into(), "no-store".into()),
        ];
        sec_headers(cfg, ctx.tls, &mut out);
        resp.headers(200, out).await.map_err(|_| ())?;
        if !head_only {
            resp.send_body(Bytes::from(html)).await.map_err(|_| ())?;
        }
        resp.finish().await.map_err(|_| ())?;
        return Ok(Outcome { bytes_sent: if head_only { 0 } else { len } });
    }

    serve_file(cfg, site, path, &meta, ctx, resp, head_only).await
}

async fn serve_file<R: Responder>(
    cfg: &Config,
    site: &Site,
    path: &std::path::Path,
    meta: &std::fs::Metadata,
    ctx: &RequestCtx,
    resp: &mut R,
    head_only: bool,
) -> Result<Outcome, ()> {
    let len = meta.len();
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let etag = fsops::etag_for(mtime_ns, len);
    let last_modified = httpdate::fmt_http_date(std::time::UNIX_EPOCH + std::time::Duration::from_nanos(mtime_ns as u64));

    // 条件请求（缓存 304）
    if fsops::is_not_modified(&etag, &last_modified, &ctx.headers) {
        let mut out = vec![
            ("etag".into(), etag),
            ("last-modified".into(), last_modified),
            ("cache-control".into(), "no-cache".into()),
        ];
        sec_headers(cfg, ctx.tls, &mut out);
        resp.headers(304, out).await.map_err(|_| ())?;
        resp.finish().await.map_err(|_| ())?;
        return Ok(Outcome { bytes_sent: 0 });
    }

    // Range
    let mut status: u16 = 200;
    let mut start = 0u64;
    let mut end = len.saturating_sub(1);
    let mut content_range: Option<String> = None;
    if let Some(r) = ctx.headers.get("range").and_then(|v| v.to_str().ok()) {
        match fsops::parse_range(r, len) {
            Some((s, e)) => {
                status = 206;
                start = s;
                end = e;
                content_range = Some(format!("bytes {s}-{e}/{len}"));
            }
            None if r.starts_with("bytes=") => {
                let mut out = vec![("content-range".into(), format!("bytes */{len}"))];
                sec_headers(cfg, ctx.tls, &mut out);
                resp.headers(416, out).await.map_err(|_| ())?;
                resp.finish().await.map_err(|_| ())?;
                return Ok(Outcome { bytes_sent: 0 });
            }
            _ => {}
        }
    }

    let body_len = if len == 0 { 0 } else { end - start + 1 };
    let mut out = vec![
        ("content-type".into(), mime_guess(path).into()),
        ("content-length".into(), body_len.to_string()),
        ("accept-ranges".into(), "bytes".into()),
        ("etag".into(), etag),
        ("last-modified".into(), last_modified),
        ("cache-control".into(), "no-cache".into()),
    ];
    if let Some(cr) = content_range {
        out.push(("content-range".into(), cr));
    }
    sec_headers(cfg, ctx.tls, &mut out);
    resp.headers(status, out).await.map_err(|_| ())?;

    if head_only || body_len == 0 {
        resp.finish().await.map_err(|_| ())?;
        return Ok(Outcome::default());
    }

    // 流式发送：转交响应层按需读取（内存恒定；HTTP/1.x 不再经过有界通道）
    // 大文件（>=1MiB）且开启 mmap 时，HTTP/1.x 走分段 mmap 零拷贝窗口
    let use_mmap = cfg.mmap_send && body_len >= 1024 * 1024;
    resp
        .send_file(
            path,
            start,
            body_len,
            site.io_chunk_size.max(4096),
            use_mmap,
            cfg.mmap_window_mb * 1024 * 1024,
        )
        .await
        .map_err(|_| ())?;
    resp.finish().await.map_err(|_| ())?;
    Ok(Outcome { bytes_sent: body_len })
}

// ---------------- PUT（上传） ----------------

static UPLOAD_COUNTER: OnceLock<AtomicU64> = OnceLock::new();

fn upload_counter() -> &'static AtomicU64 {
    UPLOAD_COUNTER.get_or_init(|| AtomicU64::new(1))
}

async fn do_put<B: ReadBody, R: Responder>(
    material: &crate::material::Material,
    cfg: &Config,
    site: &Site,
    path: &std::path::Path,
    body_in: Option<&mut B>,
    resp: &mut R,
    ctx: &RequestCtx,
) -> Result<Outcome, ()> {
    let Some(body) = body_in else {
        return send_error(material, resp, FsError::BadRequest("缺少请求体".into()), ctx).await;
    };
    // 目标是目录时拒绝（避免 rename 失败产生 500）
    if let Ok(md) = tokio::fs::symlink_metadata(path).await {
        if md.is_dir() {
            return send_error(
                material,
                resp,
                FsError::Conflict("目标是目录，无法写入文件".into()),
                ctx,
            )
            .await;
        }
    }
    let existed = tokio::fs::symlink_metadata(path).await.is_ok();
    let counter = upload_counter();

    let (mut file, tmp) = match fsops::begin_upload(site, path, counter).await {
        Ok(v) => v,
        Err(e) => return send_error(material, resp, e, ctx).await,
    };

    let mut total: u64 = 0;
    let idle_timeout = std::time::Duration::from_secs(site.body_idle_timeout.clamp(1, 3600));
    loop {
        let chunk = match tokio::time::timeout(idle_timeout, body.next()).await {
            Err(_) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                return send_error(material, resp, FsError::BadRequest("上传空闲超时".into()), ctx).await;
            }
            Ok(Err(_)) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                return send_error(material, resp, FsError::BadRequest("读取请求体失败".into()), ctx).await;
            }
            Ok(Ok(None)) => break,
            Ok(Ok(Some(c))) => c,
        };
        let clen = chunk.len() as u64;
        if site.max_upload_size > 0 && total + clen > site.max_upload_size {
            let _ = tokio::fs::remove_file(&tmp).await;
            return send_error(material, resp, FsError::TooLarge(site.max_upload_size), ctx).await;
        }
        use tokio::io::AsyncWriteExt;
        if let Err(e) = file.write_all(&chunk).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return send_error(material, resp, FsError::Io(e), ctx).await;
        }
        total += clen;
    }

    match fsops::commit_upload(file, &tmp, path, site.sync_on_upload).await {
        Ok(_) => {}
        Err(e) => return send_error(material, resp, e, ctx).await,
    }
    let mut out = vec![("content-type".into(), "text/plain; charset=utf-8".into()), ("content-length".into(), "0".into())];
    sec_headers(cfg, ctx.tls, &mut out);
    let status = if existed { 200 } else { 201 };
    resp.headers(status, out).await.map_err(|_| ())?;
    resp.finish().await.map_err(|_| ())?;
    Ok(Outcome { bytes_sent: 0 })
}

// ---------------- DELETE ----------------

async fn do_delete<R: Responder>(
    material: &crate::material::Material,
    cfg: &Config,
    _site: &Site,
    path: &std::path::Path,
    ctx: &RequestCtx,
    resp: &mut R,
) -> Result<Outcome, ()> {
    let recursive = ctx
        .headers
        .get("x-recursive")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    if let Err(e) = fsops::remove(path, recursive).await {
        return send_error(material, resp, e, ctx).await;
    }
    let mut out = vec![("content-length".into(), "0".into())];
    sec_headers(cfg, ctx.tls, &mut out);
    resp.headers(204, out).await.map_err(|_| ())?;
    resp.finish().await.map_err(|_| ())?;
    Ok(Outcome { bytes_sent: 0 })
}

// ---------------- MOVE（移动/重命名） ----------------

async fn do_move<R: Responder>(
    material: &crate::material::Material,
    cfg: &Config,
    site: &Site,
    src: &std::path::Path,
    ctx: &RequestCtx,
    resp: &mut R,
) -> Result<Outcome, ()> {
    let dst_raw = match ctx.headers.get("destination").and_then(|v| v.to_str().ok()) {
        Some(d) => d.to_string(),
        None => return send_error(material, resp, FsError::BadRequest("缺少 Destination 头".into()), ctx).await,
    };
    // 允许完整 URL 或纯路径
    let dst_path = if let Some(idx) = dst_raw.find("://") {
        match dst_raw[idx + 3..].find('/') {
            Some(s) => &dst_raw[idx + 3 + s..],
            None => "/",
        }
    } else {
        &dst_raw
    };
    let dst_rel = match fsops::normalize_path(dst_path) {
        Ok(r) => r,
        Err(e) => return send_error(material, resp, e, ctx).await,
    };
    if dst_rel.is_empty() {
        return send_error(material, resp, FsError::BadRequest("目标不能是根目录".into()), ctx).await;
    }
    if let Err(e) = fsops::move_within(&site.root, src, &dst_rel).await {
        return send_error(material, resp, e, ctx).await;
    }
    let mut out = vec![("content-length".into(), "0".into())];
    sec_headers(cfg, ctx.tls, &mut out);
    resp.headers(201, out).await.map_err(|_| ())?;
    resp.finish().await.map_err(|_| ())?;
    Ok(Outcome { bytes_sent: 0 })
}

// ---------------- 响应工具 ----------------

async fn send_401<R: Responder>(cfg: &Config, resp: &mut R, site: &Site, ctx: &RequestCtx) -> Result<Outcome, ()> {
    let challenge = match site.auth {
        crate::config::AuthPolicy::Bearer(_) => "Bearer realm=\"rfs\"".to_string(),
        crate::config::AuthPolicy::Basic(_) => "Basic realm=\"rfs\"".to_string(),
        _ => "Basic realm=\"rfs\", Bearer realm=\"rfs\"".to_string(),
    };
    let mut out = vec![
        ("www-authenticate".into(), challenge),
        ("content-type".into(), "text/plain; charset=utf-8".into()),
        ("content-length".into(), "2".into()),
    ];
    sec_headers(cfg, ctx.tls, &mut out);
    resp.headers(401, out).await.map_err(|_| ())?;
    resp.send_body(Bytes::from_static(b"no")).await.map_err(|_| ())?;
    resp.finish().await.map_err(|_| ())?;
    Ok(Outcome { bytes_sent: 2 })
}

pub async fn send_error<R: Responder>(
    material: &crate::material::Material,
    resp: &mut R,
    e: FsError,
    ctx: &RequestCtx,
) -> Result<Outcome, ()> {
    let cfg = &material.cfg;
    let status = e.status().as_u16();

    // 自定义错误页：精确码 > 类通配（4xx/5xx）> default；支持 {{code}}/{{message}} 占位符
    let key_p = status.to_string();
    let key_c = format!("{}xx", status / 100);
    let page = material
        .error_page_bodies
        .get(&key_p)
        .or_else(|| material.error_page_bodies.get(&key_c))
        .or_else(|| material.error_page_bodies.get("default"));

    let (body, ctype) = match page {
        Some((raw, ctype)) => {
            let code = status.to_string();
            let msg_esc = crate::fsops::html_escape(&e.msg());
            let s = String::from_utf8_lossy(raw).to_string();
            let s = s
                .replace("{{code}}", &code)
                .replace("{{message}}", &msg_esc)
                .replace("{code}", &code)
                .replace("{message}", &msg_esc);
            (Bytes::from(s), ctype.to_string())
        }
        None => (
            Bytes::from(format!("{status} {}\n", e.msg())),
            "text/plain; charset=utf-8".to_string(),
        ),
    };
    let blen = body.len() as u64;
    let mut out = vec![
        ("content-type".into(), ctype),
        ("content-length".into(), blen.to_string()),
    ];
    sec_headers(cfg, ctx.tls, &mut out);
    resp.headers(status, out).await.map_err(|_| ())?;
    resp.send_body(body).await.map_err(|_| ())?;
    resp.finish().await.map_err(|_| ())?;
    Ok(Outcome { bytes_sent: blen })
}

/// 从 Host 头提取不含端口的主机部分（兼容 IPv6 字面量）
fn host_no_port(h: &str) -> &str {
    if h.starts_with('[') {
        match h.find(']') {
            Some(i) => &h[..=i],
            None => h,
        }
    } else {
        h.split(':').next().unwrap_or(h)
    }
}

// ---------------- MIME ----------------

fn mime_guess(p: &std::path::Path) -> &'static str {
    let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "txt" | "md" | "log" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "avif" => "image/avif",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "flac" => "audio/flac",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mkv" => "video/x-matroska",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "tar" => "application/x-tar",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/vnd.rar",
        "bz2" => "application/x-bzip2",
        "xz" => "application/x-xz",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        "apk" => "application/vnd.android.package-archive",
        "deb" => "application/vnd.debian.binary-package",
        "exe" => "application/x-msdownload",
        "iso" => "application/x-iso9660-image",
        _ => "application/octet-stream",
    }
}