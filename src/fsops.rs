//! 文件系统操作：路径安全归一化、下载/上传/删除/移动/目录列表
//! 安全要点：
//!  - 百分号解码后的路径逐段归一化，拒绝任何能逃出根目录的组合（..、.、空段）
//!  - 最终目标路径做 canonicalize 校验，禁止符号链接逃出站点根目录（防跨站访问）
//!  - 上传先写同目录临时文件，流式落盘（内存占用有界，防 OOM），完成后再原子 rename
//!  - 目录列表条目数有上限，超大目录不会打爆内存

use crate::config::Site;
use http::StatusCode;
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub enum FsError {
    BadRequest(String),   // 400
    Forbidden(String),    // 403
    NotFound(String),     // 404
    Conflict(String),     // 409
    TooLarge(u64),        // 413
    Io(io::Error),        // 500
}

impl FsError {
    pub fn status(&self) -> StatusCode {
        match self {
            FsError::BadRequest(_) => StatusCode::BAD_REQUEST,
            FsError::Forbidden(_) => StatusCode::FORBIDDEN,
            FsError::NotFound(_) => StatusCode::NOT_FOUND,
            FsError::Conflict(_) => StatusCode::CONFLICT,
            FsError::TooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            FsError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    pub fn msg(&self) -> String {
        match self {
            FsError::BadRequest(m) => m.clone(),
            FsError::Forbidden(m) => m.clone(),
            FsError::NotFound(m) => m.clone(),
            FsError::Conflict(m) => m.clone(),
            FsError::TooLarge(n) => format!("文件超过大小限制（上限 {n} 字节）"),
            FsError::Io(e) => format!("IO 错误: {e}"),
        }
    }
}

/// 归一化 URL 路径（已百分号解码的原始路径），返回相对路径（无前导 '/'）
/// 非法路径（越界）返回 Err
pub fn normalize_path(raw: &str) -> Result<String, FsError> {
    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| FsError::BadRequest("路径编码非法".into()))?;
    if decoded.as_bytes().contains(&0) {
        return Err(FsError::BadRequest("路径包含空字节".into()));
    }
    let mut stack: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                if stack.pop().is_none() {
                    return Err(FsError::Forbidden("路径越界".into()));
                }
            }
            _ => stack.push(seg),
        }
    }
    Ok(stack.join("/"))
}

/// 将相对路径解析到站点根下的绝对路径；
/// 校验 canonicalize 后仍在根目录内（防符号链接逃逸）。
/// for_write=true 时只要求父目录存在并合法（对已存在的文件/目录同样适用）。
/// 供 PUT 使用：父目录不存在且 mkdir=true 时自动创建，随后做符号链接逃逸校验。
pub async fn resolve_write(canon_root: &Path, rel: &str, mkdir: bool) -> Result<PathBuf, FsError> {
    let combined = canon_root.join(rel);
    let parent = combined.parent().unwrap_or(canon_root);
    if mkdir {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return Err(FsError::Io(e));
        }
    }
    resolve(canon_root, rel, true).await
}
/// canon_root：站点根目录的规范化路径（Material 启动时已算好，避免每请求 realpath）
pub async fn resolve(canon_root: &Path, rel: &str, for_write: bool) -> Result<PathBuf, FsError> {
    let combined = canon_root.join(rel);
    if for_write {
        let parent = combined.parent().unwrap_or(canon_root);
        // 父目录必须已存在（mkdir 由调用方先做，这里只校验）
        let canon_parent = match tokio::fs::canonicalize(parent).await {
            Ok(p) => p,
            Err(_) => return Err(FsError::NotFound("目标父目录不存在".into())),
        };
        if !canon_parent.starts_with(canon_root) {
            return Err(FsError::Forbidden("目标越出站点根目录".into()));
        }
        let name = combined
            .file_name()
            .ok_or_else(|| FsError::BadRequest("非法路径".into()))?;
        Ok(canon_parent.join(name))
    } else {
        let c = match tokio::fs::canonicalize(&combined).await {
            Ok(c) => c,
            Err(_) => return Err(FsError::NotFound("资源不存在".into())),
        };
        if !c.starts_with(&canon_root) {
            return Err(FsError::Forbidden("资源越出站点根目录".into()));
        }
        Ok(c)
    }
}

/// 目录列表 HTML（条目数受 cfg.max_listing 限制）
pub fn listing_html(
    entries: &mut Vec<(String, u64, bool)>, // (名称, 大小或0, 是否目录)
    display_path: &str,
    max: usize,
) -> String {
    entries.sort_by(|a, b| {
        b.2.cmp(&a.2).then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
    });
    let truncated = entries.len() > max;
    entries.truncate(max);
    let mut out = String::with_capacity(1024 + entries.len() * 96);
    out.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Index of ");
    out.push_str(&html_escape(display_path));
    out.push_str("</title><style>body{font-family:monospace;margin:2em}table{border-collapse:collapse}td,th{padding:4px 16px;text-align:left;border-bottom:1px solid #ddd}a{text-decoration:none}</style></head><body><h1>Index of ");
    out.push_str(&html_escape(display_path));
    out.push_str("</h1><table><thead><tr><th>名称</th><th>类型</th><th>大小</th></tr></thead><tbody>");
    if display_path != "/" {
        out.push_str("<tr><td><a href=\"../\">../</a></td><td>目录</td><td>-</td></tr>");
    }
    for (name, size, is_dir) in entries.iter() {
        let href = percent_encode_segment(name);
        out.push_str("<tr><td><a href=\"");
        out.push_str(&href);
        if *is_dir {
            out.push('/');
        }
        out.push_str("\">");
        out.push_str(&html_escape(name));
        if *is_dir {
            out.push('/');
        }
        out.push_str("</a></td><td>");
        out.push_str(if *is_dir { "目录" } else { "文件" });
        out.push_str("</td><td>");
        if !is_dir {
            out.push_str(&human_size(*size));
        } else {
            out.push('-');
        }
        out.push_str("</td></tr>");
    }
    out.push_str("</tbody></table>");
    if truncated {
        out.push_str("<p>… 条目过多，仅显示前若干项</p>");
    }
    out.push_str("</body></html>");
    out
}

pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn percent_encode_segment(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// RFC 7232 条件请求校验：ETag / Last-Modified
/// 返回 true 表示"客户端已有最新副本"，应返回 304
pub fn is_not_modified(etag: &str, last_modified: &str, headers: &http::HeaderMap) -> bool {
    if let Some(et) = headers.get("if-none-match").and_then(|v| v.to_str().ok()) {
        return et.split(',').any(|t| t.trim() == "*" || t.trim() == etag);
    }
    if let Some(ims) = headers.get("if-modified-since").and_then(|v| v.to_str().ok()) {
        if let Ok(t) = httpdate::parse_http_date(ims) {
            if let Ok(lm) = httpdate::parse_http_date(last_modified) {
                return t >= lm;
            }
        }
    }
    false
}

pub fn etag_for(mtime_ns_epoch: u128, len: u64) -> String {
    format!("\"{:x}-{:x}\"", mtime_ns_epoch, len)
}

/// 上传：流式写入临时文件 -> fsync -> 原子 rename
pub async fn begin_upload(site: &Site, path: &Path, counter: &AtomicU64) -> Result<(tokio::fs::File, PathBuf), FsError> {
    let parent = path.parent().unwrap_or(path);
    if site.mkdir_on_upload {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| FsError::Io(e))?;
    }
    let id = counter.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".rfs-upload-{}-{}.part", std::process::id(), id));
    let f = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .await
        .map_err(FsError::Io)?;
    Ok((f, tmp))
}

pub async fn commit_upload(
    file: tokio::fs::File,
    tmp: &Path,
    target: &Path,
    sync: bool,
) -> Result<u64, FsError> {
    let meta = file.metadata().await.map_err(FsError::Io)?;
    let len = meta.len();
    if sync {
        file.sync_all().await.map_err(FsError::Io)?;
    }
    drop(file);
    match tokio::fs::rename(tmp, target).await {
        Ok(_) => Ok(len),
        Err(e) => {
            let _ = tokio::fs::remove_file(tmp).await;
            Err(FsError::Io(e))
        }
    }
}

/// 删除：文件或目录。目录非空时必须 recursive=true
pub async fn remove(path: &Path, recursive: bool) -> Result<(), FsError> {
    let meta = tokio::fs::symlink_metadata(path).await.map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            FsError::NotFound("资源不存在".into())
        } else {
            FsError::Io(e)
        }
    })?;
    if meta.is_dir() {
        if recursive {
            tokio::fs::remove_dir_all(path).await.map_err(FsError::Io)?;
        } else {
            // 只允许删除空目录
            let mut rd = tokio::fs::read_dir(path).await.map_err(FsError::Io)?;
            if rd.next_entry().await.map_err(FsError::Io)?.is_some() {
                return Err(FsError::Conflict("目录非空，需 X-Recursive: true".into()));
            }
            tokio::fs::remove_dir(path).await.map_err(FsError::Io)?;
        }
    } else {
        tokio::fs::remove_file(path).await.map_err(FsError::Io)?;
    }
    Ok(())
}

/// 移动/重命名：目标相对路径（dst_rel）归一化并校验仍在站点根内
pub async fn move_within(
    root: &Path,
    src: &Path,
    dst_rel: &str,
) -> Result<PathBuf, FsError> {
    let dst = resolve(root, dst_rel, true).await?;
    if src == dst {
        return Err(FsError::Conflict("源与目标相同".into()));
    }
    if tokio::fs::symlink_metadata(&dst).await.is_ok() {
        return Err(FsError::Conflict("目标已存在".into()));
    }
    tokio::fs::rename(src, &dst).await.map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            FsError::NotFound("源文件不存在".into())
        } else {
            FsError::Io(e)
        }
    })?;
    Ok(dst)
}

pub fn untrusted_display(rel: &str) -> String {
    if rel.is_empty() {
        "/".to_string()
    } else {
        format!("/{rel}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_basic() {
        assert_eq!(normalize_path("/a/b/c").unwrap(), "a/b/c");
        assert_eq!(normalize_path("/a/./b/").unwrap(), "a/b");
        assert_eq!(normalize_path("a//b").unwrap(), "a/b");
        assert_eq!(normalize_path("/").unwrap(), "");
    }

    #[test]
    fn norm_traversal_rejected() {
        assert!(normalize_path("/../etc/passwd").is_err());
        assert!(normalize_path("/a/../../b").is_err());
        assert!(normalize_path("/%2e%2e/etc/passwd").is_err()); // 编码的 ..
        assert!(normalize_path("/%00").is_err());
        assert!(normalize_path("/..").is_err());
    }

    #[test]
    fn norm_ok_with_dotdot_inside() {
        assert_eq!(normalize_path("/a/b/../c").unwrap(), "a/c");
        assert_eq!(normalize_path("/a/..").unwrap(), "");
    }

    #[test]
    fn range_parse() {
        assert_eq!(parse_range("bytes=0-99", 200), Some((0, 99)));
        assert_eq!(parse_range("bytes=100-", 200), Some((100, 199)));
        assert_eq!(parse_range("bytes=-50", 200), Some((150, 199)));
        assert_eq!(parse_range("bytes=0-0", 200), Some((0, 0)));
        assert_eq!(parse_range("bytes=200-300", 200), None); // start 越界
        assert_eq!(parse_range("bytes=abc", 200), None);
        assert_eq!(parse_range("", 200), None);
    }
}

/// 解析单个 Range: "bytes=start-end"；返回 (start, end) 闭区间（end 为实际值）
pub fn parse_range(h: &str, len: u64) -> Option<(u64, u64)> {
    let h = h.trim();
    let spec = h.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None; // 多段范围不支持，回退整文件
    }
    let (a, b) = spec.split_once('-').unwrap_or((spec, ""));
    if a.is_empty() {
        // suffix: -N
        let n: u64 = b.parse().ok()?;
        if n == 0 {
            return None;
        }
        if len == 0 {
            return None;
        }
        let start = len.saturating_sub(n);
        return Some((start, len - 1));
    }
    let start: u64 = a.parse().ok()?;
    if start >= len {
        return None;
    }
    let end = if b.is_empty() { len - 1 } else { b.parse::<u64>().ok()?.min(len - 1) };
    if end < start {
        return None;
    }
    Some((start, end))
}