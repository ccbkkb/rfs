//! 运行期“材质”：配置 + 已构建的 TLS 接受器
//! 通过 ArcSwap 原子切换以支持 SIGHUP 热重载（含证书热重载）。
use crate::config::Config;
use anyhow::Context;
use bytes::Bytes;
use std::path::PathBuf;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

pub struct Material {
    pub cfg: Config,
    /// 仅当开启了 TLS
    pub tls: Option<Arc<tokio_rustls::TlsAcceptor>>,
    /// 默认站点（wwwroot 根；单站点模式 / IP 直连时使用）；root 已 canonicalize
    pub default_site: Arc<crate::config::Site>,
    /// 虚拟主机表：小写 host -> 站点（root 已 canonicalize）
    pub sites: std::collections::HashMap<String, Arc<crate::config::Site>>,
    /// 未知域名回落站点（wwwroot/<default_vhost_dir>）；None = 禁用（返 421）
    pub fallback_site: Option<Arc<crate::config::Site>>,
    /// 强制 HTTPS：明文请求 301 跳转（需 TLS）
    pub force_https: bool,
    /// 全局自定义响应头（错误响应也携带；vhost 级覆盖见 Site.custom_headers）
    pub custom_global: Arc<Vec<(String, String)>>,
    /// 预读入内存的自定义错误页："404"/"4xx"/"5xx"/"default" -> (内容, Content-Type)
    pub error_page_bodies: std::collections::HashMap<String, (Bytes, String)>,
}

impl Material {
    /// 按 Host 键取自定义响应头（vhost 覆盖全局；与 process 的站点选择逻辑一致）
    pub fn custom_for(&self, host_key: &str) -> Arc<Vec<(String, String)>> {
        if self.sites.is_empty() {
            return self.custom_global.clone();
        }
        match self.sites.get(host_key) {
            Some(s) => s.custom_headers.clone(),
            None => self
                .fallback_site
                .as_ref()
                .map(|s| s.custom_headers.clone())
                .unwrap_or_else(|| self.custom_global.clone()),
        }
    }
}

impl Material {
    pub fn try_new(cfg: Config) -> anyhow::Result<Material> {
        let force_https = cfg.force_https;
        let tls = match (&cfg.tls_cert, &cfg.tls_key) {
            (Some(cert), Some(key)) => {
                let rcfg = build_rustls_config(cert, key, &[b"h2", b"http/1.1"])
                    .context("构建 TLS 配置失败")?;
                Some(Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(rcfg))))
            }
            _ => None,
        };
        // 确保 wwwroot 存在（缺失则创建，方便首次部署），并预规范化站点表
        if let Err(e) = std::fs::create_dir_all(&cfg.wwwroot) {
            anyhow::bail!("创建 wwwroot {} 失败: {e}", cfg.wwwroot);
        }
        for (host, vc) in &cfg.vhosts {
            if let Some(root) = &vc.wwwroot {
                std::fs::create_dir_all(root)
                    .with_context(|| format!("创建 vhost {host} 根目录 {root} 失败"))?;
            }
        }

        let canonicalize_root = |root: &str| -> anyhow::Result<PathBuf> {
            std::fs::canonicalize(root)
                .with_context(|| format!("规范化站点根目录 {root} 失败"))
        };

        let mut default_site = crate::config::Site::resolve(&cfg, None).1;
        default_site.root = canonicalize_root(&cfg.wwwroot)?;

        let mut sites = std::collections::HashMap::new();
        for host in cfg.vhosts.keys() {
            let (name, mut site) = crate::config::Site::resolve(&cfg, Some(host));
            let root = site
                .root
                .to_str()
                .context("站点根目录路径非法")?
                .to_string();
            site.root = canonicalize_root(&root)?;
            sites.insert(name.to_lowercase(), Arc::new(site));
        }

        // 未知域名回落目录：wwwroot/<default_vhost_dir>（自动创建 + 可读校验）
        let fallback_site = if cfg.default_vhost_dir.is_empty() {
            None // 显式禁用：未知域名返 421
        } else {
            let dir = std::path::Path::new(&cfg.wwwroot).join(&cfg.default_vhost_dir);
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("创建回落目录 {} 失败", dir.display()))?;
            let canon = canonicalize_root(dir.to_str().context("路径非法")?)?;
            std::fs::read_dir(&canon)
                .with_context(|| format!("回落目录 {} 不可读", canon.display()))?;
            let mut s = crate::config::Site::resolve(&cfg, None).1;
            s.root = canon;
            Some(Arc::new(s))
        };

        // 预读自定义错误页（单个 ≤1MiB，防 OOM）
        let mut error_page_bodies = std::collections::HashMap::new();
        for (k, v) in &cfg.error_pages {
            let norm = crate::fsops::normalize_path(v)
                .map_err(|e| anyhow::anyhow!("error_pages[{k}] 路径非法: {e:?}"))?;
            let full = default_site.root.join(&norm);
            let data = std::fs::read(&full)
                .with_context(|| format!("读取错误页 error_pages[{k}] ({}) 失败", full.display()))?;
            anyhow::ensure!(
                data.len() <= 1024 * 1024,
                "错误页 error_pages[{k}] 过大（>1MiB）"
            );
            let ctype = if v.ends_with(".html") || v.ends_with(".htm") {
                "text/html; charset=utf-8"
            } else {
                "text/plain; charset=utf-8"
            };
            error_page_bodies.insert(k.clone(), (Bytes::from(data), ctype.to_string()));
        }

        let custom_global = Arc::new(cfg.custom_headers.clone().into_iter().collect());

        Ok(Material {
            cfg,
            tls,
            default_site: Arc::new(default_site),
            sites,
            fallback_site,
            force_https,
            custom_global,
            error_page_bodies,
        })
    }
}

/// 构建 rustls ServerConfig（TLS/HTTP2 用 ALPN h2+http/1.1；QUIC 用 h3）
pub fn build_rustls_config(
    cert_path: &str,
    key_path: &str,
    alpn: &[&[u8]],
) -> anyhow::Result<rustls::ServerConfig> {
    let certs = {
        let f = File::open(cert_path).with_context(|| format!("打开证书 {}", cert_path))?;
        rustls_pemfile::certs(&mut BufReader::new(f))
            .collect::<Result<Vec<_>, _>>()
            .context("解析证书失败")?
    };
    if certs.is_empty() {
        anyhow::bail!("证书文件 {} 中没有证书", cert_path);
    }
    let key = {
        let f = File::open(key_path).with_context(|| format!("打开私钥 {}", key_path))?;
        rustls_pemfile::private_key(&mut BufReader::new(f))
            .context("解析私钥失败")?
            .ok_or_else(|| anyhow::anyhow!("私钥文件 {} 中没有私钥", key_path))?
    };
    let mut rcfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("加载证书/私钥失败")?;
    rcfg.alpn_protocols = alpn.iter().map(|v| v.to_vec()).collect();
    Ok(rcfg)
}