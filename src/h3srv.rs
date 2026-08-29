//! HTTP/3（QUIC）服务器：quinn 0.11 + h3 0.0.8
//! 与 HTTP/1/2 共用同一套核心逻辑；请求体/响应体均流式，内存有界。
//!
//! 可靠性：quinn 在某些平台（尤其 Android/Linux 边缘场景）存在已知的
//! “recv-only 流 drop 后 endpoint driver 不再被唤醒”问题，表现为新连接握手
//! 永久超时。这里内置 watchdog：定时用独立客户端 QUIC 连接自探测，一旦探测
//! 失败（握手超时），立即关闭并重建服务端 endpoint（同端口），实现自愈。

use crate::core::{self, ReadBody, RequestCtx, Responder};
use crate::material::Material;
use crate::{log_debug, log_error, log_info, log_warn};
use arc_swap::ArcSwap;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// 具体流类型：h3-quinn 的双向流
type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

const PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const REBUILD_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

pub async fn run_h3(material: Arc<ArcSwap<Material>>, addr: SocketAddr) -> anyhow::Result<()> {
    // 外层：endpoint 因任何原因退出（含 watchdog 自愈触发）后重建
    let mut fail_count = 0u32;
    loop {
        match run_h3_once(material.clone(), addr).await {
            Ok(()) => {
                log_warn!("HTTP/3 endpoint 已退出，{REBUILD_DELAY:?} 后重建");
                fail_count = 0;
            }
            Err(e) => {
                fail_count += 1;
                log_error!("HTTP/3 endpoint 错误: {e}");
                if fail_count >= 10 {
                    return Err(anyhow::anyhow!("HTTP/3 连续重建失败，放弃: {e}"));
                }
            }
        }
        let _ = material;
        tokio::time::sleep(REBUILD_DELAY).await;
    }
}

async fn run_h3_once(material: Arc<ArcSwap<Material>>, addr: SocketAddr) -> anyhow::Result<()> {
    let m = material.load_full();
    let cfg = &m.cfg;
    let (cert, key) = match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => anyhow::bail!("启用 HTTP/3 必须同时配置 tls_cert 与 tls_key"),
    };
    let rcfg = crate::material::build_rustls_config(&cert, &key, &[b"h3"])?;
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rcfg)
        .map_err(|e| anyhow::anyhow!("构建 QUIC TLS 配置失败: {e}"))?;
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(128u32.into())
        .keep_alive_interval(Some(std::time::Duration::from_secs(20)));
    server_cfg.transport_config(Arc::new(transport));

    let endpoint = quinn::Endpoint::server(server_cfg, addr)?;
    log_info!("HTTP/3 (QUIC) 监听 {addr}");

    // watchdog：定期自探测；探测失败代表 endpoint driver 失活，主动 close 触发重建
    let probe_ep = match quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()) {
        Ok(mut ep) => match probe_client_crypto() {
            Ok(cfg) => {
                ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(cfg)));
                Some(ep)
            }
            Err(e) => {
                log_warn!("H3 watchdog 客户端配置失败: {e}; 跳过自愈");
                None
            }
        },
        Err(e) => {
            log_warn!("H3 watchdog 探针初始化失败: {e}; 跳过自愈");
            None
        }
    };
    if let Some(probe_ep) = probe_ep {
        let endpoint = endpoint.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(PROBE_INTERVAL).await;
                let healthy = self_probe(&probe_ep, addr).await;
                log_debug!("H3 健康探测结果: healthy={healthy}");
                if !healthy {
                    log_error!("H3 健康探测失败（endpoint 疑似失活），触发重建");
                    endpoint.close(0u32.into(), b"watchdog");
                    break;
                }
            }
        });
    }

    loop {
        match endpoint.accept().await {
            Some(incoming) => {
                let material = material.clone();
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    h3_conn(material, conn).await;
                });
            }
            None => {
                log_debug!("HTTP/3 endpoint 停止接受新连接（watchdog 或主动关闭）");
                return Ok(());
            }
        }
    }
}

/// 自探测：用独立客户端 endpoint 向自身发起 QUIC 连接
/// 成功返回 true；握手超时/失败返回 false
fn probe_client_crypto() -> anyhow::Result<quinn::crypto::rustls::QuicClientConfig> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    Ok(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?)
}

async fn self_probe(probe_ep: &quinn::Endpoint, addr: SocketAddr) -> bool {
    let result = tokio::time::timeout(PROBE_TIMEOUT, async {
        match probe_ep.connect(addr, "rfs-self-probe") {
            Ok(connecting) => match connecting.await {
                Ok(conn) => {
                    conn.close(0u32.into(), b"probe");
                    true
                }
                Err(e) => {
                    log_error!("probe 握手失败: {e}");
                    false
                }
            },
            Err(e) => {
                log_error!("probe 连接失败: {e}");
                false
            }
        }
    })
    .await;
    match result {
        Ok(v) => v,
        Err(_) => {
            log_error!("probe 握手超时");
            false
        }
    }
}

/// 跳过证书校验的自测 verifier（仅用于内部探针，绝不用于对外服务）
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn h3_conn(material: Arc<ArcSwap<Material>>, conn: quinn::Connection) {
    let mut server = match h3::server::builder()
        .build(h3_quinn::Connection::new(conn))
        .await
    {
        Ok(s) => s,
        Err(e) => {
            log_debug!("HTTP/3 连接建立失败: {e}");
            return;
        }
    };
    let mut err_streak = 0u32;
    loop {
        match server.accept().await {
            Ok(Some(resolver)) => {
                err_streak = 0;
                let material = material.clone();
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => h3_req(material, req, stream).await,
                        Err(e) => log_debug!("HTTP/3 请求解析失败: {e}"),
                    }
                });
            }
            Ok(None) => break, // GOAWAY / 连接关闭，所有请求已处理完
            Err(e) => {
                // 连接关闭后 h3 可能反复报错；连续报错视为连接终态，退出循环
                // 防止在失效连接上空转（CPU 自旋）
                err_streak += 1;
                log_debug!("HTTP/3 accept 错误 #{err_streak}: {e}");
                if err_streak >= 3 {
                    break;
                }
                continue;
            }
        }
    }
}

async fn h3_req(material: Arc<ArcSwap<Material>>, req: http::Request<()>, stream: H3Stream) {
    let start = Instant::now();
    let m = material.load();
    let method = req.method().clone();
    let raw_path = req.uri().path().to_string();
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // QUIC 连接上无法直接取对端地址，日志中标记为 quic
    let ctx = RequestCtx {
        method: method.clone(),
        raw_path: raw_path.clone(),
        target: req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| raw_path.clone()),
        host: host.clone(),
        headers: req.headers().clone(),
        tls: true,
    };

    let shared = Arc::new(H3Conn {
        stream: Mutex::new(Some(stream)),
        started: std::sync::atomic::AtomicBool::new(false),
    });
    // 自定义响应头（vhost 覆盖全局）
    let host_key = host
        .as_deref()
        .map(|h| h.split(':').next().unwrap_or(h).to_lowercase())
        .unwrap_or_default();
    let custom = m.custom_for(&host_key);
    let mut responder = H3Responder {
        shared: shared.clone(),
        status: 500,
        headers: Vec::new(),
        custom,
    };
    let mut body_in = H3BodyIn { shared: shared.clone(), done: false };

    let outcome = core::process(&m, &ctx, Some(&mut body_in), &mut responder).await;
    let status = responder.status;
    let bytes = outcome.map(|o| o.bytes_sent).unwrap_or(0);
    crate::log::access(
        "quic",
        method.as_str(),
        &raw_path,
        status,
        bytes,
        start.elapsed().as_millis(),
        host.as_deref().unwrap_or(""),
    );
}

struct H3Conn {
    stream: Mutex<Option<H3Stream>>,
    /// 响应头是否已发送（同一流只能 send_response 一次）
    started: std::sync::atomic::AtomicBool,
}

fn build_h3_response(
    status: u16,
    headers: &[(String, String)],
    custom: &[(String, String)],
) -> http::Response<()> {
    let mut resp = http::Response::new(());
    *resp.status_mut() =
        http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    resp.headers_mut().insert(
        http::header::HeaderName::from_static("server"),
        http::header::HeaderValue::from_static(crate::core::SERVER_NAME),
    );
    for (k, v) in headers {
        if let (Ok(n), Ok(val)) = (
            http::header::HeaderName::from_bytes(k.as_bytes()),
            http::header::HeaderValue::from_str(v),
        ) {
            resp.headers_mut().append(n, val);
        }
    }
    // 自定义响应头（insert 覆盖同名默认头）
    for (k, v) in custom {
        if let (Ok(n), Ok(val)) = (
            http::header::HeaderName::from_bytes(k.as_bytes()),
            http::header::HeaderValue::from_str(v),
        ) {
            resp.headers_mut().insert(n, val);
        }
    }
    resp
}

struct H3Responder {
    shared: Arc<H3Conn>,
    status: u16,
    headers: Vec<(String, String)>,
    custom: Arc<Vec<(String, String)>>,
}

impl Responder for H3Responder {
    fn headers(
        &mut self,
        status: u16,
        headers: Vec<(String, String)>,
    ) -> crate::core::BoxFut<'_, Result<(), String>> {
        self.status = status;
        self.headers = headers;
        Box::pin(async { Ok(()) })
    }
    fn send_body(&mut self, b: Bytes) -> crate::core::BoxFut<'_, Result<(), String>> {
        use std::sync::atomic::Ordering;
        let shared = self.shared.clone();
        let status = self.status;
        let headers = std::mem::take(&mut self.headers);
        let custom = self.custom.clone();
        Box::pin(async move {
            let mut guard = shared.stream.lock().await;
            if !shared.started.load(Ordering::Relaxed) {
                let Some(stream) = guard.as_mut() else {
                    return Err("H3 流已结束".into());
                };
                stream
                    .send_response(build_h3_response(status, &headers, &custom))
                    .await
                    .map_err(|e| e.to_string())?;
                shared.started.store(true, Ordering::Relaxed);
            }
            let Some(stream) = guard.as_mut() else {
                return Err("H3 流已结束".into());
            };
            stream.send_data(b).await.map_err(|e| e.to_string())
        })
    }
    fn finish(&mut self) -> crate::core::BoxFut<'_, Result<(), String>> {
        use std::sync::atomic::Ordering;
        let shared = self.shared.clone();
        let status = self.status;
        let headers = std::mem::take(&mut self.headers);
        let custom = self.custom.clone();
        Box::pin(async move {
            let mut guard = shared.stream.lock().await;
            if !shared.started.load(Ordering::Relaxed) {
                // 尚未发送过响应头：补发后收尾
                let Some(mut stream) = guard.take() else {
                    return Err("H3 流已结束".into());
                };
                stream
                    .send_response(build_h3_response(status, &headers, &custom))
                    .await
                    .map_err(|e| e.to_string())?;
                stream.finish().await.map_err(|e| e.to_string())?;
                shared.started.store(true, Ordering::Relaxed);
                return Ok(());
            }
            // 已通过 send_body 发过响应头：直接收尾
            if let Some(stream) = guard.as_mut() {
                stream.finish().await.map_err(|e| e.to_string())?;
            }
            Ok(())
        })
    }
}

struct H3BodyIn {
    shared: Arc<H3Conn>,
    done: bool,
}

impl ReadBody for H3BodyIn {
    fn next(&mut self) -> crate::core::BoxFut<'_, Result<Option<Bytes>, String>> {
        Box::pin(async move {
            if self.done {
                return Ok(None);
            }
            let mut guard = self.shared.stream.lock().await;
            let stream = match guard.as_mut() {
                Some(s) => s,
                None => {
                    self.done = true;
                    return Ok(None);
                }
            };
            match stream.recv_data().await {
                Ok(Some(mut d)) => {
                    use bytes::Buf;
                    let len = d.remaining();
                    let bb = d.copy_to_bytes(len);
                    Ok(Some(bb))
                }
                Ok(None) => {
                    self.done = true;
                    Ok(None)
                }
                Err(e) => Err(e.to_string()),
            }
        })
    }
}