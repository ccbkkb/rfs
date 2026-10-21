//! 反向代理（HTTP/1.1 上游；请求/响应双向流式；全程有界缓冲防 OOM）
//!
//! 安全要点：
//! - 上游地址来自配置（非用户输入）→ 无 SSRF 面；仅允许 http/https
//! - 转发路径由归一化后的内部路径重建并做 URI 安全编码（防注入/走私）
//! - 剥离逐跳头（Connection/TE/Upgrade/Proxy-* 等）；X-Forwarded-For 可控
//! - 连接超时 5s；整请求超时按路由配置；响应体流式（背压来自下游 Responder）
//! - 上游响应默认剥离 Server 头（由本服务统一输出安全头）
use crate::config::{Route, Site, XffMode};
use crate::core::{Outcome, ReadBody, RequestCtx, Responder};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Uri};
use http_body::Frame;
use http_body_util::BodyExt;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

fn is_hop(k: &str) -> bool {
    HOP_BY_HOP.contains(&k)
}

/// URI 路径安全编码：保留 pchar 合法字符，其余百分号编码（含空格/%/#/?/控制字符）
const PATH_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'!')
    .remove(b'$')
    .remove(b'&')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'*')
    .remove(b'+')
    .remove(b',')
    .remove(b';')
    .remove(b'=')
    .remove(b':')
    .remove(b'@');

/// 将（已解码的）路径片段重新编码为可安全放入 URI/Location 的形式
pub fn encode_path(path: &str) -> String {
    utf8_percent_encode(path, PATH_SET).to_string()
}

// ---------------- 上游请求体（Empty 或有界通道） ----------------

pub struct OutBody {
    inner: OutInner,
}

enum OutInner {
    Empty,
    Chan(tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, std::io::Error>>),
}

impl OutBody {
    fn empty() -> OutBody {
        OutBody { inner: OutInner::Empty }
    }
    fn chan(rx: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, std::io::Error>>) -> OutBody {
        OutBody { inner: OutInner::Chan(rx) }
    }
}

impl http_body::Body for OutBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match &mut self.get_mut().inner {
            OutInner::Empty => Poll::Ready(None),
            OutInner::Chan(rx) => rx.poll_recv(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self.inner, OutInner::Empty)
    }
}

// ---------------- 客户端（连接池 + 可选跳过校验） ----------------

type HttpsClient = Client<HttpsConnector<HttpConnector>, OutBody>;

fn http_connector() -> HttpConnector {
    let mut c = HttpConnector::new();
    c.set_connect_timeout(Some(Duration::from_secs(5)));
    c.enforce_http(false);
    c
}

fn insecure_tls_config() -> Result<rustls::ClientConfig, String> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

    #[derive(Debug)]
    struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls 配置失败: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    Ok(cfg)
}

static CLIENT_VERIFIED: OnceLock<Result<HttpsClient, String>> = OnceLock::new();
static CLIENT_INSECURE: OnceLock<Result<HttpsClient, String>> = OnceLock::new();

fn https_client(insecure: bool) -> Result<&'static HttpsClient, String> {
    let cell = if insecure { &CLIENT_INSECURE } else { &CLIENT_VERIFIED };
    cell.get_or_init(|| {
        let b = hyper_rustls::HttpsConnectorBuilder::new();
        let b = if insecure {
            b.with_tls_config(insecure_tls_config()?)
        } else {
            b.with_native_roots()
                .map_err(|e| format!("加载系统 CA 失败（请安装 ca-certificates）: {e}"))?
        };
        let https = b
            .https_or_http()
            .enable_http1()
            .wrap_connector(http_connector());
        Ok(Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(8)
            .build(https))
    })
    .as_ref()
    .map_err(|e| e.clone())
}

// ---------------- 主流程 ----------------

pub async fn forward<B: ReadBody + 'static, R: Responder>(
    material: &crate::material::Material,
    site: &Site,
    route: &Route,
    rel: &str,
    ctx: &RequestCtx,
    body_in: Option<B>,
    resp: &mut R,
) -> Result<Outcome, ()> {
    let cfg = &material.cfg;
    let t_start = Instant::now();

    // 1) 计算上游 URL（路径重建 + 安全编码；查询串原样透传）
    let cli_path = if rel.is_empty() { "/".to_string() } else { format!("/{rel}") };
    let rest = match route.match_rest(&cli_path) {
        Some(r) => r,
        None => return gateway_error(cfg, resp, 500, "路由匹配失败", ctx).await,
    };
    let fwd_path = route.forward_path(&cli_path, rest);
    let fwd_enc = encode_path(&fwd_path);
    let query = ctx.target.split_once('?').map(|(_, q)| q).unwrap_or("");
    let url = if query.is_empty() {
        format!("{}{}", route.upstream_base, fwd_enc)
    } else {
        format!("{}{}?{}", route.upstream_base, fwd_enc, query)
    };
    let uri: Uri = match url.parse() {
        Ok(u) => u,
        Err(_) => return gateway_error(cfg, resp, 500, "上游 URL 构造失败", ctx).await,
    };

    // 2) 请求头（剥离逐跳头 + 可控的转发头 + 路由注入头）
    let conn_extra: Vec<String> = ctx
        .headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').map(|x| x.trim().to_ascii_lowercase()).collect())
        .unwrap_or_default();
    let mut headers = HeaderMap::new();
    for (k, v) in ctx.headers.iter() {
        let kl = k.as_str().to_ascii_lowercase();
        if is_hop(&kl) || conn_extra.iter().any(|x| x == &kl) || kl == "host" || kl == "expect" {
            continue;
        }
        headers.append(k.clone(), v.clone());
    }
    let peer = ctx.peer_ip.map(|ip| ip.to_string());
    match route.xff {
        XffMode::Off => {}
        XffMode::Set => {
            if let Some(p) = &peer {
                if let Ok(v) = HeaderValue::from_str(p) {
                    headers.insert("x-forwarded-for", v);
                }
            }
        }
        XffMode::Append => {
            if let Some(p) = &peer {
                let existing = headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let val = if existing.is_empty() { p.clone() } else { format!("{existing}, {p}") };
                if let Ok(v) = HeaderValue::from_str(&val) {
                    headers.insert("x-forwarded-for", v);
                }
            }
        }
    }
    if let Ok(v) = HeaderValue::from_str(if ctx.tls { "https" } else { "http" }) {
        headers.insert("x-forwarded-proto", v);
    }
    if let Some(h) = &ctx.host {
        if let Ok(v) = HeaderValue::from_str(h) {
            headers.insert("x-forwarded-host", v);
        }
        if route.preserve_host {
            if let Ok(v) = HeaderValue::from_str(h) {
                headers.insert("host", v);
            }
        }
    }
    if let Some(p) = &peer {
        if let Ok(v) = HeaderValue::from_str(p) {
            headers.insert("x-real-ip", v);
        }
    }
    for (k, v) in &route.set_req {
        if let (Ok(n), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
            headers.insert(n, val);
        }
    }

    // 3) 请求体：有界通道 + 独立泵任务（背压；空闲超时；请求结束即 drop → EOF）
    let method = ctx.method.clone();
    let bodyless = matches!(method, Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE);
    let out_body = match body_in {
        Some(mut b) if !bodyless => {
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
            let idle = Duration::from_secs(site.body_idle_timeout.clamp(1, 3600));
            tokio::spawn(async move {
                loop {
                    match tokio::time::timeout(idle, b.next()).await {
                        Ok(Ok(Some(chunk))) => {
                            if tx.send(Ok(Frame::data(chunk))).await.is_err() {
                                break; // 上游已拒绝/断开
                            }
                        }
                        _ => break,
                    }
                }
                // tx 在此 drop → 请求体正常结束
            });
            OutBody::chan(rx)
        }
        _ => OutBody::empty(),
    };

    let mut reqb = Request::builder().method(method.clone()).uri(uri);
    {
        let hm = reqb.headers_mut().expect("builder 有 headers");
        for (k, v) in headers.iter() {
            hm.append(k, v.clone());
        }
    }
    let req = match reqb.body(out_body) {
        Ok(r) => r,
        Err(_) => return gateway_error(cfg, resp, 500, "请求构造失败", ctx).await,
    };

    let client = match https_client(!route.tls_verify) {
        Ok(c) => c,
        Err(e) => {
            crate::log_error!("上游客户端初始化失败: {e}");
            return gateway_error(cfg, resp, 502, "上游客户端不可用", ctx).await;
        }
    };
    let up = match tokio::time::timeout(route.timeout, client.request(req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            crate::log_warn!("上游请求失败（{}）: {e}", route.upstream_base);
            return gateway_error(cfg, resp, 502, "上游不可达", ctx).await;
        }
        Err(_) => {
            crate::log_warn!("上游请求超时（{}s）", route.timeout.as_secs());
            return gateway_error(cfg, resp, 504, "上游超时", ctx).await;
        }
    };

    // 4) 响应头（剥离逐跳 + remove + set；安全头由本服务统一输出）
    let status = up.status().as_u16();
    let up_headers = up.headers().clone();
    let resp_conn_extra: Vec<String> = up_headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').map(|x| x.trim().to_ascii_lowercase()).collect())
        .unwrap_or_default();
    let mut out: Vec<(String, String)> = Vec::with_capacity(up_headers.len() + 8);
    for (k, v) in up_headers.iter() {
        let kl = k.as_str().to_ascii_lowercase();
        if is_hop(&kl) || resp_conn_extra.iter().any(|x| x == &kl) || kl == "server" {
            continue;
        }
        if route.remove_resp.iter().any(|r| r == &kl) {
            continue;
        }
        if let Ok(vs) = v.to_str() {
            out.push((kl, vs.to_string()));
        }
    }
    for (k, v) in &route.set_resp {
        upsert_header(&mut out, &k.to_ascii_lowercase(), v);
    }
    crate::core::sec_headers(cfg, ctx.tls, &mut out);
    resp.headers(status, out).await.map_err(|_| ())?;

    // 5) 响应体流式转发（HEAD/204/304 无体；空闲超时保护）
    let no_body = matches!(&method, &Method::HEAD) || status == 204 || status == 304 || (100..200).contains(&status);
    if no_body {
        resp.finish().await.map_err(|_| ())?;
        return Ok(Outcome { bytes_sent: 0 });
    }
    let mut up_body = up.into_body();
    let idle = Duration::from_secs(site.body_idle_timeout.clamp(1, 3600));
    let mut sent: u64 = 0;
    loop {
        match tokio::time::timeout(idle, up_body.frame()).await {
            Ok(Some(Ok(f))) => {
                if let Ok(d) = f.into_data() {
                    sent += d.len() as u64;
                    if resp.send_body(d).await.is_err() {
                        break;
                    }
                }
            }
            Ok(Some(Err(e))) => {
                crate::log_debug!("上游响应流错误（已发 {sent} 字节）: {e}");
                break;
            }
            Ok(None) => break,
            Err(_) => {
                crate::log_warn!("上游响应空闲超时（已发 {sent} 字节），终止转发");
                break;
            }
        }
    }
    resp.finish().await.map_err(|_| ())?;
    crate::log_debug!("代理完成 {}B status={} 用时 {}ms", sent, status, t_start.elapsed().as_millis());
    Ok(Outcome { bytes_sent: sent })
}

fn upsert_header(out: &mut Vec<(String, String)>, key: &str, val: &str) {
    out.retain(|(k, _)| k != key);
    out.push((key.to_string(), val.to_string()));
}

async fn gateway_error<R: Responder>(
    cfg: &crate::config::Config,
    resp: &mut R,
    status: u16,
    msg: &str,
    ctx: &RequestCtx,
) -> Result<Outcome, ()> {
    let body = Bytes::from(format!("{status} {msg}\n"));
    let mut out = vec![
        ("content-type".into(), "text/plain; charset=utf-8".into()),
        ("content-length".into(), body.len().to_string()),
    ];
    crate::core::sec_headers(cfg, ctx.tls, &mut out);
    resp.headers(status, out).await.map_err(|_| ())?;
    resp.send_body(body.clone()).await.map_err(|_| ())?;
    resp.finish().await.map_err(|_| ())?;
    Ok(Outcome { bytes_sent: body.len() as u64 })
}

// ---------------- 单元测试 ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{compile_routes, ProxyRouteCfg};

    #[test]
    fn path_encoding() {
        assert_eq!(encode_path("/a/b"), "/a/b");
        assert_eq!(encode_path("/a b"), "/a%20b");
        assert_eq!(encode_path("/a?b"), "/a%3Fb");
        assert_eq!(encode_path("/a%2e"), "/a%252e"); // 字面 '%' 被再编码（语义正确）
        assert_eq!(encode_path("/中文"), "/%E4%B8%AD%E6%96%87");
    }

    #[test]
    fn route_match_and_strip() {
        let cfg = vec![ProxyRouteCfg {
            prefix: "/api/".into(),
            upstream: "http://127.0.0.1:9000".into(),
            strip_prefix: true,
            ..Default::default()
        }];
        let rs = compile_routes(&cfg).unwrap();
        let r = &rs[0];
        assert!(r.match_rest("/api2/x").is_none()); // 段对齐，不误匹配
        assert_eq!(r.match_rest("/api/x"), Some("x"));
        assert_eq!(r.match_rest("/api"), None); // 前缀含尾 '/'，不做去斜杠匹配
        assert_eq!(r.match_rest("/api/"), Some(""));
        assert_eq!(r.forward_path("/api/x", "x"), "/x");
        assert_eq!(r.forward_path("/api", ""), "/");
    }
}
