//! HTTP/1.1 + HTTP/2 服务器（hyper 驱动，TLS 可选）
//! 采用事件驱动，空闲零轮询；连接数受信号量约束；头读取有超时（防慢速攻击）。

use crate::core::{self, ReadBody, RequestCtx, Responder};
use crate::material::Material;
use crate::{log_debug, log_info, log_warn};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};

pub async fn run(material: Arc<ArcSwap<Material>>, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    // tokio 在 Unix 上默认 SO_REUSEADDR，进程退出后端口可立即复用
    let max_conn = material.load_full().cfg.max_conn;
    let sem = Arc::new(tokio::sync::Semaphore::new(max_conn));
    log_info!("HTTP/1.1+HTTP/2 监听 {addr}（并发连接上限 {max_conn}）");
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log_warn!("accept 失败: {e}，短暂退避后重试");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        // 并发上限：容量不足时在此等待（内核队列兜底），不会无限膨胀任务
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => continue,
        };
        let material = material.clone();
        tokio::spawn(async move {
            let _permit = permit;
            conn_task(material, sock, peer).await;
        });
    }
}

async fn conn_task(material: Arc<ArcSwap<Material>>, sock: TcpStream, peer: SocketAddr) {
    // 流式响应降低小包延迟
    let _ = sock.set_nodelay(true);
    let m = material.load_full();
    let tls = m.tls.clone();
    let tls_enabled = tls.is_some();

    // force_https：同端口协议嗅探——首字节 0x16（TLS ClientHello）走 TLS，
    // 否则按明文 HTTP 处理（core 层 301 跳转到 https://，实现单端口 HTTP+HTTPS 共存）
    let mut plaintext = false;
    if tls_enabled && m.cfg.force_https {
        let mut first = [0u8; 1];
        plaintext = match sock.peek(&mut first).await {
            Ok(n) if n > 0 => first[0] != 0x16,
            _ => false,
        };
    }
    if plaintext {
        serve(material, TokioIo::new(sock), peer, false).await;
        return;
    }
    if let Some(acceptor) = tls {
        let tls_stream = match acceptor.accept(sock).await {
            Ok(s) => s,
            Err(_) => return,
        };
        serve(material, TokioIo::new(tls_stream), peer, tls_enabled).await;
    } else {
        serve(material, TokioIo::new(sock), peer, tls_enabled).await;
    }
}

async fn serve<I>(material: Arc<ArcSwap<Material>>, io: TokioIo<I>, peer: SocketAddr, tls: bool)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Some(Duration::from_secs(30)))
        .keep_alive(true);
    let svc = service_fn(move |req| handle(material.clone(), req, peer, tls));
    if let Err(e) = builder.serve_connection(io, svc).await {
        log_debug!("连接 {peer} 结束: {e}");
    }
}

async fn handle(
    material: Arc<ArcSwap<Material>>,
    req: hyper::Request<Incoming>,
    peer: SocketAddr,
    tls: bool,
) -> Result<hyper::Response<BoxBody<Bytes, io::Error>>, Infallible> {
    // 热路径：load() 返回借用守卫，避免每次请求的 Arc 引用计数开销
    let m = material.load();
    let start = Instant::now();
    let method = req.method().clone();
    let raw_path = req.uri().path().to_string();
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

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
        peer_ip: Some(peer.ip()),
        tls,
    };

    let (mut responder, body) = HyperResponder::new();
    let body_in = HyperBodyIn::new(req.into_body());
    let outcome = core::process(&m, &ctx, Some(body_in), &mut responder).await;
    let status = responder.status();
    let bytes = outcome.map(|o| o.bytes_sent).unwrap_or(0);

    crate::log::access(
        &peer.to_string(),
        method.as_str(),
        &raw_path,
        status,
        bytes,
        start.elapsed().as_millis(),
        host.as_deref().unwrap_or(""),
    );

    let mut out = hyper::Response::new(BoxBody::new(body));
    *out.status_mut() = http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    let headers = responder.take_headers();
    for (k, v) in headers {
        let name = http::header::HeaderName::from_bytes(k.as_bytes())
            .unwrap_or_else(|_| http::header::HeaderName::from_static("x-rfs"));
        if let Ok(val) = http::header::HeaderValue::from_str(&v) {
            out.headers_mut().append(name, val);
        }
    }
    // 自定义响应头（vhost 覆盖全局；insert 覆盖同名默认头，如自定义 Cache-Control/CORS）
    let host_key = host
        .as_deref()
        .map(|h| h.split(':').next().unwrap_or(h).to_lowercase())
        .unwrap_or_default();
    for (k, v) in m.custom_for(&host_key).iter() {
        if let (Ok(n), Ok(val)) = (
            http::header::HeaderName::from_bytes(k.as_bytes()),
            http::header::HeaderValue::from_str(v),
        ) {
            out.headers_mut().insert(n, val);
        }
    }
    Ok(out)
}

// ---------------- 响应端：内存通道 -> body ----------------

/// 按需文件流状态（由 HyperResponder 写入、ChanBody 读取）
/// 两种来源：
///  - Read：同步读流式（小文件 / mmap 预算耗尽 / 关闭 mmap 时的回退路径）
///  - Mmap：分段 mmap 零拷贝（大文件；窗口制，全局活跃窗口有预算上限防 RAM 溢出）
/// 同步路径保证 head+body 同包写出（避免 Nagle×延迟ACK 的 40ms 尾延迟）。
enum FileSrc {
    Read {
        file: std::fs::File,
        buf: Vec<u8>,
        remain: u64,
    },
    Mmap {
        file: Option<std::fs::File>, // 保留下一个窗口的映射源
        window: Option<Bytes>,       // 当前映射窗口（Bytes::from_owner(mmap)，Drop 即 munmap）
        pos: usize,                  // 窗口内已发送偏移
        remain: u64,                 // 总剩余字节
        next_off: u64,               // 下一窗口的文件偏移
        window_size: usize,          // 窗口大小
        broken: bool,                // mmap 失败后转同步 read 回退
    },
}

struct FileState {
    src: FileSrc,
}

impl FileState {
    fn remain(&self) -> u64 {
        match &self.src {
            FileSrc::Read { remain, .. } | FileSrc::Mmap { remain, .. } => *remain,
        }
    }
}

impl Drop for FileState {
    fn drop(&mut self) {
        if let FileSrc::Mmap { window, .. } = &mut self.src {
            if let Some(w) = window.take() {
                MMAP_ACTIVE_BYTES.fetch_sub(w.len() as u64, Ordering::Relaxed);
            }
        }
    }
}

type SharedFile = Arc<Mutex<Option<FileState>>>;

/// 全局 mmap 活跃窗口字节数（防 RAM 溢出预算；上限由 main 按 config 设置）
static MMAP_ACTIVE_BYTES: AtomicU64 = AtomicU64::new(0);
static MMAP_BUDGET_BYTES: OnceLock<u64> = OnceLock::new();

/// 页对齐地映射 [off, off+len)，返回从 off 开始有效数据的窗口 Bytes（零拷贝）
fn map_window(file: &std::fs::File, off: u64, len: usize) -> io::Result<Bytes> {
    use memmap2::MmapOptions;
    let page = 4096u64;
    let pa_off = off & !(page - 1);
    let skip = (off - pa_off) as usize;
    let map_len = len + skip;
    let mmap = unsafe { MmapOptions::new().offset(pa_off).len(map_len).map(file)? };
    #[cfg(unix)]
    {
        use memmap2::Advice;
        let _ = mmap.advise(Advice::Sequential);
    }
    let b = Bytes::from_owner(mmap); // Drop 时 munmap
    Ok(b.slice(skip..skip + len))
}

fn mmap_budget_ok(add: usize) -> bool {
    let budget = *MMAP_BUDGET_BYTES.get().unwrap_or(&(256 * 1024 * 1024));
    MMAP_ACTIVE_BYTES.load(Ordering::Relaxed) + add as u64 <= budget
}

pub struct HyperResponder {
    status: u16,
    headers: Vec<(String, String)>,
    tx: Option<tokio::sync::mpsc::Sender<Result<Frame<Bytes>, io::Error>>>,
    file: SharedFile,
}

impl HyperResponder {
    pub fn new() -> (Self, ChanBody) {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, io::Error>>(16);
        let file: SharedFile = Arc::new(Mutex::new(None));
        (
            HyperResponder { status: 500, headers: Vec::new(), tx: Some(tx), file: file.clone() },
            ChanBody { rx, file },
        )
    }
    pub fn status(&self) -> u16 {
        self.status
    }
    pub fn take_headers(self) -> Vec<(String, String)> {
        self.headers
    }
    fn file_sender(
        &mut self,
        path: std::path::PathBuf,
        start: u64,
        len: u64,
        chunk: usize,
        use_mmap: bool,
        window_size: usize,
    ) -> crate::core::BoxFut<'_, Result<(), String>> {
        use std::io::Seek as _;
        let shared = self.file.clone();
        Box::pin(async move {
            let mut f = std::fs::File::open(&path).map_err(|e| e.to_string())?;
            if start > 0 {
                f.seek(std::io::SeekFrom::Start(start)).map_err(|e| e.to_string())?;
            }
            let src = if use_mmap && len >= 1024 * 1024 {
                // 首窗口映射；fstat 限制窗口不超过文件当前大小（缩小 SIGBUS 窗口）
                let flen = f.metadata().map(|m| m.len()).unwrap_or(0);
                let wlen = (len.min(window_size as u64)).min(flen.saturating_sub(start)) as usize;
                if wlen > 0 && mmap_budget_ok(wlen) {
                    match map_window(&f, start, wlen) {
                        Ok(w) => {
                            MMAP_ACTIVE_BYTES.fetch_add(w.len() as u64, Ordering::Relaxed);
                            FileSrc::Mmap {
                                file: Some(f),
                                window: Some(w),
                                pos: 0,
                                remain: len,
                                next_off: start + wlen as u64,
                                window_size: window_size.max(1024 * 1024),
                                broken: false,
                            }
                        }
                        Err(_) => FileSrc::Read {
                            file: f,
                            buf: vec![0u8; chunk.max(64 * 1024)],
                            remain: len,
                        },
                    }
                } else {
                    FileSrc::Read {
                        file: f,
                        buf: vec![0u8; chunk.max(64 * 1024)],
                        remain: len,
                    }
                }
            } else {
                FileSrc::Read {
                    file: f,
                    buf: vec![0u8; chunk.max(64 * 1024)],
                    remain: len,
                }
            };
            let mut g = shared.lock().unwrap();
            *g = Some(FileState { src });
            Ok(())
        })
    }
}

impl Responder for HyperResponder {
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
        match self.tx.as_ref() {
            Some(tx) => {
                let res = tx.send(Ok(Frame::data(b)));
                Box::pin(async move { res.await.map_err(|_| "客户端已断开".to_string()) })
            }
            None => Box::pin(async { Err("连接已关闭".to_string()) }),
        }
    }
    fn send_file(
        &mut self,
        path: &std::path::Path,
        start: u64,
        len: u64,
        chunk: usize,
        use_mmap: bool,
        window_size: usize,
    ) -> crate::core::BoxFut<'_, Result<(), String>> {
        self.file_sender(path.to_path_buf(), start, len, chunk, use_mmap, window_size)
    }
    fn finish(&mut self) -> crate::core::BoxFut<'_, Result<(), String>> {
        self.tx.take();
        Box::pin(async { Ok(()) })
    }
}

pub struct ChanBody {
    rx: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, io::Error>>,
    file: SharedFile,
}

impl http_body::Body for ChanBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        use std::io::Read as _;
        // 文件流优先：避免把大文件灌入有界通道（生产-消费握手死锁），
        // Read：同步读（head+body 同包写出）；Mmap：零拷贝切片（窗口制，预算防溢出）
        {
            let mut g = self.file.lock().unwrap();
            if let Some(fs) = g.as_mut() {
                match &mut fs.src {
                    FileSrc::Read { file, buf, remain } => {
                        if *remain == 0 {
                            *g = None;
                            return Poll::Ready(None);
                        }
                        let want = (*remain).min(buf.len() as u64) as usize;
                        match file.read(&mut buf[..want]) {
                            Ok(0) => {
                                *g = None;
                                return Poll::Ready(None);
                            }
                            Ok(n) => {
                                *remain -= n as u64;
                                return Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(
                                    &buf[..n],
                                )))));
                            }
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                                return Poll::Pending; // 重试
                            }
                            Err(e) => {
                                *g = None;
                                return Poll::Ready(Some(Err(e)));
                            }
                        }
                    }
                    FileSrc::Mmap {
                        file,
                        window,
                        pos,
                        remain,
                        next_off,
                        window_size,
                        broken,
                    } => loop {
                        if *remain == 0 {
                            if let Some(w) = window.take() {
                                MMAP_ACTIVE_BYTES.fetch_sub(w.len() as u64, Ordering::Relaxed);
                            }
                            *g = None;
                            return Poll::Ready(None);
                        }
                        if *broken {
                            // mmap 不可用：同步 read 回退（head+body 同包语义不变）
                            if let Some(f) = file.as_mut() {
                                let want = (*remain).min(256 * 1024) as usize;
                                let mut buf = vec![0u8; want];
                                match f.read(&mut buf) {
                                    Ok(0) => {
                                        *g = None;
                                        return Poll::Ready(None);
                                    }
                                    Ok(n) => {
                                        *remain -= n as u64;
                                        return Poll::Ready(Some(Ok(Frame::data(
                                            Bytes::copy_from_slice(&buf[..n]),
                                        ))));
                                    }
                                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                                        return Poll::Pending;
                                    }
                                    Err(e) => {
                                        *g = None;
                                        return Poll::Ready(Some(Err(e)));
                                    }
                                }
                            }
                            *g = None;
                            return Poll::Ready(None);
                        }
                        // 窗口耗尽则映射下一窗口
                        let need_map = match window {
                            None => true,
                            Some(w) => *pos >= w.len(),
                        };
                        if need_map {
                            if let Some(w) = window.take() {
                                MMAP_ACTIVE_BYTES.fetch_sub(w.len() as u64, Ordering::Relaxed);
                            }
                            let flen = file
                                .as_ref()
                                .map(|f| f.metadata().map(|m| m.len()).unwrap_or(0))
                                .unwrap_or(0);
                            let wlen = ((*remain).min(*window_size as u64))
                                .min(flen.saturating_sub(*next_off)) as usize;
                            if wlen == 0 {
                                // 文件被并发截断：无法继续兑现 content-length，断开连接
                                *g = None;
                                return Poll::Ready(Some(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "file truncated",
                                ))));
                            }
                            match file
                                .as_ref()
                                .map(|f| map_window(f, *next_off, wlen))
                                .unwrap_or_else(|| Err(io::Error::other("no fd")))
                            {
                                Ok(w) => {
                                    MMAP_ACTIVE_BYTES.fetch_add(w.len() as u64, Ordering::Relaxed);
                                    *next_off += w.len() as u64;
                                    *window = Some(w);
                                    *pos = 0;
                                }
                                Err(_) => {
                                    // mmap 失败：后续转同步 read 回退
                                    *broken = true;
                                    break;
                                }
                            }
                        }
                        let w = window.as_ref().unwrap();
                        let n = (*remain).min((w.len() - *pos) as u64) as usize;
                        let frame = w.slice(*pos..*pos + n); // 零拷贝视图
                        *pos += n;
                        *remain -= n as u64;
                        return Poll::Ready(Some(Ok(Frame::data(frame))));
                    },
                }
            }
        }
        Pin::new(&mut self.rx).poll_recv(cx)
    }

    fn is_end_stream(&self) -> bool {
        // 必须“发送端全部关闭且缓冲读空”才算结束；
        // 只判断 is_closed() 会在 finish() 后立刻误判为空响应（hyper 会跳过 body）。
        let file_done = self
            .file
            .lock()
            .unwrap()
            .as_ref()
            .map(|f| f.remain() == 0)
            .unwrap_or(true);
        self.rx.is_closed() && self.rx.is_empty() && file_done
    }

    fn size_hint(&self) -> http_body::SizeHint {
        // 文件流模式给出精确长度，让 hyper 按固定长度发送（免 chunked 开销）
        match self.file.lock().unwrap().as_ref().map(|f| f.remain()) {
            Some(len) if len > 0 => http_body::SizeHint::with_exact(len),
            _ => http_body::SizeHint::default(),
        }
    }
}

// ---------------- mmap 发送的安全网 ----------------

/// 初始化全局 mmap 活跃字节预算
pub fn mmap_budget_init(bytes: u64) -> Result<(), ()> {
    MMAP_BUDGET_BYTES.set(bytes).map_err(|_| ())
}

/// SIGBUS 兜底：mmap 区域因文件被外部截断而失效时内核会发出 SIGBUS。
/// 信号处理器内只能做 async-signal-safe 操作（write/_exit）。
extern "C" fn sigbus_handler(_sig: i32, _info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    const MSG: &[u8] = b"rfs: SIGBUS (mapped file truncated during send) - exiting\n";
    unsafe {
        let _ = libc::write(2, MSG.as_ptr().cast(), MSG.len());
        libc::_exit(70);
    }
}

/// 安装 SIGBUS 处理器（进程生命周期内一次）
pub fn install_sigbus_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigbus_handler as extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
    }
}

// ---------------- 请求体 ----------------

pub struct HyperBodyIn {
    body: Option<Incoming>,
}

impl HyperBodyIn {
    pub fn new(body: Incoming) -> Self {
        HyperBodyIn { body: Some(body) }
    }
}

impl ReadBody for HyperBodyIn {
    fn next(&mut self) -> crate::core::BoxFut<'_, Result<Option<Bytes>, String>> {
        Box::pin(async move {
            let body = match self.body.as_mut() {
                Some(b) => b,
                None => return Ok(None),
            };
            loop {
                match body.frame().await {
                    Some(Ok(f)) => match f.into_data() {
                        Ok(d) => return Ok(Some(d)),
                        Err(_) => continue, // trailers，忽略
                    },
                    Some(Err(e)) => return Err(e.to_string()),
                    None => return Ok(None),
                }
            }
        })
    }
}