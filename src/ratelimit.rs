//! 速率限制：令牌桶（默认内存桶 + 文件持久化；可选 Redis 固定窗口）
//! 设计目标：低开销、默认零外部依赖；内存有硬上限（防 OOM）；
//! IPv6 按 /64 聚合（防单机换后缀绕过、控制键基数）。
use crate::config::{LimitPolicy, RateLimitCfg};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 限速键：IPv4 取全地址；IPv6 聚合到 /64
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpKey {
    V4(u32),
    V6(u64),
}

impl IpKey {
    pub fn from_ip(ip: &IpAddr) -> IpKey {
        match ip {
            IpAddr::V4(v4) => IpKey::V4(u32::from_be_bytes(v4.octets())),
            IpAddr::V6(v6) => {
                let o = v6.octets();
                let mut hi = [0u8; 8];
                hi.copy_from_slice(&o[..8]);
                IpKey::V6(u64::from_be_bytes(hi))
            }
        }
    }

    fn v4_str(v: u32) -> String {
        format!("{}.{}.{}.{}", (v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255)
    }

    /// 持久化/日志用的字符串 token
    pub fn token(&self) -> String {
        match self {
            IpKey::V4(v) => format!("4:{}", Self::v4_str(*v)),
            IpKey::V6(v) => format!("6:{v:016x}/64"),
        }
    }

    fn parse_token(s: &str) -> Option<IpKey> {
        if let Some(rest) = s.strip_prefix("4:") {
            let ip: std::net::Ipv4Addr = rest.parse().ok()?;
            return Some(IpKey::V4(u32::from_be_bytes(ip.octets())));
        }
        if let Some(rest) = s.strip_prefix("6:") {
            let hex = rest.trim_end_matches("/64");
            return u64::from_str_radix(hex, 16).ok().map(IpKey::V6);
        }
        None
    }

    /// Redis 键用的可读串（IPv6 用 /64 前缀 hex）
    fn to_display(&self) -> String {
        match self {
            IpKey::V4(v) => Self::v4_str(*v),
            IpKey::V6(v) => format!("{v:016x}/64"),
        }
    }
}

struct Bucket {
    tokens: f64,
    last_ms: u64,
}

pub struct RateLimiter {
    cfg: ArcSwap<RateLimitCfg>,
    buckets: Mutex<HashMap<IpKey, Bucket>>,
    flush_started: AtomicBool,
    dirty: AtomicBool,
    redis: tokio::sync::Mutex<Option<RedisConn>>,
}

static GLOBAL: OnceLock<Arc<RateLimiter>> = OnceLock::new();

/// 进程级单例：首次调用创建（载入文件状态），之后调用仅刷新配置
pub fn global(cfg: &crate::config::Config) -> Arc<RateLimiter> {
    let rl = GLOBAL
        .get_or_init(|| Arc::new(RateLimiter::new(cfg.ratelimit.clone())))
        .clone();
    rl.cfg.store(Arc::new(cfg.ratelimit.clone()));
    if !rl.flush_started.swap(true, Ordering::SeqCst) {
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            let me = rl.clone();
            h.spawn(async move {
                loop {
                    let flush = me.cfg.load().flush_secs.clamp(1, 3600);
                    tokio::time::sleep(Duration::from_secs(flush)).await;
                    let c = me.cfg.load();
                    if c.storage == "file" && me.dirty.swap(false, Ordering::Relaxed) {
                        me.save_file(&c.file);
                    }
                }
            });
        }
    }
    rl
}

impl RateLimiter {
    fn new(cfg: RateLimitCfg) -> RateLimiter {
        let rl = RateLimiter {
            cfg: ArcSwap::from_pointee(cfg.clone()),
            buckets: Mutex::new(HashMap::new()),
            flush_started: AtomicBool::new(false),
            dirty: AtomicBool::new(false),
            redis: tokio::sync::Mutex::new(None),
        };
        if cfg.storage == "file" && !cfg.file.is_empty() {
            rl.load_file(&cfg.file);
        }
        rl
    }

    /// 检查并消耗一个令牌：Ok=放行；Err(secs)=建议的 Retry-After
    pub async fn check(&self, policy: &LimitPolicy, ip: Option<IpAddr>) -> Result<(), u64> {
        let cfg = self.cfg.load_full();
        if cfg.storage == "redis" {
            self.check_redis(&cfg, policy, ip).await
        } else {
            self.check_mem(&cfg, policy, ip)
        }
    }

    fn check_mem(&self, cfg: &RateLimitCfg, policy: &LimitPolicy, ip: Option<IpAddr>) -> Result<(), u64> {
        let key = match ip {
            Some(x) => IpKey::from_ip(&x),
            None => IpKey::V4(0), // 无对端地址（如某些 QUIC 场景）的共享桶
        };
        let now = now_ms();
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= cfg.max_entries && !map.contains_key(&key) {
            // 先清理 10 分钟无活动的桶；仍满则暂时拒绝新来源（防 OOM）
            let cutoff = now.saturating_sub(600_000);
            map.retain(|_, b| b.last_ms >= cutoff);
            if map.len() >= cfg.max_entries {
                crate::log_warn!("限速桶表已满（{}），新来源暂时拒绝", map.len());
                return Err(60);
            }
        }
        let b = map
            .entry(key)
            .or_insert(Bucket { tokens: policy.burst, last_ms: now });
        let elapsed = now.saturating_sub(b.last_ms) as f64 / 1000.0;
        b.tokens = (b.tokens + elapsed * policy.rate).min(policy.burst);
        b.last_ms = now;
        self.dirty.store(true, Ordering::Relaxed);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            let need = (1.0 - b.tokens) / policy.rate;
            Err(need.ceil().max(1.0) as u64)
        }
    }

    async fn check_redis(
        &self,
        cfg: &RateLimitCfg,
        policy: &LimitPolicy,
        ip: Option<IpAddr>,
    ) -> Result<(), u64> {
        let keyb = match ip {
            Some(x) => IpKey::from_ip(&x),
            None => IpKey::V4(0),
        };
        let now = now_ms() / 1000;
        let window = ((policy.burst / policy.rate).ceil() as u64).clamp(1, 3600);
        let slot = now / window;
        let rkey = format!("{}{}:{}:{}", cfg.redis_prefix, keyb.to_display(), window, slot);
        let limit = policy.burst.ceil().max(1.0) as i64;

        let fut = async {
            let mut g = self.redis.lock().await;
            if g.is_none() {
                *g = Some(RedisConn::connect(&cfg.redis_addr).await?);
            }
            let Some(c) = g.as_mut() else {
                return Err("redis 连接不可用".to_string());
            };
            match c.cmd_int(&["INCR", &rkey]).await {
                Ok(n) => {
                    if n == 1 {
                        // 首次计数：设置窗口过期（+1 秒冗余）；失败不致命
                        let _ = c.cmd_int(&["EXPIRE", &rkey, &(window + 1).to_string()]).await;
                    }
                    Ok(n)
                }
                Err(e) => Err(e),
            }
        };

        match tokio::time::timeout(Duration::from_millis(cfg.redis_timeout_ms), fut).await {
            Ok(Ok(n)) => {
                if n <= limit {
                    Ok(())
                } else {
                    Err((window - (now % window)).max(1))
                }
            }
            Ok(Err(e)) => {
                *self.redis.lock().await = None; // 连接可能已损坏，下次重连
                crate::log_warn!("redis 限速失败: {e}");
                if cfg.fail_open {
                    Ok(())
                } else {
                    Err(1)
                }
            }
            Err(_) => {
                *self.redis.lock().await = None;
                crate::log_warn!("redis 限速超时（{}ms）", cfg.redis_timeout_ms);
                if cfg.fail_open {
                    Ok(())
                } else {
                    Err(1)
                }
            }
        }
    }

    // ---------------- 文件持久化 ----------------

    fn load_file(&self, path: &str) {
        let data = match std::fs::read_to_string(path) {
            Ok(d) => d,
            Err(_) => return,
        };
        let max = self.cfg.load().max_entries;
        let mut n = 0usize;
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        for line in data.lines() {
            if n >= max {
                break;
            }
            let mut it = line.split(' ');
            let (k, t, l) = (it.next(), it.next(), it.next());
            if let (Some(k), Some(t), Some(l)) = (k, t, l) {
                if let (Some(ik), Ok(tok), Ok(last)) =
                    (IpKey::parse_token(k), t.parse::<f64>(), l.parse::<u64>())
                {
                    if tok.is_finite() && (0.0..1e9).contains(&tok) {
                        map.insert(ik, Bucket { tokens: tok, last_ms: last });
                        n += 1;
                    }
                }
            }
        }
        crate::log_info!("限速状态载入: {} 个桶（{}）", n, path);
    }

    fn save_file(&self, path: &str) {
        let max = self.cfg.load().max_entries;
        let body: String = {
            let map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
            let mut parts: Vec<String> = Vec::with_capacity(map.len().min(max));
            for (k, b) in map.iter().take(max) {
                parts.push(format!("{} {} {}", k.token(), b.tokens, b.last_ms));
            }
            parts.join("\n")
        };
        let tmp = format!("{path}.tmp");
        if let Err(e) = std::fs::write(&tmp, body.as_bytes()).and_then(|_| std::fs::rename(&tmp, path)) {
            crate::log_warn!("限速状态持久化失败（{path}）: {e}");
        }
    }
}

// ---------------- 极简 Redis 客户端（RESP：INCR/EXPIRE） ----------------

struct RedisConn {
    stream: tokio::net::TcpStream,
}

impl RedisConn {
    async fn connect(addr: &str) -> Result<RedisConn, String> {
        let s = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| format!("连接 redis {addr} 失败: {e}"))?;
        let _ = s.set_nodelay(true);
        Ok(RedisConn { stream: s })
    }

    async fn read_line(&mut self) -> Result<String, String> {
        use tokio::io::AsyncReadExt;
        let mut out: Vec<u8> = Vec::with_capacity(64);
        loop {
            let mut b = [0u8; 1];
            self.stream
                .read_exact(&mut b)
                .await
                .map_err(|e| format!("redis 读失败: {e}"))?;
            if b[0] == b'\r' {
                continue;
            }
            if b[0] == b'\n' {
                break;
            }
            out.push(b[0]);
            if out.len() > 4096 {
                return Err("redis 响应过长".into());
            }
        }
        Ok(String::from_utf8_lossy(&out).to_string())
    }

    async fn cmd_int(&mut self, args: &[&str]) -> Result<i64, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut msg: Vec<u8> = Vec::with_capacity(64);
        msg.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
        for a in args {
            msg.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
            msg.extend_from_slice(a.as_bytes());
            msg.extend_from_slice(b"\r\n");
        }
        self.stream
            .write_all(&msg)
            .await
            .map_err(|e| format!("redis 写失败: {e}"))?;
        let mut t = [0u8; 1];
        self.stream
            .read_exact(&mut t)
            .await
            .map_err(|e| format!("redis 读失败: {e}"))?;
        let line = self.read_line().await?;
        match t[0] {
            b':' | b'+' => line.trim().parse::<i64>().map_err(|e| format!("redis 响应非法: {e}")),
            b'-' => Err(format!("redis 错误: {line}")),
            b'$' => {
                let n: i64 = line.trim().parse().unwrap_or(-1);
                if n < 0 {
                    Ok(0)
                } else if n > 16 * 1024 {
                    Err("redis 响应过大（>16KiB）".to_string())
                } else {
                    let mut buf = vec![0u8; n as usize + 2];
                    self.stream
                        .read_exact(&mut buf)
                        .await
                        .map_err(|e| format!("redis 读失败: {e}"))?;
                    String::from_utf8_lossy(&buf[..n as usize])
                        .trim()
                        .parse::<i64>()
                        .map_err(|e| format!("redis 响应非法: {e}"))
                }
            }
            _ => Err(format!("redis 未知响应类型: {:?}", t[0] as char)),
        }
    }
}

// ---------------- 单元测试 ----------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipkey_v4_v6() {
        let a = "1.2.3.4".parse().unwrap();
        let b = "1.2.3.4".parse().unwrap();
        assert_eq!(IpKey::from_ip(&a), IpKey::from_ip(&b));
        // 同 /64 前缀的 IPv6 视为同一键
        let c1 = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        let c2 = "2001:db8:1:2:ffff::1".parse().unwrap();
        let d = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(IpKey::from_ip(&c1), IpKey::from_ip(&c2));
        assert_ne!(IpKey::from_ip(&c1), IpKey::from_ip(&d));
    }

    #[test]
    fn token_roundtrip() {
        let k = IpKey::from_ip(&"9.8.7.6".parse().unwrap());
        assert_eq!(IpKey::parse_token(&k.token()), Some(k));
        let v6 = IpKey::from_ip(&"2001:db8::1".parse().unwrap());
        assert_eq!(IpKey::parse_token(&v6.token()), Some(v6));
    }

    #[tokio::test]
    async fn bucket_limits() {
        let rl = RateLimiter::new(RateLimitCfg::default());
        let policy = LimitPolicy { rate: 1.0, burst: 2.0 };
        let ip = "10.0.0.1".parse().unwrap();
        assert!(rl.check(&policy, Some(ip)).await.is_ok());
        assert!(rl.check(&policy, Some(ip)).await.is_ok());
        let err = rl.check(&policy, Some(ip)).await;
        assert!(err.is_err());
        assert!(err.unwrap_err() >= 1);
    }
}
