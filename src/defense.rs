//! 应用层防护：每 IP 并发连接限制 + 违规（路径穿越等）计数封禁
//! 设计目标：内存有硬上限（防大量来源 IP 打爆内存）；无锁外阻塞。
use crate::config::DefenseCfg;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 65536;

pub struct Defense {
    cfg: DefenseCfg,
    bans: Mutex<HashMap<IpAddr, Ban>>,
    conns: Mutex<HashMap<IpAddr, usize>>,
    active: AtomicUsize,
}

struct Ban {
    strikes: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
    last_seen: Instant,
}

impl Defense {
    pub fn new(cfg: DefenseCfg) -> Defense {
        Defense {
            cfg,
            bans: Mutex::new(HashMap::new()),
            conns: Mutex::new(HashMap::new()),
            active: AtomicUsize::new(0),
        }
    }

    #[allow(dead_code)]
    pub fn enabled(&self) -> bool {
        self.cfg.enable
    }

    #[allow(dead_code)]
    pub fn active_conns(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// 是否处于封禁期
    pub fn is_banned(&self, ip: Option<IpAddr>) -> bool {
        if !self.cfg.enable {
            return false;
        }
        let Some(ip) = ip else { return false };
        let now = Instant::now();
        let mut g = self.bans.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(b) = g.get_mut(&ip) {
            if let Some(until) = b.banned_until {
                if now < until {
                    return true;
                }
                b.banned_until = None;
                b.strikes = 0;
                b.window_start = now;
            }
        }
        false
    }

    /// 记录一次违规（路径穿越/NUL/非法编码等）；窗口内达到阈值即临时封禁
    pub fn record_violation(&self, ip: Option<IpAddr>) {
        if !self.cfg.enable || self.cfg.max_violations == 0 {
            return;
        }
        let Some(ip) = ip else { return };
        let now = Instant::now();
        let window = Duration::from_secs(self.cfg.violation_window_secs.max(1));
        let mut g = self.bans.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= MAX_ENTRIES {
            let keep = Duration::from_secs(600);
            g.retain(|_, b| {
                b.banned_until.map(|u| u > now).unwrap_or(false)
                    || now.duration_since(b.last_seen) < keep
            });
            if g.len() >= MAX_ENTRIES {
                g.clear();
            }
        }
        let e = g.entry(ip).or_insert(Ban {
            strikes: 0,
            window_start: now,
            banned_until: None,
            last_seen: now,
        });
        e.last_seen = now;
        if now.duration_since(e.window_start) > window {
            e.window_start = now;
            e.strikes = 0;
        }
        e.strikes += 1;
        if e.strikes >= self.cfg.max_violations as u32 {
            e.banned_until = Some(now + Duration::from_secs(self.cfg.ban_secs.max(1)));
            e.strikes = 0;
            crate::log_warn!("应用层封禁违规 IP: {ip}（{}s）", self.cfg.ban_secs.max(1));
        }
    }

    /// 获取一个连接配额；None = 超出每 IP 并发上限（应直接断开）
    pub fn acquire_conn(self: &Arc<Self>, ip: Option<IpAddr>) -> Option<ConnGuard> {
        if !self.cfg.enable || self.cfg.max_conn_per_ip == 0 {
            return Some(ConnGuard { defense: self.clone(), ip: None, active: false });
        }
        let Some(ip) = ip else {
            return Some(ConnGuard { defense: self.clone(), ip: None, active: false });
        };
        let mut g = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= MAX_ENTRIES {
            g.retain(|_, c| *c > 0);
            if g.len() >= MAX_ENTRIES {
                return None; // 极端情况：保守拒绝，防内存膨胀
            }
        }
        let c = g.entry(ip).or_insert(0);
        if *c >= self.cfg.max_conn_per_ip {
            return None;
        }
        *c += 1;
        self.active.fetch_add(1, Ordering::Relaxed);
        Some(ConnGuard { defense: self.clone(), ip: Some(ip), active: true })
    }

    fn release(&self, ip: Option<IpAddr>) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        if let Some(ip) = ip {
            let mut g = self.conns.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(c) = g.get_mut(&ip) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    g.remove(&ip);
                }
            }
        }
    }
}

pub struct ConnGuard {
    defense: Arc<Defense>,
    ip: Option<IpAddr>,
    active: bool,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if self.active {
            self.defense.release(self.ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DefenseCfg {
        DefenseCfg {
            enable: true,
            max_conn_per_ip: 2,
            max_violations: 3,
            violation_window_secs: 60,
            ban_secs: 60,
            max_header_kb: 64,
            max_requests_per_conn: 100,
        }
    }

    #[test]
    fn violation_bans() {
        let d = Arc::new(Defense::new(cfg()));
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(!d.is_banned(Some(ip)));
        d.record_violation(Some(ip));
        d.record_violation(Some(ip));
        assert!(!d.is_banned(Some(ip)));
        d.record_violation(Some(ip)); // 第 3 次触发封禁
        assert!(d.is_banned(Some(ip)));
        assert!(d.is_banned(Some(ip)));
    }

    #[test]
    fn conn_limit() {
        let d = Arc::new(Defense::new(cfg()));
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        let g1 = d.acquire_conn(Some(ip)).unwrap();
        let g2 = d.acquire_conn(Some(ip)).unwrap();
        assert!(d.acquire_conn(Some(ip)).is_none());
        drop(g1);
        let g3 = d.acquire_conn(Some(ip)).unwrap();
        assert_eq!(d.active_conns(), 2);
        drop(g2);
        drop(g3);
        assert_eq!(d.active_conns(), 0);
    }
}
