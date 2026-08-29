//! 极简日志：等级过滤 + 时间戳，全部输出到 stdout，零依赖开销
//! 空闲时不做任何轮询，CPU 占用为 0。

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
}

static LEVEL: AtomicU8 = AtomicU8::new(1); // 默认 info
static ACCESS: AtomicBool = AtomicBool::new(true);

pub fn set_level(s: &str) {
    let lv = match s.trim().to_lowercase().as_str() {
        "debug" | "trace" => Level::Debug,
        "info" => Level::Info,
        "warn" | "warning" => Level::Warn,
        "error" => Level::Error,
        _ => Level::Info,
    };
    LEVEL.store(lv as u8, Ordering::Relaxed);
}

pub fn set_access(on: bool) {
    ACCESS.store(on, Ordering::Relaxed);
}

pub fn enabled(lv: Level) -> bool {
    (lv as u8) >= LEVEL.load(Ordering::Relaxed)
}

fn now_iso() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = t.as_secs() as i64;
    let ms = t.subsec_millis();
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}")
}

/// Howard Hinnant 经典算法：儒略日 -> 公历
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn log(lv: Level, msg: &str) {
    if !enabled(lv) {
        return;
    }
    let tag = match lv {
        Level::Debug => "DBG",
        Level::Info => "INF",
        Level::Warn => "WRN",
        Level::Error => "ERR",
    };
    println!("{} [{}] {}", now_iso(), tag, msg);
}

#[macro_export]
macro_rules! log_debug { ($($arg:tt)*) => { $crate::log::log($crate::log::Level::Debug, &format!($($arg)*)) } }
#[macro_export]
macro_rules! log_info { ($($arg:tt)*) => { $crate::log::log($crate::log::Level::Info, &format!($($arg)*)) } }
#[macro_export]
macro_rules! log_warn { ($($arg:tt)*) => { $crate::log::log($crate::log::Level::Warn, &format!($($arg)*)) } }
#[macro_export]
macro_rules! log_error { ($($arg:tt)*) => { $crate::log::log($crate::log::Level::Error, &format!($($arg)*)) } }

/// 访问日志：一行一条
pub fn access(
    peer: &str,
    method: &str,
    path: &str,
    status: u16,
    bytes: u64,
    dur_ms: u128,
    host: &str,
) {
    if !ACCESS.load(Ordering::Relaxed) || !enabled(Level::Info) {
        return;
    }
    println!(
        "{} [ACC] {} \"{} {} HTTP\" {} {} {}ms host={}",
        now_iso(),
        peer,
        method,
        path,
        status,
        bytes,
        dur_ms,
        if host.is_empty() { "-" } else { host }
    );
}