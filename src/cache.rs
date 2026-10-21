//! 小文件内存缓存：近似 FIFO 淘汰，字节预算硬上限（防 OOM）
//! 仅缓存“整文件 GET/HEAD”（Range 请求不缓存）；mtime/长度变化自动失效。
use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

struct Entry {
    mtime_ns: u128,
    len: u64,
    data: Bytes,
    generation: u64,
}

struct Inner {
    map: HashMap<PathBuf, Entry>,
    order: VecDeque<(PathBuf, u64)>,
    used: usize,
    next_gen: u64,
}

pub struct SmallFileCache {
    budget: usize,
    max_file: usize,
    inner: Mutex<Inner>,
}

impl SmallFileCache {
    pub fn new(budget_mb: usize, max_kb: usize) -> SmallFileCache {
        SmallFileCache {
            budget: budget_mb.saturating_mul(1024 * 1024),
            max_file: max_kb.saturating_mul(1024),
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
                used: 0,
                next_gen: 1,
            }),
        }
    }

    pub fn enabled(&self) -> bool {
        self.budget > 0 && self.max_file > 0
    }

    /// 命中返回完整文件内容；mtime/长度不一致视为未命中
    pub fn get(&self, path: &Path, mtime_ns: u128, len: u64) -> Option<Bytes> {
        if !self.enabled() {
            return None;
        }
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let e = g.map.get(path)?;
        if e.mtime_ns == mtime_ns && e.len == len {
            Some(e.data.clone())
        } else {
            None
        }
    }

    /// 写入缓存；超预算时按插入顺序淘汰
    pub fn put(&self, path: &Path, mtime_ns: u128, len: u64, data: Bytes) {
        if !self.enabled() || data.len() > self.max_file || data.len() > self.budget {
            return;
        }
        let n = data.len();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let generation = g.next_gen;
        g.next_gen = generation.wrapping_add(1);
        if let Some(old) = g.map.insert(
            path.to_path_buf(),
            Entry { mtime_ns, len, data, generation },
        ) {
            g.used = g.used.saturating_sub(old.data.len());
        }
        g.used += n;
        g.order.push_back((path.to_path_buf(), generation));
        while g.used > self.budget {
            let Some((p, gen)) = g.order.pop_front() else { break };
            let remove = g.map.get(&p).map(|e| e.generation == gen).unwrap_or(false);
            if remove {
                if let Some(e) = g.map.remove(&p) {
                    g.used = g.used.saturating_sub(e.data.len());
                }
            }
        }
    }

    #[cfg(test)]
    fn stats(&self) -> (usize, usize) {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (g.map.len(), g.used)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_and_invalidate() {
        let c = SmallFileCache::new(1, 64);
        let p = Path::new("/tmp/a.txt");
        c.put(p, 1, 3, Bytes::from_static(b"abc"));
        assert_eq!(c.get(p, 1, 3).unwrap(), Bytes::from_static(b"abc"));
        assert!(c.get(p, 2, 3).is_none()); // mtime 变化 → 失效
        assert!(c.get(p, 1, 4).is_none()); // 长度变化 → 失效
    }

    #[test]
    fn budget_eviction() {
        // 预算 1MiB、单文件上限 512KiB：3 × 400KiB 必须淘汰到 ≤1MiB
        let c = SmallFileCache::new(0, 512); // 0MB=关闭
        assert!(!c.enabled());
        let c = SmallFileCache::new(1, 512);
        let a = Path::new("/tmp/a");
        let b = Path::new("/tmp/b");
        let cpath = Path::new("/tmp/c");
        let kb400: usize = 400 * 1024;
        c.put(a, 1, kb400 as u64, Bytes::from(vec![1u8; kb400]));
        c.put(b, 1, kb400 as u64, Bytes::from(vec![2u8; kb400]));
        let (n, used) = c.stats();
        assert!(used <= 1024 * 1024 && n <= 2);
        c.put(cpath, 1, kb400 as u64, Bytes::from(vec![3u8; kb400]));
        let (_n, used2) = c.stats();
        assert!(used2 <= 1024 * 1024);
        // 超大文件（>512KiB）不入缓存
        let kb600: usize = 600 * 1024;
        c.put(Path::new("/tmp/big"), 1, kb600 as u64, Bytes::from(vec![4u8; kb600]));
        assert!(c.get(Path::new("/tmp/big"), 1, kb600 as u64).is_none());
    }
}
