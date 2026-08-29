//! 鉴权：Bearer Token / Basic Auth / 无
//! 所有字符串比较均使用常量时间比较（subtle），防止时序侧信道。
use crate::config::AuthPolicy;
use base64::Engine;
use http::HeaderMap;
use subtle::ConstantTimeEq;

pub enum AuthResult {
    Ok,
    /// 未提供凭据，应返回 401 + WWW-Authenticate
    Missing,
    /// 凭据错误
    Invalid,
}

/// 从请求头提取凭据并校验
pub fn check(policy: &AuthPolicy, headers: &HeaderMap) -> AuthResult {
    match policy {
        AuthPolicy::None => AuthResult::Ok,
        AuthPolicy::Bearer(tokens) => {
            let Some(v) = header(headers, "authorization") else {
                return AuthResult::Missing;
            };
            if let Some(tok) = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")) {
                let tok = tok.trim();
                if tokens.iter().any(|t| ct_eq(t.as_bytes(), tok.as_bytes())) {
                    return AuthResult::Ok;
                }
                AuthResult::Invalid
            } else {
                AuthResult::Missing
            }
        }
        AuthPolicy::Basic(users) => {
            let Some(v) = header(headers, "authorization") else {
                return AuthResult::Missing;
            };
            let Some(b64) = v
                .strip_prefix("Basic ")
                .or_else(|| v.strip_prefix("basic "))
            else {
                return AuthResult::Missing;
            };
            let Ok(dec) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
                return AuthResult::Invalid;
            };
            let Ok(s) = String::from_utf8(dec) else {
                return AuthResult::Invalid;
            };
            let Some((user, pass)) = s.split_once(':') else {
                return AuthResult::Invalid;
            };
            match users.get(user) {
                None => {
                    // 用户不存在也走一次比较，避免用户名枚举时序差异
                    let _ = ct_eq(b"dummy", b"dummy");
                    AuthResult::Invalid
                }
                Some(p) => {
                    if ct_eq(p.as_bytes(), pass.as_bytes()) {
                        AuthResult::Ok
                    } else {
                        AuthResult::Invalid
                    }
                }
            }
        }
        AuthPolicy::Any(tokens, users) => {
            let Some(v) = header(headers, "authorization") else {
                return AuthResult::Missing;
            };
            if let Some(tok) = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")) {
                if tokens.iter().any(|t| ct_eq(t.as_bytes(), tok.trim().as_bytes())) {
                    return AuthResult::Ok;
                }
                return AuthResult::Invalid;
            }
            if let Some(b64) = v.strip_prefix("Basic ").or_else(|| v.strip_prefix("basic ")) {
                let Ok(dec) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
                    return AuthResult::Invalid;
                };
                let Ok(s) = String::from_utf8(dec) else { return AuthResult::Invalid };
                let Some((user, pass)) = s.split_once(':') else { return AuthResult::Invalid };
                match users.get(user) {
                    Some(p) if ct_eq(p.as_bytes(), pass.as_bytes()) => AuthResult::Ok,
                    _ => AuthResult::Invalid,
                }
            } else {
                AuthResult::Missing
            }
        }
    }
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// 常量时间比较
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // 长度不同时也做一次假比较，尽量抹平时序
        let _ = a.ct_eq(b);
        return false;
    }
    a.ct_eq(b).into()
}