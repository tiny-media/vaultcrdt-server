use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use crate::errors::ServerError;

const JWT_EXPIRY_SECS: u64 = 3600; // 1 hour
const AUTH_REQUEST_LIMIT: u32 = 10;
const AUTH_WINDOW_SECS: u64 = 60;
/// Upper bound on tracked keys: distinct client identifiers within one window.
/// Beyond it the limiter fails CLOSED (429) — bounded memory beats an open
/// door under key spraying.
const AUTH_MAX_KEYS: usize = 65_536;

/// Compare all bytes without an early exit on a mismatch.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

#[derive(Default)]
pub struct AuthRateLimiter {
    windows: Mutex<HashMap<String, (u64, u32)>>,
}

impl AuthRateLimiter {
    pub async fn check(&self, key: &str, now_secs: u64) -> bool {
        let mut windows = self.windows.lock().await;
        windows.retain(|_, (start, _)| now_secs.saturating_sub(*start) < AUTH_WINDOW_SECS);
        if windows.len() >= AUTH_MAX_KEYS && !windows.contains_key(key) {
            return false;
        }
        let (_, count) = windows.entry(key.to_string()).or_insert((now_secs, 0));
        if *count >= AUTH_REQUEST_LIMIT {
            return false;
        }
        *count += 1;
        true
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    pub sub: String,
    pub exp: u64,
}

/// Sign a JWT that carries the vault_id claim.
pub fn jwt_sign(vault_id: &str, secret: &str) -> Result<String, ServerError> {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_secs()
        + JWT_EXPIRY_SECS;

    let claims = Claims {
        sub: vault_id.to_string(),
        exp,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(ServerError::Jwt)
}

/// Verify a JWT and return the vault_id.
pub fn jwt_verify(token: &str, secret: &str) -> Result<String, ServerError> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(ServerError::Jwt)?;
    Ok(data.claims.sub)
}
