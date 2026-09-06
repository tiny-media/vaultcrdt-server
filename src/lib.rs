pub mod auth;
pub mod cli;
pub mod db;
pub mod errors;
pub mod handlers;
pub mod invites;
pub mod vv_serde;
pub mod ws;

use axum::{
    Json, Router,
    extract::{ConnectInfo, FromRequest, Path, Query, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use db::Db;
use errors::ServerError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tracing::info;

// ── Per-document locks ──────────────────────────────────────────────────────

/// Serialize read-modify-write operations per document (prevents TOCTOU races).
/// Lock entries grow with the number of unique documents but are small (~100 bytes each).
/// For typical vault sizes (<10k docs) this is negligible.
#[derive(Clone, Default)]
pub struct DocLocks {
    locks: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
}

impl DocLocks {
    pub fn lock_key(vault_id: &str, doc_uuid: &str) -> String {
        format!("{vault_id}:{doc_uuid}")
    }

    pub fn get(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.locks.lock().expect("doc_locks mutex poisoned");
        // Evict unused entries so the map does not grow without bound.
        map.retain(|_, lock| Arc::strong_count(lock) > 1);
        map.entry(key.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Number of entries currently held (test/introspection helper).
    pub fn len(&self) -> usize {
        self.locks.lock().expect("doc_locks mutex poisoned").len()
    }

    /// Whether no entries are currently held (clippy: len without is_empty).
    pub fn is_empty(&self) -> bool {
        self.locks
            .lock()
            .expect("doc_locks mutex poisoned")
            .is_empty()
    }
}

// ── App state ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum BroadcastEvent {
    Delta {
        vault_id: String,
        doc_uuid: String,
        delta: Vec<u8>,
        peer_id: String,
        sender_conn_id: u64,
        server_vv: Vec<u8>,
    },
    Delete {
        vault_id: String,
        doc_uuid: String,
        sender_conn_id: u64,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfo {
    pub conn_id: u64,
    pub vault_id: String,
    pub device_name: String,
    pub connected_at: u64,
}

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub jwt_secret: String,
    pub admin_token: String,
    pub trust_proxy: bool,
    pub auth_rate_limiter: Arc<auth::AuthRateLimiter>,
    pub broadcast_tx: broadcast::Sender<BroadcastEvent>,
    pub server_epoch: String,
    pub connections: Arc<Mutex<HashMap<u64, ConnectionInfo>>>,
    pub doc_locks: DocLocks,
}

// ── VaultAuth extractor ─────────────────────────────────────────────────────

pub struct VaultAuth(pub String);

impl axum::extract::FromRequestParts<AppState> for VaultAuth {
    type Rejection = ServerError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(|| {
                ServerError::Auth("Missing or invalid Authorization header".to_string())
            })?;

        let vault_id = auth::jwt_verify(token, &state.jwt_secret)?;
        Ok(VaultAuth(vault_id))
    }
}

// ── Auth endpoint ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AuthRequest {
    vault_id: String,
    api_key: String,
    #[serde(default)]
    admin_token: Option<String>,
}

#[derive(Serialize)]
struct AuthResponse {
    token: String,
    vault_id: String,
}

async fn auth_verify(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
) -> Result<Response, ServerError> {
    check_auth_rate_limit(&state, addr, req.headers()).await?;
    auth_verify_body(state, req).await
}

async fn check_auth_rate_limit(
    state: &AppState,
    addr: SocketAddr,
    headers: &HeaderMap,
) -> Result<(), ServerError> {
    // Rate-limit key. X-Forwarded-For is deliberately NOT used: in a
    // CDN/tunnel/reverse-proxy chain the first XFF hop is client-controllable
    // (a fronting CDN appends the real IP to a supplied XFF) and the last hop
    // is constant. CF-Connecting-IP is set authoritatively by Cloudflare and
    // not forgeable through it — use it only when the operator declared a
    // trusted proxy via VAULTCRDT_TRUST_PROXY, else key by the socket
    // address. Key length is capped in the limiter.
    // note: a non-Cloudflare proxy chain would need its own header
    // decision; upgrade path = configurable header extraction.
    let key = if state.trust_proxy {
        headers
            .get("cf-connecting-ip")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.chars().take(64).collect::<String>())
            .unwrap_or_else(|| addr.ip().to_string())
    } else {
        addr.ip().to_string()
    };
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_secs();
    if !state.auth_rate_limiter.check(&key, now_secs).await {
        return Err(ServerError::TooManyRequests);
    }
    Ok(())
}

/// Vault name rule: <=64 bytes, [a-z0-9_-], must start alphanumeric.
pub fn valid_vault_id(vault_id: &str) -> bool {
    !vault_id.is_empty()
        && vault_id.len() <= 64
        && vault_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && vault_id.as_bytes()[0].is_ascii_alphanumeric()
}

async fn auth_verify_body(
    state: AppState,
    req: axum::extract::Request,
) -> Result<Response, ServerError> {
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::Bytes::from_request(
        axum::extract::Request::from_parts(parts.clone(), body),
        &state,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(rejection) => {
            tracing::warn!("invalid JSON body (0 bytes decoded)");
            return Ok((rejection.status(), "invalid JSON body").into_response());
        }
    };
    let byte_len = bytes.len();
    let req = axum::extract::Request::from_parts(parts, axum::body::Body::from(bytes));
    let Json(body) = match Json::<AuthRequest>::from_request(req, &state).await {
        Ok(body) => body,
        Err(rejection) => {
            tracing::warn!("invalid JSON body ({byte_len} bytes)");
            return Ok((rejection.status(), "invalid JSON body").into_response());
        }
    };
    if !valid_vault_id(&body.vault_id) {
        return Err(ServerError::Auth(
            "Invalid vault name (lowercase letters, numbers, hyphens, underscores; must start with a letter or number)".to_string(),
        ));
    }

    let exists = db::vault_exists(&state.db, &body.vault_id).await?;

    if exists {
        let ok = db::verify_vault(&state.db, &body.vault_id, &body.api_key).await?;
        if !ok {
            return Err(ServerError::Auth("Authentication failed".to_string()));
        }
    } else {
        let key = body.admin_token.as_deref().unwrap_or("");
        if !auth::constant_time_eq(key, &state.admin_token) {
            return Err(ServerError::Auth("Authentication failed".to_string()));
        }
        if db::create_vault(&state.db, &body.vault_id, &body.api_key).await? {
            info!("auth: new vault registered vault_id={}", body.vault_id);
        } else if !db::verify_vault(&state.db, &body.vault_id, &body.api_key).await? {
            return Err(ServerError::Auth("Authentication failed".to_string()));
        }
    }

    let token = auth::jwt_sign(&body.vault_id, &state.jwt_secret)?;
    info!("auth: vault_id={}", body.vault_id);
    Ok(Json(AuthResponse {
        token,
        vault_id: body.vault_id,
    })
    .into_response())
}

// ── Health endpoint ─────────────────────────────────────────────────────────

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "server_epoch": state.server_epoch,
        "protocol_version": ws::PROTOCOL_VERSION,
        "features": ["invite", "device_keys"],
    }))
}

// ── Debug endpoint ─────────────────────────────────────────────────────────

async fn debug_connections(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Result<impl IntoResponse, ServerError> {
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    match auth {
        Some(token) if auth::constant_time_eq(token, &state.admin_token) => {}
        _ => return Err(ServerError::Auth("Admin token required".to_string())),
    }

    let conns = state
        .connections
        .lock()
        .expect("connections mutex poisoned");
    let list: Vec<&ConnectionInfo> = conns.values().collect();
    Ok(Json(serde_json::json!({
        "connections": list,
        "count": list.len(),
    })))
}

// ── Vault stats endpoint ────────────────────────────────────────────────────

async fn vault_stats_handler(
    State(state): State<AppState>,
    VaultAuth(vault_id): VaultAuth,
) -> Result<impl IntoResponse, ServerError> {
    let stats = db::vault_stats(&state.db, &vault_id).await?;
    Ok(Json(stats))
}

// ── Vault peers endpoint ──────────────────────────────────────────────────────

async fn vault_peers_handler(
    State(state): State<AppState>,
    VaultAuth(vault_id): VaultAuth,
) -> Result<impl IntoResponse, ServerError> {
    let peers = db::list_peers(&state.db, &vault_id).await?;
    Ok(Json(serde_json::json!({ "peers": peers })))
}

// ── Peer retire endpoint ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RetirePeerQuery {
    vault_id: Option<String>,
    device_name: Option<String>,
}

/// `DELETE /vault/peers/{peer_id}?vault_id=<v>&device_name=<exact name>`
///
/// Retire a single device from a vault's peer retention so that tombstone
/// cleanup no longer waits on a scrapped device. Confirmation-gated: the caller
/// must repeat the stored `device_name`, otherwise nothing is deleted. Scoped
/// strictly per vault — a peer that lingers in several vaults is retired one
/// vault at a time; there is deliberately no global delete.
async fn retire_peer_handler(
    State(state): State<AppState>,
    Path(peer_id): Path<String>,
    Query(query): Query<RetirePeerQuery>,
    headers: HeaderMap,
) -> Result<Response, ServerError> {
    // 1. Constant-time admin-token auth first. Fail before touching the DB so
    //    nothing about peers/vaults leaks to the unauthorized.
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    match auth {
        Some(token) if auth::constant_time_eq(token, &state.admin_token) => {}
        _ => return Err(ServerError::Auth("Admin token required".to_string())),
    }

    // 2. Required query parameters. Missing vault_id → 400 (never scan all
    //    vaults). Missing device_name → 400 (confirmation is mandatory).
    let Some(vault_id) = query.vault_id.filter(|v| !v.is_empty()) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "missing required query parameter: vault_id"
            })),
        )
            .into_response());
    };
    let Some(device_name) = query.device_name.filter(|v| !v.is_empty()) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "missing required query parameter: device_name (confirmation)"
            })),
        )
            .into_response());
    };

    // 3. Peer lookup by (vault_id, peer_id). Unknown pair → 404.
    let Some(peer) = db::get_peer(&state.db, &vault_id, &peer_id).await? else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "no such peer in this vault"
            })),
        )
            .into_response());
    };

    // 4. device_name mismatch → 409, echoing the STORED name + last_seen_at so
    //    the caller sees what they would delete and can repeat deliberately.
    if peer.device_name != device_name {
        return Ok((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "device_name does not match the stored peer; repeat with the exact stored name to confirm",
                "peer_id": peer.peer_id,
                "device_name": peer.device_name,
                "last_seen_at": peer.last_seen_at,
            })),
        )
            .into_response());
    }

    // 5. Match → delete peer (scoped to vault) and report an upper-bound hint of
    //    tombstones this peer was blocking.
    let tombstones_possibly_freed =
        db::count_peer_blocked_tombstones(&state.db, &vault_id, &peer.last_seen_at).await?;
    {
        let mut conn = state.db.lock().await;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE device_keys SET revoked_at = datetime('now') WHERE vault_id = ? AND peer_id = ?",
            rusqlite::params![&vault_id, &peer_id],
        )?;
        tx.execute(
            "DELETE FROM peers WHERE vault_id = ? AND peer_id = ?",
            rusqlite::params![&vault_id, &peer_id],
        )?;
        tx.commit()?;
    }
    info!("peer retired vault_id={vault_id} peer_id={peer_id}");

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "retired_peer": {
                "peer_id": peer.peer_id,
                "device_name": peer.device_name,
                "last_seen_at": peer.last_seen_at,
            },
            // Upper bound: other retained peers in this vault may still block the
            // same tombstones, so this is a hint, not a guarantee.
            "tombstones_possibly_freed": tombstones_possibly_freed,
        })),
    )
        .into_response())
}

// ── Router ──────────────────────────────────────────────────────────────────

pub fn build_router(state: AppState) -> Router {
    let onboarding = Router::new()
        .route("/invite", post(invites::create))
        .route("/invite/redeem", post(invites::redeem))
        .route("/auth/device", post(invites::device_auth))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            invites::rate_limit,
        ));
    Router::new()
        .merge(onboarding)
        .route("/health", get(health))
        .route("/auth/verify", post(auth_verify))
        .route("/ws", get(ws::ws_handler))
        .route("/debug/connections", get(debug_connections))
        .route("/debug/vault-stats", get(vault_stats_handler))
        .route("/vault/peers", get(vault_peers_handler))
        .route("/vault/peers/{peer_id}", delete(retire_peer_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests;
