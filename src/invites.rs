use axum::{
    Json,
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use std::net::SocketAddr;

use crate::{AppState, VaultAuth, auth, db, errors::ServerError};

// UUID v4 uses the existing OS-backed randomness source. Exclude the two
// version/variant bytes; rejection sampling avoids alphabet modulo bias.

/// Invite tokens carry 128 bits of OS randomness: a plain SHA-256 is the
/// correct hash (KDFs protect low-entropy secrets; here they only created an
/// O(rows) CPU DoS surface on the unauthenticated redeem route — review
/// 2026-09-06T11-38-07-269Z). Device keys keep argon2 (verify cost, single-row).
fn sha256_hex(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    format!("{:x}", h.finalize())
}

pub(crate) fn random_secret(len: usize, alphabet: &[u8]) -> String {
    let mut result = String::with_capacity(len);
    while result.len() < len {
        let uuid = uuid::Uuid::new_v4();
        for (i, &byte) in uuid.as_bytes().iter().enumerate() {
            if i == 6 || i == 8 || usize::from(byte) >= 256 / alphabet.len() * alphabet.len() {
                continue;
            }
            result.push(alphabet[usize::from(byte) % alphabet.len()] as char);
            if result.len() == len {
                break;
            }
        }
    }
    result
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error": message}))).into_response()
}

// Apply the same limiter before JSON decoding or Argon2 work, including on
// device authentication. Shared IP accounting never depends on a vault name.
pub async fn rate_limit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: axum::middleware::Next,
) -> Result<Response, ServerError> {
    crate::check_auth_rate_limit(&state, addr, req.headers()).await?;
    Ok(next.run(req).await)
}

#[derive(Deserialize)]
pub struct InviteRequest {
    peer_id: String,
    device_name: Option<String>,
}

pub async fn create(
    State(state): State<AppState>,
    VaultAuth(vault_id): VaultAuth,
    Json(body): Json<InviteRequest>,
) -> Result<Response, ServerError> {
    if body.peer_id.is_empty() {
        return Ok(error(StatusCode::BAD_REQUEST, "peer_id must not be empty"));
    }
    let (invite, expires_at) = mint_invite(
        &state.pool,
        &vault_id,
        &body.peer_id,
        body.device_name.as_deref(),
    )
    .await?;
    Ok(
        Json(json!({"invite": invite, "vault_id": vault_id, "expires_at": expires_at}))
            .into_response(),
    )
}

/// Mint one invite row. Shared by the HTTP handler and the operator CLI.
pub(crate) async fn mint_invite(
    pool: &sqlx::SqlitePool,
    vault_id: &str,
    inviter_peer_id: &str,
    device_name: Option<&str>,
) -> Result<(String, String), ServerError> {
    let invite = random_secret(
        22,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
    );
    // Housekeeping: invites live minutes; rows older than a day are dead
    // weight (the redeem scan only considers the last day anyway).
    sqlx::query("DELETE FROM invites WHERE created_at < datetime('now', '-1 day')")
        .execute(pool)
        .await?;
    let hash = sha256_hex(&invite);
    let expires_at: String = sqlx::query_scalar(
        "INSERT INTO invites (vault_id, token_hash, inviter_peer_id, device_name, expires_at) VALUES (?, ?, ?, ?, datetime('now', '+15 minutes')) RETURNING expires_at",
    )
    .bind(vault_id).bind(hash).bind(inviter_peer_id).bind(device_name)
    .fetch_one(pool).await?;
    Ok((invite, expires_at))
}

#[derive(Deserialize)]
pub struct RedeemRequest {
    invite: String,
    peer_id: String,
    device_name: String,
}

pub async fn redeem(
    State(state): State<AppState>,
    Json(body): Json<RedeemRequest>,
) -> Result<Response, ServerError> {
    if body.invite.len() != 22
        || !body
            .invite
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Ok(error(StatusCode::UNAUTHORIZED, "invalid invite"));
    }
    if body.peer_id.is_empty() {
        return Ok(error(StatusCode::BAD_REQUEST, "peer_id must not be empty"));
    }
    // No caller-controlled vault selector or per-vault brute-force counter.
    // Keep used/expired hashes so their exact, authenticated errors remain available.
    let candidates = sqlx::query(
        "SELECT id, vault_id, token_hash FROM invites WHERE created_at > datetime('now', '-1 day')",
    )
    .fetch_all(&state.pool)
    .await?;
    let matched = candidates
        .into_iter()
        .find(|row| row.get::<&str, _>("token_hash") == sha256_hex(&body.invite).as_str());
    let Some(row) = matched else {
        return Ok(error(StatusCode::UNAUTHORIZED, "invalid invite"));
    };
    let id: i64 = row.get("id");
    let vault_id: String = row.get("vault_id");
    let device_key = random_secret(
        32,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    );
    let hash = db::hash_secret(&device_key)?;
    let token = auth::jwt_sign(&vault_id, &state.jwt_secret)?;
    let mut tx = state.pool.begin().await?;
    // First statement is a write: no deferred read-to-write upgrade race.
    let updated = sqlx::query("UPDATE invites SET used_at = datetime('now') WHERE id = ? AND used_at IS NULL AND expires_at > datetime('now')")
        .bind(id).execute(&mut *tx).await?.rows_affected();
    if updated == 0 {
        let used: Option<String> = sqlx::query_scalar("SELECT used_at FROM invites WHERE id = ?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        tx.rollback().await?;
        return Ok(if used.is_some() {
            error(StatusCode::CONFLICT, "invite already used")
        } else {
            error(StatusCode::GONE, "invite expired")
        });
    }
    sqlx::query(
        "INSERT INTO device_keys (vault_id, peer_id, key_hash, device_name) VALUES (?, ?, ?, ?)",
    )
    .bind(&vault_id)
    .bind(body.peer_id)
    .bind(hash)
    .bind(body.device_name)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(
        Json(json!({"device_key": device_key, "token": token, "vault_id": vault_id}))
            .into_response(),
    )
}

#[derive(Deserialize)]
pub struct DeviceRequest {
    vault_id: String,
    peer_id: String,
    device_key: String,
}

pub async fn device_auth(
    State(state): State<AppState>,
    Json(body): Json<DeviceRequest>,
) -> Result<Response, ServerError> {
    let hash: Option<String> = sqlx::query_scalar("SELECT key_hash FROM device_keys WHERE vault_id = ? AND peer_id = ? AND revoked_at IS NULL")
        .bind(&body.vault_id).bind(body.peer_id).fetch_optional(&state.pool).await?;
    if !hash.is_some_and(|hash| db::verify_secret(&body.device_key, &hash)) {
        return Ok(error(StatusCode::UNAUTHORIZED, "authentication failed"));
    }
    Ok(Json(json!({"token": auth::jwt_sign(&body.vault_id, &state.jwt_secret)?})).into_response())
}
