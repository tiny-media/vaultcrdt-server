use axum::{
    Json,
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

use crate::{AppState, VaultAuth, auth, db, db::Db, errors::ServerError};

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
        &state.db,
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
    db: &Db,
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
    let conn = db.lock().await;
    conn.execute(
        "DELETE FROM invites WHERE created_at < datetime('now', '-1 day')",
        [],
    )?;
    let hash = sha256_hex(&invite);
    let expires_at: String = conn.query_row(
        "INSERT INTO invites (vault_id, token_hash, inviter_peer_id, device_name, expires_at) VALUES (?, ?, ?, ?, datetime('now', '+15 minutes')) RETURNING expires_at",
        params![vault_id, hash, inviter_peer_id, device_name],
        |r| r.get(0),
    )?;
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
    let candidates: Vec<(i64, String, String)> = {
        let conn = state.db.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, vault_id, token_hash FROM invites WHERE created_at > datetime('now', '-1 day')",
        )?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?
    };
    let matched = candidates
        .into_iter()
        .find(|(_, _, token_hash)| token_hash.as_str() == sha256_hex(&body.invite).as_str());
    let Some((id, vault_id, _)) = matched else {
        return Ok(error(StatusCode::UNAUTHORIZED, "invalid invite"));
    };
    let device_key = random_secret(
        32,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    );
    let hash = db::hash_secret(&device_key)?;
    let token = auth::jwt_sign(&vault_id, &state.jwt_secret)?;
    let mut conn = state.db.lock().await;
    let tx = conn.transaction()?;
    // First statement is a write: no deferred read-to-write upgrade race.
    let updated = tx.execute(
        "UPDATE invites SET used_at = datetime('now') WHERE id = ? AND used_at IS NULL AND expires_at > datetime('now')",
        params![id],
    )?;
    if updated == 0 {
        let used: Option<String> = tx.query_row(
            "SELECT used_at FROM invites WHERE id = ?",
            params![id],
            |r| r.get(0),
        )?;
        tx.rollback()?;
        return Ok(if used.is_some() {
            error(StatusCode::CONFLICT, "invite already used")
        } else {
            error(StatusCode::GONE, "invite expired")
        });
    }
    tx.execute(
        "INSERT INTO device_keys (vault_id, peer_id, key_hash, device_name) VALUES (?, ?, ?, ?)",
        params![&vault_id, body.peer_id, hash, body.device_name],
    )?;
    tx.commit()?;
    drop(conn);
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
    let hash: Option<String> = {
        let conn = state.db.lock().await;
        conn.query_row(
            "SELECT key_hash FROM device_keys WHERE vault_id = ? AND peer_id = ? AND revoked_at IS NULL",
            params![&body.vault_id, body.peer_id],
            |r| r.get(0),
        )
        .optional()?
    };
    if !hash.is_some_and(|hash| db::verify_secret(&body.device_key, &hash)) {
        return Ok(error(StatusCode::UNAUTHORIZED, "authentication failed"));
    }
    Ok(Json(json!({"token": auth::jwt_sign(&body.vault_id, &state.jwt_secret)?})).into_response())
}
