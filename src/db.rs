use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool, sqlite::SqliteConnectOptions};
use std::str::FromStr;

use crate::errors::ServerError;

const INVALID_VV_SENTINEL_JSON: &[u8] = b"__vaultcrdt_invalid_vv__";

// ── Pool creation ────────────────────────────────────────────────────────────

pub async fn create_pool(db_path: &str) -> Result<SqlitePool, ServerError> {
    let opts = SqliteConnectOptions::from_str(&format!("sqlite:{db_path}"))
        .map_err(ServerError::Db)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

    let pool_size: u32 = std::env::var("VAULTCRDT_POOL_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);

    let pool = sqlx::pool::PoolOptions::new()
        .max_connections(pool_size)
        .connect_with(opts)
        .await
        .map_err(ServerError::Db)?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(ServerError::Migration)?;

    // Performance pragmas (safe with WAL mode)
    sqlx::query("PRAGMA busy_timeout = 5000")
        .execute(&pool)
        .await
        .map_err(ServerError::Db)?;
    // 128 MB memory-mapped I/O — speeds up reads for typical vault sizes (<1 GB)
    sqlx::query("PRAGMA mmap_size = 134217728")
        .execute(&pool)
        .await
        .map_err(ServerError::Db)?;
    sqlx::query("PRAGMA cache_size = -8000")
        .execute(&pool)
        .await
        .map_err(ServerError::Db)?;
    sqlx::query("PRAGMA temp_store = MEMORY")
        .execute(&pool)
        .await
        .map_err(ServerError::Db)?;

    Ok(pool)
}

// ── Structs ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DocEntry {
    pub doc_uuid: String,
    pub updated_at: String,
    #[serde(with = "serde_bytes")]
    pub server_vv: Vec<u8>,
}

// ── Secret hashing (Argon2id) ────────────────────────────────────────────────

use argon2::Argon2;
use password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};

/// Hash a plaintext secret with Argon2id, returning a PHC string.
pub fn hash_secret(plaintext: &str) -> Result<String, ServerError> {
    Argon2::default()
        .hash_password(plaintext.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| ServerError::Auth(format!("hash error: {e}")))
}

/// Verify a plaintext secret against a stored value.
/// If `stored` is a PHC Argon2 string, performs constant-time verification.
/// Otherwise treats `stored` as legacy plaintext (lazy-migration path).
pub fn verify_secret(plaintext: &str, stored: &str) -> bool {
    if stored.starts_with("$argon2") {
        match PasswordHash::new(stored) {
            Ok(parsed) => Argon2::default()
                .verify_password(plaintext.as_bytes(), &parsed)
                .is_ok(),
            Err(_) => false,
        }
    } else {
        stored == plaintext
    }
}

// ── Vault queries ─────────────────────────────────────────────────────────────

pub async fn create_vault(
    pool: &SqlitePool,
    vault_id: &str,
    api_key: &str,
) -> Result<bool, ServerError> {
    let hashed = hash_secret(api_key)?;
    let result = sqlx::query("INSERT OR IGNORE INTO vaults (vault_id, api_key) VALUES (?, ?)")
        .bind(vault_id)
        .bind(hashed)
        .execute(pool)
        .await
        .map_err(ServerError::Db)?;
    Ok(result.rows_affected() == 1)
}

/// (vault_id, created_at) for the operator CLI listing.
pub async fn list_vaults(pool: &SqlitePool) -> Result<Vec<(String, String)>, ServerError> {
    let rows = sqlx::query("SELECT vault_id, created_at FROM vaults ORDER BY vault_id")
        .fetch_all(pool)
        .await
        .map_err(ServerError::Db)?;
    Ok(rows
        .into_iter()
        .map(|r| (r.get("vault_id"), r.get("created_at")))
        .collect())
}

pub async fn vault_exists(pool: &SqlitePool, vault_id: &str) -> Result<bool, ServerError> {
    let row = sqlx::query("SELECT 1 FROM vaults WHERE vault_id = ?")
        .bind(vault_id)
        .fetch_optional(pool)
        .await
        .map_err(ServerError::Db)?;
    Ok(row.is_some())
}

pub async fn verify_vault(
    pool: &SqlitePool,
    vault_id: &str,
    api_key: &str,
) -> Result<bool, ServerError> {
    let row = sqlx::query("SELECT api_key FROM vaults WHERE vault_id = ?")
        .bind(vault_id)
        .fetch_optional(pool)
        .await
        .map_err(ServerError::Db)?;

    let Some(r) = row else { return Ok(false) };
    let stored: String = r.get("api_key");

    if !verify_secret(api_key, &stored) {
        return Ok(false);
    }

    // Lazy migration: legacy plaintext entry → upgrade to Argon2id PHC.
    if !stored.starts_with("$argon2") {
        let hashed = hash_secret(api_key)?;
        sqlx::query("UPDATE vaults SET api_key = ? WHERE vault_id = ?")
            .bind(hashed)
            .bind(vault_id)
            .execute(pool)
            .await
            .map_err(ServerError::Db)?;
    }

    Ok(true)
}

// ── Document queries ─────────────────────────────────────────────────────────

pub async fn store_snapshot_with_vv(
    pool: &SqlitePool,
    vault_id: &str,
    doc_uuid: &str,
    snapshot: &[u8],
    vv_blob: &[u8],
) -> Result<(), ServerError> {
    sqlx::query(
        "INSERT INTO documents (vault_id, doc_uuid, snapshot_blob, vv_blob) VALUES (?, ?, ?, ?) \
         ON CONFLICT(vault_id, doc_uuid) DO UPDATE SET \
           snapshot_blob = excluded.snapshot_blob, \
           vv_blob = excluded.vv_blob, \
           updated_at = datetime('now')",
    )
    .bind(vault_id)
    .bind(doc_uuid)
    .bind(snapshot)
    .bind(vv_blob)
    .execute(pool)
    .await
    .map_err(ServerError::Db)?;
    Ok(())
}

pub async fn get_snapshot_with_vv(
    pool: &SqlitePool,
    vault_id: &str,
    doc_uuid: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, ServerError> {
    let row = sqlx::query(
        "SELECT snapshot_blob, vv_blob FROM documents WHERE vault_id = ? AND doc_uuid = ?",
    )
    .bind(vault_id)
    .bind(doc_uuid)
    .fetch_optional(pool)
    .await
    .map_err(ServerError::Db)?;

    Ok(row.map(|r| {
        let snapshot: Vec<u8> = r.get("snapshot_blob");
        let vv: Vec<u8> = r.get("vv_blob");
        (snapshot, vv)
    }))
}

pub async fn list_docs_with_vv(
    pool: &SqlitePool,
    vault_id: &str,
) -> Result<Vec<DocEntry>, ServerError> {
    let rows = sqlx::query(
        "SELECT doc_uuid, updated_at, vv_blob FROM documents WHERE vault_id = ? ORDER BY doc_uuid",
    )
    .bind(vault_id)
    .fetch_all(pool)
    .await
    .map_err(ServerError::Db)?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let db_vv: Vec<u8> = r.get("vv_blob");
            // Convert from DB binary encoding to JSON bytes (same format as sync_delta)
            let json_vv = match crate::vv_serde::vv_from_db_bytes(&db_vv) {
                Ok(vv) => crate::vv_serde::vv_to_json_bytes(&vv),
                // Never return raw DB bytes as if they were JSON VV. Clients treat this
                // sentinel as unparseable/unknown and take conservative full-sync paths.
                Err(_) => INVALID_VV_SENTINEL_JSON.to_vec(),
            };
            DocEntry {
                doc_uuid: r.get("doc_uuid"),
                updated_at: r.get("updated_at"),
                server_vv: json_vv,
            }
        })
        .collect())
}

// ── Tombstone queries ─────────────────────────────────────────────────────────

pub async fn tombstone(
    pool: &SqlitePool,
    vault_id: &str,
    doc_uuid: &str,
    deleted_by: &str,
) -> Result<(), ServerError> {
    sqlx::query(
        "INSERT INTO tombstones (vault_id, doc_uuid, deleted_by) VALUES (?, ?, ?) \
         ON CONFLICT(vault_id, doc_uuid) DO UPDATE SET \
           deleted_by = excluded.deleted_by, \
           deleted_at = datetime('now')",
    )
    .bind(vault_id)
    .bind(doc_uuid)
    .bind(deleted_by)
    .execute(pool)
    .await
    .map_err(ServerError::Db)?;
    Ok(())
}

pub async fn list_tombstones(
    pool: &SqlitePool,
    vault_id: &str,
) -> Result<Vec<String>, ServerError> {
    let rows = sqlx::query("SELECT doc_uuid FROM tombstones WHERE vault_id = ? ORDER BY doc_uuid")
        .bind(vault_id)
        .fetch_all(pool)
        .await
        .map_err(ServerError::Db)?;

    Ok(rows.into_iter().map(|r| r.get("doc_uuid")).collect())
}

pub async fn is_tombstoned(
    pool: &SqlitePool,
    vault_id: &str,
    doc_uuid: &str,
) -> Result<bool, ServerError> {
    let row = sqlx::query("SELECT 1 FROM tombstones WHERE vault_id = ? AND doc_uuid = ?")
        .bind(vault_id)
        .bind(doc_uuid)
        .fetch_optional(pool)
        .await
        .map_err(ServerError::Db)?;
    Ok(row.is_some())
}

pub async fn remove_tombstone(
    pool: &SqlitePool,
    vault_id: &str,
    doc_uuid: &str,
) -> Result<(), ServerError> {
    sqlx::query("DELETE FROM tombstones WHERE vault_id = ? AND doc_uuid = ?")
        .bind(vault_id)
        .bind(doc_uuid)
        .execute(pool)
        .await
        .map_err(ServerError::Db)?;
    Ok(())
}

pub async fn delete_doc(
    pool: &SqlitePool,
    vault_id: &str,
    doc_uuid: &str,
) -> Result<(), ServerError> {
    sqlx::query("DELETE FROM documents WHERE vault_id = ? AND doc_uuid = ?")
        .bind(vault_id)
        .bind(doc_uuid)
        .execute(pool)
        .await
        .map_err(ServerError::Db)?;
    Ok(())
}

/// Atomically delete the document row and insert/update its tombstone.
pub async fn delete_doc_and_tombstone(
    pool: &SqlitePool,
    vault_id: &str,
    doc_uuid: &str,
    deleted_by: &str,
) -> Result<(), ServerError> {
    let mut tx = pool.begin().await.map_err(ServerError::Db)?;
    sqlx::query("DELETE FROM documents WHERE vault_id = ? AND doc_uuid = ?")
        .bind(vault_id)
        .bind(doc_uuid)
        .execute(&mut *tx)
        .await
        .map_err(ServerError::Db)?;
    sqlx::query(
        "INSERT INTO tombstones (vault_id, doc_uuid, deleted_by) VALUES (?, ?, ?) \
         ON CONFLICT(vault_id, doc_uuid) DO UPDATE SET \
           deleted_by = excluded.deleted_by, \
           deleted_at = datetime('now')",
    )
    .bind(vault_id)
    .bind(doc_uuid)
    .bind(deleted_by)
    .execute(&mut *tx)
    .await
    .map_err(ServerError::Db)?;
    tx.commit().await.map_err(ServerError::Db)?;
    Ok(())
}

// ── Stats queries ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct VaultStats {
    pub doc_count: i64,
    pub total_snapshot_bytes: i64,
    pub total_vv_bytes: i64,
    pub largest_docs: Vec<DocSize>,
}

#[derive(Debug, Serialize)]
pub struct DocSize {
    pub doc_uuid: String,
    pub snapshot_bytes: i64,
}

pub async fn vault_stats(pool: &SqlitePool, vault_id: &str) -> Result<VaultStats, ServerError> {
    let agg = sqlx::query(
        "SELECT COUNT(*) as cnt, COALESCE(SUM(LENGTH(snapshot_blob)),0) as snap, \
         COALESCE(SUM(LENGTH(vv_blob)),0) as vv FROM documents WHERE vault_id = ?",
    )
    .bind(vault_id)
    .fetch_one(pool)
    .await
    .map_err(ServerError::Db)?;

    let largest_rows = sqlx::query(
        "SELECT doc_uuid, LENGTH(snapshot_blob) as size FROM documents \
         WHERE vault_id = ? ORDER BY size DESC LIMIT 10",
    )
    .bind(vault_id)
    .fetch_all(pool)
    .await
    .map_err(ServerError::Db)?;

    Ok(VaultStats {
        doc_count: agg.get("cnt"),
        total_snapshot_bytes: agg.get("snap"),
        total_vv_bytes: agg.get("vv"),
        largest_docs: largest_rows
            .into_iter()
            .map(|r| DocSize {
                doc_uuid: r.get("doc_uuid"),
                snapshot_bytes: r.get("size"),
            })
            .collect(),
    })
}

// ── Peer queries ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub device_name: String,
    pub last_seen_at: String,
}

pub async fn upsert_peer(
    pool: &SqlitePool,
    vault_id: &str,
    peer_id: &str,
    device_name: &str,
) -> Result<(), ServerError> {
    sqlx::query(
        "INSERT INTO peers (vault_id, peer_id, device_name) VALUES (?, ?, ?) \
         ON CONFLICT(vault_id, peer_id) DO UPDATE SET \
           device_name = excluded.device_name, \
           last_seen_at = datetime('now')",
    )
    .bind(vault_id)
    .bind(peer_id)
    .bind(device_name)
    .execute(pool)
    .await
    .map_err(ServerError::Db)?;
    Ok(())
}

pub async fn list_peers(pool: &SqlitePool, vault_id: &str) -> Result<Vec<PeerInfo>, ServerError> {
    let rows = sqlx::query(
        "SELECT peer_id, device_name, last_seen_at FROM peers \
         WHERE vault_id = ? ORDER BY last_seen_at DESC",
    )
    .bind(vault_id)
    .fetch_all(pool)
    .await
    .map_err(ServerError::Db)?;

    Ok(rows
        .into_iter()
        .map(|r| PeerInfo {
            peer_id: r.get("peer_id"),
            device_name: r.get("device_name"),
            last_seen_at: r.get("last_seen_at"),
        })
        .collect())
}

/// Fetch a single peer by `(vault_id, peer_id)`. Returns `None` if that exact
/// pair is unknown (scoped per vault — the same `peer_id` in another vault is a
/// different peer and is not returned here).
pub async fn get_peer(
    pool: &SqlitePool,
    vault_id: &str,
    peer_id: &str,
) -> Result<Option<PeerInfo>, ServerError> {
    let row = sqlx::query(
        "SELECT peer_id, device_name, last_seen_at FROM peers \
         WHERE vault_id = ? AND peer_id = ?",
    )
    .bind(vault_id)
    .bind(peer_id)
    .fetch_optional(pool)
    .await
    .map_err(ServerError::Db)?;

    Ok(row.map(|r| PeerInfo {
        peer_id: r.get("peer_id"),
        device_name: r.get("device_name"),
        last_seen_at: r.get("last_seen_at"),
    }))
}

/// Delete a single peer scoped to its vault. Returns the number of rows
/// affected (0 or 1). Never crosses vault boundaries — a peer that lingers in
/// several vaults must be retired per vault individually.
pub async fn delete_peer(
    pool: &SqlitePool,
    vault_id: &str,
    peer_id: &str,
) -> Result<u64, ServerError> {
    let result = sqlx::query("DELETE FROM peers WHERE vault_id = ? AND peer_id = ?")
        .bind(vault_id)
        .bind(peer_id)
        .execute(pool)
        .await
        .map_err(ServerError::Db)?;
    Ok(result.rows_affected())
}

/// Count tombstones in `vault_id` whose deletion this peer currently blocks,
/// i.e. tombstones deleted at or after the peer's `last_seen_at` (the peer has
/// not provably seen those deletions yet).
///
/// This is an UPPER BOUND, not a guarantee: other retained peers in the same
/// vault may still block the very same tombstones after this peer is removed.
/// Treat the number as a hint about how much cleanup retiring this peer could
/// unblock, never as an exact count of tombstones that will actually expire.
pub async fn count_peer_blocked_tombstones(
    pool: &SqlitePool,
    vault_id: &str,
    last_seen_at: &str,
) -> Result<i64, ServerError> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS cnt FROM tombstones \
         WHERE vault_id = ? AND deleted_at >= ?",
    )
    .bind(vault_id)
    .bind(last_seen_at)
    .fetch_one(pool)
    .await
    .map_err(ServerError::Db)?;
    Ok(row.get("cnt"))
}

pub async fn expire_tombstones(pool: &SqlitePool, max_age_days: i64) -> Result<u64, ServerError> {
    let result = sqlx::query(
        "DELETE FROM tombstones
         WHERE deleted_at < datetime('now', '-' || ? || ' days')
           AND NOT EXISTS (
             SELECT 1 FROM peers
             WHERE peers.vault_id = tombstones.vault_id
               AND peers.last_seen_at <= tombstones.deleted_at
           )",
    )
    .bind(max_age_days)
    .execute(pool)
    .await
    .map_err(ServerError::Db)?;
    Ok(result.rows_affected())
}

/// Remove peers not seen for more than `max_age_days` days.
pub async fn expire_stale_peers(pool: &SqlitePool, max_age_days: i64) -> Result<u64, ServerError> {
    let result =
        sqlx::query("DELETE FROM peers WHERE last_seen_at < datetime('now', '-' || ? || ' days')")
            .bind(max_age_days)
            .execute(pool)
            .await
            .map_err(ServerError::Db)?;
    Ok(result.rows_affected())
}

/// Run non-blocking SQLite maintenance: truncate the WAL and refresh query
/// planner stats. Deliberately does NOT run `VACUUM` — that takes exclusive
/// locks and would stall the server. Full reclamation is a manual step, see
/// [`run_full_vacuum`].
pub async fn run_maintenance(pool: &SqlitePool) -> Result<(), ServerError> {
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(pool)
        .await
        .map_err(ServerError::Db)?;
    sqlx::query("PRAGMA optimize")
        .execute(pool)
        .await
        .map_err(ServerError::Db)?;
    Ok(())
}

/// Run a full `VACUUM` to reclaim fragmented disk space.
///
/// WARNING: `VACUUM` rewrites the entire database and takes an exclusive lock,
/// blocking all reads and writes for its duration (seconds to minutes on large
/// databases). It is intentionally NOT wired into any automatic task — call it
/// manually only inside a planned maintenance window.
pub async fn run_full_vacuum(pool: &SqlitePool) -> Result<(), ServerError> {
    sqlx::query("VACUUM")
        .execute(pool)
        .await
        .map_err(ServerError::Db)?;
    Ok(())
}
