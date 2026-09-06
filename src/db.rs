use rusqlite::{Connection, OptionalExtension, params};
use rusqlite_migration::{M, Migrations};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

use crate::errors::ServerError;

const INVALID_VV_SENTINEL_JSON: &[u8] = b"__vaultcrdt_invalid_vv__";

// ── Connection handle ────────────────────────────────────────────────────────

/// One SQLite connection per process, serialized by a mutex.
///
/// Call sites acquire the lock in async code and then run the rusqlite call
/// synchronously — SQLite operations here are microseconds to low
/// milliseconds, so briefly occupying the executor thread is acceptable at
/// friends/family scale.
/// note: ceiling = a single writer/reader under contention. Upgrade path =
/// a dedicated connection thread (actor) or a small pool — measure first.
#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

impl Db {
    pub async fn lock(&self) -> MutexGuard<'_, Connection> {
        self.0.lock().await
    }
}

/// Migrations are compiled in; the `migrations/` directory stays the source of
/// truth. note: three `include_str!` lines beat pulling in `include_dir`
/// via the `from-directory` feature; switch when migrations get numerous.
fn migrations() -> Migrations<'static> {
    Migrations::new(vec![
        M::up(include_str!("../migrations/001_init.sql")),
        M::up(include_str!("../migrations/002_peers.sql")),
        M::up(include_str!("../migrations/003_invites_device_keys.sql")),
    ])
}

/// Databases created by the previous sqlx-based runner track applied
/// migrations in `_sqlx_migrations` and leave `user_version` at 0.
/// Seed `user_version` from the applied count once, then drop the old table so
/// rusqlite_migration takes over silently.
fn adopt_sqlx_migration_state(conn: &Connection) -> Result<(), rusqlite::Error> {
    let has_sqlx: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if !has_sqlx {
        return Ok(());
    }
    let user_version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if user_version == 0 {
        let applied: i64 =
            conn.query_row("SELECT COUNT(*) FROM _sqlx_migrations", [], |r| r.get(0))?;
        conn.pragma_update(None, "user_version", applied)?;
    }
    conn.execute("DROP TABLE _sqlx_migrations", [])?;
    Ok(())
}

pub async fn open_db(db_path: &str) -> Result<Db, ServerError> {
    let conn = Connection::open(db_path).map_err(ServerError::Db)?;

    // Parity with the previous sqlx connect options + performance pragmas.
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(ServerError::Db)?;
    // journal_mode returns a row, so it needs a query rather than pragma_update.
    let _: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
        .map_err(ServerError::Db)?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(ServerError::Db)?;
    conn.pragma_update(None, "busy_timeout", 5000)
        .map_err(ServerError::Db)?;
    // 128 MB memory-mapped I/O — speeds up reads for typical vault sizes (<1 GB)
    conn.pragma_update(None, "mmap_size", 134_217_728i64)
        .map_err(ServerError::Db)?;
    conn.pragma_update(None, "cache_size", -8000)
        .map_err(ServerError::Db)?;
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(ServerError::Db)?;

    adopt_sqlx_migration_state(&conn).map_err(ServerError::Db)?;

    let mut conn = conn;
    migrations()
        .to_latest(&mut conn)
        .map_err(ServerError::Migration)?;

    Ok(Db(Arc::new(Mutex::new(conn))))
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

pub async fn create_vault(db: &Db, vault_id: &str, api_key: &str) -> Result<bool, ServerError> {
    let hashed = hash_secret(api_key)?;
    let conn = db.lock().await;
    let rows = conn.execute(
        "INSERT OR IGNORE INTO vaults (vault_id, api_key) VALUES (?, ?)",
        params![vault_id, hashed],
    )?;
    Ok(rows == 1)
}

/// (vault_id, created_at) for the operator CLI listing.
pub async fn list_vaults(db: &Db) -> Result<Vec<(String, String)>, ServerError> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare("SELECT vault_id, created_at FROM vaults ORDER BY vault_id")?;
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub async fn vault_exists(db: &Db, vault_id: &str) -> Result<bool, ServerError> {
    let conn = db.lock().await;
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM vaults WHERE vault_id = ?",
            params![vault_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

pub async fn verify_vault(db: &Db, vault_id: &str, api_key: &str) -> Result<bool, ServerError> {
    let stored: Option<String> = {
        let conn = db.lock().await;
        conn.query_row(
            "SELECT api_key FROM vaults WHERE vault_id = ?",
            params![vault_id],
            |r| r.get(0),
        )
        .optional()?
    };

    let Some(stored) = stored else {
        return Ok(false);
    };

    if !verify_secret(api_key, &stored) {
        return Ok(false);
    }

    // Lazy migration: legacy plaintext entry → upgrade to Argon2id PHC.
    if !stored.starts_with("$argon2") {
        let hashed = hash_secret(api_key)?;
        let conn = db.lock().await;
        conn.execute(
            "UPDATE vaults SET api_key = ? WHERE vault_id = ?",
            params![hashed, vault_id],
        )?;
    }

    Ok(true)
}

// ── Document queries ─────────────────────────────────────────────────────────

pub async fn store_snapshot_with_vv(
    db: &Db,
    vault_id: &str,
    doc_uuid: &str,
    snapshot: &[u8],
    vv_blob: &[u8],
) -> Result<(), ServerError> {
    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO documents (vault_id, doc_uuid, snapshot_blob, vv_blob) VALUES (?, ?, ?, ?) \
         ON CONFLICT(vault_id, doc_uuid) DO UPDATE SET \
           snapshot_blob = excluded.snapshot_blob, \
           vv_blob = excluded.vv_blob, \
           updated_at = datetime('now')",
        params![vault_id, doc_uuid, snapshot, vv_blob],
    )?;
    Ok(())
}

pub async fn get_snapshot_with_vv(
    db: &Db,
    vault_id: &str,
    doc_uuid: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, ServerError> {
    let conn = db.lock().await;
    let row = conn
        .query_row(
            "SELECT snapshot_blob, vv_blob FROM documents WHERE vault_id = ? AND doc_uuid = ?",
            params![vault_id, doc_uuid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(row)
}

pub async fn list_docs_with_vv(db: &Db, vault_id: &str) -> Result<Vec<DocEntry>, ServerError> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare(
        "SELECT doc_uuid, updated_at, vv_blob FROM documents WHERE vault_id = ? ORDER BY doc_uuid",
    )?;
    let rows = stmt
        .query_map(params![vault_id], |r| {
            let doc_uuid: String = r.get(0)?;
            let updated_at: String = r.get(1)?;
            let db_vv: Vec<u8> = r.get(2)?;
            Ok((doc_uuid, updated_at, db_vv))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows
        .into_iter()
        .map(|(doc_uuid, updated_at, db_vv)| {
            // Convert from DB binary encoding to JSON bytes (same format as sync_delta)
            let json_vv = match crate::vv_serde::vv_from_db_bytes(&db_vv) {
                Ok(vv) => crate::vv_serde::vv_to_json_bytes(&vv),
                // Never return raw DB bytes as if they were JSON VV. Clients treat this
                // sentinel as unparseable/unknown and take conservative full-sync paths.
                Err(_) => INVALID_VV_SENTINEL_JSON.to_vec(),
            };
            DocEntry {
                doc_uuid,
                updated_at,
                server_vv: json_vv,
            }
        })
        .collect())
}

// ── Tombstone queries ─────────────────────────────────────────────────────────

pub async fn tombstone(
    db: &Db,
    vault_id: &str,
    doc_uuid: &str,
    deleted_by: &str,
) -> Result<(), ServerError> {
    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO tombstones (vault_id, doc_uuid, deleted_by) VALUES (?, ?, ?) \
         ON CONFLICT(vault_id, doc_uuid) DO UPDATE SET \
           deleted_by = excluded.deleted_by, \
           deleted_at = datetime('now')",
        params![vault_id, doc_uuid, deleted_by],
    )?;
    Ok(())
}

pub async fn list_tombstones(db: &Db, vault_id: &str) -> Result<Vec<String>, ServerError> {
    let conn = db.lock().await;
    let mut stmt =
        conn.prepare("SELECT doc_uuid FROM tombstones WHERE vault_id = ? ORDER BY doc_uuid")?;
    let rows = stmt
        .query_map(params![vault_id], |r| r.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(rows)
}

pub async fn is_tombstoned(db: &Db, vault_id: &str, doc_uuid: &str) -> Result<bool, ServerError> {
    let conn = db.lock().await;
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM tombstones WHERE vault_id = ? AND doc_uuid = ?",
            params![vault_id, doc_uuid],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

pub async fn remove_tombstone(db: &Db, vault_id: &str, doc_uuid: &str) -> Result<(), ServerError> {
    let conn = db.lock().await;
    conn.execute(
        "DELETE FROM tombstones WHERE vault_id = ? AND doc_uuid = ?",
        params![vault_id, doc_uuid],
    )?;
    Ok(())
}

pub async fn delete_doc(db: &Db, vault_id: &str, doc_uuid: &str) -> Result<(), ServerError> {
    let conn = db.lock().await;
    conn.execute(
        "DELETE FROM documents WHERE vault_id = ? AND doc_uuid = ?",
        params![vault_id, doc_uuid],
    )?;
    Ok(())
}

/// Atomically delete the document row and insert/update its tombstone.
pub async fn delete_doc_and_tombstone(
    db: &Db,
    vault_id: &str,
    doc_uuid: &str,
    deleted_by: &str,
) -> Result<(), ServerError> {
    let mut conn = db.lock().await;
    let tx = conn.transaction()?;
    tx.execute(
        "DELETE FROM documents WHERE vault_id = ? AND doc_uuid = ?",
        params![vault_id, doc_uuid],
    )?;
    tx.execute(
        "INSERT INTO tombstones (vault_id, doc_uuid, deleted_by) VALUES (?, ?, ?) \
         ON CONFLICT(vault_id, doc_uuid) DO UPDATE SET \
           deleted_by = excluded.deleted_by, \
           deleted_at = datetime('now')",
        params![vault_id, doc_uuid, deleted_by],
    )?;
    tx.commit()?;
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

pub async fn vault_stats(db: &Db, vault_id: &str) -> Result<VaultStats, ServerError> {
    let conn = db.lock().await;
    let (doc_count, total_snapshot_bytes, total_vv_bytes) = conn.query_row(
        "SELECT COUNT(*) as cnt, COALESCE(SUM(LENGTH(snapshot_blob)),0) as snap, \
         COALESCE(SUM(LENGTH(vv_blob)),0) as vv FROM documents WHERE vault_id = ?",
        params![vault_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;

    let mut stmt = conn.prepare(
        "SELECT doc_uuid, LENGTH(snapshot_blob) as size FROM documents \
         WHERE vault_id = ? ORDER BY size DESC LIMIT 10",
    )?;
    let largest_docs = stmt
        .query_map(params![vault_id], |r| {
            Ok(DocSize {
                doc_uuid: r.get(0)?,
                snapshot_bytes: r.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(VaultStats {
        doc_count,
        total_snapshot_bytes,
        total_vv_bytes,
        largest_docs,
    })
}

// ── Peer queries ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub device_name: String,
    pub last_seen_at: String,
}

fn peer_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<PeerInfo> {
    Ok(PeerInfo {
        peer_id: r.get(0)?,
        device_name: r.get(1)?,
        last_seen_at: r.get(2)?,
    })
}

pub async fn upsert_peer(
    db: &Db,
    vault_id: &str,
    peer_id: &str,
    device_name: &str,
) -> Result<(), ServerError> {
    let conn = db.lock().await;
    conn.execute(
        "INSERT INTO peers (vault_id, peer_id, device_name) VALUES (?, ?, ?) \
         ON CONFLICT(vault_id, peer_id) DO UPDATE SET \
           device_name = excluded.device_name, \
           last_seen_at = datetime('now')",
        params![vault_id, peer_id, device_name],
    )?;
    Ok(())
}

pub async fn list_peers(db: &Db, vault_id: &str) -> Result<Vec<PeerInfo>, ServerError> {
    let conn = db.lock().await;
    let mut stmt = conn.prepare(
        "SELECT peer_id, device_name, last_seen_at FROM peers \
         WHERE vault_id = ? ORDER BY last_seen_at DESC",
    )?;
    let peers = stmt
        .query_map(params![vault_id], peer_from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(peers)
}

/// Fetch a single peer by `(vault_id, peer_id)`. Returns `None` if that exact
/// pair is unknown (scoped per vault — the same `peer_id` in another vault is a
/// different peer and is not returned here).
pub async fn get_peer(
    db: &Db,
    vault_id: &str,
    peer_id: &str,
) -> Result<Option<PeerInfo>, ServerError> {
    let conn = db.lock().await;
    let peer = conn
        .query_row(
            "SELECT peer_id, device_name, last_seen_at FROM peers \
             WHERE vault_id = ? AND peer_id = ?",
            params![vault_id, peer_id],
            peer_from_row,
        )
        .optional()?;
    Ok(peer)
}

/// Delete a single peer scoped to its vault. Returns the number of rows
/// affected (0 or 1). Never crosses vault boundaries — a peer that lingers in
/// several vaults must be retired per vault individually.
pub async fn delete_peer(db: &Db, vault_id: &str, peer_id: &str) -> Result<u64, ServerError> {
    let conn = db.lock().await;
    let rows = conn.execute(
        "DELETE FROM peers WHERE vault_id = ? AND peer_id = ?",
        params![vault_id, peer_id],
    )?;
    Ok(rows as u64)
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
    db: &Db,
    vault_id: &str,
    last_seen_at: &str,
) -> Result<i64, ServerError> {
    let conn = db.lock().await;
    let count = conn.query_row(
        "SELECT COUNT(*) AS cnt FROM tombstones \
         WHERE vault_id = ? AND deleted_at >= ?",
        params![vault_id, last_seen_at],
        |r| r.get(0),
    )?;
    Ok(count)
}

pub async fn expire_tombstones(db: &Db, max_age_days: i64) -> Result<u64, ServerError> {
    let conn = db.lock().await;
    let rows = conn.execute(
        "DELETE FROM tombstones
         WHERE deleted_at < datetime('now', '-' || ? || ' days')
           AND NOT EXISTS (
             SELECT 1 FROM peers
             WHERE peers.vault_id = tombstones.vault_id
               AND peers.last_seen_at <= tombstones.deleted_at
           )",
        params![max_age_days],
    )?;
    Ok(rows as u64)
}

/// Remove peers not seen for more than `max_age_days` days.
pub async fn expire_stale_peers(db: &Db, max_age_days: i64) -> Result<u64, ServerError> {
    let conn = db.lock().await;
    let rows = conn.execute(
        "DELETE FROM peers WHERE last_seen_at < datetime('now', '-' || ? || ' days')",
        params![max_age_days],
    )?;
    Ok(rows as u64)
}

/// Run non-blocking SQLite maintenance: truncate the WAL and refresh query
/// planner stats. Deliberately does NOT run `VACUUM` — that takes exclusive
/// locks and would stall the server. Full reclamation is a manual step, see
/// [`run_full_vacuum`].
pub async fn run_maintenance(db: &Db) -> Result<(), ServerError> {
    let conn = db.lock().await;
    // wal_checkpoint returns a row, so it must be queried rather than executed.
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
    conn.execute_batch("PRAGMA optimize")?;
    Ok(())
}

/// Run a full `VACUUM` to reclaim fragmented disk space.
///
/// WARNING: `VACUUM` rewrites the entire database and takes an exclusive lock,
/// blocking all reads and writes for its duration (seconds to minutes on large
/// databases). It is intentionally NOT wired into any automatic task — call it
/// manually only inside a planned maintenance window.
pub async fn run_full_vacuum(db: &Db) -> Result<(), ServerError> {
    let conn = db.lock().await;
    conn.execute_batch("VACUUM")?;
    Ok(())
}
