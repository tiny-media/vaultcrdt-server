mod cli;
mod invites;
mod ws_integration;

use crate::db::Db;
use crate::{AppState, BroadcastEvent, DocLocks, build_router, db};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tokio::sync::broadcast;
use tower::ServiceExt;

async fn test_db() -> Db {
    db::open_db(":memory:").await.expect("open in-memory db")
}

/// Test-only raw SQL against the single connection.
pub(crate) async fn exec(db: &Db, sql: &str) {
    db.lock().await.execute_batch(sql).expect("test sql");
}

pub(crate) async fn scalar<T: rusqlite::types::FromSql>(db: &Db, sql: &str) -> T {
    db.lock()
        .await
        .query_row(sql, [], |r| r.get(0))
        .expect("test scalar")
}

fn test_state(db: Db) -> AppState {
    let (broadcast_tx, _) = broadcast::channel::<BroadcastEvent>(16);
    AppState {
        db,
        jwt_secret: "test-secret".to_string(),
        admin_token: "test-admin-token".to_string(),
        trust_proxy: false,
        auth_rate_limiter: std::sync::Arc::new(crate::auth::AuthRateLimiter::default()),
        broadcast_tx,
        server_epoch: "test-epoch".to_string(),
        connections: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        doc_locks: DocLocks::default(),
    }
}

#[test]
fn test_ws_error_messages_are_generic() {
    use crate::errors::ServerError;
    let sync = ServerError::Sync("loro import client delta: XYZZY".into());
    assert!(!sync.client_facing().1.contains("XYZZY"));
    assert_eq!(
        ServerError::Db(rusqlite::Error::QueryReturnedNoRows)
            .client_facing()
            .0,
        "storage_error"
    );
    for error in [
        sync,
        ServerError::BadFrame("msgpack XYZZY".into()),
        ServerError::Db(rusqlite::Error::QueryReturnedNoRows),
        ServerError::Auth("argon XYZZY".into()),
    ] {
        for internal in ["loro", "msgpack", "sqlite", "SQL", "argon"] {
            assert!(!error.client_facing().1.contains(internal));
        }
    }
}

#[tokio::test]
async fn test_auth_json_rejection_is_generic() {
    let app = build_router(test_state(test_db().await));
    let response = app
        .oneshot(auth_request(
            r#"{"vault_id":"v","api_key":["XYZZY-INJECTED"]}"#,
            1234,
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), b"invalid JSON body");
    assert!(!String::from_utf8_lossy(&body).contains("XYZZY-INJECTED"));
}

// ── Health endpoint ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_health_endpoint() {
    let state = test_state(test_db().await);
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["protocol_version"], 1);
    assert!(json.get("version").is_some());
    assert!(json.get("server_epoch").is_some());
}

// ── Debug connections endpoint ─────────────────────────────────────────────

#[tokio::test]
async fn test_debug_connections_endpoint() {
    let state = test_state(test_db().await);
    let app = build_router(state);

    // Without admin token → 401
    let resp_unauth = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/debug/connections")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_unauth.status(), StatusCode::UNAUTHORIZED);

    // With admin token → 200
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/debug/connections")
                .header("Authorization", "Bearer test-admin-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["count"], 0);
    assert!(json["connections"].as_array().unwrap().is_empty());
}

// ── JWT sign → verify roundtrip ────────────────────────────────────────────

#[test]
fn test_jwt_roundtrip() {
    use crate::auth;

    let token = auth::jwt_sign("my-vault", "secret123").unwrap();
    let vault_id = auth::jwt_verify(&token, "secret123").unwrap();
    assert_eq!(vault_id, "my-vault");
}

#[test]
fn test_jwt_wrong_secret() {
    use crate::auth;

    let token = auth::jwt_sign("my-vault", "secret123").unwrap();
    let result = auth::jwt_verify(&token, "wrong-secret");
    assert!(result.is_err());
}

// ── Vault create + verify ───────────────────────────────────────────────────

#[tokio::test]
async fn test_vault_create_and_verify() {
    let db = test_db().await;

    assert!(db::create_vault(&db, "vault-unit", "my-key").await.unwrap());

    assert!(db::verify_vault(&db, "vault-unit", "my-key").await.unwrap());
    assert!(
        !db::verify_vault(&db, "vault-unit", "wrong-key")
            .await
            .unwrap()
    );
    assert!(
        !db::verify_vault(&db, "no-such-vault", "my-key")
            .await
            .unwrap()
    );

    // INSERT OR IGNORE — does not overwrite
    assert!(
        !db::create_vault(&db, "vault-unit", "different-key")
            .await
            .unwrap()
    );
    assert!(db::verify_vault(&db, "vault-unit", "my-key").await.unwrap());
}

// ── Argon2 hashing + lazy migration ─────────────────────────────────────────

#[tokio::test]
async fn test_create_vault_stores_argon2_hash() {
    let db = test_db().await;
    db::create_vault(&db, "v-hash", "secret-key").await.unwrap();

    let stored: String = scalar(&db, "SELECT api_key FROM vaults WHERE vault_id = 'v-hash'").await;
    assert!(
        stored.starts_with("$argon2id$"),
        "expected PHC hash, got: {stored}"
    );
    assert_ne!(stored, "secret-key");
}

#[test]
fn test_verify_secret_accepts_fixture_from_argon2_0_5() {
    let fixture = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$k4DNdhqUyq4QNuG9R72afZRqpYYCYZnjmPf8LNxJV2c";

    assert!(db::verify_secret("fixture-password", fixture));
    assert!(!db::verify_secret("wrong-password", fixture));
}

#[tokio::test]
async fn test_verify_vault_with_legacy_plaintext_migrates() {
    let db = test_db().await;

    // Simulate legacy entry by inserting plaintext directly (bypassing create_vault).
    exec(
        &db,
        "INSERT INTO vaults (vault_id, api_key) VALUES ('v-legacy', 'legacy-plain')",
    )
    .await;

    // Verify with correct legacy key → succeeds.
    assert!(
        db::verify_vault(&db, "v-legacy", "legacy-plain")
            .await
            .unwrap()
    );

    // Stored value is now an Argon2id PHC hash.
    let stored: String = scalar(
        &db,
        "SELECT api_key FROM vaults WHERE vault_id = 'v-legacy'",
    )
    .await;
    assert!(
        stored.starts_with("$argon2id$"),
        "expected migrated PHC hash, got: {stored}"
    );

    // Subsequent verify still works against the migrated hash.
    assert!(
        db::verify_vault(&db, "v-legacy", "legacy-plain")
            .await
            .unwrap()
    );
    assert!(!db::verify_vault(&db, "v-legacy", "wrong").await.unwrap());
}

// ── Snapshot store + retrieve ───────────────────────────────────────────────

#[tokio::test]
async fn test_snapshot_store_and_retrieve() {
    let db = test_db().await;

    assert!(
        db::get_snapshot_with_vv(&db, "v", "d")
            .await
            .unwrap()
            .is_none()
    );

    db::store_snapshot_with_vv(&db, "v", "d", b"snap", b"vv")
        .await
        .unwrap();
    let (snap, vv) = db::get_snapshot_with_vv(&db, "v", "d")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snap, b"snap");
    assert_eq!(vv, b"vv");

    // Overwrite
    db::store_snapshot_with_vv(&db, "v", "d", b"snap2", b"vv2")
        .await
        .unwrap();
    let (snap2, vv2) = db::get_snapshot_with_vv(&db, "v", "d")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snap2, b"snap2");
    assert_eq!(vv2, b"vv2");
}

// ── List docs with VV ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_list_docs_with_vv() {
    let db = test_db().await;
    let mut vv_a = loro::VersionVector::new();
    vv_a.insert(42, 7);
    let mut vv_b = loro::VersionVector::new();
    vv_b.insert(99, 3);

    db::store_snapshot_with_vv(
        &db,
        "v",
        "doc-a",
        b"a",
        &crate::vv_serde::vv_to_db_bytes(&vv_a),
    )
    .await
    .unwrap();
    db::store_snapshot_with_vv(
        &db,
        "v",
        "doc-b",
        b"b",
        &crate::vv_serde::vv_to_db_bytes(&vv_b),
    )
    .await
    .unwrap();

    let docs = db::list_docs_with_vv(&db, "v").await.unwrap();
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[0].doc_uuid, "doc-a");
    assert_eq!(docs[1].doc_uuid, "doc-b");
    assert_eq!(docs[0].server_vv, br#"{"42":7}"#);
}

#[tokio::test]
async fn test_list_docs_with_vv_never_returns_raw_corrupt_db_bytes() {
    let db = test_db().await;

    db::store_snapshot_with_vv(&db, "v", "doc-corrupt", b"a", b"not-valid-loro-vv")
        .await
        .unwrap();

    let docs = db::list_docs_with_vv(&db, "v").await.unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].doc_uuid, "doc-corrupt");
    assert_eq!(docs[0].server_vv, b"__vaultcrdt_invalid_vv__");
    assert_ne!(docs[0].server_vv, b"not-valid-loro-vv");
}

// ── Tombstone lifecycle ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_tombstone_lifecycle() {
    let db = test_db().await;

    db::tombstone(&db, "v", "doc-dead", "peer-1").await.unwrap();
    let tombs = db::list_tombstones(&db, "v").await.unwrap();
    assert_eq!(tombs, vec!["doc-dead"]);

    // Idempotent re-tombstone
    db::tombstone(&db, "v", "doc-dead", "peer-2").await.unwrap();
    assert_eq!(db::list_tombstones(&db, "v").await.unwrap().len(), 1);

    // Remove
    db::remove_tombstone(&db, "v", "doc-dead").await.unwrap();
    assert!(db::list_tombstones(&db, "v").await.unwrap().is_empty());

    // Remove non-existent = no-op
    db::remove_tombstone(&db, "v", "doc-dead").await.unwrap();
}

// ── is_tombstoned ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_is_tombstoned() {
    let db = test_db().await;

    assert!(!db::is_tombstoned(&db, "v", "doc-x").await.unwrap());

    db::tombstone(&db, "v", "doc-x", "peer-1").await.unwrap();
    assert!(db::is_tombstoned(&db, "v", "doc-x").await.unwrap());

    // Vault isolation
    assert!(
        !db::is_tombstoned(&db, "other-vault", "doc-x")
            .await
            .unwrap()
    );

    db::remove_tombstone(&db, "v", "doc-x").await.unwrap();
    assert!(!db::is_tombstoned(&db, "v", "doc-x").await.unwrap());
}

// ── Delete doc ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_delete_doc() {
    let db = test_db().await;

    db::store_snapshot_with_vv(&db, "v", "d", b"data", b"vv")
        .await
        .unwrap();
    assert!(
        db::get_snapshot_with_vv(&db, "v", "d")
            .await
            .unwrap()
            .is_some()
    );

    db::delete_doc(&db, "v", "d").await.unwrap();
    assert!(
        db::get_snapshot_with_vv(&db, "v", "d")
            .await
            .unwrap()
            .is_none()
    );

    // Delete non-existent = no-op
    db::delete_doc(&db, "v", "d").await.unwrap();
}

// ── Expire tombstones ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_expire_tombstones() {
    let db = test_db().await;

    db::tombstone(&db, "v", "old-doc", "peer").await.unwrap();
    exec(
        &db,
        "UPDATE tombstones SET deleted_at = datetime('now', '-10 days') WHERE doc_uuid = 'old-doc'",
    )
    .await;

    db::tombstone(&db, "v", "new-doc", "peer").await.unwrap();

    let expired = db::expire_tombstones(&db, 7).await.unwrap();
    assert_eq!(expired, 1);

    let remaining = db::list_tombstones(&db, "v").await.unwrap();
    assert_eq!(remaining, vec!["new-doc"]);
}

#[tokio::test]
async fn test_expire_tombstones_waits_for_peer_that_has_not_seen_delete() {
    let db = test_db().await;

    db::tombstone(&db, "v", "offline-doc", "peer-del")
        .await
        .unwrap();
    exec(&db, "UPDATE tombstones SET deleted_at = datetime('now', '-100 days') WHERE doc_uuid = 'offline-doc'").await;

    db::upsert_peer(&db, "v", "old-tablet", "Old Tablet")
        .await
        .unwrap();
    exec(
        &db,
        "UPDATE peers SET last_seen_at = datetime('now', '-200 days') WHERE peer_id = 'old-tablet'",
    )
    .await;

    let expired = db::expire_tombstones(&db, 7).await.unwrap();
    assert_eq!(expired, 0);
    assert_eq!(
        db::list_tombstones(&db, "v").await.unwrap(),
        vec!["offline-doc"]
    );
}

#[tokio::test]
async fn test_expire_tombstones_after_all_peers_have_seen_delete() {
    let db = test_db().await;

    db::tombstone(&db, "v", "seen-doc", "peer-del")
        .await
        .unwrap();
    exec(&db, "UPDATE tombstones SET deleted_at = datetime('now', '-100 days') WHERE doc_uuid = 'seen-doc'").await;

    db::upsert_peer(&db, "v", "seen-laptop", "Seen Laptop")
        .await
        .unwrap();
    exec(
        &db,
        "UPDATE peers SET last_seen_at = datetime('now', '-50 days') WHERE peer_id = 'seen-laptop'",
    )
    .await;

    let expired = db::expire_tombstones(&db, 7).await.unwrap();
    assert_eq!(expired, 1);
    assert!(db::list_tombstones(&db, "v").await.unwrap().is_empty());
}

#[tokio::test]
async fn test_expire_tombstones_after_stale_peer_is_forgotten() {
    let db = test_db().await;

    db::tombstone(&db, "v", "forgotten-doc", "peer-del")
        .await
        .unwrap();
    exec(&db, "UPDATE tombstones SET deleted_at = datetime('now', '-100 days') WHERE doc_uuid = 'forgotten-doc'").await;

    db::upsert_peer(&db, "v", "retired-phone", "Retired Phone")
        .await
        .unwrap();
    exec(&db, "UPDATE peers SET last_seen_at = datetime('now', '-200 days') WHERE peer_id = 'retired-phone'").await;

    assert_eq!(db::expire_tombstones(&db, 7).await.unwrap(), 0);
    assert_eq!(db::expire_stale_peers(&db, 180).await.unwrap(), 1);
    assert_eq!(db::expire_tombstones(&db, 7).await.unwrap(), 1);
    assert!(db::list_tombstones(&db, "v").await.unwrap().is_empty());
}

// ── Migration adoption from the old sqlx runner ─────────────────────────────

#[tokio::test]
async fn test_open_db_adopts_existing_sqlx_migration_state() {
    // A production DB written by the sqlx runner: schema applied, migration
    // bookkeeping in _sqlx_migrations, user_version still 0.
    let path = std::env::temp_dir().join(format!("vault-sqlx-{}.db", uuid::Uuid::new_v4()));
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        for sql in [
            include_str!("../../migrations/001_init.sql"),
            include_str!("../../migrations/002_peers.sql"),
            include_str!("../../migrations/003_invites_device_keys.sql"),
        ] {
            conn.execute_batch(sql).unwrap();
        }
        conn.execute_batch(
            "CREATE TABLE _sqlx_migrations (version BIGINT PRIMARY KEY, description TEXT NOT NULL);
             INSERT INTO _sqlx_migrations VALUES (1, 'init'), (2, 'peers'), (3, 'invites');
             INSERT INTO vaults (vault_id, api_key) VALUES ('legacy-vault', 'k');",
        )
        .unwrap();
        assert_eq!(
            conn.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
                .unwrap(),
            0
        );
    }

    let db = db::open_db(path.to_str().unwrap()).await.unwrap();
    assert_eq!(scalar::<i64>(&db, "PRAGMA user_version").await, 3);
    assert_eq!(
        scalar::<i64>(
            &db,
            "SELECT count(*) FROM sqlite_master WHERE name = '_sqlx_migrations'"
        )
        .await,
        0
    );
    // Existing data survives the adoption untouched.
    assert!(db::vault_exists(&db, "legacy-vault").await.unwrap());
    drop(db);
    let _ = std::fs::remove_file(&path);
}

// ── DB maintenance ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_run_maintenance_succeeds() {
    let db = test_db().await;
    // wal_checkpoint(TRUNCATE) + optimize must not error, even on :memory:.
    db::run_maintenance(&db).await.unwrap();
}

#[tokio::test]
async fn test_run_full_vacuum_succeeds() {
    let db = test_db().await;
    db::run_full_vacuum(&db).await.unwrap();
}

// ── Vault isolation ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_vault_isolation() {
    let db = test_db().await;

    db::create_vault(&db, "vault-A", "key-a").await.unwrap();
    db::create_vault(&db, "vault-B", "key-b").await.unwrap();

    db::store_snapshot_with_vv(&db, "vault-A", "shared-uuid", b"data-a", b"vv")
        .await
        .unwrap();

    assert!(
        db::list_docs_with_vv(&db, "vault-B")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db::list_docs_with_vv(&db, "vault-A").await.unwrap().len(),
        1
    );

    db::tombstone(&db, "vault-A", "shared-uuid", "p")
        .await
        .unwrap();
    assert!(
        db::list_tombstones(&db, "vault-B")
            .await
            .unwrap()
            .is_empty()
    );
}

// ── Auth endpoint — admin token protection ──────────────────────────────────

#[tokio::test]
async fn test_auth_requires_admin_token() {
    let state = test_state(test_db().await);
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        "127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
    ));

    // No admin token → 401
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"vault_id":"new-vault","api_key":"key1"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Wrong admin token → 401
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"vault_id":"new-vault","api_key":"key1","admin_token":"wrong"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Correct admin token → 200
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"vault_id":"new-vault","api_key":"key1","admin_token":"test-admin-token"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Existing vault — auth without admin token
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"vault_id":"new-vault","api_key":"key1"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Existing vault — wrong api_key → 401
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"vault_id":"new-vault","api_key":"wrong-key"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn test_constant_time_eq() {
    use crate::auth::constant_time_eq;
    assert!(constant_time_eq("token", "token"));
    assert!(constant_time_eq("", ""));
    assert!(!constant_time_eq("token", "taken"));
    assert!(!constant_time_eq("token", "tokens"));
    assert!(!constant_time_eq("", "x"));
    assert!(!constant_time_eq("x", ""));
    assert!(!constant_time_eq("a", "a\0"));
    assert!(!constant_time_eq("", &"\0".repeat(256)));
}

#[tokio::test]
async fn test_auth_rate_limiter() {
    let limiter = crate::auth::AuthRateLimiter::default();
    for _ in 0..10 {
        assert!(limiter.check("a", 100).await);
    }
    assert!(!limiter.check("a", 100).await);
    assert!(limiter.check("b", 100).await);
    assert!(!limiter.check("a", 159).await);
    assert!(limiter.check("a", 160).await);
    assert!(limiter.check("b", 160).await);
}

fn auth_request(body: &str, port: u16, headers: &[(&str, &str)]) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/auth/verify")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))))
        .header("Content-Type", "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(Body::from(body.to_owned())).unwrap()
}

#[tokio::test]
async fn test_auth_verify_rate_limit_keyed_by_socket_and_cf_ip() {
    let db = test_db().await;
    let mut state = test_state(db);
    state.trust_proxy = true;
    let app = build_router(state);
    // 1. trust_proxy on, no CF header → socket IP is the key (ports ignored,
    //    XFF is NOT a key: spoofing it must not buy new buckets).
    for n in 0..11 {
        let resp = app
            .clone()
            .oneshot(auth_request(
                r#"{"vault_id":"INVALID","api_key":"wrong"}"#,
                1000 + n,
                &[("X-Forwarded-For", &format!("198.51.100.{}", n))],
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            if n < 10 {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
    // 2. Malformed JSON is still rate limited before parsing (429, not 400).
    let resp = app
        .clone()
        .oneshot(auth_request("{", 2000, &[]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json, serde_json::json!({"error": "too many requests"}));
    // 3. trust_proxy on + CF-Connecting-IP → each value its own bucket.
    for ip in ["203.0.113.1", "203.0.113.2"] {
        let resp = app
            .clone()
            .oneshot(auth_request(
                r#"{"vault_id":"INVALID","api_key":"wrong"}"#,
                3000,
                &[("CF-Connecting-IP", ip)],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn test_auth_verify_rate_limit_ignores_headers_without_trust() {
    let app = build_router(test_state(test_db().await));
    for n in 0..11 {
        let resp = app
            .clone()
            .oneshot(auth_request(
                r#"{"vault_id":"INVALID","api_key":"wrong"}"#,
                1000 + n,
                &[
                    ("CF-Connecting-IP", &format!("203.0.113.{}", n)),
                    ("X-Forwarded-For", &format!("198.51.100.{}", n)),
                ],
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            if n < 10 {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
}

#[tokio::test]
async fn test_auth_verify_existing_vault_requires_correct_key() {
    let db = test_db().await;
    assert!(db::create_vault(&db, "existing", "correct").await.unwrap());
    let app = build_router(test_state(db));
    for key in ["wrong", "correct"] {
        let body = serde_json::json!({"vault_id": "existing", "api_key": key, "admin_token": "test-admin-token"}).to_string();
        let resp = app
            .clone()
            .oneshot(auth_request(&body, 1234, &[]))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            if key == "wrong" {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::OK
            }
        );
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if key == "wrong" {
            assert_eq!(json["error"], "auth error: Authentication failed");
        } else {
            assert_eq!(
                crate::auth::jwt_verify(json["token"].as_str().unwrap(), "test-secret").unwrap(),
                "existing"
            );
        }
    }
}

#[tokio::test]
async fn test_auth_verify_lost_insert_race_verifies_winner_key() {
    let db = test_db().await;
    assert!(db::create_vault(&db, "winner", "correct").await.unwrap());
    // Deterministically insert the winner after vault_exists but before the
    // handler's INSERT, then report zero rows for the losing INSERT.
    exec(
        &db,
        "CREATE TRIGGER competing_registration BEFORE INSERT ON vaults
        WHEN NEW.vault_id != 'winner'
        BEGIN
            INSERT INTO vaults (vault_id, api_key)
                SELECT NEW.vault_id, api_key FROM vaults WHERE vault_id = 'winner';
            SELECT RAISE(IGNORE);
        END",
    )
    .await;
    let app = build_router(test_state(db));
    for key in ["wrong", "correct"] {
        let body =
            serde_json::json!({"vault_id": key, "api_key": key, "admin_token": "test-admin-token"})
                .to_string();
        let resp = app
            .clone()
            .oneshot(auth_request(&body, 1234, &[]))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            if key == "wrong" {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::OK
            }
        );
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if key == "wrong" {
            assert_eq!(json["error"], "auth error: Authentication failed");
        } else {
            assert_eq!(
                crate::auth::jwt_verify(json["token"].as_str().unwrap(), "test-secret").unwrap(),
                "correct"
            );
        }
    }
}

// ── Vault stats endpoint ────────────────────────────────────────────────────

#[tokio::test]
async fn test_vault_stats() {
    let db = test_db().await;

    db::create_vault(&db, "stats-vault", "key").await.unwrap();
    db::store_snapshot_with_vv(&db, "stats-vault", "d1", b"hello", b"vv1")
        .await
        .unwrap();
    db::store_snapshot_with_vv(&db, "stats-vault", "d2", b"world!!", b"vv2")
        .await
        .unwrap();

    let stats = db::vault_stats(&db, "stats-vault").await.unwrap();
    assert_eq!(stats.doc_count, 2);
    assert_eq!(stats.total_snapshot_bytes, 12); // "hello" (5) + "world!!" (7)
    assert_eq!(stats.largest_docs.len(), 2);
    assert_eq!(stats.largest_docs[0].doc_uuid, "d2"); // largest first
}

// ── Vault stats HTTP endpoint ───────────────────────────────────────────────

#[tokio::test]
async fn test_vault_stats_http_endpoint() {
    use crate::auth;

    let db = test_db().await;
    let state = test_state(db.clone());

    db::create_vault(&db, "stats-vault", "key").await.unwrap();
    db::store_snapshot_with_vv(&db, "stats-vault", "d1", b"hello", b"vv1")
        .await
        .unwrap();

    let token = auth::jwt_sign("stats-vault", "test-secret").unwrap();
    let app = build_router(state);

    // With valid JWT → 200
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/debug/vault-stats")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["doc_count"], 1);

    // Without JWT → 401
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/debug/vault-stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── Peer retire endpoint (A2.5) ─────────────────────────────────────────────

#[tokio::test]
async fn test_retire_peer_wrong_device_name_returns_409() {
    let db = test_db().await;
    db::upsert_peer(&db, "v", "peer-1", "My Laptop")
        .await
        .unwrap();
    let app = build_router(test_state(db.clone()));

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/vault/peers/peer-1?vault_id=v&device_name=Wrong%20Name")
                .header("Authorization", "Bearer test-admin-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let body = axum::body::to_bytes(resp.into_body(), 2048).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["device_name"], "My Laptop");
    assert!(json.get("last_seen_at").is_some());

    // Peer must still exist (nothing deleted on mismatch).
    assert!(db::get_peer(&db, "v", "peer-1").await.unwrap().is_some());
}

#[tokio::test]
async fn test_retire_peer_correct_device_name_returns_200_and_removes_peer() {
    let db = test_db().await;
    db::upsert_peer(&db, "v", "peer-1", "My Laptop")
        .await
        .unwrap();
    // Push last_seen_at into the past so a later tombstone is "blocked" by it.
    exec(
        &db,
        "UPDATE peers SET last_seen_at = datetime('now', '-10 days') WHERE peer_id = 'peer-1'",
    )
    .await;
    // A tombstone deleted after the peer's last_seen_at → blocked by this peer.
    db::tombstone(&db, "v", "dead-doc", "peer-del")
        .await
        .unwrap();

    let app = build_router(test_state(db.clone()));

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/vault/peers/peer-1?vault_id=v&device_name=My%20Laptop")
                .header("Authorization", "Bearer test-admin-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 2048).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["retired_peer"]["peer_id"], "peer-1");
    assert_eq!(json["retired_peer"]["device_name"], "My Laptop");
    assert_eq!(json["tombstones_possibly_freed"], 1);

    // Peer is gone from the vault's peer list.
    let peers = db::list_peers(&db, "v").await.unwrap();
    assert!(peers.iter().all(|p| p.peer_id != "peer-1"));
}

#[tokio::test]
async fn test_retire_peer_missing_or_wrong_admin_token_returns_401() {
    let db = test_db().await;
    db::upsert_peer(&db, "v", "peer-1", "My Laptop")
        .await
        .unwrap();
    let app = build_router(test_state(db.clone()));

    // Missing admin token → 401.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/vault/peers/peer-1?vault_id=v&device_name=My%20Laptop")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Wrong admin token → 401.
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/vault/peers/peer-1?vault_id=v&device_name=My%20Laptop")
                .header("Authorization", "Bearer wrong-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Peer untouched.
    assert!(db::get_peer(&db, "v", "peer-1").await.unwrap().is_some());
}

#[tokio::test]
async fn test_retire_peer_unknown_pair_returns_404() {
    let db = test_db().await;
    let app = build_router(test_state(db.clone()));

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/vault/peers/nope?vault_id=v&device_name=Whatever")
                .header("Authorization", "Bearer test-admin-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_retire_peer_missing_vault_id_query_returns_400() {
    let db = test_db().await;
    db::upsert_peer(&db, "v", "peer-1", "My Laptop")
        .await
        .unwrap();
    let app = build_router(test_state(db.clone()));

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/vault/peers/peer-1?device_name=My%20Laptop")
                .header("Authorization", "Bearer test-admin-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Peer untouched.
    assert!(db::get_peer(&db, "v", "peer-1").await.unwrap().is_some());
}

// ── Delete → recreate tombstone replacement ────────────────────────────────

#[tokio::test]
async fn test_doc_create_replace_tombstone_removes_tombstone_and_stores_doc() {
    use crate::handlers::process_message;
    use crate::ws::msg;
    use loro::{ExportMode, LoroDoc};

    let db = test_db().await;
    db::create_vault(&db, "v", "k").await.unwrap();
    let doc_locks = DocLocks::default();
    db::tombstone(&db, "v", "same.md", "peer-del")
        .await
        .unwrap();

    let doc = LoroDoc::new();
    doc.get_text("text").insert(0, "recreated").unwrap();
    let snapshot = doc.export(ExportMode::Snapshot).unwrap();

    let create_msg = rmp_serde::to_vec_named(&msg::ClientMsg::DocCreate {
        doc_uuid: "same.md".into(),
        snapshot,
        peer_id: "peer-new".into(),
        replace_tombstone: true,
    })
    .unwrap();

    let (resp, broadcast) = process_message(&create_msg, &db, "v", 1, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::Ack));
    assert!(broadcast.is_some());
    assert!(!db::is_tombstoned(&db, "v", "same.md").await.unwrap());
    assert!(
        db::get_snapshot_with_vv(&db, "v", "same.md")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_doc_create_and_sync_push_without_replace_still_refuse_tombstone() {
    use crate::handlers::process_message;
    use crate::ws::msg;
    use loro::{ExportMode, LoroDoc};

    let db = test_db().await;
    db::create_vault(&db, "v", "k").await.unwrap();
    let doc_locks = DocLocks::default();
    db::tombstone(&db, "v", "dead.md", "peer-del")
        .await
        .unwrap();

    let doc = LoroDoc::new();
    doc.get_text("text").insert(0, "stale").unwrap();
    let snapshot = doc.export(ExportMode::Snapshot).unwrap();

    let blind_create = rmp_serde::to_vec_named(&msg::ClientMsg::DocCreate {
        doc_uuid: "dead.md".into(),
        snapshot: snapshot.clone(),
        peer_id: "peer-stale".into(),
        replace_tombstone: false,
    })
    .unwrap();
    let (resp, broadcast) = process_message(&blind_create, &db, "v", 1, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::DocTombstoned { .. }));
    assert!(broadcast.is_none());
    assert!(db::is_tombstoned(&db, "v", "dead.md").await.unwrap());
    assert!(
        db::get_snapshot_with_vv(&db, "v", "dead.md")
            .await
            .unwrap()
            .is_none()
    );

    let stale_push = rmp_serde::to_vec_named(&msg::ClientMsg::SyncPush {
        doc_uuid: "dead.md".into(),
        delta: snapshot,
        peer_id: "peer-stale".into(),
    })
    .unwrap();
    let (resp, broadcast) = process_message(&stale_push, &db, "v", 2, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::DocTombstoned { .. }));
    assert!(broadcast.is_none());
    assert!(db::is_tombstoned(&db, "v", "dead.md").await.unwrap());
}

// ── DocDelete / SyncPush race (regression for TOCTOU against tombstone) ─────

#[tokio::test]
async fn test_doc_delete_vs_sync_push_race() {
    use crate::handlers::process_message;
    use crate::ws::msg;
    use loro::{ExportMode, LoroDoc};

    let db = test_db().await;
    db::create_vault(&db, "v", "k").await.unwrap();
    let doc_locks = DocLocks::default();

    // Run many iterations to shake out the race: without the lock on
    // DocDelete, a concurrent sync_push can finish *after* delete_doc +
    // tombstone and leave both an active doc row and a tombstone row
    // for the same (vault, doc).
    for i in 0..50 {
        let doc_uuid = format!("race-{i}.md");

        // Seed: create a document via DocCreate so there is something to push against.
        let seed = LoroDoc::new();
        seed.get_text("text").insert(0, "seed").unwrap();
        let seed_snapshot = seed.export(ExportMode::Snapshot).unwrap();
        let create_msg = rmp_serde::to_vec_named(&msg::ClientMsg::DocCreate {
            doc_uuid: doc_uuid.clone(),
            snapshot: seed_snapshot.clone(),
            peer_id: "peer-seed".into(),
            replace_tombstone: false,
        })
        .unwrap();
        let (resp, _) = process_message(&create_msg, &db, "v", 1, &doc_locks).await;
        assert!(matches!(resp, msg::ServerMsg::Ack), "seed create failed");

        // Build a fresh delta from the seed state representing a concurrent edit.
        let client = LoroDoc::new();
        client.import(&seed_snapshot).unwrap();
        let base_vv = client.oplog_vv();
        client.get_text("text").insert(4, " + edit").unwrap();
        let delta = client.export(ExportMode::updates(&base_vv)).unwrap();

        let push_bytes = rmp_serde::to_vec_named(&msg::ClientMsg::SyncPush {
            doc_uuid: doc_uuid.clone(),
            delta,
            peer_id: "peer-push".into(),
        })
        .unwrap();
        let delete_bytes = rmp_serde::to_vec_named(&msg::ClientMsg::DocDelete {
            doc_uuid: doc_uuid.clone(),
            peer_id: "peer-del".into(),
        })
        .unwrap();

        let db_a = db.clone();
        let locks_a = doc_locks.clone();
        let db_b = db.clone();
        let locks_b = doc_locks.clone();

        let push_task =
            tokio::spawn(
                async move { process_message(&push_bytes, &db_a, "v", 2, &locks_a).await },
            );
        let delete_task =
            tokio::spawn(
                async move { process_message(&delete_bytes, &db_b, "v", 3, &locks_b).await },
            );
        let _ = push_task.await.unwrap();
        let _ = delete_task.await.unwrap();

        // Invariant: after both operations, we never have an active doc row
        // AND a tombstone row for the same doc at the same time.
        let has_doc = db::get_snapshot_with_vv(&db, "v", &doc_uuid)
            .await
            .unwrap()
            .is_some();
        let tombstoned = db::is_tombstoned(&db, "v", &doc_uuid).await.unwrap();
        assert!(
            !(has_doc && tombstoned),
            "iter {i}: doc={doc_uuid} simultaneously active and tombstoned"
        );
    }
}

// ── K1: DocLocks eviction ───────────────────────────────────────────────────

#[test]
fn test_doc_locks_evict_unused_entries() {
    let locks = DocLocks::default();
    {
        let _a = locks.get("v:a");
        let _b = locks.get("v:b");
        let _c = locks.get("v:c");
        assert!(locks.len() >= 3, "held locks must stay in the map");
    }
    // Dropped Arcs are unused (strong_count == 1 in the map) — next get evicts.
    let _d = locks.get("v:d");
    assert_eq!(
        locks.len(),
        1,
        "unused lock entries must be evicted; map must not grow monotonically"
    );
}

// ── K2: Jwt → 401 unauthorized ──────────────────────────────────────────────

#[tokio::test]
async fn test_jwt_error_maps_to_401_unauthorized() {
    use axum::response::IntoResponse;
    use jsonwebtoken::{DecodingKey, Validation, decode};

    // Force a Jwt error via decode of garbage
    let err = decode::<serde_json::Value>(
        "not.a.jwt",
        &DecodingKey::from_secret(b"secret"),
        &Validation::default(),
    )
    .expect_err("garbage jwt must fail");
    let resp = crate::errors::ServerError::Jwt(err).into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "unauthorized");
}

#[tokio::test]
async fn test_doc_create_disjoint_history_refused() {
    use crate::{handlers::process_message, ws::msg};
    use loro::{ExportMode, LoroDoc};

    let db = test_db().await;
    let doc_locks = DocLocks::default();
    let a = LoroDoc::new();
    a.set_peer_id(1).unwrap();
    a.get_text("text").insert(0, "server text").unwrap();
    let create = rmp_serde::to_vec_named(&msg::ClientMsg::DocCreate {
        doc_uuid: "c.md".into(),
        snapshot: a.export(ExportMode::Snapshot).unwrap(),
        peer_id: "1".into(),
        replace_tombstone: false,
    })
    .unwrap();
    let (resp, _) = process_message(&create, &db, "v", 1, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::Ack));
    let before = db::get_snapshot_with_vv(&db, "v", "c.md")
        .await
        .unwrap()
        .unwrap();

    let b = LoroDoc::new();
    b.set_peer_id(2).unwrap();
    b.get_text("text").insert(0, "local text").unwrap();
    let create = rmp_serde::to_vec_named(&msg::ClientMsg::DocCreate {
        doc_uuid: "c.md".into(),
        snapshot: b.export(ExportMode::Snapshot).unwrap(),
        peer_id: "2".into(),
        replace_tombstone: false,
    })
    .unwrap();
    let (resp, broadcast) = process_message(&create, &db, "v", 2, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::CreateConflict { .. }));
    assert!(broadcast.is_none());
    let wire: serde_json::Value =
        rmp_serde::from_slice(&rmp_serde::to_vec_named(&resp).unwrap()).unwrap();
    assert_eq!(
        wire,
        serde_json::json!({"type": "create_conflict", "doc_uuid": "c.md"})
    );
    let after = db::get_snapshot_with_vv(&db, "v", "c.md")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after, before);
    let stored = LoroDoc::new();
    stored.import(&after.0).unwrap();
    assert_eq!(stored.get_text("text").to_string(), "server text");
}

#[tokio::test]
async fn test_sync_push_disjoint_history_refused() {
    use crate::{handlers::process_message, ws::msg};
    use loro::{ExportMode, LoroDoc, VersionVector};

    let db = test_db().await;
    let doc_locks = DocLocks::default();
    let a = LoroDoc::new();
    a.set_peer_id(1).unwrap();
    a.get_text("text").insert(0, "server text").unwrap();
    let create = rmp_serde::to_vec_named(&msg::ClientMsg::DocCreate {
        doc_uuid: "c.md".into(),
        snapshot: a.export(ExportMode::Snapshot).unwrap(),
        peer_id: "1".into(),
        replace_tombstone: false,
    })
    .unwrap();
    let (resp, _) = process_message(&create, &db, "v", 1, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::Ack));
    let before = db::get_snapshot_with_vv(&db, "v", "c.md")
        .await
        .unwrap()
        .unwrap();

    let b = LoroDoc::new();
    b.set_peer_id(2).unwrap();
    b.get_text("text").insert(0, "local text").unwrap();
    let push = rmp_serde::to_vec_named(&msg::ClientMsg::SyncPush {
        doc_uuid: "c.md".into(),
        delta: b
            .export(ExportMode::updates(&VersionVector::new()))
            .unwrap(),
        peer_id: "2".into(),
    })
    .unwrap();
    let (resp, broadcast) = process_message(&push, &db, "v", 2, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::CreateConflict { .. }));
    assert!(broadcast.is_none());
    let wire: serde_json::Value =
        rmp_serde::from_slice(&rmp_serde::to_vec_named(&resp).unwrap()).unwrap();
    assert_eq!(
        wire,
        serde_json::json!({"type": "create_conflict", "doc_uuid": "c.md"})
    );
    let after = db::get_snapshot_with_vv(&db, "v", "c.md")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after, before);
    let stored = LoroDoc::new();
    stored.import(&after.0).unwrap();
    assert_eq!(stored.get_text("text").to_string(), "server text");
}

#[tokio::test]
async fn test_sync_push_after_adopting_snapshot_merges() {
    use crate::{handlers::process_message, ws::msg};
    use loro::{ExportMode, LoroDoc};

    let db = test_db().await;
    let doc_locks = DocLocks::default();
    let a = LoroDoc::new();
    a.set_peer_id(1).unwrap();
    a.get_text("text").insert(0, "server text").unwrap();
    let snapshot = a.export(ExportMode::Snapshot).unwrap();
    let create = rmp_serde::to_vec_named(&msg::ClientMsg::DocCreate {
        doc_uuid: "c.md".into(),
        snapshot: snapshot.clone(),
        peer_id: "1".into(),
        replace_tombstone: false,
    })
    .unwrap();
    let (resp, _) = process_message(&create, &db, "v", 1, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::Ack));
    let b = LoroDoc::new();
    b.set_peer_id(2).unwrap();
    b.import(&snapshot).unwrap();
    let vv0 = b.oplog_vv();
    b.get_text("text").insert(11, " +B").unwrap();
    let push = rmp_serde::to_vec_named(&msg::ClientMsg::SyncPush {
        doc_uuid: "c.md".into(),
        delta: b.export(ExportMode::updates(&vv0)).unwrap(),
        peer_id: "2".into(),
    })
    .unwrap();
    let (resp, broadcast) = process_message(&push, &db, "v", 2, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::Ack), "{resp:?}");
    assert!(matches!(broadcast, Some(BroadcastEvent::Delta { .. })));
    let (snapshot, _) = db::get_snapshot_with_vv(&db, "v", "c.md")
        .await
        .unwrap()
        .unwrap();
    let stored = LoroDoc::new();
    stored.import(&snapshot).unwrap();
    assert_eq!(stored.get_text("text").to_string(), "server text +B");
}

#[tokio::test]
async fn test_sync_push_no_stored_doc_unchanged() {
    use crate::{handlers::process_message, ws::msg};
    use loro::{ExportMode, LoroDoc, VersionVector};

    let db = test_db().await;
    let doc_locks = DocLocks::default();
    let a = LoroDoc::new();
    a.set_peer_id(1).unwrap();
    a.get_text("text").insert(0, "new text").unwrap();
    let push = rmp_serde::to_vec_named(&msg::ClientMsg::SyncPush {
        doc_uuid: "c.md".into(),
        delta: a
            .export(ExportMode::updates(&VersionVector::new()))
            .unwrap(),
        peer_id: "1".into(),
    })
    .unwrap();
    let (resp, broadcast) = process_message(&push, &db, "v", 1, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::Ack));
    assert!(matches!(broadcast, Some(BroadcastEvent::Delta { .. })));
    let (snapshot, _) = db::get_snapshot_with_vv(&db, "v", "c.md")
        .await
        .unwrap()
        .unwrap();
    let stored = LoroDoc::new();
    stored.import(&snapshot).unwrap();
    assert_eq!(stored.get_text("text").to_string(), "new text");
}

#[tokio::test]
async fn test_sync_push_same_peer_incremental_unchanged() {
    use crate::{handlers::process_message, ws::msg};
    use loro::{ExportMode, LoroDoc};

    let db = test_db().await;
    let doc_locks = DocLocks::default();
    let a = LoroDoc::new();
    a.set_peer_id(1).unwrap();
    a.get_text("text").insert(0, "server text").unwrap();
    let create = rmp_serde::to_vec_named(&msg::ClientMsg::DocCreate {
        doc_uuid: "c.md".into(),
        snapshot: a.export(ExportMode::Snapshot).unwrap(),
        peer_id: "1".into(),
        replace_tombstone: false,
    })
    .unwrap();
    let (resp, _) = process_message(&create, &db, "v", 1, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::Ack));
    let vv0 = a.oplog_vv();
    a.get_text("text").insert(11, " +A").unwrap();
    let delta = a.export(ExportMode::updates(&vv0)).unwrap();
    let empty = a.export(ExportMode::updates(&a.oplog_vv())).unwrap();
    for delta in [delta, empty] {
        let push = rmp_serde::to_vec_named(&msg::ClientMsg::SyncPush {
            doc_uuid: "c.md".into(),
            delta,
            peer_id: "1".into(),
        })
        .unwrap();
        let (resp, broadcast) = process_message(&push, &db, "v", 1, &doc_locks).await;
        assert!(matches!(resp, msg::ServerMsg::Ack), "{resp:?}");
        assert!(matches!(broadcast, Some(BroadcastEvent::Delta { .. })));
    }
    let (snapshot, _) = db::get_snapshot_with_vv(&db, "v", "c.md")
        .await
        .unwrap()
        .unwrap();
    let stored = LoroDoc::new();
    stored.import(&snapshot).unwrap();
    assert_eq!(stored.get_text("text").to_string(), "server text +A");
}

#[tokio::test]
async fn test_doc_create_corrupt_stored_vv_refused() {
    use crate::{handlers::process_message, ws::msg};
    use loro::{ExportMode, LoroDoc};

    let db = test_db().await;
    let doc_locks = DocLocks::default();
    let a = LoroDoc::new();
    a.get_text("text").insert(0, "server text").unwrap();
    let snapshot = a.export(ExportMode::Snapshot).unwrap();
    db::store_snapshot_with_vv(&db, "v", "c.md", &snapshot, b"not-valid-loro-vv")
        .await
        .unwrap();
    let b = LoroDoc::new();
    b.get_text("text").insert(0, "local text").unwrap();
    let create = rmp_serde::to_vec_named(&msg::ClientMsg::DocCreate {
        doc_uuid: "c.md".into(),
        snapshot: b.export(ExportMode::Snapshot).unwrap(),
        peer_id: "2".into(),
        replace_tombstone: false,
    })
    .unwrap();
    let (resp, broadcast) = process_message(&create, &db, "v", 2, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::CreateConflict { .. }));
    assert!(broadcast.is_none());
    assert_eq!(
        db::get_snapshot_with_vv(&db, "v", "c.md")
            .await
            .unwrap()
            .unwrap(),
        (snapshot, b"not-valid-loro-vv".to_vec())
    );
}

#[tokio::test]
async fn test_doc_create_shared_history_merges() {
    use crate::{handlers::process_message, ws::msg};
    use loro::{ExportMode, LoroDoc};

    let db = test_db().await;
    let doc_locks = DocLocks::default();
    let a = LoroDoc::new();
    a.set_peer_id(1).unwrap();
    a.get_text("text").insert(0, "server text").unwrap();
    let a_snapshot = a.export(ExportMode::Snapshot).unwrap();
    let create = rmp_serde::to_vec_named(&msg::ClientMsg::DocCreate {
        doc_uuid: "c.md".into(),
        snapshot: a_snapshot.clone(),
        peer_id: "1".into(),
        replace_tombstone: false,
    })
    .unwrap();
    let (resp, _) = process_message(&create, &db, "v", 1, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::Ack));

    let b = LoroDoc::new();
    b.set_peer_id(2).unwrap();
    b.import(&a_snapshot).unwrap();
    b.get_text("text").insert(11, " +B").unwrap();
    let create = rmp_serde::to_vec_named(&msg::ClientMsg::DocCreate {
        doc_uuid: "c.md".into(),
        snapshot: b.export(ExportMode::Snapshot).unwrap(),
        peer_id: "2".into(),
        replace_tombstone: false,
    })
    .unwrap();
    let (resp, broadcast) = process_message(&create, &db, "v", 2, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::Ack));
    assert!(broadcast.is_some());
    let (snapshot, _) = db::get_snapshot_with_vv(&db, "v", "c.md")
        .await
        .unwrap()
        .unwrap();
    let stored = LoroDoc::new();
    stored.import(&snapshot).unwrap();
    let text = stored.get_text("text").to_string();
    assert!(text.contains("server text"));
    assert!(text.contains("+B"));
}

// ── S1: live doc + replace_tombstone must merge, not discard ────────────────

#[tokio::test]
async fn test_doc_create_replace_tombstone_on_live_doc_merges() {
    use crate::handlers::process_message;
    use crate::ws::msg;
    use loro::{ExportMode, LoroDoc};

    let db = test_db().await;
    db::create_vault(&db, "v", "k").await.unwrap();
    let doc_locks = DocLocks::default();

    // Seed a live server doc with content "server".
    let server = LoroDoc::new();
    server.get_text("text").insert(0, "server").unwrap();
    let server_snap = server.export(ExportMode::Snapshot).unwrap();
    let server_vv = crate::vv_serde::vv_to_db_bytes(&server.oplog_vv());
    db::store_snapshot_with_vv(&db, "v", "live.md", &server_snap, &server_vv)
        .await
        .unwrap();

    // Client sends a different snapshot with replace_tombstone=true (but doc is live).
    let client = LoroDoc::new();
    client.import(&server_snap).unwrap();
    client.get_text("text").insert(6, " client").unwrap();
    let client_snap = client.export(ExportMode::Snapshot).unwrap();

    let create_msg = rmp_serde::to_vec_named(&msg::ClientMsg::DocCreate {
        doc_uuid: "live.md".into(),
        snapshot: client_snap,
        peer_id: "peer-c".into(),
        replace_tombstone: true,
    })
    .unwrap();

    let (resp, _) = process_message(&create_msg, &db, "v", 1, &doc_locks).await;
    assert!(matches!(resp, msg::ServerMsg::Ack));

    let (stored, _) = db::get_snapshot_with_vv(&db, "v", "live.md")
        .await
        .unwrap()
        .expect("doc must still exist");
    let merged = LoroDoc::new();
    merged.import(&stored).unwrap();
    let text = merged.get_text("text").to_string();
    // Both peer histories must survive — silent LWW discard of "server" is the bug.
    assert!(
        text.contains("server"),
        "server content lost on live replace_tombstone: {text:?}"
    );
    assert!(
        text.contains("client"),
        "client content missing after merge: {text:?}"
    );
}

#[tokio::test]
async fn test_doc_create_replace_tombstone_keeps_tombstone_on_bad_snapshot() {
    use crate::handlers::process_message;
    use crate::ws::msg;

    let db = test_db().await;
    db::create_vault(&db, "v", "k").await.unwrap();
    let doc_locks = DocLocks::default();
    db::tombstone(&db, "v", "dead.md", "peer-del")
        .await
        .unwrap();

    let create_msg = rmp_serde::to_vec_named(&msg::ClientMsg::DocCreate {
        doc_uuid: "dead.md".into(),
        snapshot: b"not-a-valid-loro-snapshot".to_vec(),
        peer_id: "peer-bad".into(),
        replace_tombstone: true,
    })
    .unwrap();

    let (resp, broadcast) = process_message(&create_msg, &db, "v", 1, &doc_locks).await;
    assert!(
        matches!(resp, msg::ServerMsg::Error { .. }),
        "expected Error for invalid snapshot, got {resp:?}"
    );
    assert!(broadcast.is_none());
    assert!(
        db::is_tombstoned(&db, "v", "dead.md").await.unwrap(),
        "tombstone must remain after failed replace"
    );
    assert!(
        db::get_snapshot_with_vv(&db, "v", "dead.md")
            .await
            .unwrap()
            .is_none(),
        "no doc row should appear after failed replace"
    );
}

// ── S2: delete + tombstone atomic ───────────────────────────────────────────

#[tokio::test]
async fn test_delete_doc_and_tombstone_atomic() {
    let db = test_db().await;
    db::store_snapshot_with_vv(&db, "v", "d", b"data", b"vv")
        .await
        .unwrap();

    db::delete_doc_and_tombstone(&db, "v", "d", "peer-x")
        .await
        .unwrap();

    assert!(
        db::get_snapshot_with_vv(&db, "v", "d")
            .await
            .unwrap()
            .is_none()
    );
    assert!(db::is_tombstoned(&db, "v", "d").await.unwrap());
}

// ── S3: oversized-frame error message shape ─────────────────────────────────

#[test]
fn test_oversized_frame_error_message_shape() {
    use crate::ws::msg;
    let n = 50 * 1024 * 1024 + 1;
    let err = msg::ServerMsg::Error {
        code: "frame_too_large".into(),
        message: format!("frame too large ({n} bytes, limit 50 MiB) — document not synced"),
    };
    let bytes = rmp_serde::to_vec_named(&err).expect("serialize");
    let back: msg::ServerMsg = rmp_serde::from_slice(&bytes).expect("deserialize");
    match back {
        msg::ServerMsg::Error { message, .. } => {
            assert!(message.contains("frame too large"));
            assert!(message.contains(&n.to_string()));
            assert!(message.contains("document not synced"));
        }
        other => panic!("expected Error, got {other:?}"),
    }
}
