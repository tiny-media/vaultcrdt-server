use super::{exec, scalar, test_db, test_state};
use crate::{AppState, auth, build_router};
use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tower::ServiceExt;

async fn call(
    state: &AppState,
    method: &str,
    uri: &str,
    body: Value,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .extension(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()));
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
    }
    let response = build_router(state.clone())
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 8192).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn invite(state: &AppState, vault: &str) -> String {
    let jwt = auth::jwt_sign(vault, &state.jwt_secret).unwrap();
    let (status, body) = call(
        state,
        "POST",
        "/invite",
        json!({"peer_id":"inviter", "device_name":"Laptop"}),
        Some(&jwt),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["vault_id"], vault);
    let token = body["invite"].as_str().unwrap();
    assert_eq!(token.len(), 22);
    assert!(
        token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    );
    let ttl: i64 = scalar(&state.db, "SELECT unixepoch(expires_at) - unixepoch(created_at) FROM invites ORDER BY id DESC LIMIT 1").await;
    assert_eq!(ttl, 900);
    token.to_owned()
}

async fn redeem(state: &AppState, token: &str, peer: &str) -> (StatusCode, Value) {
    call(
        state,
        "POST",
        "/invite/redeem",
        json!({"invite":token,"peer_id":peer,"device_name":"Phone"}),
        None,
    )
    .await
}

#[tokio::test]
async fn invite_errors_and_features() {
    let state = test_state(test_db().await);
    let (status, body) = call(&state, "GET", "/health", json!(null), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["features"], json!(["invite", "device_keys"]));
    assert_eq!(
        call(&state, "POST", "/invite", json!({"peer_id":"x"}), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        redeem(&state, "AAAAAAAAAAAAAAAAAAAAAA", "x").await,
        (StatusCode::UNAUTHORIZED, json!({"error":"invalid invite"}))
    );
    let token = invite(&state, "vault-a").await;
    exec(
        &state.db,
        "UPDATE invites SET expires_at = datetime('now', '-1 second')",
    )
    .await;
    assert_eq!(
        redeem(&state, &token, "x").await,
        (StatusCode::GONE, json!({"error":"invite expired"}))
    );
    let token = invite(&state, "vault-b").await;
    assert_eq!(redeem(&state, &token, "x").await.0, StatusCode::OK);
    assert_eq!(
        redeem(&state, &token, "y").await,
        (StatusCode::CONFLICT, json!({"error":"invite already used"}))
    );
}

#[tokio::test]
async fn device_auth_hashes_and_retirement() {
    let state = test_state(test_db().await);
    let token = invite(&state, "vault-a").await;
    let (status, body) = redeem(&state, &token, "joining").await;
    assert_eq!(status, StatusCode::OK);
    let key = body["device_key"].as_str().unwrap();
    assert_eq!(key.len(), 32);
    assert!(key.bytes().all(|b| b.is_ascii_alphanumeric()));
    assert_eq!(
        auth::jwt_verify(body["token"].as_str().unwrap(), &state.jwt_secret).unwrap(),
        "vault-a"
    );
    let stored: String = scalar(&state.db, "SELECT token_hash FROM invites").await;
    assert_ne!(stored, token);
    // Invite tokens are high-entropy random values: stored as SHA-256 hex
    // (64 chars), not argon2 — argon2 on the redeem scan was a CPU DoS
    // surface (review 2026-09-06).
    assert_eq!(stored.len(), 64);
    assert!(stored.bytes().all(|b| b.is_ascii_hexdigit()));
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    assert_eq!(stored, format!("{:x}", h.finalize()));
    let stored: String = scalar(&state.db, "SELECT key_hash FROM device_keys").await;
    assert_ne!(stored, key);
    assert!(stored.starts_with("$argon2"));
    assert!(crate::db::verify_secret(key, &stored));
    let credentials = json!({"vault_id":"vault-a","peer_id":"joining","device_key":key});
    let (status, body) = call(&state, "POST", "/auth/device", credentials.clone(), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        auth::jwt_verify(body["token"].as_str().unwrap(), &state.jwt_secret).unwrap(),
        "vault-a"
    );
    for bad in [
        json!({"vault_id":"vault-a","peer_id":"joining","device_key":"wrong"}),
        json!({"vault_id":"other-vault","peer_id":"joining","device_key":key}),
        json!({"vault_id":"vault-a","peer_id":"unknown","device_key":key}),
    ] {
        assert_eq!(
            call(&state, "POST", "/auth/device", bad, None).await,
            (
                StatusCode::UNAUTHORIZED,
                json!({"error":"authentication failed"})
            )
        );
    }
    exec(
        &state.db,
        "INSERT INTO peers (vault_id, peer_id, device_name) VALUES ('vault-a', 'joining', 'Phone')",
    )
    .await;
    // Rejected confirmation must not revoke a key.
    assert_eq!(
        call(
            &state,
            "DELETE",
            "/vault/peers/joining?vault_id=vault-a&device_name=Wrong",
            json!(null),
            Some(&state.admin_token)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let revoked: Option<String> = scalar(&state.db, "SELECT revoked_at FROM device_keys").await;
    assert!(revoked.is_none());
    assert_eq!(
        call(
            &state,
            "DELETE",
            "/vault/peers/joining?vault_id=vault-a&device_name=Phone",
            json!(null),
            Some(&state.admin_token)
        )
        .await
        .0,
        StatusCode::OK
    );
    let revoked: Option<String> = scalar(&state.db, "SELECT revoked_at FROM device_keys").await;
    assert!(revoked.is_some());
    assert_eq!(
        call(&state, "POST", "/auth/device", credentials, None).await,
        (
            StatusCode::UNAUTHORIZED,
            json!({"error":"authentication failed"})
        )
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_redeem_has_one_winner() {
    // A file-backed DB exercises the real on-disk write path and its locking.
    let path = std::env::temp_dir().join(format!("vault-invite-{}.db", uuid::Uuid::new_v4()));
    let state = test_state(crate::db::open_db(path.to_str().unwrap()).await.unwrap());
    let token = invite(&state, "vault-a").await;
    let (a, b) = tokio::join!(redeem(&state, &token, "a"), redeem(&state, &token, "b"));
    let mut statuses = [a.0.as_u16(), b.0.as_u16()];
    statuses.sort();
    assert_eq!(statuses, [200, 409]);
    let count: i64 = scalar(&state.db, "SELECT count(*) FROM device_keys").await;
    assert_eq!(count, 1);
    drop(state);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn onboarding_shares_auth_rate_limit() {
    let state = test_state(test_db().await);
    for _ in 0..10 {
        assert_eq!(
            redeem(&state, "AAAAAAAAAAAAAAAAAAAAAA", "x").await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let jwt = auth::jwt_sign("v", &state.jwt_secret).unwrap();
    for uri in ["/invite/redeem", "/invite", "/auth/device", "/auth/verify"] {
        assert_eq!(
            call(&state, "POST", uri, json!({}), Some(&jwt)).await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
