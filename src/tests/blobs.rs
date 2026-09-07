use super::{exec, scalar, test_db, test_state};
use crate::{
    AppState, auth,
    blobs::{
        looks_like_svg, svg_at_fixpoint, svg_filter_output, type_cap_for_ext, validate_blob_key,
    },
    build_router, cli, db,
};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde_json::{Value, json};
use std::path::PathBuf;
use tower::ServiceExt;

struct BlobDir(PathBuf);
impl Drop for BlobDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

async fn setup() -> (axum::Router, AppState, BlobDir, String) {
    let db = test_db().await;
    db::create_vault(&db, "v", "k").await.unwrap();
    let dir = std::env::temp_dir().join(format!("vaultcrdt-blobs-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("tmp")).unwrap();
    let mut state = test_state(db);
    state.blob_dir = dir.clone();
    let token = auth::jwt_sign("v", &state.jwt_secret).unwrap();
    let app = build_router(state.clone());
    (app, state, BlobDir(dir), token)
}

async fn json_call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"));
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let req = builder
        .body(
            body.map(|b| Body::from(b.to_string()))
                .unwrap_or_else(Body::empty),
        )
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let value = if bytes.is_empty() {
        json!(null)
    } else {
        serde_json::from_slice(&bytes).unwrap_or(json!({"raw": String::from_utf8_lossy(&bytes)}))
    };
    (status, value)
}

async fn put_range(
    app: &axum::Router,
    token: &str,
    upload_id: &str,
    a: u64,
    b: u64,
    total: u64,
    bytes: &[u8],
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/vault/blobs/uploads/{upload_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Range", format!("bytes {a}-{b}/{total}"))
        .header("Content-Type", "application/octet-stream")
        .body(Body::from(bytes.to_vec()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let value = serde_json::from_slice(&body).unwrap_or(json!(null));
    (status, value)
}

async fn get_raw(
    app: &axum::Router,
    uri: &str,
    token: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, Vec<u8>, HeaderMap) {
    let mut builder = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"));
    for (k, v) in extra {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), 2 * 1024 * 1024).await.unwrap();
    (status, body.to_vec(), headers)
}

async fn upload_all(app: &axum::Router, token: &str, data: &[u8]) -> String {
    let hash = hex(data);
    let (status, body) = json_call(
        app,
        "POST",
        "/vault/blobs/uploads",
        token,
        Some(json!({"hash": hash, "size": data.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["upload_id"].as_str().unwrap().to_string();
    let last = data.len() as u64 - 1;
    let (status, body) = put_range(app, token, &id, 0, last, data.len() as u64, data).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    hash
}

async fn run_cli(db: &db::Db, default_quota: u64, args: &[&str]) -> (i32, String, String) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run(db, default_quota, &args, &mut out, &mut err).await;
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn test_validate_blob_key_rejects_null_vectors() {
    let parsed: Value =
        serde_json::from_str(include_str!("../../docs/blob-path-key-vectors.json")).unwrap();
    let mut nulls = 0;
    for vector in parsed["vectors"].as_array().unwrap() {
        if vector["key"].is_null() {
            nulls += 1;
            let input = vector["input"].as_str().unwrap();
            assert!(!validate_blob_key(input), "expected reject for {input:?}");
        }
    }
    assert_eq!(nulls, 8);
}

#[test]
fn test_validate_blob_key_obsidian_allowlist() {
    // json/css stay off the 19-extension attachment whitelist.
    assert_eq!(type_cap_for_ext("json"), None);
    assert_eq!(type_cap_for_ext("css"), None);

    for key in [
        ".obsidian/app.json",
        ".obsidian/appearance.json",
        ".obsidian/snippets/wide.css",
        ".obsidian/themes/minimal/theme.css",
        ".obsidian/themes/minimal/manifest.json",
        ".obsidian/themes/über/theme.css",
        ".obsidian/themes/über/manifest.json",
    ] {
        assert!(validate_blob_key(key), "expected accept for {key:?}");
    }
    for key in [
        ".obsidian/workspace.json",
        ".obsidian/workspace-mobile.json",
        ".obsidian/plugins",
        ".obsidian/plugins/x",
        ".obsidian/plugins/vaultcrdt/data.json",
        "foo.json",
        "x.css",
        ".obsidian/snippets/nested/dir.css",
        ".obsidian/themes/minimal/styles.css",
        ".obsidian/a.png",
        ".Obsidian/a.png",
        ".obsidian/snippets/a\\..\\plugins\\vaultcrdt\\x.css",
        "pics/a\\b.png",
    ] {
        assert!(!validate_blob_key(key), "expected reject for {key:?}");
    }
}

#[tokio::test]
async fn test_blob_happy_path_file_get_and_range() {
    let (app, state, _dir, token) = setup().await;
    let data = b"hello-blob-bytes";
    let hash = upload_all(&app, &token, data).await;
    let path = state.blob_dir.join("v").join(&hash[..2]).join(&hash);
    assert!(path.is_file(), "missing {path:?}");
    assert_eq!(std::fs::read(&path).unwrap(), data);

    let (status, body, headers) = get_raw(&app, &format!("/vault/blobs/{hash}"), &token, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, data);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    assert_eq!(
        headers.get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment"
    );
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get(header::ACCEPT_RANGES).unwrap(), "bytes");
    assert_eq!(
        headers.get(header::ETAG).unwrap(),
        format!("\"{hash}\"").as_str()
    );

    let (status, body, headers) = get_raw(
        &app,
        &format!("/vault/blobs/{hash}"),
        &token,
        &[("Range", "bytes=0-4")],
    )
    .await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body, b"hello");
    assert_eq!(headers.get(header::CONTENT_RANGE).unwrap(), "bytes 0-4/16");
    assert_eq!(
        headers.get(header::ETAG).unwrap(),
        format!("\"{hash}\"").as_str()
    );
}

#[tokio::test]
async fn test_blob_abort_resume_then_201() {
    let (app, _state, _dir, token) = setup().await;
    let data = b"abcdefghijklmnop";
    let hash = hex(data);
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blobs/uploads",
        &token,
        Some(json!({"hash": hash, "size": data.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = body["upload_id"].as_str().unwrap();

    let (status, body) = put_range(&app, &token, id, 0, 7, data.len() as u64, &data[..8]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["next_offset"], 8);

    let (status, body) = json_call(
        &app,
        "GET",
        &format!("/vault/blobs/uploads/{id}"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["next_offset"], 8);

    let (status, body) = put_range(&app, &token, id, 8, 15, data.len() as u64, &data[8..]).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["hash"], hash);
}

#[tokio::test]
async fn test_blob_wrong_hash_422_no_row_no_file() {
    let (app, state, _dir, token) = setup().await;
    let data = b"payload-for-hash-mismatch";
    let claimed = hex(b"other-bytes-not-the-payload!!");
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blobs/uploads",
        &token,
        Some(json!({"hash": claimed, "size": data.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = body["upload_id"].as_str().unwrap().to_string();
    let last = data.len() as u64 - 1;
    let (status, _) = put_range(&app, &token, &id, 0, last, data.len() as u64, data).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let count: i64 = scalar(&state.db, "SELECT count(*) FROM blobs").await;
    assert_eq!(count, 0);
    let dest = state.blob_dir.join("v").join(&claimed[..2]).join(&claimed);
    assert!(!dest.exists());
    let tmp = state.blob_dir.join("tmp").join(&id);
    assert!(!tmp.exists());
}

#[tokio::test]
async fn test_blob_offset_mismatch_409() {
    let (app, _state, _dir, token) = setup().await;
    let data = b"0123456789abcdef";
    let hash = hex(data);
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blobs/uploads",
        &token,
        Some(json!({"hash": hash, "size": data.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = body["upload_id"].as_str().unwrap();
    let (status, body) = put_range(&app, &token, id, 4, 7, data.len() as u64, &data[4..8]).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["next_offset"], 0);
}

#[tokio::test]
async fn test_blob_dedup_exists_true() {
    let (app, _state, _dir, token) = setup().await;
    let data = b"same-bytes-twice";
    let hash = upload_all(&app, &token, data).await;
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blobs/uploads",
        &token,
        Some(json!({"hash": hash, "size": data.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["exists"], true);
}

#[tokio::test]
async fn test_blob_paths_lww_and_idempotent() {
    let (app, _state, _dir, token) = setup().await;
    let data = b"lww-blob";
    let hash = upload_all(&app, &token, data).await;
    let other = upload_all(&app, &token, b"lww-other").await;
    let post = |generation: i64, peer: &str, h: &str| {
        json!({
            "path_key": "pics/a.png",
            "display_path": "Pics/a.png",
            "key_version": 1,
            "generation": generation,
            "state": "live",
            "content_hash": h,
            "size": 8,
            "peer_id": peer,
        })
    };

    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blob-paths",
        &token,
        Some(post(1, "peer-a", &hash)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], true);
    let seq1 = body["seq"].as_i64().unwrap();

    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blob-paths",
        &token,
        Some(post(0, "peer-z", &hash)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["accepted"], false);
    assert_eq!(body["current"]["generation"], 1);

    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blob-paths",
        &token,
        Some(post(1, "peer-a", &hash)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], true);
    assert_eq!(body["seq"], seq1);

    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blob-paths",
        &token,
        Some(post(1, "aaa", &other)),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["current"]["peer_id"], "peer-a");

    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blob-paths",
        &token,
        Some(post(1, "peer-b", &other)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], true);
    assert!(body["seq"].as_i64().unwrap() > seq1);

    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blob-paths",
        &token,
        Some(post(3, "peer-a", &hash)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], true);
}

#[tokio::test]
async fn test_blob_paths_412_missing_and_foreign_hash() {
    let (app, state, _dir, token) = setup().await;
    db::create_vault(&state.db, "other", "k").await.unwrap();
    let foreign = auth::jwt_sign("other", &state.jwt_secret).unwrap();
    let data = b"owned-by-v";
    let hash = upload_all(&app, &token, data).await;

    let (status, _) = json_call(
        &app,
        "POST",
        "/vault/blob-paths",
        &token,
        Some(json!({
            "path_key": "pics/missing.png",
            "display_path": "pics/missing.png",
            "key_version": 1,
            "generation": 1,
            "state": "live",
            "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "size": 1,
            "peer_id": "p",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);

    let (status, _) = json_call(
        &app,
        "POST",
        "/vault/blob-paths",
        &foreign,
        Some(json!({
            "path_key": "pics/x.png",
            "display_path": "pics/x.png",
            "key_version": 1,
            "generation": 1,
            "state": "live",
            "content_hash": hash,
            "size": data.len(),
            "peer_id": "p",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn test_blob_foreign_vault_get_404() {
    let (app, state, _dir, token) = setup().await;
    db::create_vault(&state.db, "other", "k").await.unwrap();
    let foreign = auth::jwt_sign("other", &state.jwt_secret).unwrap();
    let hash = upload_all(&app, &token, b"secret-bytes").await;
    let (status, _, _) = get_raw(&app, &format!("/vault/blobs/{hash}"), &foreign, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_blob_type_cap_and_segment_body_limit() {
    let (app, _state, _dir, token) = setup().await;
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blob-paths",
        &token,
        Some(json!({
            "path_key": "pics/big.jpg",
            "display_path": "pics/big.jpg",
            "key_version": 1,
            "generation": 1,
            "state": "live",
            "content_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "size": 10 * 1024 * 1024 + 1,
            "peer_id": "p",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["error"], "type_cap_exceeded");

    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blobs/uploads",
        &token,
        Some(json!({
            "hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "size": 1
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["upload_id"].as_str().unwrap();
    let too_big = vec![0u8; 4 * 1024 * 1024 + 4 * 1024 + 1];
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/vault/blobs/uploads/{id}"))
        .header("Authorization", format!("Bearer {token}"))
        .header(
            "Content-Range",
            format!("bytes 0-{}/{}", too_big.len() - 1, too_big.len()),
        )
        .header("Content-Type", "application/octet-stream")
        .body(Body::from(too_big))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_obsidian_type_cap() {
    let (app, _state, _dir, token) = setup().await;
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blob-paths",
        &token,
        Some(json!({
            "path_key": ".obsidian/app.json",
            "display_path": ".obsidian/app.json",
            "key_version": 1,
            "generation": 1,
            "state": "live",
            "content_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "size": 2 * 1024 * 1024 + 1,
            "peer_id": "p",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["error"], "type_cap_exceeded");
    assert_eq!(body["max_bytes"], 2 * 1024 * 1024);
}

#[tokio::test]
async fn test_blob_quota_cli_raise_unlimited_and_default() {
    let db = test_db().await;
    db::create_vault(&db, "v", "k").await.unwrap();
    let dir = std::env::temp_dir().join(format!("vaultcrdt-blobs-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("tmp")).unwrap();
    let _guard = BlobDir(dir.clone());
    let mut state = test_state(db);
    state.blob_dir = dir;
    state.default_quota_bytes = 50;
    let token = auth::jwt_sign("v", &state.jwt_secret).unwrap();
    let app = build_router(state.clone());

    let small = vec![b'x'; 40];
    let hash = hex(&small);
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blobs/uploads",
        &token,
        Some(json!({"hash": hash, "size": small.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["upload_id"].as_str().unwrap().to_string();
    let (status, _) = put_range(
        &app,
        &token,
        &id,
        0,
        small.len() as u64 - 1,
        small.len() as u64,
        &small,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let other = vec![b'y'; 20];
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blobs/uploads",
        &token,
        Some(json!({"hash": hex(&other), "size": other.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["error"], "quota_exceeded");
    assert_eq!(body["quota_bytes"], 50);

    let (code, out, err) = run_cli(&state.db, 50, &["vault", "quota", "v", "1000"]).await;
    assert_eq!((code, err.as_str()), (0, ""), "{out}{err}");
    assert!(out.contains("1000"), "{out}");

    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blobs/uploads",
        &token,
        Some(json!({"hash": hex(&other), "size": other.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (code, out, _) = run_cli(&state.db, 50, &["vault", "quota", "v", "0"]).await;
    assert_eq!(code, 0);
    assert!(out.contains("effective") || out.contains('0'), "{out}");

    let third = vec![b'z'; 30];
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blobs/uploads",
        &token,
        Some(json!({"hash": hex(&third), "size": third.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (code, out, _) = run_cli(&state.db, 50, &["vault", "quota", "v", "default"]).await;
    assert_eq!(code, 0);
    assert!(out.contains("50"), "{out}");
}

#[tokio::test]
async fn test_blob_paths_since_seq_pagination() {
    let (app, state, _dir, token) = setup().await;
    let hash = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    exec(
        &state.db,
        &format!("INSERT INTO blobs (vault_id, hash, size) VALUES ('v', '{hash}', 1)"),
    )
    .await;
    let mut sql = String::from("BEGIN;\n");
    for i in 1..=1001 {
        sql.push_str(&format!(
            "INSERT INTO blob_path_states (vault_id, path_key, display_path, generation, state, content_hash, size, peer_id, seq)
             VALUES ('v', 'pics/f{i}.png', 'pics/f{i}.png', 1, 'live', '{hash}', 1, 'p', {i});\n"
        ));
    }
    sql.push_str("UPDATE counters SET value = 1001 WHERE name = 'blob_seq';\nCOMMIT;");
    exec(&state.db, &sql).await;

    let (status, page1) = json_call(
        &app,
        "GET",
        "/vault/blob-paths?since_seq=0&limit=1000",
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let states1 = page1["states"].as_array().unwrap();
    assert_eq!(states1.len(), 1000);
    assert_eq!(page1["max_seq"], 1001);
    let last = states1.last().unwrap()["seq"].as_i64().unwrap();

    let (status, page2) = json_call(
        &app,
        "GET",
        &format!("/vault/blob-paths?since_seq={last}&limit=5000"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let states2 = page2["states"].as_array().unwrap();
    assert_eq!(states2.len(), 1);
    assert_eq!(page2["max_seq"], 1001);
    let mut seen: Vec<i64> = states1
        .iter()
        .chain(states2.iter())
        .map(|s| s["seq"].as_i64().unwrap())
        .collect();
    seen.sort();
    seen.dedup();
    assert_eq!(seen, (1..=1001).collect::<Vec<_>>());
}

#[tokio::test]
async fn test_blob_expired_upload_404_on_get_and_put() {
    let (app, state, _dir, token) = setup().await;
    let data = b"expire-me-please";
    let hash = hex(data);
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blobs/uploads",
        &token,
        Some(json!({"hash": hash, "size": data.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = body["upload_id"].as_str().unwrap().to_string();
    exec(
        &state.db,
        &format!(
            "UPDATE blob_uploads SET created_at = datetime('now', '-25 hours') WHERE upload_id = '{id}'"
        ),
    )
    .await;

    let (status, _) = json_call(
        &app,
        "GET",
        &format!("/vault/blobs/uploads/{id}"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blobs/uploads",
        &token,
        Some(json!({"hash": hash, "size": data.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id2 = body["upload_id"].as_str().unwrap().to_string();
    exec(
        &state.db,
        &format!(
            "UPDATE blob_uploads SET created_at = datetime('now', '-25 hours') WHERE upload_id = '{id2}'"
        ),
    )
    .await;
    let last = data.len() as u64 - 1;
    let (status, _) = put_range(&app, &token, &id2, 0, last, data.len() as u64, data).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_blob_expired_inflight_does_not_eat_quota() {
    let (app, state, _dir, token) = setup().await;
    exec(
        &state.db,
        "UPDATE vaults SET quota_bytes = 50 WHERE vault_id = 'v'",
    )
    .await;

    let first = vec![b'x'; 40];
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blobs/uploads",
        &token,
        Some(json!({"hash": hex(&first), "size": first.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["upload_id"].as_str().unwrap();
    exec(
        &state.db,
        &format!(
            "UPDATE blob_uploads SET created_at = datetime('now', '-25 hours') WHERE upload_id = '{id}'"
        ),
    )
    .await;

    let second = vec![b'y'; 40];
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blobs/uploads",
        &token,
        Some(json!({"hash": hex(&second), "size": second.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

fn svg_vector(name: &str) -> (Vec<u8>, String) {
    let parsed: Value =
        serde_json::from_str(include_str!("../../docs/svg-sanitize-vectors.json")).unwrap();
    for v in parsed.as_array().unwrap() {
        if v["name"].as_str() == Some(name) {
            let input = B64.decode(v["input_b64"].as_str().unwrap()).unwrap();
            let expected = v["output_blake3_hex"].as_str().unwrap().to_string();
            return (input, expected);
        }
    }
    panic!("missing svg vector {name}");
}

#[test]
fn test_svg_sanitize_golden_vectors() {
    let parsed: Value =
        serde_json::from_str(include_str!("../../docs/svg-sanitize-vectors.json")).unwrap();
    for v in parsed.as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let input = B64.decode(v["input_b64"].as_str().unwrap()).unwrap();
        let expected = v["output_blake3_hex"].as_str().unwrap();
        let out = svg_filter_output(&input).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let got = blake3::hash(&out).to_hex().to_string();
        assert_eq!(
            got, expected,
            "golden hash mismatch for {name} — STOP, do not fix vectors"
        );
    }
}

#[test]
fn test_looks_like_svg_sniff_vectors() {
    assert!(looks_like_svg(b"<svg xmlns='http://www.w3.org/2000/svg'>"));
    assert!(looks_like_svg(
        b"\xEF\xBB\xBF<?xml version=\"1.0\"?><svg xmlns='http://www.w3.org/2000/svg'>"
    ));
    assert!(looks_like_svg(
        b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\"><svg xmlns='http://www.w3.org/2000/svg'>"
    ));
    assert!(!looks_like_svg(
        b"<svg:svg xmlns:svg='http://www.w3.org/2000/svg'>"
    ));
    assert!(!looks_like_svg(b"<SVG xmlns='http://www.w3.org/2000/svg'>"));
    assert!(!looks_like_svg(
        b"<svgfoo xmlns='http://www.w3.org/2000/svg'>"
    ));
    assert!(!looks_like_svg(b"\x89PNG\r\n\x1a\n<svg "));
    assert!(looks_like_svg(
        b"  \n\t<div><svg xmlns='http://www.w3.org/2000/svg'>"
    ));
    assert!(!looks_like_svg(
        b"\x00<svg xmlns='http://www.w3.org/2000/svg'>"
    ));
}

#[test]
fn test_svg_at_fixpoint_sanitized_script_malformed() {
    let (clean, _) = svg_vector("clean-svg");
    let sanitized = svg_filter_output(&clean).unwrap();
    assert!(svg_at_fixpoint(&sanitized).unwrap());

    let (script, _) = svg_vector("script-svg");
    assert!(!svg_at_fixpoint(&script).unwrap());

    assert!(svg_at_fixpoint(b"<svg xmlns='http://www.w3.org/2000/svg'><").is_err());
}

#[test]
fn test_svg_in_image_cap() {
    assert_eq!(type_cap_for_ext("svg"), Some(10 * 1024 * 1024));
    assert!(validate_blob_key("x.svg"));
}

async fn try_upload(app: &axum::Router, token: &str, data: &[u8]) -> (StatusCode, Value, String) {
    let hash = hex(data);
    let (status, body) = json_call(
        app,
        "POST",
        "/vault/blobs/uploads",
        token,
        Some(json!({"hash": hash, "size": data.len()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["upload_id"].as_str().unwrap().to_string();
    let last = data.len() as u64 - 1;
    let (status, body) = put_range(app, token, &id, 0, last, data.len() as u64, data).await;
    (status, body, id)
}

#[tokio::test]
async fn test_svg_r1_presanitized_upload_ok() {
    let (app, _state, _dir, token) = setup().await;
    let (clean, _) = svg_vector("clean-svg");
    let sanitized = svg_filter_output(&clean).unwrap();
    let (status, body, _) = try_upload(&app, &token, &sanitized).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["hash"], hex(&sanitized));
}

#[tokio::test]
async fn test_svg_r1_script_422_no_row_tmp_cleaned() {
    let (app, state, _dir, token) = setup().await;
    let (script, _) = svg_vector("script-svg");
    let (status, body, id) = try_upload(&app, &token, &script).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"], "svg_not_sanitized");
    let count: i64 = scalar(&state.db, "SELECT count(*) FROM blobs").await;
    assert_eq!(count, 0);
    let tmp = state.blob_dir.join("tmp").join(&id);
    assert!(!tmp.exists());
    let claimed = hex(&script);
    let dest = state.blob_dir.join("v").join(&claimed[..2]).join(&claimed);
    assert!(!dest.exists());
}

#[tokio::test]
async fn test_svg_r1_malformed_422_svg_invalid() {
    let (app, state, _dir, token) = setup().await;
    let bad = b"<svg xmlns='http://www.w3.org/2000/svg'><";
    assert!(looks_like_svg(bad));
    assert!(svg_at_fixpoint(bad).is_err());
    let (status, body, id) = try_upload(&app, &token, bad).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"], "svg_invalid");
    let count: i64 = scalar(&state.db, "SELECT count(*) FROM blobs").await;
    assert_eq!(count, 0);
    let tmp = state.blob_dir.join("tmp").join(&id);
    assert!(!tmp.exists());
}

#[tokio::test]
async fn test_svg_r2_live_attach_sanitized_ok() {
    let (app, _state, _dir, token) = setup().await;
    let (clean, _) = svg_vector("clean-svg");
    let sanitized = svg_filter_output(&clean).unwrap();
    let hash = upload_all(&app, &token, &sanitized).await;
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blob-paths",
        &token,
        Some(json!({
            "path_key": "pics/a.svg",
            "display_path": "pics/a.svg",
            "key_version": 1,
            "generation": 1,
            "state": "live",
            "content_hash": hash,
            "size": sanitized.len(),
            "peer_id": "p",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], true);
}

#[tokio::test]
async fn test_svg_r2_live_attach_nonsanitized_direct_insert_422() {
    let (app, state, _dir, token) = setup().await;
    let (script, _) = svg_vector("script-svg");
    let hash = hex(&script);
    let dir = state.blob_dir.join("v").join(&hash[..2]);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(&hash), &script).unwrap();
    exec(
        &state.db,
        &format!(
            "INSERT INTO blobs (vault_id, hash, size) VALUES ('v', '{hash}', {})",
            script.len()
        ),
    )
    .await;
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blob-paths",
        &token,
        Some(json!({
            "path_key": "pics/evil.svg",
            "display_path": "pics/evil.svg",
            "key_version": 1,
            "generation": 1,
            "state": "live",
            "content_hash": hash,
            "size": script.len(),
            "peer_id": "p",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"], "svg_not_sanitized");
    let paths: i64 = scalar(&state.db, "SELECT count(*) FROM blob_path_states").await;
    assert_eq!(paths, 0);
}

#[tokio::test]
async fn test_svg_r2_tombstone_missing_blob_not_rejected() {
    let (app, _state, _dir, token) = setup().await;
    let (status, body) = json_call(
        &app,
        "POST",
        "/vault/blob-paths",
        &token,
        Some(json!({
            "path_key": "pics/gone.svg",
            "display_path": "pics/gone.svg",
            "key_version": 1,
            "generation": 1,
            "state": "deleted",
            "peer_id": "p",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], true);
}
