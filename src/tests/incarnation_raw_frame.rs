//! ADR-0006 §6.1: this file MUST remain runnable with e221571 production code.
//! No production message enums or incarnation APIs participate in this test.
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::Message};

fn string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend([0xd9, u8::try_from(value.len()).unwrap()]);
    bytes.extend(value.as_bytes());
}

#[tokio::test]
async fn raw_frame_rejects_absence_attestation_on_live_document() {
    let db = crate::db::open_db(":memory:").await.unwrap();
    // This store API already exists on e221571; the return value is ignored.
    crate::db::store_snapshot_with_vv(&db, "raw", "note.md", b"snapshot", b"vv")
        .await
        .unwrap();
    let state = crate::AppState {
        db: db.clone(),
        jwt_secret: "raw-test-secret".into(),
        admin_token: "raw-test-admin".into(),
        trust_proxy: false,
        auth_rate_limiter: std::sync::Arc::new(crate::auth::AuthRateLimiter::default()),
        broadcast_tx: tokio::sync::broadcast::channel(16).0,
        server_epoch: "raw-test".into(),
        connections: Default::default(),
        doc_locks: Default::default(),
        blob_dir: std::env::temp_dir(),
        default_quota_bytes: 0,
    };
    let token = crate::auth::jwt_sign("raw", &state.jwt_secret).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, crate::build_router(state))
            .await
            .unwrap();
    });
    let (mut socket, _) = connect_async(format!("ws://{addr}/ws")).await.unwrap();
    // Hand-encoded named msgpack, including old Auth without features.
    let mut auth = vec![0x83];
    for (key, value) in [("type", "auth"), ("token", token.as_str())] {
        string(&mut auth, key);
        string(&mut auth, value);
    }
    string(&mut auth, "protocol_version");
    auth.push(1);
    socket.send(Message::Binary(auth.into())).await.unwrap();
    let Message::Binary(bytes) =
        tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    else {
        panic!("expected auth response")
    };
    let response: serde_json::Value = rmp_serde::from_slice(&bytes).unwrap();
    assert_eq!(response["type"], "auth_ok");

    let mut delete = vec![0x86];
    for (key, value) in [
        ("type", "doc_delete"),
        ("doc_uuid", "note.md"),
        ("peer_id", "p"),
        ("intent_id", "intent-raw"),
        ("request_id", "request-raw"),
    ] {
        string(&mut delete, key);
        string(&mut delete, value);
    }
    string(&mut delete, "expected_incarnation");
    delete.push(0);
    socket.send(Message::Binary(delete.into())).await.unwrap();
    let Message::Binary(bytes) =
        tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    else {
        panic!("expected delete response")
    };
    let response: serde_json::Value = rmp_serde::from_slice(&bytes).unwrap();
    assert_eq!(
        response["type"], "delete_rejected",
        "a live row MUST reject expected_incarnation=0"
    );
    assert_eq!(response["doc_uuid"], "note.md");
    assert_eq!(response["intent_id"], "intent-raw");
    assert_eq!(response["request_id"], "request-raw");
    assert!(
        crate::db::get_snapshot_with_vv(&db, "raw", "note.md")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        !crate::db::is_tombstoned(&db, "raw", "note.md")
            .await
            .unwrap()
    );
    socket.close(None).await.unwrap();
    server.abort();
}
