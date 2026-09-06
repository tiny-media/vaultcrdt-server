use futures_util::{SinkExt, StreamExt};
use loro::{ExportMode, LoroDoc};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::{AppState, BroadcastEvent, DocLocks, build_router, db, ws::msg};

// ── Test helpers ────────────────────────────────────────────────────────────

async fn spawn_server() -> (String, AppState) {
    let db = db::open_db(":memory:").await.expect("db");
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<BroadcastEvent>(256);
    let state = AppState {
        db,
        jwt_secret: "test-secret".to_string(),
        admin_token: "test-admin".to_string(),
        trust_proxy: false,
        auth_rate_limiter: std::sync::Arc::new(crate::auth::AuthRateLimiter::default()),
        broadcast_tx,
        server_epoch: "test".to_string(),
        connections: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        doc_locks: DocLocks::default(),
    };

    let router = build_router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    (format!("127.0.0.1:{}", addr.port()), state)
}

fn get_token(jwt_secret: &str, vault_id: &str) -> String {
    crate::auth::jwt_sign(vault_id, jwt_secret).unwrap()
}

async fn ws_connect(
    addr: &str,
    token: &str,
) -> (
    futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) {
    let (mut sink, mut stream) = ws_connect_raw(addr).await;
    send_msg(
        &mut sink,
        &msg::ClientMsg::Auth {
            token: token.into(),
            protocol_version: crate::ws::PROTOCOL_VERSION,
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut stream).await,
        msg::ServerMsg::AuthOk {
            protocol_version: 1
        }
    ));
    (sink, stream)
}

type TestSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_connect_raw(
    addr: &str,
) -> (
    futures_util::stream::SplitSink<TestSocket, Message>,
    futures_util::stream::SplitStream<TestSocket>,
) {
    let (ws, _) = connect_async(format!("ws://{addr}/ws?peer_id=test&device=t"))
        .await
        .unwrap();
    ws.split()
}

async fn expect_close(
    stream: &mut futures_util::stream::SplitStream<TestSocket>,
    timeout: Option<std::time::Duration>,
) -> (u16, String) {
    tokio::time::timeout(
        timeout.unwrap_or(std::time::Duration::from_secs(5)),
        async {
            loop {
                match stream
                    .next()
                    .await
                    .expect("stream ended")
                    .expect("WS error")
                {
                    Message::Close(Some(frame)) => {
                        return (frame.code.into(), frame.reason.to_string());
                    }
                    Message::Binary(_) => {
                        panic!("unexpected binary frame before close (including AuthOk)")
                    }
                    _ => {}
                }
            }
        },
    )
    .await
    .expect("close timeout")
}

async fn send_msg(
    sink: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    msg: &msg::ClientMsg,
) {
    let bytes = rmp_serde::to_vec_named(msg).unwrap();
    sink.send(Message::Binary(bytes.into())).await.unwrap();
}

async fn recv_msg(
    stream: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> msg::ServerMsg {
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next()).await;
    let msg = timeout
        .expect("recv timeout")
        .expect("stream ended")
        .expect("ws error");
    match msg {
        Message::Binary(data) => rmp_serde::from_slice(&data).expect("decode ServerMsg"),
        other => panic!("unexpected WS message: {other:?}"),
    }
}

fn make_doc(peer_id: u64, content: &str) -> LoroDoc {
    let doc = LoroDoc::new();
    doc.set_peer_id(peer_id).unwrap();
    doc.get_text("content")
        .update(content, Default::default())
        .unwrap();
    doc.commit();
    doc
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_ws_auth_happy_path() {
    let (addr, state) = spawn_server().await;
    let (mut sink, mut stream) = ws_connect_raw(&addr).await;
    send_msg(
        &mut sink,
        &msg::ClientMsg::Auth {
            token: get_token(&state.jwt_secret, "v1"),
            protocol_version: 1,
        },
    )
    .await;
    assert!(matches!(
        recv_msg(&mut stream).await,
        msg::ServerMsg::AuthOk {
            protocol_version: 1
        }
    ));
    send_msg(&mut sink, &msg::ClientMsg::Ping).await;
    assert!(matches!(recv_msg(&mut stream).await, msg::ServerMsg::Pong));
}

#[tokio::test]
async fn test_ws_first_frame_not_auth_closes() {
    let (addr, state) = spawn_server().await;
    let (mut sink, mut stream) = ws_connect_raw(&addr).await;
    send_msg(&mut sink, &msg::ClientMsg::Ping).await;
    assert_eq!(
        expect_close(&mut stream, None).await,
        (1008, "auth_required".into())
    );
    assert!(state.connections.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_ws_protocol_version_mismatch() {
    let (addr, state) = spawn_server().await;
    let (mut sink, mut stream) = ws_connect_raw(&addr).await;
    send_msg(
        &mut sink,
        &msg::ClientMsg::Auth {
            token: get_token(&state.jwt_secret, "v1"),
            protocol_version: 99,
        },
    )
    .await;
    match recv_msg(&mut stream).await {
        msg::ServerMsg::Error { code, message } => {
            assert_eq!(code, "protocol_version_mismatch");
            assert_eq!(message, "server=1 client=99");
        }
        _ => panic!("expected mismatch error"),
    }
    assert_eq!(
        expect_close(&mut stream, None).await,
        (1008, "protocol_version_mismatch".into())
    );
}

#[tokio::test]
async fn test_ws_auth_timeout_closes() {
    let (addr, _) = spawn_server().await;
    let (_sink, mut stream) = ws_connect_raw(&addr).await;
    let close = tokio::time::timeout(
        std::time::Duration::from_secs(13),
        expect_close(&mut stream, Some(std::time::Duration::from_secs(12))),
    )
    .await
    .unwrap();
    assert_eq!(close, (1008, "auth_timeout".into()));
}

#[tokio::test]
async fn test_ws_url_token_grants_nothing() {
    let (addr, state) = spawn_server().await;
    let token = get_token(&state.jwt_secret, "v1");
    let (ws, _) = connect_async(format!("ws://{addr}/ws?token={token}"))
        .await
        .unwrap();
    let (mut sink, mut stream) = ws.split();
    send_msg(&mut sink, &msg::ClientMsg::Ping).await;
    assert_eq!(
        expect_close(&mut stream, None).await,
        (1008, "auth_required".into())
    );
}

#[tokio::test]
async fn test_ws_bearer_header_grants_nothing() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let (addr, state) = spawn_server().await;
    let mut request = format!("ws://{addr}/ws").into_client_request().unwrap();
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", get_token(&state.jwt_secret, "v1"))
            .parse()
            .unwrap(),
    );
    let (ws, _) = connect_async(request).await.unwrap();
    let (mut sink, mut stream) = ws.split();
    send_msg(&mut sink, &msg::ClientMsg::Ping).await;
    assert_eq!(
        expect_close(&mut stream, None).await,
        (1008, "auth_required".into())
    );
}

#[tokio::test]
async fn test_ws_post_auth_auth_is_bad_frame_without_close() {
    let (addr, state) = spawn_server().await;
    let token = get_token(&state.jwt_secret, "v1");
    let (mut sink, mut stream) = ws_connect(&addr, &token).await;
    send_msg(
        &mut sink,
        &msg::ClientMsg::Auth {
            token,
            protocol_version: 1,
        },
    )
    .await;
    match recv_msg(&mut stream).await {
        msg::ServerMsg::Error { code, message } => {
            assert_eq!(code, "bad_frame");
            assert_eq!(message, "message could not be decoded");
        }
        _ => panic!("expected bad frame error"),
    }
    send_msg(&mut sink, &msg::ClientMsg::Ping).await;
    assert!(matches!(recv_msg(&mut stream).await, msg::ServerMsg::Pong));
}

#[tokio::test]
async fn test_ws_ping_pong() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "v1", "key1").await.unwrap();
    let token = get_token(&state.jwt_secret, "v1");

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;
    send_msg(&mut sink, &msg::ClientMsg::Ping).await;
    let resp = recv_msg(&mut stream).await;
    assert!(matches!(resp, msg::ServerMsg::Pong));
}

#[tokio::test]
async fn test_ws_request_doc_list_empty() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "v1", "key1").await.unwrap();
    let token = get_token(&state.jwt_secret, "v1");

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;
    send_msg(&mut sink, &msg::ClientMsg::RequestDocList).await;

    match recv_msg(&mut stream).await {
        msg::ServerMsg::DocList { docs, tombstones } => {
            assert!(docs.is_empty());
            assert!(tombstones.is_empty());
        }
        other => panic!("expected DocList, got {other:?}"),
    }
}

#[tokio::test]
async fn test_ws_doc_create_and_list() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "v1", "key1").await.unwrap();
    let token = get_token(&state.jwt_secret, "v1");

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;

    // Create a doc
    let doc = make_doc(42, "Hello World");
    let snapshot = doc.export(ExportMode::Snapshot).unwrap();

    send_msg(
        &mut sink,
        &msg::ClientMsg::DocCreate {
            doc_uuid: "note.md".to_string(),
            snapshot,
            peer_id: "42".to_string(),
            replace_tombstone: false,
        },
    )
    .await;

    match recv_msg(&mut stream).await {
        msg::ServerMsg::Ack => {}
        other => panic!("expected Ack, got {other:?}"),
    }

    // List docs
    send_msg(&mut sink, &msg::ClientMsg::RequestDocList).await;
    match recv_msg(&mut stream).await {
        msg::ServerMsg::DocList { docs, tombstones } => {
            assert_eq!(docs.len(), 1);
            assert_eq!(docs[0].doc_uuid, "note.md");
            assert!(tombstones.is_empty());
        }
        other => panic!("expected DocList, got {other:?}"),
    }
}

#[tokio::test]
async fn test_ws_sync_start_unknown_doc() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "v1", "key1").await.unwrap();
    let token = get_token(&state.jwt_secret, "v1");

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;

    send_msg(
        &mut sink,
        &msg::ClientMsg::SyncStart {
            doc_uuid: "nonexistent.md".to_string(),
            client_vv: None,
        },
    )
    .await;

    match recv_msg(&mut stream).await {
        msg::ServerMsg::DocUnknown { doc_uuid } => {
            assert_eq!(doc_uuid, "nonexistent.md");
        }
        other => panic!("expected DocUnknown, got {other:?}"),
    }
}

#[tokio::test]
async fn test_ws_sync_start_full_snapshot() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "v1", "key1").await.unwrap();
    let token = get_token(&state.jwt_secret, "v1");

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;

    // Create doc on server
    let doc = make_doc(42, "Hello");
    let snapshot = doc.export(ExportMode::Snapshot).unwrap();
    send_msg(
        &mut sink,
        &msg::ClientMsg::DocCreate {
            doc_uuid: "note.md".to_string(),
            snapshot,
            peer_id: "42".to_string(),
            replace_tombstone: false,
        },
    )
    .await;
    let _ = recv_msg(&mut stream).await; // Ack

    // SyncStart without VV → full snapshot
    send_msg(
        &mut sink,
        &msg::ClientMsg::SyncStart {
            doc_uuid: "note.md".to_string(),
            client_vv: None,
        },
    )
    .await;

    match recv_msg(&mut stream).await {
        msg::ServerMsg::SyncDelta {
            doc_uuid,
            delta,
            server_vv,
        } => {
            assert_eq!(doc_uuid, "note.md");
            assert!(!delta.is_empty());
            assert!(!server_vv.is_empty());

            // Import and verify content
            let client = LoroDoc::new();
            client.import(&delta).unwrap();
            assert_eq!(client.get_text("content").to_string(), "Hello");
        }
        other => panic!("expected SyncDelta, got {other:?}"),
    }
}

#[tokio::test]
async fn test_ws_sync_start_incremental_delta() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "v1", "key1").await.unwrap();
    let token = get_token(&state.jwt_secret, "v1");

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;

    // Create doc
    let doc = make_doc(42, "Hello");
    let snapshot = doc.export(ExportMode::Snapshot).unwrap();
    let client_vv = doc.oplog_vv();
    send_msg(
        &mut sink,
        &msg::ClientMsg::DocCreate {
            doc_uuid: "note.md".to_string(),
            snapshot,
            peer_id: "42".to_string(),
            replace_tombstone: false,
        },
    )
    .await;
    let _ = recv_msg(&mut stream).await; // Ack

    // Push more content
    doc.get_text("content")
        .update("Hello World", Default::default())
        .unwrap();
    doc.commit();
    let delta = doc.export(ExportMode::updates(&client_vv)).unwrap();
    send_msg(
        &mut sink,
        &msg::ClientMsg::SyncPush {
            doc_uuid: "note.md".to_string(),
            delta,
            peer_id: "42".to_string(),
        },
    )
    .await;
    let _ = recv_msg(&mut stream).await; // Ack

    // SyncStart with old VV → should get incremental delta
    let vv_bytes = crate::vv_serde::vv_to_json_bytes(&client_vv);
    send_msg(
        &mut sink,
        &msg::ClientMsg::SyncStart {
            doc_uuid: "note.md".to_string(),
            client_vv: Some(vv_bytes),
        },
    )
    .await;

    match recv_msg(&mut stream).await {
        msg::ServerMsg::SyncDelta { delta, .. } => {
            // Apply delta to a doc with old state → should get "Hello World"
            let old_doc = make_doc(42, "Hello");
            old_doc.import(&delta).unwrap();
            assert_eq!(old_doc.get_text("content").to_string(), "Hello World");
        }
        other => panic!("expected SyncDelta, got {other:?}"),
    }
}

#[tokio::test]
async fn test_ws_sync_push_and_broadcast() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "v1", "key1").await.unwrap();
    let token = get_token(&state.jwt_secret, "v1");

    // Client A
    let (mut sink_a, mut stream_a) = ws_connect(&addr, &token).await;
    // Client B
    let (sink_b, mut stream_b) = ws_connect(&addr, &token).await;

    // A creates doc
    let doc_a = make_doc(100, "Hello");
    let snapshot = doc_a.export(ExportMode::Snapshot).unwrap();
    send_msg(
        &mut sink_a,
        &msg::ClientMsg::DocCreate {
            doc_uuid: "note.md".to_string(),
            snapshot: snapshot.clone(),
            peer_id: "100".to_string(),
            replace_tombstone: false,
        },
    )
    .await;
    let _ = recv_msg(&mut stream_a).await; // Ack

    // B should receive broadcast
    match recv_msg(&mut stream_b).await {
        msg::ServerMsg::DeltaBroadcast {
            doc_uuid,
            delta,
            peer_id,
            ..
        } => {
            assert_eq!(doc_uuid, "note.md");
            assert_eq!(peer_id, "100");

            let doc_b = LoroDoc::new();
            doc_b.import(&delta).unwrap();
            assert_eq!(doc_b.get_text("content").to_string(), "Hello");
        }
        other => panic!("expected DeltaBroadcast, got {other:?}"),
    }

    // A pushes update
    let vv_before = doc_a.oplog_vv();
    doc_a
        .get_text("content")
        .update("Hello World", Default::default())
        .unwrap();
    doc_a.commit();
    let delta = doc_a.export(ExportMode::updates(&vv_before)).unwrap();
    send_msg(
        &mut sink_a,
        &msg::ClientMsg::SyncPush {
            doc_uuid: "note.md".to_string(),
            delta,
            peer_id: "100".to_string(),
        },
    )
    .await;
    let _ = recv_msg(&mut stream_a).await; // Ack

    // B should receive the update broadcast
    match recv_msg(&mut stream_b).await {
        msg::ServerMsg::DeltaBroadcast {
            doc_uuid,
            delta,
            peer_id,
            ..
        } => {
            assert_eq!(doc_uuid, "note.md");
            assert_eq!(peer_id, "100");
            assert!(!delta.is_empty());
        }
        other => panic!("expected DeltaBroadcast, got {other:?}"),
    }

    // A should NOT receive its own broadcast — verify by sending ping and expecting pong (not a broadcast)
    send_msg(&mut sink_a, &msg::ClientMsg::Ping).await;
    match recv_msg(&mut stream_a).await {
        msg::ServerMsg::Pong => {} // correct — no broadcast echoed
        other => panic!("expected Pong (no self-broadcast), got {other:?}"),
    }

    // Cleanup
    drop(sink_a);
    drop(sink_b);
}

#[tokio::test]
async fn test_ws_concurrent_sync_push_merge() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "v1", "key1").await.unwrap();
    let token = get_token(&state.jwt_secret, "v1");

    let (mut sink_a, mut stream_a) = ws_connect(&addr, &token).await;
    let (mut sink_b, mut stream_b) = ws_connect(&addr, &token).await;

    // Both start from same base
    let base = LoroDoc::new();
    base.set_peer_id(1).unwrap();
    base.get_text("content")
        .update("Hello", Default::default())
        .unwrap();
    base.commit();
    let base_snapshot = base.export(ExportMode::Snapshot).unwrap();
    let base_vv = base.oplog_vv();

    // A creates doc
    send_msg(
        &mut sink_a,
        &msg::ClientMsg::DocCreate {
            doc_uuid: "note.md".to_string(),
            snapshot: base_snapshot.clone(),
            peer_id: "1".to_string(),
            replace_tombstone: false,
        },
    )
    .await;
    let _ = recv_msg(&mut stream_a).await; // Ack
    let _ = recv_msg(&mut stream_b).await; // B gets broadcast

    // A appends " World" at end (pos 5)
    let doc_a = LoroDoc::new();
    doc_a.set_peer_id(100).unwrap();
    doc_a.import(&base_snapshot).unwrap();
    doc_a.get_text("content").insert(5, " World").unwrap();
    doc_a.commit();
    let delta_a = doc_a.export(ExportMode::updates(&base_vv)).unwrap();

    // B inserts "Dear " at start (pos 0)
    let doc_b = LoroDoc::new();
    doc_b.set_peer_id(200).unwrap();
    doc_b.import(&base_snapshot).unwrap();
    doc_b.get_text("content").insert(0, "Dear ").unwrap();
    doc_b.commit();
    let delta_b = doc_b.export(ExportMode::updates(&base_vv)).unwrap();

    // A pushes
    send_msg(
        &mut sink_a,
        &msg::ClientMsg::SyncPush {
            doc_uuid: "note.md".to_string(),
            delta: delta_a.clone(),
            peer_id: "100".to_string(),
        },
    )
    .await;
    let _ = recv_msg(&mut stream_a).await; // Ack

    // B pushes
    send_msg(
        &mut sink_b,
        &msg::ClientMsg::SyncPush {
            doc_uuid: "note.md".to_string(),
            delta: delta_b.clone(),
            peer_id: "200".to_string(),
        },
    )
    .await;

    // B may get A's broadcast before its own Ack — drain until we see Ack
    loop {
        match recv_msg(&mut stream_b).await {
            msg::ServerMsg::Ack => break,
            msg::ServerMsg::DeltaBroadcast { .. } => continue, // A's broadcast
            other => panic!("unexpected from B: {other:?}"),
        }
    }

    // Verify server has merged both
    let (snap, _) = db::get_snapshot_with_vv(&state.db, "v1", "note.md")
        .await
        .unwrap()
        .unwrap();
    let server_doc = LoroDoc::new();
    server_doc.import(&snap).unwrap();
    let content = server_doc.get_text("content").to_string();

    // Both edits should be present in the merged content
    assert!(content.contains("World"), "missing A's edit: {content}");
    assert!(content.contains("Dear"), "missing B's edit: {content}");
}

#[tokio::test]
async fn test_ws_doc_delete_and_broadcast() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "v1", "key1").await.unwrap();
    let token = get_token(&state.jwt_secret, "v1");

    let (mut sink_a, mut stream_a) = ws_connect(&addr, &token).await;
    let (_sink_b, mut stream_b) = ws_connect(&addr, &token).await;

    // A creates doc
    let doc = make_doc(42, "content");
    let snapshot = doc.export(ExportMode::Snapshot).unwrap();
    send_msg(
        &mut sink_a,
        &msg::ClientMsg::DocCreate {
            doc_uuid: "note.md".to_string(),
            snapshot,
            peer_id: "42".to_string(),
            replace_tombstone: false,
        },
    )
    .await;
    let _ = recv_msg(&mut stream_a).await; // Ack
    let _ = recv_msg(&mut stream_b).await; // B gets create broadcast

    // A deletes doc
    send_msg(
        &mut sink_a,
        &msg::ClientMsg::DocDelete {
            doc_uuid: "note.md".to_string(),
            peer_id: "peer-a".to_string(),
        },
    )
    .await;
    match recv_msg(&mut stream_a).await {
        msg::ServerMsg::Ack => {}
        other => panic!("expected Ack, got {other:?}"),
    }

    // B should receive DocDeleted
    match recv_msg(&mut stream_b).await {
        msg::ServerMsg::DocDeleted { doc_uuid } => {
            assert_eq!(doc_uuid, "note.md");
        }
        other => panic!("expected DocDeleted, got {other:?}"),
    }

    // Doc should be gone, tombstone should exist
    assert!(
        db::get_snapshot_with_vv(&state.db, "v1", "note.md")
            .await
            .unwrap()
            .is_none()
    );
    let tombs = db::list_tombstones(&state.db, "v1").await.unwrap();
    assert_eq!(tombs, vec!["note.md"]);
}

#[tokio::test]
async fn test_ws_vault_isolation() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "vault-a", "key-a")
        .await
        .unwrap();
    db::create_vault(&state.db, "vault-b", "key-b")
        .await
        .unwrap();

    let token_a = get_token(&state.jwt_secret, "vault-a");
    let token_b = get_token(&state.jwt_secret, "vault-b");

    let (mut sink_a, mut stream_a) = ws_connect(&addr, &token_a).await;
    let (mut sink_b, mut stream_b) = ws_connect(&addr, &token_b).await;

    // A creates doc
    let doc = make_doc(42, "secret");
    let snapshot = doc.export(ExportMode::Snapshot).unwrap();
    send_msg(
        &mut sink_a,
        &msg::ClientMsg::DocCreate {
            doc_uuid: "note.md".to_string(),
            snapshot,
            peer_id: "42".to_string(),
            replace_tombstone: false,
        },
    )
    .await;
    let _ = recv_msg(&mut stream_a).await; // Ack

    // B should NOT receive broadcast — verify by ping/pong
    send_msg(&mut sink_b, &msg::ClientMsg::Ping).await;
    match recv_msg(&mut stream_b).await {
        msg::ServerMsg::Pong => {} // good — no cross-vault leak
        other => panic!("expected Pong, got cross-vault broadcast: {other:?}"),
    }

    // B's doc list should be empty
    send_msg(&mut sink_b, &msg::ClientMsg::RequestDocList).await;
    match recv_msg(&mut stream_b).await {
        msg::ServerMsg::DocList { docs, .. } => assert!(docs.is_empty()),
        other => panic!("expected empty DocList, got {other:?}"),
    }
}

#[tokio::test]
async fn test_ws_invalid_token_rejected() {
    let (addr, _state) = spawn_server().await;

    let (mut sink, mut stream) = ws_connect_raw(&addr).await;
    send_msg(
        &mut sink,
        &msg::ClientMsg::Auth {
            token: "invalid-jwt".into(),
            protocol_version: 1,
        },
    )
    .await;
    assert_eq!(
        expect_close(&mut stream, None).await,
        (1008, "auth_invalid".into())
    );
}

#[tokio::test]
async fn test_ws_connection_tracking() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "v1", "key1").await.unwrap();
    let token = get_token(&state.jwt_secret, "v1");

    assert_eq!(state.connections.lock().unwrap().len(), 0);

    let (sink, _stream) = ws_connect(&addr, &token).await;

    // Give server a moment to register
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(state.connections.lock().unwrap().len(), 1);

    // Disconnect
    drop(sink);
    drop(_stream);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(state.connections.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn test_ws_corrupted_loro_delta_returns_error() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "v1", "key1").await.unwrap();
    let token = get_token(&state.jwt_secret, "v1");

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;

    // Create a doc first
    let doc = make_doc(42, "Hello");
    let snapshot = doc.export(ExportMode::Snapshot).unwrap();
    send_msg(
        &mut sink,
        &msg::ClientMsg::DocCreate {
            doc_uuid: "note.md".to_string(),
            snapshot,
            peer_id: "42".to_string(),
            replace_tombstone: false,
        },
    )
    .await;
    let _ = recv_msg(&mut stream).await; // Ack

    // Push a corrupted delta (valid msgpack, invalid Loro bytes)
    send_msg(
        &mut sink,
        &msg::ClientMsg::SyncPush {
            doc_uuid: "note.md".to_string(),
            delta: vec![0xDE, 0xAD, 0xBE, 0xEF],
            peer_id: "42".to_string(),
        },
    )
    .await;

    match recv_msg(&mut stream).await {
        msg::ServerMsg::Error { code, message } => {
            assert_eq!(code, "sync_failed");
            assert!(!message.contains("loro"));
            assert_eq!(message, "document could not be processed — not synced");
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn test_ws_invalid_msgpack_returns_error() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "v1", "key1").await.unwrap();
    let token = get_token(&state.jwt_secret, "v1");

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;

    // Send garbage binary
    sink.send(Message::Binary(vec![0xFF, 0xFE, 0xFD].into()))
        .await
        .unwrap();

    match recv_msg(&mut stream).await {
        msg::ServerMsg::Error { code, message } => {
            assert_eq!(code, "bad_frame");
            assert!(!message.contains("msgpack"));
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn test_ws_full_lifecycle() {
    let (addr, state) = spawn_server().await;
    db::create_vault(&state.db, "v1", "key1").await.unwrap();
    let token = get_token(&state.jwt_secret, "v1");

    let (mut sink, mut stream) = ws_connect(&addr, &token).await;

    // 1. Empty doc list
    send_msg(&mut sink, &msg::ClientMsg::RequestDocList).await;
    match recv_msg(&mut stream).await {
        msg::ServerMsg::DocList { docs, tombstones } => {
            assert!(docs.is_empty());
            assert!(tombstones.is_empty());
        }
        other => panic!("step 1: {other:?}"),
    }

    // 2. Create doc
    let doc = make_doc(42, "Initial");
    let snapshot = doc.export(ExportMode::Snapshot).unwrap();
    send_msg(
        &mut sink,
        &msg::ClientMsg::DocCreate {
            doc_uuid: "test.md".to_string(),
            snapshot,
            peer_id: "42".to_string(),
            replace_tombstone: false,
        },
    )
    .await;
    assert!(matches!(recv_msg(&mut stream).await, msg::ServerMsg::Ack));

    // 3. Push update
    let vv = doc.oplog_vv();
    doc.get_text("content")
        .update("Initial + edit", Default::default())
        .unwrap();
    doc.commit();
    let delta = doc.export(ExportMode::updates(&vv)).unwrap();
    send_msg(
        &mut sink,
        &msg::ClientMsg::SyncPush {
            doc_uuid: "test.md".to_string(),
            delta,
            peer_id: "42".to_string(),
        },
    )
    .await;
    assert!(matches!(recv_msg(&mut stream).await, msg::ServerMsg::Ack));

    // 4. SyncStart → should get updated content
    send_msg(
        &mut sink,
        &msg::ClientMsg::SyncStart {
            doc_uuid: "test.md".to_string(),
            client_vv: None,
        },
    )
    .await;
    match recv_msg(&mut stream).await {
        msg::ServerMsg::SyncDelta { delta, .. } => {
            let verify = LoroDoc::new();
            verify.import(&delta).unwrap();
            assert_eq!(verify.get_text("content").to_string(), "Initial + edit");
        }
        other => panic!("step 4: {other:?}"),
    }

    // 5. Delete doc
    send_msg(
        &mut sink,
        &msg::ClientMsg::DocDelete {
            doc_uuid: "test.md".to_string(),
            peer_id: "peer-1".to_string(),
        },
    )
    .await;
    assert!(matches!(recv_msg(&mut stream).await, msg::ServerMsg::Ack));

    // 6. Verify tombstone in doc list
    send_msg(&mut sink, &msg::ClientMsg::RequestDocList).await;
    match recv_msg(&mut stream).await {
        msg::ServerMsg::DocList { docs, tombstones } => {
            assert!(docs.is_empty());
            assert_eq!(tombstones, vec!["test.md"]);
        }
        other => panic!("step 6: {other:?}"),
    }
}
