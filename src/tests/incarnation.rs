//! ADR-0006 implementation brief §6: acceptance groups 2–12.
use super::{exec, loro_snapshot_with_content, scalar, test_db, test_state};
use crate::{
    BroadcastEvent, DocLocks, db,
    errors::ServerError,
    handlers::process_message,
    ws::msg::{ClientMsg, ServerMsg},
};
use futures_util::{SinkExt, StreamExt};
use loro::{ExportMode, LoroDoc};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::{connect_async, tungstenite::Message};

fn create(path: &str, snapshot: Vec<u8>, replace: bool, request: Option<&str>) -> ClientMsg {
    ClientMsg::DocCreate {
        doc_uuid: path.into(),
        snapshot,
        peer_id: "p".into(),
        replace_tombstone: replace,
        request_id: request.map(str::to_owned),
    }
}

fn push(path: &str, delta: Vec<u8>, request: Option<&str>) -> ClientMsg {
    ClientMsg::SyncPush {
        doc_uuid: path.into(),
        delta,
        peer_id: "p".into(),
        request_id: request.map(str::to_owned),
    }
}

fn delete(
    path: &str,
    expected: Option<i64>,
    intent: Option<&str>,
    request: Option<&str>,
) -> ClientMsg {
    ClientMsg::DocDelete {
        doc_uuid: path.into(),
        peer_id: "p".into(),
        expected_incarnation: expected,
        intent_id: intent.map(str::to_owned),
        request_id: request.map(str::to_owned),
    }
}

fn ack(response: ServerMsg, token: Option<i64>, request: Option<&str>) {
    match response {
        ServerMsg::Ack {
            incarnation,
            request_id,
        } => {
            assert_eq!(incarnation, token);
            assert_eq!(request_id.as_deref(), request);
        }
        other => panic!("expected Ack, got {other:?}"),
    }
}

fn grant(response: ServerMsg, request: Option<&str>) -> i64 {
    match response {
        ServerMsg::Ack {
            incarnation: Some(token),
            request_id,
        } => {
            assert!(token > 0, "0 MUST NOT be allocated");
            assert_eq!(request_id.as_deref(), request);
            token
        }
        other => panic!("expected establishing Ack, got {other:?}"),
    }
}

async fn process(db: &db::Db, message: ClientMsg) -> (ServerMsg, Option<BroadcastEvent>) {
    process_message(
        &rmp_serde::to_vec_named(&message).unwrap(),
        db,
        "v",
        1,
        &DocLocks::default(),
    )
    .await
}

#[tokio::test]
async fn g02_allocation_matrix() {
    let db = test_db().await;
    let (snapshot, _) = loro_snapshot_with_content("same");
    let k = grant(
        process(&db, create("a", snapshot.clone(), false, None))
            .await
            .0,
        None,
    );
    let second = grant(
        process(&db, create("b", snapshot.clone(), false, None))
            .await
            .0,
        None,
    );
    assert_eq!((k, second), (1, 2));
    let next_before: i64 = scalar(
        &db,
        "SELECT next_incarnation FROM vault_incarnation WHERE vault_id='v'",
    )
    .await;
    ack(
        process(&db, delete("a", Some(k), None, None)).await.0,
        None,
        None,
    );
    assert_eq!(
        scalar::<i64>(
            &db,
            "SELECT next_incarnation FROM vault_incarnation WHERE vault_id='v'"
        )
        .await,
        next_before
    );
    let replaced = grant(
        process(&db, create("a", snapshot.clone(), true, None))
            .await
            .0,
        None,
    );
    assert_eq!(replaced, 3);
    db::tombstone(&db, "v", "a", "stale").await.unwrap();
    let rotated = grant(
        process(&db, create("a", snapshot.clone(), true, None))
            .await
            .0,
        None,
    );
    assert_eq!(rotated, 4);
    assert!(!db::is_tombstoned(&db, "v", "a").await.unwrap());
    let doc = LoroDoc::new();
    doc.import(&snapshot).unwrap();
    let established_push = grant(
        process(&db, push("c", snapshot.clone(), None)).await.0,
        None,
    );
    assert_eq!(established_push, 5);
    let vv = doc.oplog_vv();
    doc.get_text("content").insert(4, "-update").unwrap();
    ack(
        process(
            &db,
            push("c", doc.export(ExportMode::updates(&vv)).unwrap(), None),
        )
        .await
        .0,
        None,
        None,
    );
    // Ordinary create, including replace=true without a tombstone, MUST keep the token.
    ack(
        process(
            &db,
            create("c", doc.export(ExportMode::Snapshot).unwrap(), true, None),
        )
        .await
        .0,
        None,
        None,
    );
    assert_eq!(
        scalar::<i64>(&db, "SELECT incarnation FROM documents WHERE doc_uuid='c'").await,
        established_push
    );
    assert_eq!(
        scalar::<i64>(
            &db,
            "SELECT next_incarnation FROM vault_incarnation WHERE vault_id='v'"
        )
        .await,
        6
    );
    assert!(
        [k, second, replaced, rotated, established_push]
            .iter()
            .all(|token| *token > 0)
    );
    assert_eq!(
        scalar::<i64>(&db, "SELECT COUNT(*) FROM documents WHERE incarnation <= 0").await,
        0
    );
    assert_eq!(
        db::store_snapshot_with_vv(&db, "other", "a", b"snap", b"vv")
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn g02_allocation_rolls_back_with_establishing_transaction() {
    let db = test_db().await;
    exec(&db, "CREATE TRIGGER fail_store BEFORE INSERT ON documents BEGIN SELECT RAISE(ABORT, 'test failure'); END;").await;
    assert!(
        db::store_snapshot_with_vv(&db, "v", "a", b"snap", b"vv")
            .await
            .is_err()
    );
    assert_eq!(
        scalar::<i64>(&db, "SELECT COUNT(*) FROM vault_incarnation").await,
        0
    );
    exec(&db, "DROP TRIGGER fail_store;").await;
    let k = db::store_snapshot_with_vv(&db, "v", "a", b"snap", b"vv")
        .await
        .unwrap();
    db::tombstone(&db, "v", "a", "p").await.unwrap();
    exec(&db, "CREATE TRIGGER fail_clear BEFORE DELETE ON tombstones BEGIN SELECT RAISE(ABORT, 'test failure'); END;").await;
    assert!(
        db::store_snapshot_replacing_tombstone(&db, "v", "a", b"new", b"newvv")
            .await
            .is_err()
    );
    assert_eq!(
        db::get_snapshot_with_vv(&db, "v", "a")
            .await
            .unwrap()
            .unwrap(),
        (b"snap".to_vec(), b"vv".to_vec())
    );
    assert_eq!(
        scalar::<i64>(&db, "SELECT incarnation FROM documents").await,
        k
    );
    assert_eq!(
        scalar::<i64>(&db, "SELECT next_incarnation FROM vault_incarnation").await,
        k + 1
    );
    assert!(db::is_tombstoned(&db, "v", "a").await.unwrap());
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
struct Server {
    address: String,
    state: crate::AppState,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start() -> Self {
        let state = test_state(test_db().await);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("ws://{}/ws", listener.local_addr().unwrap());
        let router = crate::build_router(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            address,
            state,
            task,
        }
    }
    async fn connect(&self) -> (Socket, ServerMsg) {
        let (mut socket, _) = connect_async(&self.address).await.unwrap();
        let token = crate::auth::jwt_sign("v", &self.state.jwt_secret).unwrap();
        // Old Auth shape: no features field.
        send(
            &mut socket,
            &serde_json::json!({"type":"auth", "token":token, "protocol_version":1}),
        )
        .await;
        let response = receive(&mut socket).await;
        assert!(matches!(
            response,
            ServerMsg::AuthOk {
                protocol_version: 1,
                ..
            }
        ));
        // A processed Ping proves this connection has subscribed before writes begin.
        send(&mut socket, &ClientMsg::Ping).await;
        assert!(matches!(receive(&mut socket).await, ServerMsg::Pong));
        (socket, response)
    }
}

async fn send(socket: &mut Socket, value: &impl Serialize) {
    socket
        .send(Message::Binary(
            rmp_serde::to_vec_named(value).unwrap().into(),
        ))
        .await
        .unwrap();
}
async fn receive(socket: &mut Socket) -> ServerMsg {
    let event = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    match event {
        Message::Binary(bytes) => rmp_serde::from_slice(&bytes).unwrap(),
        other => panic!("expected binary message: {other:?}"),
    }
}
async fn no_event(socket: &mut Socket) {
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), socket.next())
            .await
            .is_err(),
        "rejection MUST NOT produce a broadcast"
    );
    send(socket, &ClientMsg::Ping).await;
    assert!(matches!(receive(socket).await, ServerMsg::Pong));
}
fn delta_broadcast(response: ServerMsg, path: &str, token: Option<i64>) {
    match response {
        ServerMsg::DeltaBroadcast {
            doc_uuid,
            incarnation,
            ..
        } => {
            assert_eq!(doc_uuid, path);
            assert_eq!(incarnation, token);
        }
        other => panic!("expected DeltaBroadcast: {other:?}"),
    }
}
fn rejected(response: ServerMsg, path: &str, intent: Option<&str>, request: Option<&str>) {
    match response {
        ServerMsg::DeleteRejected {
            doc_uuid,
            intent_id,
            request_id,
        } => {
            assert_eq!(doc_uuid, path);
            assert_eq!(intent_id.as_deref(), intent);
            assert_eq!(request_id.as_deref(), request);
        }
        other => panic!("expected DeleteRejected: {other:?}"),
    }
}

#[tokio::test]
async fn g03_same_text_recreation_rejects_stale_delete_requester_only() {
    let server = Server::start().await;
    let (mut a, _) = server.connect().await;
    let (mut b, _) = server.connect().await;
    for (path, text) in [("same.md", "identical text"), ("empty.md", "")] {
        let (snapshot, _) = loro_snapshot_with_content(text);
        send(
            &mut a,
            &create(path, snapshot.clone(), false, Some("create")),
        )
        .await;
        let k = grant(receive(&mut a).await, Some("create"));
        delta_broadcast(receive(&mut b).await, path, Some(k));
        send(&mut a, &delete(path, Some(k), Some("D1"), Some("delete"))).await;
        ack(receive(&mut a).await, None, Some("delete"));
        match receive(&mut b).await {
            ServerMsg::DocDeleted {
                doc_uuid,
                content_hash,
            } => {
                assert_eq!(doc_uuid, path);
                assert_eq!(content_hash, Some(crate::fnv::fnv1a_64_hex(text)));
            }
            other => panic!("expected DocDeleted: {other:?}"),
        }
        send(&mut a, &create(path, snapshot, true, Some("recreate"))).await;
        let j = grant(receive(&mut a).await, Some("recreate"));
        assert!(j > k);
        delta_broadcast(receive(&mut b).await, path, Some(j));
        send(&mut a, &delete(path, Some(k), Some("D1"), Some("stale"))).await;
        rejected(receive(&mut a).await, path, Some("D1"), Some("stale"));
        send(&mut a, &ClientMsg::RequestDocList).await;
        match receive(&mut a).await {
            ServerMsg::DocList {
                docs, tombstones, ..
            } => {
                assert_eq!(
                    docs.iter()
                        .find(|d| d.doc_uuid == path)
                        .unwrap()
                        .incarnation,
                    Some(j)
                );
                assert!(!tombstones.iter().any(|d| d == path));
            }
            other => panic!("expected DocList: {other:?}"),
        }
        let (snapshot, _) = db::get_snapshot_with_vv(&server.state.db, "v", path)
            .await
            .unwrap()
            .unwrap();
        let stored = LoroDoc::new();
        stored.import(&snapshot).unwrap();
        assert_eq!(stored.get_text("content").to_string(), text);
        no_event(&mut b).await;
    }
}

#[tokio::test]
async fn g04_absence_race() {
    let db = test_db().await;
    let (response, broadcast) =
        process(&db, delete("a", Some(0), Some("absent"), Some("r0"))).await;
    ack(response, None, Some("r0"));
    assert!(matches!(
        broadcast,
        Some(BroadcastEvent::Delete {
            content_hash: None,
            ..
        })
    ));
    assert!(db::is_tombstoned(&db, "v", "a").await.unwrap());
    assert_eq!(
        scalar::<i64>(&db, "SELECT incarnation FROM tombstones").await,
        1
    );
    assert_eq!(
        scalar::<i64>(&db, "SELECT COUNT(*) FROM vault_incarnation").await,
        0
    );
    let (snapshot, _) = loro_snapshot_with_content("raced create");
    let k = grant(
        process(&db, create("a", snapshot, true, None)).await.0,
        None,
    );
    let before = db::get_snapshot_with_vv(&db, "v", "a").await.unwrap();
    let (response, broadcast) =
        process(&db, delete("a", Some(0), Some("absent"), Some("r1"))).await;
    rejected(response, "a", Some("absent"), Some("r1"));
    assert!(broadcast.is_none());
    assert_eq!(
        db::get_snapshot_with_vv(&db, "v", "a").await.unwrap(),
        before
    );
    assert_eq!(
        scalar::<i64>(&db, "SELECT incarnation FROM documents").await,
        k
    );
    assert!(!db::is_tombstoned(&db, "v", "a").await.unwrap());
}

async fn row_state(db: &db::Db) -> (String, String, String) {
    (
        scalar(db, "SELECT COALESCE(json_group_array(json_array(vault_id,doc_uuid,hex(snapshot_blob),hex(vv_blob),updated_at,incarnation)), '[]') FROM documents").await,
        scalar(db, "SELECT COALESCE(json_group_array(json_array(vault_id,doc_uuid,deleted_by,deleted_at,content_hash,incarnation)), '[]') FROM tombstones").await,
        scalar(db, "SELECT COALESCE(json_group_array(json_array(vault_id,next_incarnation)), '[]') FROM vault_incarnation").await,
    )
}

#[tokio::test]
async fn g05_delete_semantics_matrix() {
    use db::DeleteOutcome::*;
    let db = test_db().await;
    let (snapshot, vv) = loro_snapshot_with_content("vaultcrdt fnv golden");
    let k = db::store_snapshot_with_vv(&db, "v", "a", &snapshot, &vv)
        .await
        .unwrap();
    // A pre-existing stale tombstone MUST also remain byte-for-byte unchanged on rejection.
    db::tombstone(&db, "v", "a", "old-peer").await.unwrap();
    exec(
        &db,
        "UPDATE tombstones SET deleted_at='2000-01-01 00:00:00', content_hash='old-hash'",
    )
    .await;
    let before = row_state(&db).await;
    for expected in [Some(k + 1), Some(0)] {
        assert_eq!(
            db::delete_doc_guarded(&db, "v", "a", "p", expected)
                .await
                .unwrap(),
            Rejected {
                live_incarnation: k
            }
        );
        assert_eq!(row_state(&db).await, before);
    }
    assert_eq!(
        db::delete_doc_guarded(&db, "v", "a", "p", Some(k))
            .await
            .unwrap(),
        Deleted {
            content_hash: Some("a6a9b25f2a464e61".into()),
            incarnation: k
        }
    );
    assert!(
        db::get_snapshot_with_vv(&db, "v", "a")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        scalar::<i64>(&db, "SELECT incarnation FROM tombstones").await,
        k
    );
    assert_eq!(
        scalar::<String>(&db, "SELECT content_hash FROM tombstones").await,
        "a6a9b25f2a464e61"
    );
    let before = row_state(&db).await;
    // Both tombstoned and never-existing paths reject positive attestations.
    for path in ["a", "never"] {
        assert_eq!(
            db::delete_doc_guarded(&db, "v", path, "p", Some(k))
                .await
                .unwrap(),
            Rejected {
                live_incarnation: 0
            }
        );
        assert_eq!(row_state(&db).await, before);
    }
    for expected in [Some(0), None] {
        assert_eq!(
            db::delete_doc_guarded(&db, "v", "a", "replay", expected)
                .await
                .unwrap(),
            IdempotentNoLive {
                content_hash: Some("a6a9b25f2a464e61".into())
            }
        );
        assert_eq!(
            scalar::<i64>(&db, "SELECT incarnation FROM tombstones WHERE doc_uuid='a'").await,
            k
        );
        assert_eq!(
            db::delete_doc_guarded(&db, "v", "never", "p", expected)
                .await
                .unwrap(),
            IdempotentNoLive { content_hash: None }
        );
    }
    let j = db::store_snapshot_replacing_tombstone(&db, "v", "a", &snapshot, &vv)
        .await
        .unwrap();
    assert!(j > k);
    assert_eq!(
        db::delete_doc_guarded(&db, "v", "a", "legacy", None)
            .await
            .unwrap(),
        Deleted {
            content_hash: Some("a6a9b25f2a464e61".into()),
            incarnation: j
        }
    );
    // Replay must retain j, not the default backfill token 1.
    assert!(matches!(
        db::delete_doc_guarded(&db, "v", "a", "legacy", None)
            .await
            .unwrap(),
        IdempotentNoLive { .. }
    ));
    assert_eq!(
        scalar::<i64>(&db, "SELECT incarnation FROM tombstones WHERE doc_uuid='a'").await,
        j
    );
    assert_eq!(
        scalar::<i64>(&db, "SELECT next_incarnation FROM vault_incarnation").await,
        j + 1
    );
}

#[tokio::test]
async fn g05_delete_mutation_rolls_back_on_tombstone_failure() {
    let db = test_db().await;
    let k = db::store_snapshot_with_vv(&db, "v", "a", b"snap", b"vv")
        .await
        .unwrap();
    exec(&db, "CREATE TRIGGER fail_delete BEFORE INSERT ON tombstones BEGIN SELECT RAISE(ABORT, 'test failure'); END;").await;
    let before = row_state(&db).await;
    assert!(
        db::delete_doc_guarded(&db, "v", "a", "p", Some(k))
            .await
            .is_err()
    );
    assert_eq!(row_state(&db).await, before);
}

#[tokio::test]
async fn g06_request_id_echo_on_ack_and_error() {
    let server = Server::start().await;
    let (mut socket, _) = server.connect().await;
    let (snapshot, _) = loro_snapshot_with_content("echo");
    send(
        &mut socket,
        &create("a", snapshot.clone(), false, Some("c")),
    )
    .await;
    let k = grant(receive(&mut socket).await, Some("c"));
    send(&mut socket, &push("b", snapshot.clone(), Some("p"))).await;
    let j = grant(receive(&mut socket).await, Some("p"));
    assert!(j > k);
    let doc = LoroDoc::new();
    doc.import(&snapshot).unwrap();
    let vv = doc.oplog_vv();
    doc.get_text("content").insert(4, "!").unwrap();
    send(
        &mut socket,
        &push(
            "b",
            doc.export(ExportMode::updates(&vv)).unwrap(),
            Some("update"),
        ),
    )
    .await;
    ack(receive(&mut socket).await, None, Some("update"));
    send(&mut socket, &delete("a", Some(k), Some("D"), Some("d"))).await;
    ack(receive(&mut socket).await, None, Some("d"));
    // Validation and dispatch errors MUST retain parsed request_id, for every carrier.
    for (kind, payload) in [
        ("doc_create", "snapshot"),
        ("sync_push", "delta"),
        ("doc_delete", "unused"),
    ] {
        let mut frame = serde_json::json!({"type":kind,"doc_uuid":"error","peer_id":"p".repeat(129),"request_id":"error-echo"});
        if kind != "doc_delete" {
            frame[payload] = serde_json::json!([]);
        }
        send(&mut socket, &frame).await;
        match receive(&mut socket).await {
            ServerMsg::Error {
                code, request_id, ..
            } => {
                assert_eq!(code, "bad_frame");
                assert_eq!(request_id.as_deref(), Some("error-echo"));
            }
            other => panic!("expected Error: {other:?}"),
        }
    }
    for frame in [
        create("bad-create", vec![1, 2, 3], false, Some("bad-loro")),
        push("bad-push", vec![1, 2, 3], Some("bad-loro")),
    ] {
        send(&mut socket, &frame).await;
        assert!(
            matches!(receive(&mut socket).await, ServerMsg::Error { code, request_id: Some(id), .. } if code == "sync_failed" && id == "bad-loro")
        );
    }
    // An unparseable frame has no correlation value to echo.
    socket
        .send(Message::Binary(vec![0xc1].into()))
        .await
        .unwrap();
    assert!(matches!(
        receive(&mut socket).await,
        ServerMsg::Error {
            request_id: None,
            ..
        }
    ));
    // Old Error path, physically missing request_id.
    send(
        &mut socket,
        &serde_json::json!({"type":"doc_delete","doc_uuid":"a","peer_id":"p".repeat(129)}),
    )
    .await;
    assert!(matches!(
        receive(&mut socket).await,
        ServerMsg::Error {
            request_id: None,
            ..
        }
    ));
}

#[tokio::test]
async fn g06_identifier_caps_every_carrier_utf8_bytes() {
    let db = test_db().await;
    let (snapshot, _) = loro_snapshot_with_content("caps");
    for (case, value) in [
        "x".repeat(128),
        "ä".repeat(64),
        "x".repeat(129),
        "ä".repeat(65),
    ]
    .into_iter()
    .enumerate()
    {
        for kind in ["create", "push", "delete-request", "delete-intent"] {
            let path = format!("{kind}-{case}");
            let message = match kind {
                "create" => create(&path, snapshot.clone(), false, Some(&value)),
                "push" => push(&path, snapshot.clone(), Some(&value)),
                "delete-request" => delete(&path, Some(0), None, Some(&value)),
                _ => delete(&path, Some(0), Some(&value), Some("echo")),
            };
            let before = row_state(&db).await;
            let (response, broadcast) = process(&db, message).await;
            if value.len() > 128 {
                match response {
                    ServerMsg::Error {
                        code, request_id, ..
                    } => {
                        assert_eq!(code, "bad_frame");
                        assert_eq!(
                            request_id.as_deref(),
                            Some(if kind == "delete-intent" {
                                "echo"
                            } else {
                                &value
                            })
                        );
                    }
                    other => panic!("expected BadFrame: {other:?}"),
                }
                assert!(broadcast.is_none());
                assert_eq!(row_state(&db).await, before);
            } else {
                assert!(matches!(response, ServerMsg::Ack { .. }));
                assert!(broadcast.is_some());
            }
        }
    }
}

// Frozen e221571 named-msgpack message definitions. These fixtures MUST NOT gain
// incarnation, correlation, or capability fields when production enums evolve.
mod frozen {
    use super::*;
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum ClientMsg {
        Auth {
            token: String,
            protocol_version: u32,
            #[serde(default)]
            features: Vec<String>,
        },
        Ping,
        RequestDocList,
        SyncStart {
            doc_uuid: String,
            #[serde(with = "serde_bytes", default)]
            client_vv: Option<Vec<u8>>,
        },
        SyncPush {
            doc_uuid: String,
            #[serde(with = "serde_bytes")]
            delta: Vec<u8>,
            peer_id: String,
        },
        DocCreate {
            doc_uuid: String,
            #[serde(with = "serde_bytes")]
            snapshot: Vec<u8>,
            peer_id: String,
            #[serde(default)]
            replace_tombstone: bool,
        },
        DocDelete {
            doc_uuid: String,
            peer_id: String,
        },
    }
    #[derive(Debug, Serialize, Deserialize)]
    pub struct DocEntry {
        pub doc_uuid: String,
        pub updated_at: String,
        #[serde(with = "serde_bytes")]
        pub server_vv: Vec<u8>,
    }
    #[derive(Debug, Serialize, Deserialize)]
    pub struct TombstoneHash {
        pub doc_uuid: String,
        pub content_hash: Option<String>,
    }
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum ServerMsg {
        AuthOk {
            protocol_version: u32,
        },
        Pong,
        Ack,
        Error {
            code: String,
            message: String,
        },
        DocList {
            docs: Vec<DocEntry>,
            tombstones: Vec<String>,
            tombstone_hashes: Vec<TombstoneHash>,
        },
        SyncDelta {
            doc_uuid: String,
            #[serde(with = "serde_bytes")]
            delta: Vec<u8>,
            #[serde(with = "serde_bytes")]
            server_vv: Vec<u8>,
        },
        DocUnknown {
            doc_uuid: String,
        },
        DeltaBroadcast {
            doc_uuid: String,
            #[serde(with = "serde_bytes")]
            delta: Vec<u8>,
            peer_id: String,
            #[serde(with = "serde_bytes")]
            server_vv: Vec<u8>,
        },
        DocDeleted {
            doc_uuid: String,
            #[serde(default)]
            content_hash: Option<String>,
        },
        DocTombstoned {
            doc_uuid: String,
        },
        CreateConflict {
            doc_uuid: String,
        },
        BlobPathChanged {
            path_key: String,
            seq: i64,
        },
    }
}

#[tokio::test]
async fn g07_legacy_frames_and_capability_advertisement() {
    let server = Server::start().await;
    let (mut a, auth) = server.connect().await;
    match auth {
        ServerMsg::AuthOk {
            protocol_version,
            capabilities,
        } => {
            assert_eq!(protocol_version, 1);
            assert!(
                capabilities
                    .unwrap()
                    .iter()
                    .any(|cap| cap == "delete_incarnation")
            );
        }
        other => panic!("expected AuthOk: {other:?}"),
    }
    let (mut b, _) = server.connect().await;
    let (snapshot, _) = loro_snapshot_with_content("legacy");
    for frame in [
        frozen::ClientMsg::DocCreate {
            doc_uuid: "create".into(),
            snapshot: snapshot.clone(),
            peer_id: "p".into(),
            replace_tombstone: false,
        },
        frozen::ClientMsg::SyncPush {
            doc_uuid: "push".into(),
            delta: snapshot,
            peer_id: "p".into(),
        },
    ] {
        let encoded = rmp_serde::to_vec_named(&frame).unwrap();
        assert!(matches!(
            rmp_serde::from_slice::<ClientMsg>(&encoded).unwrap(),
            ClientMsg::DocCreate {
                request_id: None,
                ..
            } | ClientMsg::SyncPush {
                request_id: None,
                ..
            }
        ));
        send(&mut a, &frame).await;
        let token = grant(receive(&mut a).await, None);
        assert!(
            matches!(receive(&mut b).await, ServerMsg::DeltaBroadcast { incarnation: Some(t), .. } if t == token)
        );
    }
    let frame = frozen::ClientMsg::DocDelete {
        doc_uuid: "create".into(),
        peer_id: "old".into(),
    };
    let bytes = rmp_serde::to_vec_named(&frame).unwrap();
    assert!(matches!(
        rmp_serde::from_slice::<ClientMsg>(&bytes).unwrap(),
        ClientMsg::DocDelete {
            expected_incarnation: None,
            request_id: None,
            intent_id: None,
            ..
        }
    ));
    // A legacy delete, including a replay, MUST produce Ack + DocDeleted, never DeleteRejected.
    for _ in 0..2 {
        send(&mut a, &frame).await;
        ack(receive(&mut a).await, None, None);
        match receive(&mut b).await {
            ServerMsg::DocDeleted {
                doc_uuid,
                content_hash,
            } => {
                assert_eq!(doc_uuid, "create");
                assert_eq!(content_hash, Some(crate::fnv::fnv1a_64_hex("legacy")));
            }
            other => panic!("expected legacy Delete broadcast: {other:?}"),
        }
    }
    assert!(
        db::get_snapshot_with_vv(&server.state.db, "v", "create")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn g08_observability_surfaces() {
    let server = Server::start().await;
    let (mut a, _) = server.connect().await;
    let (mut b, _) = server.connect().await;
    // Exercise both write handlers, both SyncStart branches, and the conservative rotation.
    for path in ["create", "push"] {
        let (snapshot, _) = loro_snapshot_with_content("surface");
        let message = if path == "create" {
            create(path, snapshot.clone(), false, None)
        } else {
            push(path, snapshot.clone(), None)
        };
        send(&mut a, &message).await;
        let k = grant(receive(&mut a).await, None);
        delta_broadcast(receive(&mut b).await, path, Some(k));
        let doc = LoroDoc::new();
        doc.import(&snapshot).unwrap();
        let vv = doc.oplog_vv();
        doc.get_text("content").insert(7, "!").unwrap();
        let message = if path == "create" {
            create(path, doc.export(ExportMode::Snapshot).unwrap(), false, None)
        } else {
            push(path, doc.export(ExportMode::updates(&vv)).unwrap(), None)
        };
        send(&mut a, &message).await;
        ack(receive(&mut a).await, None, None);
        delta_broadcast(receive(&mut b).await, path, None);
        send(&mut a, &ClientMsg::RequestDocList).await;
        match receive(&mut a).await {
            ServerMsg::DocList { docs, .. } => assert_eq!(
                docs.iter()
                    .find(|d| d.doc_uuid == path)
                    .unwrap()
                    .incarnation,
                Some(k)
            ),
            other => panic!("expected DocList: {other:?}"),
        }
        for client_vv in [None, Some(crate::vv_serde::vv_to_json_bytes(&vv))] {
            send(
                &mut a,
                &ClientMsg::SyncStart {
                    doc_uuid: path.into(),
                    client_vv,
                },
            )
            .await;
            match receive(&mut a).await {
                ServerMsg::SyncDelta {
                    doc_uuid,
                    incarnation,
                    delta,
                    ..
                } => {
                    assert_eq!(doc_uuid, path);
                    assert_eq!(incarnation, Some(k));
                    let check = LoroDoc::new();
                    check.import(&snapshot).unwrap();
                    check.import(&delta).unwrap();
                    assert_eq!(check.get_text("content").to_string(), "surface!");
                }
                other => panic!("expected SyncDelta: {other:?}"),
            }
        }
        db::tombstone(&server.state.db, "v", path, "stale")
            .await
            .unwrap();
        send(
            &mut a,
            &create(
                path,
                doc.export(ExportMode::Snapshot).unwrap(),
                true,
                Some("rotate"),
            ),
        )
        .await;
        let j = grant(receive(&mut a).await, Some("rotate"));
        assert!(j > k);
        delta_broadcast(receive(&mut b).await, path, Some(j));
    }
    send(
        &mut a,
        &ClientMsg::SyncStart {
            doc_uuid: "absent".into(),
            client_vv: None,
        },
    )
    .await;
    assert!(
        matches!(receive(&mut a).await, ServerMsg::DocUnknown { doc_uuid } if doc_uuid == "absent")
    );
}

#[tokio::test]
async fn g09_i64_guard_errors_without_mutation() {
    let db = test_db().await;
    db::store_snapshot_with_vv(&db, "v", "live", b"snap", b"vv")
        .await
        .unwrap();
    exec(
        &db,
        "UPDATE vault_incarnation SET next_incarnation=9223372036854775806",
    )
    .await;
    assert_eq!(
        db::store_snapshot_with_vv(&db, "v", "last", b"snap", b"vv")
            .await
            .unwrap(),
        i64::MAX - 1
    );
    assert_eq!(
        scalar::<i64>(&db, "SELECT next_incarnation FROM vault_incarnation").await,
        i64::MAX
    );
    // Force the bound explicitly, independent of the preceding boundary allocation.
    exec(
        &db,
        "UPDATE vault_incarnation SET next_incarnation=9223372036854775807",
    )
    .await;
    db::tombstone(&db, "v", "live", "p").await.unwrap();
    let before = row_state(&db).await;
    for error in [
        db::store_snapshot_with_vv(&db, "v", "new", b"snap", b"vv")
            .await
            .unwrap_err(),
        db::store_snapshot_replacing_tombstone(&db, "v", "live", b"new", b"newvv")
            .await
            .unwrap_err(),
    ] {
        assert!(matches!(error, ServerError::Db(_)));
        assert!(error.to_string().contains("incarnation space exhausted"));
    }
    assert_eq!(row_state(&db).await, before);
    // Ordinary updates do not allocate, even when allocation is exhausted.
    assert_eq!(
        db::store_snapshot_with_vv(&db, "v", "live", b"updated", b"vv")
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn g10_migration_backfill_seed_and_durable_counter() {
    let path = std::env::temp_dir().join(format!("vault-incarnation-{}.db", uuid::Uuid::new_v4()));
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        for sql in [
            include_str!("../../migrations/001_init.sql"),
            include_str!("../../migrations/002_peers.sql"),
            include_str!("../../migrations/003_invites_device_keys.sql"),
            include_str!("../../migrations/004_blob_lane.sql"),
            include_str!("../../migrations/005_tombstone_content_hash.sql"),
        ] {
            conn.execute_batch(sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 5).unwrap();
        conn.execute_batch("INSERT INTO documents (vault_id,doc_uuid,snapshot_blob,vv_blob) VALUES ('v','a',X'0102',X'0304'), ('v','b',X'01',X'02'), ('docs-only','d',X'01',X'02');
            INSERT INTO tombstones (vault_id,doc_uuid,deleted_by,content_hash) VALUES ('v','dead','p','hash'), ('tombs-only','dead','p',NULL);
            INSERT INTO vaults (vault_id,api_key) VALUES ('fresh','test-key');").unwrap();
    }
    let db = db::open_db(path.to_str().unwrap()).await.unwrap();
    assert_eq!(scalar::<i64>(&db, "PRAGMA user_version").await, 6);
    assert_eq!(
        scalar::<i64>(&db, "SELECT COUNT(*) FROM documents WHERE incarnation=1").await,
        3
    );
    assert_eq!(
        scalar::<i64>(&db, "SELECT COUNT(*) FROM tombstones WHERE incarnation=1").await,
        2
    );
    assert_eq!(
        db::get_snapshot_with_vv(&db, "v", "a")
            .await
            .unwrap()
            .unwrap(),
        (vec![1, 2], vec![3, 4])
    );
    assert_eq!(
        scalar::<String>(
            &db,
            "SELECT content_hash FROM tombstones WHERE vault_id='v'"
        )
        .await,
        "hash"
    );
    assert_eq!(
        scalar::<i64>(&db, "SELECT COUNT(*) FROM vault_incarnation").await,
        3
    );
    assert_eq!(
        scalar::<i64>(
            &db,
            "SELECT COUNT(*) FROM vault_incarnation WHERE next_incarnation=2"
        )
        .await,
        3
    );
    assert_eq!(
        scalar::<i64>(
            &db,
            "SELECT COUNT(*) FROM vault_incarnation WHERE vault_id='fresh'"
        )
        .await,
        0
    );
    for vault in ["v", "docs-only", "tombs-only"] {
        assert_eq!(
            db::store_snapshot_with_vv(&db, vault, "new", b"s", b"v")
                .await
                .unwrap(),
            2
        );
    }
    assert_eq!(
        db::store_snapshot_with_vv(&db, "fresh", "new", b"s", b"v")
            .await
            .unwrap(),
        1
    );
    drop(db);
    let db = db::open_db(path.to_str().unwrap()).await.unwrap();
    assert_eq!(
        db::store_snapshot_with_vv(&db, "v", "after-reopen", b"s", b"v")
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        db::store_snapshot_with_vv(&db, "fresh", "after-reopen", b"s", b"v")
            .await
            .unwrap(),
        2
    );
    drop(db);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn g11_expiry_never_recycles() {
    let db = test_db().await;
    let k = db::store_snapshot_with_vv(&db, "v", "a", b"s", b"v")
        .await
        .unwrap();
    assert!(
        matches!(db::delete_doc_guarded(&db, "v", "a", "p", Some(k)).await.unwrap(), db::DeleteOutcome::Deleted { incarnation, .. } if incarnation == k)
    );
    exec(
        &db,
        "UPDATE tombstones SET deleted_at='2000-01-01 00:00:00'",
    )
    .await;
    let counter: i64 = scalar(&db, "SELECT next_incarnation FROM vault_incarnation").await;
    assert_eq!(db::expire_tombstones(&db, 7).await.unwrap(), 1);
    assert!(!db::is_tombstoned(&db, "v", "a").await.unwrap());
    let j = db::store_snapshot_with_vv(&db, "v", "a", b"s", b"v")
        .await
        .unwrap();
    assert!(j > k, "expiry MUST NOT recycle incarnation {k}");
    assert_eq!(j, counter);
    assert_eq!(
        scalar::<i64>(&db, "SELECT next_incarnation FROM vault_incarnation").await,
        counter + 1
    );
}

fn roundtrip<T: serde::de::DeserializeOwned>(value: &impl Serialize) -> T {
    rmp_serde::from_slice(&rmp_serde::to_vec_named(value).unwrap()).unwrap()
}

#[test]
fn g12_new_decoder_accepts_frozen_old_shapes() {
    assert!(matches!(
        roundtrip::<ServerMsg>(&frozen::ServerMsg::AuthOk {
            protocol_version: 1
        }),
        ServerMsg::AuthOk {
            protocol_version: 1,
            capabilities: None
        }
    ));
    ack(roundtrip(&frozen::ServerMsg::Ack), None, None);
    assert!(matches!(
        roundtrip::<ServerMsg>(&frozen::ServerMsg::Error {
            code: "bad_frame".into(),
            message: "message could not be decoded".into()
        }),
        ServerMsg::Error {
            request_id: None,
            ..
        }
    ));
    let old_entry = frozen::DocEntry {
        doc_uuid: "a".into(),
        updated_at: "2026-09-11 00:00:00".into(),
        server_vv: b"{}".to_vec(),
    };
    assert_eq!(roundtrip::<db::DocEntry>(&old_entry).incarnation, None);
    assert!(matches!(
        roundtrip::<ServerMsg>(&frozen::ServerMsg::SyncDelta {
            doc_uuid: "a".into(),
            delta: vec![],
            server_vv: b"{}".to_vec()
        }),
        ServerMsg::SyncDelta {
            incarnation: None,
            ..
        }
    ));
    assert!(matches!(
        roundtrip::<ServerMsg>(&frozen::ServerMsg::DeltaBroadcast {
            doc_uuid: "a".into(),
            delta: vec![],
            peer_id: "p".into(),
            server_vv: b"{}".to_vec()
        }),
        ServerMsg::DeltaBroadcast {
            incarnation: None,
            ..
        }
    ));
}

#[test]
fn g12_frozen_old_decoder_accepts_new_additive_shapes() {
    assert!(matches!(
        roundtrip::<frozen::ServerMsg>(&ServerMsg::Ack {
            incarnation: Some(7),
            request_id: Some("r".into())
        }),
        frozen::ServerMsg::Ack
    ));
    assert!(matches!(
        roundtrip::<frozen::ServerMsg>(&ServerMsg::AuthOk {
            protocol_version: 1,
            capabilities: Some(vec!["delete_incarnation".into()])
        }),
        frozen::ServerMsg::AuthOk {
            protocol_version: 1
        }
    ));
    match roundtrip::<frozen::ServerMsg>(&ServerMsg::Error {
        code: "bad_frame".into(),
        message: "message could not be decoded".into(),
        request_id: Some("r".into()),
    }) {
        frozen::ServerMsg::Error { code, message } => {
            assert_eq!(code, "bad_frame");
            assert_eq!(message, "message could not be decoded");
        }
        other => panic!("expected frozen Error: {other:?}"),
    }
    assert!(
        matches!(roundtrip::<frozen::ClientMsg>(&delete("a", Some(7), Some("D"), Some("r"))), frozen::ClientMsg::DocDelete { doc_uuid, peer_id } if doc_uuid == "a" && peer_id == "p")
    );
    assert!(
        matches!(roundtrip::<frozen::ClientMsg>(&create("a", vec![1], false, Some("r"))), frozen::ClientMsg::DocCreate { doc_uuid, snapshot, .. } if doc_uuid == "a" && snapshot == vec![1])
    );
    assert!(
        matches!(roundtrip::<frozen::ClientMsg>(&push("a", vec![1], Some("r"))), frozen::ClientMsg::SyncPush { doc_uuid, delta, .. } if doc_uuid == "a" && delta == vec![1])
    );
    let response = ServerMsg::DeleteRejected {
        doc_uuid: "a".into(),
        intent_id: Some("D".into()),
        request_id: Some("r".into()),
    };
    let bytes = rmp_serde::to_vec_named(&response).unwrap();
    assert!(rmp_serde::from_slice::<frozen::ServerMsg>(&bytes).is_err());
    rejected(
        rmp_serde::from_slice(&bytes).unwrap(),
        "a",
        Some("D"),
        Some("r"),
    );
}
