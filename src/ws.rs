use axum::{
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket, close_code},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::{AppState, BroadcastEvent, ConnectionInfo, auth, db, handlers};

pub const PROTOCOL_VERSION: u32 = 1;

// ── Message types (shared with handlers) ────────────────────────────────────

pub mod msg {
    use serde::{Deserialize, Serialize};

    use crate::db;

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
            #[serde(default)]
            request_id: Option<String>,
        },
        DocCreate {
            doc_uuid: String,
            #[serde(with = "serde_bytes")]
            snapshot: Vec<u8>,
            peer_id: String,
            #[serde(default)]
            replace_tombstone: bool,
            #[serde(default)]
            request_id: Option<String>,
        },
        DocDelete {
            doc_uuid: String,
            peer_id: String,
            #[serde(default)]
            expected_incarnation: Option<i64>,
            #[serde(default)]
            intent_id: Option<String>,
            #[serde(default)]
            request_id: Option<String>,
        },
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum ServerMsg {
        AuthOk {
            protocol_version: u32,
            #[serde(default)]
            capabilities: Option<Vec<String>>,
        },
        Pong,
        Ack {
            #[serde(default)]
            incarnation: Option<i64>,
            #[serde(default)]
            request_id: Option<String>,
        },
        Error {
            code: String,
            message: String,
            #[serde(default)]
            request_id: Option<String>,
        },
        DeleteRejected {
            doc_uuid: String,
            #[serde(default)]
            intent_id: Option<String>,
            #[serde(default)]
            request_id: Option<String>,
        },
        DocList {
            docs: Vec<db::DocEntry>,
            tombstones: Vec<String>,
            tombstone_hashes: Vec<db::TombstoneHash>,
        },
        SyncDelta {
            doc_uuid: String,
            #[serde(with = "serde_bytes")]
            delta: Vec<u8>,
            #[serde(with = "serde_bytes")]
            server_vv: Vec<u8>,
            #[serde(default)]
            incarnation: Option<i64>,
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
            #[serde(default)]
            incarnation: Option<i64>,
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

// ── Connection counter ──────────────────────────────────────────────────────

static CONN_COUNTER: AtomicU64 = AtomicU64::new(0);

// ── WS upgrade handler ─────────────────────────────────────────────────────

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let device_name = params.get("device").cloned().unwrap_or_default();
    let peer_id = params.get("peer_id").cloned().unwrap_or_default();

    // Identifier caps (#5/N19): reject before upgrade, logging or persistence.
    // Empty peer ids stay valid (they merely skip peer persistence below).
    for (field, value) in [("peer_id", &peer_id), ("device", &device_name)] {
        if value.len() > crate::MAX_PEER_ID_BYTES {
            warn!(
                "WS upgrade rejected: {field} too long ({} bytes, limit {})",
                value.len(),
                crate::MAX_PEER_ID_BYTES
            );
            return (StatusCode::BAD_REQUEST, "identifier too long").into_response();
        }
    }

    let query_vault_id = params.get("vault_id").cloned();
    ws.on_upgrade(move |socket| handle_socket(socket, state, device_name, peer_id, query_vault_id))
}

async fn close_with(mut socket: WebSocket, reason: &'static str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: close_code::POLICY,
            reason: reason.into(),
        })))
        .await;
}

// ── Socket handler (3 tasks) ────────────────────────────────────────────────

async fn handle_socket(
    mut socket: WebSocket,
    state: AppState,
    device_name: String,
    peer_id: String,
    query_vault_id: Option<String>,
) {
    let conn_id = CONN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let first = tokio::time::timeout(std::time::Duration::from_secs(10), socket.recv()).await;
    let data = match first {
        Err(_) | Ok(None) => {
            close_with(socket, "auth_timeout").await;
            return;
        }
        Ok(Some(Ok(Message::Binary(data)))) => data,
        _ => {
            close_with(socket, "auth_required").await;
            return;
        }
    };
    let Ok(msg::ClientMsg::Auth {
        token,
        protocol_version,
        features,
    }) = rmp_serde::from_slice(&data)
    else {
        close_with(socket, "auth_required").await;
        return;
    };
    let vault_id = match auth::jwt_verify(&token, &state.jwt_secret) {
        Ok(vault_id) => vault_id,
        Err(_) => {
            warn!("conn {conn_id}, device={device_name}: auth invalid");
            close_with(socket, "auth_invalid").await;
            return;
        }
    };
    if protocol_version != PROTOCOL_VERSION {
        let response = msg::ServerMsg::Error {
            code: "protocol_version_mismatch".into(),
            message: format!("server={PROTOCOL_VERSION} client={protocol_version}"),
            request_id: None,
        };
        if let Ok(bytes) = rmp_serde::to_vec_named(&response) {
            let _ = socket.send(Message::Binary(bytes.into())).await;
        }
        close_with(socket, "protocol_version_mismatch").await;
        return;
    }
    let Ok(bytes) = rmp_serde::to_vec_named(&msg::ServerMsg::AuthOk {
        protocol_version: PROTOCOL_VERSION,
        capabilities: Some(vec!["delete_incarnation".into()]),
    }) else {
        return;
    };
    if socket.send(Message::Binary(bytes.into())).await.is_err() {
        return;
    }
    let device_label = if device_name.is_empty() {
        format!("conn_id={conn_id}")
    } else {
        format!("conn_id={conn_id}, device={device_name}")
    };
    let has_blob_feature = features.iter().any(|f| f == "blobs");
    info!("WS connected ({device_label}, vault={vault_id}, query_vault_id={query_vault_id:?})");

    // Register connection
    {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        state
            .connections
            .lock()
            .expect("connections mutex poisoned")
            .insert(
                conn_id,
                ConnectionInfo {
                    conn_id,
                    vault_id: vault_id.clone(),
                    device_name: device_name.clone(),
                    connected_at: secs,
                },
            );
    }

    // Persist peer info for the "synced devices" list
    if !peer_id.is_empty()
        && let Err(e) = db::upsert_peer(&state.db, &vault_id, &peer_id, &device_name).await
    {
        warn!("conn {conn_id}: failed to upsert peer: {e}");
    }

    let mut broadcast_rx = state.broadcast_tx.subscribe();
    let (mut ws_sink, mut ws_stream) = socket.split();
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(64);

    // Task 1: WS Writer — serializes all outbound messages through one sink
    //         (started first because Tasks 2+3 send into write_tx)
    let ws_writer = tokio::spawn(async move {
        while let Some(bytes) = write_rx.recv().await {
            if ws_sink.send(Message::Binary(bytes.into())).await.is_err() {
                break;
            }
        }
    });

    // Task 2: Client → Server (read messages, dispatch to handlers)
    let write_tx_read = write_tx.clone();
    let conn_db = state.db.clone();
    let broadcast_tx = state.broadcast_tx.clone();
    let doc_locks = state.doc_locks.clone();
    let vault_id_read = vault_id.clone();
    let client_read = async move {
        loop {
            let msg = tokio::select! {
                msg = ws_stream.next() => msg,
                // Idle timeout: must comfortably exceed the plugin's 30s
                // heartbeat to avoid reconnect churn under mobile/browser
                // timer throttling.
                _ = tokio::time::sleep(std::time::Duration::from_secs(120)) => None,
            };
            let Some(Ok(msg)) = msg else { break };
            match msg {
                Message::Binary(data) => {
                    const MAX_WS_MSG_BYTES: usize = 50 * 1024 * 1024; // 50 MB
                    if data.len() > MAX_WS_MSG_BYTES {
                        warn!(
                            "conn {conn_id}: message too large ({} bytes), dropping",
                            data.len()
                        );
                        let err = self::msg::ServerMsg::Error {
                            code: "frame_too_large".into(),
                            request_id: None,
                            message: format!(
                                "frame too large ({} bytes, limit 50 MiB) — document not synced",
                                data.len()
                            ),
                        };
                        if let Ok(bytes) = rmp_serde::to_vec_named(&err) {
                            let _ = write_tx_read.send(bytes).await;
                        }
                        continue;
                    }
                    let (response, maybe_broadcast) = handlers::process_message(
                        &data,
                        &conn_db,
                        &vault_id_read,
                        conn_id,
                        &doc_locks,
                    )
                    .await;
                    let Ok(bytes) = rmp_serde::to_vec_named(&response) else {
                        error!("Failed to serialize response");
                        break;
                    };
                    if write_tx_read.send(bytes).await.is_err() {
                        break;
                    }
                    if let Some(event) = maybe_broadcast {
                        let _ = broadcast_tx.send(event);
                    }
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {}
                _ => {}
            }
        }
    };

    // Task 3: Broadcast → Client (forward broadcasts for same vault, different conn)
    let write_tx_bcast = write_tx;
    let broadcast_fwd = async move {
        loop {
            match broadcast_rx.recv().await {
                Ok(BroadcastEvent::Delta {
                    vault_id: evt_vault,
                    doc_uuid,
                    delta,
                    peer_id,
                    sender_conn_id,
                    server_vv,
                    incarnation,
                }) if evt_vault == vault_id && sender_conn_id != conn_id => {
                    let msg = msg::ServerMsg::DeltaBroadcast {
                        doc_uuid,
                        delta,
                        peer_id,
                        server_vv,
                        incarnation,
                    };
                    let Ok(bytes) = rmp_serde::to_vec_named(&msg) else {
                        break;
                    };
                    if write_tx_bcast.send(bytes).await.is_err() {
                        break;
                    }
                }
                Ok(BroadcastEvent::Delete {
                    vault_id: evt_vault,
                    doc_uuid,
                    sender_conn_id,
                    content_hash,
                }) if evt_vault == vault_id && sender_conn_id != conn_id => {
                    let msg = msg::ServerMsg::DocDeleted {
                        doc_uuid,
                        content_hash,
                    };
                    let Ok(bytes) = rmp_serde::to_vec_named(&msg) else {
                        break;
                    };
                    if write_tx_bcast.send(bytes).await.is_err() {
                        break;
                    }
                }
                Ok(BroadcastEvent::BlobPathChanged {
                    vault_id: evt_vault,
                    path_key,
                    seq,
                }) if evt_vault == vault_id && has_blob_feature => {
                    // Originates from HTTP handlers, so there is no sender-conn to filter.
                    let msg = msg::ServerMsg::BlobPathChanged { path_key, seq };
                    let Ok(bytes) = rmp_serde::to_vec_named(&msg) else {
                        break;
                    };
                    if write_tx_bcast.send(bytes).await.is_err() {
                        break;
                    }
                }
                Ok(_) => {} // skip own messages / other vaults / clients without blobs
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!("conn {conn_id} lagged {n} msgs — disconnecting");
                    break;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    let connections = state.connections.clone();
    tokio::select! {
        _ = client_read => {},
        _ = broadcast_fwd => {},
    }
    ws_writer.abort();
    connections
        .lock()
        .expect("connections mutex poisoned")
        .remove(&conn_id);
    info!("WS disconnected ({device_label})");
}
