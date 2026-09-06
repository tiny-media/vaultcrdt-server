use loro::{ExportMode, LoroDoc};
use sqlx::SqlitePool;
use tracing::{debug, info};

use crate::{BroadcastEvent, DocLocks, db, errors::ServerError, vv_serde, ws::msg};

// ── Message processing ──────────────────────────────────────────────────────

pub async fn process_message(
    data: &[u8],
    pool: &SqlitePool,
    vault_id: &str,
    conn_id: u64,
    doc_locks: &DocLocks,
) -> (msg::ServerMsg, Option<BroadcastEvent>) {
    match process_inner(data, pool, vault_id, conn_id, doc_locks).await {
        Ok(result) => result,
        Err(e) => {
            let (code, message) = e.client_facing();
            // Decoder errors may echo raw client bytes, including credentials.
            match &e {
                ServerError::BadFrame(_) | ServerError::Sync(_) => tracing::warn!(
                    "conn {conn_id}: WS message error: {code} ({message}), {} bytes",
                    data.len()
                ),
                _ => tracing::warn!("conn {conn_id}: WS message error: {e}"),
            }
            (
                msg::ServerMsg::Error {
                    code: code.into(),
                    message: message.into(),
                },
                None,
            )
        }
    }
}

async fn process_inner(
    data: &[u8],
    pool: &SqlitePool,
    vault_id: &str,
    conn_id: u64,
    doc_locks: &DocLocks,
) -> Result<(msg::ServerMsg, Option<BroadcastEvent>), ServerError> {
    let msg: msg::ClientMsg = rmp_serde::from_slice(data)
        .map_err(|e| ServerError::BadFrame(format!("invalid msgpack: {e}")))?;

    match msg {
        msg::ClientMsg::Auth { .. } => Err(ServerError::BadFrame("unexpected auth frame".into())),
        msg::ClientMsg::Ping => Ok((msg::ServerMsg::Pong, None)),

        msg::ClientMsg::RequestDocList => {
            let docs = db::list_docs_with_vv(pool, vault_id).await?;
            let tombstones = db::list_tombstones(pool, vault_id).await?;
            info!(
                "request_doc_list: vault={vault_id}, docs={}, tombstones={}",
                docs.len(),
                tombstones.len()
            );
            Ok((msg::ServerMsg::DocList { docs, tombstones }, None))
        }

        msg::ClientMsg::SyncStart {
            doc_uuid,
            client_vv,
        } => handle_sync_start(pool, vault_id, &doc_uuid, client_vv.as_deref()).await,

        msg::ClientMsg::SyncPush {
            doc_uuid,
            delta,
            peer_id,
        } => {
            let lock_key = DocLocks::lock_key(vault_id, &doc_uuid);
            let lock = doc_locks.get(&lock_key);
            let _guard = lock.lock().await;
            handle_sync_push(pool, vault_id, &doc_uuid, &delta, &peer_id, conn_id).await
        }

        msg::ClientMsg::DocCreate {
            doc_uuid,
            snapshot,
            peer_id,
            replace_tombstone,
        } => {
            let lock_key = DocLocks::lock_key(vault_id, &doc_uuid);
            let lock = doc_locks.get(&lock_key);
            let _guard = lock.lock().await;
            handle_doc_create(
                pool,
                vault_id,
                &doc_uuid,
                &snapshot,
                &peer_id,
                conn_id,
                replace_tombstone,
            )
            .await
        }

        msg::ClientMsg::DocDelete { doc_uuid, peer_id } => {
            // Serialise with sync_push / doc_create on the same doc: the
            // tombstone guard in those handlers is a TOCTOU check that only
            // holds if delete, push and create are mutually exclusive.
            let lock_key = DocLocks::lock_key(vault_id, &doc_uuid);
            let lock = doc_locks.get(&lock_key);
            let _guard = lock.lock().await;
            db::delete_doc_and_tombstone(pool, vault_id, &doc_uuid, &peer_id).await?;
            debug!("doc_delete: vault={vault_id}, doc={doc_uuid}");
            let broadcast = BroadcastEvent::Delete {
                vault_id: vault_id.to_string(),
                doc_uuid,
                sender_conn_id: conn_id,
            };
            Ok((msg::ServerMsg::Ack, Some(broadcast)))
        }
    }
}

// ── SyncStart ───────────────────────────────────────────────────────────────

async fn handle_sync_start(
    pool: &SqlitePool,
    vault_id: &str,
    doc_uuid: &str,
    client_vv_bytes: Option<&[u8]>,
) -> Result<(msg::ServerMsg, Option<BroadcastEvent>), ServerError> {
    let existing = db::get_snapshot_with_vv(pool, vault_id, doc_uuid).await?;

    let Some((snapshot_blob, _vv_blob)) = existing else {
        debug!("sync_start: vault={vault_id}, doc={doc_uuid} → DocUnknown");
        return Ok((
            msg::ServerMsg::DocUnknown {
                doc_uuid: doc_uuid.to_string(),
            },
            None,
        ));
    };

    let doc = LoroDoc::new();
    doc.import(&snapshot_blob)
        .map_err(|e| ServerError::Sync(format!("loro import existing: {e}")))?;

    let server_vv = doc.oplog_vv();
    let server_vv_json = vv_serde::vv_to_json_bytes(&server_vv);

    match client_vv_bytes {
        Some(vv_bytes) => {
            let client_vv = vv_serde::vv_from_json_bytes(vv_bytes)?;
            let delta = doc
                .export(ExportMode::updates(&client_vv))
                .map_err(|e| ServerError::Sync(format!("loro export delta: {e}")))?;
            debug!(
                "sync_start: vault={vault_id}, doc={doc_uuid}, incremental delta={}b",
                delta.len()
            );
            Ok((
                msg::ServerMsg::SyncDelta {
                    doc_uuid: doc_uuid.to_string(),
                    delta,
                    server_vv: server_vv_json,
                },
                None,
            ))
        }
        None => {
            debug!(
                "sync_start: vault={vault_id}, doc={doc_uuid}, full snapshot={}b",
                snapshot_blob.len()
            );
            Ok((
                msg::ServerMsg::SyncDelta {
                    doc_uuid: doc_uuid.to_string(),
                    delta: snapshot_blob,
                    server_vv: server_vv_json,
                },
                None,
            ))
        }
    }
}

// ── SyncPush ────────────────────────────────────────────────────────────────

async fn handle_sync_push(
    pool: &SqlitePool,
    vault_id: &str,
    doc_uuid: &str,
    delta: &[u8],
    peer_id: &str,
    conn_id: u64,
) -> Result<(msg::ServerMsg, Option<BroadcastEvent>), ServerError> {
    // Anti-resurrection: refuse pushes for tombstoned docs.
    if db::is_tombstoned(pool, vault_id, doc_uuid).await? {
        debug!("sync_push refused: vault={vault_id}, doc={doc_uuid} is tombstoned");
        return Ok((
            msg::ServerMsg::DocTombstoned {
                doc_uuid: doc_uuid.to_string(),
            },
            None,
        ));
    }

    let existing = db::get_snapshot_with_vv(pool, vault_id, doc_uuid).await?;

    if let Some((_, existing_vv_blob)) = &existing {
        let disjoint = match vv_serde::vv_from_db_bytes(existing_vv_blob) {
            Ok(stored_vv) => {
                let meta = LoroDoc::decode_import_blob_meta(delta, true)
                    .map_err(|e| ServerError::Sync(format!("loro decode client delta: {e}")))?;
                !stored_vv.is_empty() && meta.change_num > 0 && meta.start_frontiers.is_empty()
            }
            Err(_) => true,
        };
        if disjoint {
            debug!("sync_push refused: vault={vault_id}, doc={doc_uuid} has disjoint history");
            return Ok((
                msg::ServerMsg::CreateConflict {
                    doc_uuid: doc_uuid.to_string(),
                },
                None,
            ));
        }
    }

    let doc = LoroDoc::new();
    if let Some((ref snapshot_blob, _)) = existing {
        doc.import(snapshot_blob)
            .map_err(|e| ServerError::Sync(format!("loro import existing: {e}")))?;
    }

    doc.import(delta)
        .map_err(|e| ServerError::Sync(format!("loro import client delta: {e}")))?;

    let new_snapshot = doc
        .export(ExportMode::Snapshot)
        .map_err(|e| ServerError::Sync(format!("loro export snapshot: {e}")))?;
    let new_vv = doc.oplog_vv();
    let new_vv_blob = vv_serde::vv_to_db_bytes(&new_vv);

    db::store_snapshot_with_vv(pool, vault_id, doc_uuid, &new_snapshot, &new_vv_blob).await?;

    debug!(
        "sync_push: vault={vault_id}, doc={doc_uuid}, delta={}b, snapshot={}b",
        delta.len(),
        new_snapshot.len()
    );

    let server_vv_json = vv_serde::vv_to_json_bytes(&new_vv);
    let broadcast = BroadcastEvent::Delta {
        vault_id: vault_id.to_string(),
        doc_uuid: doc_uuid.to_string(),
        delta: delta.to_vec(),
        peer_id: peer_id.to_string(),
        sender_conn_id: conn_id,
        server_vv: server_vv_json,
    };

    Ok((msg::ServerMsg::Ack, Some(broadcast)))
}

// ── DocCreate ───────────────────────────────────────────────────────────────

async fn handle_doc_create(
    pool: &SqlitePool,
    vault_id: &str,
    doc_uuid: &str,
    snapshot: &[u8],
    peer_id: &str,
    conn_id: u64,
    replace_tombstone: bool,
) -> Result<(msg::ServerMsg, Option<BroadcastEvent>), ServerError> {
    // Anti-resurrection: refuse blind creates for tombstoned docs. A client
    // may explicitly replace a same-path tombstone only after a local
    // delete→recreate intent; that path removes the tombstone and treats the
    // incoming snapshot as the new document identity for this path.
    // `replace_tombstone` only takes effect when the doc is actually tombstoned —
    // on a live doc it must not discard the server snapshot (silent LWW loss).
    let was_tombstoned = db::is_tombstoned(pool, vault_id, doc_uuid).await?;
    if was_tombstoned && !replace_tombstone {
        debug!("doc_create refused: vault={vault_id}, doc={doc_uuid} is tombstoned");
        return Ok((
            msg::ServerMsg::DocTombstoned {
                doc_uuid: doc_uuid.to_string(),
            },
            None,
        ));
    }
    let effective_replace = was_tombstoned && replace_tombstone;
    if effective_replace {
        debug!("doc_create replacing tombstone: vault={vault_id}, doc={doc_uuid}");
    }

    let existing = db::get_snapshot_with_vv(pool, vault_id, doc_uuid).await?;

    if !effective_replace && let Some((_, existing_vv_blob)) = &existing {
        let disjoint = match vv_serde::vv_from_db_bytes(existing_vv_blob) {
            Ok(stored_vv) => {
                let probe = LoroDoc::new();
                probe
                    .import(snapshot)
                    .map_err(|e| ServerError::Sync(format!("loro import client snapshot: {e}")))?;
                let incoming_vv = probe.oplog_vv();
                !stored_vv.is_empty()
                    && !incoming_vv.is_empty()
                    && !stored_vv
                        .iter()
                        .any(|(peer, _)| incoming_vv.get(peer).is_some())
            }
            Err(_) => true,
        };
        if disjoint {
            debug!("doc_create refused: vault={vault_id}, doc={doc_uuid} has disjoint history");
            return Ok((
                msg::ServerMsg::CreateConflict {
                    doc_uuid: doc_uuid.to_string(),
                },
                None,
            ));
        }
    }

    let doc = LoroDoc::new();
    if !effective_replace && let Some((ref existing_blob, _)) = existing {
        doc.import(existing_blob)
            .map_err(|e| ServerError::Sync(format!("loro import existing: {e}")))?;
    }

    doc.import(snapshot)
        .map_err(|e| ServerError::Sync(format!("loro import client snapshot: {e}")))?;

    let new_snapshot = doc
        .export(ExportMode::Snapshot)
        .map_err(|e| ServerError::Sync(format!("loro export snapshot: {e}")))?;
    let new_vv = doc.oplog_vv();
    let new_vv_blob = vv_serde::vv_to_db_bytes(&new_vv);

    db::store_snapshot_with_vv(pool, vault_id, doc_uuid, &new_snapshot, &new_vv_blob).await?;

    // Remove tombstone only after a successful store — otherwise a failed
    // import/export would leave neither doc nor tombstone.
    if effective_replace {
        db::remove_tombstone(pool, vault_id, doc_uuid).await?;
    }

    debug!(
        "doc_create: vault={vault_id}, doc={doc_uuid}, snapshot={}b, existing={}, replace_tombstone={}",
        snapshot.len(),
        existing.is_some(),
        effective_replace,
    );

    let server_vv_json = vv_serde::vv_to_json_bytes(&new_vv);
    let broadcast = BroadcastEvent::Delta {
        vault_id: vault_id.to_string(),
        doc_uuid: doc_uuid.to_string(),
        delta: snapshot.to_vec(),
        peer_id: peer_id.to_string(),
        sender_conn_id: conn_id,
        server_vv: server_vv_json,
    };

    Ok((msg::ServerMsg::Ack, Some(broadcast)))
}
