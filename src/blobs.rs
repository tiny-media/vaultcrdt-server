//! Attachment blob lane: content-addressed store, resumable uploads, LWW path states.
use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{Cursor, SeekFrom};
use std::path::{Path as FsPath, PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::{AppState, BroadcastEvent, VaultAuth, db::Db, errors::ServerError};

/// Advertised PUT segment size. The route guard is this plus 4 KiB so a 4 MiB
/// segment is not 413'd by axum's default 2 MiB limit before the handler runs.
pub const SEGMENT_BYTES: usize = 4 * 1024 * 1024;
pub const SEGMENT_BODY_GUARD: usize = SEGMENT_BYTES + 4 * 1024;

const IMAGE_CAP: u64 = 10 * 1024 * 1024;
const PDF_CAP: u64 = 10 * 1024 * 1024;
const AUDIO_CAP: u64 = 25 * 1024 * 1024;
/// Largest per-type cap. POST /uploads has no extension, so creation can only
/// enforce this ceiling; extension-specific caps run at blob-paths.
const ABSOLUTE_MAX: u64 = AUDIO_CAP;
const MAX_OPEN_UPLOADS: i64 = 4;
const KEY_MAX_BYTES: usize = 1024;

fn json_error(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

fn json_ok(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

fn is_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn type_cap_for_ext(ext: &str) -> Option<u64> {
    match ext {
        "jpg" | "jpeg" | "png" | "webp" | "gif" | "heic" | "heif" | "avif" | "svg" => {
            Some(IMAGE_CAP)
        }
        "pdf" => Some(PDF_CAP),
        "mp3" | "m4a" | "ogg" | "oga" | "opus" | "flac" | "wav" | "webm" | "3gp" => Some(AUDIO_CAP),
        _ => None,
    }
}

/// Shared protocol Filter. Bytes are never rewritten on disk; callers reject
/// unless the input is already a fixpoint of this filter.
pub(crate) fn svg_filter_output(bytes: &[u8]) -> Result<Vec<u8>, svg_hush::FError> {
    let mut f = svg_hush::Filter::new();
    f.set_data_url_filter(svg_hush::data_url_filter::allow_standard_images);
    let mut out = Vec::new();
    f.filter(Cursor::new(bytes), &mut out)?;
    Ok(out)
}

pub(crate) fn svg_at_fixpoint(bytes: &[u8]) -> Result<bool, svg_hush::FError> {
    Ok(svg_filter_output(bytes)? == bytes)
}

/// Cheap sniff: first non-BOM, non-ASCII-whitespace byte is `<`, and
/// case-sensitive `<svg` plus a delimiter appears in the first 4096 bytes.
pub(crate) fn looks_like_svg(bytes: &[u8]) -> bool {
    let mut i = 0;
    if bytes.len() >= 3 && bytes[..3] == [0xEF, 0xBB, 0xBF] {
        i = 3;
    }
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'<' {
        return false;
    }
    let window = &bytes[..bytes.len().min(4096)];
    let mut n = 0;
    while n + 5 <= window.len() {
        if &window[n..n + 4] == b"<svg"
            && matches!(window[n + 4], b' ' | b'>' | b'/' | b'\t' | b'\n' | b'\r')
        {
            return true;
        }
        n += 1;
    }
    false
}

fn svg_fixpoint_error(bytes: &[u8]) -> Option<&'static str> {
    match svg_at_fixpoint(bytes) {
        Ok(true) => None,
        Ok(false) => Some("svg_not_sanitized"),
        Err(_) => Some("svg_invalid"),
    }
}

fn last_extension(name: &str) -> Option<&str> {
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    Some(ext)
}

fn validate_segments(path: &str, allow_ascii_upper: bool) -> bool {
    if path.is_empty() || path.len() > KEY_MAX_BYTES || path.starts_with('/') {
        return false;
    }
    if !allow_ascii_upper && path.bytes().any(|b| b.is_ascii_uppercase()) {
        return false;
    }
    if path == ".obsidian"
        || path == ".trash"
        || path.starts_with(".obsidian/")
        || path.starts_with(".trash/")
    {
        return false;
    }
    let mut last = None;
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return false;
        }
        if segment.ends_with(' ') || segment.ends_with('.') {
            return false;
        }
        last = Some(segment);
    }
    let Some(last) = last else {
        return false;
    };
    let Some(ext) = last_extension(last) else {
        return false;
    };
    type_cap_for_ext(&ext.to_ascii_lowercase()).is_some()
}

/// Structural-only path-key check. Unicode folding is the client's job; this
/// crate has no Unicode dependency and only rejects ASCII-uppercase as a cheap
/// sanity check that the key arrived casefolded.
pub fn validate_blob_key(key: &str) -> bool {
    validate_segments(key, false)
}

/// Display path: same segment rules as the key except ASCII case is allowed.
/// NFC is required of the client; without a Unicode crate we cannot verify it.
fn validate_display_path(path: &str) -> bool {
    validate_segments(path, true)
}

fn cap_for_key(key: &str) -> Option<u64> {
    let last = key.rsplit('/').next()?;
    let ext = last_extension(last)?;
    type_cap_for_ext(&ext.to_ascii_lowercase())
}

fn blob_file_path(blob_dir: &FsPath, vault_id: &str, hash: &str) -> PathBuf {
    blob_dir.join(vault_id).join(&hash[..2]).join(hash)
}

fn tmp_file_path(blob_dir: &FsPath, upload_id: &str) -> PathBuf {
    blob_dir.join("tmp").join(upload_id)
}

fn upload_lock_key(vault_id: &str, hash: &str) -> String {
    format!("blob-upload:{vault_id}:{hash}")
}

fn path_lock_key(vault_id: &str, path_key: &str) -> String {
    format!("blob:{vault_id}:{path_key}")
}

#[derive(Clone)]
struct UploadRow {
    hash_claimed: String,
    size_claimed: i64,
    received_bytes: i64,
    expired: bool,
}

fn read_upload(
    conn: &rusqlite::Connection,
    vault_id: &str,
    upload_id: &str,
) -> Result<Option<UploadRow>, rusqlite::Error> {
    conn.query_row(
        "SELECT hash_claimed, size_claimed, received_bytes,
                created_at < datetime('now', '-24 hours')
         FROM blob_uploads WHERE upload_id = ? AND vault_id = ?",
        params![upload_id, vault_id],
        |r| {
            Ok(UploadRow {
                hash_claimed: r.get(0)?,
                size_claimed: r.get(1)?,
                received_bytes: r.get(2)?,
                expired: r.get::<_, i64>(3)? != 0,
            })
        },
    )
    .optional()
}

async fn discard_upload(db: &Db, blob_dir: &FsPath, vault_id: &str, upload_id: &str) {
    {
        let conn = db.lock().await;
        let _ = conn.execute(
            "DELETE FROM blob_uploads WHERE upload_id = ? AND vault_id = ?",
            params![upload_id, vault_id],
        );
    }
    let _ = tokio::fs::remove_file(tmp_file_path(blob_dir, upload_id)).await;
}

fn parse_content_range(header: &str) -> Option<(u64, u64, u64)> {
    let rest = header.strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let (a, b) = range.split_once('-')?;
    if a.is_empty() || b.is_empty() {
        return None;
    }
    Some((a.parse().ok()?, b.parse().ok()?, total.parse().ok()?))
}

fn parse_byte_range(header: &str, total: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(spec) = header.strip_prefix("bytes=") else {
        return Err(());
    };
    let spec = spec.split(',').next().ok_or(())?.trim();
    if spec.is_empty() {
        return Err(());
    }
    let (start, end) = if let Some(start) = spec.strip_suffix('-').filter(|s| !s.is_empty()) {
        let start: u64 = start.parse().map_err(|_| ())?;
        if total == 0 || start >= total {
            return Ok(None);
        }
        (start, total - 1)
    } else if let Some(suffix) = spec.strip_prefix('-') {
        let n: u64 = suffix.parse().map_err(|_| ())?;
        if n == 0 || total == 0 {
            return Ok(None);
        }
        let n = n.min(total);
        (total - n, total - 1)
    } else {
        let (a, b) = spec.split_once('-').ok_or(())?;
        let start: u64 = a.parse().map_err(|_| ())?;
        let end: u64 = b.parse().map_err(|_| ())?;
        if start > end || total == 0 || start >= total {
            return Ok(None);
        }
        (start, end.min(total - 1))
    };
    Ok(Some((start, end)))
}

#[derive(Deserialize)]
pub struct CreateUpload {
    hash: String,
    size: i64,
}

/// POST /vault/blobs/uploads
pub async fn create_upload(
    State(state): State<AppState>,
    VaultAuth(vault_id): VaultAuth,
    Json(body): Json<CreateUpload>,
) -> Result<Response, ServerError> {
    if !is_hash(&body.hash) || body.size <= 0 {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid hash or size"}),
        ));
    }
    let size = body.size as u64;

    let exists: bool = {
        let conn = state.db.lock().await;
        conn.query_row(
            "SELECT 1 FROM blobs WHERE vault_id = ? AND hash = ?",
            params![&vault_id, &body.hash],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false)
    };
    if exists {
        return Ok(json_ok(StatusCode::OK, json!({"exists": true})));
    }

    if size > ABSOLUTE_MAX {
        return Ok(json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"error": "type_cap_exceeded", "max_bytes": ABSOLUTE_MAX}),
        ));
    }

    let conn = state.db.lock().await;
    let open_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM blob_uploads
         WHERE vault_id = ? AND created_at >= datetime('now', '-24 hours')",
        params![&vault_id],
        |r| r.get(0),
    )?;
    if open_count >= MAX_OPEN_UPLOADS {
        drop(conn);
        let mut resp = json_error(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error": "too_many_uploads"}),
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        return Ok(resp);
    }

    let quota_bytes: Option<i64> = conn
        .query_row(
            "SELECT quota_bytes FROM vaults WHERE vault_id = ?",
            params![&vault_id],
            |r| r.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten();
    let effective = match quota_bytes {
        Some(0) => 0,
        Some(n) if n > 0 => n as u64,
        _ => state.default_quota_bytes,
    };
    // Enforcement is only at creation. Concurrent creates can overshoot by at
    // most 4 open uploads × 25 MiB; that window is accepted.
    if effective > 0 {
        let stored: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM blobs WHERE vault_id = ?",
            params![&vault_id],
            |r| r.get(0),
        )?;
        let inflight: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size_claimed - received_bytes), 0)
             FROM blob_uploads
             WHERE vault_id = ? AND created_at >= datetime('now', '-24 hours')",
            params![&vault_id],
            |r| r.get(0),
        )?;
        let projected = (stored as u64)
            .saturating_add(inflight as u64)
            .saturating_add(size);
        if projected > effective {
            drop(conn);
            return Ok(json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error": "quota_exceeded", "quota_bytes": effective}),
            ));
        }
    }

    let upload_id = uuid::Uuid::new_v4().to_string();
    drop(conn);

    let tmp = tmp_file_path(&state.blob_dir, &upload_id);
    if let Some(parent) = tmp.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::File::create(&tmp).await?;

    let inserted = {
        let conn = state.db.lock().await;
        conn.execute(
            "INSERT INTO blob_uploads (vault_id, upload_id, hash_claimed, size_claimed)
             VALUES (?, ?, ?, ?)",
            params![&vault_id, &upload_id, &body.hash, body.size],
        )
    };
    if let Err(e) = inserted {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e.into());
    }

    Ok(json_ok(
        StatusCode::CREATED,
        json!({
            "upload_id": upload_id,
            "next_offset": 0,
            "segment_bytes": SEGMENT_BYTES,
        }),
    ))
}

/// GET /vault/blobs/uploads/{upload_id}
pub async fn get_upload(
    State(state): State<AppState>,
    VaultAuth(vault_id): VaultAuth,
    Path(upload_id): Path<String>,
) -> Result<Response, ServerError> {
    let row = {
        let conn = state.db.lock().await;
        read_upload(&conn, &vault_id, &upload_id)?
    };
    let Some(row) = row else {
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            json!({"error": "upload not found"}),
        ));
    };
    if row.expired {
        discard_upload(&state.db, &state.blob_dir, &vault_id, &upload_id).await;
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            json!({"error": "upload not found"}),
        ));
    }
    Ok(json_ok(
        StatusCode::OK,
        json!({
            "next_offset": row.received_bytes,
            "hash": row.hash_claimed,
            "size": row.size_claimed,
            "segment_bytes": SEGMENT_BYTES,
        }),
    ))
}

/// PUT /vault/blobs/uploads/{upload_id}
pub async fn put_upload(
    State(state): State<AppState>,
    VaultAuth(vault_id): VaultAuth,
    Path(upload_id): Path<String>,
    req: axum::extract::Request,
) -> Result<Response, ServerError> {
    let (parts, body) = req.into_parts();
    let headers = parts.headers;
    let range_hdr = headers
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok());
    let Some(range_hdr) = range_hdr else {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            json!({"error": "missing or malformed Content-Range"}),
        ));
    };
    let Some((a, b, hdr_size)) = parse_content_range(range_hdr) else {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            json!({"error": "missing or malformed Content-Range"}),
        ));
    };
    if a > b {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid Content-Range"}),
        ));
    }

    // Buffer the whole segment first. A 400 must never leave partial bytes on disk.
    let mut stream = body.into_data_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| std::io::Error::other(e.to_string()))?;
        if buf.len().saturating_add(chunk.len()) > SEGMENT_BODY_GUARD {
            return Ok(json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error": "payload_too_large"}),
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    let span = (b - a).saturating_add(1);
    if buf.len() > SEGMENT_BYTES {
        return Ok(json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"error": "payload_too_large"}),
        ));
    }
    if span as usize != buf.len() {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            json!({"error": "Content-Range length does not match body"}),
        ));
    }

    let preview = {
        let conn = state.db.lock().await;
        read_upload(&conn, &vault_id, &upload_id)?
    };
    let Some(preview) = preview else {
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            json!({"error": "upload not found"}),
        ));
    };
    if preview.expired {
        discard_upload(&state.db, &state.blob_dir, &vault_id, &upload_id).await;
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            json!({"error": "upload not found"}),
        ));
    }

    let lock = state
        .doc_locks
        .get(&upload_lock_key(&vault_id, &preview.hash_claimed));
    let _guard = lock.lock().await;

    let row = {
        let conn = state.db.lock().await;
        read_upload(&conn, &vault_id, &upload_id)?
    };
    let Some(row) = row else {
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            json!({"error": "upload not found"}),
        ));
    };
    if row.expired {
        discard_upload(&state.db, &state.blob_dir, &vault_id, &upload_id).await;
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            json!({"error": "upload not found"}),
        ));
    }
    if hdr_size != row.size_claimed as u64 {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            json!({"error": "Content-Range size does not match upload"}),
        ));
    }
    if a != row.received_bytes as u64 {
        return Ok(json_ok(
            StatusCode::CONFLICT,
            json!({"next_offset": row.received_bytes}),
        ));
    }
    let next = b.saturating_add(1);
    if next > row.size_claimed as u64 {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            json!({"error": "Content-Range exceeds claimed size"}),
        ));
    }
    let is_final = next == row.size_claimed as u64;

    let tmp = tmp_file_path(&state.blob_dir, &upload_id);
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&tmp)
        .await?;
    file.seek(SeekFrom::Start(row.received_bytes as u64))
        .await?;
    file.write_all(&buf).await?;
    file.sync_all().await?;
    drop(file);

    {
        let conn = state.db.lock().await;
        conn.execute(
            "UPDATE blob_uploads SET received_bytes = ?, updated_at = datetime('now')
             WHERE upload_id = ? AND vault_id = ?",
            params![next as i64, &upload_id, &vault_id],
        )?;
    }

    if !is_final {
        return Ok(json_ok(StatusCode::ACCEPTED, json!({"next_offset": next})));
    }

    // Defensive duplicate of the creation cap: cannot fire when creation is correct.
    if next > ABSOLUTE_MAX {
        discard_upload(&state.db, &state.blob_dir, &vault_id, &upload_id).await;
        return Ok(json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"error": "type_cap_exceeded", "max_bytes": ABSOLUTE_MAX}),
        ));
    }

    let bytes = tokio::fs::read(&tmp).await?;
    let digest = blake3::hash(&bytes).to_hex().to_string();
    if digest != row.hash_claimed {
        discard_upload(&state.db, &state.blob_dir, &vault_id, &upload_id).await;
        return Ok(json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({"error": "hash_mismatch"}),
        ));
    }
    if looks_like_svg(&bytes)
        && let Some(kind) = svg_fixpoint_error(&bytes)
    {
        tracing::warn!(
            hash = %row.hash_claimed,
            error = kind,
            "svg rejected at upload finalize"
        );
        discard_upload(&state.db, &state.blob_dir, &vault_id, &upload_id).await;
        return Ok(json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({"error": kind}),
        ));
    }

    let dest = blob_file_path(&state.blob_dir, &vault_id, &row.hash_claimed);
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Unix rename replaces an existing dest. Skip rename when the target is
    // already there so a concurrent same-hash winner is never overwritten.
    let dest_existed = tokio::fs::try_exists(&dest).await?;
    if dest_existed {
        let _ = tokio::fs::remove_file(&tmp).await;
    } else {
        let tmp_file = tokio::fs::OpenOptions::new().write(true).open(&tmp).await?;
        tmp_file.sync_all().await?;
        drop(tmp_file);
        tokio::fs::rename(&tmp, &dest).await?;
    }

    let insert_result = {
        let conn = state.db.lock().await;
        conn.execute(
            "INSERT OR IGNORE INTO blobs (vault_id, hash, size) VALUES (?, ?, ?)",
            params![&vault_id, &row.hash_claimed, row.size_claimed],
        )
    };
    let inserted = match insert_result {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(
                "blob INSERT failed after rename vault={} hash={}: {e}",
                vault_id,
                row.hash_claimed
            );
            if !dest_existed {
                let _ = tokio::fs::remove_file(&dest).await;
            }
            discard_upload(&state.db, &state.blob_dir, &vault_id, &upload_id).await;
            return Err(e.into());
        }
    };
    // 0 rows: concurrent same-hash upload won. The lock makes this rare;
    // OR IGNORE is belt-and-braces. Tmp was discarded above when dest existed;
    // if we renamed onto an empty dest the bytes match the existing hash.
    if inserted == 0 && !dest_existed {
        // INSERT failed to add a row after we placed a new file. Keep the file
        // only if a row now exists; otherwise delete to avoid row-without-file
        // invert (file without row is a GC candidate).
        let has_row: bool = {
            let conn = state.db.lock().await;
            conn.query_row(
                "SELECT 1 FROM blobs WHERE vault_id = ? AND hash = ?",
                params![&vault_id, &row.hash_claimed],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false)
        };
        if !has_row {
            tracing::error!(
                "blob INSERT failed after rename vault={} hash={}",
                vault_id,
                row.hash_claimed
            );
            let _ = tokio::fs::remove_file(&dest).await;
            discard_upload(&state.db, &state.blob_dir, &vault_id, &upload_id).await;
            return Err(ServerError::Io(std::io::Error::other(
                "blob insert failed after rename",
            )));
        }
    }

    {
        let conn = state.db.lock().await;
        conn.execute(
            "DELETE FROM blob_uploads WHERE upload_id = ? AND vault_id = ?",
            params![&upload_id, &vault_id],
        )?;
    }

    Ok(json_ok(
        StatusCode::CREATED,
        json!({"hash": row.hash_claimed}),
    ))
}

/// GET /vault/blobs/{hash}
pub async fn get_blob(
    State(state): State<AppState>,
    VaultAuth(vault_id): VaultAuth,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ServerError> {
    if !is_hash(&hash) {
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            json!({"error": "blob not found"}),
        ));
    }
    let size: Option<i64> = {
        let conn = state.db.lock().await;
        conn.query_row(
            "SELECT size FROM blobs WHERE vault_id = ? AND hash = ?",
            params![&vault_id, &hash],
            |r| r.get(0),
        )
        .optional()?
    };
    let Some(size) = size else {
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            json!({"error": "blob not found"}),
        ));
    };
    let path = blob_file_path(&state.blob_dir, &vault_id, &hash);
    let meta = match tokio::fs::metadata(&path).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json_error(
                StatusCode::NOT_FOUND,
                json!({"error": "blob not found"}),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let total = size.max(0) as u64;
    if meta.len() != total {
        return Ok(json_error(
            StatusCode::NOT_FOUND,
            json!({"error": "blob not found"}),
        ));
    }

    let mut start = 0u64;
    let mut end = total.saturating_sub(1);
    let mut status = StatusCode::OK;
    if let Some(range) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        match parse_byte_range(range, total) {
            Ok(Some((s, e))) => {
                start = s;
                end = e;
                status = StatusCode::PARTIAL_CONTENT;
            }
            Ok(None) => {
                let mut resp = json_error(
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    json!({"error": "range not satisfiable"}),
                );
                resp.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{total}"))
                        .unwrap_or(HeaderValue::from_static("bytes */0")),
                );
                return Ok(resp);
            }
            Err(()) => {}
        }
    }
    let len = if total == 0 {
        0
    } else {
        end.saturating_sub(start).saturating_add(1)
    };
    let mut file = tokio::fs::File::open(&path).await?;
    file.seek(SeekFrom::Start(start)).await?;
    let mut buf = vec![0u8; len as usize];
    if len > 0 {
        file.read_exact(&mut buf).await?;
    }

    let mut resp = Response::new(Body::from(buf));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    h.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{hash}\"")).unwrap_or(HeaderValue::from_static("")),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if status == StatusCode::PARTIAL_CONTENT {
        h.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{total}"))
                .unwrap_or(HeaderValue::from_static("bytes 0-0/0")),
        );
    }
    Ok(resp)
}

#[derive(Deserialize)]
pub struct BlobPathBody {
    path_key: String,
    display_path: String,
    #[serde(default = "default_key_version")]
    key_version: i64,
    generation: i64,
    state: String,
    content_hash: Option<String>,
    size: Option<i64>,
    peer_id: String,
}

fn default_key_version() -> i64 {
    1
}

#[derive(Deserialize)]
pub struct BlobPathQuery {
    #[serde(default)]
    since_seq: i64,
    #[serde(default = "default_list_limit")]
    limit: i64,
}

fn default_list_limit() -> i64 {
    1000
}

#[allow(clippy::too_many_arguments)]
fn path_row_json(
    vault_id: &str,
    path_key: &str,
    display_path: &str,
    key_version: i64,
    generation: i64,
    state: &str,
    content_hash: Option<&str>,
    size: Option<i64>,
    peer_id: &str,
    updated_at: &str,
    seq: i64,
    env_json: Option<&str>,
) -> Value {
    json!({
        "vault_id": vault_id,
        "path_key": path_key,
        "display_path": display_path,
        "key_version": key_version,
        "generation": generation,
        "state": state,
        "content_hash": content_hash,
        "size": size,
        "peer_id": peer_id,
        "updated_at": updated_at,
        "seq": seq,
        "env_json": env_json,
    })
}

/// POST /vault/blob-paths
pub async fn post_blob_path(
    State(state): State<AppState>,
    VaultAuth(vault_id): VaultAuth,
    Json(body): Json<BlobPathBody>,
) -> Result<Response, ServerError> {
    if body.peer_id.is_empty()
        || body.generation < 0
        || body.key_version != 1
        || (body.state != "live" && body.state != "deleted")
        || !validate_blob_key(&body.path_key)
        || !validate_display_path(&body.display_path)
    {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid blob path"}),
        ));
    }
    if body.state == "live" && (body.content_hash.is_none() || body.size.is_none()) {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid blob path"}),
        ));
    }
    if let Some(ref h) = body.content_hash
        && !is_hash(h)
    {
        return Ok(json_error(
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid blob path"}),
        ));
    }
    if let Some(size) = body.size {
        if size < 0 {
            return Ok(json_error(
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid blob path"}),
            ));
        }
        if let Some(cap) = cap_for_key(&body.path_key)
            && size as u64 > cap
        {
            return Ok(json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error": "type_cap_exceeded", "max_bytes": cap}),
            ));
        }
    }

    let lock = state
        .doc_locks
        .get(&path_lock_key(&vault_id, &body.path_key));
    let _guard = lock.lock().await;

    let stored: Option<StoredPath> = {
        let conn = state.db.lock().await;
        conn.query_row(
            "SELECT display_path, key_version, generation, state, content_hash, size,
                    peer_id, updated_at, seq, env_json
             FROM blob_path_states WHERE vault_id = ? AND path_key = ?",
            params![&vault_id, &body.path_key],
            |r| {
                Ok(StoredPath {
                    display_path: r.get(0)?,
                    key_version: r.get(1)?,
                    generation: r.get(2)?,
                    state: r.get(3)?,
                    content_hash: r.get(4)?,
                    size: r.get(5)?,
                    peer_id: r.get(6)?,
                    updated_at: r.get(7)?,
                    seq: r.get(8)?,
                    env_json: r.get(9)?,
                })
            },
        )
        .optional()?
    };

    if let Some(ref cur) = stored
        && cur.generation == body.generation
        && cur.content_hash == body.content_hash
        && cur.state == body.state
    {
        return Ok(json_ok(
            StatusCode::OK,
            json!({"accepted": true, "seq": cur.seq}),
        ));
    }

    if let Some(ref cur) = stored {
        let incoming_hash = body.content_hash.clone().unwrap_or_default();
        let stored_hash = cur.content_hash.clone().unwrap_or_default();
        let wins = body.generation > cur.generation
            || (body.generation == cur.generation
                && (body.peer_id.as_str(), incoming_hash.as_str())
                    > (cur.peer_id.as_str(), stored_hash.as_str()));
        if !wins {
            return Ok(json_ok(
                StatusCode::CONFLICT,
                json!({
                    "accepted": false,
                    "current": path_row_json(
                        &vault_id,
                        &body.path_key,
                        &cur.display_path,
                        cur.key_version,
                        cur.generation,
                        &cur.state,
                        cur.content_hash.as_deref(),
                        cur.size,
                        &cur.peer_id,
                        &cur.updated_at,
                        cur.seq,
                        cur.env_json.as_deref(),
                    ),
                }),
            ));
        }
    }

    let skip_412 = body.state == "deleted" && body.content_hash.is_none();
    if !skip_412 && let Some(ref hash) = body.content_hash {
        let present: bool = {
            let conn = state.db.lock().await;
            conn.query_row(
                "SELECT 1 FROM blobs WHERE vault_id = ? AND hash = ?",
                params![&vault_id, hash],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false)
        };
        if !present {
            return Ok(json_error(
                StatusCode::PRECONDITION_FAILED,
                json!({"error": "blob not uploaded"}),
            ));
        }
    }

    if body.state == "live"
        && last_extension(&body.path_key) == Some("svg")
        && let Some(ref hash) = body.content_hash
    {
        let path = blob_file_path(&state.blob_dir, &vault_id, hash);
        let bytes = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(json_error(
                    StatusCode::PRECONDITION_FAILED,
                    json!({"error": "blob not uploaded"}),
                ));
            }
            Err(e) => return Err(e.into()),
        };
        if let Some(kind) = svg_fixpoint_error(&bytes) {
            tracing::warn!(
                hash = %hash,
                path_key = %body.path_key,
                error = kind,
                "svg rejected at path attach"
            );
            return Ok(json_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({"error": kind}),
            ));
        }
    }

    let seq: i64 = {
        let mut conn = state.db.lock().await;
        let tx = conn.transaction()?;
        let seq: i64 = tx.query_row(
            "UPDATE counters SET value = value + 1 WHERE name = 'blob_seq' RETURNING value",
            [],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO blob_path_states (
                vault_id, path_key, display_path, key_version, generation, state,
                content_hash, size, peer_id, seq, env_json
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
             ON CONFLICT(vault_id, path_key) DO UPDATE SET
                display_path = excluded.display_path,
                key_version = excluded.key_version,
                generation = excluded.generation,
                state = excluded.state,
                content_hash = excluded.content_hash,
                size = excluded.size,
                peer_id = excluded.peer_id,
                updated_at = datetime('now'),
                seq = excluded.seq,
                env_json = excluded.env_json",
            params![
                &vault_id,
                &body.path_key,
                &body.display_path,
                body.key_version,
                body.generation,
                &body.state,
                &body.content_hash,
                body.size,
                &body.peer_id,
                seq,
            ],
        )?;
        tx.commit()?;
        seq
    };

    let _ = state.broadcast_tx.send(BroadcastEvent::BlobPathChanged {
        vault_id: vault_id.clone(),
        path_key: body.path_key.clone(),
        seq,
    });

    Ok(json_ok(
        StatusCode::OK,
        json!({"accepted": true, "seq": seq}),
    ))
}

struct StoredPath {
    display_path: String,
    key_version: i64,
    generation: i64,
    state: String,
    content_hash: Option<String>,
    size: Option<i64>,
    peer_id: String,
    updated_at: String,
    seq: i64,
    env_json: Option<String>,
}

/// GET /vault/blob-paths
pub async fn list_blob_paths(
    State(state): State<AppState>,
    VaultAuth(vault_id): VaultAuth,
    Query(query): Query<BlobPathQuery>,
) -> Result<Response, ServerError> {
    let limit = if query.limit <= 0 {
        1000
    } else {
        query.limit.min(1000)
    };
    let conn = state.db.lock().await;
    let max_seq: i64 = conn.query_row(
        "SELECT COALESCE(MAX(seq), 0) FROM blob_path_states WHERE vault_id = ?",
        params![&vault_id],
        |r| r.get(0),
    )?;
    let mut stmt = conn.prepare(
        "SELECT path_key, display_path, key_version, generation, state, content_hash, size,
                peer_id, updated_at, seq, env_json
         FROM blob_path_states
         WHERE vault_id = ? AND seq > ?
         ORDER BY seq ASC
         LIMIT ?",
    )?;
    let rows = stmt
        .query_map(params![&vault_id, query.since_seq, limit], |r| {
            let path_key: String = r.get(0)?;
            let display_path: String = r.get(1)?;
            let key_version: i64 = r.get(2)?;
            let generation: i64 = r.get(3)?;
            let state: String = r.get(4)?;
            let content_hash: Option<String> = r.get(5)?;
            let size: Option<i64> = r.get(6)?;
            let peer_id: String = r.get(7)?;
            let updated_at: String = r.get(8)?;
            let seq: i64 = r.get(9)?;
            let env_json: Option<String> = r.get(10)?;
            Ok(path_row_json(
                &vault_id,
                &path_key,
                &display_path,
                key_version,
                generation,
                &state,
                content_hash.as_deref(),
                size,
                &peer_id,
                &updated_at,
                seq,
                env_json.as_deref(),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    drop(conn);
    Ok(json_ok(
        StatusCode::OK,
        json!({"states": rows, "max_seq": max_seq}),
    ))
}
