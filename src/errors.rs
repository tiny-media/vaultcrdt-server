use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("migration error: {0}")]
    Migration(#[from] rusqlite_migration::Error),

    #[error("auth error: {0}")]
    Auth(String),

    #[error("too many requests")]
    TooManyRequests,

    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("bad frame: {0}")]
    BadFrame(String),

    #[error("sync error: {0}")]
    Sync(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl ServerError {
    /// (stable code, client-safe text). Internals stay in the server log.
    pub fn client_facing(&self) -> (&'static str, &'static str) {
        match self {
            Self::BadFrame(_) => ("bad_frame", "message could not be decoded"),
            Self::Sync(_) => (
                "sync_failed",
                "document could not be processed — not synced",
            ),
            Self::Db(_) | Self::Migration(_) => {
                ("storage_error", "server storage error — not synced")
            }
            _ => ("internal", "internal server error"),
        }
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ServerError::Auth(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            ServerError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            ServerError::Jwt(_) => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            ServerError::Db(_) | ServerError::Migration(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error".to_string(),
            ),
            ServerError::Sync(_) => (StatusCode::INTERNAL_SERVER_ERROR, "sync error".to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
