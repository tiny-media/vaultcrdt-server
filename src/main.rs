use tokio::sync::broadcast;
use tracing::{info, warn};
use vaultcrdt_server::{
    AppState, BroadcastEvent, DocLocks, build_router, cli, cli::Invocation, db,
};

const DEFAULT_TOMBSTONE_RETENTION_DAYS: i64 = 365;
const DEFAULT_PEER_RETENTION_DAYS: i64 = 365;
const DEFAULT_VAULT_QUOTA_BYTES: u64 = 5 * 1024 * 1024 * 1024;

async fn run_server() -> anyhow::Result<()> {
    let bind = std::env::var("VAULTCRDT_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let db_path =
        std::env::var("VAULTCRDT_DB_PATH").unwrap_or_else(|_| "./vaultcrdt.db".to_string());
    let jwt_secret = require_non_empty("VAULTCRDT_JWT_SECRET");
    let admin_token = require_non_empty("VAULTCRDT_ADMIN_TOKEN");

    let database = db::open_db(&db_path).await?;

    // Background task: hourly cleanup (tombstones + stale peers)
    let tombstone_days: i64 = std::env::var("VAULTCRDT_TOMBSTONE_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_TOMBSTONE_RETENTION_DAYS);
    let peer_days: i64 = std::env::var("VAULTCRDT_PEER_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PEER_RETENTION_DAYS);
    let hourly_db = database.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match db::expire_tombstones(&hourly_db, tombstone_days).await {
                Ok(0) => {}
                Ok(n) => info!("expired {n} stale tombstones"),
                Err(e) => warn!("tombstone expiry failed: {e}"),
            }
            match db::expire_stale_peers(&hourly_db, peer_days).await {
                Ok(0) => {}
                Ok(n) => info!("expired {n} stale peers (>{peer_days} days)"),
                Err(e) => warn!("peer expiry failed: {e}"),
            }
        }
    });

    // Background task: weekly non-blocking DB maintenance
    // (wal_checkpoint(TRUNCATE) + PRAGMA optimize; no VACUUM — that is a manual
    // maintenance-window step, see db::run_full_vacuum).
    let maint_db = database.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(7 * 24 * 3600));
        loop {
            interval.tick().await;
            match db::run_maintenance(&maint_db).await {
                Ok(()) => info!("DB maintenance complete (wal_checkpoint + optimize)"),
                Err(e) => warn!("DB maintenance failed: {e}"),
            }
        }
    });

    let (broadcast_tx, _) = broadcast::channel::<BroadcastEvent>(256);
    let blob_dir = std::env::var("VAULTCRDT_BLOB_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/vaultcrdt/blobs"));
    std::fs::create_dir_all(&blob_dir)?;
    std::fs::create_dir_all(blob_dir.join("tmp"))?;
    // 0 = unlimited. Unset keeps the 5 GiB default from the attachment-lane design.
    let default_quota_bytes = std::env::var("VAULTCRDT_DEFAULT_VAULT_QUOTA")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_VAULT_QUOTA_BYTES);
    let state = AppState {
        db: database,
        jwt_secret,
        admin_token,
        // Behind a CDN/tunnel/reverse-proxy chain the client IP is
        // authoritative only in CF-Connecting-IP; XFF first hop is attacker-
        // controllable (CDN appends), last hop is constant. Off by default.
        trust_proxy: std::env::var("VAULTCRDT_TRUST_PROXY")
            .is_ok_and(|v| !v.is_empty() && v != "0" && v != "false"),
        auth_rate_limiter: std::sync::Arc::new(vaultcrdt_server::auth::AuthRateLimiter::default()),
        broadcast_tx,
        server_epoch: uuid::Uuid::new_v4().to_string(),
        connections: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        doc_locks: DocLocks::default(),
        blob_dir,
        default_quota_bytes,
    };

    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    info!("VaultCRDT server listening on {bind}");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C handler");
    info!("Shutdown signal received");
}

/// CLI branch: tracing to stderr only (stdout carries --json results).
async fn run_cli(args: Vec<String>) -> i32 {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::WARN)
        .init();
    let db_path =
        std::env::var("VAULTCRDT_DB_PATH").unwrap_or_else(|_| "./vaultcrdt.db".to_string());
    // Migrations are idempotent — safe next to a running server.
    let database = match db::open_db(&db_path).await {
        Ok(database) => database,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let default_quota_bytes = std::env::var("VAULTCRDT_DEFAULT_VAULT_QUOTA")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_VAULT_QUOTA_BYTES);
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    cli::run(&database, default_quota_bytes, &args, &mut out, &mut err).await
}

#[tokio::main]
async fn main() {
    let mut raw = std::env::args();
    // The binary name (argv[0]) is not part of the invocation contract.
    let _ = raw.next();
    // note: hand-rolled dispatch; upgrade to clap when a 4th command or
    // nested flags arrive.
    match cli::parse_invocation(raw) {
        Invocation::Cli(args) => std::process::exit(run_cli(args).await),
        Invocation::UsageError => {
            eprint!("{}", cli::USAGE);
            std::process::exit(2);
        }
        Invocation::Server => {}
    }

    // Default keeps per-document logs (debug) off and silences Loro's
    // internal noise. Operators can override with RUST_LOG when debugging.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("info,loro=warn,loro_internal=warn")
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if let Err(e) = run_server().await {
        eprintln!("Server error: {e}");
        std::process::exit(1);
    }
}

/// Read a required secret env var. Fails on UNSET and on EMPTY values: an
/// empty JWT secret would sign tokens with publicly-known material, an empty
/// admin token makes `constant_time_eq("", "")` accept every registration
/// (security review 2026-09-08, finding 3). docker-compose.yml guards both
/// via `${VAR:?…}`; the bare binary and plain `docker run` do not.
fn require_non_empty(var: &str) -> String {
    match require_non_empty_value(var, std::env::var(var)) {
        Ok(value) => value,
        Err(reason) => panic!("{reason}"),
    }
}

/// Pure decision core of [`require_non_empty`], separated for testing.
fn require_non_empty_value(
    var: &str,
    value: Result<String, std::env::VarError>,
) -> Result<String, String> {
    match value {
        Ok(v) if !v.is_empty() => Ok(v),
        Ok(_) => Err(format!("{var} must not be empty")),
        Err(_) => Err(format!("{var} must be set")),
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_PEER_RETENTION_DAYS, DEFAULT_TOMBSTONE_RETENTION_DAYS, require_non_empty};

    #[test]
    fn default_tombstone_retention_is_private_long_offline_safe() {
        assert_eq!(DEFAULT_TOMBSTONE_RETENTION_DAYS, 365);
        assert_eq!(
            DEFAULT_PEER_RETENTION_DAYS,
            DEFAULT_TOMBSTONE_RETENTION_DAYS
        );
    }

    #[test]
    fn require_non_empty_rejects_unset_and_empty() {
        use super::require_non_empty_value;
        use std::env::VarError;
        assert_eq!(
            require_non_empty_value("V", Ok("secret".to_string())),
            Ok("secret".to_string())
        );
        assert!(require_non_empty_value("V", Ok(String::new())).is_err());
        assert!(require_non_empty_value("V", Err(VarError::NotPresent)).is_err());
        assert!(require_non_empty_value("V", Err(VarError::NotUnicode("x".into()))).is_err());
    }
}
