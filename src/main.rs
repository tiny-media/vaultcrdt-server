use tokio::sync::broadcast;
use tracing::{info, warn};
use vaultcrdt_server::{
    AppState, BroadcastEvent, DocLocks, build_router, cli, cli::Invocation, db,
};

const DEFAULT_TOMBSTONE_RETENTION_DAYS: i64 = 365;
const DEFAULT_PEER_RETENTION_DAYS: i64 = 365;

async fn run_server() -> anyhow::Result<()> {
    let bind = std::env::var("VAULTCRDT_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let db_path =
        std::env::var("VAULTCRDT_DB_PATH").unwrap_or_else(|_| "./vaultcrdt.db".to_string());
    let jwt_secret =
        std::env::var("VAULTCRDT_JWT_SECRET").expect("VAULTCRDT_JWT_SECRET must be set");
    let admin_token =
        std::env::var("VAULTCRDT_ADMIN_TOKEN").expect("VAULTCRDT_ADMIN_TOKEN must be set");

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
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    cli::run(&database, &args, &mut out, &mut err).await
}

#[tokio::main]
async fn main() {
    let mut raw = std::env::args();
    // The binary name (argv[0]) is not part of the invocation contract.
    let _ = raw.next();
    // ponytail: hand-rolled dispatch; upgrade to clap when a 4th command or
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

#[cfg(test)]
mod tests {
    use super::{DEFAULT_PEER_RETENTION_DAYS, DEFAULT_TOMBSTONE_RETENTION_DAYS};

    #[test]
    fn default_tombstone_retention_is_private_long_offline_safe() {
        assert_eq!(DEFAULT_TOMBSTONE_RETENTION_DAYS, 365);
        assert_eq!(
            DEFAULT_PEER_RETENTION_DAYS,
            DEFAULT_TOMBSTONE_RETENTION_DAYS
        );
    }
}
