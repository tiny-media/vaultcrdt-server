use super::{test_pool, test_state};
use crate::{build_router, cli, db};
use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::net::SocketAddr;
use tower::ServiceExt;

/// Run the CLI with captured stdout/stderr.
async fn run(pool: &SqlitePool, args: &[&str]) -> (i32, String, String) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run(pool, &args, &mut out, &mut err).await;
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn field(stdout: &str, key: &str) -> String {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}:")))
        .unwrap_or_else(|| panic!("missing {key} in {stdout:?}"))
        .trim()
        .to_string()
}

#[tokio::test]
async fn cli_vault_create_registers_argon2_and_prints_secret() {
    let pool = test_pool().await;
    let (code, out, err) = run(&pool, &["vault", "create", "v"]).await;
    assert_eq!(code, 0);
    assert_eq!(err, "");
    assert_eq!(field(&out, "vault"), "v");
    let secret = field(&out, "secret");
    assert_eq!(secret.len(), 32);
    assert!(secret.bytes().all(|b| b.is_ascii_alphanumeric()));
    let stored: String = sqlx::query_scalar("SELECT api_key FROM vaults WHERE vault_id = 'v'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(stored.starts_with("$argon2"));
    assert!(db::verify_vault(&pool, "v", &secret).await.unwrap());
}

#[tokio::test]
async fn cli_vault_create_json_and_setup_uri() {
    let pool = test_pool().await;
    let (code, out, err) = run(
        &pool,
        &[
            "vault",
            "create",
            "v",
            "--json",
            "--server-url",
            "https://s.example.com/",
        ],
    )
    .await;
    assert_eq!((code, err.as_str()), (0, ""));
    let value: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(value["vault_id"], "v");
    assert_eq!(value["server_url"], "https://s.example.com");
    assert_eq!(
        value["setup_uri"],
        "obsidian://vaultcrdt/setup?v=1&server=https%3A%2F%2Fs.example.com&vaultId=v"
    );
    assert!(!value["setup_uri"].as_str().unwrap().contains("invite="));
}

#[tokio::test]
async fn cli_vault_create_exists_exit_3() {
    let pool = test_pool().await;
    let (_, out, _) = run(&pool, &["vault", "create", "v"]).await;
    let secret = field(&out, "secret");

    let (code, out, err) = run(&pool, &["vault", "create", "v"]).await;
    assert_eq!(code, 3);
    assert_eq!(out, "");
    assert_eq!(err, "vault exists: v\n");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM vaults")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert!(db::verify_vault(&pool, "v", &secret).await.unwrap());
}

#[tokio::test]
async fn cli_vault_create_invalid_name_exit_2() {
    let pool = test_pool().await;
    for name in ["Bad-Name", "-x", &"a".repeat(65)] {
        let (code, out, err) = run(&pool, &["vault", "create", name]).await;
        assert_eq!(code, 2, "name {name}");
        assert_eq!(out, "");
        assert!(err.starts_with("usage:"));
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM vaults")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn cli_vault_list_sorted_and_json() {
    let pool = test_pool().await;
    assert_eq!(run(&pool, &["vault", "list"]).await.1, "");
    assert_eq!(run(&pool, &["vault", "list", "--json"]).await.1, "[]\n");

    db::create_vault(&pool, "zeta", "k").await.unwrap();
    db::create_vault(&pool, "alpha", "k").await.unwrap();
    let (code, out, err) = run(&pool, &["vault", "list"]).await;
    assert_eq!((code, err.as_str()), (0, ""));
    let names: Vec<&str> = out
        .lines()
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(names, ["alpha", "zeta"]);
    assert!(out.starts_with("alpha  ")); // left-aligned to max width (5)

    let (_, out, _) = run(&pool, &["vault", "list", "--json"]).await;
    let value: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(value[0]["vault_id"], "alpha");
    assert_eq!(value[1]["vault_id"], "zeta");
    assert!(value[0]["created_at"].is_string());
}

#[tokio::test]
async fn cli_invite_mint_redeemable_via_router() {
    let state = test_state(test_pool().await);
    db::create_vault(&state.pool, "v", "k").await.unwrap();
    let (code, out, err) = run(&state.pool, &["invite", "mint", "v"]).await;
    assert_eq!((code, err.as_str()), (0, ""));
    let token = field(&out, "invite");
    assert_eq!(token.len(), 22);
    assert!(
        token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    );
    let (ttl, inviter): (i64, String) = sqlx::query_as(
        "SELECT unixepoch(expires_at) - unixepoch(created_at), inviter_peer_id FROM invites",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert_eq!(ttl, 900);
    assert_eq!(inviter, "operator-cli");

    let redeem = |token: String| {
        let state = state.clone();
        async move {
            let request = Request::builder()
                .method("POST")
                .uri("/invite/redeem")
                .header("content-type", "application/json")
                .extension(ConnectInfo("127.0.0.1:1234".parse::<SocketAddr>().unwrap()))
                .body(Body::from(
                    json!({"invite":token,"peer_id":"p","device_name":"Phone"}).to_string(),
                ))
                .unwrap();
            let response = build_router(state).oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 8192).await.unwrap();
            (status, serde_json::from_slice::<Value>(&bytes).unwrap())
        }
    };
    let (status, body) = redeem(token.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["device_key"].is_string());
    assert_eq!(redeem(token).await.0, StatusCode::CONFLICT);
}

#[tokio::test]
async fn cli_invite_mint_unknown_vault_exit_3() {
    let pool = test_pool().await;
    let (code, out, err) = run(&pool, &["invite", "mint", "nope"]).await;
    assert_eq!(code, 3);
    assert_eq!(out, "");
    assert_eq!(err, "vault not found: nope\n");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM invites")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn cli_invite_mint_setup_uri_carries_invite() {
    let pool = test_pool().await;
    db::create_vault(&pool, "v", "k").await.unwrap();
    let (code, out, _) = run(
        &pool,
        &[
            "invite",
            "mint",
            "v",
            "--json",
            "--server-url=https://s.example.com",
        ],
    )
    .await;
    assert_eq!(code, 0);
    let value: Value = serde_json::from_str(&out).unwrap();
    let token = value["invite"].as_str().unwrap();
    assert!(
        value["setup_uri"]
            .as_str()
            .unwrap()
            .ends_with(&format!("&vaultId=v&invite={token}")),
        "{value}"
    );
}

#[tokio::test]
async fn cli_usage_and_unknown_exit_2() {
    let pool = test_pool().await;
    for args in [
        vec!["vault"],
        vec!["vault", "frob"],
        vec!["invite", "mint", "v", "--bogus"],
        vec!["vault", "create", "v", "--server-url", "ftp://x"],
        vec!["frobnicate"],
    ] {
        let (code, out, err) = run(&pool, &args).await;
        assert_eq!(code, 2, "{args:?}");
        assert_eq!(out, "");
        assert!(err.starts_with("usage: vaultcrdt-server"), "{args:?}");
    }
    let (code, out, err) = run(&pool, &["help"]).await;
    assert_eq!(code, 0);
    assert!(out.starts_with("usage: vaultcrdt-server"));
    assert_eq!(err, "");
    assert_eq!(run(&pool, &["--help"]).await.0, 0);
    assert_eq!(run(&pool, &["-h"]).await.0, 0);
    // No vault was created by any failing invocation.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM vaults")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn percent_encode_encodes_everything_outside_unreserved() {
    assert_eq!(
        cli::percent_encode("https://a.b/c?d=e f"),
        "https%3A%2F%2Fa.b%2Fc%3Fd%3De%20f"
    );
}

/// The main() dispatch itself: an unknown first argument must NEVER fall
/// through to the server branch (a typo like `vaults list` used to start a
/// second server against the same SQLite file).
#[test]
fn parse_invocation_never_servers_on_unknown_first_arg() {
    use crate::cli::Invocation;
    let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let cli_of = |v: &[&str]| Invocation::Cli(args(v));

    assert_eq!(
        cli::parse_invocation(args(&[]).into_iter()),
        Invocation::Server
    );
    for known in ["vault", "invite", "help", "--help", "-h"] {
        assert_eq!(
            cli::parse_invocation(args(&[known, "x"]).into_iter()),
            cli_of(&[known, "x"]),
            "known first arg {known}"
        );
    }
    // Typos, flags the CLI does not own, anything else: usage error, exit 2.
    for unknown in ["vaults", "frobnicate", "--version", "-v", "Vault"] {
        assert_eq!(
            cli::parse_invocation(args(&[unknown, "list"]).into_iter()),
            Invocation::UsageError,
            "unknown first arg {unknown}"
        );
    }
}
