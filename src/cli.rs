//! Operator CLI: vault create/list, invite mint. Runs against the same DB as
//! the server; no auth (container exec is the trust boundary).
use crate::{db, invites, valid_vault_id};
use sqlx::SqlitePool;
use std::io::Write;

pub const USAGE: &str = "\
usage: vaultcrdt-server                      run the server
       vaultcrdt-server vault create NAME [--server-url URL] [--json]
       vaultcrdt-server vault list [--json]
       vaultcrdt-server invite mint VAULT [--server-url URL] [--json]
";

/// What `main` should do with the process arguments. Kept as a pure
/// function so the dispatch itself is testable (reviewed 2026-09-06:
/// an unknown first argument used to fall through to the server branch —
/// a typo could start a second server against the same SQLite file).
#[derive(Debug, PartialEq, Eq)]
pub enum Invocation {
    Server,
    Cli(Vec<String>),
    UsageError,
}

pub fn parse_invocation(mut args: impl Iterator<Item = String>) -> Invocation {
    let Some(first) = args.next() else {
        return Invocation::Server;
    };
    if matches!(
        first.as_str(),
        "vault" | "invite" | "help" | "--help" | "-h"
    ) {
        return Invocation::Cli(std::iter::once(first).chain(args).collect());
    }
    // Unknown first argument: never silently start a server.
    Invocation::UsageError
}

/// Percent-encode for the setup URI. Unreserved set per RFC 3986.
pub(crate) fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn setup_uri(server_url: &str, vault_id: &str, invite: Option<&str>) -> String {
    // vaultId and invite use alphabet-safe charsets — only the URL needs encoding.
    let mut uri = format!(
        "obsidian://vaultcrdt/setup?v=1&server={}&vaultId={vault_id}",
        percent_encode(server_url)
    );
    if let Some(invite) = invite {
        uri.push_str(&format!("&invite={invite}"));
    }
    uri
}

struct Parsed {
    positionals: Vec<String>,
    server_url: Option<String>,
    json: bool,
}

/// Flags may appear anywhere after the positionals; unknown `-…` is a usage error.
fn parse(args: &[String]) -> Result<Parsed, ()> {
    let mut p = Parsed {
        positionals: Vec::new(),
        server_url: None,
        json: false,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--json" {
            p.json = true;
        } else if let Some(value) = arg.strip_prefix("--server-url=") {
            p.server_url = Some(normalize_url(value)?);
        } else if arg == "--server-url" {
            let value = args.get(i + 1).ok_or(())?;
            p.server_url = Some(normalize_url(value)?);
            i += 1;
        } else if arg.starts_with('-') {
            return Err(());
        } else {
            p.positionals.push(arg.to_string());
        }
        i += 1;
    }
    Ok(p)
}

fn normalize_url(value: &str) -> Result<String, ()> {
    let url = value.trim().trim_end_matches('/');
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(url.to_string())
    } else {
        Err(())
    }
}

fn kv(out: &mut dyn Write, width: usize, key: &str, value: &str) {
    let _ = writeln!(
        out,
        "{:<width$}{}",
        format!("{key}:"),
        value,
        width = width + 3
    );
}

/// `args` excludes the program name: args[0] is the command.
pub async fn run(
    pool: &SqlitePool,
    args: &[String],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    match args.first().map(String::as_str) {
        Some("help" | "--help" | "-h") => {
            let _ = write!(out, "{USAGE}");
            return 0;
        }
        Some("vault") | Some("invite") => {}
        _ => return usage(err),
    }
    let Ok(p) = parse(&args[1..]) else {
        return usage(err);
    };
    let sub = p.positionals.first().map(String::as_str);
    match (args[0].as_str(), sub, p.positionals.len()) {
        ("vault", Some("create"), 2) => {
            vault_create(
                pool,
                &p.positionals[1],
                p.server_url.as_deref(),
                p.json,
                out,
                err,
            )
            .await
        }
        ("vault", Some("list"), 1) => vault_list(pool, p.json, out, err).await,
        ("invite", Some("mint"), 2) => {
            invite_mint(
                pool,
                &p.positionals[1],
                p.server_url.as_deref(),
                p.json,
                out,
                err,
            )
            .await
        }
        _ => usage(err),
    }
}

fn usage(err: &mut dyn Write) -> i32 {
    let _ = write!(err, "{USAGE}");
    2
}

fn runtime_error(err: &mut dyn Write, e: impl std::fmt::Display) -> i32 {
    let _ = writeln!(err, "error: {e}");
    1
}

async fn vault_create(
    pool: &SqlitePool,
    name: &str,
    server_url: Option<&str>,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    if !valid_vault_id(name) {
        return usage(err);
    }
    match db::vault_exists(pool, name).await {
        Ok(true) => {
            let _ = writeln!(err, "vault exists: {name}");
            return 3;
        }
        Ok(false) => {}
        Err(e) => return runtime_error(err, e),
    }
    let secret = invites::random_secret(
        32,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    );
    // Lost race: the stored secret is not the one we generated — never print it.
    match db::create_vault(pool, name, &secret).await {
        Ok(true) => {}
        Ok(false) => {
            let _ = writeln!(err, "vault exists: {name}");
            return 3;
        }
        Err(e) => return runtime_error(err, e),
    }
    if json {
        let mut value = serde_json::json!({"vault_id": name, "secret": secret});
        if let Some(url) = server_url {
            value["server_url"] = url.into();
            value["setup_uri"] = setup_uri(url, name, None).into();
        }
        let _ = writeln!(out, "{}", serde_json::to_string(&value).unwrap());
        return 0;
    }
    kv(out, 6, "vault", name);
    kv(out, 6, "secret", &secret);
    if let Some(url) = server_url {
        kv(out, 6, "server", url);
        kv(out, 6, "setup", &setup_uri(url, name, None));
    }
    let _ = writeln!(
        out,
        "\nStore the secret. It is shown once and cannot be recovered."
    );
    if let Some(url) = server_url {
        let _ = writeln!(
            out,
            "Next: vaultcrdt-server invite mint {name} --server-url {url}"
        );
    }
    0
}

async fn vault_list(
    pool: &SqlitePool,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let vaults = match db::list_vaults(pool).await {
        Ok(v) => v,
        Err(e) => return runtime_error(err, e),
    };
    if json {
        let rows: Vec<_> = vaults
            .iter()
            .map(|(id, created)| serde_json::json!({"vault_id": id, "created_at": created}))
            .collect();
        let _ = writeln!(out, "{}", serde_json::to_string(&rows).unwrap());
        return 0;
    }
    let width = vaults.iter().map(|(id, _)| id.len()).max().unwrap_or(0);
    for (id, created) in &vaults {
        let _ = writeln!(out, "{id:<width$}  {created}");
    }
    0
}

async fn invite_mint(
    pool: &SqlitePool,
    vault: &str,
    server_url: Option<&str>,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    if !valid_vault_id(vault) {
        return usage(err);
    }
    // invites has no FK to vaults — check here or mint a dangling invite.
    match db::vault_exists(pool, vault).await {
        Ok(true) => {}
        Ok(false) => {
            let _ = writeln!(err, "vault not found: {vault}");
            return 3;
        }
        Err(e) => return runtime_error(err, e),
    }
    let (invite, expires_at) = match invites::mint_invite(pool, vault, "operator-cli", None).await {
        Ok(v) => v,
        Err(e) => return runtime_error(err, e),
    };
    if json {
        let mut value =
            serde_json::json!({"vault_id": vault, "invite": invite, "expires_at": expires_at});
        if let Some(url) = server_url {
            value["server_url"] = url.into();
            value["setup_uri"] = setup_uri(url, vault, Some(&invite)).into();
        }
        let _ = writeln!(out, "{}", serde_json::to_string(&value).unwrap());
        return 0;
    }
    kv(out, 7, "vault", vault);
    kv(out, 7, "invite", &invite);
    kv(out, 7, "expires", &expires_at);
    if let Some(url) = server_url {
        kv(out, 7, "server", url);
        kv(out, 7, "setup", &setup_uri(url, vault, Some(&invite)));
    }
    let _ = writeln!(
        out,
        "\nOpen the setup link on the new device, or render it as a QR code (any QR tool) and scan it with the phone."
    );
    0
}
