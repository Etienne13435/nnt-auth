//! NNT.GG account auth + template sync.
//!
//! Implements the contract in `docs/auth-api.md`: email/password login issuing a
//! session token, single-connection enforcement (a new login supersedes the old,
//! checked here so the client needs no cooperation), and per-account template
//! sync so a user's layouts follow them across machines.
//!
//! Config (env):
//!   DATABASE_URL     required   postgres://user:pass@host:5432/db
//!   ADMIN_TOKEN      required   bearer for the /admin account-creation route
//!   PORT             8080       listen port
//!   TOKEN_TTL_DAYS   30         how long an issued token stays valid
//!
//! All timestamps are epoch-millis BIGINTs and the session id is a TEXT uuid, so
//! no extra sqlx type features are needed.

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(Clone)]
struct App {
    pool: PgPool,
    admin_token: String,
    ttl_ms: i64,
    /// A valid Argon2 hash of throwaway input, verified against on a missing
    /// account so login takes the same time whether or not the email exists.
    dummy_hash: String,
}

type ApiError = (StatusCode, Json<Value>);

fn err(status: StatusCode, code: &str) -> ApiError {
    (status, Json(json!({ "error": code })))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A fresh, high-entropy opaque token: two v4 uuids' worth of randomness, hex,
/// no dashes — ~244 bits, plenty for a bearer secret.
fn new_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

#[tokio::main]
async fn main() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required");
    let admin_token = std::env::var("ADMIN_TOKEN").expect("ADMIN_TOKEN is required");
    let port: u16 = std::env::var("PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8080);
    let ttl_days: i64 = std::env::var("TOKEN_TTL_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await
        .expect("connect to Postgres");
    migrate(&pool).await.expect("run migrations");

    let dummy_hash = Argon2::default()
        .hash_password(b"nnt-timing-equalizer", &SaltString::generate(&mut OsRng))
        .expect("dummy hash")
        .to_string();

    let app = App {
        pool,
        admin_token,
        ttl_ms: ttl_days * 24 * 60 * 60 * 1000,
        dummy_hash,
    };

    let router = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/auth/login", post(login))
        .route("/auth/validate", post(validate))
        .route("/auth/logout", post(logout))
        .route("/templates", get(list_templates))
        .route("/templates/:name", put(put_template).delete(delete_template))
        .route("/admin/accounts", post(create_account))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("bind");
    eprintln!("nnt-auth listening on :{port}");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown())
        .await
        .expect("serve");
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
    // Single-connection lives in accounts.current_session: a login rewrites it,
    // and validate rejects any token whose session_id no longer matches.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS accounts (
            id BIGSERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL DEFAULT '',
            pw_hash TEXT NOT NULL,
            current_session TEXT,
            created_at BIGINT NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            session_id TEXT NOT NULL,
            created_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS templates (
            account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            updated_ms BIGINT NOT NULL,
            body TEXT NOT NULL,
            PRIMARY KEY (account_id, name)
        )",
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Resolve a bearer token to its account, enforcing single-connection and expiry.
/// Returns (account_id, display_name) or the precise 401 the client keys off.
async fn account_for(app: &App, headers: &HeaderMap) -> Result<(i64, String), ApiError> {
    let token = bearer(headers).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid"))?;
    let row = sqlx::query(
        "SELECT a.id, a.display_name, a.current_session, s.session_id, s.expires_at
         FROM sessions s JOIN accounts a ON a.id = s.account_id
         WHERE s.token = $1",
    )
    .bind(&token)
    .fetch_optional(&app.pool)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let Some(row) = row else {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid"));
    };
    let id: i64 = row.get("id");
    let display_name: String = row.get("display_name");
    let current: Option<String> = row.get("current_session");
    let session_id: String = row.get("session_id");
    let expires_at: i64 = row.get("expires_at");

    if now_ms() >= expires_at {
        return Err(err(StatusCode::UNAUTHORIZED, "expired"));
    }
    if current.as_deref() != Some(session_id.as_str()) {
        return Err(err(StatusCode::UNAUTHORIZED, "session_superseded"));
    }
    Ok((id, display_name))
}

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    password: String,
}

async fn login(State(app): State<App>, Json(body): Json<LoginBody>) -> Result<Json<Value>, ApiError> {
    let row = sqlx::query("SELECT id, display_name, pw_hash FROM accounts WHERE email = $1")
        .bind(body.email.trim().to_lowercase())
        .fetch_optional(&app.pool)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    let Some(row) = row else {
        // Verify against a throwaway hash anyway: a missing email must cost the
        // same as a wrong password, or the timing gap enumerates accounts.
        if let Ok(dummy) = PasswordHash::new(&app.dummy_hash) {
            let _ = Argon2::default().verify_password(body.password.as_bytes(), &dummy);
        }
        return Err(err(StatusCode::UNAUTHORIZED, "invalid_credentials"));
    };
    let id: i64 = row.get("id");
    let display_name: String = row.get("display_name");
    let pw_hash: String = row.get("pw_hash");

    let parsed = PasswordHash::new(&pw_hash).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "hash"))?;
    if Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed)
        .is_err()
    {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid_credentials"));
    }

    // Issue a fresh session and make it the account's only live one: point
    // current_session at it and drop every prior token for this account.
    let token = new_token();
    let session_id = Uuid::new_v4().to_string();
    let now = now_ms();
    let expires = now + app.ttl_ms;

    let mut tx = app
        .pool
        .begin()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    sqlx::query("UPDATE accounts SET current_session = $1 WHERE id = $2")
        .bind(&session_id)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    sqlx::query("DELETE FROM sessions WHERE account_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    sqlx::query(
        "INSERT INTO sessions (token, account_id, session_id, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&token)
    .bind(id)
    .bind(&session_id)
    .bind(now)
    .bind(expires)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    Ok(Json(json!({
        "token": token,
        "display_name": display_name,
        "session_id": session_id
    })))
}

async fn validate(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let (_, display_name) = account_for(&app, &headers).await?;
    Ok(Json(json!({ "valid": true, "display_name": display_name })))
}

async fn logout(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    if let Some(token) = bearer(&headers) {
        let _ = sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(&token)
            .execute(&app.pool)
            .await;
    }
    Ok(Json(json!({ "ok": true })))
}

async fn list_templates(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let (account_id, _) = account_for(&app, &headers).await?;
    let rows = sqlx::query("SELECT name, updated_ms, body FROM templates WHERE account_id = $1")
        .bind(account_id)
        .fetch_all(&app.pool)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "name": r.get::<String, _>("name"),
                "updated_ms": r.get::<i64, _>("updated_ms"),
                "body": r.get::<String, _>("body"),
            })
        })
        .collect();
    Ok(Json(Value::Array(out)))
}

#[derive(Deserialize)]
struct TemplateBody {
    updated_ms: i64,
    body: String,
}

async fn put_template(
    State(app): State<App>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(t): Json<TemplateBody>,
) -> Result<Json<Value>, ApiError> {
    let (account_id, _) = account_for(&app, &headers).await?;
    // Last-writer-wins: only overwrite when the incoming copy is at least as new.
    sqlx::query(
        "INSERT INTO templates (account_id, name, updated_ms, body)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (account_id, name)
         DO UPDATE SET updated_ms = EXCLUDED.updated_ms, body = EXCLUDED.body
         WHERE templates.updated_ms <= EXCLUDED.updated_ms",
    )
    .bind(account_id)
    .bind(&name)
    .bind(t.updated_ms)
    .bind(&t.body)
    .execute(&app.pool)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(json!({ "ok": true })))
}

async fn delete_template(
    State(app): State<App>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (account_id, _) = account_for(&app, &headers).await?;
    sqlx::query("DELETE FROM templates WHERE account_id = $1 AND name = $2")
        .bind(account_id)
        .bind(&name)
        .execute(&app.pool)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct NewAccount {
    email: String,
    password: String,
    #[serde(default)]
    display_name: String,
}

/// Create (or reset) an account. Guarded by the ADMIN_TOKEN bearer — there is no
/// public sign-up; you provision users deliberately.
async fn create_account(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<NewAccount>,
) -> Result<Json<Value>, ApiError> {
    // Constant-time so a wrong admin token can't be recovered byte-by-byte.
    let provided = bearer(&headers).unwrap_or_default();
    let admin_ok: bool = provided.as_bytes().ct_eq(app.admin_token.as_bytes()).into();
    if !admin_ok {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid"));
    }
    let email = body.email.trim().to_lowercase();
    if email.is_empty() || body.password.len() < 8 {
        return Err(err(StatusCode::BAD_REQUEST, "weak_input"));
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "hash"))?
        .to_string();

    let mut tx = app
        .pool
        .begin()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    sqlx::query(
        "INSERT INTO accounts (email, display_name, pw_hash, created_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (email)
         DO UPDATE SET display_name = EXCLUDED.display_name, pw_hash = EXCLUDED.pw_hash,
                       current_session = NULL",
    )
    .bind(&email)
    .bind(&body.display_name)
    .bind(&hash)
    .bind(now_ms())
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    // A password reset must not leave old tokens live: drop this account's
    // sessions (current_session is already cleared above for an existing row).
    sqlx::query(
        "DELETE FROM sessions WHERE account_id = (SELECT id FROM accounts WHERE email = $1)",
    )
    .bind(&email)
    .execute(&mut *tx)
    .await
    .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    tx.commit()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;

    Ok(Json(json!({ "ok": true, "email": email })))
}
