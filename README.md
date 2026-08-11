# nnt-auth

The account-auth + template-sync service for NNT.GG. Implements the contract in
[`../docs/auth-api.md`](../docs/auth-api.md). Rust + axum + Postgres.

## Endpoints

- `GET  /health` — liveness (returns `ok`).
- `POST /auth/login` — `{email,password}` → `{token,display_name,session_id}`.
- `POST /auth/validate` — Bearer token → `{valid,display_name}` or a typed 401.
- `POST /auth/logout` — Bearer token → revokes it.
- `GET  /templates` · `PUT /templates/{name}` · `DELETE /templates/{name}` —
  per-account layout sync (Bearer).
- `POST /admin/accounts` — Bearer = `ADMIN_TOKEN`; `{email,password,display_name}`
  creates or resets an account. No public sign-up.

## Single connection per account

`accounts.current_session` holds the one live session id. Logging in rewrites it
and deletes prior tokens, so the previous device's next `/auth/validate` returns
`401 session_superseded`.

## Config (env)

| var              | default | notes                                    |
|------------------|---------|------------------------------------------|
| `DATABASE_URL`   | —       | `postgres://user:pass@host:5432/db`      |
| `ADMIN_TOKEN`    | —       | bearer for `/admin/accounts`             |
| `PORT`           | `8080`  | listen port                              |
| `TOKEN_TTL_DAYS` | `30`    | issued-token lifetime                    |

## Deploy (Coolify)

Deployed on the `nnt` project against the `nnt-auth-db` Postgres. Build pack:
Dockerfile. Set the env vars above (`DATABASE_URL` = the DB's internal URL). The
desktop app points at it via `NNT_AUTH_BASE`.

## Create the first user

```
curl -X POST https://<auth-host>/admin/accounts \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"…","display_name":"You"}'
```
