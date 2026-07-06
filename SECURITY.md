# Security

## Reporting a vulnerability

Open a GitHub issue with the `security` label, or email the maintainer
directly. Please include reproduction steps.

## Authentication model

- **Browser sessions**: `POST /login` verifies a PBKDF2-hashed password
  (100k iterations, per-user salt) and issues a random token stored **hashed**
  in the `sessions` table with a TTL (`SESSION_TTL_HOURS`). The cookie is
  `HttpOnly`, `SameSite=Lax`, and `Secure` when `COOKIE_SECURE=1`.
- **API access**: send `X-API-Key: <key>.<secret>`. Keys are created from the
  dashboard, stored as SHA-256 hashes in the `api_keys` table.
- **Roles**: `Admin`, `Analyst`, `Viewer`. Destructive routes (reset, backup,
  user management, API keys, IP blocking) require `Admin`.
- **First boot**: no default credentials ship with the app. An `admin` user is
  created using `ADMIN_PASSWORD` from the environment, or a random password
  printed once to the console.
- The internal broadcast endpoint used by the demo pipeline subprocess requires
  a shared `INTERNAL_API_TOKEN`.

## Hardening checklist for real deployments

- Set `DEMO_MODE=0` — demo mode **deletes alert data** on every dashboard load.
- Set `COOKIE_SECURE=1` and serve behind TLS (reverse proxy).
- Set explicit `SECRET_KEY`, `ADMIN_PASSWORD`, `INTERNAL_API_TOKEN`.
- Restrict `CORS_ORIGINS` (empty default = same-origin only).
- Rate limiting is in-memory per-process; put a real limiter (e.g. reverse
  proxy) in front for multi-worker deployments.

## Scope notes

This is a portfolio / lab platform. IP "blocking" writes to a blocklist table
and JSON file — it does not touch firewalls. Do not point it at production
traffic without review.
