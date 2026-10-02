# URL Reliability Dashboard

A small FastAPI application deployed on DigitalOcean App Platform that checks a URL
for HTTP status, response time, DNS status, TLS status, and check timestamp.

- **App Platform** hosts the web app (FastAPI + uvicorn).
- **Managed PostgreSQL** stores URL check history (`url_checks` table).
- **Managed Valkey** caches the latest result per URL (key `url:<sha>:latest`, TTL 60s).

## Endpoints
- `GET /` interactive UI
- `POST /api/check` run a check against a URL
- `GET /api/history?limit=10` recent check history
- `GET /health` connectivity health check

## Environment variables
- `DATABASE_URL` PostgreSQL connection string
- `VALKEY_URL` Valkey/Redis connection string
- `CACHE_TTL` cache TTL seconds (default 60)
- `CHECK_TIMEOUT` outbound check timeout seconds (default 15)
