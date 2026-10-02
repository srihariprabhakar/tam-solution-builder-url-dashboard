import datetime as dt
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import time
import uuid
from urllib.parse import urlsplit

import httpx
import psycopg2
import psycopg2.extras
import redis
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="URL Reliability Dashboard")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
VALKEY_URL = os.environ.get("VALKEY_URL", "")
CACHE_TTL = int(os.environ.get("CACHE_TTL", "60"))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "15"))

RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "20"))
RATE_WINDOW = float(os.environ.get("RATE_WINDOW", "60"))
CHECK_TOKEN = os.environ.get("CHECK_TOKEN", "")

_rate_hits = {}
_rate_lock = __import__("threading").Lock()

PRIVATE_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::/128"),
]

_redis_client = None


def get_redis():
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(
            VALKEY_URL, socket_timeout=5, socket_connect_timeout=5, decode_responses=True
        )
    return _redis_client


def get_conn():
    return psycopg2.connect(DATABASE_URL, connect_timeout=5)


def init_db():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS url_checks (
                    id UUID PRIMARY KEY,
                    url TEXT NOT NULL,
                    http_status INTEGER,
                    response_time_ms REAL,
                    dns_status TEXT,
                    tls_status TEXT,
                    error TEXT,
                    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_url_checks_checked_at ON url_checks (checked_at DESC);"
            )
        conn.commit()
    finally:
        conn.close()


def is_private_host(host: str) -> bool:
    """Resolve host and return True if any resolved IP is private/reserved."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    seen = set()
    for info in infos:
        addr = info[4][0]
        if addr in seen:
            continue
        seen.add(addr)
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        for net in PRIVATE_NETS:
            if ip in net:
                return True
    return False


def validate_url(value: str) -> str:
    """Validate and normalize a URL; raise ValueError if disallowed."""
    value = value.strip()
    if not value:
        raise ValueError("empty URL")
    if not value.lower().startswith(("http://", "https://")):
        value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("only http/https allowed")
    host = parsed.hostname
    if not host:
        raise ValueError("invalid host")
    try:
        ip = ipaddress.ip_address(host)
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False
    if is_ip_literal:
        for net in PRIVATE_NETS:
            if ip in net:
                raise ValueError("private/reserved host not allowed")
    elif is_private_host(host):
        raise ValueError("private/reserved host not allowed")
    return value


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value.startswith("http://") and not value.startswith("https://"):
        value = "https://" + value
    return value


def perform_check(raw_url: str):
    url = validate_url(raw_url)
    result = {
        "url": url,
        "http_status": None,
        "response_time_ms": None,
        "dns_status": "unknown",
        "tls_status": "n/a",
        "error": None,
    }
    start = time.time()
    try:
        host = url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
        try:
            socket.getaddrinfo(host, None)
            result["dns_status"] = "ok"
        except Exception:
            result["dns_status"] = "failed"

        if url.startswith("https://"):
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                    s.settimeout(CHECK_TIMEOUT)
                    s.connect((host, 443))
                    cert = s.getpeercert()
                expire_s = ssl.get_server_certificate((host, 443))
                result["tls_status"] = "ok"
            except Exception:
                result["tls_status"] = "failed"

        with httpx.Client(follow_redirects=True, timeout=CHECK_TIMEOUT) as client:
            resp = client.get(url)
            result["http_status"] = resp.status_code
            result["response_time_ms"] = round((time.time() - start) * 1000, 2)
    except Exception as exc:
        result["error"] = str(exc)[:500]
        result["response_time_ms"] = round((time.time() - start) * 1000, 2)

    result["checked_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    return result


def persist_result(result: dict):
    conn = get_conn()
    try:
        row_id = str(uuid.uuid4())
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO url_checks
                    (id, url, http_status, response_time_ms, dns_status, tls_status, error, checked_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    row_id,
                    result["url"],
                    result["http_status"],
                    result["response_time_ms"],
                    result["dns_status"],
                    result["tls_status"],
                    result["error"],
                    result["checked_at"],
                ),
            )
        conn.commit()
        return row_id
    finally:
        conn.close()


def cache_result(result: dict):
    key = cache_key(result["url"])
    payload = json.dumps(result)
    try:
        r = get_redis()
        r.set(key, payload, ex=CACHE_TTL)
    except Exception:
        pass
    return key


def cache_key(url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    return f"url:{digest}:latest"


@app.on_event("startup")
def _startup():
    init_db()


@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse(INDEX_HTML)


@app.get("/health")
def health():
    status = {"status": "ok", "pg": False, "valkey": False}
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        conn.close()
        status["pg"] = True
    except Exception:
        pass
    try:
        get_redis().ping()
        status["valkey"] = True
    except Exception:
        pass
    if not (status["pg"] and status["valkey"]):
        raise HTTPException(status_code=503, detail=status)
    return status


class CheckRequest(BaseModel):
    url: str


def rate_limited(key: str) -> bool:
    now = time.time()
    with _rate_lock:
        hits = [t for t in _rate_hits.get(key, []) if now - t < RATE_WINDOW]
        if len(hits) >= RATE_LIMIT:
            _rate_hits[key] = hits
            return True
        hits.append(now)
        _rate_hits[key] = hits
        return False


def client_key(req: Request) -> str:
    return req.client.host if (req.client and req.client.host) else "unknown"


@app.post("/api/check")
def check_url(req: CheckRequest, request: Request):
    if CHECK_TOKEN:
        auth = request.headers.get("x-check-token", "")
        if auth != CHECK_TOKEN:
            raise HTTPException(status_code=401, detail="unauthorized")
    key = client_key(request)
    if rate_limited(key):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    try:
        result = perform_check(req.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    result["id"] = persist_result(result)
    result["cache_key"] = cache_result(result)
    return result


@app.get("/api/history")
def history(limit: int = 10):
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, url, http_status, response_time_ms, dns_status, tls_status, error, checked_at "
                "FROM url_checks ORDER BY checked_at DESC LIMIT %s",
                (min(limit, 100),),
            )
            rows = cur.fetchall()
        conn.close()
        return {"checks": rows}
    finally:
        conn.close()


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>URL Reliability Dashboard</title>
<style>
  :root { --bg:#0f172a; --card:#1e293b; --accent:#38bdf8; --ok:#22c55e; --warn:#f59e0b; --err:#ef4444; --muted:#94a3b8; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:#e2e8f0; min-height:100vh; }
  .wrap { max-width:760px; margin:0 auto; padding:32px 20px 64px; }
  h1 { font-size:1.5rem; font-weight:700; margin:0 0 4px; }
  .sub { color:var(--muted); font-size:.9rem; margin:0 0 24px; }
  form { display:flex; gap:10px; margin-bottom:20px; }
  input { flex:1; padding:12px 14px; border-radius:10px; border:1px solid #334155; background:#0b1220; color:#e2e8f0; font-size:1rem; }
  button { padding:12px 20px; border:none; border-radius:10px; background:var(--accent); color:#052033; font-weight:700; font-size:1rem; cursor:pointer; }
  button:disabled { opacity:.5; cursor:not-allowed; }
  .result, .card { background:var(--card); border-radius:12px; padding:20px; margin-top:16px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-top:12px; }
  .stat { background:#0b1220; border-radius:10px; padding:12px; }
  .stat .label { color:var(--muted); font-size:.75rem; text-transform:uppercase; letter-spacing:.05em; }
  .stat .value { font-size:1.25rem; font-weight:600; margin-top:4px; }
  .ok { color:var(--ok); } .warn { color:var(--warn); } .err { color:var(--err); }
  table { width:100%; border-collapse:collapse; margin-top:12px; font-size:.85rem; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #334155; }
  th { color:var(--muted); font-weight:600; }
  code { font-family:ui-monospace,Menlo,monospace; }
  .err-text { color:var(--err); font-size:.85rem; margin-top:8px; word-break:break-all; }
  .spin { display:inline-block; width:14px; height:14px; border:2px solid #05203388; border-top-color:#052033; border-radius:50%; animation:sp .6s linear infinite; vertical-align:middle; margin-right:6px; }
  @keyframes sp { to { transform:rotate(360deg); } }
</style>
</head>
<body>
<div class="wrap">
  <h1>URL Reliability Dashboard</h1>
  <p class="sub">App Platform &middot; Managed PostgreSQL &middot; Managed Valkey</p>
  <form id="f">
    <input id="url" type="text" placeholder="Enter a URL, e.g. example.com" autocomplete="off" value="https://example.com"/>
    <button id="btn" type="submit">Check</button>
  </form>
  <div id="result"></div>
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <strong>Recent checks</strong>
      <button id="refresh" type="button" style="padding:6px 12px;font-size:.8rem;">Refresh</button>
    </div>
    <div id="history"></div>
  </div>
</div>
<script>
const $ = (s) => document.querySelector(s);
async function doCheck(e) {
  e.preventDefault();
  const btn = $("#btn"), url = $("#url").value.trim();
  if (!url) return;
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span>Checking';
  $("#result").innerHTML = "";
  try {
    const r = await fetch("/api/check", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({url})});
    const d = await r.json();
    if (!r.ok) { $("#result").innerHTML = `<div class="result"><div class="err">${escapeHtml(JSON.stringify(d))}</div></div>`; return; }
    renderResult(d);
    loadHistory();
  } catch (err) {
    $("#result").innerHTML = `<div class="result"><div class="err">${escapeHtml(String(err))}</div></div>`;
  } finally { btn.disabled=false; btn.textContent="Check"; }
}
function renderResult(d) {
  const cls = (v, good) => v && v.toString().toLowerCase() === good ? "ok" : "err";
  const status = d.http_status ? `${d.http_status}` : "—";
  const sc = d.http_status >= 200 && d.http_status < 400 ? "ok" : (d.http_status ? "warn" : "err");
  $("#result").innerHTML = `
    <div class="result">
      <strong>Result for <code>${escapeHtml(d.url)}</code></strong>
      <div class="grid">
        <div class="stat"><div class="label">HTTP status</div><div class="value ${sc}">${status}</div></div>
        <div class="stat"><div class="label">Response time</div><div class="value">${d.response_time_ms ?? "—"} ms</div></div>
        <div class="stat"><div class="label">DNS status</div><div class="value ${cls(d.dns_status,'ok')}">${escapeHtml(d.dns_status||"—")}</div></div>
        <div class="stat"><div class="label">TLS status</div><div class="value ${cls(d.tls_status,'ok')}">${escapeHtml(d.tls_status||"—")}</div></div>
        <div class="stat"><div class="label">Checked at</div><div class="value" style="font-size:.95rem;">${new Date(d.checked_at).toLocaleString()}</div></div>
      </div>
      ${d.error ? `<div class="err-text">error: ${escapeHtml(d.error)}</div>` : ""}
      ${d.cache_key ? `<div style="margin-top:10px;color:var(--muted);font-size:.78rem;">cached → <code>${escapeHtml(d.cache_key)}</code></div>` : ""}
    </div>`;
}
async function loadHistory() {
  try {
    const r = await fetch("/api/history?limit=10");
    const d = await r.json();
    const rows = d.checks || [];
    $("#history").innerHTML = rows.length ? `
      <table><thead><tr><th>URL</th><th>HTTP</th><th>ms</th><th>DNS</th><th>TLS</th><th>Checked at</th></tr></thead><tbody>
      ${rows.map(x => `<tr><td><code>${escapeHtml(x.url)}</code></td><td>${x.http_status ?? "—"}</td><td>${x.response_time_ms ?? "—"}</td><td>${escapeHtml(x.dns_status||"—")}</td><td>${escapeHtml(x.tls_status||"—")}</td><td>${new Date(x.checked_at).toLocaleString()}</td></tr>`).join("")}
      </tbody></table>` : `<p style="color:var(--muted)">No checks yet.</p>`;
  } catch (err) { $("#history").innerHTML = `<div class="err">${escapeHtml(String(err))}</div>`; }
}
function escapeHtml(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
$("#f").addEventListener("submit", doCheck);
$("#refresh").addEventListener("click", loadHistory);
loadHistory();
</script>
</body>
</html>
"""
