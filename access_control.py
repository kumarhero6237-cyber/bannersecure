"""
Access-key + domain-lock layer for the Raven Info/Banner API.

* Keys are created from the admin panel (/admin).
* A key works ONLY on the domains saved for it. A new key has no domain,
  so by default it works nowhere until you add one.
* Browser calls are checked against the Origin / Referer header.
* Server-side calls (no Origin/Referer) are allowed only from IPs saved on the key.
"""
import functools
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Blueprint, jsonify, make_response, render_template, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

KEY_PREFIX = "RVN-"
COOKIE_NAME = "raven_admin"
SESSION_TTL = int(os.environ.get("ADMIN_SESSION_HOURS", "12")) * 3600


# ===============================
# Storage
# ===============================
class LocalStore:
    """JSON file storage. Fine for a VPS / Render disk / local PC."""

    kind = "local"

    def __init__(self):
        self._lock = threading.Lock()
        self._rate = {}
        env_path = os.environ.get("KEYS_FILE")
        here = os.path.dirname(os.path.abspath(__file__))
        candidates = [env_path] if env_path else [
            os.path.join(here, "data", "keys.json"),
            "/tmp/raven_keys.json",
        ]
        self.path = None
        for p in candidates:
            try:
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "a"):
                    pass
                self.path = p
                break
            except OSError:
                continue
        # /tmp (serverless) is wiped between deployments / instances
        self.persistent = bool(self.path) and not self.path.startswith("/tmp")

    def _read(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict):
                d.setdefault("keys", {})
                d.setdefault("usage", {})
                return d
        except Exception:
            pass
        return {"keys": {}, "usage": {}}

    def _write(self, d):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False)
        os.replace(tmp, self.path)

    @staticmethod
    def _merge(rec, usage):
        u = usage or {}
        out = dict(rec)
        out["used"] = int(u.get("used", 0))
        out["last_used"] = int(u.get("last", 0))
        out["last_host"] = u.get("host", "")
        return out

    def all_keys(self):
        with self._lock:
            d = self._read()
        return [self._merge(r, d["usage"].get(k)) for k, r in d["keys"].items()]

    def get(self, key):
        with self._lock:
            d = self._read()
        rec = d["keys"].get(key)
        return self._merge(rec, d["usage"].get(key)) if rec else None

    def put(self, key, rec):
        with self._lock:
            d = self._read()
            d["keys"][key] = rec
            self._write(d)

    def delete(self, key):
        with self._lock:
            d = self._read()
            d["keys"].pop(key, None)
            d["usage"].pop(key, None)
            self._write(d)

    def hit(self, key, host):
        with self._lock:
            d = self._read()
            u = d["usage"].setdefault(key, {"used": 0})
            u["used"] = int(u.get("used", 0)) + 1
            u["last"] = int(time.time())
            u["host"] = host
            self._write(d)

    def rate_peek(self, bucket):
        c, reset = self._rate.get(bucket, (0, 0))
        return c if time.time() < reset else 0

    def rate_hit(self, bucket, window):
        now = time.time()
        c, reset = self._rate.get(bucket, (0, 0))
        if now >= reset:
            c, reset = 0, now + window
        self._rate[bucket] = (c + 1, reset)


class UpstashStore:
    """Upstash Redis / Vercel KV over REST. Use this on Vercel (persistent)."""

    kind = "upstash"
    persistent = True

    def __init__(self, url, token):
        import httpx  # imported lazily so the module loads without it

        self.url = url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}
        self.client = httpx.Client(timeout=8.0)

    def _pipe(self, cmds):
        r = self.client.post(
            self.url + "/pipeline",
            headers=self.headers,
            json=[[str(a) for a in c] for c in cmds],
        )
        r.raise_for_status()
        out = []
        for item in r.json():
            if isinstance(item, dict) and item.get("error"):
                raise RuntimeError(item["error"])
            out.append(item.get("result") if isinstance(item, dict) else item)
        return out

    @staticmethod
    def _pairs(flat):
        flat = flat or []
        return {flat[i]: flat[i + 1] for i in range(0, len(flat) - 1, 2)}

    @staticmethod
    def _merge(rec_json, used, last):
        rec = json.loads(rec_json)
        rec["used"] = int(used or 0)
        ts, _, host = (last or "0|").partition("|")
        rec["last_used"] = int(ts or 0)
        rec["last_host"] = host
        return rec

    def all_keys(self):
        keys, used, last = self._pipe(
            [("HGETALL", "raven:keys"), ("HGETALL", "raven:used"), ("HGETALL", "raven:last")]
        )
        used, last = self._pairs(used), self._pairs(last)
        return [self._merge(v, used.get(k), last.get(k)) for k, v in self._pairs(keys).items()]

    def get(self, key):
        rec, used, last = self._pipe(
            [("HGET", "raven:keys", key), ("HGET", "raven:used", key), ("HGET", "raven:last", key)]
        )
        return self._merge(rec, used, last) if rec else None

    def put(self, key, rec):
        self._pipe([("HSET", "raven:keys", key, json.dumps(rec, ensure_ascii=False))])

    def delete(self, key):
        self._pipe([("HDEL", "raven:keys", key), ("HDEL", "raven:used", key), ("HDEL", "raven:last", key)])

    def hit(self, key, host):
        self._pipe([
            ("HINCRBY", "raven:used", key, 1),
            ("HSET", "raven:last", key, f"{int(time.time())}|{host}"),
        ])

    def rate_peek(self, bucket):
        return int(self._pipe([("GET", bucket)])[0] or 0)

    def rate_hit(self, bucket, window):
        n = self._pipe([("INCR", bucket)])[0]
        if int(n) == 1:
            self._pipe([("EXPIRE", bucket, window)])


# Built-in Upstash Redis connection (used when no env variables are set).
# Env variables UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN (or KV_REST_API_*) override these.
# KEEP THE GITHUB REPO PRIVATE: anyone who can read this token can edit your keys database.
DEFAULT_UPSTASH_URL = "https://faithful-bat-191818.upstash.io"
DEFAULT_UPSTASH_TOKEN = "gQAAAAAAAu1KAAIgcDI1OTlkMWVlYTZkNDI0YjExODk0NDlhYzY0MjkyMGZhMg"


def _make_store():
    url = (os.environ.get("UPSTASH_REDIS_REST_URL") or os.environ.get("KV_REST_API_URL")
           or DEFAULT_UPSTASH_URL)
    token = (os.environ.get("UPSTASH_REDIS_REST_TOKEN") or os.environ.get("KV_REST_API_TOKEN")
             or DEFAULT_UPSTASH_TOKEN)
    if url and token:
        return UpstashStore(url, token)
    return LocalStore()


store = _make_store()


# ===============================
# Helpers
# ===============================
def _err(msg, status, **extra):
    return jsonify({"error": msg, **extra}), status


_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_RE = re.compile(rf"^(?:\*\.)?{_LABEL}(?:\.{_LABEL})*$")


def normalize_domain(raw):
    """'https://Example.com:443/x' -> 'example.com'. '*.example.com' = subdomains only."""
    s = (raw or "").strip().lower()
    if not s:
        return None
    if "://" in s:
        s = urlparse(s).netloc
    s = re.split(r"[/?#]", s, 1)[0].rsplit("@", 1)[-1]
    s = re.sub(r":\d+$", "", s).rstrip(".")
    if not s or s == "*" or not _HOST_RE.match(s):
        raise ValueError(f"Invalid domain: {raw!r}")
    if s.startswith("*.") and "." not in s[2:]:
        raise ValueError(f"Wildcard too broad: {raw!r}")
    return s


def normalize_ip(raw):
    try:
        return str(ipaddress.ip_address((raw or "").strip()))
    except ValueError:
        raise ValueError(f"Invalid IP: {raw!r}")


def parse_list(value, fn):
    if value is None:
        return []
    items = value if isinstance(value, list) else re.split(r"[,\s]+", str(value))
    out = []
    for it in items:
        if str(it).strip():
            v = fn(str(it))
            if v and v not in out:
                out.append(v)
    return out


def parse_expiry(value):
    """'' / None -> 0 (never). 'YYYY-MM-DD' -> end of that day (UTC)."""
    if not value:
        return 0
    try:
        d = datetime.strptime(str(value), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("Expiry must be YYYY-MM-DD")
    return int(d.timestamp()) + 86399


def parse_limit(value):
    if value in (None, ""):
        return 0
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError("Max requests must be a number")
    if n < 0:
        raise ValueError("Max requests cannot be negative")
    return n


def host_allowed(host, domains):
    for d in domains:
        if d.startswith("*."):
            if host.endswith("." + d[2:]):
                return True
        elif host == d:
            return True
    return False


def client_ip():
    if os.environ.get("TRUST_PROXY_HEADERS", "1") == "1":
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote_addr or ""


def request_origin_host():
    """(has_origin, host) from Origin, falling back to Referer."""
    for name in ("Origin", "Referer"):
        v = (request.headers.get(name) or "").strip()
        if v:
            try:
                host = (urlparse(v).hostname or "").lower().rstrip(".")
            except ValueError:
                host = ""
            return True, host
    return False, ""


# ===============================
# API-key check (used by /uc-* routes)
# ===============================
def authorize():
    """Return (record, None) when allowed, else (None, (flask_response, status))."""
    key = (request.args.get("key") or request.headers.get("X-API-Key") or "").strip()
    if not key:
        return None, _err("API key required", 401)
    try:
        rec = store.get(key)
    except Exception as e:  # fail closed
        print(f"[access] store error: {e}")
        return None, _err("Key store unavailable", 503)
    if not rec:
        return None, _err("Invalid API key", 401)
    if not rec.get("active", True):
        return None, _err("API key is disabled", 403)
    exp = int(rec.get("expires_at") or 0)
    if exp and time.time() > exp:
        return None, _err("API key expired", 403)

    has_origin, host = request_origin_host()
    ip = client_ip()
    if has_origin:
        ok = bool(host) and host_allowed(host, rec.get("domains") or [])
    else:
        ok = ip in (rec.get("ips") or [])
    if not ok:
        return None, _err(
            "This API key is not allowed on this domain",
            403,
            detected=host if has_origin else "no Origin/Referer header",
        )

    limit = int(rec.get("max_requests") or 0)
    if limit and rec.get("used", 0) >= limit:
        return None, _err("API key request limit reached", 429)
    try:
        store.hit(key, host or ip)
    except Exception as e:
        print(f"[access] usage write failed: {e}")
    return rec, None


# ===============================
# Admin
# ===============================
admin_bp = Blueprint("admin", __name__)


# Salted PBKDF2-SHA256 hash of the default admin password (the password itself is NOT stored anywhere).
# Override with env ADMIN_PASSWORD_HASH (make one with: python tools/make_password_hash.py).
DEFAULT_ADMIN_HASH = (
    "pbkdf2_sha256$260000$18bb19374cefd29f9b8314f827cc29c1$"
    "c80b80280bf23164526951d30ee9cbb20dcf2eae5fc905165f87a745d760fbdd"
)


def make_password_hash(password, iterations=260000):
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations).hex()
    return f"pbkdf2_sha256${iterations}${salt}${dk}"


def verify_password(password, stored):
    try:
        algo, it, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(it)).hex()
        return hmac.compare_digest(dk, digest)
    except Exception:
        return False


def _password_hash():
    """Hash used for admin login. Priority: ADMIN_PASSWORD_HASH > ADMIN_PASSWORD (hashed in memory) > built-in default."""
    h = os.environ.get("ADMIN_PASSWORD_HASH", "").strip()
    if h:
        return h
    plain = os.environ.get("ADMIN_PASSWORD", "")
    if plain:
        return _hash_env_plain(plain)
    return DEFAULT_ADMIN_HASH


_plain_cache = {}


def _hash_env_plain(plain):
    if plain not in _plain_cache:
        _plain_cache[plain] = make_password_hash(plain)
    return _plain_cache[plain]


def _secret():
    s = os.environ.get("SESSION_SECRET", "")
    if s:
        return s
    # derived from the hash: changing the password invalidates old sessions
    return hashlib.sha256(("raven-session:" + _password_hash()).encode()).hexdigest()


def _serializer():
    return URLSafeTimedSerializer(_secret(), salt="raven-admin")


def is_admin():
    tok = request.cookies.get(COOKIE_NAME, "")
    if not tok:
        return False
    try:
        return _serializer().loads(tok, max_age=SESSION_TTL).get("a") == 1
    except (BadSignature, SignatureExpired):
        return False


def admin_required(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not is_admin():
            return _err("Admin login required", 401)
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("X-Requested-With") != "raven-admin":
            return _err("Bad request", 400)
        return fn(*a, **kw)

    return wrapper


def _no_cache(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@admin_bp.route("/admin")
def admin_page():
    return _no_cache(make_response(render_template("admin.html")))


@admin_bp.route("/admin/api/me")
def me():
    authed = is_admin()
    out = {"configured": True, "authed": authed}
    if authed:
        out["storage"] = {"kind": store.kind, "persistent": store.persistent}
    return _no_cache(jsonify(out))


@admin_bp.route("/admin/api/login", methods=["POST"])
def login():
    if request.headers.get("X-Requested-With") != "raven-admin":
        return _err("Bad request", 400)
    bucket = f"raven:login:{client_ip()}"
    try:
        if store.rate_peek(bucket) >= 8:
            return _err("Too many attempts. Try again in 10 minutes.", 429)
    except Exception as e:
        print(f"[admin] rate check failed: {e}")
    given = str((request.get_json(silent=True) or {}).get("password", ""))
    if not verify_password(given, _password_hash()):
        try:
            store.rate_hit(bucket, 600)
        except Exception:
            pass
        time.sleep(0.6)
        return _err("Wrong password", 401)
    resp = jsonify({"ok": True})
    resp.set_cookie(
        COOKIE_NAME,
        _serializer().dumps({"a": 1}),
        max_age=SESSION_TTL,
        httponly=True,
        samesite="Strict",
        secure=request.is_secure or request.headers.get("X-Forwarded-Proto") == "https",
        path="/",
    )
    return _no_cache(resp)


@admin_bp.route("/admin/api/logout", methods=["POST"])
def logout():
    resp = jsonify({"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/")
    return _no_cache(resp)


def _new_key():
    return KEY_PREFIX + secrets.token_urlsafe(24)


def _apply_fields(rec, body):
    if "label" in body:
        rec["label"] = str(body.get("label") or "").strip()[:80] or "Untitled"
    if "domains" in body:
        rec["domains"] = parse_list(body["domains"], normalize_domain)
    if "ips" in body:
        rec["ips"] = parse_list(body["ips"], normalize_ip)
    if "expires" in body:
        rec["expires_at"] = parse_expiry(body["expires"])
    if "max_requests" in body:
        rec["max_requests"] = parse_limit(body["max_requests"])
    if "active" in body:
        rec["active"] = bool(body["active"])


def _public(rec, key):
    out = dict(rec)
    out["key"] = key
    return out


@admin_bp.route("/admin/api/keys", methods=["GET"])
@admin_required
def list_keys():
    try:
        rows = store.all_keys()
    except Exception as e:
        return _err(f"Key store error: {e}", 503)
    rows.sort(key=lambda r: r.get("created_at", 0), reverse=True)
    return _no_cache(jsonify({"keys": rows}))


@admin_bp.route("/admin/api/keys", methods=["POST"])
@admin_required
def create_key():
    body = request.get_json(silent=True) or {}
    rec = {"label": "Untitled", "domains": [], "ips": [], "active": True,
           "created_at": int(time.time()), "expires_at": 0, "max_requests": 0}
    try:
        _apply_fields(rec, body)
        key = _new_key()
        rec["key"] = key
        store.put(key, rec)
    except ValueError as e:
        return _err(str(e), 400)
    except Exception as e:
        return _err(f"Key store error: {e}", 503)
    return _no_cache(jsonify(_public(rec, key)))


def _load(key):
    rec = store.get(key)
    if rec:
        for f in ("used", "last_used", "last_host"):
            rec.pop(f, None)
    return rec


@admin_bp.route("/admin/api/keys/<key>", methods=["PATCH"])
@admin_required
def update_key(key):
    body = request.get_json(silent=True) or {}
    try:
        rec = _load(key)
        if not rec:
            return _err("Key not found", 404)
        _apply_fields(rec, body)
        store.put(key, rec)
    except ValueError as e:
        return _err(str(e), 400)
    except Exception as e:
        return _err(f"Key store error: {e}", 503)
    return jsonify(_public(rec, key))


@admin_bp.route("/admin/api/keys/<key>/rotate", methods=["POST"])
@admin_required
def rotate_key(key):
    try:
        rec = _load(key)
        if not rec:
            return _err("Key not found", 404)
        new = _new_key()
        rec["key"] = new
        store.put(new, rec)
        store.delete(key)
    except Exception as e:
        return _err(f"Key store error: {e}", 503)
    return jsonify(_public(rec, new))


@admin_bp.route("/admin/api/keys/<key>", methods=["DELETE"])
@admin_required
def delete_key(key):
    try:
        store.delete(key)
    except Exception as e:
        return _err(f"Key store error: {e}", 503)
    return jsonify({"ok": True})
