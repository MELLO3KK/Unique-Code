"""Proven (DM Code) — anti-counterfeit product authentication platform.

Flask app with two main surfaces:
  * ``/``            customer-facing verification stepper
  * ``/dashboard``   business dashboard for brand management

Security model:
  * Product units are registered with a unique public serial and a secret
    passcode.  Passcodes are stored only as salted PBKDF2-HMAC-SHA256 hashes.
  * Verification uses constant-time comparisons.
  * An immutable, append-only ledger records every scan attempt; the first
    valid scan of a unit "claims" it, later valid scans reveal cloning.
  * Per-IP rate limiting protects the verify and register endpoints.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from io import BytesIO

from flask import (
    Flask,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from PIL import Image, ImageDraw, ImageFont

try:
    from pylibdmtx.pylibdmtx import encode as dmtx_encode
    DMTX_AVAILABLE = True
except Exception:  # libdmtx shared library missing (common on Windows)
    dmtx_encode = None
    DMTX_AVAILABLE = False


def _ensure_libdmtx() -> bool:
    """Make sure the native libdmtx shared library can be loaded.

    ``pylibdmtx`` is only a ctypes wrapper — pip does not install the
    native library with it.  On Linux that is ``apt-get install
    libdmtx0b``; on Windows you must supply ``libdmtx-64.dll`` yourself
    (see README.md).  Python 3.8+ no longer searches the script
    directory for DLLs, so register this folder first and then retry the
    import.  Returns ``True`` when DM encoding is available.
    """
    global dmtx_encode, DMTX_AVAILABLE
    if DMTX_AVAILABLE:
        return True
    try:
        if os.name == "nt":
            # A copy of libdmtx-64.dll next to app.py is found this way.
            try:
                os.add_dll_directory(BASE_DIR)
            except (OSError, ValueError):
                pass
        from pylibdmtx.pylibdmtx import encode as dmtx_encode  # noqa: F811
        DMTX_AVAILABLE = True
    except Exception:
        dmtx_encode = None
        DMTX_AVAILABLE = False
    return DMTX_AVAILABLE


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("PROVEN_DB", os.path.join(BASE_DIR, "proven.db"))

_ensure_libdmtx()

PBKDF2_ITERATIONS = 200_000
RATE_LIMIT_WINDOW = 60.0          # seconds
RATE_LIMIT_MAX_VERIFY = 12        # verify attempts per window / IP
RATE_LIMIT_MAX_REGISTER = 30      # registration attempts per window / IP
MAX_LEDGER_ROWS_PER_UNIT = 500    # sanity cap for display

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "PROVEN_SECRET_KEY", secrets.token_hex(32)
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS brands (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT UNIQUE NOT NULL COLLATE NOCASE,
    api_key         TEXT UNIQUE NOT NULL,
    created_utc     TEXT NOT NULL
);

-- Append-only ledger of every successful scan against a genuine unit.
CREATE TABLE IF NOT EXISTS units (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id      INTEGER NOT NULL REFERENCES products(id),
    scanned_utc     TEXT NOT NULL,
    ip              TEXT NOT NULL DEFAULT '',
    user_agent      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS products (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    brand_id        INTEGER NOT NULL REFERENCES brands(id),
    serial          TEXT UNIQUE NOT NULL COLLATE NOCASE,
    code_hash       TEXT NOT NULL,
    code_salt       TEXT NOT NULL,
    kdf_iters       INTEGER NOT NULL,
    product_name    TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    batch           TEXT NOT NULL DEFAULT '',
    issued_utc      TEXT NOT NULL,
    claimed_unit_id INTEGER REFERENCES units(id)
);

-- Every verification attempt (success or failure) is logged for analysis.
CREATE TABLE IF NOT EXISTS scan_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    serial      TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    brand_id    INTEGER REFERENCES brands(id),
    scanned_utc TEXT NOT NULL,
    ip          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_units_product ON units(product_id);
CREATE INDEX IF NOT EXISTS idx_scanlog_brand ON scan_log(brand_id);
"""


def get_db() -> sqlite3.Connection:
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_db(_exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    con.commit()
    con.close()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Cryptography: salted PBKDF2-HMAC-SHA256 + constant-time comparison
# --------------------------------------------------------------------------


def hash_passcode(passcode: str, *, salt: bytes | None = None,
                  iterations: int = PBKDF2_ITERATIONS) -> tuple[str, str, int]:
    """Return (hash_hex, salt_hex, iterations) for a secret passcode."""
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", passcode.encode("utf-8"), salt, iterations
    )
    return dk.hex(), salt.hex(), iterations


def verify_passcode(passcode: str, code_hash: str, salt_hex: str,
                    iterations: int) -> bool:
    """Constant-time check of a passcode against its stored digest."""
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac(
        "sha256", passcode.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(dk.hex(), code_hash.lower())


def new_api_key() -> str:
    return "prv_" + secrets.token_hex(24)


def normalize_serial(raw: str) -> str:
    """Serials are case-insensitive alphanumerics/dashes, max 64 chars."""
    s = "".join((raw or "").split()).upper()
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    if not (6 <= len(s) <= 64):
        return ""
    if not all(ch in allowed for ch in s):
        return ""
    return s


# --------------------------------------------------------------------------
# Per-IP rate limiting (sliding-window, in-process token bucket)
# --------------------------------------------------------------------------

_rate_buckets: dict[tuple[str, str], deque] = defaultdict(deque)


def client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limited(endpoint: str) -> bool:
    """True when the caller exceeded the budget for this endpoint."""
    limit = (RATE_LIMIT_MAX_VERIFY if endpoint == "verify"
             else RATE_LIMIT_MAX_REGISTER)
    key = (endpoint, client_ip())
    now = time.monotonic()
    bucket = _rate_buckets[key]
    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW:
        bucket.popleft()
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False


def rate_limit_response(endpoint: str):
    resp = jsonify({
        "ok": False,
        "error": "rate_limited",
        "message": ("Too many requests from this device. Please wait a "
                    "minute and try again."),
    })
    resp.status_code = 429
    resp.headers["Retry-After"] = str(int(RATE_LIMIT_WINDOW))
    return resp


# --------------------------------------------------------------------------
# Data Matrix code rendering (styled to resemble a QR-like badge)
# --------------------------------------------------------------------------

CODE_BASE_URL = os.environ.get("PROVEN_PUBLIC_URL", "").rstrip("/")


def build_payload(serial: str, passcode: str) -> str:
    """The payload embedded in the physical DM code on the product."""
    base = CODE_BASE_URL or request.url_root.rstrip("/")
    return f"{base}/verify?serial={serial}&key={passcode}"


# Font candidates across platforms (Linux / Windows / macOS).  PIL also
# accepts bare family names like "arialbd.ttf" which it resolves through
# the Windows font registry (HKLM SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts).
_FONT_CANDIDATES = (
    # Windows
    "arialbd.ttf",
    r"C:\Windows\Fonts\arialbd.ttf",
    r"C:\Windows\Fonts\segoeuib.ttf",
    r"C:\Windows\Fonts\calibrib.ttf",
    # Linux
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    # macOS
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "/Library/Fonts/Arial Bold.ttf",
)


def _load_badge_font(size: int = 16):
    for path in _FONT_CANDIDATES:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


def render_dm_badge(payload: str) -> Image.Image:
    """Render a Data Matrix symbol inside a QR-style rounded badge.

    Falls back to a placeholder badge when the native libdmtx shared
    library is unavailable (e.g. ``pylibdmtx`` installed via pip on
    Windows without libdmtx-64.dll on PATH — see README.md).
    The availability check is retried lazily here so that installing
    the library while the app runs (or fixing the DLL search path)
    takes effect without a restart.
    """
    if not _ensure_libdmtx():
        return _render_placeholder_badge(payload)

    # Pick the smallest square DM size that fits the payload, then upscale.
    last_err = None
    enc = None
    for size in ("12x12", "14x14", "16x16", "18x18", "20x20", "22x22",
                 "24x24", "26x26", "32x32", "36x36", "40x40", "44x44",
                 "48x48", "52x52", "64x64", "72x72", "80x80", "88x88",
                 "96x96", "104x104", "120x120", "132x132", "144x144"):
        try:
            enc = dmtx_encode(payload.encode("utf-8"), size=size)
            break
        except Exception as err:  # too small for this payload
            last_err = err
    if enc is None:
        raise RuntimeError(f"DM encode failed: {last_err}")
    # pylibdmtx returns raw RGB pixels (bpp=24); convert to a 1-bit symbol.
    symbol = Image.frombytes("RGB", (enc.width, enc.height), enc.pixels) \
        .convert("L").convert("1")

    scale = max(3, 240 // symbol.width)
    sym = symbol.resize((symbol.width * scale, symbol.height * scale),
                        Image.NEAREST)
    pad = 26
    side = sym.width + pad * 2
    badge = Image.new("RGB", (side, side + 34), "#ffffff")
    draw = ImageDraw.Draw(badge)

    # Rounded frame resembling a QR container.
    r = 18
    draw.rounded_rectangle([1, 1, side - 2, side + 32], radius=r,
                           outline="#123c2e", width=4)
    badge.paste(sym, (pad, pad))

    label = "PROVEN · DM CODE"
    font = _load_badge_font(16)
    tw = draw.textlength(label, font=font)
    draw.text(((side - tw) / 2, side + 4), label, font=font, fill="#123c2e")
    return badge


def _render_placeholder_badge(payload: str) -> Image.Image:
    """Badge shown when the native libdmtx encoder is unavailable."""
    side = 240
    badge = Image.new("RGB", (side, side + 34), "#ffffff")
    draw = ImageDraw.Draw(badge)
    draw.rounded_rectangle([1, 1, side - 2, side + 32], radius=18,
                           outline="#123c2e", width=4)
    font = _load_badge_font(14)
    for i, line in enumerate(("libdmtx unavailable —",
                              "install libdmtx.dll",
                              "(see README)")):
        tw = draw.textlength(line, font=font)
        draw.text(((side - tw) / 2, 90 + i * 20), line, font=font,
                  fill="#a33")
    label = "PROVEN · DM CODE"
    tw = draw.textlength(label, font=font)
    draw.text(((side - tw) / 2, side + 4), label, font=font, fill="#123c2e")
    return badge


def badge_to_data_uri(img: Image.Image) -> str:
    buf = BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


# --------------------------------------------------------------------------
# Core authentication logic
# --------------------------------------------------------------------------


def lookup_product(db: sqlite3.Connection, serial: str):
    return db.execute(
        "SELECT p.*, b.name AS brand_name FROM products p "
        "JOIN brands b ON b.id = p.brand_id WHERE p.serial = ?",
        (serial,),
    ).fetchone()


def scan_result(db: sqlite3.Connection, serial: str, passcode: str) -> dict:
    """Classify a scan into one of the ledger outcomes.

    Outcomes:
      * genuine_first_use — valid code, never seen before → claims unit
      * genuine_cloned    — valid code already claimed by another scan
      * unknown_serial    — serial not in the registry (counterfeit print)
      * bad_passcode      — serial exists but secret does not match

    Every attempt is appended to ``scan_log`` for brand analysis; only
    successful scans are appended to the immutable ownership ledger
    (``units``).
    """
    product = lookup_product(db, serial)
    if product is None:
        outcome = "unknown_serial"
    elif not verify_passcode(passcode, product["code_hash"],
                             product["code_salt"], product["kdf_iters"]):
        outcome = "bad_passcode"
    else:
        # Valid credentials → append to the immutable ledger.
        claimed = product["claimed_unit_id"]
        if claimed is None:
            cur = db.execute(
                "INSERT INTO units (product_id, scanned_utc, ip, user_agent) "
                "VALUES (?, ?, ?, ?)",
                (product["id"], utcnow_iso(), client_ip(),
                 request.headers.get("User-Agent", "")[:200]),
            )
            unit_id = cur.lastrowid
            # First valid scan wins; guarded UPDATE avoids double-claim races.
            upd = db.execute(
                "UPDATE products SET claimed_unit_id = ? "
                "WHERE id = ? AND claimed_unit_id IS NULL",
                (unit_id, product["id"]),
            )
            if upd.rowcount == 1:
                outcome = "genuine_first_use"
            else:
                db.execute("DELETE FROM units WHERE id = ?", (unit_id,))
                outcome = "genuine_cloned"
        else:
            db.execute(
                "INSERT INTO units (product_id, scanned_utc, ip, user_agent) "
                "VALUES (?, ?, ?, ?)",
                (product["id"], utcnow_iso(), client_ip(),
                 request.headers.get("User-Agent", "")[:200]),
            )
            outcome = "genuine_cloned"

    db.execute(
        "INSERT INTO scan_log (serial, outcome, brand_id, scanned_utc, ip) "
        "VALUES (?, ?, ?, ?, ?)",
        (serial, outcome,
         product["brand_id"] if product else None,
         utcnow_iso(), client_ip()),
    )
    db.commit()

    res = {"outcome": outcome, "product": product}
    if product is not None:
        res["scan_count"] = db.execute(
            "SELECT COUNT(*) c FROM units WHERE product_id = ?",
            (product["id"],),
        ).fetchone()["c"]
    return res


OUTCOME_COPY = {
    "genuine_first_use": {
        "title": "Genuine — first verified use",
        "verdict": "GENUINE",
        "tone": "good",
        "blurb": ("This is an authentic {brand} item. Your scan has "
                  "registered it as the first legitimate owner."),
    },
    "genuine_cloned": {
        "title": "Genuine code — but already claimed",
        "verdict": "POSSIBLE CLONE",
        "tone": "warn",
        "blurb": ("The security code is authentic, however this exact code "
                  "was already verified {prior} time(s). You may have been "
                  "sold a cloned or second-hand item — contact {brand}."),
    },
    "unknown_serial": {
        "title": "Serial not found",
        "verdict": "COUNTERFEIT",
        "tone": "bad",
        "blurb": ("This serial does not exist in the {brand} registry. The "
                  "label was most likely fabricated. Do not consume or use "
                  "this product."),
    },
    "bad_passcode": {
        "title": "Secret mismatch",
        "verdict": "COUNTERFEIT",
        "tone": "bad",
        "blurb": ("The serial exists, but the hidden security key does not "
                  "match. Counterfeiters often copy visible serials without "
                  "the secret. Treat this product as fake."),
    },
}


# --------------------------------------------------------------------------
# Session / auth helpers for the dashboard
# --------------------------------------------------------------------------


def current_brand():
    bid = session.get("brand_id")
    if bid is None:
        return None
    return get_db().execute(
        "SELECT * FROM brands WHERE id = ?", (bid,)
    ).fetchone()


def require_brand():
    brand = current_brand()
    if brand is None:
        return None
    return brand


# --------------------------------------------------------------------------
# Routes — customer facing
# --------------------------------------------------------------------------


def _render_verify_page():
    """Render the customer-facing scan/verification stepper."""
    serial = (request.args.get("serial") or "").strip().upper()
    key = (request.args.get("key") or "").strip()
    return render_template("verify.html", prefill_serial=serial,
                           prefill_key=key, auto=bool(serial and key))


@app.route("/")
def index():
    """Home page is the scan/verify page — never the brand login page."""
    return _render_verify_page()


@app.route("/verify", methods=["GET"])
def verify_page():
    """Deep link target of the DM code: prefills and auto-runs the stepper."""
    return _render_verify_page()


@app.route("/api/verify", methods=["POST"])
def api_verify():
    if rate_limited("verify"):
        return rate_limit_response("verify")

    data = request.get_json(silent=True) or {}
    serial = normalize_serial(data.get("serial", ""))
    passcode = (data.get("passcode") or "").strip()

    if not serial or not passcode:
        return jsonify({"ok": False, "error": "missing_fields",
                        "message": "Both serial and security key "
                                   "are required."}), 400

    db = get_db()
    res = scan_result(db, serial, passcode)
    product = res["product"]
    outcome = res["outcome"]
    copy = OUTCOME_COPY[outcome]
    brand_name = product["brand_name"] if product else "the manufacturer"

    prior = max(res.get("scan_count", 1) - 1, 0)
    payload = {
        "ok": True,
        "outcome": outcome,
        "verdict": copy["verdict"],
        "tone": copy["tone"],
        "title": copy["title"],
        "message": copy["blurb"].format(brand=brand_name, prior=prior),
    }
    if product:
        payload.update({
            "product_name": product["product_name"],
            "brand": brand_name,
            "batch": product["batch"],
            "issued_utc": product["issued_utc"],
            "scan_count": res.get("scan_count"),
        })
    status = 200 if outcome.startswith("genuine") else 404 \
        if outcome == "unknown_serial" else 403
    return jsonify(payload), status


# --------------------------------------------------------------------------
# Routes — business dashboard
# --------------------------------------------------------------------------


@app.route("/dashboard")
def dashboard():
    brand = require_brand()
    if brand is None:
        return redirect(url_for("login"))
    db = get_db()
    products = db.execute(
        """
        SELECT p.*,
               (SELECT COUNT(*) FROM units u WHERE u.product_id = p.id)
                 AS scan_count,
               (SELECT MAX(scanned_utc) FROM units u
                 WHERE u.product_id = p.id) AS last_scan
        FROM products p WHERE p.brand_id = ? ORDER BY p.id DESC
        """,
        (brand["id"],),
    ).fetchall()

    stats = {
        "products": len(products),
        "scans": sum(p["scan_count"] for p in products),
        "first_uses": sum(1 for p in products if p["claimed_unit_id"]),
        "clone_alerts": sum(1 for p in products
                            if p["claimed_unit_id"] and p["scan_count"] > 1),
    }

    # Attempt analytics from the append-only scan log (includes failed
    # attempts such as counterfeit serials probing this brand's formats).
    outcome_rows = db.execute(
        "SELECT outcome, COUNT(*) c FROM scan_log WHERE brand_id = ? "
        "GROUP BY outcome",
        (brand["id"],),
    ).fetchall()
    stats["outcomes"] = {r["outcome"]: r["c"] for r in outcome_rows}
    stats["fake_attempts"] = sum(
        c for o, c in stats["outcomes"].items()
        if o in ("bad_passcode",)
    ) + db.execute(
        "SELECT COUNT(*) c FROM scan_log "
        "WHERE brand_id IS NULL AND outcome = 'unknown_serial'"
    ).fetchone()["c"]

    recent = db.execute(
        "SELECT * FROM scan_log WHERE brand_id = ? OR brand_id IS NULL "
        "ORDER BY id DESC LIMIT 15",
        (brand["id"],),
    ).fetchall()

    alerts = [p for p in products
              if p["claimed_unit_id"] and p["scan_count"] > 1]
    return render_template("dashboard.html", brand=brand,
                           products=products, stats=stats, alerts=alerts,
                           recent=recent)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        name = (request.form.get("brand_name") or "").strip()
        key = (request.form.get("api_key") or "").strip()
        db = get_db()
        brand = db.execute(
            "SELECT * FROM brands WHERE name = ? COLLATE NOCASE",
            (name,),
        ).fetchone()
        if brand and hmac.compare_digest(brand["api_key"], key):
            session["brand_id"] = brand["id"]
            session.permanent = False
            return redirect(url_for("dashboard"))
        error = "Unknown brand or incorrect API key."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/register-brand", methods=["POST"])
def register_brand():
    if rate_limited("register"):
        return rate_limit_response("register")
    name = (request.form.get("brand_name") or "").strip()
    if not (2 <= len(name) <= 60):
        return render_template(
            "login.html",
            error="Brand name must be 2–60 characters."), 400
    db = get_db()
    api_key = new_api_key()
    try:
        cur = db.execute(
            "INSERT INTO brands (name, api_key, created_utc) "
            "VALUES (?, ?, ?)",
            (name, api_key, utcnow_iso()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return render_template(
            "login.html",
            error=f"A brand named “{name}” already exists."), 409
    session["brand_id"] = cur.lastrowid
    # The freshly minted API key is revealed exactly once on the login page;
    # the brand is already signed in, but we show it so they can save it.
    return render_template(
        "login.html", error=None,
        new_brand_name=name, new_api_key=api_key)


@app.route("/api/products", methods=["POST"])
def api_create_product():
    """Register a genuine product unit: serial + secret passcode."""
    brand = current_brand()
    if brand is None:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    if rate_limited("register"):
        return rate_limit_response("register")

    data = request.get_json(silent=True) or {}
    serial = normalize_serial(data.get("serial", ""))
    passcode = (data.get("passcode") or "").strip()
    pname = (data.get("product_name") or "").strip()[:120]
    batch = (data.get("batch") or "").strip()[:60]
    description = (data.get("description") or "").strip()[:500]

    errors = []
    if not serial:
        errors.append("Serial must be 6–64 chars of A–Z 0–9 - _")
    if len(passcode) < 8:
        errors.append("Passcode must be at least 8 characters")
    if not pname:
        errors.append("Product name is required")
    if errors:
        return jsonify({"ok": False, "error": "validation",
                        "messages": errors}), 400

    code_hash, salt, iters = hash_passcode(passcode)
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO products (brand_id, serial, code_hash, code_salt, "
            "kdf_iters, product_name, description, batch, issued_utc) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (brand["id"], serial, code_hash, salt, iters, pname,
             description, batch, utcnow_iso()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "duplicate",
                        "message": f"Serial {serial} is already "
                                    "registered."}), 409

    pid = cur.lastrowid
    payload = build_payload(serial, passcode)
    badge = render_dm_badge(payload)
    png_b64 = badge_to_data_uri(badge)[len("data:image/png;base64,"):]
    return jsonify({
        "ok": True,
        "product_id": pid,
        "serial": serial,
        "payload": payload,
        # Shown exactly once so the brand can print the scratch panel.
        "passcode_shown_once": passcode,
        "png_base64": png_b64,
    })


@app.route("/products/<serial>/ledger")
def product_ledger(serial):
    brand = require_brand()
    if brand is None:
        return redirect(url_for("login"))
    db = get_db()
    product = db.execute(
        "SELECT p.*, b.name AS brand_name FROM products p "
        "JOIN brands b ON b.id = p.brand_id "
        "WHERE p.serial = ? AND p.brand_id = ?",
        (normalize_serial(serial), brand["id"]),
    ).fetchone()
    if product is None:
        abort(404)
    entries = db.execute(
        "SELECT * FROM units WHERE product_id = ? "
        "ORDER BY id ASC LIMIT ?",
        (product["id"], MAX_LEDGER_ROWS_PER_UNIT),
    ).fetchall()
    return render_template("ledger.html", brand=brand, product=product,
                           entries=entries)


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True, "time": utcnow_iso()})


# --------------------------------------------------------------------------
# Bootstrap
# --------------------------------------------------------------------------

init_db()

if __name__ == "__main__":
    # Windows console fonts (legacy cp codepages) can't render the Unicode
    # middot in banner text; force UTF-8 output when possible.
    if os.name == "nt":
        try:
            os.system("chcp 65001 >nul 2>nul")
        except Exception:
            pass

    port = int(os.environ.get("PORT", 5000))
    print(f"Proven (DM Code) running on http://localhost:{port}/")
    if not DMTX_AVAILABLE:
        print("WARNING: libdmtx native library not found — DM badges will "
              "use a placeholder image.")
        print("See README.md for installation instructions.")
    app.run(host="0.0.0.0", port=port,
            debug=bool(os.environ.get("FLASK_DEBUG")))
