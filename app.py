"""Flask website that generates a scannable "QR-look-alike" image.

The image is NOT a QR code - it is a Data Matrix (ECC200) barcode styled to
resemble one (rounded modules, QR-like colors). It can be scanned by any
common phone scanner app.

Every generated code now carries a UNIQUE ID protected by a PASSCODE:

* POST /api/codes            -> create a unique ID (+ its passcode, shown once)
* GET  /api/codes/<id>       -> public info: message, owner-or-not, style
* GET  /c/<id>               -> the Data Matrix PNG whose payload IS the ID
* POST /api/codes/<id>/change-> change the ID's message/owner/style/passcode
                               (the correct passcode is REQUIRED)
"""

from flask import (Flask, render_template, request, Response, jsonify,
                   session, redirect)
from urllib.parse import quote

import csv
import os
import time
import io

import brands
import codes
import dmcode
import authenticity
import scans

app = Flask(__name__)
app.secret_key = codes.load_secret_key()


# --------------------------------------------------------------------------
# THE WHOLE SITE IS EXACTLY TWO PAGES:
#   /          -> customer page: scan the product code & verify it
#   /dashboard -> business page: manage the brand, codes, units & records
# Everything else is an API endpoint or a generated image.
# --------------------------------------------------------------------------
@app.route("/")
def index():
    """The ONLY customer-facing page: scan a product code to prove authenticity."""
    return render_template(
        "home.html",
        styles=dmcode.STYLES,
        max_bytes=dmcode.MAX_TEXT_BYTES,
    )


@app.route("/style.css")
def style_css():
    """The shared Twitter/X-style dark theme for every page."""
    css_path = os.path.join(app.root_path, "templates", "theme.css")
    return Response(open(css_path, encoding="utf-8").read(), mimetype="text/css")


@app.route("/dashboard")
def dashboard():
    """The ONLY business-facing page: brand dashboard (codes, units, ledger)."""
    return render_template(
        "dashboard.html",
        styles=dmcode.STYLES,
        max_bytes=dmcode.MAX_TEXT_BYTES,
    )


_OLD_PAGES = {"/brands": "/dashboard", "/create": "/dashboard",
              "/verify": "/", "/scan": "/"}


@app.route("/brands")
@app.route("/create")
@app.route("/verify")
@app.route("/verify/<serial>")
@app.route("/scan")
def _removed_page(serial=""):
    """Old extra pages were removed — only / (customer) and /dashboard exist."""
    if request.method == "POST" and request.path == "/scan":
        # legacy image-decode uploads keep working from the customer page
        return api_decode()
    target = _OLD_PAGES.get(request.path, "/")
    if request.path == "/verify" and (serial or request.args.get("serial")):
        # a scanned product code must still land on the customer page
        s = quote((serial or request.args.get("serial", "")).strip().upper())
        return redirect(f"/?serial={s}", 302)
    return redirect(target, 301)


# --------------------------------------------------------------------------
# Unique-ID + passcode API
# --------------------------------------------------------------------------
def _client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For")
    return (fwd.split(",")[0].strip() if fwd else request.remote_addr) or "?"


@app.post("/api/codes")
def create_code():
    """Create a brand-new unique ID with a freshly generated passcode."""
    body = request.get_json(silent=True) or {}
    try:
        rec = codes.store.create(
            message=body.get("message", ""),
            owner=body.get("owner", ""),
            style=body.get("style", "classic"),
        )
    except codes.CodeError as exc:
        return jsonify(error=str(exc)), 400
    # Remember ownership in the browser session (convenience only — every
    # actual change still requires the passcode server-side).
    owned = session.setdefault("owned_codes", {})
    owned[rec["id"]] = True
    return jsonify(rec), 201


@app.get("/api/codes/<uid>")
def get_code(uid):
    """Public details of a unique ID: message, style, and whether it has an owner."""
    try:
        rec = codes.store.get(uid)
    except codes.CodeError as exc:
        return jsonify(error=str(exc)), 404
    rec["you_own_it"] = bool(session.get("owned_codes", {}).get(rec["id"]))
    return jsonify(rec)


@app.get("/c/<uid>.png")
@app.get("/c/<uid>")
def code_image(uid):
    """Render the Data Matrix image for a unique ID (payload = the ID itself)."""
    try:
        rec = codes.store.get(uid)
    except codes.CodeError as exc:
        return Response(str(exc), status=404, mimetype="text/plain")
    try:
        img = dmcode.generate(rec["id"], style=rec.get("style", "classic"), scale=10)
    except dmcode.DMCodeError as exc:
        return Response(str(exc), status=400, mimetype="text/plain")
    return Response(dmcode.to_png_bytes(img), mimetype="image/png")


@app.post("/api/codes/<uid>/change")
def change_code(uid):
    """Change a unique ID. The caller MUST supply the correct passcode."""
    body = request.get_json(silent=True) or {}
    try:
        rec = codes.store.change(
            uid,
            passcode=body.get("passcode", ""),
            message=body.get("message"),
            owner=body.get("owner"),
            style=body.get("style"),
            new_passcode=body.get("new_passcode"),
            ip=_client_ip(),
        )
    except codes.CodeError as exc:
        # 403 when the passcode was missing/wrong, 404 unknown id, 400 bad input
        msg = str(exc)
        status = 404 if "exists" in msg else 403 if "passcode" in msg.lower() else 400
        return jsonify(error=msg), status
    session.setdefault("owned_codes", {})[rec["id"]] = True
    return jsonify(rec)


@app.post("/api/codes/<uid>/verify")
def verify_passcode(uid):
    """Check a passcode without changing anything (throttled)."""
    body = request.get_json(silent=True) or {}
    try:
        codes.store.verify_owner(uid, body.get("passcode", ""), ip=_client_ip())
    except codes.CodeError as exc:
        msg = str(exc)
        return jsonify(ok=False, error=msg), 404 if "exists" in msg else 403
    session.setdefault("owned_codes", {})[uid] = True
    return jsonify(ok=True)


# --------------------------------------------------------------------------
# Business-brand accounts + product codes + customer copies (API)
# --------------------------------------------------------------------------
def _brand_status(msg: str) -> int:
    m = msg.lower()
    if "exists" in m or "no brand" in m or "no product" in m:
        return 404
    if "passcode" in m:
        return 403
    return 400


@app.get("/api/brands")
def list_brands():
    """The social directory: every business brand account on the platform."""
    return jsonify(brands.store.list_brands())


@app.post("/api/brands")
def create_brand():
    """A business brand creates its account. Its passcode is returned ONCE."""
    body = request.get_json(silent=True) or {}
    try:
        rec = brands.store.create_brand(
            handle=body.get("handle", ""),
            name=body.get("name", ""),
            bio=body.get("bio", ""),
            category=body.get("category", ""),
            style=body.get("style", "classic"),
        )
    except brands.BrandError as exc:
        return jsonify(error=str(exc)), _brand_status(str(exc))
    session.setdefault("owned_brands", {})[rec["handle"]] = True
    return jsonify(rec), 201


@app.get("/api/brands/<handle>")
def get_brand(handle):
    """Public brand profile + its product codes."""
    try:
        rec = brands.store.get_brand(handle)
        rec["products"] = brands.store.list_products(handle)
    except brands.BrandError as exc:
        return jsonify(error=str(exc)), 404
    rec["you_own_it"] = bool(session.get("owned_brands", {}).get(rec["handle"]))
    return jsonify(rec)


@app.post("/api/brands/<handle>/login")
def login_brand(handle):
    """Verify a brand's passcode (throttled). Grants management rights in this browser."""
    body = request.get_json(silent=True) or {}
    try:
        rec = brands.store.verify_brand(handle, body.get("passcode", ""), ip=_client_ip())
    except brands.BrandError as exc:
        return jsonify(ok=False, error=str(exc)), _brand_status(str(exc))
    session.setdefault("owned_brands", {})[rec["handle"]] = True
    return jsonify(ok=True, brand=rec)


@app.post("/api/brands/<handle>/change")
def change_brand(handle):
    """Update the brand profile — the brand's passcode is REQUIRED."""
    body = request.get_json(silent=True) or {}
    try:
        rec = brands.store.update_brand(
            handle,
            passcode=body.get("passcode", ""),
            name=body.get("name"),
            bio=body.get("bio"),
            category=body.get("category"),
            style=body.get("style"),
            new_passcode=body.get("new_passcode"),
            ip=_client_ip(),
        )
    except brands.BrandError as exc:
        return jsonify(error=str(exc)), _brand_status(str(exc))
    session.setdefault("owned_brands", {})[rec["handle"]] = True
    return jsonify(rec)


@app.post("/api/brands/<handle>/products")
def create_product(handle):
    """The brand creates a product code (QR-look-alike). Brand passcode required."""
    body = request.get_json(silent=True) or {}
    try:
        rec = brands.store.create_product(
            handle,
            passcode=body.get("passcode", ""),
            message=body.get("message", ""),
            title=body.get("title", ""),
            style=body.get("style"),
            ip=_client_ip(),
        )
    except brands.BrandError as exc:
        return jsonify(error=str(exc)), _brand_status(str(exc))
    return jsonify(rec), 201


@app.get("/api/products/<pid>")
def get_product(pid):
    """Public info about one product code (brand original or customer copy)."""
    try:
        rec = brands.store.get_product(pid)
    except brands.BrandError as exc:
        return jsonify(error=str(exc)), 404
    if not rec["is_copy"]:
        rec["copies"] = brands.store.list_copies(pid)
    return jsonify(rec)


@app.post("/api/products/<pid>/change")
def change_product(pid):
    """Change a product code — requires that code's own passcode."""
    body = request.get_json(silent=True) or {}
    try:
        rec = brands.store.get_product(pid)
        if rec["is_copy"]:
            out = brands.store.update_copy(
                pid,
                passcode=body.get("passcode", ""),
                message=body.get("message"),
                style=body.get("style"),
                customer=body.get("customer"),
                ip=_client_ip(),
            )
        else:
            out = brands.store.update_product(
                pid,
                passcode=body.get("passcode", ""),
                message=body.get("message"),
                title=body.get("title"),
                style=body.get("style"),
                ip=_client_ip(),
            )
    except brands.BrandError as exc:
        return jsonify(error=str(exc)), _brand_status(str(exc))
    return jsonify(out)


@app.post("/api/products/<pid>/copy")
def claim_copy(pid):
    """A CUSTOMER makes their OWN version of a brand's product code.

    Returns a brand-new personal unique ID + passcode linked to the product.
    """
    body = request.get_json(silent=True) or {}
    try:
        rec = brands.store.claim_copy(
            pid, customer=body.get("customer", ""), style=body.get("style")
        )
    except brands.BrandError as exc:
        return jsonify(error=str(exc)), _brand_status(str(exc))
    return jsonify(rec), 201


@app.get("/p/<pid>.png")
@app.get("/p/<pid>")
def product_image(pid):
    """Render the Data Matrix PNG for a product code or a customer's personal copy."""
    try:
        rec = brands.store.get_product(pid)
    except brands.BrandError as exc:
        return Response(str(exc), status=404, mimetype="text/plain")
    try:
        img = dmcode.generate(rec["id"], style=rec.get("style", "classic"), scale=10)
    except dmcode.DMCodeError as exc:
        return Response(str(exc), status=400, mimetype="text/plain")
    return Response(dmcode.to_png_bytes(img), mimetype="image/png")


# --------------------------------------------------------------------------
# Product authenticity: register genuine units -> verify by scan + passcode
# (the customer verifies on the single home page "/" — no separate page)
# --------------------------------------------------------------------------
@app.post("/api/verify")
def api_verify():
    """Verify a product: serial (from the scanned code) + printed passcode.

    Every attempt is saved to the permanent scan ledger (``scan_records.json``)
    so brands have a full record of who scanned/bought their products.
    """
    body = request.get_json(silent=True) or {}
    try:
        verdict = authenticity.store.verify(
            body.get("serial", ""),
            body.get("passcode", ""),
            ip=_client_ip(),
        )
    except authenticity.AuthenticityError as exc:
        msg = str(exc)
        status = 404 if "exists" in msg else 400
        scans.store.log(serial=body.get("serial", ""), brand=None,
                        result="ERROR", authentic=False, message=msg,
                        customer=body.get("customer", ""), ip=_client_ip(),
                        device=request.headers.get("User-Agent", ""))
        return jsonify(result="ERROR", authentic=False, error=msg, message=msg), status

    # A genuine unit that was already proven purchased elsewhere -> ALREADY_USED
    if verdict["result"] == "AUTHENTIC_BUT_RESELLER":
        verdict["result"] = "ALREADY_USED"
        verdict["authentic"] = True  # the code itself is genuine, but resold/cloned

    unit = verdict.get("unit") or {}
    scans.store.log(serial=body.get("serial", ""), brand=unit.get("brand"),
                    result=verdict["result"], authentic=verdict["authentic"],
                    message=verdict["message"],
                    customer=body.get("customer", ""), ip=_client_ip(),
                    device=request.headers.get("User-Agent", ""))

    status = 200 if verdict["result"] in ("AUTHENTIC", "ALREADY_USED") else 403
    return jsonify(verdict), status


@app.get("/api/auth/info/<serial>")
def auth_info(serial):
    """Public info shown right after scanning, BEFORE entering the passcode."""
    try:
        unit = authenticity.store.get_unit(serial)
    except authenticity.AuthenticityError as exc:
        return jsonify(error=str(exc)), 404
    brand_name = None
    try:
        brand_name = brands.store.get_brand(unit["brand"])["name"]
    except brands.BrandError:
        pass
    unit["brand_name"] = brand_name
    unit["product_url"] = f"/v/{unit['serial']}"
    unit["image_url"] = f"/a/{unit['serial']}.png"
    unit.pop("last_verified", None)  # customer privacy
    return jsonify(unit)


@app.post("/api/brands/<handle>/units")
def register_units(handle):
    """A brand registers genuine product units (batch). Brand passcode required.

    Returns each unit's serial + its printing passcode — shown ONCE so the
    brand can put them on the packaging / tamper stickers.
    """
    body = request.get_json(silent=True) or {}
    try:
        record = brands.store.authenticate_brand(
            handle, body.get("passcode", ""), ip=_client_ip()
        )
        units = authenticity.store.register_units(
            brand_handle=record["handle"],
            brand_passcode_hash=record["passcode_hash"],
            brand_salt=record["salt"],
            title=body.get("title", ""),
            quantity=body.get("quantity", 1),
        )
    except (brands.BrandError, authenticity.AuthenticityError) as exc:
        msg = str(exc)
        m = msg.lower()
        status = 404 if ("exists" in m or "no brand" in m) else 403 if "passcode" in m else 400
        return jsonify(error=msg), status
    return jsonify({"brand": record["handle"], "count": len(units), "units": units}), 201


@app.get("/api/brands/<handle>/units")
def brand_units(handle):
    """The brand's registered units with verification stats (public summary)."""
    try:
        brands.store.get_brand(handle)  # 404 if unknown brand
    except brands.BrandError as exc:
        return jsonify(error=str(exc)), 404
    units = authenticity.store.list_for_brand(handle)
    for u in units:
        u.pop("last_verified", None)  # keep customer privacy on the public list
    return jsonify({"summary": authenticity.store.brand_summary(handle), "units": units})


@app.post("/api/brands/<handle>/scans")
def brand_scans(handle):
    """The brand's FULL scan/purchase ledger — brand passcode required.

    Without a valid passcode only aggregate stats and the last few serials
    are released; the complete history (who, IP, device) is private to the
    brand.
    """
    body = request.get_json(silent=True) or {}
    key = handle.lstrip("@").lower()
    rows = scans.store.list_for_brand(key)
    out = {"brand": key, "stats": scans.store.stats_for_brand(key),
           "authenticated": False}
    try:
        brands.store.verify_brand(handle, body.get("passcode", ""), ip=_client_ip())
    except brands.BrandError as exc:
        out["recent"] = [{"at": r["at"], "serial": r["serial"], "result": r["result"]}
                         for r in rows[:5]]
        out["locked"] = str(exc)
        return jsonify(out), 200
    out["authenticated"] = True
    out["scans"] = rows
    return jsonify(out)


@app.get("/api/brands/<handle>/recent-scans")
def brand_recent_scans(handle):
    """Public 'recent purchase proofs' ticker for a brand (no customer PII)."""
    key = handle.lstrip("@").lower()
    rows = []
    for r in scans.store.list_for_brand(key)[:8]:
        if r["result"] in ("AUTHENTIC", "ALREADY_USED"):
            rows.append({"at": r["at"], "serial": r["serial"],
                         "customer": r.get("customer"), "result": r["result"]})
    return jsonify({"stats": scans.store.stats_for_brand(key), "recent": rows})


@app.get("/api/brands/<handle>/scans.csv")
def brand_scans_csv(handle):
    """Same ledger as a CSV download (for spreadsheets / accounting)."""
    key = handle.lstrip("@").lower()
    owned = session.get("owned_brands", {}).get(key)
    if not owned:
        return jsonify(error="Log in as this brand first (passcode required)."), 403
    fieldnames = ["at", "serial", "title", "result", "authentic",
                  "customer", "ip", "device", "message"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    titles = {u["serial"]: u.get("title", "")
              for u in authenticity.store.list_for_brand(key)}
    for row in scans.store.list_for_brand(key, limit=100_000):
        row = dict(row)
        row["title"] = titles.get(row.get("serial", ""), "")
        row["at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row.get("at", 0)))
        writer.writerow(row)
    return Response(buf.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": f"attachment; filename={key}-scans.csv"})


@app.get("/a/<serial>.png")
@app.get("/a/<serial>")
def unit_image(serial):
    """The printable code image whose payload is the customer URL /v/<SERIAL>."""
    try:
        unit = authenticity.store.get_unit(serial)
    except authenticity.AuthenticityError as exc:
        return Response(str(exc), status=404, mimetype="text/plain")
    style = "classic"
    try:
        style = brands.store.get_brand(unit["brand"]).get("style", "classic")
    except brands.BrandError:
        pass
    url = request.url_root.rstrip("/") + "/v/" + unit["serial"]
    try:
        img = dmcode.generate(url, style=style, scale=10)
    except dmcode.DMCodeError as exc:
        return Response(str(exc), status=400, mimetype="text/plain")
    return Response(dmcode.to_png_bytes(img), mimetype="image/png")


@app.get("/v/<serial>")
def unit_landing(serial):
    """Where a phone lands after scanning the printed code: the verify page."""
    return redirect("/verify?serial=" + quote((serial or "").strip().upper()))


@app.route("/image")
def image():
    """Return the generated PNG for the given text/style parameters."""
    text = (request.args.get("text") or "").strip()
    style = request.args.get("style", "classic")
    rounded = request.args.get("rounded", "1") != "0"
    try:
        scale = max(4, min(20, int(request.args.get("scale", 10))))
    except ValueError:
        scale = 10

    if not text:
        return Response("Missing 'text' parameter", status=400)

    try:
        img = dmcode.generate(text, style=style, scale=scale, rounded=rounded)
    except dmcode.DMCodeError as exc:
        return Response(str(exc), status=400, mimetype="text/plain")

    return Response(dmcode.to_png_bytes(img), mimetype="image/png")


@app.route("/api/decode", methods=["POST"])
def api_decode():
    """API endpoint: decode an uploaded DM-code image back to its text.

    (Used by the single customer page "/" — there is no separate scan page.)
    """
    file = request.files.get("file")
    if file is None:
        return jsonify(error="No file uploaded"), 400

    from PIL import Image
    import io

    try:
        img = Image.open(io.BytesIO(file.read()))
    except Exception:
        return jsonify(error="Could not read that file as an image"), 400

    import zxingcpp

    results = zxingcpp.read_barcodes(img)
    if not results:
        return jsonify(error="No barcode found in the image"), 422

    r = results[0]
    return jsonify(
        format=r.format.name,   # will show "DataMatrix", proving it's not a QR
        text=r.text,
        is_qr=(r.format == zxingcpp.BarcodeFormat.QRCode),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
