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

from flask import Flask, render_template, request, Response, jsonify, session

import codes
import dmcode

app = Flask(__name__)
app.secret_key = codes.load_secret_key()


@app.route("/")
def index():
    return render_template(
        "index.html",
        styles=dmcode.STYLES,
        max_bytes=dmcode.MAX_TEXT_BYTES,
    )


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


@app.route("/scan", methods=["POST"])
def scan():
    """Upload endpoint: decode an uploaded DM-code image back to its text."""
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
