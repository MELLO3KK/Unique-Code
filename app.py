"""Flask website that generates a scannable "QR-look-alike" image.

The image is NOT a QR code - it is a Data Matrix (ECC200) barcode styled to
resemble one (rounded modules, QR-like colors). It can be scanned by any
common phone scanner app.
"""

from flask import Flask, render_template, request, Response, jsonify

import dmcode

app = Flask(__name__)


@app.route("/")
def index():
    return render_template(
        "index.html",
        styles=dmcode.STYLES,
        max_bytes=dmcode.MAX_TEXT_BYTES,
    )


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
