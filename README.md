# DM Code — a scannable image that looks like a QR code but is NOT one

A Flask website that turns any text or URL into a **Data Matrix (ECC200)**
barcode rendered in a QR-like style (rounded modules, QR-ish colors), so at a
glance it resembles a QR code — while being an entirely different symbology
(ISO/IEC 16022). Any ordinary scanner app (Google Lens, iOS Camera, ZXing-based
readers) can scan it.

## How it works

1. `zxing-cpp` encodes the message into a real Data Matrix module grid.
2. Pillow renders that grid as a styled PNG (rounded "QR-looking" dots,
   color presets, quiet zone for reliable scanning).
3. The server decodes the image it just rendered back to text to **prove it is
   scannable** before returning it (`dmcode.verify`).
4. A `/scan` upload endpoint lets you feed any image back to the decoder; it
   reports the symbology (`DataMatrix`, not `QRCode`) and the recovered text.

## Run

```bash
pip install -r requirements.txt
python3 app.py            # serves http://localhost:5000
```

## Endpoints

| Route    | Method | Description                                              |
|----------|--------|----------------------------------------------------------|
| `/`      | GET    | Web UI: enter text, pick style/size, generate + download |
| `/image` | GET    | PNG of the code (`text`, `style`, `scale`, `rounded`)    |
| `/scan`  | POST   | multipart `file` upload → JSON `{format, text, is_qr}`   |

Example:

```bash
curl -o dm.png --get --data-urlencode "text=https://example.com" localhost:5000/image
curl -F "file=@dm.png" localhost:5000/scan
# -> {"format":"DataMatrix","is_qr":false,"text":"https://example.com"}
```

## Why it's not a QR code

- No three corner finder patterns; instead an L-shaped solid bar plus a dashed
  clock track on the opposite edges.
- Different standard (ISO/IEC 16022 vs ISO/IEC 18004) and error-correction
  layout; scanners report it as `DataMatrix`.