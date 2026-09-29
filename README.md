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
5. **Unique IDs + passcodes** (`codes.py`): every code you create gets a random
   16-character unique ID plus a 10-character passcode. Each ID may have an
   **owner** or none at all. Anyone can look up an ID (the DM image encodes the
   ID itself), but **changing** its message/owner/style/passcode requires
   entering the correct passcode. Passcodes are stored only as salted
   PBKDF2-HMAC-SHA256 hashes, compared in constant time, and brute-force
   attempts are rate-limited per IP (10 wrong tries → 5-minute lockout).
   Records persist in `codes.json`.

## Run

```bash
pip install -r requirements.txt
python3 app.py            # serves http://localhost:5000
```

## Endpoints

| Route    | Method | Description                                              |
|----------|--------|----------------------------------------------------------|
| `/`      | GET    | Web UI: create a unique ID, or change one with its passcode |
| `/image` | GET    | PNG of a free-text code (`text`, `style`, `scale`, `rounded`) |
| `/scan`  | POST   | multipart `file` upload → JSON `{format, text, is_qr}`   |
| `/api/codes` | POST | JSON `{message, owner?, style?}` → creates a unique ID and returns its **passcode once** |
| `/api/codes/<id>` | GET | Public info: message, style, `has_owner`, `owner` |
| `/c/<id>.png` | GET | Data Matrix PNG whose payload IS the unique ID |
| `/api/codes/<id>/change` | POST | JSON `{passcode, message?, owner?, style?, new_passcode?}` — **passcode required**; 403 if missing/wrong |
| `/api/codes/<id>/verify` | POST | JSON `{passcode}` → `{ok:true}` without changing anything |

## Brand Network (social-style business accounts) — `/brands`

Like a social media app: **every business brand creates its own account**, the
brand publishes **product codes**, and **customers of that brand can make their
own copy** of any product code (their own unique ID + personal passcode).

| Route | Method | Description |
|-------|--------|-------------|
| `/brands` | GET | Web UI: brand sign-up, brand management, customer copies, public brand feed |
| `/api/brands` | GET | Directory of all brand accounts |
| `/api/brands` | POST | JSON `{handle, name, bio?, category?, style?}` → creates the brand account, returns its **passcode once** |
| `/api/brands/<handle>` | GET | Public profile + its product codes |
| `/api/brands/<handle>/login` | POST | JSON `{passcode}` → verifies the brand's passcode (throttled) |
| `/api/brands/<handle>/change` | POST | JSON `{passcode, name?, bio?, category?, style?, new_passcode?}` — brand passcode required |
| `/api/brands/<handle>/products` | POST | JSON `{passcode, message, title?, style?}` → brand creates a product code; returns product ID + its passcode once |
| `/api/products/<id>` | GET | Public info about a product code or a customer's personal copy (`is_copy`, `copies[]`) |
| `/api/products/<id>/copy` | POST | JSON `{customer?, style?}` → **customer makes their OWN copy** of a brand product code; returns a new personal ID + passcode (shown once) |
| `/api/products/<id>/change` | POST | JSON `{passcode, ...}` → change a product (brand's product passcode) or a personal copy (customer's own passcode); 403 otherwise |
| `/p/<id>.png` | GET | Data Matrix PNG whose payload IS that product/copy ID |

Example:

```bash
curl -o dm.png --get --data-urlencode "text=https://example.com" localhost:5000/image
curl -F "file=@dm.png" localhost:5000/scan
# -> {"format":"DataMatrix","is_qr":false,"text":"https://example.com"}

# Create a unique ID (with an owner)
curl -s -X POST localhost:5000/api/codes -H 'Content-Type: application/json' \
     -d '{"message":"my secret note","owner":"alice"}'
# -> {"id":"rL0bxredbIzNDX1M","passcode":"DDBGP59U9K","has_owner":true,...}

# Try to change it WITHOUT / with a WRONG passcode -> 403 rejected
curl -s -X POST localhost:5000/api/codes/rL0bxredbIzNDX1M/change \
     -H 'Content-Type: application/json' -d '{"message":"hacked"}'
# -> {"error":"A passcode is required to change this unique ID."}

# Change it with the CORRECT passcode -> 200 applied
curl -s -X POST localhost:5000/api/codes/rL0bxredbIzNDX1M/change \
     -H 'Content-Type: application/json' \
     -d '{"passcode":"DDBGP59U9K","message":"updated by alice"}'

# --- Brand Network: brand account -> product code -> customer's own copy ---

# 1) A business brand creates its social-style account (passcode shown once)
curl -s -X POST localhost:5000/api/brands -H 'Content-Type: application/json' \
     -d '{"handle":"coffee_roasters","name":"Coffee Roasters Co.","category":"Food & Drink"}'
# -> {"handle":"coffee_roasters",...,"passcode":"NLEY3BX0UD"}

# 2) The brand publishes a product code (brand passcode required)
curl -s -X POST localhost:5000/api/brands/coffee_roasters/products \
     -H 'Content-Type: application/json' \
     -d '{"passcode":"NLEY3BX0UD","title":"Signature Blend 250g","message":"https://shop.example.com/signature-blend"}'
# -> {"id":"qKHerQBjMSuFkcb3","passcode":"C7EGSI0PW4",...}   /p/qKHerQBjMSuFkcb3.png is printable

# 3) A CUSTOMER of that brand makes their OWN copy of the product code
curl -s -X POST localhost:5000/api/products/qKHerQBjMSuFkcb3/copy \
     -H 'Content-Type: application/json' -d '{"customer":"bob","style":"ocean"}'
# -> {"id":"VNZwLgRk3X4IqEOa","passcode":"37XL5VAE49","is_copy":true,...}

# 4) Only bob's own passcode can change bob's copy (even the brand cannot)
curl -s -X POST localhost:5000/api/products/VNZwLgRk3X4IqEOa/change \
     -H 'Content-Type: application/json' \
     -d '{"passcode":"37XL5VAE49","message":"https://shop.example.com/bobs-blend"}'
```

## Why it's not a QR code

- No three corner finder patterns; instead an L-shaped solid bar plus a dashed
  clock track on the opposite edges.
- Different standard (ISO/IEC 16022 vs ISO/IEC 18004) and error-correction
  layout; scanners report it as `DataMatrix`.