# Proven (DM Code)

A Flask web app for product authentication using **Data Matrix** codes.
Customers scan a DM badge to verify a product's provenance; brands sign
in to register products and view verification events.

- **Home page (`/`)** is the customer **scan/verify** page — not a login
  page. `/verify` shows the same page.
- Brand sign-in lives at `/login`; the dashboard is at `/dashboard`.

## Features

- Data Matrix badge rendering (scannable, via `pylibdmtx` + native
  libdmtx), with a graceful placeholder fallback if the native library
  is missing.
- Product registration with per-product serial + HMAC signing key
  embedded in the code payload.
- One-time brand API keys shown at sign-up, session-based dashboard.
- Verification event log (time, IP, result) per product.

## Requirements

- Python 3.10+
- Packages from `requirements.txt`:

```
flask>=3.0
pillow>=10.0
pylibdmtx>=0.1.10
```

- Native **libdmtx** shared library (pip does *not* install it):
  - Debian/Ubuntu: `sudo apt-get install libdmtx0b`
  - macOS: `brew install libdmtx`
  - Windows: see [Running on Windows](#running-on-windows) below.

Without the native library the app still runs, but DM badges fall back
to a placeholder image that says *"libdmtx unavailable — install
libdmtx.dll"*. The app re-checks for the library each time it renders a
badge, so once the library/DLL is in place new badges are scannable
without restarting (a restart is still recommended).

## Quick start

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open <http://localhost:5000/> — you'll land on the customer scan/verify
page. Register a brand at `/login`, then manage products at
`/dashboard`.

> Note: scanning a DM code with your *phone* requires the site to be
> reachable from the phone's network — localhost won't work. For testing
> use a tunnel such as `ngrok http 5000`, or set `PROVEN_PUBLIC_URL` to
> your LAN IP so generated codes point to e.g.
> `http://192.168.1.50:5000`.

## Configuration (environment variables)

| Variable | Purpose | Default |
| --- | --- | --- |
| `PROVEN_SECRET_KEY` | Session signing key (keep sessions valid across restarts) | random per run |
| `PROVEN_DB` | SQLite database location | `proven.db` |
| `PROVEN_PUBLIC_URL` | Base URL embedded in DM codes | `http://localhost:5000` |
| `PORT` | HTTP port | `5000` |
| `FLASK_DEBUG` | Enable dev auto-reloader when set | off |

On Windows cmd use `set NAME=value`; in PowerShell use
`$env:NAME = "value"`.

## Running on Windows

### 1. Install Python and packages

Use Python 3.10+ from [python.org](https://www.python.org/downloads/)
(check **Add Python to PATH** during the installer).

```bat
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 2. libdmtx native DLL (required for real Data Matrix badges)

`pylibdmtx` is only a Python wrapper — on Windows you must supply
`libdmtx-64.dll` yourself. Pick one of these options:

**Option A — Copy the DLL next to `app.py` (simplest)**

1. Download the prebuilt Windows binary (64-bit) from the libdmtx
   releases page: <https://github.com/dmtx/libdmtx/releases>
   (e.g. `libdmtx-0.7.5-windows-x64.zip`, or the `libdmtx-64.dll`
   bundled inside some pylibdmtx wheels).
2. Place `libdmtx-64.dll` in the same folder as `app.py`.
3. If Python still can't find it, add that folder to your PATH before
   launching. The app already registers its own folder via
   `os.add_dll_directory()` (Python 3.8+ no longer searches the script
   directory for DLLs), so Option A normally just works.

**Option B — vcpkg**

```bat
vcpkg install libdmtx:x64-windows
:: then copy the DLL out of vcpkg_installed\x64-windows\bin into the
:: project folder, or add that bin directory to PATH.
```

**Verify the install**

```bat
python -c "from pylibdmtx.pylibdmtx import encode; print(encode(b'hello'))"
```

If this prints an `Encoded` result instead of raising
`ImportError`/`OSError` ("libdmtx.dll not found"), badge rendering works.

### 3. Run

```bat
python app.py
```

Open <http://localhost:5000/> — the home page is the customer
**scan/verify** page (`/` and `/verify`); the brand dashboard is at
`/dashboard` (sign in via `/login`).

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `OSError: libdmtx.dll not found` / `libdmtx.so... cannot open shared object file` | Install the native library (see above). On Windows confirm the DLL bitness matches your Python (64-bit Python needs the 64-bit DLL). |
| Placeholder badge instead of a scannable code | Same as above — libdmtx missing. |
| `UnicodeEncodeError` printing the banner in cmd (Windows) | Run `chcp 65001` first, or use Windows Terminal. |
| Port 5000 already in use (common with AirPlay Receiver on some tools) | `set PORT=8080` (cmd) / `$env:PORT="8080"` (PowerShell) before running. |
| Firewall prompt when Flask starts (Windows) | Allow private-network access, or bind via `PORT` behind a reverse proxy. |

## Testing

```bash
python -m unittest test_proven -v
```
