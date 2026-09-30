# Running Proven (DM Code) on Windows

## 1. Install Python and packages

Use Python 3.10+ from [python.org](https://www.python.org/downloads/)
(check **Add Python to PATH** during the installer).

```bat
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## 2. libdmtx native library (required for real Data Matrix badges)

`pylibdmtx` is only a Python wrapper — it needs the native **libdmtx**
shared library, which pip does *not* install for you. On Linux the app
uses `apt-get install libdmtx0b`; on Windows you must supply
`libdmtx-64.dll` yourself. Without it the app still runs, but DM badges
fall back to a placeholder image (a warning is printed at startup).

Pick one of these options:

### Option A — Copy the DLL next to `app.py` (simplest)

1. Download the prebuilt Windows binary (64-bit) from the libdmtx
   releases page: <https://github.com/dmtx/libdmtx/releases>
   (e.g. `libdmtx-0.7.5-windows-x64.zip`, or the `libdmtx-64.dll`
   bundled inside some pylibdmtx wheels).
2. Place `libdmtx-64.dll` in the same folder as `app.py`.
3. If Python still can't find it, add that folder to your PATH before
   launching, or (Python 3.8+) insert this at the top of `app.py`:

   ```python
   import os
   os.add_dll_directory(os.path.dirname(os.path.abspath(__file__)))
   ```

### Option B — vcpkg

```bat
vcpkg install libdmtx:x64-windows
:: then copy the DLL out of vcpkg_installed\x64-windows\bin into the
:: project folder, or add that bin directory to PATH.
```

### Verify the install

```bat
python -c "from pylibdmtx.pylibdmtx import encode; print(encode(b'hello'))"
```

If this prints an `Encoded` result instead of raising
`ImportError`/`OSError` ("libdmtx.dll not found"), badge rendering works.

## 3. Run the app

```bat
python app.py
```

Open <http://localhost:5000/> in your browser (dashboard: `/dashboard`).

> Note: scanning a DM code with your *phone* requires the site to be
> reachable from the phone's network — localhost won't work. For testing
> use a tunnel such as `ngrok http 5000`, or set `PROVEN_PUBLIC_URL` to
> your LAN IP (`ipconfig`) so generated codes point to e.g.
> `http://192.168.1.50:5000`.

## 4. Optional environment variables (set in cmd / PowerShell)

```bat
set PROVEN_SECRET_KEY=<long-random-hex>   :: keep sessions valid across restarts
set PROVEN_DB=C:\path\to\proven.db        :: database location
set PROVEN_PUBLIC_URL=http://localhost:5000 :: base URL embedded in DM codes
set PORT=5000
set FLASK_DEBUG=1                          :: dev auto-reloader
```

PowerShell uses `$env:NAME = "value"` instead of `set`.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `OSError: libdmtx.dll not found` at startup | Follow step 2 above; confirm the DLL bitness matches your Python (64-bit Python needs the 64-bit DLL). |
| Placeholder badge instead of a scannable code | Same as above — libdmtx missing. |
| `UnicodeEncodeError` printing the banner in cmd | Run `chcp 65001` first, or use Windows Terminal. |
| Port 5000 already in use (common with AirPlay Receiver on some tools) | `set PORT=8080` before running. |
| Firewall prompt when Flask starts | Allow private-network access, or bind via `PORT` behind a reverse proxy. |
