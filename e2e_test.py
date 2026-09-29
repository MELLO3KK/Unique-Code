#!/usr/bin/env python3
"""End-to-end test of the authenticity flow against a running server."""
import json, sys, urllib.request

BASE = "http://localhost:5000"

def req(path, method="GET", body=None, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method,
                               headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(r) as resp:
            payload = resp.read()
            code = resp.status
    except urllib.error.HTTPError as e:
        payload = e.read(); code = e.code
    if raw:
        return code, payload
    return code, json.loads(payload)

fails = []
def check(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + ("  " + str(extra) if extra else ""))
    if not cond: fails.append(name)

# 1) business creates an account
code, brand = req("/api/brands", "POST", {"handle": "luxury_leather", "name": "Luxury Leather Co.", "category": "Fashion", "style": "qrblack"})
check("brand signup -> 201", code == 201, code)
bpass = brand["passcode"]

# 1b) duplicate handle rejected
code, _ = req("/api/brands", "POST", {"handle": "luxury_leather", "name": "X"})
check("duplicate handle rejected", code == 404 or code == 400, code)

# 2) register batch of 3 genuine units (needs brand passcode)
code, bad = req("/api/brands/luxury_leather/units", "POST", {"passcode": "WRONGPASS", "title": "Classic Wallet", "quantity": 3})
check("wrong brand passcode rejected 403", code == 403, (code, bad))
code, units = req("/api/brands/luxury_leather/units", "POST", {"passcode": bpass, "title": "Classic Wallet", "quantity": 3})
check("batch registration -> 201 x3", code == 201 and units.get("count") == 3, (code, units.get("count")))
u0 = units["units"][0]
serial, pcode = u0["serial"], u0["passcode"]
check("unit has serial(12) + passcode(8)", len(serial) == 12 and len(pcode) == 8, (serial, pcode))

# 3) printable code image exists and decodes to the /v/<serial> URL
code, png = req(f"/a/{serial}.png", raw=True)
check("code image PNG served", code == 200 and png[:8] == b"\x89PNG\r\n\x1a\n", code)
import zxingcpp, io
from PIL import Image
res = zxingcpp.read_barcodes(Image.open(io.BytesIO(png)))
check("image scannable & encodes landing URL", len(res) == 1 and res[0].text.endswith("/v/" + serial), res[0].text if res else "none")

# 4) /v/<serial> redirect lands on verify page with prefill
r = urllib.request.Request(BASE + f"/v/{serial}", method="GET")
with urllib.request.urlopen(r) as resp:
    final = resp.geturl(); html = resp.read().decode()
check("/v redirect -> /verify?serial=", final.endswith(f"/verify?serial={serial}"), final)
check("verify page prefills serial", serial in html)

# 5) public pre-info endpoint
code, info = req(f"/api/auth/info/{serial}")
check("pre-info shows brand+product", code == 200 and info["brand"] == "luxury_leather" and info["title"] == "Classic Wallet", (code, info))

# 6) customer verifies with WRONG passcode -> FAKE (403)
code, v = req("/api/verify", "POST", {"serial": serial, "passcode": "AAAABBBB"})
check("wrong passcode -> FAKE 403", code == 403 and v["result"] == "FAKE" and v["authentic"] is False, (code, v.get("result")))

# 7) unknown serial -> NOT_FOUND (403)
code, v = req("/api/verify", "POST", {"serial": "ZZZZZZZZZZZZ", "passcode": pcode})
check("unknown serial -> NOT_FOUND", code == 403 and v["result"] == "NOT_FOUND", (code, v.get("result")))

# 8) correct pair -> AUTHENTIC (200), first verification
code, v = req("/api/verify", "POST", {"serial": serial, "passcode": pcode})
check("correct pair -> AUTHENTIC 200", code == 200 and v["result"] == "AUTHENTIC" and v["first_verification"], (code, v.get("result")))

# 9) re-verify same unit -> warning about previous verification
code, v = req("/api/verify", "POST", {"serial": serial, "passcode": pcode})
check("re-verify -> AUTHENTIC_BUT_RESELLER warn", code == 200 and v["result"] == "AUTHENTIC_BUT_RESELLER" and v["authentic"] is False, (code, v.get("result"), v.get("authentic")))

# 10) brand stats reflect verifications
code, lst = req("/api/brands/luxury_leather/units")
s = lst["summary"]
check("brand summary counts", s["total_units"] == 3 and s["verified_units"] == 1 and s["suspect_units"] == 1, s)

# 11) passcodes never leak through public APIs
check("no passcode/hash leaks in list", all(("passcode" not in u and "salt" not in u and "passcode_hash" not in u) for u in lst["units"]), None)
code, pub = req(f"/api/auth/info/{serial}")
check("no secrets in pre-info", "passcode" not in pub and "salt" not in pub, None)

# 12) throttle after many wrong attempts (same IP) — expect lockout message eventually
locked = False
for i in range(12):
    code, v = req("/api/verify", "POST", {"serial": serial, "passcode": "BADCODE%d" % i})
    if "Too many" in (v.get("message") or ""): locked = True; break
check("brute-force throttled", locked, code)

print("\nRESULT:", "ALL PASS" if not fails else f"{len(fails)} FAILURES: {fails}")
sys.exit(1 if fails else 0)
