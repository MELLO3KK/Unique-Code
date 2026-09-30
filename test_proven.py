"""End-to-end tests for the Proven (DM Code) platform."""
import os, re, tempfile, unittest

os.environ["PROVEN_DB"] = tempfile.mktemp(suffix=".db")

import app as proven
from pylibdmtx.pylibdmtx import decode as dmtx_decode


class ProvenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = proven.app.test_client()

    def test_01_health(self):
        r = self.client.get("/healthz")
        self.assertEqual(r.status_code, 200)

    def test_02_register_brand_and_login(self):
        r = self.client.post("/register-brand",
                             data={"brand_name": "Aurelia"})
        self.assertEqual(r.status_code, 200)
        key = re.search(r"API key for .*?Aurelia.*?<code>(prv_[0-9a-f]+)",
                        r.get_data(as_text=True))
        self.assertIsNotNone(key, "one-time API key not shown")
        self.api_key = key.group(1)
        # dashboard accessible after registration session
        r = self.client.get("/dashboard")
        self.assertEqual(r.status_code, 200)
        # logout then login with api key
        self.client.post("/logout")
        r = self.client.get("/dashboard")
        self.assertEqual(r.status_code, 302)  # redirect to login
        r = self.client.post("/login", data={"brand_name": "aurelia",
                                             "api_key": self.api_key})
        self.assertEqual(r.status_code, 302)
        r = self.client.get("/dashboard")
        self.assertEqual(r.status_code, 200)

    def test_03_create_product_and_dm_roundtrip(self):
        payload_json = {"serial": "prvn-8fj2-qd41",
                        "passcode": "S3CRET-K3Y-XYZ",
                        "product_name": "Reserve Olive Oil",
                        "batch": "B-2026-07"}
        r = self.client.post("/api/products", json=payload_json)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        d = r.get_json()
        self.assertTrue(d["ok"])
        self.assertEqual(d["serial"], "PRVN-8FJ2-QD41")
        self.assertIn("verify?serial=PRVN-8FJ2-QD41&key=S3CRET-K3Y-XYZ",
                      d["payload"])
        import base64, io
        from PIL import Image
        img = Image.open(io.BytesIO(base64.b64decode(d["png_base64"])))
        dec = dmtx_decode(img.convert("RGB"))
        self.assertEqual(len(dec), 1)
        self.assertEqual(dec[0].data.decode(), d["payload"])
        # duplicate serial rejected
        r = self.client.post("/api/products", json=payload_json)
        self.assertEqual(r.status_code, 409)
        # validation failure
        r = self.client.post("/api/products", json={"serial": "!!", "passcode": "x", "product_name": ""})
        self.assertEqual(r.status_code, 400)

    def test_04_verify_first_use_then_clone(self):
        body = {"serial": "PRVN-8FJ2-QD41", "passcode": "S3CRET-K3Y-XYZ"}
        r = self.client.post("/api/verify", json=body)
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d["outcome"], "genuine_first_use")
        self.assertEqual(d["verdict"], "GENUINE")
        self.assertEqual(d["scan_count"], 1)
        # second valid scan => clone detected
        r = self.client.post("/api/verify", json=body)
        d = r.get_json()
        self.assertEqual(d["outcome"], "genuine_cloned")
        self.assertEqual(d["verdict"], "POSSIBLE CLONE")
        self.assertEqual(d["scan_count"], 2)

    def test_05_bad_passcode_and_unknown_serial(self):
        r = self.client.post("/api/verify", json={
            "serial": "PRVN-8FJ2-QD41", "passcode": "WRONG-PASSCODE"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.get_json()["outcome"], "bad_passcode")
        r = self.client.post("/api/verify", json={
            "serial": "FAKE-SERIAL-99", "passcode": "whatever123"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.get_json()["outcome"], "unknown_serial")
        # missing fields
        r = self.client.post("/api/verify", json={"serial": "PRVN8FJ2QD41"})
        self.assertEqual(r.status_code, 400)

    def test_06_hashing_is_salted_pbkdf2(self):
        h1, s1, i1 = proven.hash_passcode("same-pass")
        h2, s2, i2 = proven.hash_passcode("same-pass")
        self.assertNotEqual(s1, s2)
        self.assertNotEqual(h1, h2)
        self.assertTrue(proven.verify_passcode("same-pass", h1, s1, i1))
        self.assertFalse(proven.verify_passcode("same-pasS", h1, s1, i1))
        # DB stores only hash+salt
        con = proven.sqlite3.connect(proven.DB_PATH)
        row = con.execute("SELECT code_hash, code_salt FROM products").fetchone()
        con.close()
        self.assertNotIn("S3CRET", row[0] + row[1])

    def test_07_rate_limit_verify(self):
        saved = proven.RATE_LIMIT_MAX_VERIFY
        proven.RATE_LIMIT_MAX_VERIFY = 3
        try:
            ip = "203.0.113.7"
            codes = []
            for _ in range(5):
                r = self.client.post("/api/verify",
                                     json={"serial": "PRVN-8FJ2-QD41",
                                           "passcode": "nope-nope"},
                                     headers={"X-Forwarded-For": ip})
                codes.append(r.status_code)
            self.assertIn(429, codes)
            last = self.client.post("/api/verify",
                                    json={"serial": "PRVN-8FJ2-QD41",
                                          "passcode": "nope-nope"},
                                    headers={"X-Forwarded-For": ip})
            self.assertEqual(last.status_code, 429)
            self.assertEqual(last.headers.get("Retry-After"), "60")
        finally:
            proven.RATE_LIMIT_MAX_VERIFY = saved

    def test_08_ledger_page_and_append_only(self):
        r = self.client.get("/products/PRVN-8FJ2-QD41/ledger")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("Append-only ledger", html)
        self.assertIn("FIRST USE", html)
        con = proven.sqlite3.connect(proven.DB_PATH)
        n_before = con.execute("SELECT COUNT(*) FROM units").fetchone()[0]
        con.close()
        # every genuine scan appended a row
        self.assertGreaterEqual(n_before, 2)

    def test_09_dashboard_shows_alerts(self):
        r = self.client.get("/dashboard")
        html = r.get_data(as_text=True)
        self.assertIn("CLONE SUSPECTED", html)
        self.assertIn("Recent verification activity", html)

    def test_10_verify_page_prefill(self):
        r = self.client.get("/verify?serial=PRVN-8FJ2-QD41&key=S3CRET-K3Y-XYZ")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("PRVN-8FJ2-QD41", html)
        self.assertIn("auto: true", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
