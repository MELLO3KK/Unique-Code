"""Business-brand registry for the social-style DM Code network.

Every business brand can create an account on the platform, just like a social
media profile.  Each brand account owns:

* a unique **handle** (its @name, claimed once — no two brands may share it);
* a display name, bio and category;
* a **passcode** (the brand's password) — required to change anything about
  the account or to manage its codes;
* a list of **product codes**: QR-look-alike Data Matrix codes the brand
  creates for its products.

Customers who buy a product from that brand can then make their OWN copy of
that product code ("claim a copy"): they scan the brand's code, enter the
brand's handle + the product code ID, pick a style, and receive a personal
unique ID linked back to the brand's product.  The customer's personal code
is protected by its own freshly generated passcode — exactly like the brand's
original — so only the customer can later change it.

Storage is JSON files (brands.json / brand_products.json) so everything
survives server restarts.  Passcodes are never stored in plain text: PBKDF2-
HMAC-SHA256 with a per-record salt, compared in constant time, with per-IP
brute-force throttling.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import string
import threading
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BRAND_DB = os.environ.get("BRANDS_DB", os.path.join(BASE_DIR, "brands.json"))
PRODUCT_DB = os.environ.get("BRAND_PRODUCTS_DB", os.path.join(BASE_DIR, "brand_products.json"))

HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9_]{1,29}$")  # instagram-style @handle
MAX_BIO_CHARS = 300
MAX_MESSAGE_BYTES = 800

ID_ALPHABET = string.ascii_letters + string.digits
ID_LENGTH = 16
PASSCODE_LENGTH = 10
PASSCODE_ALPHABET = string.ascii_uppercase + string.digits

_PBKDF2_ITERATIONS = 200_000
_MAX_FAILS = 10
_WINDOW_SECONDS = 300


class BrandError(ValueError):
    """Raised for any invalid brand/product operation (maps to HTTP 4xx)."""


def new_passcode() -> str:
    return "".join(secrets.choice(PASSCODE_ALPHABET) for _ in range(PASSCODE_LENGTH))


def _hash_passcode(passcode: str, salt_hex: str | None = None) -> tuple[str, str]:
    if salt_hex is None:
        salt_hex = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", passcode.encode("utf-8"), bytes.fromhex(salt_hex), _PBKDF2_ITERATIONS
    )
    return salt_hex, digest.hex()


class _JsonCollection:
    """Tiny thread-safe JSON-backed dict-of-dicts store."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._fails: dict[str, list[float]] = {}

    def _load(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self, data: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self.path)

    # ---- brute-force throttle (shared across collections' methods) ----
    def _check_throttle(self, ip: str) -> None:
        now = time.time()
        fails = [t for t in self._fails.get(ip, []) if now - t < _WINDOW_SECONDS]
        if len(fails) >= _MAX_FAILS:
            raise BrandError(
                "Too many incorrect passcode attempts. Please wait a few minutes."
            )
        self._fails[ip] = fails

    def _record_fail(self, ip: str) -> None:
        self._fails.setdefault(ip, []).append(time.time())

    def _clear_fails(self, ip: str) -> None:
        self._fails.pop(ip, None)

    def _verify(self, record: dict, passcode: str, ip: str, what: str) -> None:
        passcode = (passcode or "").strip().upper()
        if not passcode:
            raise BrandError(f"A passcode is required to change this {what}.")
        _, hashed = _hash_passcode(passcode, record["salt"])
        if not hmac.compare_digest(hashed, record["passcode_hash"]):
            self._record_fail(ip)
            raise BrandError(f"Incorrect passcode — changes to this {what} are not allowed.")
        self._clear_fails(ip)


class BrandStore(_JsonCollection):
    """Brand accounts + the product codes they publish."""

    def __init__(self, brand_path: str = BRAND_DB, product_path: str = PRODUCT_DB):
        super().__init__(brand_path)
        self.products = _JsonCollection(product_path)

    # ------------------------------------------------------------------
    # Brand accounts
    # ------------------------------------------------------------------
    def create_brand(self, *, handle: str, name: str, bio: str = "",
                     category: str = "", style: str = "classic") -> dict:
        handle = (handle or "").strip().lower().lstrip("@")
        if not HANDLE_RE.match(handle):
            raise BrandError(
                "Handle must be 2-30 characters: lowercase letters, digits or "
                "underscores, starting with a letter or digit."
            )
        name = (name or "").strip()[:80]
        if not name:
            raise BrandError("A business/display name is required.")
        bio = (bio or "").strip()[:MAX_BIO_CHARS]
        category = (category or "").strip()[:60]

        passcode = new_passcode()
        salt, hashed = _hash_passcode(passcode)

        with self._lock:
            data = self._load()
            if handle in data:
                raise BrandError(f"The @{handle} handle is already taken.")
            record = {
                "handle": handle,
                "name": name,
                "bio": bio,
                "category": category,
                "style": style,
                "salt": salt,
                "passcode_hash": hashed,
                "created": time.time(),
                "modified": time.time(),
            }
            data[handle] = record
            self._save(data)

        out = self._public_brand(record)
        out["passcode"] = passcode  # shown ONCE to the creator
        return out

    def get_brand(self, handle: str) -> dict:
        return self._public_brand(self._get_brand_record(handle))

    def update_brand(self, handle: str, *, passcode: str, name: str | None = None,
                     bio: str | None = None, category: str | None = None,
                     style: str | None = None, new_passcode: str | None = None,
                     ip: str = "?") -> dict:
        with self._lock:
            self._check_throttle(ip)
            data = self._load()
            record = data.get((handle or "").strip().lower().lstrip("@"))
            if record is None:
                raise BrandError(f"No brand account named “{(handle or '').strip()}”.")
            self._verify(record, passcode, ip, "brand account")

            if name is not None:
                name = name.strip()[:80]
                if not name:
                    raise BrandError("The business name cannot be empty.")
                record["name"] = name
            if bio is not None:
                record["bio"] = bio.strip()[:MAX_BIO_CHARS]
            if category is not None:
                record["category"] = category.strip()[:60]
            if style:
                record["style"] = style
            if new_passcode:
                salt, hashed = _hash_passcode(new_passcode.upper())
                record["salt"] = salt
                record["passcode_hash"] = hashed
            record["modified"] = time.time()
            data[record["handle"]] = record
            self._save(data)

        out = self._public_brand(record)
        if new_passcode:
            out["passcode"] = new_passcode
        return out

    def verify_brand(self, handle: str, passcode: str, ip: str = "?") -> dict:
        """Log-in style check: returns the public brand if the passcode matches."""
        with self._lock:
            self._check_throttle(ip)
            data = self._load()
            record = data.get((handle or "").strip().lower().lstrip("@"))
            if record is None:
                raise BrandError(f"No brand account named “{(handle or '').strip()}”.")
            self._verify(record, passcode, ip, "brand account")
        return self._public_brand(record)

    def authenticate_brand(self, handle: str, passcode: str, ip: str = "?") -> dict:
        """Verify a brand passcode and return its *internal* record.

        Unlike :meth:`verify_brand` this keeps the salted passcode hash so
        other modules (e.g. authenticity.py) can re-check it without ever
        seeing — or storing — the plaintext passcode.
        """
        with self._lock:
            self._check_throttle(ip)
            data = self._load()
            record = data.get((handle or "").strip().lower().lstrip("@"))
            if record is None:
                raise BrandError(f"No brand account named “{(handle or '').strip()}”.")
            self._verify(record, passcode, ip, "brand account")
        return record

    def list_brands(self) -> list[dict]:
        data = self._load()
        brands = [self._public_brand(r) for r in data.values()]
        brands.sort(key=lambda b: b["created"])
        for b in brands:
            b["product_count"] = self.count_products(b["handle"])
        return brands

    # ------------------------------------------------------------------
    # Product codes owned by a brand
    # ------------------------------------------------------------------
    def create_product(self, handle: str, *, passcode: str, message: str,
                       title: str = "", style: str | None = None,
                       ip: str = "?") -> dict:
        """A brand creates a product code. Requires the brand's passcode."""
        brand = self._get_brand_record(handle)
        message = (message or "").strip()
        if not message:
            raise BrandError("A product link or message is required.")
        if len(message.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise BrandError(
                f"Message too long ({len(message.encode('utf-8'))} bytes); "
                f"limit is {MAX_MESSAGE_BYTES}."
            )
        title = (title or "").strip()[:80] or message[:60]

        with self._lock:
            self._check_throttle(ip)
            self._verify(brand, passcode, ip, "brand account")
            self._clear_fails(ip)

        passcode_prod = new_passcode()
        salt, hashed = _hash_passcode(passcode_prod)

        with self.products._lock:
            prods = self.products._load()
            uid = self._new_id(prods)
            record = {
                "id": uid,
                "brand": brand["handle"],
                "title": title,
                "message": message,
                "style": style or brand.get("style", "classic"),
                "salt": salt,
                "passcode_hash": hashed,
                "copies": 0,
                "created": time.time(),
                "modified": time.time(),
            }
            prods[uid] = record
            self.products._save(prods)

        out = self._public_product(record)
        out["passcode"] = passcode_prod  # shown once; lets the brand edit it later
        return out

    def list_products(self, handle: str) -> list[dict]:
        self._get_brand_record(handle)  # 404 if unknown brand
        prods = self.products._load()
        items = [self._public_product(p) for p in prods.values()
                 if p["brand"] == (handle or "").strip().lower().lstrip("@")]
        items.sort(key=lambda p: p["created"])
        return items

    def count_products(self, handle: str) -> int:
        prods = self.products._load()
        return sum(1 for p in prods.values() if p["brand"] == handle)

    def get_product(self, pid: str) -> dict:
        return self._public_product(self._get_product_record(pid))

    def update_product(self, pid: str, *, passcode: str, message: str | None = None,
                       title: str | None = None, style: str | None = None,
                       ip: str = "?") -> dict:
        record = self._get_product_record(pid)
        with self.products._lock:
            self._check_throttle(ip)
            self._verify(record, passcode, ip, "product code")
            if message is not None:
                message = message.strip()
                if not message:
                    raise BrandError("The new message cannot be empty.")
                if len(message.encode("utf-8")) > MAX_MESSAGE_BYTES:
                    raise BrandError(f"Message too long; limit is {MAX_MESSAGE_BYTES} bytes.")
                record["message"] = message
            if title is not None:
                record["title"] = title.strip()[:80] or record["title"]
            if style:
                record["style"] = style
            record["modified"] = time.time()
            prods = self.products._load()
            prods[record["id"]] = record
            self.products._save(prods)
        return self._public_product(record)

    # ------------------------------------------------------------------
    # Customers making their own copy of a brand's product code
    # ------------------------------------------------------------------
    def claim_copy(self, pid: str, *, customer: str = "", style: str | None = None) -> dict:
        """A customer creates their OWN personal version of a brand product code.

        No brand passcode needed — the product ID itself (obtained by scanning
        the brand's printed code) is the authorisation.  The customer receives
        a brand-new unique ID + passcode protecting their personal copy, which
        links back to the brand's product.
        """
        product = self._get_product_record(pid)
        brand = self._get_brand_record(product["brand"])
        customer = (customer or "").strip()[:64]

        passcode = new_passcode()
        salt, hashed = _hash_passcode(passcode)

        with self.products._lock:
            prods = self.products._load()
            uid = self._new_id(prods)
            copy = {
                "id": uid,
                "brand": brand["handle"],
                "product": product["id"],
                "product_title": product["title"],
                "customer": customer or None,
                "message": product["message"],  # personal copy starts from the brand's payload
                "style": style or product.get("style", "classic"),
                "salt": salt,
                "passcode_hash": hashed,
                "is_copy": True,
                "created": time.time(),
                "modified": time.time(),
            }
            prods[uid] = copy
            product["copies"] = product.get("copies", 0) + 1
            prods[product["id"]] = product
            self.products._save(prods)

        out = self._public_product(copy)
        out["passcode"] = passcode  # shown once to the customer
        return out

    def update_copy(self, uid: str, *, passcode: str, message: str | None = None,
                    style: str | None = None, customer: str | None = None,
                    ip: str = "?") -> dict:
        """Customer edits their personal copy — their own passcode required."""
        record = self._get_product_record(uid)
        if not record.get("is_copy"):
            raise BrandError(
                "This is the brand's original product code — use the brand's "
                "management endpoint instead."
            )
        with self.products._lock:
            self._check_throttle(ip)
            self._verify(record, passcode, ip, "personal copy")
            if message is not None:
                message = message.strip()
                if not message:
                    raise BrandError("The new message cannot be empty.")
                if len(message.encode("utf-8")) > MAX_MESSAGE_BYTES:
                    raise BrandError(f"Message too long; limit is {MAX_MESSAGE_BYTES} bytes.")
                record["message"] = message
            if style:
                record["style"] = style
            if customer is not None:
                record["customer"] = customer.strip()[:64] or None
            record["modified"] = time.time()
            prods = self.products._load()
            prods[record["id"]] = record
            self.products._save(prods)
        return self._public_product(record)

    def list_copies(self, pid: str) -> list[dict]:
        self._get_product_record(pid)
        prods = self.products._load()
        copies = [self._public_product(p) for p in prods.values()
                  if p.get("product") == pid]
        copies.sort(key=lambda c: c["created"])
        return copies

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _new_id(existing: dict) -> str:
        while True:
            uid = "".join(secrets.choice(ID_ALPHABET) for _ in range(ID_LENGTH))
            if uid not in existing:
                return uid

    def _get_brand_record(self, handle: str) -> dict:
        key = (handle or "").strip().lower().lstrip("@")
        if not key:
            raise BrandError("Missing brand handle.")
        data = self._load()
        record = data.get(key)
        if record is None:
            raise BrandError(f"No brand account named “{key}”.")
        return record

    def _get_product_record(self, pid: str) -> dict:
        key = (pid or "").strip()
        if not key:
            raise BrandError("Missing product code ID.")
        prods = self.products._load()
        record = prods.get(key)
        if record is None:
            raise BrandError(f"No product code “{key}” exists.")
        return record

    @staticmethod
    def _public_brand(record: dict) -> dict:
        return {
            "handle": record["handle"],
            "name": record["name"],
            "bio": record.get("bio", ""),
            "category": record.get("category", ""),
            "style": record.get("style", "classic"),
            "created": record.get("created"),
            "modified": record.get("modified"),
        }

    @staticmethod
    def _public_product(record: dict) -> dict:
        out = {
            "id": record["id"],
            "brand": record["brand"],
            "title": record.get("title", ""),
            "message": record["message"],
            "style": record.get("style", "classic"),
            "is_copy": bool(record.get("is_copy")),
            "created": record.get("created"),
            "modified": record.get("modified"),
        }
        if record.get("is_copy"):
            out["product"] = record.get("product")
            out["customer"] = record.get("customer")
        else:
            out["copies"] = record.get("copies", 0)
        return out


store = BrandStore()
