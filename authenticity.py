"""Product-authenticity registry — the core of the verification flow.

A business registers a batch of **genuine product units**.  Every unit gets:

* a unique, unguessable **serial** (encoded inside the printed code image);
* a human-readable **passcode** that ships *with* the physical product
  (printed on a tamper sticker / card inside the box).

The customer's flow:

1. Scan the code attached to the product  ->  the browser opens
   ``/verify/<serial>`` with the serial pre-filled.
2. Type the passcode that came with the product.
3. The server answers one of:

   * **AUTHENTIC** – the serial exists, belongs to a registered brand and the
     passcode matches;
   * **INVALID PASSCODE / NOT RECOGNISED** – no such serial, or the passcode
     does not match (a counterfeit can copy the printed image, but it cannot
     guess the secret passcode stored only on our servers);
   * **ALREADY VERIFIED ELSEWHERE** – first-use tracking: the very same
     serial+passcode verified from another place before, so this unit may be
     cloned or resold ("grey market" warning).

Passcodes are stored salted + PBKDF2-HMAC-SHA256 hashed (never in plain
text), compared in constant time, and brute-force attempts are throttled per
IP.  Verification history is capped per unit so the JSON file stays small.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import string
import threading
import time

DB_PATH = os.environ.get(
    "AUTH_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "authenticity.json")
)

SERIAL_ALPHABET = string.ascii_uppercase + string.digits
SERIAL_LENGTH = 12                       # ~62^12 possibilities: unguessable
PASSCODE_LENGTH = 8
PASSCODE_ALPHABET = string.ascii_uppercase + string.digits
# strip look-alike chars from customer-facing passcodes for readability
PASSCODE_ALPHABET = PASSCODE_ALPHABET.replace("O", "").replace("I", "").replace("0", "").replace("1", "")

MAX_BATCH = 500                          # units created per request
_MAX_FAILS = 10                          # wrong passcodes per IP ...
_WINDOW_SECONDS = 300                    # ... within this window -> lockout
_PBKDF2_ITERATIONS = 200_000
_HISTORY_CAP = 25


class AuthenticityError(ValueError):
    """Raised for any invalid registration/verification operation."""


def new_serial() -> str:
    return "".join(secrets.choice(SERIAL_ALPHABET) for _ in range(SERIAL_LENGTH))


def new_passcode() -> str:
    return "".join(secrets.choice(PASSCODE_ALPHABET) for _ in range(PASSCODE_LENGTH))


def _hash(passcode: str, salt_hex: str | None = None) -> tuple[str, str]:
    if salt_hex is None:
        salt_hex = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", passcode.encode("utf-8"), bytes.fromhex(salt_hex), _PBKDF2_ITERATIONS
    )
    return salt_hex, digest.hex()


class AuthenticityStore:
    """Thread-safe JSON-backed registry of genuine product units."""

    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._lock = threading.Lock()
        self._fails: dict[str, list[float]] = {}

    # ---------- persistence ----------
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

    # ---------- throttle ----------
    def _check_throttle(self, ip: str) -> None:
        now = time.time()
        fails = [t for t in self._fails.get(ip, []) if now - t < _WINDOW_SECONDS]
        if len(fails) >= _MAX_FAILS:
            raise AuthenticityError(
                "Too many incorrect verification attempts. Please wait a few minutes."
            )
        self._fails[ip] = fails

    def _record_fail(self, ip: str) -> None:
        self._fails.setdefault(ip, []).append(time.time())

    def _clear_fails(self, ip: str) -> None:
        self._fails.pop(ip, None)

    # ---------- registration (brand side) ----------
    def register_units(self, *, brand_handle: str, brand_passcode_hash: str,
                       brand_salt: str, title: str, quantity: int = 1) -> list[dict]:
        """Create `quantity` genuine units for a verified brand.

        Returns records including each unit's plaintext passcode — shown to
        the brand exactly once so it can be printed on the packaging.
        """
        title = (title or "").strip()[:80]
        try:
            quantity = int(quantity)
        except (TypeError, ValueError):
            raise AuthenticityError("Quantity must be a whole number.")
        if not 1 <= quantity <= MAX_BATCH:
            raise AuthenticityError(f"Quantity must be between 1 and {MAX_BATCH}.")
        if not (brand_handle or "").strip():
            raise AuthenticityError("Missing brand handle.")

        units = []
        with self._lock:
            data = self._load()
            for _ in range(quantity):
                serial = new_serial()
                while serial in data:
                    serial = new_serial()
                passcode = new_passcode()
                salt, hashed = _hash(passcode)
                record = {
                    "serial": serial,
                    "brand": brand_handle.strip().lower().lstrip("@"),
                    "brand_passcode_hash": brand_passcode_hash,
                    "brand_salt": brand_salt,
                    "title": title,
                    "salt": salt,
                    "passcode_hash": hashed,
                    "verified_count": 0,
                    "first_verified": None,
                    "history": [],
                    "created": time.time(),
                }
                data[serial] = record
                out = self._public(record)
                out["passcode"] = passcode      # shown once, never stored plain
                units.append(out)
            self._save(data)
        return units

    def get_unit(self, serial: str) -> dict:
        return self._public(self._get_record(serial))

    def list_for_brand(self, handle: str) -> list[dict]:
        key = (handle or "").strip().lower().lstrip("@")
        data = self._load()
        units = [self._public(r) for r in data.values() if r["brand"] == key]
        units.sort(key=lambda u: u["created"], reverse=True)
        return units

    def brand_summary(self, handle: str) -> dict:
        units = self.list_for_brand(handle)
        return {
            "total_units": len(units),
            "verified_units": sum(1 for u in units if u["verified_count"] > 0),
            "suspect_units": sum(1 for u in units if u.get("suspect")),
        }

    # ---------- verification (customer side) ----------
    def verify(self, serial: str, passcode: str, *, ip: str = "?") -> dict:
        """The heart of the app: is this product genuine?

        Possible outcomes (``result`` field):
          * ``AUTHENTIC``               – valid serial + matching passcode
          * ``UNKNOWN_CODE``            – serial not in the registry (404-ish)
          * ``FAKE``                    – serial exists but passcode is wrong
          * ``AUTHENTIC_BUT_RESELLER``  – genuine code, right passcode, but it
            was already verified elsewhere: possible clone / grey-market unit
        """
        serial = (serial or "").strip().upper()
        passcode = (passcode or "").strip().upper()
        if not serial:
            raise AuthenticityError("A product code (serial) is required.")
        if not passcode:
            raise AuthenticityError("The passcode printed with the product is required.")

        with self._lock:
            self._check_throttle(ip)
            data = self._load()
            record = data.get(serial)
            if record is None:
                # unknown code — also throttled so enumerating serials is hard
                self._record_fail(ip)
                return self._verdict(
                    "NOT_FOUND", False,
                    "This product code is not in our registry. It may be a "
                    "counterfeit, a mistyped code, or from a brand that has "
                    "not registered it.",
                )

            _, hashed = _hash(passcode, record["salt"])
            if not hmac.compare_digest(hashed, record["passcode_hash"]):
                self._record_fail(ip)
                return self._verdict(
                    "FAKE", False,
                    "The passcode does not match this product code. Genuine "
                    "products always carry the correct pairing — treat this "
                    "item as counterfeit and contact the brand.",
                )
            self._clear_fails(ip)

            now = time.time()
            first_time = record["verified_count"] == 0
            record["verified_count"] += 1
            if record["first_verified"] is None:
                record["first_verified"] = now
            record.setdefault("history", []).append({"at": now, "ip": ip})
            record["history"] = record["history"][-_HISTORY_CAP:]
            data[record["serial"]] = record
            self._save(data)

        suspect = record["verified_count"] > 1
        if suspect:
            message = (
                "The passcode is correct, but this exact product code was "
                f"already verified {record['verified_count'] - 1} time(s) before. "
                "If you bought this item new, it may be a clone of a genuine "
                "code or a resold unit — ask the brand to confirm."
            )
            verdict = "AUTHENTIC_BUT_RESELLER"
        else:
            verdict = "AUTHENTIC"
            message = "Genuine product ✔ — this code and passcode pair is authentic and was verified for the first time."

        out = self._verdict(verdict, not suspect, message)
        out["unit"] = self._public(record)
        out["first_verification"] = first_time
        return out

    @staticmethod
    def _verdict(result: str, authentic: bool, message: str) -> dict:
        return {"result": result, "authentic": authentic, "message": message}

    # ---------- helpers ----------
    def _get_record(self, serial: str) -> dict:
        key = (serial or "").strip().upper()
        if not key:
            raise AuthenticityError("Missing product code.")
        record = self._load().get(key)
        if record is None:
            raise AuthenticityError(f"No product with code “{key}” exists.")
        return record

    @staticmethod
    def _public(record: dict) -> dict:
        """Record stripped of every secret (hashes, salts, raw IPs of history)."""
        history = record.get("history", [])
        return {
            "serial": record["serial"],
            "brand": record["brand"],
            "title": record.get("title", ""),
            "verified_count": record.get("verified_count", 0),
            "first_verified": record.get("first_verified"),
            "last_verified": history[-1]["at"] if history else None,
            "created": record.get("created"),
            "suspect": record.get("verified_count", 0) > 1,
        }


store = AuthenticityStore()
