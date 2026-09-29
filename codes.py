"""Unique-ID registry with passcode protection.

Every code stored here has:

* a **unique ID** – a random, unguessable token that is also the text encoded
  inside the generated Data Matrix image;
* a **passcode** – required to *change* anything about that unique ID
  (its message, its style, or to claim ownership of it);
* an optional **owner** – anyone can create a code anonymously, but only the
  person who knows the passcode can claim/keep ownership of it.

The passcode itself is never stored in plain text: it is salted and hashed
with PBKDF2-HMAC-SHA256, and compared with a constant-time function.

Storage is a small JSON file so codes survive server restarts.
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

DB_PATH = os.environ.get("DMCODE_DB", os.path.join(os.path.dirname(__file__), "codes.json"))


def _secret_file() -> str:
    return os.path.join(os.path.dirname(DB_PATH), ".flask_secret_key")


def load_secret_key() -> str:
    """Persistent Flask secret key (needed to sign owner session cookies).

    Generated once and stored next to the database; falls back to an ephemeral
    key if the location is read-only.
    """
    path = _secret_file()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            key = fh.read().strip()
            if key:
                return key
    except OSError:
        pass
    key = secrets.token_hex(32)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(key)
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key

ID_ALPHABET = string.ascii_letters + string.digits  # base62-ish
ID_LENGTH = 16
PASSCODE_LENGTH = 10
PASSCODE_ALPHABET = string.ascii_uppercase + string.digits  # easy to read out loud

MAX_MESSAGE_BYTES = 800  # same limit as dmcode.MAX_TEXT_BYTES

# Simple brute-force throttle: per-IP failed-attempt window.
_MAX_FAILS = 10
_WINDOW_SECONDS = 300

_PBKDF2_ITERATIONS = 200_000


class CodeError(ValueError):
    """Raised for any invalid operation on the registry (maps to HTTP 4xx)."""


def _new_unique_id() -> str:
    return "".join(secrets.choice(ID_ALPHABET) for _ in range(ID_LENGTH))


def new_passcode() -> str:
    """Generate a fresh human-readable passcode."""
    return "".join(secrets.choice(PASSCODE_ALPHABET) for _ in range(PASSCODE_LENGTH))


def _hash_passcode(passcode: str, salt_hex: str | None = None) -> tuple[str, str]:
    """Return (salt_hex, hash_hex) for PBKDF2-HMAC-SHA256 over the passcode."""
    if salt_hex is None:
        salt_hex = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", passcode.encode("utf-8"), bytes.fromhex(salt_hex), _PBKDF2_ITERATIONS
    )
    return salt_hex, digest.hex()


class CodeStore:
    """Thread-safe JSON-backed store of unique IDs protected by passcodes."""

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

    # ---------- throttling ----------
    def _check_throttle(self, ip: str) -> None:
        now = time.time()
        fails = [t for t in self._fails.get(ip, []) if now - t < _WINDOW_SECONDS]
        if len(fails) >= _MAX_FAILS:
            raise CodeError("Too many incorrect passcode attempts. Please wait a few minutes.")
        self._fails[ip] = fails

    def _record_fail(self, ip: str) -> None:
        self._fails.setdefault(ip, []).append(time.time())

    def _clear_fails(self, ip: str) -> None:
        self._fails.pop(ip, None)

    # ---------- public API ----------
    def create(self, message: str, owner: str = "", style: str = "classic") -> dict:
        """Create a brand-new unique ID protected by a freshly generated passcode."""
        message = (message or "").strip()
        if not message:
            raise CodeError("A message is required to create a unique ID.")
        if len(message.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise CodeError(f"Message too long ({len(message.encode('utf-8'))} bytes); limit is {MAX_MESSAGE_BYTES}.")

        owner = (owner or "").strip()[:64]
        passcode = new_passcode()
        salt, hashed = _hash_passcode(passcode)

        with self._lock:
            data = self._load()
            uid = _new_unique_id()
            while uid in data:  # astronomically unlikely, but be safe
                uid = _new_unique_id()
            record = {
                "id": uid,
                "message": message,
                "style": style,
                "owner": owner or None,
                "salt": salt,
                "passcode_hash": hashed,
                "created": time.time(),
                "modified": time.time(),
            }
            data[uid] = record
            self._save(data)

        # The plaintext passcode exists only in this response — it is shown to
        # the creator once and never stored or returned again.
        record_out = self._public(record)
        record_out["passcode"] = passcode
        return record_out

    def get(self, uid: str) -> dict:
        record = self._get_record(uid)
        return self._public(record)

    def change(self, uid: str, passcode: str, *, message: str | None = None,
               owner: str | None = None, style: str | None = None,
               new_passcode: str | None = None, ip: str = "?") -> dict:
        """Change a unique ID's contents. The correct passcode is mandatory."""
        passcode = (passcode or "").strip()
        if not passcode:
            raise CodeError("A passcode is required to change this unique ID.")

        with self._lock:
            self._check_throttle(ip)
            data = self._load()
            record = data.get(self._norm(uid))
            if record is None:
                raise CodeError(f"No unique ID “{(uid or '').strip()}” exists.")

            _, hashed = _hash_passcode(passcode, record["salt"])
            if not hmac.compare_digest(hashed, record["passcode_hash"]):
                self._record_fail(ip)
                raise CodeError("Incorrect passcode — changes to this unique ID are not allowed.")
            self._clear_fails(ip)

            if message is not None:
                message = message.strip()
                if not message:
                    raise CodeError("The new message cannot be empty.")
                if len(message.encode("utf-8")) > MAX_MESSAGE_BYTES:
                    raise CodeError(f"Message too long; limit is {MAX_MESSAGE_BYTES} bytes.")
                record["message"] = message
            if style:
                record["style"] = style
            if owner is not None:
                record["owner"] = owner.strip()[:64] or None
            if new_passcode:
                salt, hashed_new = _hash_passcode(new_passcode)
                record["salt"] = salt
                record["passcode_hash"] = hashed_new

            record["modified"] = time.time()
            data[record["id"]] = record
            self._save(data)

        out = self._public(record)
        if new_passcode:
            out["passcode"] = new_passcode
        return out

    def verify_owner(self, uid: str, passcode: str, ip: str = "?") -> bool:
        """Check a passcode without changing anything (throttled like change())."""
        with self._lock:
            self._check_throttle(ip)
            data = self._load()
            record = data.get(self._norm(uid))
            if record is None:
                raise CodeError(f"No unique ID “{(uid or '').strip()}” exists.")
            _, hashed = _hash_passcode((passcode or "").strip(), record["salt"])
            if not hmac.compare_digest(hashed, record["passcode_hash"]):
                self._record_fail(ip)
                raise CodeError("Incorrect passcode.")
            self._clear_fails(ip)
            return True

    # ---------- helpers ----------
    @staticmethod
    def _norm(uid: str) -> str:
        uid = (uid or "").strip()
        if not uid:
            raise CodeError("Missing unique ID.")
        return uid

    def _get_record(self, uid: str) -> dict:
        data = self._load()
        record = data.get(self._norm(uid))
        if record is None:
            raise CodeError(f"No unique ID “{(uid or '').strip()}” exists.")
        return record

    @staticmethod
    def _public(record: dict) -> dict:
        """Record stripped of all secret material."""
        return {
            "id": record["id"],
            "message": record["message"],
            "style": record.get("style", "classic"),
            "owner": record.get("owner"),
            "has_owner": bool(record.get("owner")),
            "created": record.get("created"),
            "modified": record.get("modified"),
        }


store = CodeStore()
