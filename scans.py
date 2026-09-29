"""Scan ledger — every customer scan / proof-of-purchase is saved here.

When a customer scans a product code on the homepage and submits their proof
of purchase, one immutable record is appended to ``scan_records.json``:

    who      – optional customer name/handle they typed
    what     – the serial of the genuine unit registered by the brand
    brand    – which business brand the unit belongs to
    result   – AUTHENTIC / FAKE / NOT_FOUND / ALREADY_USED
    ip       – best-effort client IP
    device   – browser user-agent (helps spot suspicious resale rings)

Brands can pull their own history through :func:`ScanStore.list_for_brand`,
which requires the brand's passcode (verified server-side with the same
PBKDF2 hash stored on the brand account).  Nothing is ever deleted; the
ledger only grows.
"""

from __future__ import annotations

import json
import os
import threading
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_DB = os.environ.get("SCAN_DB", os.path.join(BASE_DIR, "scan_records.json"))


class ScanError(ValueError):
    """Raised for invalid scan-ledger operations."""


class ScanStore:
    """Thread-safe append-only JSON ledger of customer scans."""

    def __init__(self, path: str = SCAN_DB):
        self.path = path
        self._lock = threading.Lock()

    # ---------- persistence ----------
    def _load(self) -> list[dict]:
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            return []

    def _save(self, rows: list[dict]) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2)
        os.replace(tmp, self.path)

    # ---------- write ----------
    def log(self, *, serial: str, brand: str | None, result: str,
            authentic: bool, message: str, customer: str = "",
            ip: str = "?", device: str = "") -> dict:
        """Append one scan record and return it."""
        row = {
            "at": time.time(),
            "serial": (serial or "").strip().upper(),
            "brand": (brand or "").strip().lower().lstrip("@") or None,
            "result": result,
            "authentic": bool(authentic),
            "message": message,
            "customer": (customer or "").strip()[:60] or None,
            "ip": ip,
            "device": device[:200],
        }
        with self._lock:
            rows = self._load()
            rows.append(row)
            self._save(rows)
        return row

    # ---------- read ----------
    def all_rows(self) -> list[dict]:
        rows = self._load()
        rows.sort(key=lambda r: r.get("at", 0), reverse=True)
        return rows

    def list_for_brand(self, handle: str, *, limit: int = 500) -> list[dict]:
        key = (handle or "").strip().lower().lstrip("@")
        rows = [r for r in self.all_rows() if r.get("brand") == key]
        return rows[:limit]

    def stats_for_brand(self, handle: str) -> dict:
        rows = self.list_for_brand(handle, limit=100_000)
        return {
            "total_scans": len(rows),
            "proofs_ok": sum(1 for r in rows if r["result"] == "AUTHENTIC"),
            "suspect_resale": sum(1 for r in rows if r["result"] == "ALREADY_USED"),
            "fakes": sum(1 for r in rows if r["result"] in ("FAKE", "NOT_FOUND")),
        }


store = ScanStore()
