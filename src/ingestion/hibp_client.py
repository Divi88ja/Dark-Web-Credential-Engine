"""
hibp_client.py
==============
Have I Been Pwned (HIBP) API v3 client for real-world breach validation.

Features:
  - Rate-limited HTTP calls
  - Local JSON cache with masked email keys
  - Severity mapping from breach data_classes
  - Strict output schema for pipeline ingestion
  - Raises on API failures (pipeline decides fallback)
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

# Data classes that significantly raise severity
HIGH_SEVERITY_CLASSES = {
    "Passwords",
    "Password hints",
    "Credit cards",
    "Bank account numbers",
    "Social security numbers",
    "Government issued IDs",
    "Health records",
    "Financial data",
    "Biometric data",
    "Private messages",
    "Personal health data",
}

MEDIUM_SEVERITY_CLASSES = {
    "Email addresses",
    "Usernames",
    "Dates of birth",
    "Phone numbers",
    "Physical addresses",
    "Geographic locations",
    "IP addresses",
    "Device information",
    "Auth tokens",
}


def _compute_severity(data_classes: list[str]) -> str:
    """Map HIBP DataClasses to severity: LOW|MEDIUM|HIGH|CRITICAL."""
    classes_set = set(data_classes or [])
    if classes_set & HIGH_SEVERITY_CLASSES:
        # Passwords + financial = critical
        if "Passwords" in classes_set and (
            classes_set & {"Credit cards", "Bank account numbers", "Financial data"}
        ):
            return "CRITICAL"
        return "HIGH"
    if classes_set & MEDIUM_SEVERITY_CLASSES:
        return "MEDIUM"
    return "LOW"


class HIBPClientError(Exception):
    """Raised when the HIBP API lookup fails and the pipeline should handle fallback."""


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

CACHE_DIR = Path("data/hibp_cache")
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _mask_email(email: str) -> str:
    """One-way hash of email for use as cache key (no PII stored in filenames)."""
    return hashlib.sha256(email.lower().encode()).hexdigest()[:16]


def _cache_path(email: str) -> Path:
    return CACHE_DIR / f"{_mask_email(email)}.json"


def _load_cache(email: str) -> Optional[list[dict]]:
    path = _cache_path(email)
    if path.exists():
        try:
            with path.open() as f:
                payload = json.load(f)
            logger.debug("Cache hit for masked email %s", _mask_email(email))
            return payload.get("breaches", [])
        except (json.JSONDecodeError, KeyError):
            logger.warning("Corrupt cache file %s – ignoring.", path)
    return None


def _save_cache(email: str, breaches: list[dict]) -> None:
    path = _cache_path(email)
    payload = {
        "masked_email": _mask_email(email),
        "cached_at": datetime.utcnow().isoformat(),
        "breaches": breaches,
    }
    with path.open("w") as f:
        json.dump(payload, f, indent=2)
    logger.debug("Cached %d breach(es) for masked email %s", len(breaches), _mask_email(email))


# ---------------------------------------------------------------------------
# Rate limiter (token-bucket, thread-safe-enough for single-process use)
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple fixed-window rate limiter."""

    def __init__(self, calls_per_minute: int = 10) -> None:
        self._interval = 60.0 / max(calls_per_minute, 1)
        self._last_call: float = 0.0

    def wait(self) -> None:
        elapsed = time.monotonic() - self._last_call
        gap = self._interval - elapsed
        if gap > 0:
            logger.debug("Rate limiter sleeping %.2fs", gap)
            time.sleep(gap)
        self._last_call = time.monotonic()


# ---------------------------------------------------------------------------
# HIBP Client
# ---------------------------------------------------------------------------

class HIBPClient:
    """
    Client for the Have I Been Pwned v3 breachedaccount endpoint.

    Parameters
    ----------
    api_key : str
        HIBP API key (obtain from https://haveibeenpwned.com/API/Key).
    rate_limit_per_min : int
        Maximum API calls per minute (default 10, HIBP free tier = 10/min).
    use_cache : bool
        Whether to cache API responses locally.
    """

    BASE_URL = "https://haveibeenpwned.com/api/v3"
    TIMEOUT = 10  # seconds

    def __init__(
        self,
        api_key: str,
        rate_limit_per_min: int = 10,
        use_cache: bool = True,
    ) -> None:
        self._api_key = api_key
        self._use_cache = use_cache
        self._limiter = _RateLimiter(rate_limit_per_min)
        self._session = requests.Session()
        self._session.headers.update(
            {
                "hibp-api-key": self._api_key,
                "user-agent": "DarkWebCredentialDetector/2.0",
                "Accept": "application/json",
            }
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get_breaches_for_email(self, email: str) -> list[dict]:
        """
        Accept an email address and return a list of breach items.

        Each returned breach item contains ONLY:
          - breach_name (str)
          - breach_date (str, YYYY-MM-DD)
          - data_classes (list[str])
          - severity (str: LOW|MEDIUM|HIGH|CRITICAL)

        Returns [] when the account has no breaches.
        Raises `HIBPClientError` when the API request fails.
        """
        if self._use_cache:
            cached = _load_cache(email)
            if cached is not None:
                return cached

        raw_breaches = self._fetch_breaches(email)
        # _fetch_breaches raises on failure; on success it returns [] or the raw JSON list.
        records = [self._normalise(b) for b in (raw_breaches or [])]

        if self._use_cache:
            _save_cache(email, records)

        return records

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _fetch_breaches(self, email: str) -> Optional[list[dict]]:
        """Call HIBP API; return raw JSON list or None on failure."""
        url = f"{self.BASE_URL}/breachedaccount/{requests.utils.quote(email)}"
        params = {"truncateResponse": "false"}

        self._limiter.wait()

        try:
            resp = self._session.get(url, params=params, timeout=self.TIMEOUT)

            if resp.status_code == 200:
                return resp.json()

            if resp.status_code == 404:
                # 404 = no breaches found (not an error)
                logger.info("No breaches found for masked email %s", _mask_email(email))
                return []

            if resp.status_code == 401:
                raise HIBPClientError("HIBP API key invalid or missing (401).")

            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", 60))
                logger.warning("HIBP rate limit hit; sleeping %ds", retry_after)
                time.sleep(retry_after)
                # single retry; if it fails again, _fetch_breaches will raise.
                return self._fetch_breaches(email)

            raise HIBPClientError(
                f"HIBP API unexpected response {resp.status_code}: {resp.text[:200]}"
            )

        except requests.exceptions.Timeout:
            raise HIBPClientError("HIBP request timed out.")
        except requests.exceptions.ConnectionError as exc:
            raise HIBPClientError(f"HIBP connection error: {exc}")
        except Exception as exc:  # noqa: BLE001
            raise HIBPClientError(f"Unexpected error calling HIBP: {exc}")

    @staticmethod
    def _normalise(raw: dict) -> dict:
        """Convert a raw HIBP breach object to the strict client return schema."""
        data_classes: list[str] = raw.get("DataClasses") or []
        breach_date_raw: str = raw.get("BreachDate") or "1970-01-01"

        # Ensure date is YYYY-MM-DD
        try:
            breach_date = datetime.strptime(breach_date_raw, "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            breach_date = "1970-01-01"

        return {
            "breach_name": raw.get("Name", "Unknown"),
            "breach_date": breach_date,
            "data_classes": data_classes,
            "severity": _compute_severity(data_classes),
        }


# ---------------------------------------------------------------------------
# Factory – loads from settings.yaml automatically
# ---------------------------------------------------------------------------

def build_client_from_config(config: dict) -> Optional[HIBPClient]:
    """
    Construct HIBPClient from the `hibp` section of settings.yaml.

    Returns None if hibp is disabled or api_key is missing.
    """
    # Support both config layouts:
    #   1) top-level `hibp: {...}`
    #   2) nested `ingestion: { hibp: {...} }`
    hibp_cfg = config.get("hibp") or config.get("ingestion", {}).get("hibp", {})

    if not hibp_cfg.get("enabled", False):
        logger.info("HIBP integration is disabled in config.")
        return None

    api_key = hibp_cfg.get("api_key", "")
    if not api_key or api_key == "YOUR_API_KEY":
        logger.error("HIBP enabled but api_key is not configured.")
        return None

    return HIBPClient(
        api_key=api_key,
        rate_limit_per_min=hibp_cfg.get("rate_limit_per_min", 10),
        use_cache=hibp_cfg.get("use_cache", True),
    )
