"""abuse.ch threat-intel client for SentinelLLM (Person 2).

Pulls *metadata only* from three abuse.ch community feeds and caches the raw
responses on disk:

    MalwareBazaar  POST  https://mb-api.abuse.ch/api/v1/          (get_recent / get_info)
    ThreatFox      POST  https://threatfox-api.abuse.ch/api/v1/   (get_iocs)
    URLhaus        GET   https://urlhaus-api.abuse.ch/v2/files/exports/<KEY>/recent.csv

It deliberately never calls `get_file` / the batch downloads: the pipeline needs
indicator metadata (hashes, families, reputation), not live malware. Samples are
password-protected zips served by abuse.ch and have no place in this repo.

Authentication
    An Auth-Key is required by MalwareBazaar and ThreatFox (URLhaus also has a
    keyless public dump). Provide it via the `ABUSECH_AUTH_KEY` environment
    variable, a `.env` file, or a `.abusech_key` file in the repo root (all
    gitignored). Get a free key at https://auth.abuse.ch/. Usage is governed by
    the abuse.ch fair-use principles; commercial use needs the paid enhanced API.

Usage
    python intel/abusech.py --smoke           # fetch one page of each feed
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

AUTH_KEY_ENV = "ABUSECH_AUTH_KEY"
KEY_FILE = Path(".abusech_key")
DOTENV_FILE = Path(".env")

MB_API = "https://mb-api.abuse.ch/api/v1/"
TF_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_EXPORT = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"
URLHAUS_PUBLIC_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"

CACHE_DIR = Path("data_real/intel/cache")
MIN_INTERVAL_S = 1.0
TIMEOUT_S = 30

_LAST_CALL = [0.0]


class AuthKeyMissing(RuntimeError):
    """Raised when no abuse.ch Auth-Key can be found."""


class AbuseChError(RuntimeError):
    """Raised when a feed answers with a non-ok query_status."""


def _dotenv_get(name: str) -> str | None:
    """Read KEY=VALUE from a local .env without clobbering real env vars."""
    if not DOTENV_FILE.exists():
        return None
    for line in DOTENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip() == name:
            return v.strip().strip("'\"")
    return None


def load_auth_key() -> str:
    key = os.environ.get(AUTH_KEY_ENV) or _dotenv_get(AUTH_KEY_ENV)
    if not key and KEY_FILE.exists():
        key = KEY_FILE.read_text().strip()
    if not key:
        raise AuthKeyMissing(
            f"no abuse.ch Auth-Key found. Set ${AUTH_KEY_ENV}, or put it in "
            f"{DOTENV_FILE} / {KEY_FILE} (both gitignored). "
            "Get one free at https://auth.abuse.ch/."
        )
    return key


def auth_key_id() -> str:
    """Short, non-reversible fingerprint so a manifest can name the key that
    produced an index without leaking it."""
    return hashlib.sha256(load_auth_key().encode()).hexdigest()[:12]


def has_key() -> bool:
    return bool(os.environ.get(AUTH_KEY_ENV) or _dotenv_get(AUTH_KEY_ENV)) or KEY_FILE.exists()


def _throttle() -> None:
    dt = time.time() - _LAST_CALL[0]
    if dt < MIN_INTERVAL_S:
        time.sleep(MIN_INTERVAL_S - dt)
    _LAST_CALL[0] = time.time()


def _safe_url(url: str) -> str:
    """Strip the Auth-Key from a URL before it can reach a log or error message.
    URLhaus carries the key in the path, so this is not cosmetic."""
    try:
        key = load_auth_key()
    except AuthKeyMissing:
        return url
    return url.replace(key, "<KEY>")


def _http(url: str, *, data: bytes | None = None, headers: dict | None = None,
          cache: bool = True) -> bytes:
    cache_key = hashlib.sha256(f"{url}|{data!r}".encode()).hexdigest()[:24]
    cache_path = CACHE_DIR / f"{cache_key}.bin"
    if cache and cache_path.exists():
        return cache_path.read_bytes()

    _throttle()
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            payload = resp.read()
    except urllib.error.HTTPError as exc:  # surface the status, not the key
        raise AbuseChError(f"HTTP {exc.code} from {_safe_url(url).split('?')[0]}") from exc
    except urllib.error.URLError as exc:
        raise AbuseChError(
            f"network error for {_safe_url(url).split('?')[0]}: {exc.reason}") from exc

    if cache:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(payload)
    return payload


def _json(raw: bytes, field: str = "data"):
    obj = json.loads(raw.decode("utf-8", "ignore"))
    status = obj.get("query_status")
    if status not in (None, "ok"):
        empty = {"no_results", "hash_not_found", "tag_not_found", "no_results_found"}
        if status in empty:
            return []
        raise AbuseChError(f"abuse.ch query_status={status}")
    return obj.get(field, obj)


# --- MalwareBazaar ---------------------------------------------------------
def malwarebazaar_recent(selector: str = "100", key: str | None = None) -> list[dict]:
    """Most recent additions. selector is 'time' (past 60 min) or '100' - the API
    rejects anything else with unknown_selector."""
    key = key or load_auth_key()
    body = urllib.parse.urlencode({"query": "get_recent", "selector": selector}).encode()
    return _json(_http(MB_API, data=body, headers={"Auth-Key": key}))


def malwarebazaar_filetype(file_type: str, limit: int = 100,
                           key: str | None = None) -> list[dict]:
    """Recent samples of a given file type (limit <= 1000). Used to widen the
    hash index beyond the 100 fixed recent additions."""
    key = key or load_auth_key()
    body = urllib.parse.urlencode(
        {"query": "get_file_type", "file_type": file_type, "limit": max(1, min(1000, limit))}).encode()
    return _json(_http(MB_API, data=body, headers={"Auth-Key": key}))


def malwarebazaar_info(sha256: str, key: str | None = None) -> dict | None:
    key = key or load_auth_key()
    body = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
    data = _json(_http(MB_API, data=body, headers={"Auth-Key": key}))
    return data[0] if isinstance(data, list) and data else None


# --- ThreatFox -------------------------------------------------------------
def threatfox_iocs(days: int = 7, key: str | None = None) -> list[dict]:
    """Current IOC dataset, filtered by first_seen. days must be 1..7."""
    days = max(1, min(7, int(days)))
    key = key or load_auth_key()
    body = json.dumps({"query": "get_iocs", "days": days}).encode()
    return _json(_http(TF_API, data=body,
                       headers={"Auth-Key": key, "Content-Type": "application/json"}))


# --- URLhaus ---------------------------------------------------------------
def urlhaus_recent_csv(key: str | None = None) -> str:
    """Recent malware-URL CSV.

    Prefers the keyed v2 export when an Auth-Key is available, otherwise falls
    back to the public dump, which needs no key. Rows are '#'-commented in the
    public dump, so consumers must skip comments (see build_index.normalize_urlhaus).
    """
    if key or has_key():
        return _http(URLHAUS_EXPORT.format(key=key or load_auth_key())).decode("utf-8", "ignore")
    return _http(URLHAUS_PUBLIC_CSV).decode("utf-8", "ignore")


def smoke() -> dict:
    """One small page from each feed. URLhaus works without a key; MalwareBazaar
    and ThreatFox report an error string when no Auth-Key is configured."""
    checks = {
        "auth_key_id": auth_key_id() if has_key() else None,
        "malwarebazaar_recent": lambda: len(malwarebazaar_recent("100")),
        "threatfox_iocs": lambda: len(threatfox_iocs(1)),
        "urlhaus_csv_lines": lambda: len([l for l in urlhaus_recent_csv().splitlines() if l.strip()]),
    }
    out: dict = {}
    for name, check in checks.items():
        if not callable(check):
            out[name] = check
            continue
        try:
            out[name] = check()
        except (AbuseChError, AuthKeyMissing) as exc:
            out[name] = f"error: {exc}"
    return out


def main() -> None:
    import argparse

    p = argparse.ArgumentParser(description="abuse.ch client smoke test")
    p.add_argument("--smoke", action="store_true", help="fetch one page from each feed")
    a = p.parse_args()
    if not a.smoke:
        p.print_help()
        return
    print(json.dumps(smoke(), indent=2))


if __name__ == "__main__":
    main()
