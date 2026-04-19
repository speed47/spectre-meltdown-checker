"""Load/save/migrate/lookup helpers for state/seen.json.

Schema v2:
    {
      "schema_version": 2,
      "last_run": "<iso8601>|null",
      "sources": {
        "<name>": {
          "etag": "...",
          "last_modified": "...",
          "hwm_id": "...",
          "hwm_published_at": "<iso8601>",
          "last_fetched_at": "<iso8601>",
          "last_status": 200|304|<http-err>|"<str-err>"
        }
      },
      "seen": {
        "<canonical_id>": {
          "bucket": "toimplement|tocheck|unrelated",
          "seen_at": "<iso8601>",
          "sources": ["<source-name>", ...],
          "urls":    ["<permalink>", ...]
        }
      },
      "aliases": { "<alt_id>": "<canonical_id>" }
    }
"""
from __future__ import annotations

import datetime
import json
import pathlib
from typing import Any


STATE_PATH = pathlib.Path("state/seen.json")
SCHEMA_VERSION = 2


def empty() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "last_run": None,
        "sources": {},
        "seen": {},
        "aliases": {},
    }


def load(path: pathlib.Path = STATE_PATH) -> dict[str, Any]:
    if not path.exists():
        return empty()
    data = json.loads(path.read_text())
    return _migrate(data)


def save(data: dict[str, Any], path: pathlib.Path = STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def _migrate(data: dict[str, Any]) -> dict[str, Any]:
    """Bring any older schema up to SCHEMA_VERSION."""
    version = data.get("schema_version")
    if version == SCHEMA_VERSION:
        data.setdefault("sources", {})
        data.setdefault("aliases", {})
        data.setdefault("seen", {})
        return data

    # v1 shape: {"last_run": ..., "seen": {<id>: {bucket, seen_at, source, cve?}}}
    migrated_seen: dict[str, Any] = {}
    aliases: dict[str, str] = {}
    for key, entry in (data.get("seen") or {}).items():
        rec = {
            "bucket":  entry.get("bucket", "unrelated"),
            "seen_at": entry.get("seen_at"),
            "sources": [entry["source"]] if entry.get("source") else [],
            "urls":    [key] if isinstance(key, str) and key.startswith("http") else [],
        }
        migrated_seen[key] = rec
        # If a v1 entry had a CVE that differs from the key, alias the CVE -> key.
        cve = entry.get("cve")
        if cve and cve != key:
            aliases[cve] = key

    return {
        "schema_version": SCHEMA_VERSION,
        "last_run": data.get("last_run"),
        "sources": {},
        "seen": migrated_seen,
        "aliases": aliases,
    }


def lookup(data: dict[str, Any], candidate_ids: list[str]) -> str | None:
    """Return the canonical key if any candidate is already known, else None."""
    seen = data["seen"]
    aliases = data["aliases"]
    for cid in candidate_ids:
        if not cid:
            continue
        if cid in seen:
            return cid
        canonical = aliases.get(cid)
        if canonical and canonical in seen:
            return canonical
    return None


_BUCKET_STRENGTH = {"unrelated": 0, "tocheck": 1, "toimplement": 2}


def promote_bucket(current: str, incoming: str) -> str:
    """Return whichever of two buckets represents the 'stronger' classification."""
    return incoming if _BUCKET_STRENGTH.get(incoming, 0) > _BUCKET_STRENGTH.get(current, 0) else current


def prune(data: dict[str, Any], days: int, now: datetime.datetime) -> tuple[int, int]:
    """Drop seen entries older than `days`, and aliases pointing at dropped keys."""
    cutoff = (now - datetime.timedelta(days=days)).isoformat()
    before = len(data["seen"])
    data["seen"] = {
        k: v for k, v in data["seen"].items()
        if (v.get("seen_at") or "9999") >= cutoff
    }
    data["aliases"] = {k: v for k, v in data["aliases"].items() if v in data["seen"]}
    return before, len(data["seen"])
