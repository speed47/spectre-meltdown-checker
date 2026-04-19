#!/usr/bin/env python3
"""Merge Claude's classifications.json into state/seen.json.

Inputs:
    state/seen.json          (already has updated .sources from fetch_and_diff)
    classifications.json     (written by the Claude step; list of records)
    new_items.json           (fallback source of per-item metadata, if Claude
                              omitted urls/sources in a record)

Each classification record has shape:
    {
      "stable_id":      "...",           # required (the key used in new_items.json)
      "canonical_id":   "...",           # optional; defaults to first extracted_cves, else stable_id
      "bucket":         "toimplement|tocheck|unrelated",
      "extracted_cves": ["...", ...],    # optional
      "sources":        ["...", ...],    # optional
      "urls":           ["...", ...]     # optional
    }

Behavior:
    - Upsert seen[canonical_id], union sources/urls, promote bucket strength.
    - For every alt_id in (stable_id, vendor_ids, extracted_cves) that differs
      from canonical_id, set aliases[alt_id] = canonical_id.
    - Update last_run to SCAN_DATE.
    - Prune entries older than RETENTION_DAYS (180) before writing.
    - Also writes the three daily watch_*.md files as stubs if Claude didn't run
      (i.e. when new_items.json was empty and the classify step was skipped).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import sys
from typing import Any

from . import state


RETENTION_DAYS = 180
NEW_ITEMS_PATH = pathlib.Path("new_items.json")
CLASSIFICATIONS_PATH = pathlib.Path("classifications.json")


def _load_json(path: pathlib.Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text())


def _canonical(record: dict[str, Any], fallback_meta: dict[str, Any] | None) -> str:
    if record.get("canonical_id"):
        return record["canonical_id"]
    cves = record.get("extracted_cves") or (fallback_meta or {}).get("extracted_cves") or []
    if cves:
        return cves[0]
    return record["stable_id"]


def _alt_ids(record: dict[str, Any], fallback_meta: dict[str, Any] | None) -> list[str]:
    ids: list[str] = []
    ids.append(record.get("stable_id", ""))
    ids.extend(record.get("extracted_cves") or [])
    if fallback_meta:
        ids.extend(fallback_meta.get("extracted_cves") or [])
        ids.extend(fallback_meta.get("vendor_ids") or [])
        guid = fallback_meta.get("guid")
        if guid:
            ids.append(guid)
        link = fallback_meta.get("permalink")
        if link:
            ids.append(link)
    return [i for i in ids if i]


def _unique(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def merge(
    data: dict[str, Any],
    classifications: list[dict[str, Any]],
    new_items_by_stable_id: dict[str, dict[str, Any]],
    scan_date: str,
) -> None:
    for rec in classifications:
        stable_id = rec.get("stable_id")
        if not stable_id:
            continue
        meta = new_items_by_stable_id.get(stable_id, {})
        canonical = _canonical(rec, meta)
        bucket = rec.get("bucket", "unrelated")

        title = (meta.get("title") or "").strip()

        existing = data["seen"].get(canonical)
        if existing is None:
            data["seen"][canonical] = {
                "bucket": bucket,
                "first_seen": scan_date,
                "seen_at": scan_date,
                "title": title,
                "sources": _unique(list(rec.get("sources") or []) + ([meta.get("source")] if meta.get("source") else [])),
                "urls":    _unique(list(rec.get("urls") or []) + ([meta.get("permalink")] if meta.get("permalink") else [])),
            }
        else:
            existing["bucket"] = state.promote_bucket(existing["bucket"], bucket)
            existing["seen_at"] = scan_date
            existing.setdefault("first_seen", existing.get("seen_at") or scan_date)
            if not existing.get("title") and title:
                existing["title"] = title
            existing["sources"] = _unique(list(existing.get("sources") or []) + list(rec.get("sources") or []) + ([meta.get("source")] if meta.get("source") else []))
            existing["urls"] = _unique(list(existing.get("urls") or []) + list(rec.get("urls") or []) + ([meta.get("permalink")] if meta.get("permalink") else []))

        # Aliases: every alt id that is not the canonical key points at it.
        for alt in _alt_ids(rec, meta):
            if alt != canonical:
                data["aliases"][alt] = canonical


def ensure_stub_reports(scan_date: str) -> None:
    """If the Claude step was skipped, write empty stub watch_*.md files so the
    report artifact is consistent across runs."""
    day = scan_date[:10]  # YYYY-MM-DD
    stub = "(no new items in this window)\n"
    for bucket in ("toimplement", "tocheck", "unrelated"):
        p = pathlib.Path(f"watch_{day}_{bucket}.md")
        if not p.exists():
            p.write_text(stub)


def write_snapshots(data: dict[str, Any], scan_date: str) -> None:
    """Write current_toimplement.md and current_tocheck.md — full backlog
    snapshots reflecting every entry in state under those buckets. A human
    who reads only the latest run's artifact sees the complete picture
    without having to consult prior runs."""
    for bucket in ("toimplement", "tocheck"):
        entries = [
            (cid, rec) for cid, rec in data["seen"].items()
            if rec.get("bucket") == bucket
        ]
        # Oldest first — long-lingering items stay at the top as a reminder.
        entries.sort(key=lambda kv: kv[1].get("first_seen") or kv[1].get("seen_at") or "")
        out = [
            f"# Current `{bucket}` backlog",
            "",
            f"_Snapshot as of {scan_date}. "
            f"{len(entries)} item(s). Oldest first._",
            "",
        ]
        if not entries:
            out.append("(backlog is empty)")
        else:
            for cid, rec in entries:
                title = rec.get("title") or ""
                first_seen = (rec.get("first_seen") or rec.get("seen_at") or "")[:10]
                sources = ", ".join(rec.get("sources") or []) or "(none)"
                out.append(f"- **{cid}**" + (f" — {title}" if title else ""))
                out.append(f"  first seen {first_seen} · sources: {sources}")
                for u in rec.get("urls") or []:
                    out.append(f"  - {u}")
                out.append("")
        pathlib.Path(f"current_{bucket}.md").write_text("\n".join(out))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-date", default=os.environ.get("SCAN_DATE", ""))
    ap.add_argument("--classifications", type=pathlib.Path, default=CLASSIFICATIONS_PATH)
    ap.add_argument("--new-items", type=pathlib.Path, default=NEW_ITEMS_PATH)
    args = ap.parse_args()

    scan_date = args.scan_date or datetime.datetime.now(datetime.timezone.utc).isoformat()

    data = state.load()
    classifications = _load_json(args.classifications, [])
    new_items_doc = _load_json(args.new_items, {"items": []})
    new_items_by_stable_id = {it["stable_id"]: it for it in new_items_doc.get("items", []) if it.get("stable_id")}

    if not isinstance(classifications, list):
        print(f"warning: {args.classifications} is not a list; ignoring", file=sys.stderr)
        classifications = []

    merge(data, classifications, new_items_by_stable_id, scan_date)
    data["last_run"] = scan_date

    scan_now = datetime.datetime.fromisoformat(scan_date.replace("Z", "+00:00"))
    before, after = state.prune(data, RETENTION_DAYS, scan_now)
    state.save(data)
    ensure_stub_reports(scan_date)
    write_snapshots(data, scan_date)

    print(f"Merged {len(classifications)} classifications.")
    print(f"Pruned seen: {before} -> {after} entries (retention={RETENTION_DAYS}d).")
    print(f"Aliases: {len(data['aliases'])}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
