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
      "urls":           ["...", ...],    # optional
      "reconsider":     true             # optional; set by Claude for reconsidered
                                         #   backlog entries — merge overwrites
                                         #   the stored bucket (incl. demotions)
                                         #   instead of promoting
    }

Behavior:
    - For records WITHOUT `reconsider: true` (fresh items):
      upsert seen[canonical_id], union sources/urls, promote bucket strength.
    - For records WITH `reconsider: true` (previously-classified entries):
      overwrite the stored bucket unconditionally (permits demotions), union
      sources/urls. If Claude's canonical_id differs from the stable_id (the
      previous canonical), rekey the seen entry under the new ID and leave
      the old as an alias — used when a CVE has since been assigned to what
      was previously a bare vendor-ID entry.
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
        if not rec.get("stable_id"):
            continue
        if rec.get("reconsider"):
            _apply_reconsider(data, rec, scan_date)
        else:
            _apply_new_item(data, rec, new_items_by_stable_id, scan_date)


def _apply_new_item(
    data: dict[str, Any],
    rec: dict[str, Any],
    new_items_by_stable_id: dict[str, dict[str, Any]],
    scan_date: str,
) -> None:
    stable_id = rec["stable_id"]
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

    for alt in _alt_ids(rec, meta):
        if alt != canonical:
            data["aliases"][alt] = canonical


def _apply_reconsider(
    data: dict[str, Any],
    rec: dict[str, Any],
    scan_date: str,
) -> None:
    """Re-review of a previously-classified entry. The record's stable_id
    is the entry's current canonical key in state; `canonical_id` may name
    a new key (e.g. a freshly-assigned CVE) — in which case we rekey."""
    old_key = rec["stable_id"]
    new_canonical = _canonical(rec, None)
    bucket = rec.get("bucket", "unrelated")

    # Resolve the current record — may need to follow an alias if the
    # backlog snapshot the classifier reviewed is slightly out of sync.
    current_key = old_key if old_key in data["seen"] else data["aliases"].get(old_key)
    if not current_key or current_key not in data["seen"]:
        print(f"warning: reconsider record for {old_key!r} points at no "
              f"state entry; skipping.", file=sys.stderr)
        return

    existing = data["seen"][current_key]

    # Overwrite bucket unconditionally (allows demotions) and stamp the
    # reconsideration date so we can later throttle if this grows.
    existing["bucket"] = bucket
    existing["seen_at"] = scan_date
    existing["reconsidered_at"] = scan_date

    # Union any fresh sources/urls the classifier surfaced.
    if rec.get("sources"):
        existing["sources"] = _unique(list(existing.get("sources") or []) + list(rec["sources"]))
    if rec.get("urls"):
        existing["urls"] = _unique(list(existing.get("urls") or []) + list(rec["urls"]))

    # Alias every alt ID the classifier provided to the current key
    # (before a possible rekey below redirects them).
    for alt in _alt_ids(rec, None):
        if alt != current_key:
            data["aliases"][alt] = current_key

    # Rekey if Claude newly identified a canonical ID (e.g., a CVE for a
    # vendor-ID entry). If the destination already exists, merge; else
    # move. In both cases, retarget all aliases and leave the old key
    # itself as an alias.
    if new_canonical and new_canonical != current_key:
        if new_canonical in data["seen"]:
            dest = data["seen"][new_canonical]
            dest["bucket"] = state.promote_bucket(dest.get("bucket", "unrelated"), existing.get("bucket", "unrelated"))
            dest["sources"] = _unique(list(dest.get("sources") or []) + list(existing.get("sources") or []))
            dest["urls"] = _unique(list(dest.get("urls") or []) + list(existing.get("urls") or []))
            if not dest.get("title") and existing.get("title"):
                dest["title"] = existing["title"]
            dest["seen_at"] = scan_date
            dest["reconsidered_at"] = scan_date
            dest.setdefault("first_seen", existing.get("first_seen") or scan_date)
            del data["seen"][current_key]
        else:
            data["seen"][new_canonical] = existing
            del data["seen"][current_key]

        for alias_key, target in list(data["aliases"].items()):
            if target == current_key:
                data["aliases"][alias_key] = new_canonical
        data["aliases"][current_key] = new_canonical
        # Clean up any self-aliases the retarget may have produced.
        for k in [k for k, v in data["aliases"].items() if k == v]:
            del data["aliases"][k]


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
