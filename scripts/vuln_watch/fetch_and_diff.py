#!/usr/bin/env python3
"""Fetch all configured sources, dedup against state/seen.json, emit new_items.json.

Writes updated per-source HTTP cache metadata (etag, last_modified, hwm_*) back
into state/seen.json. Does NOT touch state.seen / state.aliases — that is the
merge step's job, after Claude has classified the new items.

Usage:
    SCAN_DATE=2026-04-18T14:24:43Z python -m scripts.vuln_watch.fetch_and_diff
"""
from __future__ import annotations

import argparse
import datetime
import gzip
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable

import feedparser  # type: ignore[import-untyped]

from .sources import REQUEST_TIMEOUT, SOURCES, Source, USER_AGENT
from . import state


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
DEFAULT_WINDOW_HOURS = 25
DEFAULT_RECONSIDER_AGE_DAYS = 7
MAX_ITEMS_PER_FEED = 200
SNIPPET_MAX = 400
NEW_ITEMS_PATH = pathlib.Path("new_items.json")


def parse_iso(ts: str | None) -> datetime.datetime | None:
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def now_from_scan_date(scan_date: str) -> datetime.datetime:
    dt = parse_iso(scan_date)
    if dt is None:
        dt = datetime.datetime.now(datetime.timezone.utc)
    return dt


def conditional_get(
    url: str,
    etag: str | None,
    last_modified: str | None,
    user_agent: str = USER_AGENT,
) -> tuple[int | str, bytes | None, str | None, str | None]:
    """Perform a conditional GET.

    Returns (status, body, new_etag, new_last_modified).

    status is:
      - 200 with body on success
      - 304 with body=None when unchanged
      - an int HTTP error code on server-side errors
      - a string describing a network/transport failure
    """
    req = urllib.request.Request(url, headers={
        "User-Agent": user_agent,
        # AMD's CDN stalls on non-gzip clients; asking for gzip speeds up
        # every source and is strictly beneficial (we decompress locally).
        "Accept-Encoding": "gzip",
    })
    if etag:
        req.add_header("If-None-Match", etag)
    if last_modified:
        req.add_header("If-Modified-Since", last_modified)
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            body = resp.read()
            if resp.headers.get("Content-Encoding", "").lower() == "gzip":
                try:
                    body = gzip.decompress(body)
                except OSError:
                    pass  # server lied about encoding; use as-is
            return (
                resp.status,
                body,
                resp.headers.get("ETag"),
                resp.headers.get("Last-Modified"),
            )
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return (304, None, etag, last_modified)
        return (e.code, None, etag, last_modified)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return (f"network:{type(e).__name__}", None, etag, last_modified)


def extract_cves(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in CVE_RE.findall(text or ""):
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


def extract_vendor_ids(text: str, patterns: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for p in patterns:
        for m in re.findall(p, text or ""):
            if m not in seen:
                seen.add(m)
                out.append(m)
    return out


def pick_stable_id(vendor_ids: list[str], cves: list[str], guid: str, link: str) -> str:
    """Pick canonical-ish stable ID: vendor advisory → CVE → guid → permalink.

    CVE is preferred over guid/URL so that the same CVE seen via different
    feeds collapses on its stable_id alone (in addition to the alias map).
    """
    if vendor_ids:
        return vendor_ids[0]
    if cves:
        return cves[0]
    if guid:
        return guid
    return link


def clean_snippet(s: str) -> str:
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def _struct_time_to_iso(st: Any) -> str | None:
    if not st:
        return None
    try:
        return datetime.datetime(*st[:6], tzinfo=datetime.timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None


def parse_feed_body(src: Source, body: bytes) -> list[dict[str, Any]]:
    parsed = feedparser.parse(body)
    items: list[dict[str, Any]] = []
    for entry in parsed.entries[:MAX_ITEMS_PER_FEED]:
        link = (entry.get("link") or "").strip()
        guid = (entry.get("id") or entry.get("guid") or "").strip()
        title = (entry.get("title") or "").strip()
        summary = entry.get("summary") or ""
        published_at = (
            _struct_time_to_iso(entry.get("published_parsed"))
            or _struct_time_to_iso(entry.get("updated_parsed"))
        )
        blob = f"{title}\n{summary}"
        cves = extract_cves(blob)
        vendor_ids = extract_vendor_ids(blob, src.advisory_id_patterns)
        stable_id = pick_stable_id(vendor_ids, cves, guid, link)
        items.append({
            "source": src.name,
            "stable_id": stable_id,
            "title": title,
            "permalink": link,
            "guid": guid,
            "published_at": published_at,
            "extracted_cves": cves,
            "vendor_ids": vendor_ids,
            "snippet": clean_snippet(summary)[:SNIPPET_MAX],
        })
    return items


def _parse_intel_psirt(src: Source, text: str) -> list[dict[str, Any]]:
    """Intel's security-center page uses a table of <tr class="data"> rows:

        <tr class="data" ...>
          <td ...><a href="/.../intel-sa-NNNNN.html">Title</a></td>
          <td>INTEL-SA-NNNNN</td>
          <td>March 10, 2026</td>    <- Last updated
          <td>March 10, 2026</td>    <- First published
        </tr>

    We pick the later of the two dates as `published_at` (most recent
    activity) so updates to older advisories also show up in the window.
    """
    items: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    permalink_base = src.display_url or src.url
    for m in re.finditer(r'<tr class="data"[^>]*>(.*?)</tr>', text, re.DOTALL):
        row = m.group(1)
        sid = re.search(r'INTEL-SA-\d+', row)
        if not sid:
            continue
        advisory_id = sid.group(0)
        if advisory_id in seen_ids:
            continue
        seen_ids.add(advisory_id)
        link_m = re.search(r'href="([^"#]+)"', row)
        permalink = urllib.parse.urljoin(permalink_base, link_m.group(1)) if link_m else permalink_base
        title_m = re.search(r'<a[^>]*>([^<]+)</a>', row)
        title = title_m.group(1).strip() if title_m else advisory_id
        published_at: str | None = None
        for ds in re.findall(r'<td[^>]*>\s*([A-Z][a-z]+ \d{1,2}, \d{4})\s*</td>', row):
            try:
                dt = datetime.datetime.strptime(ds, "%B %d, %Y").replace(tzinfo=datetime.timezone.utc)
                iso = dt.isoformat()
                if published_at is None or iso > published_at:
                    published_at = iso
            except ValueError:
                continue
        items.append({
            "source": src.name,
            "stable_id": advisory_id,
            "title": title,
            "permalink": permalink,
            "guid": "",
            "published_at": published_at,
            "extracted_cves": extract_cves(row),
            "vendor_ids": [advisory_id],
            "snippet": clean_snippet(row)[:SNIPPET_MAX],
        })
    return items[:MAX_ITEMS_PER_FEED]


def _parse_amd_psirt(src: Source, text: str) -> list[dict[str, Any]]:
    """AMD's product-security page has a bulletin table where each row ends
    with two `<td data-sort="YYYY-MM-DD HHMMSS">` cells (Published Date,
    Last Updated Date). The machine-readable `data-sort` attribute is far
    easier to parse than the human-readable text alongside it.
    """
    items: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    permalink_base = src.display_url or src.url
    for m in re.finditer(r'<tr[^>]*>(.*?AMD-SB-\d+.*?)</tr>', text, re.DOTALL):
        row = m.group(1)
        sid = re.search(r'AMD-SB-\d+', row)
        if not sid:
            continue
        advisory_id = sid.group(0)
        if advisory_id in seen_ids:
            continue
        seen_ids.add(advisory_id)
        link_m = re.search(r'href="([^"#]+)"', row)
        permalink = urllib.parse.urljoin(permalink_base, link_m.group(1)) if link_m else permalink_base
        title_m = re.search(r'<a[^>]*>([^<]+)</a>', row)
        title = title_m.group(1).strip() if title_m else advisory_id
        published_at: str | None = None
        for (y, mo, d, h, mi, s) in re.findall(
            r'data-sort="(\d{4})-(\d{2})-(\d{2})\s+(\d{2})(\d{2})(\d{2})"', row
        ):
            iso = f"{y}-{mo}-{d}T{h}:{mi}:{s}+00:00"
            if published_at is None or iso > published_at:
                published_at = iso
        items.append({
            "source": src.name,
            "stable_id": advisory_id,
            "title": title,
            "permalink": permalink,
            "guid": "",
            "published_at": published_at,
            "extracted_cves": extract_cves(row),
            "vendor_ids": [advisory_id],
            "snippet": clean_snippet(row)[:SNIPPET_MAX],
        })
    return items[:MAX_ITEMS_PER_FEED]


def _parse_html_generic(src: Source, text: str) -> list[dict[str, Any]]:
    """Fallback regex-only extractor for HTML sources with no known table
    layout (arm-spec, transient-fail's tree.js). Emits `published_at=None`
    — items pass the window filter as fail-safe, but state.seen dedup
    prevents re-emission across runs."""
    items: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    permalink_base = src.display_url or src.url
    for pat in src.advisory_id_patterns:
        for m in re.finditer(pat, text):
            advisory_id = m.group(0)
            if advisory_id in seen_ids:
                continue
            seen_ids.add(advisory_id)
            window = text[max(0, m.start() - 400): m.end() + 400]
            href_match = re.search(r'href="([^"#]+)"', window)
            if href_match:
                permalink = urllib.parse.urljoin(permalink_base, href_match.group(1))
            else:
                permalink = permalink_base
            cves_in_window = extract_cves(window)
            is_cve = advisory_id.startswith("CVE-")
            cves = cves_in_window if not is_cve else list({advisory_id, *cves_in_window})
            vendor_ids = [] if is_cve else [advisory_id]
            items.append({
                "source": src.name,
                "stable_id": advisory_id,
                "title": advisory_id,
                "permalink": permalink,
                "guid": "",
                "published_at": None,
                "extracted_cves": cves,
                "vendor_ids": vendor_ids,
                "snippet": clean_snippet(window)[:SNIPPET_MAX],
            })
    return items[:MAX_ITEMS_PER_FEED]


_HTML_PARSERS = {
    "intel-psirt": _parse_intel_psirt,
    "amd-psirt":   _parse_amd_psirt,
}


def parse_html_body(src: Source, body: bytes) -> list[dict[str, Any]]:
    """Dispatch to a per-source HTML parser when one is registered;
    fall back to the generic regex-over-advisory-IDs extractor."""
    text = body.decode("utf-8", errors="replace")
    parser = _HTML_PARSERS.get(src.name, _parse_html_generic)
    return parser(src, text)


def parse_body(src: Source, body: bytes) -> list[dict[str, Any]]:
    return parse_feed_body(src, body) if src.kind in ("rss", "atom") else parse_html_body(src, body)


def compute_cutoff(
    scan_now: datetime.datetime,
    last_run: str | None,
    window_hours: float = DEFAULT_WINDOW_HOURS,
) -> datetime.datetime:
    base = scan_now - datetime.timedelta(hours=window_hours)
    lr = parse_iso(last_run)
    if lr is None:
        return base
    widened = scan_now - (scan_now - lr + datetime.timedelta(hours=1))
    return min(base, widened)


def _resolve_window_hours() -> float:
    """Pick up WINDOW_HOURS from the environment (set by workflow_dispatch).
    Falls back to DEFAULT_WINDOW_HOURS for cron runs or local invocations."""
    raw = os.environ.get("WINDOW_HOURS", "").strip()
    if not raw:
        return float(DEFAULT_WINDOW_HOURS)
    try:
        v = float(raw)
        if v <= 0:
            raise ValueError("must be > 0")
        return v
    except ValueError:
        print(f"warning: ignoring invalid WINDOW_HOURS={raw!r}, using {DEFAULT_WINDOW_HOURS}",
              file=sys.stderr)
        return float(DEFAULT_WINDOW_HOURS)


def _resolve_reconsider_age_days() -> float:
    """Pick up RECONSIDER_AGE_DAYS from the environment. Entries whose last
    review (reconsidered_at, or first_seen if never reconsidered) is more
    recent than this many days ago are skipped. 0 = reconsider everything
    every run (no throttle)."""
    raw = os.environ.get("RECONSIDER_AGE_DAYS", "").strip()
    if not raw:
        return float(DEFAULT_RECONSIDER_AGE_DAYS)
    try:
        v = float(raw)
        if v < 0:
            raise ValueError("must be >= 0")
        return v
    except ValueError:
        print(f"warning: ignoring invalid RECONSIDER_AGE_DAYS={raw!r}, "
              f"using {DEFAULT_RECONSIDER_AGE_DAYS}", file=sys.stderr)
        return float(DEFAULT_RECONSIDER_AGE_DAYS)


def backlog_to_reconsider(
    data: dict[str, Any],
    scan_now: datetime.datetime,
    min_age_days: float = DEFAULT_RECONSIDER_AGE_DAYS,
) -> list[dict[str, Any]]:
    """Walk state.seen and emit toimplement/tocheck entries for re-review.

    Throttle: skip entries whose "last review" timestamp is more recent
    than `min_age_days` ago. "Last review" is `reconsidered_at` if Claude
    has already reconsidered the entry at least once, otherwise
    `first_seen` (the initial classification was itself a review). With
    `min_age_days=0` the throttle is disabled — every qualifying entry
    is emitted on every run.

    Items in `unrelated` are never emitted — those are settled.
    A CVE alias pointing at this canonical is included in `extracted_cves`
    so Claude sees every known CVE for the item without having to consult
    the full alias map.
    """
    seen = data.get("seen", {})
    aliases = data.get("aliases", {})
    by_canonical: dict[str, list[str]] = {}
    for alt, canon in aliases.items():
        by_canonical.setdefault(canon, []).append(alt)

    # Any entry whose last review is newer than this ISO cutoff is throttled.
    cutoff = (scan_now - datetime.timedelta(days=min_age_days)).isoformat()

    out: list[dict[str, Any]] = []
    for canonical, rec in seen.items():
        if rec.get("bucket") not in ("toimplement", "tocheck"):
            continue
        last_reviewed = rec.get("reconsidered_at") or rec.get("first_seen") or ""
        if min_age_days > 0 and last_reviewed and last_reviewed > cutoff:
            continue
        cves: list[str] = []
        if canonical.startswith("CVE-"):
            cves.append(canonical)
        for alt in by_canonical.get(canonical, []):
            if alt.startswith("CVE-") and alt not in cves:
                cves.append(alt)
        out.append({
            "canonical_id":   canonical,
            "current_bucket": rec.get("bucket"),
            "title":          rec.get("title") or "",
            "sources":        list(rec.get("sources") or []),
            "urls":           list(rec.get("urls") or []),
            "extracted_cves": cves,
            "first_seen":     rec.get("first_seen"),
            "reconsidered_at": rec.get("reconsidered_at"),
        })
    return out


def candidate_ids(item: dict[str, Any]) -> list[str]:
    """All identifiers under which this item might already be known."""
    seen: set[str] = set()
    out: list[str] = []
    for cand in (
        *(item.get("extracted_cves") or []),
        *(item.get("vendor_ids") or []),
        item.get("stable_id"),
        item.get("guid"),
        item.get("permalink"),
    ):
        if cand and cand not in seen:
            seen.add(cand)
            out.append(cand)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-date", default=os.environ.get("SCAN_DATE", ""))
    ap.add_argument("--output", type=pathlib.Path, default=NEW_ITEMS_PATH)
    args = ap.parse_args()

    scan_now = now_from_scan_date(args.scan_date)
    scan_date_iso = scan_now.isoformat()
    window_hours = _resolve_window_hours()
    reconsider_age_days = _resolve_reconsider_age_days()
    data = state.load()
    cutoff = compute_cutoff(scan_now, data.get("last_run"), window_hours)

    per_source: dict[str, dict[str, Any]] = {}
    all_new: list[dict[str, Any]] = []

    for src in SOURCES:
        meta = dict(data["sources"].get(src.name, {}))
        status, body, etag, last_modified = conditional_get(
            src.url, meta.get("etag"), meta.get("last_modified"),
            user_agent=src.user_agent or USER_AGENT,
        )
        meta["last_fetched_at"] = scan_date_iso
        meta["last_status"] = status

        if isinstance(status, str) or (isinstance(status, int) and status >= 400 and status != 304):
            per_source[src.name] = {"status": status, "new": 0}
            data["sources"][src.name] = meta
            continue

        if status == 304 or body is None:
            per_source[src.name] = {"status": 304, "new": 0}
            data["sources"][src.name] = meta
            continue

        # Refresh cache headers only on successful 200.
        if etag:
            meta["etag"] = etag
        if last_modified:
            meta["last_modified"] = last_modified

        items = parse_body(src, body)
        total = len(items)

        in_window = []
        for it in items:
            pub = parse_iso(it.get("published_at"))
            if pub is None or pub >= cutoff:
                in_window.append(it)

        new: list[dict[str, Any]] = []
        hwm_pub = meta.get("hwm_published_at")
        hwm_id = meta.get("hwm_id")
        for it in in_window:
            if state.lookup(data, candidate_ids(it)) is not None:
                continue
            new.append(it)
            pub = it.get("published_at")
            if pub and (not hwm_pub or pub > hwm_pub):
                hwm_pub = pub
                hwm_id = it.get("stable_id")

        if new:
            meta["hwm_published_at"] = hwm_pub
            meta["hwm_id"] = hwm_id

        data["sources"][src.name] = meta
        per_source[src.name] = {"status": status, "new": len(new), "total_in_feed": total}
        all_new.extend(new)

    # Persist updated HTTP cache metadata regardless of whether Claude runs.
    state.save(data)

    reconsider = backlog_to_reconsider(data, scan_now, reconsider_age_days)

    out = {
        "scan_date": scan_date_iso,
        "window_cutoff": cutoff.isoformat(),
        "per_source": per_source,
        "items": all_new,
        "reconsider": reconsider,
    }
    args.output.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")

    # GitHub Actions step outputs. Downstream `if:` conditions gate the
    # classify step on `new_count || reconsider_count`; both must be 0
    # for Claude to be skipped.
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as f:
            f.write(f"new_count={len(all_new)}\n")
            f.write(f"reconsider_count={len(reconsider)}\n")
            failures = [
                s for s, v in per_source.items()
                if not (isinstance(v["status"], int) and v["status"] in (200, 304))
            ]
            f.write(f"fetch_failures_count={len(failures)}\n")

    print(f"Scan date:    {scan_date_iso}")
    print(f"Window:       {window_hours:g} h")
    print(f"Cutoff:       {cutoff.isoformat()}")
    print(f"New items:    {len(all_new)}")
    if reconsider_age_days == 0:
        print(f"Reconsider:   {len(reconsider)} (throttle disabled)")
    else:
        print(f"Reconsider:   {len(reconsider)} (throttle: "
              f"skip entries reviewed <{reconsider_age_days:g}d ago)")
    for s, v in per_source.items():
        print(f"  {s:14s} status={str(v['status']):>16} new={v['new']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
