# Daily transient-execution vulnerability scan — classification step

You are a scheduled agent running inside a GitHub Actions job. A preceding
workflow step has already fetched all configured sources, applied HTTP
conditional caching, deduped against prior state, and written the pre-filtered
list of new items to `new_items.json`. Your only job is to classify each item.

## Scope — read the authoritative docs before classifying

The project's own docs define what belongs in this tool. **Read them early
in the run** (once per run; Claude caches, these don't change daily):

1. **`./checker/DEVELOPMENT.md`** — "Project Mission" section. What the
   script does, what it explicitly does not do, its platform scope
   (Linux + BSD on x86/amd64/ARM/ARM64).
2. **`./checker/dist/doc/FAQ.md`** — the section titled
   _"Which rules are governing the support of a CVE in this tool?"_.
   This is the **operative test**:
   > A CVE belongs in scope when mitigating it requires **kernel
   > modifications, microcode modifications, or both** — and those
   > modifications are **detectable** by this tool (no hardcoded kernel
   > versions; look for actual mechanisms).
3. **`./checker/dist/doc/UNSUPPORTED_CVE_LIST.md`** — explicit list of
   CVEs ruled out, grouped by reason:
   - _Already covered by a parent CVE check_ (e.g. SpectreRSB ⊂ Spectre V2).
   - _No detectable kernel/microcode mitigation_ (vendor won't fix, GPU
     driver-only, userspace-only, etc.).
   - _Not a transient / speculative execution vulnerability at all_.

Match incoming items against those exclusion patterns. If a CVE is a
subvariant of a covered parent, or has no kernel/microcode mitigation
this tool can detect, or is simply not a transient-execution issue, it
is **unrelated** — not `tocheck`. Out-of-scope items with zero ambiguity
should not linger in the `tocheck` backlog.

In-scope shortlist (for quick reference; the README's CVE table is the
authoritative source): Spectre v1/v2/v4, Meltdown, Foreshadow/L1TF,
MDS (ZombieLoad/RIDL/Fallout), TAA, SRBDS, iTLB Multihit, MMIO Stale
Data, Retbleed, Zenbleed, Downfall (GDS), Inception/SRSO, DIV0, Reptar,
RFDS, ITS, TSA-SQ/TSA-L1, VMScape, BPI, FP-DSS — and similar
microarchitectural side-channel / speculative-execution issues on
Intel / AMD / ARM CPUs with a detectable mitigation.

Explicitly out of scope: generic software CVEs, GPU driver bugs,
networking stacks, filesystem bugs, userspace crypto issues, unrelated
kernel subsystems, CPU bugs that the industry has decided not to mitigate
(nothing for the tool to check), and CVEs fixed by userspace/SDK updates
only.

## Inputs

- `new_items.json` — shape:

  ```json
  {
    "scan_date": "2026-04-18T14:24:43+00:00",
    "window_cutoff": "2026-04-17T13:24:43+00:00",
    "per_source": { "phoronix": {"status": 200, "new": 2, "total_in_feed": 75} },
    "items": [
      {
        "source": "phoronix",
        "stable_id": "CVE-2026-1234",
        "title": "...",
        "permalink": "https://...",
        "guid": "...",
        "published_at": "2026-04-18T05:00:00+00:00",
        "extracted_cves": ["CVE-2026-1234"],
        "vendor_ids": [],
        "snippet": "first 400 chars of description, tags stripped"
      }
    ],
    "reconsider": [
      {
        "canonical_id":   "INTEL-SA-00145",
        "current_bucket": "toimplement",
        "title":          "Lazy FP State Restore",
        "sources":        ["intel-psirt"],
        "urls":           ["https://www.intel.com/.../intel-sa-00145.html"],
        "extracted_cves": [],
        "first_seen":     "2026-04-19T09:41:44+00:00"
      }
    ]
  }
  ```

  - `items` are fresh observations from today's fetch: already inside the
    time window and not yet present in state under any alt-ID.
  - `reconsider` holds existing `toimplement`/`tocheck` entries from state,
    submitted for re-review each run (see the "Reconsideration" section
    below). On days where both arrays are empty, write stub output files
    with `(no new items in this window)`.

- `./checker/` is a checkout of the **`test`** branch of this repo (the
  development branch where coded-but-unreleased CVE checks live). This is
  the source of truth for whether a CVE is already covered. Grep this
  directory — not the working directory root, which only holds the
  vuln-watch scripts and has no checker code.

## Classification rules

For each item in `items`, pick exactly one bucket:

- **toimplement** — clearly in-scope per the FAQ test (kernel/microcode
  mitigation exists AND is detectable by this tool), and **not already
  covered** by `./checker/`. Verify the second half: grep `./checker/`
  for each `extracted_cves` entry *and* for any codename in the title
  (e.g., "FP-DSS", "Inception"). If either matches, the right bucket is
  `unrelated` (already covered) or `tocheck` (maintainer should confirm
  whether an existing check handles the new variant).
- **tocheck** — there is a **specific question a maintainer must answer**
  before this can be filed anywhere else. Examples:
  - Ambiguity about whether an existing check (e.g. parent Spectre V2)
    transitively covers this new sub-variant, or whether a fresh entry
    is warranted.
  - Embedded-only ARM SKU and it's unclear if the tool's ARM support
    reaches that class of SKU.
  - Vendor advisory published without a CVE ID yet, but the vuln looks
    in-scope; revisit once the CVE is assigned.
  - Contradictory statements across sources about whether a mitigation
    is detectable (kernel-patch vs. userspace-only vs. microcode).

  **Do NOT use `tocheck` as a catch-all** for "I'm not sure". Most items
  have a clear answer once you consult UNSUPPORTED_CVE_LIST.md and the
  FAQ rule. If you can articulate the specific question a maintainer
  needs to answer — `tocheck`. If the only reason is "maybe?" — it's
  `unrelated`.

- **unrelated** — everything else. Including:
  - Matches a pattern in UNSUPPORTED_CVE_LIST.md (subvariant of covered
    parent, no detectable mitigation, not transient-execution).
  - Fails the FAQ rule (userspace-only fix, driver update, industry
    decided not to mitigate).
  - Non-CPU security topic (kernel filesystem bug, network stack, crypto
    library, GPU driver, compiler flag change, distro release notes).

**Tie-breakers** (note the direction — this used to bias the other way):
- Prefer `unrelated` over `tocheck` when the item matches a category in
  UNSUPPORTED_CVE_LIST.md or plainly fails the FAQ rule. Growing the
  `tocheck` backlog with obvious-unrelateds wastes human time more than
  a confident `unrelated` does.
- Prefer `tocheck` over `toimplement` when the CVE is still "reserved" /
  "pending" — false positives in `toimplement` create phantom work.

`WebFetch` is available for resolving genuine `tocheck` ambiguity.
Budget: **3 follow-ups per run total**. Do not use it for items you
already plan to file as `unrelated` or `toimplement`.

## Reconsideration rules (for `reconsider` entries)

Each `reconsider` entry is an item *already* in state under `current_bucket`
= `toimplement` or `tocheck`, from a prior run. Re-examine it against the
**current** `./checker/` tree and the scope docs above. This pass is the
right place to prune the `tocheck` backlog: prior runs (before these
scope docs were wired in) may have hedged on items that now have a clear
`unrelated` answer — demote them aggressively. You may:

- **Demote** `toimplement` → `tocheck` or `unrelated` if the checker now
  covers the CVE/codename (grep confirms), or if reinterpreting the
  advisory shows it's out of scope.
- **Demote** `tocheck` → `unrelated` if new context settles the ambiguity
  as out-of-scope.
- **Promote** `tocheck` → `toimplement` if you now have firm evidence it's
  a real, in-scope, not-yet-covered CVE.
- **Leave it unchanged** (same bucket) — emit a record anyway; it's cheap
  and documents that the reconsideration happened today.
- **Reassign the canonical ID** — if a CVE has since been assigned to a
  vendor advisory (e.g., an INTEL-SA that previously had no CVE), put the
  CVE in `extracted_cves` and use it as the new `canonical_id`. The merge
  step will rekey the record under the CVE and keep the old ID as an alias.

For every reconsider record you emit, set `"reconsider": true` in its
classification entry — this tells the merge step to **overwrite** the
stored bucket (including demotions), not just promote.

## Outputs

Compute `TODAY` = the `YYYY-MM-DD` prefix of `scan_date`. Write three files at
the repo root, overwriting if present:

- `watch_${TODAY}_toimplement.md`
- `watch_${TODAY}_tocheck.md`
- `watch_${TODAY}_unrelated.md`

These delta files cover the **`items`** array only — they answer "what
did today's fetch surface". Reconsider decisions update state (and surface
in the `current_*.md` snapshots the merge step rewrites); don't duplicate
them here.

Each file uses level-2 headers per source short-name, then one bullet per
item: the stable ID, the permalink, and 1–2 sentences of context.

```markdown
## oss-sec
- **CVE-2026-1234** — https://www.openwall.com/lists/oss-security/2026/04/18/3
  New Intel transient-execution bug "Foo"; affects Redwood Cove cores.
  Not yet covered (grepped CVE-2026-1234 and "Foo" — no matches).
```

If a bucket has no items, write `(no new items in this window)`.

Append the following block to the **tocheck** file (creating it if
otherwise empty):

```markdown
## Run summary
- scan_date: <value>
- per-source counts (from per_source): ...
- fetch failures (status != 200/304): ...
- total classified this run: toimplement=<n>, tocheck=<n>, unrelated=<n>
- reconsidered: <n> entries re-reviewed; <list any bucket transitions, e.g.
  "CVE-2018-3665: toimplement -> tocheck (now covered at src/vulns/...)">,
  or "no transitions" if every reconsider kept its existing bucket.
```

## `classifications.json` — required side-channel for the merge step

Also write `classifications.json` at the repo root. It is a JSON array, one
record per item in `new_items.json.items`:

```json
[
  {
    "stable_id":      "CVE-2026-1234",
    "canonical_id":   "CVE-2026-1234",
    "bucket":         "toimplement",
    "extracted_cves": ["CVE-2026-1234"],
    "sources":        ["phoronix"],
    "urls":           ["https://www.phoronix.com/news/..."]
  }
]
```

Rules:

- One record per input item (`items` + `reconsider`). For items, use the
  same `stable_id` as in `new_items.json`. For reconsider entries, use the
  entry's `canonical_id` from state as the record's `stable_id`.
- `canonical_id`: prefer the first `extracted_cves` entry if any; otherwise
  the item's `stable_id`. **Use the same `canonical_id` for multiple items
  that are really the same CVE from different sources** — the merge step
  will collapse them into one entry and add alias rows automatically.
- **Populate `extracted_cves` / `canonical_id` from context when the feed
  didn't.** If the title, body, or a well-known transient-execution codename
  mapping lets you identify a CVE the feed didn't emit (e.g., "Lazy FP
  State Restore" → `CVE-2018-3665`, "LazyFP" → same, "FP-DSS" → whatever
  CVE AMD/Intel assigned), put the CVE in `extracted_cves` and use it as
  `canonical_id`. This prevents Intel's CVE-less listing entries from
  creating orphan `INTEL-SA-NNNNN` records in the backlog.
- `sources` / `urls`: arrays; default to the item's own single source and
  permalink if you didn't enrich further.
- **`reconsider: true`** — set on every record that corresponds to an
  input from the `reconsider` array. The merge step uses this flag to
  overwrite the stored bucket instead of merging by "strongest wins" —
  this is what enables demotions.
- If both `items` and `reconsider` are empty, write `[]`.

## Guardrails

- Do NOT modify any repo source code. Only write the four output files.
- Do NOT create commits, branches, or PRs.
- Do NOT call tools that post externally (Slack, GitHub comments, issues, …).
- Do NOT re-fetch the RSS/HTML sources — that was the prior step's job.
  `WebFetch` is only for drilling into a specific advisory/article URL to
  resolve a `tocheck` ambiguity (budget 3).
- If total runtime exceeds 10 minutes, finish what you have, write partial
  outputs (+ a note in the tocheck run summary), and exit cleanly.
