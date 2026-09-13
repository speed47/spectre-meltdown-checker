# Intel affected processor database tools

These maintainer tools generate the checker's INTELDB data using Python 3
(standard library only) and Git. Python is not a runtime checker dependency.

## Files

- `parse_inteldb_csv.py`: CSV parsing, status normalization, combined CVE
  expansion, duplicate-column naming, and worst-case merging.
- `build_inteldb.py`: database reading and historical merge logic
- `header.txt`: database format and status legend included by `build_inteldb.py`.
- `historical_records.db`: baseline database retaining legacy processor records
  absent from Intel's CSV history.
- `test_inteldb.py`: regression checks for the database tools.
- `README.md`: usage and maintenance documentation for these tools.

## Parse one CSV

Run from this project's root:

```sh
python3 scripts/intel-affected-processor-list/parse_inteldb_csv.py \
    /path/to/Intel-affected-processor-list/Intel_affected_processor_list.csv \
    /tmp/inteldb-current.db
```

Columns are found by header name. The hybrid column contains
`CPUID.0x7.EDX[15]=0` or `=1`, optionally followed by
`CPUID.0x1A.EAX[31:24]=20` or `=40` (hexadecimal core types).
Explicit hybrid qualifiers are retained even for a single row/profile.
`NA`, `N/A`, and empty cells are unqualified; only CSV versions **without**
the column use the original codename inference.

Output uses the checker's existing `CPUID,H=0/1` lookup granularity. Core-type
and segment differences sharing a CPUID/hybrid key are worst-case merged;
the output does not add a core-type-specific runtime lookup. Unrecognized
hybrid expressions fail rather than silently producing unqualified entries.

## Build from history

Use a full clone to retain CPUs that Intel removed from later lists:

```sh
git clone https://github.com/intel/Intel-affected-processor-list.git \
    /tmp/Intel-affected-processor-list
python3 scripts/intel-affected-processor-list/build_inteldb.py \
    /tmp/Intel-affected-processor-list /tmp/inteldb.db \
    --base-db scripts/intel-affected-processor-list/historical_records.db
```

- `--ref COMMIT` pins the source revision (default: the clone's `HEAD`). The
  resolved commit is recorded in the output. Fetch updates in the clone before
  building when needed.
- History is processed oldest-first in Git topological order, with the selected
  tip processed last. This fixes the original pipeline's commit-hash glob order.
- A newer snapshot replaces **all profiles for each CPUID it contains**,
  including obsolete hybrid qualifiers/unqualified fallbacks. CPUs absent
  from that snapshot keep their previous data. As in the original pipeline,
  replacement is per processor profile, not a union of historical CVE columns.
- `--base-db` seeds legacy entries (including XLSX-only CPUs) absent from the
  entire CSV history. CSV history supersedes baseline data for CPUs it covers.
- Output is generated only after all input snapshots parse successfully.

Both commands write to stdout if the output filename is omitted, and send
diagnostics to stderr. Review generated entries before integrating them into
`src/db/100_inteldb.sh`; that file also carries format documentation and build
boundary markers.

## Regression checks

```sh
python3 -m unittest discover -s scripts/intel-affected-processor-list -p 'test_*.py'
```
