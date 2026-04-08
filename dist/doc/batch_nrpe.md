# NRPE Output Format

`--batch nrpe` produces output that conforms to the
[Nagios Plugin Development Guidelines](https://nagios-plugins.org/doc/guidelines.html),
making it directly consumable by Nagios, Icinga, Zabbix (via NRPE), and
compatible monitoring stacks.

```sh
sudo ./spectre-meltdown-checker.sh --batch nrpe
```

## Output structure

The plugin emits one mandatory status line followed by optional long output:

```
STATUS: summary | checked=N vulnerable=N unknown=N
NOTE: ...          ← context notes (when applicable)
[CRITICAL] CVE-XXXX-YYYY (NAME): description
[UNKNOWN]  CVE-XXXX-YYYY (NAME): description
```

### Line 1 (status line)

Always present.  Parsed by every Nagios-compatible monitoring system.

```
STATUS: summary | perfdata
```

| Field | Values | Meaning |
|---|---|---|
| `STATUS` | `OK` / `CRITICAL` / `UNKNOWN` | Overall check outcome (see below) |
| `summary` | human-readable string | Count and CVE IDs of affected checks |
| `perfdata` | `checked=N vulnerable=N unknown=N` | Machine-readable counters for graphing |

#### Status values

| Status | Exit code | Condition |
|---|---|---|
| `OK` | `0` | All CVE checks passed |
| `CRITICAL` | `2` | At least one CVE is vulnerable |
| `UNKNOWN` | `3` | No VULN found, but at least one check is inconclusive **or** the script was not run as root and found apparent vulnerabilities (see below) |

#### Summary format

| Condition | Summary |
|---|---|
| All OK | `All N CVE checks passed` |
| VULN only | `N/T CVE(s) vulnerable: CVE-A CVE-B ...` |
| VULN + UNK | `N/T CVE(s) vulnerable: CVE-A CVE-B ..., M inconclusive` |
| UNK only | `N/T CVE checks inconclusive` |
| Non-root + VULN | `N/T CVE(s) appear vulnerable (unconfirmed, not root): CVE-A ...` |

### Lines 2+ (long output)

Shown in the detail/extended info view of most monitoring frontends.
Never parsed by the monitoring core; safe to add or reorder.

#### Context notes

Printed before per-CVE details when applicable:

| Note | Condition |
|---|---|
| `NOTE: paranoid mode active, stricter mitigation requirements applied` | `--paranoid` was used |
| `NOTE: hypervisor host detected (reason); L1TF/MDS severity is elevated` | System is a VM host (KVM, Xen, VMware…) |
| `NOTE: not a hypervisor host` | System is confirmed not a VM host |
| `NOTE: not running as root; MSR reads skipped, results may be incomplete` | Script ran without root privileges |

#### Per-CVE detail lines

One line per non-OK CVE.  VULN entries (`[CRITICAL]`) appear before UNK
entries (`[UNKNOWN]`); within each group the order follows the CVE registry.

```
[CRITICAL] CVE-XXXX-YYYY (SHORT NAME): mitigation status description
[UNKNOWN]  CVE-XXXX-YYYY (SHORT NAME): reason check was inconclusive
```

## Exit codes

| Code | Nagios meaning | Condition |
|---|---|---|
| `0` | OK | All checked CVEs are mitigated or hardware-unaffected |
| `2` | CRITICAL | At least one CVE is vulnerable (script ran as root) |
| `3` | UNKNOWN | At least one check inconclusive, or apparent VULN found without root |
| `255` | - | Script error (bad arguments, unsupported platform) |

Exit code `1` (WARNING) is not used; there is no "degraded but acceptable"
state for CPU vulnerability mitigations.

## Non-root behaviour

Running without root privileges skips MSR reads and limits access to some
kernel interfaces.  When the script finds apparent vulnerabilities without root:

- The status word becomes `UNKNOWN` instead of `CRITICAL`
- The exit code is `3` instead of `2`
- The summary says `appear vulnerable (unconfirmed, not root)`
- A `NOTE: not running as root` line is added to the long output

**Recommendation:** always run with `sudo` for authoritative results.  A
`CRITICAL` from a root-run scan is a confirmed vulnerability; an `UNKNOWN`
from a non-root scan is a signal to investigate further.

## Hypervisor hosts

When `NOTE: hypervisor host detected` is present, L1TF (CVE-2018-3646) and
MDS (CVE-2018-12126/12130/12127) carry significantly higher risk because
they can be exploited across VM boundaries by a malicious guest.  Prioritise
remediation on these hosts.

## Examples

**All mitigated (root):**
```
OK: All 31 CVE checks passed | checked=31 vulnerable=0 unknown=0
NOTE: not a hypervisor host
```
Exit: `0`

**Two CVEs vulnerable (root):**
```
CRITICAL: 2/31 CVE(s) vulnerable: CVE-2018-3615 CVE-2019-11135 | checked=31 vulnerable=2 unknown=0
NOTE: not a hypervisor host
[CRITICAL] CVE-2018-3615 (L1TF SGX): your CPU supports SGX and the microcode is not up to date
[CRITICAL] CVE-2019-11135 (TAA): Your kernel doesn't support TAA mitigation, update it
```
Exit: `2`

**Apparent vulnerabilities, non-root scan:**
```
UNKNOWN: 2/31 CVE(s) appear vulnerable (unconfirmed, not root): CVE-2018-3615 CVE-2019-11135 | checked=31 vulnerable=2 unknown=0
NOTE: not a hypervisor host
NOTE: not running as root; MSR reads skipped, results may be incomplete
[CRITICAL] CVE-2018-3615 (L1TF SGX): your CPU supports SGX and the microcode is not up to date
[CRITICAL] CVE-2019-11135 (TAA): Your kernel doesn't support TAA mitigation, update it
```
Exit: `3`

**Inconclusive checks, paranoid mode, VMM host:**
```
UNKNOWN: 3/31 CVE checks inconclusive | checked=31 vulnerable=0 unknown=3
NOTE: paranoid mode active, stricter mitigation requirements applied
NOTE: hypervisor host detected (kvm); L1TF/MDS severity is elevated
[UNKNOWN]  CVE-2018-3646 (L1TF VMM): SMT is enabled on a hypervisor host, not mitigated under paranoid mode
```
Exit: `3`
