# Prometheus Batch Mode — Fleet Operator Guide

`--batch prometheus` emits Prometheus text-format metrics that can be fed into any
Prometheus-compatible monitoring stack.  It is designed for **fleet-scale security
monitoring**: run the script periodically on every host, push the output to a
Prometheus Pushgateway (or drop it into a node_exporter textfile directory), then
alert and dashboard from Prometheus/Grafana like any other infrastructure metric.

---

## Quick start

### Pushgateway (recommended for cron/batch fleet scans)

```sh
#!/bin/sh
PUSHGATEWAY="http://pushgateway.internal:9091"
INSTANCE=$(hostname -f)

spectre-meltdown-checker.sh --batch prometheus \
  | curl --silent --show-error --data-binary @- \
    "${PUSHGATEWAY}/metrics/job/smc/instance/${INSTANCE}"
```

Run this as root via cron or a systemd timer on every host.  The Pushgateway
retains the last pushed value, so Prometheus scrapes it on its own schedule.
A stale-data alert (`smc_last_scan_timestamp_seconds`) catches hosts that stopped
reporting.

### node_exporter textfile collector

```sh
#!/bin/sh
TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector"
TMP="${TEXTFILE_DIR}/smc.prom.$$"

spectre-meltdown-checker.sh --batch prometheus > "$TMP"
mv "$TMP" "${TEXTFILE_DIR}/smc.prom"
```

The atomic `mv` prevents node_exporter from reading a partially written file.
node_exporter must be started with `--collector.textfile.directory` pointing at
`TEXTFILE_DIR`.

---

## Metric reference

All metric names are prefixed `smc_` (spectre-meltdown-checker).  All metrics
are **gauges**: they represent the state at the time of the scan, not a running
counter.

---

### `smc_build_info`

Script metadata.  Always value `1`; all data is in labels.

| Label | Values | Meaning |
|---|---|---|
| `version` | string | Script version (e.g. `25.30.0250400123`) |
| `mode` | `live` / `offline` | `live` = running on the active kernel; `offline` = inspecting a kernel image |
| `run_as_root` | `true` / `false` | Whether the script ran as root.  Non-root scans skip MSR reads and may miss mitigations |
| `paranoid` | `true` / `false` | `--paranoid` mode: stricter criteria (e.g. requires SMT disabled) |
| `sysfs_only` | `true` / `false` | `--sysfs-only` mode: only the kernel's own sysfs report was used, not independent detection |
| `reduced_accuracy` | `true` / `false` | Kernel information was incomplete (no kernel image, config, or map); some checks may be less precise |
| `mocked` | `true` / `false` | Debug/test mode: CPU values were overridden.  Results do **not** reflect the real system |

**Example:**
```
smc_build_info{version="25.30.0250400123",mode="live",run_as_root="true",paranoid="false",sysfs_only="false",reduced_accuracy="false",mocked="false"} 1
```

**Important labels for fleet operators:**

- `run_as_root="false"` means the scan was incomplete.  Treat those results as
  lower confidence and alert separately.
- `sysfs_only="true"` means the script trusted the kernel's self-report without
  independent verification.  The kernel may be wrong about its own mitigation
  status (known to happen on older kernels).
- `paranoid="true"` raises the bar: a host with `paranoid="true"` and
  `vulnerable_count=0` is held to a higher standard than one with `paranoid="false"`.
  Do not compare counts across hosts with different `paranoid` values.
- `mocked="true"` must never appear on a production host; if it does, the results
  are fabricated and every downstream alert is unreliable.

---

### `smc_system_info`

Operating system and kernel metadata.  Always value `1`.

Absent in offline mode when neither `uname -r` nor `uname -m` is available.

| Label | Values | Meaning |
|---|---|---|
| `kernel_release` | string | Output of `uname -r` (live mode only) |
| `kernel_arch` | string | Output of `uname -m` (live mode only) |
| `hypervisor_host` | `true` / `false` | Whether this machine is detected as a hypervisor host (running KVM, Xen, VMware, etc.) |

**Example:**
```
smc_system_info{kernel_release="5.15.0-100-generic",kernel_arch="x86_64",hypervisor_host="false"} 1
```

**`hypervisor_host`** materially changes the risk profile of several CVEs.
L1TF (CVE-2018-3646) and MDS (CVE-2018-12126/12130/12127) are significantly more
severe on hypervisor hosts because they can be exploited across VM boundaries by
a malicious guest.  Always prioritise remediation on hosts where
`hypervisor_host="true"`.

---

### `smc_cpu_info`

CPU hardware and microcode metadata.  Always value `1`.  Absent when `--no-hw`
is used.

| Label | Values | Meaning |
|---|---|---|
| `vendor` | string | CPU vendor (e.g. `Intel`, `AuthenticAMD`) |
| `model` | string | CPU friendly name from `/proc/cpuinfo` |
| `family` | integer string | CPU family number |
| `model_id` | integer string | CPU model number |
| `stepping` | integer string | CPU stepping number |
| `cpuid` | hex string | Full CPUID value (e.g. `0x000906ed`); absent on some ARM CPUs |
| `codename` | string | Intel CPU codename (e.g. `Coffee Lake`); absent on AMD and ARM |
| `smt` | `true` / `false` | Whether SMT (HyperThreading) is currently enabled |
| `microcode` | hex string | Installed microcode version (e.g. `0xf4`) |
| `microcode_latest` | hex string | Latest known-good microcode version from the firmware database |
| `microcode_up_to_date` | `true` / `false` | Whether `microcode == microcode_latest` |
| `microcode_blacklisted` | `true` / `false` | Whether the installed microcode is known to cause problems and should be rolled back |

**Example:**
```
smc_cpu_info{vendor="Intel",model="Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz",family="6",model_id="158",stepping="13",cpuid="0x000906ed",codename="Coffee Lake",smt="true",microcode="0xf4",microcode_latest="0xf4",microcode_up_to_date="true",microcode_blacklisted="false"} 1
```

**Microcode labels:**

- `microcode_up_to_date="false"` means a newer microcode is available in the
  firmware database.  This does not necessarily mean the system is vulnerable
  (the current microcode may still provide all required mitigations), but it
  warrants investigation.
- `microcode_blacklisted="true"` means the installed microcode is known to
  cause system instability or incorrect behaviour and must be rolled back
  immediately.  Treat this as a P1 incident.
- `microcode_latest` may be absent if the CPU is not in the firmware database
  (very new, very old, or exotic CPUs).

**`smt`** affects the risk level of several CVEs (MDS, L1TF).  For those CVEs,
full mitigation requires disabling SMT in addition to kernel and microcode updates.
The script accounts for this in its status assessment; use this label to audit
which hosts still have SMT enabled.

---

### `smc_vulnerability_status`

One time series per CVE.  The **numeric value** encodes the check result:

| Value | Meaning |
|---|---|
| `0` | Not vulnerable (CPU is unaffected by design, or all required mitigations are in place) |
| `1` | Vulnerable (mitigations are missing or insufficient) |
| `2` | Unknown (the script could not determine the status, e.g. due to missing kernel info or insufficient privileges) |

| Label | Values | Meaning |
|---|---|---|
| `cve` | CVE ID string | The CVE identifier (e.g. `CVE-2017-5753`) |
| `name` | string | Human-readable CVE name and aliases (e.g. `Spectre Variant 1, bounds check bypass`) |
| `cpu_affected` | `true` / `false` | Whether this CPU's hardware design is concerned by this CVE |

**Example:**
```
smc_vulnerability_status{cve="CVE-2017-5753",name="Spectre Variant 1, bounds check bypass",cpu_affected="true"} 0
smc_vulnerability_status{cve="CVE-2017-5715",name="Spectre Variant 2, branch target injection",cpu_affected="true"} 1
smc_vulnerability_status{cve="CVE-2022-29900",name="Retbleed, arbitrary speculative code execution with return instructions (AMD)",cpu_affected="false"} 0
```

**`cpu_affected` explained:**

A value of `0` with `cpu_affected="false"` means the CPU hardware is architecturally
immune to this CVE — no patch was needed or applied.

A value of `0` with `cpu_affected="true"` means the CPU has the hardware weakness
but all required mitigations (kernel, microcode, or both) are in place.

This distinction is important when auditing a fleet: if you need to verify that
all at-risk systems are patched, filter on `cpu_affected="true"` to exclude
hardware-immune systems from the analysis.

---

### `smc_vulnerable_count`

Number of CVEs with status `1` (vulnerable) in this scan.  Value is `0` when
no CVEs are vulnerable.

---

### `smc_unknown_count`

Number of CVEs with status `2` (unknown) in this scan.  A non-zero value
typically means the scan lacked sufficient privileges or kernel information.
Treat unknown the same as vulnerable for alerting purposes.

---

### `smc_last_scan_timestamp_seconds`

Unix timestamp (seconds since epoch) when the scan completed.  Use this to
detect hosts that have stopped reporting.

---

## Alerting rules

```yaml
groups:
  - name: spectre_meltdown_checker
    rules:

      # Fire when any CVE is confirmed vulnerable
      - alert: SMCVulnerable
        expr: smc_vulnerable_count > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.instance }} has {{ $value }} vulnerable CVE(s)"
          description: >
            Run spectre-meltdown-checker.sh interactively on {{ $labels.instance }}
            for remediation guidance.

      # Fire when status is unknown (usually means scan ran without root)
      - alert: SMCUnknown
        expr: smc_unknown_count > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.instance }} has {{ $value }} CVE(s) with unknown status"
          description: >
            Ensure the checker runs as root on {{ $labels.instance }}.

      # Fire when a host stops reporting (scan not run in 8 days)
      - alert: SMCScanStale
        expr: time() - smc_last_scan_timestamp_seconds > 8 * 86400
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.instance }} has not reported scan results in 8 days"

      # Fire when installed microcode is known-bad
      - alert: SMCMicrocodeBlacklisted
        expr: smc_cpu_info{microcode_blacklisted="true"} == 1
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.instance }} is running blacklisted microcode"
          description: >
            The installed microcode ({{ $labels.microcode }}) is known to cause
            instability.  Roll back to the previous version immediately.

      # Fire when scan ran without root (results may be incomplete)
      - alert: SMCScanNotRoot
        expr: smc_build_info{run_as_root="false"} == 1
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.instance }} scan ran without root privileges"

      # Fire when mocked data is detected on a production host
      - alert: SMCScanMocked
        expr: smc_build_info{mocked="true"} == 1
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.instance }} scan results are mocked and unreliable"
```

---

## Useful PromQL queries

```promql
# All vulnerable CVEs across the fleet
smc_vulnerability_status == 1

# Vulnerable CVEs on hosts that are also hypervisor hosts (highest priority)
smc_vulnerability_status == 1
  * on(instance) group_left(hypervisor_host)
  smc_system_info{hypervisor_host="true"}

# Vulnerable CVEs on affected CPUs only (excludes hardware-immune systems)
smc_vulnerability_status{cpu_affected="true"} == 1

# Fleet-wide: how many hosts are vulnerable to each CVE
count by (cve, name) (smc_vulnerability_status == 1)

# Hosts with outdated microcode, with CPU model context
smc_cpu_info{microcode_up_to_date="false"}

# Hosts with SMT still enabled (relevant for MDS/L1TF remediation)
smc_cpu_info{smt="true"}

# For a specific CVE: hosts affected by hardware but fully mitigated
smc_vulnerability_status{cve="CVE-2018-3646", cpu_affected="true"} == 0

# Proportion of fleet that is fully clean (no vulnerable, no unknown)
(
  count(smc_vulnerable_count == 0 and smc_unknown_count == 0)
  /
  count(smc_vulnerable_count >= 0)
)

# Hosts where scan ran without root — results less reliable
smc_build_info{run_as_root="false"}

# Hosts with sysfs_only mode — independent detection was skipped
smc_build_info{sysfs_only="true"}

# Vulnerable CVEs joined with kernel release for patch tracking
smc_vulnerability_status == 1
  * on(instance) group_left(kernel_release)
  smc_system_info

# Vulnerable CVEs joined with CPU model and microcode version
smc_vulnerability_status == 1
  * on(instance) group_left(vendor, model, microcode, microcode_up_to_date)
  smc_cpu_info
```

---

## Caveats and edge cases

**Offline mode (`--kernel`)**
`smc_system_info` will have no `kernel_release` or `kernel_arch` labels (those
come from `uname`, which reports the running kernel, not the inspected one).
`mode="offline"` in `smc_build_info` signals this.  Offline mode is primarily
useful for pre-deployment auditing, not fleet runtime monitoring.

**`--no-hw`**
`smc_cpu_info` is not emitted.  CPU and microcode labels are absent from all
queries.  CVE checks that rely on hardware capability detection (`cap_*` flags,
MSR reads) will report `unknown` status.

**`--sysfs-only`**
The script trusts the kernel's sysfs report (`/sys/devices/system/cpu/vulnerabilities/`)
without running its own independent detection.  Some older kernels are known to
misreport their mitigation status.  `sysfs_only="true"` in `smc_build_info`
flags this condition.  Do not use `--sysfs-only` for production fleet monitoring.

**`--paranoid`**
Enables defense-in-depth checks beyond the security community consensus (e.g.
requires SMT to be disabled, IBPB always-on).  A host is only `vulnerable_count=0`
under `paranoid` if it meets this higher bar.  Do not compare `vulnerable_count`
across hosts with different `paranoid` values.

**`reduced_accuracy`**
Set when the kernel image, config file, or System.map could not be read.  Some
checks fall back to weaker heuristics and may report `unknown` for CVEs that are
actually mitigated.  This typically happens when the script runs without root or
on a kernel with an inaccessible image.

**Label stability**
Prometheus identifies time series by their full label set.  If a script upgrade
adds or renames a label (e.g. a new `smc_cpu_info` label is added for a new CVE),
Prometheus will create a new time series and the old one will become stale.  Plan
for this in long-retention dashboards by using `group_left` joins rather than
hardcoding label matchers.
