# JSON Output Format

`--batch json` emits a single, self-contained JSON object that describes the
scan environment and the result of every CVE check. You can feed it to your
monitoring system, to a SIEM, to a time-series database, you name it.

```sh
sudo ./spectre-meltdown-checker.sh --batch json | jq .
```

## Top-level schema

```
{
  "meta":          { ... },   // Run metadata and flags
  "system":        { ... },   // Kernel and host context
  "cpu":           { ... },   // CPU hardware identification
  "cpu_microcode": { ... },   // Microcode version and status
  "vulnerabilities": [ ... ]  // One object per checked CVE
}
```

`format_version` in `meta` is an integer that will be incremented on
backward-incompatible schema changes.  The current value is **1**.

## Section reference

### `meta`

Run metadata.  Always present.

| Field | Type | Values | Meaning |
|---|---|---|---|
| `script_version` | string | e.g. `"25.30.0250400123"` | Script version |
| `format_version` | integer | `1` | JSON schema version; incremented on breaking changes |
| `timestamp` | string | ISO 8601 UTC, e.g. `"2025-04-07T12:00:00Z"` | When the scan started |
| `os` | string | e.g. `"Linux"`, `"FreeBSD"` | Output of `uname -s` |
| `mode` | string | `"live"` / `"no-runtime"` / `"no-hw"` / `"hw-only"` | Operating mode (see [modes](README.md#operating-modes)) |
| `run_as_root` | boolean | | Whether the script ran as root.  Non-root scans skip MSR reads and may miss mitigations |
| `reduced_accuracy` | boolean | | Kernel image, config, or System.map was missing; some checks fall back to weaker heuristics |
| `paranoid` | boolean | | `--paranoid` mode: stricter criteria (e.g. requires SMT disabled, IBPB always-on) |
| `sysfs_only` | boolean | | `--sysfs-only`: only the kernel's own sysfs report was used, not independent detection |
| `extra` | boolean | | `--extra`: additional experimental checks were enabled |
| `mocked` | boolean | | One or more CPU values were overridden for testing.  Results do **not** reflect the real system |

**Example:**
```json
"meta": {
  "script_version": "25.30.025040123",
  "format_version": 1,
  "timestamp": "2025-04-07T12:00:00Z",
  "os": "Linux",
  "mode": "live",
  "run_as_root": true,
  "reduced_accuracy": false,
  "paranoid": false,
  "sysfs_only": false,
  "extra": false,
  "mocked": false
}
```

**Important flags for fleet operators:**

- `run_as_root: false` means the scan was incomplete.  Treat results as lower
  confidence.  Alert separately: results may be missing or wrong.
- `sysfs_only: true` means the script trusted the kernel's self-report without
  independent verification.  Some older kernels misreport their mitigation
  status.  Do not use `--sysfs-only` for production fleet monitoring.
- `paranoid: true` raises the bar: only compare `vulnerable` counts across
  hosts with the same `paranoid` value.
- `mocked: true` must never appear on a production host.  If it does, every
  downstream result is fabricated.

---

### `system`

Kernel and host environment.  Always present.

| Field | Type | Values | Meaning |
|---|---|---|---|
| `kernel_release` | string \| null | e.g. `"6.1.0-21-amd64"` | Output of `uname -r` (null in no-runtime, no-hw, and hw-only modes) |
| `kernel_version` | string \| null | e.g. `"#1 SMP Debian …"` | Output of `uname -v` (null in no-runtime, no-hw, and hw-only modes) |
| `kernel_arch` | string \| null | e.g. `"x86_64"` | Output of `uname -m` (null in no-runtime, no-hw, and hw-only modes) |
| `kernel_image` | string \| null | e.g. `"/boot/vmlinuz-6.1.0-21-amd64"` | Path passed via `--kernel`, or null if not specified |
| `kernel_config` | string \| null | | Path passed via `--config`, or null |
| `kernel_version_string` | string \| null | | Kernel version banner extracted from the image |
| `kernel_cmdline` | string \| null | | Kernel command line from `/proc/cmdline` (live mode) or the image |
| `cpu_count` | integer \| null | | Number of logical CPUs detected |
| `smt_enabled` | boolean \| null | | Whether SMT (HyperThreading) is currently active; null if undeterminable |
| `hypervisor_host` | boolean \| null | | Whether this machine is detected as a VM host (running KVM, Xen, VMware, etc.) |
| `hypervisor_host_reason` | string \| null | | Human-readable explanation of why `hypervisor_host` was set |

**`hypervisor_host`** materially changes the risk profile of several CVEs.
L1TF (CVE-2018-3646) and MDS (CVE-2018-12126/12130/12127) are significantly
more severe on hypervisor hosts because they can be exploited across VM
boundaries by a malicious guest.  Prioritise remediation where
`hypervisor_host: true`.

---

### `cpu`

CPU hardware identification.  `null` when `--no-hw` is active.

The object uses `arch` as a discriminator: `"x86"` for Intel/AMD/Hygon CPUs,
`"arm"` for ARM/Cavium/Phytium.  Arch-specific fields live under a matching
sub-object (`cpu.x86` or `cpu.arm`), so consumers never see irrelevant null
fields from the other architecture.

#### Common fields

| Field | Type | Values | Meaning |
|---|---|---|---|
| `arch` | string | `"x86"` / `"arm"` | CPU architecture family; determines which sub-object is present |
| `vendor` | string \| null | e.g. `"GenuineIntel"`, `"ARM"` | CPU vendor string |
| `friendly_name` | string \| null | e.g. `"Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz"` | Human-readable CPU model |

#### `cpu.x86` (present when `arch == "x86"`)

| Field | Type | Values | Meaning |
|---|---|---|---|
| `family` | integer \| null | | CPU family number |
| `model` | integer \| null | | CPU model number |
| `stepping` | integer \| null | | CPU stepping number |
| `cpuid` | string \| null | hex, e.g. `"0x000906ed"` | Full CPUID leaf 1 EAX value |
| `platform_id` | integer \| null | | Intel platform ID (from MSR 0x17); null on AMD |
| `hybrid` | boolean \| null | | Whether this is a hybrid CPU (P-cores + E-cores, e.g. Alder Lake) |
| `codename` | string \| null | e.g. `"Coffee Lake"` | Intel CPU codename; null on AMD |
| `capabilities` | object | | CPU feature flags (see below) |

#### `cpu.arm` (present when `arch == "arm"`)

| Field | Type | Values | Meaning |
|---|---|---|---|
| `part_list` | string \| null | e.g. `"0xd0b 0xd05"` | Space-separated ARM part numbers across cores (big.LITTLE may have several) |
| `arch_list` | string \| null | e.g. `"8 8"` | Space-separated ARM architecture levels across cores |
| `capabilities` | object | | ARM-specific capability flags (currently empty; reserved for future use) |

#### `cpu.x86.capabilities`

Each capability is a **tri-state**: `true` (present), `false` (absent), or
`null` (not applicable or could not be read, e.g. when not root or on AMD for
Intel-specific features).

| Capability | Meaning |
|---|---|
| `spec_ctrl` | SPEC_CTRL MSR (Intel: ibrs + ibpb via WRMSR; required for many mitigations) |
| `ibrs` | Indirect Branch Restricted Speculation |
| `ibpb` | Indirect Branch Prediction Barrier |
| `ibpb_ret` | IBPB on return (enhanced form) |
| `stibp` | Single Thread Indirect Branch Predictors |
| `ssbd` | Speculative Store Bypass Disable |
| `l1d_flush` | L1D cache flush instruction |
| `md_clear` | VERW clears CPU buffers (MDS mitigation) |
| `arch_capabilities` | IA32_ARCH_CAPABILITIES MSR is present |
| `rdcl_no` | Not susceptible to RDCL (Meltdown-like attacks) |
| `ibrs_all` | Enhanced IBRS always-on mode supported |
| `rsba` | RSB may use return predictions from outside the RSB |
| `l1dflush_no` | Not susceptible to L1D flush side-channel |
| `ssb_no` | Not susceptible to Speculative Store Bypass |
| `mds_no` | Not susceptible to MDS |
| `taa_no` | Not susceptible to TSX Asynchronous Abort |
| `pschange_msc_no` | Page-size-change MSC not susceptible |
| `tsx_ctrl_msr` | TSX_CTRL MSR is present |
| `tsx_ctrl_rtm_disable` | RTM disabled via TSX_CTRL |
| `tsx_ctrl_cpuid_clear` | CPUID HLE/RTM bits cleared via TSX_CTRL |
| `gds_ctrl` | GDS_CTRL MSR present (GDS mitigation control) |
| `gds_no` | Not susceptible to Gather Data Sampling |
| `gds_mitg_dis` | GDS mitigation disabled |
| `gds_mitg_lock` | GDS mitigation locked |
| `rfds_no` | Not susceptible to Register File Data Sampling |
| `rfds_clear` | VERW clears register file stale data |
| `its_no` | Not susceptible to Indirect Target Selection |
| `sbdr_ssdp_no` | Not susceptible to SBDR/SSDP |
| `fbsdp_no` | Not susceptible to FBSDP |
| `psdp_no` | Not susceptible to PSDP |
| `fb_clear` | Fill buffer cleared on idle/C6 |
| `rtm` | Restricted Transactional Memory (TSX RTM) present |
| `tsx_force_abort` | TSX_FORCE_ABORT MSR present |
| `tsx_force_abort_rtm_disable` | RTM disabled via TSX_FORCE_ABORT |
| `tsx_force_abort_cpuid_clear` | CPUID RTM cleared via TSX_FORCE_ABORT |
| `sgx` | Software Guard Extensions present |
| `srbds` | SRBDS affected |
| `srbds_on` | SRBDS mitigation active |
| `amd_ssb_no` | AMD: not susceptible to Speculative Store Bypass |
| `hygon_ssb_no` | Hygon: not susceptible to Speculative Store Bypass |
| `ipred` | Indirect Predictor Barrier support |
| `rrsba` | Restricted RSB Alternate (Intel Retbleed mitigation) |
| `bhi` | Branch History Injection mitigation support |
| `tsa_sq_no` | Not susceptible to TSA-SQ |
| `tsa_l1_no` | Not susceptible to TSA-L1 |
| `verw_clear` | VERW clears CPU buffers |
| `autoibrs` | AMD AutoIBRS (equivalent to enhanced IBRS on Intel) |
| `sbpb` | Selective Branch Predictor Barrier (AMD Inception mitigation) |
| `avx2` | AVX2 supported (relevant to Downfall / GDS) |
| `avx512` | AVX-512 supported (relevant to Downfall / GDS) |

---

### `cpu_microcode`

Microcode version and status.  `null` under the same conditions as `cpu`.

| Field | Type | Values | Meaning |
|---|---|---|---|
| `installed_version` | string \| null | hex, e.g. `"0xf4"` | Currently running microcode revision |
| `latest_version` | string \| null | hex | Latest known-good version in the firmware database; null if CPU is not in the database |
| `microcode_up_to_date` | boolean \| null | | Whether `installed_version == latest_version`; null if either is unavailable |
| `is_blacklisted` | boolean | | Whether the installed microcode is known to cause instability and must be rolled back |
| `message` | string \| null | | Human-readable note from the firmware database (e.g. changelog excerpt) |
| `db_source` | string \| null | | Which database was used (e.g. `"Intel-SA"`, `"MCExtractor"`) |
| `db_info` | string \| null | | Database revision or date |

**`is_blacklisted: true`** means the installed microcode is known to cause
system instability or incorrect behaviour.  Treat this as a P1 incident: roll
back to the previous microcode immediately.

**`microcode_up_to_date: false`** means a newer microcode is available.  This
does not necessarily mean the system is vulnerable (the current microcode may
still include all required mitigations), but warrants investigation.

---

### `vulnerabilities`

Array of CVE check results.  One object per checked CVE, in check order.
Empty array (`[]`) if no CVEs were checked (unusual; would require `--cve`
with an unknown CVE ID).

| Field | Type | Values | Meaning |
|---|---|---|---|
| `cve` | string | e.g. `"CVE-2017-5753"` | CVE identifier |
| `name` | string | e.g. `"SPECTRE VARIANT 1"` | Short key name used in batch formats |
| `aliases` | string \| null | e.g. `"Spectre Variant 1, bounds check bypass"` | Full name including all known aliases |
| `cpu_affected` | boolean | | Whether this CPU's hardware design is affected by this CVE |
| `status` | string | `"OK"` / `"VULN"` / `"UNK"` | Check outcome (see below) |
| `vulnerable` | boolean \| null | `false` / `true` / `null` | `false`=OK, `true`=VULN, `null`=UNK |
| `info` | string | | Human-readable description of the specific mitigation state or reason |
| `sysfs_status` | string \| null | `"OK"` / `"VULN"` / `"UNK"` / null | Status as reported by the kernel via `/sys/devices/system/cpu/vulnerabilities/`; null if sysfs was not consulted for this CVE |
| `sysfs_message` | string \| null | | Raw text from the sysfs file (e.g. `"Mitigation: PTI"`); null if sysfs was not consulted |

#### Status values

| `status` | `vulnerable` | Meaning |
|---|---|---|
| `"OK"` | `false` | CPU is unaffected by design, or all required mitigations are in place |
| `"VULN"` | `true` | CPU is affected and mitigations are missing or insufficient |
| `"UNK"` | `null` | The script could not determine the status (missing kernel info, insufficient privileges, or no detection logic for this platform) |

#### `cpu_affected` explained

`cpu_affected: false` with `status: "OK"` means the CPU hardware is
architecturally immune, no patch was ever needed.

`cpu_affected: true` with `status: "OK"` means the hardware has the weakness
but all required mitigations (kernel, microcode, or both) are in place.

This distinction matters for fleet auditing: filter on `cpu_affected: true` to
see only systems where mitigation effort was actually required and confirmed.

#### `sysfs_status` vs `status`

`sysfs_status` is the raw kernel self-report.  `status` is the script's
independent assessment, which may differ:

- The script may **upgrade** a sysfs `"VULN"` to `"OK"` when it detects a
  silent backport that the kernel doesn't know about.
- The script may **downgrade** a sysfs `"OK"` to `"VULN"` when it detects an
  incomplete mitigation the kernel doesn't flag (e.g. L1TF on a hypervisor
  host with SMT still enabled, or TSA in `user` mode on a VMM host).
- `sysfs_status` is `null` when the kernel has no sysfs entry for this CVE
  (older kernels, or CVEs not yet tracked by the kernel).

Always use `status` / `vulnerable` for alerting.  Use `sysfs_status` for
diagnostics and audit trails.

**Example:**
```json
{
  "cve": "CVE-2017-5715",
  "name": "SPECTRE VARIANT 2",
  "aliases": "Spectre Variant 2, branch target injection",
  "cpu_affected": true,
  "status": "OK",
  "vulnerable": false,
  "info": "Full generic retpoline is mitigating the vulnerability",
  "sysfs_status": "OK",
  "sysfs_message": "Mitigation: Retpolines; IBPB: conditional; IBRS_FW; STIBP: conditional; RSB filling; PBRSB-eIBRS: Not affected; BHI: Not affected"
}
```

---

## Exit codes

The script exits with:

| Code | Meaning |
|---|---|
| `0` | All checked CVEs are `OK` |
| `2` | At least one CVE is `VULN` |
| `3` | No CVEs are `VULN`, but at least one is `UNK` |

These exit codes are the same in all batch modes and in interactive mode.
Use them in combination with the JSON body for reliable alerting.

---

## Caveats and edge cases

**No-runtime mode (`--no-runtime`)**
`system.kernel_release`, `kernel_version`, and `kernel_arch` are null (those
come from `uname`, which reports the running kernel, not the inspected one).
`meta.mode: "no-runtime"` signals this.  `system.kernel_image` and
`system.kernel_version_string` carry the inspected image path and banner
instead.

**No-hardware mode (`--no-hw`)**
`cpu` and `cpu_microcode` are null.  CVE checks that rely on hardware
capability detection (`cap_*` flags, MSR reads) will report `status: "UNK"`.
`cpu_affected` will be `false` for all CVEs (cannot determine affection without
hardware info).  `meta.mode: "no-hw"` signals this.

**Hardware-only mode (`--hw-only`)**
Only CPU information and per-CVE affectedness are reported.  No kernel
inspection is performed, so vulnerability mitigations are not checked.
`meta.mode: "hw-only"` signals this.

**`--sysfs-only`**
The script trusts the kernel's sysfs report without running independent
detection.  `meta.sysfs_only: true` flags this.  Some older kernels misreport
their status.  Do not use for production fleet monitoring.

**`--paranoid`**
Enables defense-in-depth checks beyond the security community consensus.
A `status: "OK"` under `paranoid: true` means a higher bar was met.  Do not
compare results across hosts with different `paranoid` values.

**`reduced_accuracy`**
Set when the kernel image, config file, or System.map could not be read.
Some checks fall back to weaker heuristics and may report `"UNK"` for CVEs
that are actually mitigated.

**Non-x86 architectures (ARM, ARM64)**
On ARM, `cpu.arch` is `"arm"` and the `cpu.arm` sub-object carries `part_list`
and `arch_list`.  The x86-specific sub-object is absent (no null noise).
`cpu.arm.capabilities` is currently empty; ARM-specific flags will be added
there as needed.

**`mocked: true`**
Must never appear on a production host.  If it does, the results are
fabricated and every downstream alert is unreliable.

---

## Schema stability

`meta.format_version` is incremented on backward-incompatible changes (field
removal or type change).  Additive changes (new fields) do not increment the
version; consumers must tolerate unknown fields.

Recommended practice: check `format_version == 1` at parse time and reject
or alert on any other value until you have tested compatibility with the new
version.

---

## Migration from `json-terse`

The legacy `--batch json-terse` format emits a flat array of objects:

```json
[
  {"NAME": "SPECTRE VARIANT 1", "CVE": "CVE-2017-5753", "VULNERABLE": false, "INFOS": "..."},
  ...
]
```

It carries no system, CPU, or microcode context.  It has no sysfs data.  It
uses uppercase field names.

To migrate:

1. Replace `--batch json-terse` with `--batch json`.
2. The equivalent of the old `VULNERABLE` field is `vulnerabilities[].vulnerable`.
3. The equivalent of the old `INFOS` field is `vulnerabilities[].info`.
4. The equivalent of the old `NAME` field is `vulnerabilities[].name`.
5. The old format is still available as `--batch json-terse` for transition
   periods.
