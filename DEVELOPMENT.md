# Project Overview

spectre-meltdown-checker is a single self-contained shell script (`spectre-meltdown-checker.sh`) that detects system vulnerability to several transient execution CPU CVEs (Spectre, Meltdown, and related). It supports Linux and BSD (FreeBSD, NetBSD, DragonFlyBSD) on x86, amd64, ARM, and ARM64.

The script must stay POSIX-compatible, and not use features only available in specific shells such as `bash` or `zsh`. The `local` keyword is accepted however.

## Project Mission

This tool exists to give system administrators simple, actionable answers to two questions:

1. **Am I vulnerable?**
2. **What do I have to do to mitigate these vulnerabilities on my system?**

The script does not run exploits and cannot guarantee security. It reports whether a system is **affected**, **vulnerable**, or **mitigated** against known transient execution vulnerabilities, and provides detailed insight into the prerequisites for full mitigation (microcode, kernel, hypervisor, etc.).

### Why this tool still matters

Even though the Linux `sysfs` hierarchy (`/sys/devices/system/cpu/vulnerabilities/`) now reports mitigation status for most vulnerabilities, this script provides value beyond what `sysfs` offers:

- **Independent of kernel knowledge**: A given kernel only understands vulnerabilities known at compile time. This script's detection logic is maintained independently, so it can identify gaps a kernel doesn't yet know about.
- **Detailed prerequisite breakdown**: Mitigating a vulnerability can involve multiple layers (microcode, host kernel, hypervisor, guest kernel, software). The script shows exactly which pieces are in place and which are missing.
- **No-runtime kernel analysis**: The script can inspect a kernel image before it is booted (`--kernel`, `--config`, `--map`), verifying it carries the expected mitigations.
- **Backport-aware**: It detects actual capabilities rather than checking version strings, so it works correctly with vendor kernels that silently backport or forward-port patches.
- **Covers gaps in sysfs**: Some vulnerabilities (e.g. Zenbleed) are not reported through `sysfs` at all.

### Terminology

These terms have precise meanings throughout the codebase and output:

- **Affected**: The CPU hardware, as shipped from the factory, is known to be concerned by a vulnerability. Says nothing about whether the vulnerability is currently exploitable.
- **Vulnerable**: The system uses an affected CPU *and* has no (or insufficient) mitigations in place, meaning the vulnerability can be exploited.
- **Mitigated**: A previously vulnerable system has all required layers updated so the vulnerability cannot be exploited.

## Branch Model

The project uses 4 branches organized in two pipelines (production and dev/test). Developers work on the source branches; CI builds the monolithic script and pushes it to the corresponding output branch.

| Branch | Contents | Pushed by |
|--------|----------|-----------|
| **`test`** | Dev/test source (split files + Makefile) | Developers |
| **`test-build`** | Monolithic test script (built artifact) | CI from `test` |
| **`source`** | Production source (split files + Makefile) | Developers |
| **`source-build`** | Monolithic test script (built artifact) | CI from `source` |
| **`master`** | Monolithic production script (built artifact) | PR by developers from `source-build` |

- **`source`** and **`test`** contain the split source files and the Makefile. These are the branches developers commit to.
- **`master`**, **`source-build`** and **`test-build`** contain only the monolithic `spectre-meltdown-checker.sh` built by CI. Nobody commits to these directly.
- **`master`** is the preexisting production branch that users pull from. It cannot be renamed.
- **`test-build`** is a testing branch that users can pull from to test pre-release versions.
- **`source-build`** is a preprod branch to prepare the artifact before merging to **`master`**.

Typical workflow:
1. Feature/fix branches are created from `test` and merged back into `test`.
2. CI builds the script and pushes it to `test-build` for testing.
3. When ready for release, `test` is merged into `source`.
4. CI builds the script and pushes it to `source-build` for production.
5. Developer creates a PR from `source-build` to `master`.

## Versioning

The project follows semantic versioning in the format `X.Y.Z`:

- **X** = the current year, in `YY` format.
- **Y** = the number of CVEs supported by the script, which corresponds to the number of files under `src/vulns/`.
- **Z** = `MMDDVAL`, where `MMDD` is the UTC build date and `VAL` is a 3-digit value (000–999) that increases monotonically throughout the day, computed as `seconds_since_midnight_UTC * 1000 / 86400`.

The version is patched automatically by `build.sh` into the `VERSION=` variable of the assembled script. The source file (`src/libs/001_core_header.sh`) carries a placeholder value that is overwritten at build time.

## Linting and Testing

```bash
# Assemble the final script
make build

# Lint the generated script
make fmt-check shellcheck

# Run the script (requires root for full results)
sudo ./spectre-meltdown-checker.sh

# Run specific tests that we might have just added (variant name)
sudo ./spectre-meltdown-checker.sh --variant l1tf --variant taa

# Run specific tests that we might have just added (CVE name)
sudo ./spectre-meltdown-checker.sh --cve CVE-2018-3640 --cve CVE-2022-40982

# Batch JSON mode (comprehensive output)
sudo ./spectre-meltdown-checker.sh --batch json | python3 -m json.tool

# Batch JSON terse mode (legacy flat array)
sudo ./spectre-meltdown-checker.sh --batch json-terse | python3 -m json.tool

# Update microcode firmware database
sudo ./spectre-meltdown-checker.sh --update-fwdb

# Docker
docker-compose build && docker-compose run --rm spectre-meltdown-checker
```

There is no separate test suite. CI (`.github/workflows/check.yml`) runs shellcheck, tab-indentation checks, a live execution test validating 19 CVEs, Docker builds, and a firmware DB update test that checks for temp file leaks.

## Architecture

The entire tool is a single bash script with no external script dependencies. Key structural sections:

- **Output/logging functions** (~line 253): `pr_warn`, `pr_info`, `pr_verbose`, `pr_debug`, `explain`, `pstatus`, `pvulnstatus` - verbosity-aware output with color support
- **CPU detection** (~line 2171): `parse_cpu_details`, `is_intel`/`is_amd`/`is_hygon`, `read_cpuid`, `read_msr`, `is_cpu_smt_enabled` - hardware identification via CPUID/MSR registers
- **Kernel architecture detection** (`src/libs/365_kernel_arch.sh`): `is_arm_kernel`/`is_x86_kernel` - detects the **target kernel's** architecture (not the host CPU) using kernel artifacts (System.map symbols, kconfig, kernel image), with `cpu_vendor` as a fast path for live mode. Results are cached in `g_kernel_arch`. Use these helpers to guard arch-specific kernel/kconfig/System.map checks and to select the appropriate verdict messages. In no-hw mode, the target kernel may differ from the host CPU architecture.
- **CPU architecture detection** (`src/libs/360_cpu_smt.sh`): `is_x86_cpu`/`is_arm_cpu` - detects the **host CPU's** architecture via `cpu_vendor`. Use these to gate hardware operations (CPUID, MSR, microcode) that require the physical CPU to be present. Always use positive logic: `if is_x86_cpu` (not `if ! is_arm_cpu`). These two sets of helpers are independent — a vuln check may need both, each guarding different lines.
- **Microcode database** (embedded): Intel/AMD microcode version lookup via `read_mcedb`/`read_inteldb`; updated automatically via `.github/workflows/autoupdate.yml`
- **Kernel analysis** (~line 1568): `extract_kernel`, `try_decompress` - extracts and inspects kernel images (handles gzip, bzip2, xz, lz4, zstd compression)
- **Vulnerability checks**: 19 `check_CVE_<year>_<number>()` functions, each with `_linux()` and `_bsd()` variants. Uses whitelist logic (assumes affected unless proven otherwise)
- **Batch output emitters** (`src/libs/250_output_emitters.sh`): `_emit_json_full`, `_emit_json_terse`, `_emit_text`, `_emit_nrpe`, `_emit_prometheus`, plus JSON section builders (`_build_json_meta`, `_build_json_system`, `_build_json_cpu`, `_build_json_cpu_microcode`)
- **Main flow** (~line 6668): Parse options → detect CPU → loop through requested CVEs → output results (text/json/json-terse/nrpe/prometheus) → cleanup

### JSON Batch Output Formats

Two JSON formats are available via `--batch`:

- **`--batch json`** (comprehensive): A top-level object with five sections:
  - `meta` — script version, format version, timestamp, `mode` (`live`, `no-runtime`, `no-hw`, `hw-only`), run mode flags (`run_as_root`, `reduced_accuracy`, `mocked`, `paranoid`, `sysfs_only`, `extra`)
  - `system` — kernel release/version/arch/cmdline, CPU count, SMT status, hypervisor host detection
  - `cpu` — `arch` discriminator (`x86` or `arm`), vendor, friendly name, then an arch-specific sub-object (`cpu.x86` or `cpu.arm`) with identification fields (family/model/stepping/CPUID/codename for x86; part\_list/arch\_list for ARM) and a `capabilities` sub-object containing hardware flags as booleans/nulls
  - `cpu_microcode` — `installed_version`, `latest_version`, `microcode_up_to_date`, `is_blacklisted`, firmware DB source/info
  - `vulnerabilities` — array of per-CVE objects: `cve`, `name`, `aliases`, `cpu_affected`, `status`, `vulnerable`, `info`, `sysfs_status`, `sysfs_message`

- **`--batch json-terse`** (legacy): A flat array of objects with four fields: `NAME`, `CVE`, `VULNERABLE` (bool/null), `INFOS`. This is the original format, preserved for backward compatibility.

The comprehensive format is built in two phases: static sections (`meta`, `system`, `cpu`, `cpu_microcode`) are assembled after `check_cpu()` completes, and per-CVE entries are accumulated during the main CVE loop via `_emit_json_full()`. The sysfs data for each CVE is captured by `sys_interface_check()` into `g_json_cve_sysfs_status`/`g_json_cve_sysfs_msg` globals, which are read by the emitter and reset after each CVE to prevent cross-CVE leakage. CPU affection is determined via the already-cached `is_cpu_affected()`.

When adding new `cap_*` variables (for a new CVE or updated hardware support), they must be added to `_build_json_cpu()` in `src/libs/250_output_emitters.sh`. Per-CVE data is handled automatically.

## Key Design Principles

These rules are non-negotiable and govern how every part of the script is written:

### 1. Production-safe

It must always be okay to run this script in a production environment.

- **1a. Non-destructive**: Never modify the system. If the script loads a kernel module it needs (e.g. `cpuid`, `msr`), it must unload it on exit.
- **1b. Report only**: Never attempt to "fix" or "mitigate" any vulnerability, or modify any configuration. The script reports status and leaves all decisions to the sysadmin.
- **1c. No exploit execution**: Never run any kind of exploit or proof-of-concept. This would violate rule 1a, could cause unpredictable system behavior, and may produce wrong conclusions (especially for Spectre-class PoCs that require very specific build options and prerequisites).

### 2. Never hardcode kernel versions

Never look at the kernel version string to determine whether it supports a mitigation. This would defeat the script's purpose: it must detect mitigations in unknown, vendor-patched, or backported kernels. Similarly, do not blindly trust what `sysfs` reports when it is possible to verify directly.

### 3. Never hardcode microcode versions (with one exception)

Never look at the microcode version to determine whether it has the proper mitigation mechanisms. Instead, probe for the mechanisms themselves (CPUID bits, MSR values), as the kernel would.

**Exception**: When a vulnerability is fixed purely by a microcode update and the fix exposes **no** detectable CPUID bit, MSR bit, or ARCH\_CAP flag, then we must hardcode the known-fixing microcode versions for each affected CPU stepping. In this case, build a `<vuln>_ucode_list` table of `FF-MM-SS/platformid_mask,fixed_ucode_version` tuples (sourced from the Intel affected processor list and the Intel-Linux-Processor-Microcode-Data-Files release notes), match against `cpu_cpuid` + `cpu_platformid` in `is_cpu_affected()`, and store the required version in a `g_<vuln>_fixed_ucode_version` global. The CVE check then compares `cpu_ucode` against this threshold. Because Intel never lists EOL CPUs, the microcode list may be incomplete: keep a model blacklist as a fallback so that affected CPUs without a known fix are still flagged as affected (the CVE check should handle the empty `g_<vuln>_fixed_ucode_version` case by reporting VULN with "no microcode update available"). See Reptar (`g_reptar_fixed_ucode_version`) and BPI (`g_bpi_fixed_ucode_version`) for reference implementations.

### 4. `/proc/cpuinfo` fallback for CPUID reads

The primary way to read CPU capability bits is via `read_cpuid` (which uses `/dev/cpu/N/cpuid`). However, this device may be unavailable — most commonly inside virtual machines where the `cpuid` kernel module cannot be loaded. When `read_cpuid` returns `READ_CPUID_RET_ERR` (could not read at all), we can fall back to checking `/proc/cpuinfo` flags as a secondary source, **in live mode only**.

This works because the kernel always has direct access to CPUID (it doesn't need `/dev/cpu`), and exposes the results as flags in `/proc/cpuinfo`. When a hypervisor virtualizes a CPUID bit for the guest, the guest kernel sees it and reports it in `/proc/cpuinfo`. This is the same information `read_cpuid` would return if the device were available.

**Rules:**
- This is strictly a fallback: `read_cpuid` via `/dev/cpu/N/cpuid` remains the primary method.
- Only use it when `read_cpuid` returned `READ_CPUID_RET_ERR` (device unavailable), **never** when it returned `READ_CPUID_RET_KO` (device available but bit is 0 — meaning the CPU/hypervisor explicitly reports the feature as absent).
- Only in live mode (`$g_mode = live`), since `/proc/cpuinfo` is not available in other modes.
- Only for CPUID bits that the kernel exposes as `/proc/cpuinfo` flags. Not all bits have a corresponding flag — only those listed in the kernel's `capflags.c`. If a bit has no `/proc/cpuinfo` flag, no fallback is possible.
- The fallback depends on the running kernel being recent enough to know about the CPUID bit in question. An older kernel won't expose a flag it doesn't know about, so the fallback will silently not trigger — which is fine (we just stay at UNKNOWN, same as the ERR case without fallback).

**Known mappings** (CPUID bit → `/proc/cpuinfo` flag → script `cap_*` variable):

| CPUID source | `/proc/cpuinfo` flag | `cap_*` variable |
|---|---|---|
| Intel 0x7.0.EDX[26] / AMD 0x80000008.EBX[14] | `ibrs` | `cap_ibrs` |
| AMD 0x80000008.EBX[12] | `ibpb` | `cap_ibpb` |
| Intel 0x7.0.EDX[27] / AMD 0x80000008.EBX[15] | `stibp` | `cap_stibp` |
| Intel 0x7.0.EDX[31] / AMD 0x80000008.EBX[24,25] | `ssbd` / `virt_ssbd` | `cap_ssbd` |
| Intel 0x7.0.EDX[28] | `flush_l1d` | `cap_l1df` |
| Intel 0x7.0.EDX[10] | `md_clear` | `cap_md_clear` |
| Intel 0x7.0.EDX[29] | `arch_capabilities` | `cap_arch_capabilities` |

**Implementation pattern** in `check_cpu()`:

```sh
read_cpuid 0x7 0x0 $EDX 31 1 1
ret=$?
if [ $ret = $READ_CPUID_RET_OK ]; then
    cap_ssbd='Intel SSBD'
elif [ $ret = $READ_CPUID_RET_ERR ] && [ "$g_mode" = live ]; then
    # CPUID device unavailable (e.g. in a VM): fall back to /proc/cpuinfo
    if grep ^flags "$g_procfs/cpuinfo" | grep -qw ssbd; then
        cap_ssbd='Intel SSBD (cpuinfo)'
        ret=$READ_CPUID_RET_OK
    fi
fi
```

When the fallback sets a `cap_*` variable, append ` (cpuinfo)` to the value string so the output makes it clear the information was derived from `/proc/cpuinfo` rather than read directly from hardware. Update `ret` to `READ_CPUID_RET_OK` so downstream status display logic (`pstatus`) reports YES rather than UNKNOWN.

### 5. Assume affected unless proven otherwise (whitelist approach)

When a CPU is not explicitly known to be unaffected by a vulnerability, assume that it is affected. This conservative default has been the right call since the early Spectre/Meltdown days and remains sound.

### 6. No-runtime mode

The script can analyze a non-running kernel via `--kernel`, `--config`, `--map` flags, allowing verification before deployment.

## CVE Inclusion Criteria

A vulnerability should be supported by this tool when mitigating it requires **kernel modifications**, **microcode modifications**, or **both**.

A vulnerability is **out of scope** when:

- Mitigation is handled entirely by a driver or userspace software update (e.g. CVE-2019-14615, which requires an Intel driver update).
- The vulnerability is a regression from a bad backport and cannot be detected without hardcoding kernel versions (violates rule 2).
- The vendor has determined it is not a new attack and issued no kernel or microcode changes, leaving nothing for the script to check.
- The industry has collectively decided not to address the vulnerability (no mitigations exist), leaving nothing to verify.

When evaluating whether to add a new CVE, check the [information-tagged issues](https://github.com/speed47/spectre-meltdown-checker/issues?q=is%3Aissue+label%3Ainformation) for prior discussion and precedent.

## POSIX Compliance

The script must run on both Linux and BSD systems (FreeBSD, NetBSD, DragonFlyBSD). This means all external tool invocations must use only POSIX-specified options. Many tools have GNU extensions that are not available on BSD, or BSD extensions that are not available on GNU/Linux. When in doubt, test on both.

Common traps to avoid:

| Tool | Non-portable usage | Portable alternative |
|------|--------------------|----------------------|
| `sed` | `-r` (GNU extended regex flag) | `-E` (accepted by both GNU and BSD) |
| `grep` | `-P` (Perl regex, GNU only) | Use `awk` or rework the pattern |
| `sort` | `-V` (version sort, GNU only) | Extract numeric fields and compare with `awk` or shell arithmetic |
| `cut` | `-w` (whitespace delimiter, BSD only) | `awk '{print $N}'` |
| `stat` | `-c %Y` (GNU format) | Try GNU first, fall back to BSD: `stat -c %Y ... 2>/dev/null \|\| stat -f %m ...` |
| `date` | `-d @timestamp` (GNU only) | Try GNU first, fall back to BSD: `date -d @ts ... 2>/dev/null \|\| date -r ts ...` |
| `xargs` | `-r` (no-op if empty, GNU only) | Guard with a prior `[ -n "..." ]` check, or accept the harmless empty invocation |
| `readlink` | `-f` (canonicalize, GNU only) | Use only in Linux-specific code paths, or reimplement with `cd`/`pwd` |
| `dd` | `iflag=`, `oflag=` (GNU only) | Use only in Linux-specific code paths (e.g. `/dev/cpu/*/msr`) |
| `base64` | `-w N` (set line-wrap width, GNU only; BusyBox doesn't support it) | Pipe through `tr -d '\n'` to remove newlines instead of `-w0` |

When a tool genuinely has no portable equivalent, restrict the non-portable call to a platform-specific code path (i.e. inside a BSD-only or Linux-only branch) and document why.

## Return Codes

0 = not vulnerable, 2 = vulnerable, 3 = unknown, 255 = error

## Variable naming conventions

This script uses the following naming rules for variables:

`UPPER_SNAKE_CASE`  : Constants and enums (e.g. READ_MSR_RET_OK, EAX), declared with `readonly` on the assignment line (e.g. `readonly FOO="bar"`).
                      When they're used as values affected to "Out-parameters" of a function, they should follow the `<FUNC>_RET_*` pattern.
                      Such variables should be declared right above the definition of the function they're dedicated to.
                      Other general constants go at the top of the file, below the `VERSION` affectation.
`opt_*`             : Command-line options set during argument parsing (e.g. opt_verbose, opt_batch).
`cpu_*`             : CPU identification/state filled by parse_cpu_details() (e.g. cpu_family, cpu_model).
`cap_*`             : CPU capability flags read from hardware/firmware (e.g. cap_verw_clear, cap_rdcl_no).
                      All `cap_*` variables are set in `check_cpu()`. They come in two flavors:
                      - **Immunity bits** (`cap_*_no`): The CPU vendor declares this hardware is not affected by a vulnerability.
                        The `_no` suffix mirrors the vendor's own bit naming (e.g. RDCL_NO, GDS_NO, TSA_SQ_NO).
                        These are consumed in `is_cpu_affected()` to mark a CPU as immune.
                      - **Mitigation bits** (all other `cap_*`): Microcode or hardware provides a mechanism to work around
                        a vulnerability the CPU *does* have (e.g. cap_verw_clear, cap_ibrs, cap_ssbd).
                        These are consumed in `check_CVE_*_linux()` functions to assess mitigation status.
`affected_*`        : Per-CVE vulnerability status from is_cpu_affected() (e.g. affected_l1tf).
`ret_<func>_*`      : "Out-parameters" set by a function for its caller (e.g. ret_read_cpuid_value, ret_read_msr_msg).
                        The <func> matches the function name so ownership is obvious, these variables can't be written
                        to by any other function than <func>, nor by toplevel.
`g_*`               : Other global (i.e. non-`local`) variables that don't match cases previously described.
`<name>`            : Scratch/temporary variables inside functions (e.g. core, msg, col).
                        These must be declared as `local`. These must not match any naming pattern above.
                        Any variable that is only used in the scope of a given function falls in this category.

Additionally, all vars must start with a [a-z] character, never by an underscore.

## Function naming conventions

Functions follow two naming tiers:

`public_function`   : Top-level functions called directly from the main flow or from other public functions.
                      Examples: `parse_cpu_details`, `read_cpuid`, `check_CVE_2017_5754`.

`_private_function` : Utility/helper functions that exist solely to factorize code shared by other functions.
                      These must never be called directly from the top-level main flow.
                      Examples: `_echo`, `_emit_json`, `_cve_registry_field`.

## How to Implement a New CVE Check

Adding a new CVE follows a fixed pattern. Every check uses the same three-function structure and the same decision algorithm. This section walks through both.

### Prerequisites

Before writing code, verify the CVE meets the inclusion criteria (see "CVE Inclusion Criteria" above). The vulnerability must require kernel and/or microcode changes to mitigate.

### Step 1: Create the Vulnerability File

Create `src/vulns/CVE-YYYY-NNNNN.sh`. When no real CVE applies, two placeholder ranges are reserved:

- **`CVE-0000-NNNN`** — permanent placeholder for supplementary `--extra`-only checks that will never receive a real CVE (e.g. SLS / compile-time hardening).
- **`CVE-9999-NNNN`** — temporary placeholder for real vulnerabilities awaiting CVE assignment. Once the real CVE is issued, rename the file, the registry entry, the `--variant` alias, and the function symbols across the codebase.

The file header must follow this exact format:

- **Line 1**: vim modeline (`# vim: set ts=4 sw=4 sts=4 et:`)
- **Line 2**: 31 `#` characters (`###############################`)
- **Line 3**: `# CVE-YYYY-NNNNN, Alias1, Alias2, Complete Name` — the CVE number followed by
  all known aliases and the complete name as listed in the `dist/README.md` top table.
- **Line 4**: empty

The file must contain exactly three functions:

```sh
# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-YYYY-NNNNN, Short Name, Complete Name

check_CVE_YYYY_NNNNN() {
	check_cve 'CVE-YYYY-NNNNN'
}

check_CVE_YYYY_NNNNN_linux() {
	# ... (see Step 3)
}

check_CVE_YYYY_NNNNN_bsd() {
	if ! is_cpu_affected "$cve"; then
		pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
	else
		pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
	fi
}
```

The entry point calls `check_cve`, which prints the CVE header and dispatches to `_linux()` or `_bsd()` based on `$g_os`. If BSD mitigations are not yet understood, use the stub above - it correctly reports UNK rather than a false OK.

### Step 2: Register the CVE in the CPU Affection Logic

In `src/libs/200_cpu_affected.sh`, add an `affected_yourname` variable and populate it inside `is_cpu_affected()`. The variable follows the whitelist principle: **assume affected (`1`) unless you can prove the CPU is immune (`0`)**. Two kinds of evidence can prove immunity:

- **Static identifiers**: CPU vendor, family, model, stepping - these identify the hardware design.
- **Hardware immunity `cap_*` bits**: CPUID or MSR bits that the CPU vendor defines to explicitly declare "this hardware is not affected" (e.g. `cap_rdcl_no` for Meltdown, `cap_ssb_no` for Variant 4, `cap_gds_no` for Downfall, `cap_tsa_sq_no`/`cap_tsa_l1_no` for TSA). These are read in `check_cpu()` and stored as `cap_*` globals.

Never use microcode version strings.

When populating the CPU model list, use the **most recent version** of the Linux kernel source as the authoritative reference. The relevant lists are typically found in `arch/x86/kernel/cpu/common.c` (`cpu_vuln_blacklist`) or in the vulnerability-specific mitigation source file. Cross-reference the kernel list with the vendor's published advisory to catch any models the kernel hasn't added yet. Always document the kernel commit hash(es) you based the list on in a comment above the model checks, so future maintainers can diff against newer kernels.

**Important**: Do not confuse hardware immunity bits with *mitigation* capability bits. A hardware immunity bit (e.g. `GDS_NO`, `TSA_SQ_NO`) declares that the CPU design is architecturally free of the vulnerability - it belongs here in `is_cpu_affected()`. A mitigation capability bit (e.g. `VERW_CLEAR`, `MD_CLEAR`) indicates that updated microcode provides a mechanism to work around a vulnerability the CPU *does* have - it belongs in the `check_CVE_YYYY_NNNNN_linux()` function (Phase 2), where it is used to determine whether mitigations are in place.

**JSON output**: If the new CVE introduces new `cap_*` variables in `check_cpu()` (whether immunity bits or mitigation bits), these must also be added to the `_build_json_cpu()` function in `src/libs/250_output_emitters.sh`, inside the `capabilities` sub-object. Use the same name as the shell variable without the `cap_` prefix (e.g. `cap_tsa_sq_no` becomes `"tsa_sq_no"` in JSON), and emit it via `_json_cap`. The per-CVE vulnerability data (affection, status, sysfs) is handled automatically by the existing `_emit_json_full()` function and requires no changes when adding a new CVE.

### Step 3: Implement the Linux Check

The `_linux()` function follows a standard algorithm with four phases:

**Phase 1 - Initialize and check sysfs:**

```sh
check_CVE_YYYY_NNNNN_linux() {
	local status sys_interface_available msg
	status=UNK
	sys_interface_available=0
	msg=''
	if sys_interface_check "$VULN_SYSFS_BASE/vuln_name"; then
		sys_interface_available=1
		status=$ret_sys_interface_check_status
	fi
```

`sys_interface_check` reads `/sys/devices/system/cpu/vulnerabilities/<name>` and parses the kernel's own assessment into `ret_sys_interface_check_status` (OK/VULN/UNK) and `ret_sys_interface_check_fullmsg`. If the sysfs file doesn't exist (older kernel, or the CVE predates kernel awareness), it returns false and `sys_interface_available` stays 0.

**Phase 2 - Custom detection (kernel + runtime):**

Guarded by `if [ "$opt_sysfs_only" != 1 ]; then` so users who trust sysfs can skip it.

This is where the real detection lives. Check for mitigations at each layer:

- **Kernel support**: Determine whether the kernel carries the mitigation code. Three sources of evidence are available, and any one of them is sufficient:

  - **Kernel image** (`$g_kernel`): Search for strings or symbols that prove the mitigation code is compiled in.
    ```sh
    if grep -q 'mitigation_string' "$g_kernel"; then
        kernel_mitigated="found mitigation evidence in kernel image"
    fi
    ```
    Guard with `if [ -n "$g_kernel_err" ]; then` first - the kernel image may be unavailable.

  - **Kernel config** (`$opt_config`): Look for the `CONFIG_*` option that enables the mitigation.
    ```sh
    if [ -n "$opt_config" ] && grep -q '^CONFIG_MITIGATION_NAME=y' "$opt_config"; then
        kernel_mitigated="found mitigation config option enabled"
    fi
    ```

  - **System.map** (`$opt_map`): Look for function names directly linked to the mitigation.
    ```sh
    if [ -n "$opt_map" ] && grep -q 'mitigation_function_name' "$opt_map"; then
        kernel_mitigated="found mitigation function in System.map"
    fi
    ```

  Each source may independently be unavailable (no-runtime mode without the file, or stripped kernel), so check all that are present. A match in any one confirms kernel support.

  **Architecture awareness:** Kernel symbols, kconfig options, and kernel-image strings are architecture-specific. An x86 host may be inspecting an ARM kernel (or vice versa) in offline mode, so always use positive-logic arch guards from `src/libs/365_kernel_arch.sh` and `src/libs/360_cpu_smt.sh`. This prevents searching for irrelevant strings (e.g. x86 `spec_store_bypass` in an ARM kernel image) and ensures verdict messages and `explain` text match the target architecture (e.g. "update CPU microcode" for x86 vs "update firmware for SMCCC ARCH_WORKAROUND_2" for ARM).

  Use **positive logic** — always `if is_x86_kernel` (not `if ! is_arm_kernel`) and `if is_x86_cpu` (not `if ! is_arm_cpu`). This ensures unknown architectures (MIPS, RISC-V, PowerPC) are handled safely by defaulting to "skip" rather than "execute."

  Two sets of helpers serve different purposes — in no-hw mode the host CPU and the kernel being inspected can be different architectures, so the correct guard depends on what is being checked:
  - **`is_x86_kernel`/`is_arm_kernel`**: Gate checks that inspect **kernel artifacts** (kernel image strings, kconfig, System.map). These detect the architecture of the target kernel, not the host, so they work correctly in offline/no-hw mode when analyzing a foreign kernel.
  - **`is_x86_cpu`/`is_arm_cpu`**: Gate **hardware operations** that require the host CPU to be a given architecture (CPUID, MSR reads, `/proc/cpuinfo` flags, microcode version checks). These always reflect the running host CPU.
  - Within a single vuln check, you may need **both** guards independently — e.g. `is_x86_cpu` for the microcode/MSR check and `is_x86_kernel` for the kernel image grep, not one wrapping the other.

  Example:
  ```sh
  # x86-specific kernel image search
  if [ -n "$g_kernel" ] && is_x86_kernel; then
      mitigation=$("${opt_arch_prefix}strings" "$g_kernel" | grep x86_specific_string)
  fi
  # ARM-specific System.map search
  if [ -n "$opt_map" ] && is_arm_kernel; then
      mitigation=$(grep -w arm_mitigation_function "$opt_map")
  fi
  # x86-specific hardware read
  if is_x86_cpu; then
      read_cpuid 0x7 0x0 "$EDX" 26 1 1
  fi
  ```
  The same applies to Phase 4 verdict messages: when the explanation or remediation advice differs between architectures (e.g. "CPU microcode update" vs "firmware/kernel update"), branch on `is_arm_kernel`/`is_x86_kernel` rather than on `cpu_vendor`, because `cpu_vendor` reflects the host, not the target kernel.

- **Runtime state** (live mode only): Read MSRs, check cpuinfo flags, parse dmesg, inspect debugfs. All runtime-only checks — including `/proc/cpuinfo` flags — must be guarded by `if [ "$g_mode" = live ]`, both when collecting the evidence in Phase 2 and when using it in Phase 4. In Phase 4, use explicit live/non-live branches so that live-only variables (e.g. cpuinfo flags, MSR values) are never referenced in the non-live path.
  ```sh
  if [ "$g_mode" = live ]; then
      read_msr 0xADDRESS
      ret=$?
      if [ "$ret" = "$READ_MSR_RET_OK" ]; then
          # check specific bits in ret_read_msr_value_lo / ret_read_msr_value_hi
      fi
  else
      pstatus blue N/A "not testable in non-live mode"
  fi
  ```

- **Microcode capabilities**: Check CPUID bits or MSR flags that indicate the CPU firmware supports the mitigation. Never compare microcode version numbers directly.

Close the `opt_sysfs_only` block with the forced-sysfs fallback:
```sh
	elif [ "$sys_interface_available" = 0 ]; then
		msg="/sys vulnerability interface use forced, but it's not available!"
		status=UNK
	fi
```

**Phase 3 - CPU affection gate:**

```sh
	if ! is_cpu_affected "$cve"; then
		pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
```

If the CPU is not affected, nothing else matters - report OK and return. This overrides any sysfs or custom detection result.

**Phase 4 - Final status determination:**

For affected CPUs, combine the evidence from Phase 2 into a final verdict. The dispatch
works through `msg`: if Phase 1 (sysfs) or a sysfs override set `msg` to non-empty, use
it directly; otherwise run own logic or fall back to the raw sysfs result.

```sh
	elif [ -z "$msg" ]; then
		# msg is empty: sysfs either wasn't available, or gave a standard
		# response that wasn't overridden. Use our own logic when we have it.
		if [ "$opt_sysfs_only" != 1 ]; then
			# --- own logic using Phase 2 variables ---
			if [ "$microcode_ok" = 1 ] && [ -n "$kernel_mitigated" ]; then
				pvulnstatus "$cve" OK "Both kernel and microcode mitigate the vulnerability"
			else
				pvulnstatus "$cve" VULN "Neither kernel nor microcode mitigate the vulnerability"
				explain "Remediation advice here..."
			fi
		else
			# --sysfs-only: Phase 2 variables are unset, fall back to the
			# raw sysfs result (status + fullmsg were set in Phase 1).
			pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
		fi
	else
		# msg was explicitly set - either by the "sysfs not available" elif
		# above, or by a sysfs override in Phase 1. Use it as-is.
		pvulnstatus "$cve" "$status" "$msg"
	fi
}
```

The `opt_sysfs_only` guard inside the `[ -z "$msg" ]` branch is **critical**: without it,
`--sysfs-only` mode would fall into own-logic with all Phase 2 variables unset, producing
wrong results. The `else` at line `pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"`
is safe because it is only reachable when sysfs was available (if it wasn't, the "sysfs not
available" `elif` at the end of Phase 2 would have set `msg`, sending us to the other branch).

The exact combination logic depends on the CVE. Some require **both** microcode and kernel fixes (report VULN if either is missing). Others are mitigated by **either** layer alone (report OK if one is present). Some also require SMT to be disabled - check with `is_cpu_smt_enabled()`.

**Sysfs overrides:** When the kernel's sysfs reporting is known to be incorrect for certain
messages (e.g. old kernels misclassifying a partial mitigation as fully mitigated), add an
override in Phase 1 after `sys_interface_check` returns. The override sets both `status` and
`msg`, which routes Phase 4 to the `else` branch - bypassing own logic entirely. This is
correct because the override and own logic will always agree on the verdict. Example:

```sh
	if sys_interface_check "$VULN_SYSFS_BASE/vuln_name"; then
		sys_interface_available=1
		status=$ret_sys_interface_check_status
		# Override: old kernels (before <commit>) incorrectly reported this as mitigated
		if echo "$ret_sys_interface_check_fullmsg" | grep -qi 'Mitigation:.*partial mitigation.*missing piece'; then
			status=VULN
			msg="Vulnerable: partial mitigation, missing piece (your kernel incorrectly reports this as mitigated, it was fixed in more recent kernels)"
		fi
	fi
```

When adding a sysfs override, also add an `explain` call in the `else` branch of Phase 4
(where `msg` is non-empty) to tell the user why the kernel says "Mitigated" while the script
reports vulnerable. Additionally, in Phase 2, add a kernel-image grep to inform the user
whether their kernel has the corrected reporting (the post-fix kernel will contain the new
vulnerability string in its image).

**Kernel source inventory:** Before writing any code, audit the kernel source history for
four categories of information that the script consumes in different modes:

1. **Sysfs messages** — every version of the string the kernel has ever produced for
   `/sys/devices/system/cpu/vulnerabilities/<name>`. Used in live mode to parse the
   kernel's own assessment, and in no-runtime mode to grep for known strings in `$g_kernel`.
2. **Kconfig option names** — every `CONFIG_*` symbol that enables or controls the
   mitigation. Used in no-runtime mode to check `$opt_config`. Kconfig names change over
   time (e.g. `CONFIG_GDS_FORCE_MITIGATION` → `CONFIG_MITIGATION_GDS_FORCE` →
   `CONFIG_MITIGATION_GDS`), and vendor kernels may use their own names, so all variants
   must be catalogued.
3. **Kernel function names** — functions introduced specifically for the mitigation (e.g.
   `gds_select_mitigation`, `gds_apply_mitigation`, `l1tf_select_mitigation`). Used in
   no-runtime mode to check `$opt_map` (System.map): the presence of a mitigation function
   proves the kernel was compiled with the mitigation code, even if the config file is
   unavailable.
4. **CPU affection logic** — the complete algorithm the kernel uses to decide whether a
   CPU is affected by the vulnerability (i.e. whether it sets the `X86_BUG_*` flag). This
   is what the script must replicate in `is_cpu_affected()`. The kernel typically uses a
   combination of:
   - **Model blacklists/whitelists**: explicit lists of CPU vendor/family/model/stepping
     values (e.g. `cpu_vuln_blacklist[]` in `arch/x86/kernel/cpu/common.c`). These lists
     can change between kernel versions — models may be added when new errata surface
     (e.g. client Skylake was initially missing from GDS and added in a follow-up commit).
   - **MSR/CPUID immunity bits**: hardware bits that the CPU vendor defines to declare
     "this hardware is not affected" (e.g. `ARCH_CAP_GDS_NO`, `ARCH_CAP_RDCL_NO`). These
     bits are already read in `check_cpu()` and stored as `cap_*_no` globals.
   - **Feature dependencies**: some vulnerabilities only apply when a specific CPU feature
     is present (e.g. GDS requires AVX because GATHER instructions need it; TAA requires
     TSX). If the feature is absent or disabled, the CPU is immune.
   - **Vendor scoping**: most vulnerabilities are vendor-specific (Intel-only, AMD-only),
     but some span multiple vendors. Document which vendors are checked.

   The inventory must trace how this logic evolved across kernel versions, because models
   are sometimes added in follow-up commits (as with Skylake for GDS) and the script must
   include the most complete and up-to-date list. Document every commit that changed the
   model list or the affection conditions.

The script may run on any kernel — from early release candidates that first introduced
support, through every stable release, up to the latest mainline, as well as vendor kernels
(RHEL, SUSE, Ubuntu, etc.). The inventory must catalogue every variant across all of these,
including:

- Messages/configs/functions that only existed briefly between two commits in the same
  release cycle.
- Format changes (e.g. field reordering, renamed labels, renamed Kconfig symbols).
- New states added in later kernels (e.g. new flush modes, new mitigation strategies).
- Reporting corrections where a later kernel changed its assessment of what counts as
  mitigated (e.g. a message that said `"Mitigation: ..."` in kernel A is reclassified as
  `"Vulnerable: ..."` in kernel B under the same conditions).
- Functions that were added, renamed, or split across commits (e.g. a single
  `gds_mitigation_update()` later split into `gds_select_mitigation()` +
  `gds_apply_mitigation()`).
- CPU model list changes (models added or removed from the vulnerability blacklist in
  follow-up commits or stable backports).

Document all discovered variants as comments in the CVE file, grouped by the kernel commit
that introduced or changed them, so future readers can understand the evolution at a glance.
See `src/vulns/CVE-2018-3646.sh` (Phase 1 comment block) for a reference example.

This inventory matters because later kernels may have a different — and more accurate — view
of what is vulnerable versus mitigated for a given vulnerability, as understanding progresses
over time. The script must be able to reach the same conclusions as the most recent kernel,
even when running under an old kernel that misreports a vulnerability as mitigated. This is
exactly what sysfs overrides (described above) are for: when the inventory reveals that an
old kernel's message is now known to be wrong, add an override in Phase 1 to correct the
status, and use the Phase 2 kernel-image grep to tell the user whether their kernel has the
corrected reporting.

**How to build the inventory - git blame walkback method:**

The goal is to find every commit that changed the sysfs output strings, Kconfig symbols,
mitigation function names, or CPU affection logic for a given vulnerability. The method uses
`git blame` iteratively, walking backwards through history until the vulnerability's support
no longer exists.

1. **Locate the relevant code.** Most vulnerability code lives in two files:
   `arch/x86/kernel/cpu/bugs.c` (mitigation logic and sysfs reporting) and
   `arch/x86/kernel/cpu/common.c` (CPU affection detection). Find:
   - The `*_show_state()` function for the vulnerability (e.g. `l1tf_show_state()`,
     `mds_show_state()`) and the corresponding `case X86_BUG_*` in `cpu_show_common()`.
     Both paths can produce messages: the show_state function handles the mitigated cases,
     while `cpu_show_common()` handles `"Not affected"` (common to all bugs) and
     `"Vulnerable"` (fallthrough). Some vulnerabilities also use string arrays (e.g.
     `l1tf_vmx_states[]`, `spectre_v1_strings[]`) — include those in the audit.
   - The `*_select_mitigation()` and `*_apply_mitigation()` functions (or a single
     `*_update_mitigation()` in older code). These are the function names that appear in
     System.map and can be checked via `$opt_map`.
   - The `Kconfig` entries: search `arch/x86/Kconfig` (and `arch/x86/Kconfig.cpu` or
     similar) for `CONFIG_*` symbols related to the mitigation. Note every name variant
     across kernel versions.
   - The **CPU affection detection** in `arch/x86/kernel/cpu/common.c`: find where
     `X86_BUG_<name>` is set. This typically involves a lookup in `cpu_vuln_blacklist[]`
     (or `cpu_vuln_whitelist[]`) combined with checks on `IA32_ARCH_CAPABILITIES` MSR
     bits and CPU feature flags. Document:
     - The complete model list (vendor, family, model, stepping ranges).
     - Which `ARCH_CAP_*` bits grant immunity (e.g. `ARCH_CAP_GDS_NO`).
     - Which CPU features are prerequisites (e.g. AVX for GDS, TSX for TAA).
     - Any other conditions (hypervisor detection, microcode version checks, etc.).
     - How this logic evolved: models added/removed in follow-up commits.

2. **Blame the current code.** Run `git blame` on the relevant line range:

   ```
   git blame -L<start>,<end> arch/x86/kernel/cpu/bugs.c
   ```

   For each line that contributes to the sysfs output (format strings, string arrays, enum
   lookups, conditional branches that select different messages), note the commit hash.

3. **Walk back one commit at a time.** For each commit found in step 2, check the state of
   the file **before** that commit to see what changed:

   ```
   git show <commit>^:arch/x86/kernel/cpu/bugs.c | grep -n -A10 '<function_name>'
   ```

   Compare the output strings, format patterns, and conditional logic with the version after
   the commit. Record any differences: added/removed/renamed states, reordered fields,
   changed conditions.

4. **Repeat until the vulnerability disappears.** Take the oldest commit found and check the
   parent. Eventually you reach a version where the `case X86_BUG_*` for this vulnerability
   does not exist - that is the boundary.

5. **Watch for non-obvious string changes.** Some commits change the output without touching
   the format strings themselves:
   - **Condition changes**: A commit may change *when* a branch is taken (e.g. switching from
     `cpu_smt_control == CPU_SMT_ENABLED` to `sched_smt_active()`), which changes which
     message appears for the same hardware state, even though the strings are identical.
   - **Enum additions**: A new entry in a string array (e.g. adding `"flush not necessary"` to
     `l1tf_vmx_states[]`) adds a new possible message without changing the format string.
   - **Early returns**: Adding or removing an early-return path changes which messages are
     reachable (e.g. returning `L1TF_DEFAULT_MSG` for `FLUSH_AUTO` before reaching the VMX
     format string).
   - **Mechanical changes**: `sprintf` → `sysfs_emit`, `const` qualifications, whitespace
     reformats - these do not change strings and can be noted briefly or omitted.

6. **Cross-check with `git log`.** After the blame walkback, run a targeted `git log` to
   confirm no commits were missed:

   ```
   git log --all --oneline -- arch/x86/kernel/cpu/bugs.c | xargs -I{} \
     sh -c 'git show {} -- arch/x86/kernel/cpu/bugs.c | grep -q "<vuln_name>" && echo {}'
   ```

   Any commit that touches lines mentioning the vulnerability name should already be in
   your inventory. If one is missing, inspect it.

7. **Audit the stable tree.** After completing the mainline inventory, repeat the process on
   the linux-stable repository (`~/linux-stable`). Stable/LTS branches can carry backports
   that differ from mainline in subtle ways:

   - **Partial backports**: A stable branch may backport the mitigation but not the VMX
     reporting, producing a simpler set of messages than mainline (e.g. 4.4.y has l1tf's
     `"PTE Inversion"` but no VMX flush state reporting at all).
   - **Stable-only commits**: Maintainers sometimes make stable-specific changes that never
     existed in mainline (e.g. renaming a string to match upstream without backporting the
     full commit that originally renamed it).
   - **Backport batching**: Multiple mainline commits may land in the same stable release,
     meaning intermediate formats (that existed briefly between mainline commits) may never
     have shipped in any stable release. Note this when it happens - it narrows the set of
     messages that real-world kernels can produce, but the script should still handle the
     intermediate formats since someone could be running a mainline rc kernel.
   - **Missing backports**: Some stable branches reach EOL before a fix is backported (e.g.
     the `sched_smt_active()` change was not backported to 4.17.y or 4.18.y). This doesn't
     change the strings but can change which message appears for the same hardware state.

   Check each LTS/stable branch that was active when the vulnerability's sysfs support was
   introduced. A quick way to identify relevant branches:

   ```
   cd ~/linux-stable
   for branch in $(git branch -r | grep 'linux-'); do
     count=$(git show "$branch:arch/x86/kernel/cpu/bugs.c" 2>/dev/null | grep -c '<vuln_name>')
     [ "$count" -gt 0 ] && echo "$branch: $count matches"
   done
   ```

   Then for each branch with matches, show the output function and compare it with mainline.
   Document stable-specific differences in a separate `--- stable backports ---` section of
   the inventory comment.

**Comment format in CVE files:**

The inventory comment goes in Phase 1, right after `sys_interface_check` returns successfully.
Group entries chronologically by commit, newest last. For each commit, show the hash, the
kernel version it appeared in, and the exact message(s)/config(s)/function(s) it introduced
or changed. Use `+` to indicate incremental additions to an enum or format. Example:

```sh
    # Kernel source inventory for <vuln>, traced via git blame:
    #
    # --- sysfs messages ---
    # all versions:
    #   "Not affected"                (cpu_show_common, <commit>)
    #   "Vulnerable"                  (cpu_show_common fallthrough, <commit>)
    #
    # <commit> (<version>, <what changed>):
    #   "Mitigation: <original message>"
    # <commit> (<version>, <what changed>):
    #   "Mitigation: <new message format>"
    #     <field>: value1 | value2 | value3
    # <commit> (<version>, <what changed>):
    #     <field>: + value4
    #
    # all messages start with either "Not affected", "Mitigation", or "Vulnerable"
    #
    # --- Kconfig symbols ---
    # <commit> (<version>): CONFIG_ORIGINAL_NAME (y/n)
    # <commit> (<version>): renamed to CONFIG_NEW_NAME
    # <commit> (<version>): replaced by CONFIG_ANOTHER_NAME (on/off, no force)
    # vendor kernels: CONFIG_VENDOR_SPECIFIC_NAME (RHEL 8.x)
    #
    # --- kernel functions (for $opt_map / System.map) ---
    # <commit> (<version>): <vuln>_mitigation_update()
    # <commit> (<version>): split into <vuln>_select_mitigation() + <vuln>_apply_mitigation()
    #
    # --- CPU affection logic (for is_cpu_affected) ---
    # <commit> (<version>, initial model list):
    #   Intel: MODEL_A, MODEL_B, MODEL_C (all steppings)
    #   Intel: MODEL_D (stepping 0x0 - 0x5 only)
    # <commit> (<version>, added missing models):
    #   Intel: + MODEL_E, MODEL_F
    # immunity: ARCH_CAP_<NAME>_NO (bit NN of IA32_ARCH_CAPABILITIES)
    # feature dependency: requires <FEATURE> (if absent, CPU is immune)
    # vendor scope: Intel only (no AMD/Hygon/other entries)
```

The final line of the sysfs section (`all messages start with ...`) is a summary that helps
verify the grep patterns used to derive `status` from the message are complete.

### Cross-Cutting Features

Several command-line options affect the logic inside `_linux()` checks. New CVE implementations must account for them where relevant.

#### `--explain` (`opt_explain`)

When the user passes `--explain`, the `explain()` function prints actionable "How to fix" remediation advice. Call `explain` whenever reporting a VULN status, so the user knows what concrete steps to take:

```sh
pvulnstatus "$cve" VULN "Neither kernel nor microcode mitigate the vulnerability"
explain "Update your kernel to a version that includes the mitigation, and update your CPU microcode. If you are using a distro, make sure you are up to date."
```

The text should be specific: mention kernel parameters to set (`nosmt`), sysctl knobs to toggle, or which component needs updating. If SMT must be disabled, say so explicitly. Multiple `explain` calls can be made for different failure paths, each tailored to the specific gap found. `explain` is a no-op when `--explain` was not passed, so it is always safe to call.

#### `--paranoid` (`opt_paranoid`)

Paranoid mode raises the bar for what counts as "mitigated". In normal mode, conditional mitigations or partial defenses may be accepted as sufficient. In paranoid mode, only the **maximum security configuration** qualifies as OK.

The most common effect is requiring SMT (Hyper-Threading) to be disabled. For example, MDS and TAA mitigations are considered incomplete in paranoid mode if SMT is still enabled, because a sibling thread could still exploit the vulnerability:

```sh
if [ "$opt_paranoid" != 1 ] || [ "$kernel_smt_allowed" = 0 ]; then
    pvulnstatus "$cve" OK "Microcode and kernel mitigate the vulnerability"
else
    pvulnstatus "$cve" VULN "Mitigation is active but SMT must be disabled for full protection"
fi
```

Other paranoid-mode effects include requiring unconditional (rather than conditional) L1D flushing, or requiring TSX to be fully disabled. When implementing a new CVE, consider whether there is a stricter configuration that paranoid mode should enforce and add the appropriate `opt_paranoid` branches.

#### `--vmm` (`opt_vmm`)

The `--vmm` option tells the script whether the system is a hypervisor host running untrusted virtual machines. It accepts three values: `auto` (default, auto-detect by looking for `qemu`/`kvm`/`xen` processes), `yes` (force hypervisor mode), or `no` (force non-hypervisor mode). The result is stored in `g_has_vmm` by the `check_has_vmm()` function.

Some vulnerabilities (e.g. L1TF/CVE-2018-3646, ITLBMH/CVE-2018-12207) only matter - or require additional mitigations - when the host is running a hypervisor with untrusted guests. If `g_has_vmm` is 0, the system can be reported as not vulnerable to these VMM-specific aspects:

```sh
if [ "$g_has_vmm" = 0 ]; then
    pvulnstatus "$cve" OK "this system is not running a hypervisor"
else
    # check hypervisor-specific mitigations (L1D flushing, EPT, etc.)
fi
```

CVEs that need VMM context should call `check_has_vmm` early in their `_linux()` function. Note the interaction with paranoid mode: when `--paranoid` is active and `--vmm` was not explicitly set, the script assumes a hypervisor is present (`g_has_vmm=2`), erring on the side of caution.

### Step 4: Wire Up and Test

1. **Add the CVE to `CVE_REGISTRY`** in `src/libs/002_core_globals.sh` with the correct fields: `CVE-YYYY-NNNNN|JSON_KEY|affected_var_suffix|Complete Name and Aliases`. This is the single source of truth for CVE metadata — it drives `cve2name()`, `is_cpu_affected()`, and the supported CVE list.
2. **Add a `--variant` alias** in `src/libs/230_util_optparse.sh`: add a new `case` entry mapping a short name (e.g. `rfds`, `downfall`) to `opt_cve_list="$opt_cve_list CVE-YYYY-NNNNN"`, and add that short name to the `help)` echo line. The CVE is already selectable via `--cve CVE-YYYY-NNNNN` (this is handled generically by the existing `--cve` parsing code), but the `--variant` alias provides the user-friendly short name.
3. **Update `dist/README.md`**: Add the CVE in **both** tables — the "Supported CVEs" reference table at the top (CVE link, description, alias) **and** the "Am I at risk?" matrix (with the correct leak/mitigation indicators per boundary). Also add a detailed description paragraph in the `<details>` section at the bottom.
4. **Build** the monolithic script with `make`.
5. **Test live**: Run the built script and confirm your CVE appears in the output and reports a sensible status.
6. **Test batch JSON**: Run with `--batch json` and pipe through `python3 -m json.tool` to verify:
   - The output is valid JSON.
   - The new CVE appears in the `vulnerabilities` array with correct `cve`, `name`, `aliases`, `cpu_affected`, `status`, `vulnerable`, `info`, `sysfs_status`, and `sysfs_message` fields.
   - If new `cap_*` variables were added in `check_cpu()`, they appear in `cpu.capabilities` (see Step 2 JSON note).
   - Run with `--batch json-terse` as well to verify backward-compatible output.
7. **Test no-runtime**: Run with `--kernel`/`--config`/`--map` pointing to a kernel image and verify the no-runtime code path reports correctly.
8. **Test `--variant` and `--cve`**: Run with `--variant <shortname>` and `--cve CVE-YYYY-NNNNN` separately to confirm both selection methods work and produce the same output.
9. **Lint**: Run `shellcheck` on the monolithic script and fix any warnings.

### Key Rules to Remember

- **Never hardcode kernel or microcode versions** - detect capabilities directly (design principles 2 and 3). Exception: when a microcode fix has no detectable indicator, hardcode fixing versions per CPU (see principle 3).
- **Assume affected by default** - only mark a CPU as unaffected when there is positive evidence (design principle 4).
- **Always handle both live and non-live modes** — use `$g_mode` to branch (`if [ "$g_mode" = live ]`), and print `N/A "not testable in non-live mode"` for runtime-only checks when not in live mode. Inside CVE checks, `live` is the only mode with runtime access (hw-only skips the CVE loop). Outside CVE checks (e.g. `check_cpu`), use the `has_runtime` helper which returns true for both `live` and `hw-only`.
- **Use `explain()`** when reporting VULN to give actionable remediation advice (see "Cross-Cutting Features" above).
- **Handle `--paranoid` and `--vmm`** when the CVE has stricter mitigation tiers or VMM-specific aspects (see "Cross-Cutting Features" above).
- **Keep JSON output in sync** - when adding new `cap_*` variables, add them to `_build_json_cpu()` in `src/libs/250_output_emitters.sh` (see Step 2 JSON note above). Per-CVE fields are handled automatically.
- **All indentation must use 4 spaces** (CI enforces this via `fmt-check`; the vim modeline `et` enables expandtab).
- **Guard arch-specific checks with positive logic** — use `is_x86_kernel`/`is_arm_kernel` for kernel artifact checks, `is_x86_cpu`/`is_arm_cpu` for hardware operations. Always use positive form (`if is_x86_cpu`, not `if ! is_arm_cpu`) so unknown architectures default to "skip." Never use `cpu_vendor` to branch on architecture in Phase 2/4 — it reflects the host, not the target kernel being inspected.
- **Stay POSIX-compatible** - no bashisms, no GNU-only flags in portable code paths.

## Function documentation headers

Every function must have a documentation header immediately above its definition. The format is:

```sh
# <short description of what the function does>
# Sets: <comma-separated list of global variables written by this function>
# Returns: <return value constants or description>
<function_name>()
{
```

**Header lines** (all optional except the description):

| Line         | When to include | Example |
|--------------|-----------------|---------|
| Description  | Always          | `# Read CPUID register value across one or all cores` |
| `# Args:`    | When the function takes positional parameters | `# Args: $1=msr_address $2=cpu_index(optional, default 0)` |
| `# Sets:`    | When the function writes any `ret_*` or other global variable | `# Sets: ret_read_cpuid_value, ret_read_cpuid_msg` |
| `# Returns:` | When the function uses explicit return codes (constants) | `# Returns: READ_CPUID_RET_OK \| READ_CPUID_RET_ERR \| READ_CPUID_RET_KO` |
| `# Callers:` | **Required** for `_private` (underscore-prefixed) functions | `# Callers: pvulnstatus, pstatus` |

**Rules:**

- The `# Sets:` line is critical - it makes global side effects explicit so any reviewer can immediately see what a function mutates.
- The `# Callers:` line is required for all `_`-prefixed functions. It documents which functions depend on this helper, making it safe to refactor.
- Keep descriptions to one line when possible. If more context is needed, add continuation comment lines before the structured lines.
- Parameter documentation uses `$1=name` format. Append `(optional, default X)` for optional parameters.
- **Exception**: `check_CVE_*` functions (`check_CVE_YYYY_NNNNN`, `_linux`, `_bsd`) are exempt from the documentation header requirement. They are self-explanatory, take no arguments, and live in dedicated `src/vulns/CVE-YYYY-NNNNN.sh` files whose line-3 header already describes the vulnerability.

**Full example:**

```sh
# Read a single MSR register on one CPU core
# Args: $1=msr_address $2=cpu_index(optional, default 0)
# Sets: ret_read_msr_value, ret_read_msr_msg
# Returns: READ_MSR_RET_OK | READ_MSR_RET_ERR | READ_MSR_RET_KO
read_msr()
{
```

**Private function example:**

```sh
# Emit a single CVE result as a JSON object to the batch output buffer
# Args: $1=cve_id $2=status $3=message
# Callers: _record_result
_emit_json()
{
```
