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
- **Offline kernel analysis**: The script can inspect a kernel image before it is booted (`--kernel`, `--config`, `--map`), verifying it carries the expected mitigations.
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
| **`source`** | Production source (split files + Makefile) | Developers |
| **`master`** | Monolithic production script (built artifact) | CI from `source` |
| **`dev`** | Dev/test source (split files + Makefile) | Developers |
| **`dev-build`** | Monolithic test script (built artifact) | CI from `dev` |

- **`source`** and **`dev`** contain the split source files and the Makefile. These are the branches developers commit to.
- **`master`** and **`dev-build`** contain only the monolithic `spectre-meltdown-checker.sh` built by CI. Nobody commits to these directly.
- **`master`** is the preexisting production branch that users pull from. It cannot be renamed.
- **`dev-build`** is a testing branch that users can pull from to test pre-release versions.

Typical workflow:
1. Feature/fix branches are created from `dev` and merged back into `dev`.
2. CI builds the script and pushes it to `dev-build` for testing.
3. When ready for release, `dev` is merged into `source`.
4. CI builds the script and pushes it to `master` for production.

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

# Batch JSON mode (CI validates exactly 19 CVEs in output)
sudo ./spectre-meltdown-checker.sh --batch json | jq '.[] | .CVE' | wc -l  # must be 19

# Update microcode firmware database
sudo ./spectre-meltdown-checker.sh --update-fwdb

# Docker
docker-compose build && docker-compose run --rm spectre-meltdown-checker
```

There is no separate test suite. CI (`.github/workflows/check.yml`) runs shellcheck, tab-indentation checks, a live execution test validating 19 CVEs, Docker builds, and a firmware DB update test that checks for temp file leaks.

## Architecture

The entire tool is a single bash script with no external script dependencies. Key structural sections:

- **Output/logging functions** (~line 253): `pr_warn`, `pr_info`, `pr_verbose`, `pr_debug`, `explain`, `pstatus`, `pvulnstatus` — verbosity-aware output with color support
- **CPU detection** (~line 2171): `parse_cpu_details`, `is_intel`/`is_amd`/`is_hygon`, `read_cpuid`, `read_msr`, `is_cpu_smt_enabled` — hardware identification via CPUID/MSR registers
- **Microcode database** (embedded): Intel/AMD microcode version lookup via `read_mcedb`/`read_inteldb`; updated automatically via `.github/workflows/autoupdate.yml`
- **Kernel analysis** (~line 1568): `extract_kernel`, `try_decompress` — extracts and inspects kernel images (handles gzip, bzip2, xz, lz4, zstd compression)
- **Vulnerability checks**: 19 `check_CVE_<year>_<number>()` functions, each with `_linux()` and `_bsd()` variants. Uses whitelist logic (assumes affected unless proven otherwise)
- **Main flow** (~line 6668): Parse options → detect CPU → loop through requested CVEs → output results (text/json/nrpe/prometheus) → cleanup

## Key Design Principles

These rules are non-negotiable and govern how every part of the script is written:

### 1. Production-safe

It must always be okay to run this script in a production environment.

- **1a. Non-destructive**: Never modify the system. If the script loads a kernel module it needs (e.g. `cpuid`, `msr`), it must unload it on exit.
- **1b. Report only**: Never attempt to "fix" or "mitigate" any vulnerability, or modify any configuration. The script reports status and leaves all decisions to the sysadmin.
- **1c. No exploit execution**: Never run any kind of exploit or proof-of-concept. This would violate rule 1a, could cause unpredictable system behavior, and may produce wrong conclusions (especially for Spectre-class PoCs that require very specific build options and prerequisites).

### 2. Never hardcode kernel versions

Never look at the kernel version string to determine whether it supports a mitigation. This would defeat the script's purpose: it must detect mitigations in unknown, vendor-patched, or backported kernels. Similarly, do not blindly trust what `sysfs` reports when it is possible to verify directly.

### 3. Never hardcode microcode versions

Never look at the microcode version to determine whether it has the proper mitigation mechanisms. Instead, probe for the mechanisms themselves (CPUID bits, MSR values), as the kernel would.

### 4. Assume affected unless proven otherwise (whitelist approach)

When a CPU is not explicitly known to be unaffected by a vulnerability, assume that it is affected. This conservative default has been the right call since the early Spectre/Meltdown days and remains sound.

### 5. Offline mode

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

Create `src/vulns/CVE-YYYY-NNNNN.sh`. The file must contain exactly three functions:

```sh
# vim: set ts=4 sw=4 sts=4 et:
####################
# SHORT_NAME section

# CVE-YYYY-NNNNN SHORT_NAME (one-line description) - entry point
check_CVE_YYYY_NNNNN() {
	check_cve 'CVE-YYYY-NNNNN'
}

# CVE-YYYY-NNNNN SHORT_NAME (one-line description) - Linux mitigation check
check_CVE_YYYY_NNNNN_linux() {
	# ... (see Step 3)
}

# CVE-YYYY-NNNNN SHORT_NAME (one-line description) - BSD mitigation check
check_CVE_YYYY_NNNNN_bsd() {
	if ! is_cpu_affected "$cve"; then
		pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
	else
		pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
	fi
}
```

The entry point calls `check_cve`, which prints the CVE header and dispatches to `_linux()` or `_bsd()` based on `$g_os`. If BSD mitigations are not yet understood, use the stub above — it correctly reports UNK rather than a false OK.

### Step 2: Register the CVE in the CPU Affection Logic

In `src/libs/200_cpu_affected.sh`, add an `affected_yourname` variable and populate it inside `is_cpu_affected()`. The variable follows the whitelist principle: **assume affected (`1`) unless you can prove the CPU is immune (`0`)**. Two kinds of evidence can prove immunity:

- **Static identifiers**: CPU vendor, family, model, stepping — these identify the hardware design.
- **Hardware immunity `cap_*` bits**: CPUID or MSR bits that the CPU vendor defines to explicitly declare "this hardware is not affected" (e.g. `cap_rdcl_no` for Meltdown, `cap_ssb_no` for Variant 4, `cap_gds_no` for Downfall, `cap_tsa_sq_no`/`cap_tsa_l1_no` for TSA). These are read in `check_cpu()` and stored as `cap_*` globals.

Never use microcode version strings.

**Important**: Do not confuse hardware immunity bits with *mitigation* capability bits. A hardware immunity bit (e.g. `GDS_NO`, `TSA_SQ_NO`) declares that the CPU design is architecturally free of the vulnerability — it belongs here in `is_cpu_affected()`. A mitigation capability bit (e.g. `VERW_CLEAR`, `MD_CLEAR`) indicates that updated microcode provides a mechanism to work around a vulnerability the CPU *does* have — it belongs in the `check_CVE_YYYY_NNNNN_linux()` function (Phase 2), where it is used to determine whether mitigations are in place.

### Step 3: Implement the Linux Check

The `_linux()` function follows a standard algorithm with four phases:

**Phase 1 — Initialize and check sysfs:**

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

**Phase 2 — Custom detection (kernel + runtime):**

Guarded by `if [ "$opt_sysfs_only" != 1 ]; then` so users who trust sysfs can skip it.

This is where the real detection lives. Check for mitigations at each layer:

- **Kernel support**: Determine whether the kernel carries the mitigation code. Three sources of evidence are available, and any one of them is sufficient:

  - **Kernel image** (`$g_kernel`): Search for strings or symbols that prove the mitigation code is compiled in.
    ```sh
    if grep -q 'mitigation_string' "$g_kernel"; then
        kernel_mitigated="found mitigation evidence in kernel image"
    fi
    ```
    Guard with `if [ -n "$g_kernel_err" ]; then` first — the kernel image may be unavailable.

  - **Kernel config** (`$g_kernel_config`): Look for the `CONFIG_*` option that enables the mitigation.
    ```sh
    if [ -n "$g_kernel_config" ] && grep -q '^CONFIG_MITIGATION_NAME=y' "$g_kernel_config"; then
        kernel_mitigated="found mitigation config option enabled"
    fi
    ```

  - **System.map** (`$g_kernel_map`): Look for function names directly linked to the mitigation.
    ```sh
    if [ -n "$g_kernel_map" ] && grep -q 'mitigation_function_name' "$g_kernel_map"; then
        kernel_mitigated="found mitigation function in System.map"
    fi
    ```

  Each source may independently be unavailable (offline mode without the file, or stripped kernel), so check all that are present. A match in any one confirms kernel support.

- **Runtime state** (live mode only): Read MSRs, check cpuinfo flags, parse dmesg, inspect debugfs.
  ```sh
  if [ "$opt_live" = 1 ]; then
      read_msr 0xADDRESS
      ret=$?
      if [ "$ret" = "$READ_MSR_RET_OK" ]; then
          # check specific bits in ret_read_msr_value_lo / ret_read_msr_value_hi
      fi
  else
      pstatus blue N/A "not testable in offline mode"
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

**Phase 3 — CPU affection gate:**

```sh
	if ! is_cpu_affected "$cve"; then
		pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
```

If the CPU is not affected, nothing else matters — report OK and return. This overrides any sysfs or custom detection result.

**Phase 4 — Final status determination:**

For affected CPUs, combine the evidence from Phase 2 into a final verdict:

```sh
	elif [ "$opt_sysfs_only" != 1 ]; then
		if [ "$microcode_ok" = 1 ] && [ -n "$kernel_mitigated" ]; then
			pvulnstatus "$cve" OK "Both kernel and microcode mitigate the vulnerability"
		elif [ "$microcode_ok" = 1 ]; then
			pvulnstatus "$cve" OK "Microcode mitigates the vulnerability"
		elif [ -n "$kernel_mitigated" ]; then
			pvulnstatus "$cve" OK "Kernel mitigates the vulnerability"
		else
			pvulnstatus "$cve" VULN "Neither kernel nor microcode mitigate the vulnerability"
			explain "Remediation advice here..."
		fi
	else
		pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
	fi
}
```

The exact combination logic depends on the CVE. Some require **both** microcode and kernel fixes (report VULN if either is missing). Others are mitigated by **either** layer alone (report OK if one is present). Some also require SMT to be disabled — check with `is_cpu_smt_enabled()`.

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

Some vulnerabilities (e.g. L1TF/CVE-2018-3646, ITLBMH/CVE-2018-12207) only matter — or require additional mitigations — when the host is running a hypervisor with untrusted guests. If `g_has_vmm` is 0, the system can be reported as not vulnerable to these VMM-specific aspects:

```sh
if [ "$g_has_vmm" = 0 ]; then
    pvulnstatus "$cve" OK "this system is not running a hypervisor"
else
    # check hypervisor-specific mitigations (L1D flushing, EPT, etc.)
fi
```

CVEs that need VMM context should call `check_has_vmm` early in their `_linux()` function. Note the interaction with paranoid mode: when `--paranoid` is active and `--vmm` was not explicitly set, the script assumes a hypervisor is present (`g_has_vmm=2`), erring on the side of caution.

### Step 4: Wire Up and Test

1. **Add the CVE name mapping** in the `cve2name()` function so the header prints a human-readable name.
2. **Build** the monolithic script with `make`.
3. **Test live**: Run the built script and confirm your CVE appears in the output and reports a sensible status.
4. **Test batch JSON**: Run with `--batch json` and verify the CVE count incremented by one (currently 19 → 20).
5. **Test offline**: Run with `--kernel`/`--config`/`--map` pointing to a kernel image and verify the offline code path reports correctly.
6. **Lint**: Run `shellcheck` on the monolithic script and fix any warnings.
7. **Update `dist/README.md`**: Add details about the new CVE check (name, description, what it detects) so that the user-facing documentation stays in sync with the implementation.

### Key Rules to Remember

- **Never hardcode kernel or microcode versions** — detect capabilities directly (design principles 2 and 3).
- **Assume affected by default** — only mark a CPU as unaffected when there is positive evidence (design principle 4).
- **Always handle both live and offline modes** — use `$opt_live` to branch, and print `N/A "not testable in offline mode"` for runtime-only checks when offline.
- **Use `explain()`** when reporting VULN to give actionable remediation advice (see "Cross-Cutting Features" above).
- **Handle `--paranoid` and `--vmm`** when the CVE has stricter mitigation tiers or VMM-specific aspects (see "Cross-Cutting Features" above).
- **All indentation must use tabs** (CI enforces this).
- **Stay POSIX-compatible** — no bashisms, no GNU-only flags in portable code paths.

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

- The `# Sets:` line is critical — it makes global side effects explicit so any reviewer can immediately see what a function mutates.
- The `# Callers:` line is required for all `_`-prefixed functions. It documents which functions depend on this helper, making it safe to refactor.
- Keep descriptions to one line when possible. If more context is needed, add continuation comment lines before the structured lines.
- Parameter documentation uses `$1=name` format. Append `(optional, default X)` for optional parameters.

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
