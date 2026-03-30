# Project Overview

spectre-meltdown-checker is a single self-contained shell script (`spectre-meltdown-checker.sh`) that detects system vulnerability to several transient execution CPU CVEs (Spectre, Meltdown, and related). It supports Linux and BSD (FreeBSD, NetBSD, DragonFlyBSD) on x86, amd64, ARM, and ARM64.

The script must stay POSIX-compatible, and not use features only available in specific shells such as `bash` or `zsh`. The `local` keyword is accepted however.

## Linting and Testing

```bash
# Lint (used in CI)
shellcheck spectre-meltdown-checker.sh

# Indentation must use tabs only (CI enforces this)
grep -Pn '^ ' spectre-meltdown-checker.sh  # should find nothing

# Run the script (requires root for full results)
sudo ./spectre-meltdown-checker.sh

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

- **Non-destructive**: Never modifies the system; any loaded kernel modules (cpuid, msr) are unloaded on exit
- **Version-agnostic**: Detects actual CPU/kernel capabilities rather than hardcoding version numbers
- **Whitelist approach**: CPUs are assumed affected unless proven unaffected
- **Offline mode**: Can analyze a non-running kernel via `--kernel`, `--config`, `--map` flags

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
`cap_*`             : CPU capability flags read from hardware/firmware (e.g. cap_rdcl_no).
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
