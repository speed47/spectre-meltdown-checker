# vim: set ts=4 sw=4 sts=4 et:
# Print command-line usage information to stdout
show_usage() {
    # shellcheck disable=SC2086
    cat <<EOF
	Usage:
		Live mode (auto):   $(basename $0) [options]
		Live mode (manual): $(basename $0) [options] <[--kernel <kimage>] [--config <kconfig>] [--map <mapfile>]> --live
		Offline mode:       $(basename $0) [options] <[--kernel <kimage>] [--config <kconfig>] [--map <mapfile>]>

	Modes:
		Two modes are available.

		First mode is the "live" mode (default), it does its best to find information about the currently running kernel.
		To run under this mode, just start the script without any option (you can also use --live explicitly)

		Second mode is the "offline" mode, where you can inspect a non-running kernel.
		This mode is automatically enabled when you specify the location of the kernel file, config and System.map files:

		--kernel kernel_file	specify a (possibly compressed) Linux or BSD kernel file
		--config kernel_config	specify a kernel config file (Linux only)
		--map kernel_map_file	specify a kernel System.map file (Linux only)

		If you want to use live mode while specifying the location of the kernel, config or map file yourself,
		you can add --live to the above options, to tell the script to run in live mode instead of the offline mode,
		which is enabled by default when at least one file is specified on the command line.

	Options:
		--no-color		don't use color codes
		--verbose, -v		increase verbosity level, possibly several times
		--explain		produce an additional human-readable explanation of actions to take to mitigate a vulnerability
		--paranoid		require all mitigations to be enabled to the fullest extent, including those that
					are not strictly necessary but provide defense in depth (e.g. SMT disabled, IBPB
					always-on); without this flag, the script follows the security community consensus
		--extra			run additional checks for issues that don't have a CVE but are still security-relevant,
					such as compile-time mitigations not enabled by default (e.g. Straight-Line Speculation)

		--no-sysfs		don't use the /sys interface even if present [Linux]
		--sysfs-only		only use the /sys interface, don't run our own checks [Linux]
		--coreos		special mode for CoreOS (use an ephemeral toolbox to inspect kernel) [Linux]

		--arch-prefix PREFIX	specify a prefix for cross-inspecting a kernel of a different arch, for example "aarch64-linux-gnu-",
					so that invoked tools will be prefixed with this (i.e. aarch64-linux-gnu-objdump)
		--batch text		produce machine readable output, this is the default if --batch is specified alone
		--batch short		produce only one line with the vulnerabilities separated by spaces
		--batch json		produce comprehensive JSON output with system, CPU, and vulnerability details
		--batch json-terse	produce a terse JSON array of per-CVE results (legacy format)
		--batch nrpe		produce machine readable output formatted for NRPE
		--batch prometheus      produce output for consumption by prometheus-node-exporter

		--variant VARIANT	specify which variant you'd like to check, by default all variants are checked.
					can be used multiple times (e.g. --variant 3a --variant l1tf)
					for a list of supported VARIANT parameters, use --variant help
		--cve CVE		specify which CVE you'd like to check, by default all supported CVEs are checked
					can be used multiple times (e.g. --cve CVE-2017-5753 --cve CVE-2020-0543)
		--hw-only		only check for CPU information, don't check for any variant
		--no-hw			skip CPU information and checks, if you're inspecting a kernel not to be run on this host
		--vmm [auto,yes,no]	override the detection of the presence of a hypervisor, default: auto
		--no-intel-db		don't use the builtin Intel DB of affected processors
		--allow-msr-write	allow probing for write-only MSRs, this might produce kernel logs or be blocked by your system
		--cpu [#,all]		interact with CPUID and MSR of CPU core number #, or all (default: CPU core 0)
		--update-fwdb		update our local copy of the CPU microcodes versions database (using the awesome
					MCExtractor project and the Intel firmwares GitHub repository)
		--update-builtin-fwdb	same as --update-fwdb but update builtin DB inside the script itself
		--dump-mock-data	used to mimick a CPU on an other system, mainly used to help debugging this script

	Return codes:
		0 (not vulnerable), 2 (vulnerable), 3 (unknown), 255 (error)

	IMPORTANT:
	A false sense of security is worse than no security at all.
	Please use the --disclaimer option to understand exactly what this script does.

EOF
}

# Print the legal disclaimer about tool accuracy and limitations
show_disclaimer() {
    cat <<EOF
Disclaimer:

This tool does its best to determine whether your system is immune (or has proper mitigations in place) for the
collectively named "transient execution" (aka "speculative execution") vulnerabilities that started to appear
since early 2018 with the infamous Spectre & Meltdown.

This tool does NOT attempt to run any kind of exploit, and can't 100% guarantee that your system is secure,
but rather helps you verifying whether your system has the known correct mitigations in place.
However, some mitigations could also exist in your kernel that this script doesn't know (yet) how to detect, or it might
falsely detect mitigations that in the end don't work as expected (for example, on backported or modified kernels).

Your system affectability to a given vulnerability depends on your CPU model and CPU microcode version, whereas the
mitigations in place depend on your CPU (model and microcode), your kernel version, and both the runtime configuration
of your CPU (through bits set through the MSRs) and your kernel. The script attempts to explain everything for each
vulnerability, so you know where your system stands. For a given vulnerability, detailed information is sometimes
available using the \`--explain\` switch.

Please also note that for the Spectre-like vulnerabilities, all software can possibly be exploited, in which case
this tool only verifies that the kernel (which is the core of the system) you're using has the proper protections
in place. Verifying all the other software is out of the scope of this tool, as it can't be done in a simple way.
As a general measure, ensure you always have the most up to date stable versions of all the software you use,
especially for those who are exposed to the world, such as network daemons and browsers.

For more information and answers to related questions, please refer to the FAQ.md file.

This tool has been released in the hope that it'll be useful, but don't use it to jump to conclusions about your security.

EOF
}

g_os=$(uname -s)

# parse options
opt_kernel=''
opt_config=''
opt_map=''
opt_live=-1
opt_no_color=0
opt_batch=0
opt_batch_format='text'
opt_verbose=1
opt_cve_list=''
opt_cve_all=1
opt_no_sysfs=0
opt_sysfs_only=0
opt_coreos=0
opt_arch_prefix=''
opt_hw_only=0
opt_no_hw=0
opt_vmm=-1
opt_allow_msr_write=0
opt_cpu=0
opt_explain=0
opt_paranoid=0
opt_extra=0
opt_mock=0
opt_intel_db=1

g_critical=0
g_unknown=0
g_nrpe_vuln=''

# CVE Registry: single source of truth for all CVE metadata.
# Fields: cve_id|json_key_name|affected_var_suffix|complete_name_and_aliases
readonly CVE_REGISTRY='
CVE-2017-5753|SPECTRE VARIANT 1|variant1|Spectre Variant 1, bounds check bypass
CVE-2017-5715|SPECTRE VARIANT 2|variant2|Spectre Variant 2, branch target injection
CVE-2017-5754|MELTDOWN|variant3|Variant 3, Meltdown, rogue data cache load
CVE-2018-3640|VARIANT 3A|variant3a|Variant 3a, rogue system register read
CVE-2018-3639|VARIANT 4|variant4|Variant 4, speculative store bypass
CVE-2018-3615|L1TF SGX|variantl1tf_sgx|Foreshadow (SGX), L1 terminal fault
CVE-2018-3620|L1TF OS|variantl1tf|Foreshadow-NG (OS), L1 terminal fault
CVE-2018-3646|L1TF VMM|variantl1tf|Foreshadow-NG (VMM), L1 terminal fault
CVE-2018-12126|MSBDS|msbds|Fallout, microarchitectural store buffer data sampling (MSBDS)
CVE-2018-12130|MFBDS|mfbds|ZombieLoad, microarchitectural fill buffer data sampling (MFBDS)
CVE-2018-12127|MLPDS|mlpds|RIDL, microarchitectural load port data sampling (MLPDS)
CVE-2019-11091|MDSUM|mdsum|RIDL, microarchitectural data sampling uncacheable memory (MDSUM)
CVE-2019-11135|TAA|taa|ZombieLoad V2, TSX Asynchronous Abort (TAA)
CVE-2018-12207|ITLBMH|itlbmh|No eXcuses, iTLB Multihit, machine check exception on page size changes (MCEPSC)
CVE-2020-0543|SRBDS|srbds|Special Register Buffer Data Sampling (SRBDS)
CVE-2022-21123|SBDR|mmio|Shared Buffers Data Read (SBDR), MMIO Stale Data
CVE-2022-21125|SBDS|mmio|Shared Buffers Data Sampling (SBDS), MMIO Stale Data
CVE-2022-21166|DRPW|mmio|Device Register Partial Write (DRPW), MMIO Stale Data
CVE-2023-20588|DIV0|div0|Division by Zero, AMD Zen1 speculative data leak
CVE-2023-20593|ZENBLEED|zenbleed|Zenbleed, cross-process information leak
CVE-2022-40982|DOWNFALL|downfall|Downfall, gather data sampling (GDS)
CVE-2022-29900|RETBLEED AMD|retbleed|Retbleed, arbitrary speculative code execution with return instructions (AMD)
CVE-2022-29901|RETBLEED INTEL|retbleed|Retbleed, arbitrary speculative code execution with return instructions (Intel)
CVE-2023-20569|INCEPTION|inception|Inception, return address security (RAS)
CVE-2023-23583|REPTAR|reptar|Reptar, redundant prefix issue
CVE-2024-36350|TSA_SQ|tsa|Transient Scheduler Attack - Store Queue (TSA-SQ)
CVE-2024-36357|TSA_L1|tsa|Transient Scheduler Attack - L1 (TSA-L1)
CVE-2024-28956|ITS|its|Indirect Target Selection (ITS)
CVE-2025-40300|VMSCAPE|vmscape|VMScape, VM-exit stale branch prediction
CVE-2023-28746|RFDS|rfds|Register File Data Sampling (RFDS)
CVE-2024-45332|BPI|bpi|Branch Privilege Injection (BPI)
CVE-0000-0001|SLS|sls|Straight-Line Speculation (SLS)
'

# Derive the supported CVE list from the registry
g_supported_cve_list=$(echo "$CVE_REGISTRY" | grep '^CVE-' | cut -d'|' -f1)

# Look up a field from the CVE registry
# Args: $1=cve_id $2=field_number (see CVE_REGISTRY format above)
# Callers: cve2name, _is_cpu_affected_cached, pvulnstatus
_cve_registry_field() {
    local line
    line=$(echo "$CVE_REGISTRY" | grep -E "^$1\|")
    if [ -z "$line" ]; then
        echo "$0: error: invalid CVE '$1' passed to _cve_registry_field()" >&2
        exit 255
    fi
    echo "$line" | cut -d'|' -f"$2"
}

# find a sane command to print colored messages, we prefer `printf` over `echo`
# because `printf` behavior is more standard across Linux/BSD
# we'll try to avoid using shell builtins that might not take options
g_echo_cmd_type='echo'
# ignore SC2230 here because `which` ignores builtins while `command -v` doesn't, and
# we don't want builtins here. Even if `which` is not installed, we'll fallback to the
# `echo` builtin anyway, so this is safe.
# shellcheck disable=SC2230
if command -v printf >/dev/null 2>&1; then
    g_echo_cmd=$(command -v printf)
    g_echo_cmd_type='printf'
elif which echo >/dev/null 2>&1; then
    g_echo_cmd=$(which echo)
else
    # maybe the `which` command is broken?
    [ -x /bin/echo ] && g_echo_cmd=/bin/echo
    # for Android
    [ -x /system/bin/echo ] && g_echo_cmd=/system/bin/echo
fi
# still empty? fallback to builtin
[ -z "$g_echo_cmd" ] && g_echo_cmd='echo'
