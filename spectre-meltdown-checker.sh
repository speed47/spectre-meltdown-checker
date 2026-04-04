#! /bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# vim: set ts=4 sw=4 sts=4 et:
# shellcheck disable=SC2317,SC2329,SC3043
#
# Spectre & Meltdown checker
#
# Check for the latest version at:
# https://github.com/speed47/spectre-meltdown-checker
# git clone https://github.com/speed47/spectre-meltdown-checker.git
# or wget https://meltdown.ovh -O spectre-meltdown-checker.sh
# or curl -L https://meltdown.ovh -o spectre-meltdown-checker.sh
#
# Stephane Lesimple
#
VERSION='26.26.0404682'

# --- Common paths and basedirs ---
readonly VULN_SYSFS_BASE="/sys/devices/system/cpu/vulnerabilities"
readonly DEBUGFS_BASE="/sys/kernel/debug"
readonly SYS_MODULE_BASE="/sys/module"
readonly CPU_DEV_BASE="/dev/cpu"
readonly BSD_CPUCTL_DEV_BASE="/dev/cpuctl"

trap 'exit_cleanup' EXIT
trap 'pr_warn "interrupted, cleaning up..."; exit_cleanup; exit 1' INT
# Clean up temporary files and undo module/mount side effects on exit
exit_cleanup() {
    local saved_ret
    saved_ret=$?
    # cleanup the temp decompressed config & kernel image
    [ -n "${g_dumped_config:-}" ] && [ -f "$g_dumped_config" ] && rm -f "$g_dumped_config"
    [ -n "${g_kerneltmp:-}" ] && [ -f "$g_kerneltmp" ] && rm -f "$g_kerneltmp"
    [ -n "${g_kerneltmp2:-}" ] && [ -f "$g_kerneltmp2" ] && rm -f "$g_kerneltmp2"
    [ -n "${g_mcedb_tmp:-}" ] && [ -f "$g_mcedb_tmp" ] && rm -f "$g_mcedb_tmp"
    [ -n "${g_intel_tmp:-}" ] && [ -d "$g_intel_tmp" ] && rm -rf "$g_intel_tmp"
    [ -n "${g_linuxfw_tmp:-}" ] && [ -f "$g_linuxfw_tmp" ] && rm -f "$g_linuxfw_tmp"
    [ "${g_mounted_debugfs:-}" = 1 ] && umount "$DEBUGFS_BASE" 2>/dev/null
    [ "${g_mounted_procfs:-}" = 1 ] && umount "$g_procfs" 2>/dev/null
    [ "${g_insmod_cpuid:-}" = 1 ] && rmmod cpuid 2>/dev/null
    [ "${g_insmod_msr:-}" = 1 ] && rmmod msr 2>/dev/null
    [ "${g_kldload_cpuctl:-}" = 1 ] && kldunload cpuctl 2>/dev/null
    [ "${g_kldload_vmm:-}" = 1 ] && kldunload vmm 2>/dev/null
    exit "$saved_ret"
}

# if we were git clone'd, adjust VERSION
if [ -d "$(dirname "$0")/.git" ] && command -v git >/dev/null 2>&1; then
    g_commit=$(git -C "$(dirname "$0")" describe --always --dirty --abbrev=7 --match=- 2>/dev/null)
    [ -n "$g_commit" ] && VERSION="$VERSION-git$g_commit"
fi

# >>>>>> libs/002_core_globals.sh <<<<<<

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
		--paranoid		require IBPB to deem Variant 2 as mitigated
					also require SMT disabled + unconditional L1D flush to deem Foreshadow-NG VMM as mitigated
					also require SMT disabled to deem MDS vulnerabilities mitigated

		--no-sysfs		don't use the /sys interface even if present [Linux]
		--sysfs-only		only use the /sys interface, don't run our own checks [Linux]
		--coreos		special mode for CoreOS (use an ephemeral toolbox to inspect kernel) [Linux]

		--arch-prefix PREFIX	specify a prefix for cross-inspecting a kernel of a different arch, for example "aarch64-linux-gnu-",
					so that invoked tools will be prefixed with this (i.e. aarch64-linux-gnu-objdump)
		--batch text		produce machine readable output, this is the default if --batch is specified alone
		--batch short		produce only one line with the vulnerabilities separated by spaces
		--batch json		produce JSON output formatted for Puppet, Ansible, Chef...
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
CVE-2024-45332|BPI|bpi|Branch Privilege Injection (BPI)
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

# >>>>>> libs/003_intel_models.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Generated by scripts/update_intel_models.sh from:
#   https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/arch/x86/include/asm/intel-family.h
# Run scripts/update_intel_models.sh to refresh when new Intel CPU families are added to the kernel.
# shellcheck disable=SC2034
{
    readonly INTEL_FAM5_PENTIUM_75=$((0x02))  # /* P54C */
    readonly INTEL_FAM5_PENTIUM_MMX=$((0x04)) # /* P55C */
    readonly INTEL_FAM5_QUARK_X1000=$((0x09)) # /* Quark X1000 SoC */
    readonly INTEL_FAM6_PENTIUM_PRO=$((0x01))
    readonly INTEL_FAM6_PENTIUM_II_KLAMATH=$((0x03))
    readonly INTEL_FAM6_PENTIUM_III_DESCHUTES=$((0x05))
    readonly INTEL_FAM6_PENTIUM_III_TUALATIN=$((0x0B))
    readonly INTEL_FAM6_PENTIUM_M_DOTHAN=$((0x0D))
    readonly INTEL_FAM6_CORE_YONAH=$((0x0E))
    readonly INTEL_FAM6_CORE2_MEROM=$((0x0F))
    readonly INTEL_FAM6_CORE2_MEROM_L=$((0x16))
    readonly INTEL_FAM6_CORE2_PENRYN=$((0x17))
    readonly INTEL_FAM6_CORE2_DUNNINGTON=$((0x1D))
    readonly INTEL_FAM6_NEHALEM=$((0x1E))
    readonly INTEL_FAM6_NEHALEM_G=$((0x1F)) # /* Auburndale / Havendale */
    readonly INTEL_FAM6_NEHALEM_EP=$((0x1A))
    readonly INTEL_FAM6_NEHALEM_EX=$((0x2E))
    readonly INTEL_FAM6_WESTMERE=$((0x25))
    readonly INTEL_FAM6_WESTMERE_EP=$((0x2C))
    readonly INTEL_FAM6_WESTMERE_EX=$((0x2F))
    readonly INTEL_FAM6_SANDYBRIDGE=$((0x2A))
    readonly INTEL_FAM6_SANDYBRIDGE_X=$((0x2D))
    readonly INTEL_FAM6_IVYBRIDGE=$((0x3A))
    readonly INTEL_FAM6_IVYBRIDGE_X=$((0x3E))
    readonly INTEL_FAM6_HASWELL=$((0x3C))
    readonly INTEL_FAM6_HASWELL_X=$((0x3F))
    readonly INTEL_FAM6_HASWELL_L=$((0x45))
    readonly INTEL_FAM6_HASWELL_G=$((0x46))
    readonly INTEL_FAM6_BROADWELL=$((0x3D))
    readonly INTEL_FAM6_BROADWELL_G=$((0x47))
    readonly INTEL_FAM6_BROADWELL_X=$((0x4F))
    readonly INTEL_FAM6_BROADWELL_D=$((0x56))
    readonly INTEL_FAM6_SKYLAKE_L=$((0x4E))        # /* Sky Lake */
    readonly INTEL_FAM6_SKYLAKE=$((0x5E))          # /* Sky Lake */
    readonly INTEL_FAM6_SKYLAKE_X=$((0x55))        # /* Sky Lake */
    readonly INTEL_FAM6_KABYLAKE_L=$((0x8E))       # /* Sky Lake */
    readonly INTEL_FAM6_KABYLAKE=$((0x9E))         # /* Sky Lake */
    readonly INTEL_FAM6_COMETLAKE=$((0xA5))        # /* Sky Lake */
    readonly INTEL_FAM6_COMETLAKE_L=$((0xA6))      # /* Sky Lake */
    readonly INTEL_FAM6_CANNONLAKE_L=$((0x66))     # /* Palm Cove */
    readonly INTEL_FAM6_ICELAKE_X=$((0x6A))        # /* Sunny Cove */
    readonly INTEL_FAM6_ICELAKE_D=$((0x6C))        # /* Sunny Cove */
    readonly INTEL_FAM6_ICELAKE=$((0x7D))          # /* Sunny Cove */
    readonly INTEL_FAM6_ICELAKE_L=$((0x7E))        # /* Sunny Cove */
    readonly INTEL_FAM6_ICELAKE_NNPI=$((0x9D))     # /* Sunny Cove */
    readonly INTEL_FAM6_ROCKETLAKE=$((0xA7))       # /* Cypress Cove */
    readonly INTEL_FAM6_TIGERLAKE_L=$((0x8C))      # /* Willow Cove */
    readonly INTEL_FAM6_TIGERLAKE=$((0x8D))        # /* Willow Cove */
    readonly INTEL_FAM6_SAPPHIRERAPIDS_X=$((0x8F)) # /* Golden Cove */
    readonly INTEL_FAM6_EMERALDRAPIDS_X=$((0xCF))  # /* Raptor Cove */
    readonly INTEL_FAM6_GRANITERAPIDS_X=$((0xAD))  # /* Redwood Cove */
    readonly INTEL_FAM6_GRANITERAPIDS_D=$((0xAE))
    readonly INTEL_FAM19_DIAMONDRAPIDS_X=$((0x01)) # /* Panther Cove */
    readonly INTEL_FAM6_BARTLETTLAKE=$((0xD7))     # /* Raptor Cove */
    readonly INTEL_FAM6_LAKEFIELD=$((0x8A))        # /* Sunny Cove / Tremont */
    readonly INTEL_FAM6_ALDERLAKE=$((0x97))        # /* Golden Cove / Gracemont */
    readonly INTEL_FAM6_ALDERLAKE_L=$((0x9A))      # /* Golden Cove / Gracemont */
    readonly INTEL_FAM6_RAPTORLAKE=$((0xB7))       # /* Raptor Cove / Enhanced Gracemont */
    readonly INTEL_FAM6_RAPTORLAKE_P=$((0xBA))
    readonly INTEL_FAM6_RAPTORLAKE_S=$((0xBF))
    readonly INTEL_FAM6_METEORLAKE=$((0xAC)) # /* Redwood Cove / Crestmont */
    readonly INTEL_FAM6_METEORLAKE_L=$((0xAA))
    readonly INTEL_FAM6_ARROWLAKE_H=$((0xC5)) # /* Lion Cove / Skymont */
    readonly INTEL_FAM6_ARROWLAKE=$((0xC6))
    readonly INTEL_FAM6_ARROWLAKE_U=$((0xB5))
    readonly INTEL_FAM6_LUNARLAKE_M=$((0xBD))   # /* Lion Cove / Skymont */
    readonly INTEL_FAM6_PANTHERLAKE_L=$((0xCC)) # /* Cougar Cove / Darkmont */
    readonly INTEL_FAM6_WILDCATLAKE_L=$((0xD5))
    readonly INTEL_FAM18_NOVALAKE=$((0x01))            # /* Coyote Cove / Arctic Wolf */
    readonly INTEL_FAM18_NOVALAKE_L=$((0x03))          # /* Coyote Cove / Arctic Wolf */
    readonly INTEL_FAM6_ATOM_BONNELL=$((0x1C))         # /* Diamondville, Pineview */
    readonly INTEL_FAM6_ATOM_BONNELL_MID=$((0x26))     # /* Silverthorne, Lincroft */
    readonly INTEL_FAM6_ATOM_SALTWELL=$((0x36))        # /* Cedarview */
    readonly INTEL_FAM6_ATOM_SALTWELL_MID=$((0x27))    # /* Penwell */
    readonly INTEL_FAM6_ATOM_SALTWELL_TABLET=$((0x35)) # /* Cloverview */
    readonly INTEL_FAM6_ATOM_SILVERMONT=$((0x37))      # /* Bay Trail, Valleyview */
    readonly INTEL_FAM6_ATOM_SILVERMONT_D=$((0x4D))    # /* Avaton, Rangely */
    readonly INTEL_FAM6_ATOM_SILVERMONT_MID=$((0x4A))  # /* Merriefield */
    readonly INTEL_FAM6_ATOM_SILVERMONT_MID2=$((0x5A)) # /* Anniedale */
    readonly INTEL_FAM6_ATOM_AIRMONT=$((0x4C))         # /* Cherry Trail, Braswell */
    readonly INTEL_FAM6_ATOM_AIRMONT_NP=$((0x75))      # /* Lightning Mountain */
    readonly INTEL_FAM6_ATOM_GOLDMONT=$((0x5C))        # /* Apollo Lake */
    readonly INTEL_FAM6_ATOM_GOLDMONT_D=$((0x5F))      # /* Denverton */
    readonly INTEL_FAM6_ATOM_GOLDMONT_PLUS=$((0x7A))   # /* Gemini Lake */
    readonly INTEL_FAM6_ATOM_TREMONT_D=$((0x86))       # /* Jacobsville */
    readonly INTEL_FAM6_ATOM_TREMONT=$((0x96))         # /* Elkhart Lake */
    readonly INTEL_FAM6_ATOM_TREMONT_L=$((0x9C))       # /* Jasper Lake */
    readonly INTEL_FAM6_ATOM_GRACEMONT=$((0xBE))       # /* Alderlake N */
    readonly INTEL_FAM6_ATOM_CRESTMONT_X=$((0xAF))     # /* Sierra Forest */
    readonly INTEL_FAM6_ATOM_CRESTMONT=$((0xB6))       # /* Grand Ridge */
    readonly INTEL_FAM6_ATOM_DARKMONT_X=$((0xDD))      # /* Clearwater Forest */
    readonly INTEL_FAM6_XEON_PHI_KNL=$((0x57))         # /* Knights Landing */
    readonly INTEL_FAM6_XEON_PHI_KNM=$((0x85))         # /* Knights Mill */
    readonly INTEL_FAM15_P4_WILLAMETTE=$((0x01))       # /* Also Xeon Foster */
    readonly INTEL_FAM15_P4_PRESCOTT=$((0x03))
    readonly INTEL_FAM15_P4_PRESCOTT_2M=$((0x04))
    readonly INTEL_FAM15_P4_CEDARMILL=$((0x06)) # /* Also Xeon Dempsey */
}

# >>>>>> libs/100_output_print.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# Low-level echo wrapper handling color stripping and printf/echo portability
# Args: $1=opt(-n for no newline, '' for normal) $2...=message
# Callers: _pr_echo, _pr_echo_nol
_pr_echo_raw() {
    local opt msg interpret_chars ctrlchar
    opt="$1"
    shift
    msg="$*"

    if [ "$opt_no_color" = 1 ]; then
        # strip ANSI color codes
        # some sed versions (i.e. toybox) can't seem to handle
        # \033 aka \x1B correctly, so do it for them.
        if [ "$g_echo_cmd_type" = printf ]; then
            interpret_chars=''
        else
            interpret_chars='-e'
        fi
        ctrlchar=$($g_echo_cmd $interpret_chars "\033")
        msg=$($g_echo_cmd $interpret_chars "$msg" | sed -E "s/$ctrlchar\[([0-9][0-9]?(;[0-9][0-9]?)?)?m//g")
    fi
    if [ "$g_echo_cmd_type" = printf ]; then
        if [ "$opt" = "-n" ]; then
            $g_echo_cmd "$msg"
        else
            $g_echo_cmd "$msg\n"
        fi
    else
        # shellcheck disable=SC2086
        $g_echo_cmd $opt -e "$msg"
    fi
}

# Print a message if the current verbosity level is high enough
# Args: $1=minimum_verbosity_level $2...=message
# Callers: pr_warn, pr_info, pr_verbose, pr_debug, _emit_text, toplevel batch output
_pr_echo() {
    if [ "$opt_verbose" -ge "$1" ]; then
        shift
        _pr_echo_raw '' "$*"
    fi
}

# Print a message without trailing newline if the current verbosity level is high enough
# Args: $1=minimum_verbosity_level $2...=message
# Callers: pr_info_nol, pr_verbose_nol
_pr_echo_nol() {
    if [ "$opt_verbose" -ge "$1" ]; then
        shift
        _pr_echo_raw -n "$*"
    fi
}

# Print a warning message in red to stderr (verbosity 0, always shown)
# Args: $1...=message
pr_warn() {
    _pr_echo 0 "\033[31m$*\033[0m" >&2
}

# Print an informational message (verbosity >= 1)
# Args: $1...=message
pr_info() {
    _pr_echo 1 "$*"
}

# Print an informational message without trailing newline (verbosity >= 1)
# Args: $1...=message
pr_info_nol() {
    _pr_echo_nol 1 "$*"
}

# Print a verbose message (verbosity >= 2)
# Args: $1...=message
pr_verbose() {
    _pr_echo 2 "$*"
}

# Print a verbose message without trailing newline (verbosity >= 2)
# Args: $1...=message
pr_verbose_nol() {
    _pr_echo_nol 2 "$*"
}

# Print a debug message in blue (verbosity >= 3)
# Args: $1...=message
pr_debug() {
    _pr_echo 3 "\033[34m(debug) $*\033[0m"
}

# Print a "How to fix" explanation when --explain is enabled
# Args: $1...=fix description
explain() {
    if [ "$opt_explain" = 1 ]; then
        pr_info ''
        pr_info "> \033[41m\033[30mHow to fix:\033[0m $*"
    fi
}

# Convert a CVE ID to its human-readable vulnerability name
# Args: $1=cve_id (e.g. "CVE-2017-5753")
cve2name() {
    _cve_registry_field "$1" 4
}

g_is_cpu_affected_cached=0

# >>>>>> libs/200_cpu_affected.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:

# Helpers for is_cpu_affected: encode the 4 patterns for setting affected_* variables.
# Each function takes the variable suffix as $1 (e.g. "variantl1tf", not "affected_variantl1tf").
# Variables hold 1 (not affected / immune) or 0 (affected / vuln); empty = not yet decided.

# Set affected_$1 to 1 (not affected) unconditionally.
# Use for: hardware capability bits (cap_rdcl_no, cap_ssb_no, cap_gds_no, cap_tsa_*_no),
#          is_cpu_specex_free results, and vendor-wide immune facts (AMD/L1TF, Cavium, etc.).
# This always wins and cannot be overridden by _infer_vuln (which only fires on empty).
# Must not be followed by _set_vuln for the same variable in the same code path.
_set_immune() { eval "affected_$1=1"; }

# Set affected_$1 to 0 (affected) unconditionally.
# Use for: confirmed-vuln model/erratum lists, ARM unknown-CPU fallback.
# Note: intentionally overrides a prior _infer_immune (1) — this is required for ARM
#       big.LITTLE cumulative logic where a second vuln core must override a prior safe core.
# Must not be called after _set_immune for the same variable in the same code path.
_set_vuln() { eval "affected_$1=0"; }

# Set affected_$1 to 1 (not affected) only if not yet decided (currently empty).
# Use for: model/family whitelists, per-part ARM immune inferences,
#          AMD/ARM partial immunity (immune on this variant axis but not others).
_infer_immune() { eval "[ -z \"\$affected_$1\" ] && affected_$1=1 || :"; }

# Set affected_$1 to 0 (affected) only if not yet decided (currently empty).
# Use for: family-level catch-all fallbacks (Intel L1TF non-whitelist, itlbmh non-whitelist).
_infer_vuln() { eval "[ -z \"\$affected_$1\" ] && affected_$1=0 || :"; }

# Return the cached affected_* status for a given CVE
# Args: $1=cve_id
# Returns: 0 if affected, 1 if not affected
# Callers: is_cpu_affected
_is_cpu_affected_cached() {
    local suffix
    suffix=$(_cve_registry_field "$1" 3)
    # shellcheck disable=SC2086
    eval "return \$affected_${suffix}"
}

# Determine whether the current CPU is affected by a given CVE using whitelist logic
# Args: $1=cve_id (one of the $g_supported_cve_list items)
# Returns: 0 if affected, 1 if not affected
is_cpu_affected() {
    local result cpuid_hex reptar_ucode_list bpi_ucode_list tuple fixed_ucode_ver affected_fmspi affected_fms ucode_platformid_mask affected_cpuid i cpupart cpuarch

    # if CPU is Intel and is in our dump of the Intel official affected CPUs page, use it:
    if is_intel; then
        cpuid_hex=$(printf "0x%08X" $((cpu_cpuid)))
        if [ "${g_intel_line:-}" = "no" ]; then
            pr_debug "is_cpu_affected: $cpuid_hex not in Intel database (cached)"
        elif [ -z "$g_intel_line" ]; then
            g_intel_line=$(read_inteldb | grep -F "$cpuid_hex," | head -n1)
            if [ -z "$g_intel_line" ]; then
                g_intel_line=no
                pr_debug "is_cpu_affected: $cpuid_hex not in Intel database"
            fi
        fi
        if [ "$g_intel_line" != "no" ]; then
            result=$(echo "$g_intel_line" | grep -Eo ,"$(echo "$1" | cut -c5-)"'=[^,]+' | cut -d= -f2)
            pr_debug "is_cpu_affected: inteldb for $1 says '$result'"

            # handle special case for Foreshadow SGX (CVE-2018-3615):
            # even if we are affected to L1TF (CVE-2018-3620/CVE-2018-3646), if there's no SGX on our CPU,
            # then we're not affected to the original Foreshadow.
            if [ "$1" = "CVE-2018-3615" ] && [ "$cap_sgx" = 0 ]; then
                # not affected
                return 1
            fi
            # /special case

            if [ "$result" = "N" ]; then
                # not affected
                return 1
            elif [ -n "$result" ]; then
                # non-empty string != N means affected
                return 0
            fi
        fi
    fi

    # Otherwise, do it ourselves

    if [ "$g_is_cpu_affected_cached" = 1 ]; then
        _is_cpu_affected_cached "$1"
        return $?
    fi

    affected_variant1=''
    affected_variant2=''
    affected_variant3=''
    affected_variant3a=''
    affected_variant4=''
    affected_variantl1tf=''
    affected_msbds=''
    affected_mfbds=''
    affected_mlpds=''
    affected_mdsum=''
    affected_taa=''
    affected_itlbmh=''
    affected_srbds=''
    # Zenbleed and Inception are both AMD specific, look for "is_amd" below:
    _set_immune zenbleed
    _set_immune inception
    # TSA is AMD specific (Zen 3/4), look for "is_amd" below:
    _set_immune tsa
    # Retbleed: AMD (CVE-2022-29900) and Intel (CVE-2022-29901) specific:
    _set_immune retbleed
    # Downfall, Reptar, ITS & BPI are Intel specific, look for "is_intel" below:
    _set_immune downfall
    _set_immune reptar
    _set_immune its
    _set_immune bpi
    # VMScape affects Intel, AMD and Hygon — set immune, overridden below:
    _set_immune vmscape

    if is_cpu_mds_free; then
        _infer_immune msbds
        _infer_immune mfbds
        _infer_immune mlpds
        _infer_immune mdsum
        pr_debug "is_cpu_affected: cpu not affected by Microarchitectural Data Sampling"
    fi

    if is_cpu_taa_free; then
        _infer_immune taa
        pr_debug "is_cpu_affected: cpu not affected by TSX Asynhronous Abort"
    fi

    if is_cpu_srbds_free; then
        _infer_immune srbds
        pr_debug "is_cpu_affected: cpu not affected by Special Register Buffer Data Sampling"
    fi

    # NO_SPECTRE_V2: Centaur family 7 and Zhaoxin family 7 are immune to Spectre V2
    # kernel commit 1e41a766c98b (v5.6-rc1): added NO_SPECTRE_V2 exemption
    # Zhaoxin vendor_id is "  Shanghai  " in cpuinfo (parsed as "Shanghai" by awk)
    if { [ "$cpu_vendor" = "CentaurHauls" ] || [ "$cpu_vendor" = "Shanghai" ]; } && [ "$cpu_family" = 7 ]; then
        _infer_immune variant2
        pr_debug "is_cpu_affected: Centaur/Zhaoxin family 7 immune to Spectre V2 (NO_SPECTRE_V2)"
    fi

    if is_cpu_specex_free; then
        _set_immune variant1
        _set_immune variant2
        _set_immune variant3
        _set_immune variant3a
        _set_immune variant4
        _set_immune variantl1tf
        _set_immune msbds
        _set_immune mfbds
        _set_immune mlpds
        _set_immune mdsum
        _set_immune taa
        _set_immune srbds
    elif is_intel; then
        # Intel
        # https://github.com/crozone/SpectrePoC/issues/1 ^F E5200 => spectre 2 not affected
        # https://github.com/paboldin/meltdown-exploit/issues/19 ^F E5200 => meltdown affected
        # model name : Pentium(R) Dual-Core  CPU      E5200  @ 2.50GHz
        if echo "$cpu_friendly_name" | grep -qE 'Pentium\(R\) Dual-Core[[:space:]]+CPU[[:space:]]+E[0-9]{4}K?'; then
            _set_vuln variant1
            _infer_immune variant2
            _set_vuln variant3
        fi
        if [ "$cap_rdcl_no" = 1 ]; then
            # capability bit for future Intel processor that will explicitly state
            # that they're not affected to Meltdown
            # this var is set in check_cpu()
            _set_immune variant3
            _set_immune variantl1tf
            pr_debug "is_cpu_affected: RDCL_NO is set so not vuln to meltdown nor l1tf"
        fi
        if [ "$cap_ssb_no" = 1 ]; then
            # capability bit for future Intel processor that will explicitly state
            # that they're not affected to Variant 4
            # this var is set in check_cpu()
            _set_immune variant4
            pr_debug "is_cpu_affected: SSB_NO is set so not vuln to affected_variant4"
        fi
        if is_cpu_ssb_free; then
            _infer_immune variant4
            pr_debug "is_cpu_affected: cpu not affected by speculative store bypass so not vuln to affected_variant4"
        fi
        # variant 3a
        if [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNL" ] || [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNM" ]; then
                pr_debug "is_cpu_affected: xeon phi immune to variant 3a"
                _infer_immune variant3a
            elif [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_D" ]; then
                # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00115.html
                # https://github.com/speed47/spectre-meltdown-checker/issues/310
                # => silvermont CPUs (aka cherry lake for tablets and brawsell for mobile/desktop) don't seem to be affected
                # => goldmont ARE affected
                pr_debug "is_cpu_affected: silvermont immune to variant 3a"
                _infer_immune variant3a
            fi
        fi
        # L1TF (cap_rdcl_no already checked above)
        if [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_TABLET" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_AIRMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_MID2" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_AIRMONT_NP" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_PLUS" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_TREMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNM" ]; then

                pr_debug "is_cpu_affected: intel family 6 but model known to be immune to l1tf"
                _infer_immune variantl1tf
            else
                pr_debug "is_cpu_affected: intel family 6 is vuln to l1tf"
                _infer_vuln variantl1tf
            fi
        elif [ "$cpu_family" -lt 6 ]; then
            pr_debug "is_cpu_affected: intel family < 6 is immune to l1tf"
            _infer_immune variantl1tf
        fi
        # Downfall
        if [ "$cap_gds_no" = 1 ]; then
            # capability bit for future Intel processors that will explicitly state
            # that they're unaffected by GDS. Also set by hypervisors on virtual CPUs
            # so that the guest kernel doesn't try to mitigate GDS when it's already mitigated on the host
            pr_debug "is_cpu_affected: downfall: not affected (GDS_NO)"
            _set_immune downfall
        elif [ "$cpu_family" = 6 ]; then
            # model blacklist from the kernel (arch/x86/kernel/cpu/common.c cpu_vuln_blacklist):
            # 8974eb588283 (initial list) + c9f4c45c8ec3 (added Skylake/Skylake_L client)
            set -u
            if [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_COMETLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_COMETLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_TIGERLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_TIGERLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ROCKETLAKE" ]; then
                pr_debug "is_cpu_affected: downfall: affected"
                _set_vuln downfall
            elif [ "$cap_avx2" = 0 ] && [ "$cap_avx512" = 0 ]; then
                pr_debug "is_cpu_affected: downfall: no avx; immune"
                _infer_immune downfall
            else
                # Intel family 6 CPU with AVX2 or AVX512, not in the known-affected list
                # and GDS_NO not set: assume affected (whitelist principle)
                pr_debug "is_cpu_affected: downfall: unknown AVX-capable CPU, defaulting to affected"
                _infer_vuln downfall
            fi
            set +u
        fi
        # ITS (Indirect Target Selection, CVE-2024-28956)
        # kernel vulnerable_to_its() + cpu_vuln_blacklist (159013a7ca18)
        # immunity: ARCH_CAP_ITS_NO (bit 62 of IA32_ARCH_CAPABILITIES)
        # immunity: X86_FEATURE_BHI_CTRL (none of the affected CPUs have this)
        # vendor scope: Intel only (family 6), with stepping constraints on some models
        if [ "$cap_its_no" = 1 ]; then
            pr_debug "is_cpu_affected: its: not affected (ITS_NO)"
            _set_immune its
        elif [ "$cpu_family" = 6 ]; then
            set -u
            if { [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_X" ] && [ "$cpu_stepping" -gt 5 ]; } ||
                { [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE_L" ] && [ "$cpu_stepping" -gt 11 ]; } ||
                { [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE" ] && [ "$cpu_stepping" -gt 12 ]; } ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_COMETLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_COMETLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_TIGERLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_TIGERLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ROCKETLAKE" ]; then
                pr_debug "is_cpu_affected: its: affected"
                _set_vuln its
            fi
            set +u
        fi
        # Reptar
        # the only way to know whether a CPU is vuln, is to check whether there is a known ucode update for it,
        # as the mitigation is only ucode-based and there's no flag exposed by the kernel or by an updated ucode.
        # we have to hardcode the truthtable of affected CPUs vs updated ucodes...
        # https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/redundant-prefix-issue.html
        # list initially taken from:
        # https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/commit/ece0d294a29a1375397941a4e6f2f7217910bc89#diff-e6fad0f2abbac6c9603b2e8f88fe1d151a83de708aeca1c1d93d881c958ecba4R26
        # updated 2026-04 with Intel affected processor list + releasenote.md:
        # added 06-9a-04/40 (AZB), 06-bd-01/80 (Lunar Lake, post-dates Reptar: first ucode already includes fix)
        g_reptar_fixed_ucode_version=''
        reptar_ucode_list='
06-97-02/07,00000032
06-97-05/07,00000032
06-9a-03/80,00000430
06-9a-04/80,00000430
06-9a-04/40,00000005
06-6c-01/10,01000268
06-6a-06/87,0d0003b9
06-7e-05/80,000000c2
06-ba-02/e0,0000411c
06-b7-01/32,0000011d
06-a7-01/02,0000005d
06-bf-05/07,00000032
06-bf-02/07,00000032
06-ba-03/e0,0000411c
06-8f-08/87,2b0004d0
06-8f-07/87,2b0004d0
06-8f-06/87,2b0004d0
06-8f-05/87,2b0004d0
06-8f-04/87,2b0004d0
06-8f-08/10,2c000290
06-8c-01/80,000000b4
06-8c-00/ff,000000b4
06-8d-01/c2,0000004e
06-8d-00/c2,0000004e
06-8c-02/c2,00000034
06-bd-01/80,0000011f
'
        for tuple in $reptar_ucode_list; do
            fixed_ucode_ver=$((0x$(echo "$tuple" | cut -d, -f2)))
            affected_fmspi=$(echo "$tuple" | cut -d, -f1)
            affected_fms=$(echo "$affected_fmspi" | cut -d/ -f1)
            ucode_platformid_mask=0x$(echo "$affected_fmspi" | cut -d/ -f2)
            affected_cpuid=$(
                fms2cpuid \
                    0x"$(echo "$affected_fms" | cut -d- -f1)" \
                    0x"$(echo "$affected_fms" | cut -d- -f2)" \
                    0x"$(echo "$affected_fms" | cut -d- -f3)"
            )
            if [ "$cpu_cpuid" = "$affected_cpuid" ] && [ $((cpu_platformid & ucode_platformid_mask)) -gt 0 ]; then
                _set_vuln reptar
                g_reptar_fixed_ucode_version=$fixed_ucode_ver
                break
            fi
        done
        # if we didn't match the ucode list above, also check the model blacklist:
        # Intel never tells about their EOL CPUs, so more CPUs might be affected
        # than the ones that received a microcode update (e.g. steppings with
        # different platform IDs that were dropped before the Reptar fix).
        if [ -z "$g_reptar_fixed_ucode_version" ] && [ "$cpu_family" = 6 ]; then
            set -u
            if [ "$cpu_model" = "$INTEL_FAM6_ALDERLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ALDERLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ROCKETLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_TIGERLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_TIGERLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SAPPHIRERAPIDS_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_RAPTORLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_RAPTORLAKE_P" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_RAPTORLAKE_S" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_LUNARLAKE_M" ]; then
                pr_debug "is_cpu_affected: reptar: affected (model match, no known fixing ucode)"
                _set_vuln reptar
            fi
            set +u
        fi

        # Retbleed (Intel, CVE-2022-29901): Skylake through Rocket Lake, or any CPU with RSBA
        # kernel cpu_vuln_blacklist for RETBLEED (6b80b59b3555, 6ad0ad2bf8a6, f54d45372c6a)
        # plus ARCH_CAP_RSBA catch-all (bit 2 of IA32_ARCH_CAPABILITIES)
        if [ "$cap_rsba" = 1 ]; then
            _set_vuln retbleed
        elif [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_CANNONLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_COMETLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_COMETLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_LAKEFIELD" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ROCKETLAKE" ]; then
                _set_vuln retbleed
            fi
        fi

        # VMScape (CVE-2025-40300): Intel model blacklist
        # kernel cpu_vuln_blacklist VMSCAPE (a508cec6e521 + 8a68d64bb103)
        # immunity: no ARCH_CAP bits (purely blacklist-based)
        # note: kernel only sets bug on bare metal (!X86_FEATURE_HYPERVISOR)
        # vendor scope: Intel + AMD + Hygon (AMD/Hygon handled below)
        if [ "$cpu_family" = 6 ]; then
            set -u
            if [ "$cpu_model" = "$INTEL_FAM6_SANDYBRIDGE_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SANDYBRIDGE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_IVYBRIDGE_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_IVYBRIDGE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_HASWELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_HASWELL_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_HASWELL_G" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_HASWELL_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_BROADWELL_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_BROADWELL_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_BROADWELL_G" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_BROADWELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_CANNONLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_COMETLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_COMETLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ALDERLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ALDERLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_RAPTORLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_RAPTORLAKE_P" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_RAPTORLAKE_S" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_METEORLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ARROWLAKE_H" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ARROWLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ARROWLAKE_U" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_LUNARLAKE_M" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SAPPHIRERAPIDS_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_GRANITERAPIDS_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_EMERALDRAPIDS_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GRACEMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_CRESTMONT_X" ]; then
                pr_debug "is_cpu_affected: vmscape: affected"
                _set_vuln vmscape
            fi
            set +u
        fi

        # BPI (Branch Privilege Injection, CVE-2024-45332)
        # microcode-only fix, no kernel X86_BUG flag, no CPUID/MSR indicator for the fix.
        # We have to hardcode the truthtable of affected CPUs vs fixing ucodes,
        # same approach as Reptar (see above).
        # https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/indirect-branch-predictor-delayed-updates.html
        # list taken from Intel affected processor list + Intel-Linux-Processor-Microcode-Data-Files releasenote.md
        # format: FF-MM-SS/platformid_mask,fixed_ucode_version
        g_bpi_fixed_ucode_version=''
        bpi_ucode_list='
06-9e-0d/22,00000104
06-8e-0a/c0,000000f6
06-8e-0b/d0,000000f6
06-8e-0c/94,00000100
06-a5-02/20,00000100
06-a5-03/22,00000100
06-a5-05/22,00000100
06-a6-00/80,00000102
06-a6-01/80,00000100
06-a7-01/02,00000065
06-7e-05/80,000000cc
06-6a-06/87,0d000421
06-6c-01/10,010002f1
06-8c-01/80,000000be
06-8c-02/c2,0000003e
06-8d-01/c2,00000058
06-97-02/07,0000003e
06-97-05/07,0000003e
06-9a-03/80,0000043b
06-9a-04/80,0000043b
06-9a-04/40,0000000c
06-be-00/19,00000021
06-b7-01/32,00000133
06-ba-02/e0,00006134
06-ba-03/e0,00006134
06-bf-02/07,0000003e
06-bf-05/07,0000003e
06-aa-04/e6,00000028
06-b5-00/80,0000000d
06-c5-02/82,0000011b
06-c6-02/82,0000011b
06-bd-01/80,00000125
06-55-0b/bf,07002b01
06-8f-07/87,2b000661
06-8f-08/87,2b000661
06-8f-08/10,2c000421
06-cf-02/87,210002d3
06-7a-08/01,00000026
'
        for tuple in $bpi_ucode_list; do
            fixed_ucode_ver=$((0x$(echo "$tuple" | cut -d, -f2)))
            affected_fmspi=$(echo "$tuple" | cut -d, -f1)
            affected_fms=$(echo "$affected_fmspi" | cut -d/ -f1)
            ucode_platformid_mask=0x$(echo "$affected_fmspi" | cut -d/ -f2)
            affected_cpuid=$(
                fms2cpuid \
                    0x"$(echo "$affected_fms" | cut -d- -f1)" \
                    0x"$(echo "$affected_fms" | cut -d- -f2)" \
                    0x"$(echo "$affected_fms" | cut -d- -f3)"
            )
            if [ "$cpu_cpuid" = "$affected_cpuid" ] && [ $((cpu_platformid & ucode_platformid_mask)) -gt 0 ]; then
                _set_vuln bpi
                g_bpi_fixed_ucode_version=$fixed_ucode_ver
                break
            fi
        done
        # if we didn't match the ucode list above, also check the model blacklist:
        # Intel never tells about their EOL CPUs, so more CPUs might be affected
        # than the ones that received a microcode update. In that case, we flag
        # the CPU as affected but g_bpi_fixed_ucode_version stays empty (the CVE
        # check will handle this by reporting VULN with no known fix).
        if [ -z "$g_bpi_fixed_ucode_version" ] && [ "$cpu_family" = 6 ]; then
            set -u
            if [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_COMETLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_COMETLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ROCKETLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_TIGERLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_TIGERLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ALDERLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ALDERLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GRACEMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_RAPTORLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_RAPTORLAKE_P" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_RAPTORLAKE_S" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_METEORLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ARROWLAKE_H" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ARROWLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ARROWLAKE_U" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_LUNARLAKE_M" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SAPPHIRERAPIDS_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_EMERALDRAPIDS_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_PLUS" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_CRESTMONT" ]; then
                pr_debug "is_cpu_affected: bpi: affected (model match, no known fixing ucode)"
                _set_vuln bpi
            fi
            set +u
        fi

    elif is_amd || is_hygon; then
        # AMD revised their statement about affected_variant2 => affected
        # https://www.amd.com/en/corporate/speculative-execution
        _set_vuln variant1
        _set_vuln variant2
        _infer_immune variant3
        # https://www.amd.com/en/corporate/security-updates
        # "We have not identified any AMD x86 products susceptible to the Variant 3a vulnerability in our analysis to-date."
        _infer_immune variant3a
        if is_cpu_ssb_free; then
            _infer_immune variant4
            pr_debug "is_cpu_affected: cpu not affected by speculative store bypass so not vuln to affected_variant4"
        fi
        _set_immune variantl1tf

        # Zenbleed
        amd_legacy_erratum "$(amd_model_range 0x17 0x30 0x0 0x4f 0xf)" && _set_vuln zenbleed
        amd_legacy_erratum "$(amd_model_range 0x17 0x60 0x0 0x7f 0xf)" && _set_vuln zenbleed
        amd_legacy_erratum "$(amd_model_range 0x17 0xa0 0x0 0xaf 0xf)" && _set_vuln zenbleed

        # Inception (according to kernel, zen 1 to 4)
        if [ "$cpu_family" = $((0x17)) ] || [ "$cpu_family" = $((0x19)) ]; then
            _set_vuln inception
        fi

        # TSA (Zen 3/4 are affected, unless CPUID says otherwise)
        if [ "$cap_tsa_sq_no" = 1 ] && [ "$cap_tsa_l1_no" = 1 ]; then
            # capability bits for AMD processors that explicitly state
            # they're not affected to TSA-SQ and TSA-L1
            # these vars are set in check_cpu()
            pr_debug "is_cpu_affected: TSA_SQ_NO and TSA_L1_NO are set so not vuln to TSA"
            _set_immune tsa
        elif [ "$cpu_family" = $((0x19)) ]; then
            _set_vuln tsa
        fi

        # Retbleed (AMD, CVE-2022-29900): families 0x15-0x17 (kernel X86_BUG_RETBLEED)
        if [ "$cpu_family" = $((0x15)) ] || [ "$cpu_family" = $((0x16)) ] || [ "$cpu_family" = $((0x17)) ]; then
            _set_vuln retbleed
        fi

        # VMScape (CVE-2025-40300): AMD families 0x17/0x19/0x1a, Hygon family 0x18
        # kernel cpu_vuln_blacklist VMSCAPE (a508cec6e521)
        if is_amd; then
            if [ "$cpu_family" = $((0x17)) ] || [ "$cpu_family" = $((0x19)) ] || [ "$cpu_family" = $((0x1a)) ]; then
                pr_debug "is_cpu_affected: vmscape: AMD family $cpu_family affected"
                _set_vuln vmscape
            fi
        elif is_hygon; then
            if [ "$cpu_family" = $((0x18)) ]; then
                pr_debug "is_cpu_affected: vmscape: Hygon family $cpu_family affected"
                _set_vuln vmscape
            fi
        fi

    elif [ "$cpu_vendor" = CAVIUM ]; then
        _set_immune variant3
        _set_immune variant3a
        _set_immune variantl1tf
    elif [ "$cpu_vendor" = PHYTIUM ]; then
        _set_immune variant3
        _set_immune variant3a
        _set_immune variantl1tf
    elif [ "$cpu_vendor" = ARM ]; then
        # ARM
        # reference: https://developer.arm.com/support/security-update
        # some devices (phones or other) have several ARMs and as such different part numbers,
        # an example is "bigLITTLE". we shouldn't rely on the first CPU only, so we check the whole list
        i=0
        for cpupart in $cpu_part_list; do
            i=$((i + 1))
            # do NOT quote $cpu_arch_list below
            # shellcheck disable=SC2086
            cpuarch=$(echo $cpu_arch_list | awk '{ print $'$i' }')
            pr_debug "checking cpu$i: <$cpupart> <$cpuarch>"
            # some kernels report AArch64 instead of 8
            [ "$cpuarch" = "AArch64" ] && cpuarch=8
            # some kernels report architecture with suffix (e.g. "5TEJ" for ARMv5TEJ), extract numeric prefix
            cpuarch=$(echo "$cpuarch" | grep -oE '^[0-9]+')
            if [ -n "$cpupart" ] && [ -n "$cpuarch" ]; then
                # Cortex-R7 and Cortex-R8 are real-time and only used in medical devices or such
                # I can't find their CPU part number, but it's probably not that useful anyway
                # model R7 R8 A8  A9  A12 A15 A17 A57 A72 A73 A75 A76 A77 Neoverse-N1 Neoverse-V1 Neoverse-N1 Neoverse-V2
                # part   ?  ? c08 c09 c0d c0f c0e d07 d08 d09 d0a d0b d0d d0c         d40	  d49	      d4f
                # arch  7? 7? 7   7   7   7   7   8   8   8   8   8   8   8           8		  8	      8
                #
                # Whitelist identified non-affected processors, use vulnerability information from
                # https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability
                # Partnumbers can be found here:
                # https://github.com/gcc-mirror/gcc/blob/master/gcc/config/arm/arm-cpus.in
                #
                # Maintain cumulative check of vulnerabilities -
                # if at least one of the cpu is affected, then the system is affected
                if [ "$cpuarch" = 7 ] && echo "$cpupart" | grep -q -w -e 0xc08 -e 0xc09 -e 0xc0d -e 0xc0e; then
                    _set_vuln variant1
                    _set_vuln variant2
                    _infer_immune variant3
                    _infer_immune variant3a
                    _infer_immune variant4
                    pr_debug "checking cpu$i: armv7 A8/A9/A12/A17 non affected to variants 3, 3a & 4"
                elif [ "$cpuarch" = 7 ] && echo "$cpupart" | grep -q -w -e 0xc0f; then
                    _set_vuln variant1
                    _set_vuln variant2
                    _infer_immune variant3
                    _set_vuln variant3a
                    _infer_immune variant4
                    pr_debug "checking cpu$i: armv7 A15 non affected to variants 3 & 4"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd07 -e 0xd08; then
                    _set_vuln variant1
                    _set_vuln variant2
                    _infer_immune variant3
                    _set_vuln variant3a
                    _set_vuln variant4
                    pr_debug "checking cpu$i: armv8 A57/A72 non affected to variants 3"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd09; then
                    _set_vuln variant1
                    _set_vuln variant2
                    _infer_immune variant3
                    _infer_immune variant3a
                    _set_vuln variant4
                    pr_debug "checking cpu$i: armv8 A73 non affected to variants 3 & 3a"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd0a; then
                    _set_vuln variant1
                    _set_vuln variant2
                    _set_vuln variant3
                    _infer_immune variant3a
                    _set_vuln variant4
                    pr_debug "checking cpu$i: armv8 A75 non affected to variant 3a"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd0b -e 0xd0c -e 0xd0d; then
                    _set_vuln variant1
                    _infer_immune variant2
                    _infer_immune variant3
                    _infer_immune variant3a
                    _set_vuln variant4
                    pr_debug "checking cpu$i: armv8 A76/A77/NeoverseN1 non affected to variant 2, 3 & 3a"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd40 -e 0xd49 -e 0xd4f; then
                    _set_vuln variant1
                    _infer_immune variant2
                    _infer_immune variant3
                    _infer_immune variant3a
                    _infer_immune variant4
                    pr_debug "checking cpu$i: armv8 NeoverseN2/V1/V2 non affected to variant 2, 3, 3a & 4"
                elif [ "$cpuarch" -le 7 ] || { [ "$cpuarch" = 8 ] && [ $((cpupart)) -lt $((0xd07)) ]; }; then
                    _infer_immune variant1
                    _infer_immune variant2
                    _infer_immune variant3
                    _infer_immune variant3a
                    _infer_immune variant4
                    pr_debug "checking cpu$i: arm arch$cpuarch, all immune (v7 or v8 and model < 0xd07)"
                else
                    _set_vuln variant1
                    _set_vuln variant2
                    _set_vuln variant3
                    _set_vuln variant3a
                    _set_vuln variant4
                    pr_debug "checking cpu$i: arm unknown arch$cpuarch part$cpupart, considering vuln"
                fi
            fi
            pr_debug "is_cpu_affected: for cpu$i and so far, we have <$affected_variant1> <$affected_variant2> <$affected_variant3> <$affected_variant3a> <$affected_variant4>"
        done
        _set_immune variantl1tf
    fi

    # we handle iTLB Multihit here (not linked to is_specex_free)
    if is_intel; then
        # commit f9aa6b73a407b714c9aac44734eb4045c893c6f7
        if [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_TABLET" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_AIRMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNM" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_MID2" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_PLUS" ]; then
                pr_debug "is_cpu_affected: intel family 6 but model known to be immune to itlbmh"
                _infer_immune itlbmh
            else
                pr_debug "is_cpu_affected: intel family 6 is vuln to itlbmh"
                _infer_vuln itlbmh
            fi
        elif [ "$cpu_family" -lt 6 ]; then
            pr_debug "is_cpu_affected: intel family < 6 is immune to itlbmh"
            _infer_immune itlbmh
        fi
    else
        pr_debug "is_cpu_affected: non-intel not affected to itlbmh"
        _infer_immune itlbmh
    fi

    # shellcheck disable=SC2154  # affected_zenbleed/inception/retbleed/tsa/downfall/reptar/its/vmscape/bpi set via eval (_set_immune)
    {
        pr_debug "is_cpu_affected: final results: variant1=$affected_variant1 variant2=$affected_variant2 variant3=$affected_variant3 variant3a=$affected_variant3a"
        pr_debug "is_cpu_affected: final results: variant4=$affected_variant4 variantl1tf=$affected_variantl1tf msbds=$affected_msbds mfbds=$affected_mfbds"
        pr_debug "is_cpu_affected: final results: mlpds=$affected_mlpds mdsum=$affected_mdsum taa=$affected_taa itlbmh=$affected_itlbmh srbds=$affected_srbds"
        pr_debug "is_cpu_affected: final results: zenbleed=$affected_zenbleed inception=$affected_inception retbleed=$affected_retbleed tsa=$affected_tsa downfall=$affected_downfall reptar=$affected_reptar its=$affected_its"
        pr_debug "is_cpu_affected: final results: vmscape=$affected_vmscape bpi=$affected_bpi"
    }
    affected_variantl1tf_sgx="$affected_variantl1tf"
    # even if we are affected to L1TF, if there's no SGX, we're not affected to the original foreshadow
    [ "$cap_sgx" = 0 ] && _set_immune variantl1tf_sgx
    pr_debug "is_cpu_affected: variantl1tf_sgx=<$affected_variantl1tf_sgx>"
    g_is_cpu_affected_cached=1
    _is_cpu_affected_cached "$1"
    return $?
}

# >>>>>> libs/210_cpu_detect.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# Check whether the CPU is known to not perform speculative execution
# Returns: 0 if the CPU is speculation-free, 1 otherwise
is_cpu_specex_free() {
    # source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/cpu/common.c#n882
    # { X86_VENDOR_INTEL,	6, INTEL_FAM6_ATOM_SALTWELL,	X86_FEATURE_ANY },
    # { X86_VENDOR_INTEL,	6, INTEL_FAM6_ATOM_SALTWELL_TABLET,	X86_FEATURE_ANY },
    # { X86_VENDOR_INTEL,	6, INTEL_FAM6_ATOM_BONNELL_MID,	X86_FEATURE_ANY },
    # { X86_VENDOR_INTEL,	6, INTEL_FAM6_ATOM_SALTWELL_MID,	X86_FEATURE_ANY },
    # { X86_VENDOR_INTEL,	6, INTEL_FAM6_ATOM_BONNELL,	X86_FEATURE_ANY },
    # { X86_VENDOR_CENTAUR,   5 },
    # { X86_VENDOR_INTEL,     5 },
    # { X86_VENDOR_NSC,       5 },
    # { X86_VENDOR_ANY,       4 },

    parse_cpu_details
    if is_intel; then
        if [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_TABLET" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL" ]; then
                return 0
            fi
        elif [ "$cpu_family" = 5 ]; then
            return 0
        fi
    fi
    # Centaur family 5 and NSC family 5 are also non-speculative
    if [ "$cpu_vendor" = "CentaurHauls" ] && [ "$cpu_family" = 5 ]; then
        return 0
    fi
    if [ "$cpu_vendor" = "Geode by NSC" ] && [ "$cpu_family" = 5 ]; then
        return 0
    fi
    [ "$cpu_family" = 4 ] && return 0
    return 1
}

# Check whether the CPU is known to be unaffected by microarchitectural data sampling (MDS)
# Returns: 0 if MDS-free, 1 if affected or unknown
is_cpu_mds_free() {
    # source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/cpu/common.c
    #VULNWL_INTEL(ATOM_GOLDMONT,             NO_MDS | NO_L1TF),
    #VULNWL_INTEL(ATOM_GOLDMONT_X,           NO_MDS | NO_L1TF),
    #VULNWL_INTEL(ATOM_GOLDMONT_PLUS,        NO_MDS | NO_L1TF),

    #/* AMD Family 0xf - 0x12 */
    #VULNWL_AMD(0x0f,        NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS),
    #VULNWL_AMD(0x10,        NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS),
    #VULNWL_AMD(0x11,        NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS),
    #VULNWL_AMD(0x12,        NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS),

    #/* FAMILY_ANY must be last, otherwise 0x0f - 0x12 matches won't work */
    #VULNWL_AMD(X86_FAMILY_ANY,      NO_MELTDOWN | NO_L1TF | NO_MDS),
    #VULNWL_HYGON(X86_FAMILY_ANY,    NO_MELTDOWN | NO_L1TF | NO_MDS),
    parse_cpu_details
    if is_intel; then
        if [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_PLUS" ]; then
                return 0
            fi
        fi
        [ "$cap_mds_no" = 1 ] && return 0
    fi

    # official statement from AMD says none of their CPUs are affected
    # https://www.amd.com/en/corporate/product-security
    # https://www.amd.com/system/files/documents/security-whitepaper.pdf
    if is_amd; then
        return 0
    elif is_hygon; then
        return 0
    elif [ "$cpu_vendor" = CAVIUM ]; then
        return 0
    elif [ "$cpu_vendor" = PHYTIUM ]; then
        return 0
    elif [ "$cpu_vendor" = ARM ]; then
        return 0
    fi

    return 1
}

# Check whether the CPU is known to be unaffected by TSX Asynchronous Abort (TAA)
# Returns: 0 if TAA-free, 1 if affected or unknown
is_cpu_taa_free() {

    if ! is_intel; then
        return 0
    # is intel
    elif [ "$cap_taa_no" = 1 ] || [ "$cap_rtm" = 0 ]; then
        return 0
    fi

    return 1
}

# Check whether the CPU is known to be unaffected by Special Register Buffer Data Sampling (SRBDS)
# Returns: 0 if SRBDS-free, 1 if affected or unknown
is_cpu_srbds_free() {
    # source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/cpu/common.c
    #
    # A processor is affected by SRBDS if its Family_Model and stepping is in the
    # following list, with the exception of the listed processors
    # exporting MDS_NO while Intel TSX is available yet not enabled. The
    # latter class of processors are only affected when Intel TSX is enabled
    # by software using TSX_CTRL_MSR otherwise they are not affected.
    #
    # =============  ============  ========
    # common name    Family_Model  Stepping
    # =============  ============  ========
    # IvyBridge      06_3AH        All              (INTEL_FAM6_IVYBRIDGE)
    #
    # Haswell        06_3CH        All              (INTEL_FAM6_HASWELL)
    # Haswell_L      06_45H        All              (INTEL_FAM6_HASWELL_L)
    # Haswell_G      06_46H        All              (INTEL_FAM6_HASWELL_G)
    #
    # Broadwell_G    06_47H        All              (INTEL_FAM6_BROADWELL_G)
    # Broadwell      06_3DH        All              (INTEL_FAM6_BROADWELL)
    #
    # Skylake_L      06_4EH        All              (INTEL_FAM6_SKYLAKE_L)
    # Skylake        06_5EH        All              (INTEL_FAM6_SKYLAKE)
    #
    # Kabylake_L     06_8EH        <=0xC (MDS_NO)   (INTEL_FAM6_KABYLAKE_L)
    #
    # Kabylake       06_9EH        <=0xD (MDS_NO)   (INTEL_FAM6_KABYLAKE)
    # =============  ============  ========
    parse_cpu_details
    if is_intel; then
        if [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_IVYBRIDGE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_HASWELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_HASWELL_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_HASWELL_G" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_BROADWELL_G" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_BROADWELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE" ]; then
                return 1
            elif [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE_L" ] && [ "$cpu_stepping" -le 12 ] ||
                [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE" ] && [ "$cpu_stepping" -le 13 ]; then
                if [ "$cap_mds_no" -eq 1 ] && { [ "$cap_rtm" -eq 0 ] || [ "$cap_tsx_ctrl_rtm_disable" -eq 1 ]; }; then
                    return 0
                else
                    return 1
                fi
            fi
        fi
    fi

    return 0

}

# Check whether the CPU is known to be unaffected by Speculative Store Bypass (SSB)
# Returns: 0 if SSB-free, 1 if affected or unknown
is_cpu_ssb_free() {
    # source1: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/cpu/common.c#n945
    # source2: https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/tree/arch/x86/kernel/cpu/common.c
    # Only list CPUs that speculate but are immune, to avoid duplication of cpus listed in is_cpu_specex_free()
    #{ X86_VENDOR_INTEL,	6,	INTEL_FAM6_ATOM_SILVERMONT	},
    #{ X86_VENDOR_INTEL,	6,	INTEL_FAM6_ATOM_AIRMONT		},
    #{ X86_VENDOR_INTEL,	6,	INTEL_FAM6_ATOM_SILVERMONT_X	},
    #{ X86_VENDOR_INTEL,	6,	INTEL_FAM6_ATOM_SILVERMONT_MID	},
    #{ X86_VENDOR_INTEL,	6,	INTEL_FAM6_CORE_YONAH		},
    #{ X86_VENDOR_INTEL,	6,	INTEL_FAM6_XEON_PHI_KNL		},
    #{ X86_VENDOR_INTEL,	6,	INTEL_FAM6_XEON_PHI_KNM		},
    #{ X86_VENDOR_AMD,	0x12,					},
    #{ X86_VENDOR_AMD,	0x11,					},
    #{ X86_VENDOR_AMD,	0x10,					},
    #{ X86_VENDOR_AMD,	0xf,					},
    parse_cpu_details
    if is_intel; then
        if [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_ATOM_AIRMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_MID" ]; then
                return 0
            elif [ "$cpu_model" = "$INTEL_FAM6_CORE_YONAH" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNM" ]; then
                return 0
            fi
        fi
    fi
    if is_amd; then
        if [ "$cpu_family" = "18" ] ||
            [ "$cpu_family" = "17" ] ||
            [ "$cpu_family" = "16" ] ||
            [ "$cpu_family" = "15" ]; then
            return 0
        fi
    fi
    if is_hygon; then
        return 1
    fi
    [ "$cpu_family" = 4 ] && return 0
    return 1
}

# >>>>>> libs/220_util_update.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# Print the tool name and version banner
show_header() {
    pr_info "Spectre and Meltdown mitigation detection tool v$VERSION"
    pr_info
}

# Convert Family-Model-Stepping triplet to a CPUID value (base-10 to stdout)
# Args: $1=family $2=model $3=stepping
fms2cpuid() {
    local family model stepping extfamily lowfamily extmodel lowmodel
    family="$1"
    model="$2"
    stepping="$3"

    if [ "$((family))" -le 15 ]; then
        extfamily=0
        lowfamily=$((family))
    else
        # when we have a family > 0xF, then lowfamily is stuck at 0xF
        # and extfamily is ADDED to it (as in "+"), to ensure old software
        # never sees a lowfamily < 0xF for newer families
        lowfamily=15
        extfamily=$(((family) - 15))
    fi
    extmodel=$(((model & 0xF0) >> 4))
    lowmodel=$(((model & 0x0F) >> 0))
    echo $(((stepping & 0x0F) | (lowmodel << 4) | (lowfamily << 8) | (extmodel << 16) | (extfamily << 20)))
}

# Download a file using wget, curl, or fetch (whichever is available)
# Args: $1=url $2=output_file
download_file() {
    local ret url file
    url="$1"
    file="$2"
    if command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$file"
        ret=$?
    elif command -v curl >/dev/null 2>&1; then
        curl -sL "$url" -o "$file"
        ret=$?
    elif command -v fetch >/dev/null 2>&1; then
        fetch -q "$url" -o "$file"
        ret=$?
    else
        echo ERROR "please install one of \`wget\`, \`curl\` of \`fetch\` programs"
        unset file url
        return 1
    fi
    unset file url
    if [ "$ret" != 0 ]; then
        echo ERROR "error $ret"
        return $ret
    fi
    echo DONE
}

[ -z "$HOME" ] && HOME="$(getent passwd "$(whoami)" | cut -d: -f6)"
g_mcedb_cache="$HOME/.mcedb"
# Download and update the local microcode firmware database cache
# Sets: g_mcedb_tmp (temp file, cleaned up on exit)
update_fwdb() {
    local previous_dbversion dbversion mcedb_revision iucode_tool nbfound linuxfw_hash mcedb_url intel_url linuxfw_url newfile line cpuid pfmask date version intel_timestamp intel_latest_date family model stepping sqlstm

    show_header

    set -e

    if [ -r "$g_mcedb_cache" ]; then
        previous_dbversion=$(awk '/^# %%% MCEDB / { print $4 }' "$g_mcedb_cache")
    fi

    # first, download the MCE.db from the excellent platomav's MCExtractor project
    g_mcedb_tmp="$(mktemp -t smc-mcedb-XXXXXX)"
    mcedb_url='https://github.com/platomav/MCExtractor/raw/master/MCE.db'
    pr_info_nol "Fetching MCE.db from the MCExtractor project... "
    download_file "$mcedb_url" "$g_mcedb_tmp" || return $?

    # second, get the Intel firmwares from GitHub
    g_intel_tmp="$(mktemp -d -t smc-intelfw-XXXXXX)"
    intel_url="https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/archive/main.zip"
    pr_info_nol "Fetching Intel firmwares... "
    ## https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files.git
    download_file "$intel_url" "$g_intel_tmp/fw.zip" || return $?

    # now extract MCEdb contents using sqlite
    pr_info_nol "Extracting MCEdb data... "
    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo ERROR "please install the \`sqlite3\` program"
        return 1
    fi
    mcedb_revision=$(sqlite3 "$g_mcedb_tmp" "SELECT \"revision\" from \"MCE\"")
    if [ -z "$mcedb_revision" ]; then
        echo ERROR "downloaded file seems invalid"
        return 1
    fi
    sqlite3 "$g_mcedb_tmp" "ALTER TABLE \"Intel\" ADD COLUMN \"origin\" TEXT"
    sqlite3 "$g_mcedb_tmp" "ALTER TABLE \"Intel\" ADD COLUMN \"pfmask\" TEXT"
    sqlite3 "$g_mcedb_tmp" "ALTER TABLE \"AMD\" ADD COLUMN \"origin\" TEXT"
    sqlite3 "$g_mcedb_tmp" "ALTER TABLE \"AMD\" ADD COLUMN \"pfmask\" TEXT"
    sqlite3 "$g_mcedb_tmp" "UPDATE \"Intel\" SET \"origin\"='mce'"
    sqlite3 "$g_mcedb_tmp" "UPDATE \"Intel\" SET \"pfmask\"='FF'"
    sqlite3 "$g_mcedb_tmp" "UPDATE \"AMD\" SET \"origin\"='mce'"
    sqlite3 "$g_mcedb_tmp" "UPDATE \"AMD\" SET \"pfmask\"='FF'"

    echo OK "MCExtractor database revision $mcedb_revision"

    # parse Intel firmwares to get their versions
    pr_info_nol "Integrating Intel firmwares data to db... "
    if ! command -v unzip >/dev/null 2>&1; then
        echo ERROR "please install the \`unzip\` program"
        return 1
    fi
    (cd "$g_intel_tmp" && unzip fw.zip >/dev/null)
    if ! [ -d "$g_intel_tmp/Intel-Linux-Processor-Microcode-Data-Files-main/intel-ucode" ]; then
        echo ERROR "expected the 'intel-ucode' folder in the downloaded zip file"
        return 1
    fi

    if ! command -v iucode_tool >/dev/null 2>&1; then
        if ! command -v iucode-tool >/dev/null 2>&1; then
            echo ERROR "please install the \`iucode-tool\` program"
            return 1
        else
            iucode_tool="iucode-tool"
        fi
    else
        iucode_tool="iucode_tool"
    fi
    #  079/001: sig 0x000106c2, pf_mask 0x01, 2009-04-10, rev 0x0217, size 5120
    #  078/004: sig 0x000106ca, pf_mask 0x10, 2009-08-25, rev 0x0107, size 5120
    $iucode_tool -l "$g_intel_tmp/Intel-Linux-Processor-Microcode-Data-Files-main/intel-ucode" | grep -wF sig | while read -r line; do
        cpuid=$(echo "$line" | grep -Eio 'sig 0x[0-9a-f]+' | awk '{print $2}')
        cpuid=$((cpuid))
        cpuid=$(printf "%08X" "$cpuid")
        pfmask=$(echo "$line" | grep -Eio 'pf_mask 0x[0-9a-f]+' | awk '{print $2}')
        pfmask=$((pfmask))
        pfmask=$(printf "%02X" $pfmask)
        date=$(echo "$line" | grep -Eo '(19|20)[0-9][0-9]-[01][0-9]-[0-3][0-9]' | tr -d '-')
        version=$(echo "$line" | grep -Eio 'rev 0x[0-9a-f]+' | awk '{print $2}')
        version=$((version))
        version=$(printf "%08X" "$version")
        # ensure the official Intel DB always has precedence over mcedb, even if mcedb has seen a more recent fw
        sqlite3 "$g_mcedb_tmp" "DELETE FROM \"Intel\" WHERE \"origin\" != 'intel' AND \"cpuid\" = '$cpuid';"
        # then insert our version
        sqlite3 "$g_mcedb_tmp" "INSERT INTO \"Intel\" (\"origin\",\"cpuid\",\"pfmask\",\"version\",\"yyyymmdd\") VALUES ('intel','$cpuid','$pfmask','$version','$date');"
    done
    intel_timestamp=$(stat -c %Y "$g_intel_tmp/Intel-Linux-Processor-Microcode-Data-Files-main/license" 2>/dev/null || stat -f %m "$g_intel_tmp/Intel-Linux-Processor-Microcode-Data-Files-main/license" 2>/dev/null)
    if [ -n "$intel_timestamp" ]; then
        # use this date, it matches the last commit date
        intel_latest_date=$(date -d @"$intel_timestamp" +%Y%m%d 2>/dev/null || date -r "$intel_timestamp" +%Y%m%d)
    else
        echo "Falling back to the latest microcode date"
        intel_latest_date=$(sqlite3 "$g_mcedb_tmp" "SELECT \"yyyymmdd\" FROM \"Intel\" WHERE \"origin\"='intel' ORDER BY \"yyyymmdd\" DESC LIMIT 1;")
    fi
    echo DONE "(version $intel_latest_date)"

    # now parse the most recent linux-firmware amd-ucode README file
    pr_info_nol "Fetching latest amd-ucode README from linux-firmware project... "
    linuxfw_url="https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/amd-ucode/README"
    g_linuxfw_tmp=$(mktemp -t smc-linuxfw-XXXXXX)
    download_file "$linuxfw_url" "$g_linuxfw_tmp" || return $?

    pr_info_nol "Parsing the README... "
    nbfound=0
    for line in $(grep -E 'Family=0x[0-9a-f]+ Model=0x[0-9a-f]+ Stepping=0x[0-9a-f]+: Patch=0x[0-9a-f]+' "$g_linuxfw_tmp" | tr " " ","); do
        pr_debug "Parsing line $line"
        family=$(echo "$line" | grep -Eoi 'Family=0x[0-9a-f]+' | cut -d= -f2)
        model=$(echo "$line" | grep -Eoi 'Model=0x[0-9a-f]+' | cut -d= -f2)
        stepping=$(echo "$line" | grep -Eoi 'Stepping=0x[0-9a-f]+' | cut -d= -f2)
        version=$(echo "$line" | grep -Eoi 'Patch=0x[0-9a-f]+' | cut -d= -f2)
        version=$(printf "%08X" "$((version))")
        cpuid=$(fms2cpuid "$family" "$model" "$stepping")
        cpuid=$(printf "%08X" "$cpuid")
        sqlstm="INSERT INTO \"AMD\" (\"origin\",\"cpuid\",\"pfmask\",\"version\",\"yyyymmdd\") VALUES ('linux-firmware','$cpuid','FF','$version','20000101')"
        pr_debug "family $family model $model stepping $stepping cpuid $cpuid"
        pr_debug "$sqlstm"
        sqlite3 "$g_mcedb_tmp" "$sqlstm"
        nbfound=$((nbfound + 1))
        unset family model stepping version cpuid date sqlstm
    done
    echo "found $nbfound microcodes"
    unset nbfound

    dbversion="$mcedb_revision+i$intel_latest_date"
    linuxfw_hash=$(md5sum "$g_linuxfw_tmp" 2>/dev/null | cut -c1-4)
    if [ -n "$linuxfw_hash" ]; then
        dbversion="$dbversion+$linuxfw_hash"
    fi

    if [ "$1" != builtin ] && [ -n "$previous_dbversion" ] && [ "$previous_dbversion" = "v$dbversion" ]; then
        echo "We already have this version locally, no update needed"
        return 0
    fi

    pr_info_nol "Building local database... "
    {
        echo "# Spectre & Meltdown Checker"
        echo "# %%% MCEDB v$dbversion"
        # we'll use the more recent fw for Intel and AMD
        sqlite3 "$g_mcedb_tmp" "SELECT '# I,0x'||\"t1\".\"cpuid\"||',0x'||\"t1\".\"pfmask\"||',0x'||MAX(\"t1\".\"version\")||','||\"t1\".\"yyyymmdd\" FROM \"Intel\" AS \"t1\" LEFT OUTER JOIN \"Intel\" AS \"t2\" ON \"t2\".\"cpuid\"=\"t1\".\"cpuid\" AND \"t2\".\"pfmask\"=\"t1\".\"pfmask\" AND \"t2\".\"yyyymmdd\" > \"t1\".\"yyyymmdd\" WHERE \"t2\".\"yyyymmdd\" IS NULL GROUP BY \"t1\".\"cpuid\",\"t1\".\"pfmask\" ORDER BY \"t1\".\"cpuid\",\"t1\".\"pfmask\" ASC;" | grep -v '^# .,0x00000000,'
        sqlite3 "$g_mcedb_tmp" "SELECT '# A,0x'||\"t1\".\"cpuid\"||',0x'||\"t1\".\"pfmask\"||',0x'||MAX(\"t1\".\"version\")||','||\"t1\".\"yyyymmdd\" FROM \"AMD\"   AS \"t1\" LEFT OUTER JOIN \"AMD\"   AS \"t2\" ON \"t2\".\"cpuid\"=\"t1\".\"cpuid\" AND \"t2\".\"pfmask\"=\"t1\".\"pfmask\" AND \"t2\".\"yyyymmdd\" > \"t1\".\"yyyymmdd\" WHERE \"t2\".\"yyyymmdd\" IS NULL GROUP BY \"t1\".\"cpuid\",\"t1\".\"pfmask\" ORDER BY \"t1\".\"cpuid\",\"t1\".\"pfmask\" ASC;" | grep -v '^# .,0x00000000,'
    } >"$g_mcedb_cache"
    echo DONE "(version $dbversion)"

    if [ "$1" = builtin ]; then
        newfile=$(mktemp -t smc-builtin-XXXXXX)
        awk '/^# %%% MCEDB / { exit }; { print }' "$0" >"$newfile"
        awk '{ if (NR>1) { print } }' "$g_mcedb_cache" >>"$newfile"
        cat "$newfile" >"$0"
        rm -f "$newfile"
    fi
}

# >>>>>> libs/230_util_optparse.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# Validate a command-line option that expects a readable file path
# Args: $1=option_name $2=option_value (file path)
parse_opt_file() {
    local option_name option_value
    option_name="$1"
    option_value="$2"
    if [ -z "$option_value" ]; then
        show_header
        show_usage
        echo "$0: error: --$option_name expects one parameter (a file)" >&2
        exit 1
    elif [ ! -e "$option_value" ]; then
        show_header
        echo "$0: error: couldn't find file $option_value" >&2
        exit 1
    elif [ ! -f "$option_value" ]; then
        show_header
        echo "$0: error: $option_value is not a file" >&2
        exit 1
    elif [ ! -r "$option_value" ]; then
        show_header
        echo "$0: error: couldn't read $option_value (are you root?)" >&2
        exit 1
    fi
    echo "$option_value"
    exit 0
}

while [ -n "${1:-}" ]; do
    if [ "$1" = "--kernel" ]; then
        opt_kernel=$(parse_opt_file kernel "$2")
        ret=$?
        [ $ret -ne 0 ] && exit 255
        shift 2
    elif [ "$1" = "--config" ]; then
        opt_config=$(parse_opt_file config "$2")
        ret=$?
        [ $ret -ne 0 ] && exit 255
        shift 2
    elif [ "$1" = "--map" ]; then
        opt_map=$(parse_opt_file map "$2")
        ret=$?
        [ $ret -ne 0 ] && exit 255
        shift 2
    elif [ "$1" = "--arch-prefix" ]; then
        opt_arch_prefix="$2"
        shift 2
    elif [ "$1" = "--live" ]; then
        opt_live=1
        shift
    elif [ "$1" = "--no-color" ]; then
        opt_no_color=1
        shift
    elif [ "$1" = "--no-sysfs" ]; then
        opt_no_sysfs=1
        shift
    elif [ "$1" = "--sysfs-only" ]; then
        opt_sysfs_only=1
        shift
    elif [ "$1" = "--coreos" ]; then
        opt_coreos=1
        shift
    elif [ "$1" = "--coreos-within-toolbox" ]; then
        # don't use directly: used internally by --coreos
        opt_coreos=0
        shift
    elif [ "$1" = "--paranoid" ]; then
        opt_paranoid=1
        shift
    elif [ "$1" = "--hw-only" ]; then
        opt_hw_only=1
        shift
    elif [ "$1" = "--no-hw" ]; then
        opt_no_hw=1
        shift
    elif [ "$1" = "--allow-msr-write" ]; then
        opt_allow_msr_write=1
        shift
    elif [ "$1" = "--no-intel-db" ]; then
        opt_intel_db=0
        shift
    elif [ "$1" = "--cpu" ]; then
        opt_cpu=$2
        if [ "$opt_cpu" != all ]; then
            if echo "$opt_cpu" | grep -Eq '^[0-9]+'; then
                opt_cpu=$((opt_cpu))
            else
                echo "$0: error: --cpu should be an integer or 'all', got '$opt_cpu'" >&2
                exit 255
            fi
        fi
        shift 2
    elif [ "$1" = "--no-explain" ]; then
        # deprecated, kept for compatibility
        opt_explain=0
        shift
    elif [ "$1" = "--update-fwdb" ] || [ "$1" = "--update-mcedb" ]; then
        update_fwdb
        exit $?
    elif [ "$1" = "--update-builtin-fwdb" ] || [ "$1" = "--update-builtin-mcedb" ]; then
        update_fwdb builtin
        exit $?
    elif [ "$1" = "--dump-mock-data" ]; then
        opt_mock=1
        shift
    elif [ "$1" = "--explain" ]; then
        opt_explain=1
        shift
    elif [ "$1" = "--batch" ]; then
        opt_batch=1
        opt_verbose=0
        opt_no_color=1
        shift
        case "$1" in
            text | short | nrpe | json | prometheus)
                opt_batch_format="$1"
                shift
                ;;
            --*) ;; # allow subsequent flags
            '') ;;  # allow nothing at all
            *)
                echo "$0: error: unknown batch format '$1'" >&2
                echo "$0: error: --batch expects a format from: text, nrpe, json" >&2
                exit 255
                ;;
        esac
    elif [ "$1" = "-v" ] || [ "$1" = "--verbose" ]; then
        opt_verbose=$((opt_verbose + 1))
        [ "$opt_verbose" -ge 2 ] && opt_mock=1
        shift
    elif [ "$1" = "--cve" ]; then
        if [ -z "$2" ]; then
            echo "$0: error: option --cve expects a parameter, supported CVEs are: $g_supported_cve_list" >&2
            exit 255
        fi
        selected_cve=$(echo "$g_supported_cve_list" | grep -iwo "$2")
        if [ -n "$selected_cve" ]; then
            opt_cve_list="$opt_cve_list $selected_cve"
            opt_cve_all=0
        else
            echo "$0: error: unsupported CVE specified ('$2'), supported CVEs are: $g_supported_cve_list" >&2
            exit 255
        fi
        shift 2
    elif [ "$1" = "--vmm" ]; then
        if [ -z "$2" ]; then
            echo "$0: error: option --vmm (auto, yes, no)" >&2
            exit 255
        fi
        case "$2" in
            auto) opt_vmm=-1 ;;
            yes) opt_vmm=1 ;;
            no) opt_vmm=0 ;;
            *)
                echo "$0: error: expected one of (auto, yes, no) to option --vmm instead of '$2'" >&2
                exit 255
                ;;
        esac
        shift 2
    elif [ "$1" = "--variant" ]; then
        if [ -z "$2" ]; then
            echo "$0: error: option --variant expects a parameter (see --variant help)" >&2
            exit 255
        fi
        case "$2" in
            help)
                echo "The following parameters are supported for --variant (can be used multiple times):"
                echo "1, 2, 3, 3a, 4, msbds, mfbds, mlpds, mdsum, l1tf, taa, mcepsc, srbds, zenbleed, downfall, retbleed, inception, reptar, tsa, tsa-sq, tsa-l1, its, vmscape, bpi"
                exit 0
                ;;
            1)
                opt_cve_list="$opt_cve_list CVE-2017-5753"
                opt_cve_all=0
                ;;
            2)
                opt_cve_list="$opt_cve_list CVE-2017-5715"
                opt_cve_all=0
                ;;
            3)
                opt_cve_list="$opt_cve_list CVE-2017-5754"
                opt_cve_all=0
                ;;
            3a)
                opt_cve_list="$opt_cve_list CVE-2018-3640"
                opt_cve_all=0
                ;;
            4)
                opt_cve_list="$opt_cve_list CVE-2018-3639"
                opt_cve_all=0
                ;;
            msbds)
                opt_cve_list="$opt_cve_list CVE-2018-12126"
                opt_cve_all=0
                ;;
            mfbds)
                opt_cve_list="$opt_cve_list CVE-2018-12130"
                opt_cve_all=0
                ;;
            mlpds)
                opt_cve_list="$opt_cve_list CVE-2018-12127"
                opt_cve_all=0
                ;;
            mdsum)
                opt_cve_list="$opt_cve_list CVE-2019-11091"
                opt_cve_all=0
                ;;
            l1tf)
                opt_cve_list="$opt_cve_list CVE-2018-3615 CVE-2018-3620 CVE-2018-3646"
                opt_cve_all=0
                ;;
            taa)
                opt_cve_list="$opt_cve_list CVE-2019-11135"
                opt_cve_all=0
                ;;
            mcepsc)
                opt_cve_list="$opt_cve_list CVE-2018-12207"
                opt_cve_all=0
                ;;
            srbds)
                opt_cve_list="$opt_cve_list CVE-2020-0543"
                opt_cve_all=0
                ;;
            zenbleed)
                opt_cve_list="$opt_cve_list CVE-2023-20593"
                opt_cve_all=0
                ;;
            downfall)
                opt_cve_list="$opt_cve_list CVE-2022-40982"
                opt_cve_all=0
                ;;
            retbleed)
                opt_cve_list="$opt_cve_list CVE-2022-29900 CVE-2022-29901"
                opt_cve_all=0
                ;;
            inception)
                opt_cve_list="$opt_cve_list CVE-2023-20569"
                opt_cve_all=0
                ;;
            reptar)
                opt_cve_list="$opt_cve_list CVE-2023-23583"
                opt_cve_all=0
                ;;
            tsa)
                opt_cve_list="$opt_cve_list CVE-2024-36350 CVE-2024-36357"
                opt_cve_all=0
                ;;
            tsa-sq)
                opt_cve_list="$opt_cve_list CVE-2024-36350"
                opt_cve_all=0
                ;;
            tsa-l1)
                opt_cve_list="$opt_cve_list CVE-2024-36357"
                opt_cve_all=0
                ;;
            its)
                opt_cve_list="$opt_cve_list CVE-2024-28956"
                opt_cve_all=0
                ;;
            vmscape)
                opt_cve_list="$opt_cve_list CVE-2025-40300"
                opt_cve_all=0
                ;;
            bpi)
                opt_cve_list="$opt_cve_list CVE-2024-45332"
                opt_cve_all=0
                ;;
            *)
                echo "$0: error: invalid parameter '$2' for --variant, see --variant help for a list" >&2
                exit 255
                ;;
        esac
        shift 2
    elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
        show_header
        show_usage
        exit 0
    elif [ "$1" = "--version" ]; then
        opt_no_color=1
        show_header
        exit 0
    elif [ "$1" = "--disclaimer" ]; then
        show_header
        show_disclaimer
        exit 0
    else
        show_header
        show_usage
        echo "$0: error: unknown option '$1'"
        exit 255
    fi
done

show_header

if [ "$opt_no_sysfs" = 1 ] && [ "$opt_sysfs_only" = 1 ]; then
    pr_warn "Incompatible options specified (--no-sysfs and --sysfs-only), aborting"
    exit 255
fi

if [ "$opt_no_hw" = 1 ] && [ "$opt_hw_only" = 1 ]; then
    pr_warn "Incompatible options specified (--no-hw and --hw-only), aborting"
    exit 255
fi

if [ "$opt_live" = -1 ]; then
    if [ -n "$opt_kernel" ] || [ -n "$opt_config" ] || [ -n "$opt_map" ]; then
        # no --live specified and we have a least one of the kernel/config/map files on the cmdline: offline mode
        opt_live=0
    else
        opt_live=1
    fi
fi

# >>>>>> libs/240_output_status.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# Print a colored status badge followed by an optional supplement
# Args: $1=color(red|green|yellow|blue) $2=message $3=supplement(optional)
pstatus() {
    local col
    if [ "$opt_no_color" = 1 ]; then
        pr_info_nol "$2"
    else
        case "$1" in
            red) col="\033[41m\033[30m" ;;
            green) col="\033[42m\033[30m" ;;
            yellow) col="\033[43m\033[30m" ;;
            blue) col="\033[44m\033[30m" ;;
            *) col="" ;;
        esac
        pr_info_nol "$col $2 \033[0m"
    fi
    [ -n "${3:-}" ] && pr_info_nol " ($3)"
    pr_info
    unset col
}

# >>>>>> libs/250_output_emitters.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# --- Format-specific batch emitters ---

# Emit a single CVE result as plain text
# Args: $1=cve $2=aka $3=status $4=description
# Callers: pvulnstatus
_emit_text() {
    _pr_echo 0 "$1: $3 ($4)"
}

# Append CVE ID to the space-separated short output buffer
# Args: $1=cve $2=aka $3=status $4=description
# Sets: g_short_output
# Callers: pvulnstatus
_emit_short() {
    g_short_output="${g_short_output}$1 "
}

# Append a CVE result as a JSON object to the batch output buffer
# Args: $1=cve $2=aka $3=status(UNK|VULN|OK) $4=description
# Sets: g_json_output
# Callers: pvulnstatus
_emit_json() {
    local is_vuln esc_name esc_infos
    case "$3" in
        UNK) is_vuln="null" ;;
        VULN) is_vuln="true" ;;
        OK) is_vuln="false" ;;
        *)
            echo "$0: error: unknown status '$3' passed to _emit_json()" >&2
            exit 255
            ;;
    esac
    # escape backslashes and double quotes for valid JSON strings
    esc_name=$(printf '%s' "$2" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
    esc_infos=$(printf '%s' "$4" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
    [ -z "$g_json_output" ] && g_json_output='['
    g_json_output="${g_json_output}{\"NAME\":\"$esc_name\",\"CVE\":\"$1\",\"VULNERABLE\":$is_vuln,\"INFOS\":\"$esc_infos\"},"
}

# Append vulnerable CVE IDs to the NRPE output buffer
# Args: $1=cve $2=aka $3=status $4=description
# Sets: g_nrpe_vuln
# Callers: pvulnstatus
_emit_nrpe() {
    [ "$3" = VULN ] && g_nrpe_vuln="$g_nrpe_vuln $1"
}

# Append a CVE result as a Prometheus metric to the batch output buffer
# Args: $1=cve $2=aka $3=status $4=description
# Sets: g_prometheus_output
# Callers: pvulnstatus
_emit_prometheus() {
    local esc_info
    # escape backslashes and double quotes for Prometheus label values
    esc_info=$(printf '%s' "$4" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
    g_prometheus_output="${g_prometheus_output:+$g_prometheus_output\n}specex_vuln_status{name=\"$2\",cve=\"$1\",status=\"$3\",info=\"$esc_info\"} 1"
}

# Update global state used to determine the program exit code
# Args: $1=cve $2=status(UNK|VULN|OK)
# Sets: g_unknown, g_critical
# Callers: pvulnstatus
_record_result() {
    case "$2" in
        UNK) g_unknown="1" ;;
        VULN) g_critical="1" ;;
        OK) ;;
        *)
            echo "$0: error: unknown status '$2' passed to _record_result()" >&2
            exit 255
            ;;
    esac
}

# Print the final vulnerability status for a CVE and dispatch to batch emitters
# Args: $1=cve $2=status(UNK|OK|VULN) $3=description
# Sets: g_pvulnstatus_last_cve
pvulnstatus() {
    local aka vulnstatus
    g_pvulnstatus_last_cve="$1"
    if [ "$opt_batch" = 1 ]; then
        aka=$(_cve_registry_field "$1" 2)

        case "$opt_batch_format" in
            text) _emit_text "$1" "$aka" "$2" "$3" ;;
            short) _emit_short "$1" "$aka" "$2" "$3" ;;
            json) _emit_json "$1" "$aka" "$2" "$3" ;;
            nrpe) _emit_nrpe "$1" "$aka" "$2" "$3" ;;
            prometheus) _emit_prometheus "$1" "$aka" "$2" "$3" ;;
            *)
                echo "$0: error: invalid batch format '$opt_batch_format' specified" >&2
                exit 255
                ;;
        esac
    fi

    _record_result "$1" "$2"

    # display info if we're not in quiet/batch mode
    vulnstatus="$2"
    shift 2
    pr_info_nol "> \033[46m\033[30mSTATUS:\033[0m "
    : "${g_final_summary:=}"
    : "${g_final_summary_count:=0}"
    g_final_summary_count=$((g_final_summary_count + 1))
    # wrap to a new line every 4 entries for readability
    if [ "$g_final_summary_count" -gt 1 ] && [ $((g_final_summary_count % 4)) -eq 1 ]; then
        g_final_summary="$g_final_summary\n          "
    fi
    # pad entry to fixed width so columns align despite varying CVE ID lengths
    case "$vulnstatus" in
        UNK)
            pstatus yellow 'UNKNOWN' "$@"
            _summary_label=$(printf "%-17s" "$g_pvulnstatus_last_cve:??")
            g_final_summary="$g_final_summary \033[43m\033[30m$_summary_label\033[0m"
            ;;
        VULN)
            pstatus red 'VULNERABLE' "$@"
            _summary_label=$(printf "%-17s" "$g_pvulnstatus_last_cve:KO")
            g_final_summary="$g_final_summary \033[41m\033[30m$_summary_label\033[0m"
            ;;
        OK)
            pstatus green 'NOT VULNERABLE' "$@"
            _summary_label=$(printf "%-17s" "$g_pvulnstatus_last_cve:OK")
            g_final_summary="$g_final_summary \033[42m\033[30m$_summary_label\033[0m"
            ;;
        *)
            echo "$0: error: unknown status '$vulnstatus' passed to pvulnstatus()" >&2
            exit 255
            ;;
    esac
}

# >>>>>> libs/300_kernel_extract.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# The 3 below functions are taken from the extract-linux script, available here:
# https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux
# The functions have been modified for better integration to this script
# The original header of the file has been retained below

# ----------------------------------------------------------------------
# extract-vmlinux - Extract uncompressed vmlinux from a kernel image
#
# Inspired from extract-ikconfig
# (c) 2009,2010 Dick Streefland <dick@streefland.net>
#
# (c) 2011      Corentin Chary <corentin.chary@gmail.com>
#
# Licensed under the GNU General Public License, version 2 (GPLv2).
# ----------------------------------------------------------------------

g_kernel=''
g_kernel_err=''
# Validate whether a file looks like a valid uncompressed Linux kernel image
# Args: $1=file_path
# Sets: g_kernel, g_kernel_err
check_kernel() {
    local ret file mode readelf_warnings readelf_sections kernel_size
    file="$1"
    mode="${2:-normal}"
    # checking the return code of readelf -h is not enough, we could get
    # a damaged ELF file and validate it, check for stderr warnings too

    # the warning "readelf: Warning: [16]: Link field (0) should index a symtab section./" can appear on valid kernels, ignore it
    readelf_warnings=$("${opt_arch_prefix}readelf" -S "$file" 2>&1 >/dev/null | grep -v 'should index a symtab section' | tr "\n" "/")
    ret=$?
    readelf_sections=$("${opt_arch_prefix}readelf" -S "$file" 2>/dev/null | grep -c -e data -e text -e init)
    kernel_size=$(stat -c %s "$file" 2>/dev/null || stat -f %z "$file" 2>/dev/null || echo 10000)
    pr_debug "check_kernel: ret=$? size=$kernel_size sections=$readelf_sections warnings=$readelf_warnings"
    if [ "$mode" = desperate ]; then
        if "${opt_arch_prefix}strings" "$file" | grep -Eq '^Linux version '; then
            pr_debug "check_kernel (desperate): ... matched!"
            if [ "$readelf_sections" = 0 ] && grep -qF -e armv6 -e armv7 "$file"; then
                pr_debug "check_kernel (desperate): raw arm binary found, adjusting objdump options"
                g_objdump_options="-D -b binary -marm"
            else
                g_objdump_options="-d"
            fi
            return 0
        else
            pr_debug "check_kernel (desperate): ... invalid"
        fi
    else
        if [ $ret -eq 0 ] && [ -z "$readelf_warnings" ] && [ "$readelf_sections" -gt 0 ]; then
            if [ "$kernel_size" -ge 100000 ]; then
                pr_debug "check_kernel: ... file is valid"
                g_objdump_options="-d"
                return 0
            else
                pr_debug "check_kernel: ... file seems valid but is too small, ignoring"
            fi
        else
            pr_debug "check_kernel: ... file is invalid"
        fi
    fi
    return 1
}

# Attempt to find and decompress a kernel image using a given compression format
# Args: $1=magic_search $2=magic_match $3=format_name $4=decompress_cmd $5=decompress_args $6=input_file $7=output_file
try_decompress() {
    local pos ret
    # The obscure use of the "tr" filter is to work around older versions of
    # "grep" that report the byte offset of the line instead of the pattern.

    # Try to find the header ($1) and decompress from here
    pr_debug "try_decompress: looking for $3 magic in $6"
    for pos in $(tr "$1\n$2" "\n$2=" <"$6" | grep -abo "^$2"); do
        pr_debug "try_decompress: magic for $3 found at offset $pos"
        if ! command -v "$3" >/dev/null 2>&1; then
            if [ "$8" = 1 ]; then
                # pass1: if the tool is not installed, just bail out silently
                # and hope that the next decompression tool will be, and that
                # it'll happen to be the proper one for this kernel
                pr_debug "try_decompress: the '$3' tool is not installed (pass 1), try the next algo"
            else
                # pass2: if the tool is not installed, populate g_kernel_err this time
                g_kernel_err="missing '$3' tool, please install it, usually it's in the '$5' package"
                pr_debug "try_decompress: $g_kernel_err"
            fi
            return 1
        fi
        pos=${pos%%:*}
        # shellcheck disable=SC2086
        tail -c+$pos "$6" 2>/dev/null | $3 $4 >"$g_kerneltmp" 2>/dev/null
        ret=$?
        if [ ! -s "$g_kerneltmp" ]; then
            # don't rely on $ret, sometimes it's != 0 but worked
            # (e.g. gunzip ret=2 just means there was trailing garbage)
            pr_debug "try_decompress: decompression with $3 failed (err=$ret)"
        elif check_kernel "$g_kerneltmp" "$7"; then
            g_kernel="$g_kerneltmp"
            pr_debug "try_decompress: decompressed with $3 successfully!"
            return 0
        elif [ "$3" != "cat" ]; then
            pr_debug "try_decompress: decompression with $3 worked but result is not a kernel, trying with an offset"
            [ -z "$g_kerneltmp2" ] && g_kerneltmp2=$(mktemp -t smc-kernel-XXXXXX)
            cat "$g_kerneltmp" >"$g_kerneltmp2"
            try_decompress '\177ELF' xxy 'cat' '' cat "$g_kerneltmp2" && return 0
        else
            pr_debug "try_decompress: decompression with $3 worked but result is not a kernel"
        fi
    done
    return 1
}

# Extract an uncompressed vmlinux from a possibly compressed kernel image
# Args: $1=kernel_image_path
# Sets: g_kerneltmp
extract_kernel() {
    local pass mode
    [ -n "${1:-}" ] || return 1
    # Prepare temp files:
    g_kerneltmp="$(mktemp -t smc-kernel-XXXXXX)"

    # Initial attempt for uncompressed images or objects:
    if check_kernel "$1"; then
        pr_debug "extract_kernel: found kernel is valid, no decompression needed"
        cat "$1" >"$g_kerneltmp"
        g_kernel=$g_kerneltmp
        return 0
    fi

    # That didn't work, so retry after decompression.
    for pass in 1 2; do
        for mode in normal desperate; do
            pr_debug "extract_kernel: pass $pass $mode mode"
            try_decompress '\037\213\010' xy gunzip '' gunzip "$1" "$mode" "$pass" && return 0
            try_decompress '\002\041\114\030' xyy 'lz4' '-d -l' liblz4-tool "$1" "$mode" "$pass" && return 0
            try_decompress '\3757zXZ\000' abcde unxz '' xz-utils "$1" "$mode" "$pass" && return 0
            try_decompress 'BZh' xy bunzip2 '' bzip2 "$1" "$mode" "$pass" && return 0
            try_decompress '\135\0\0\0' xxx unlzma '' xz-utils "$1" "$mode" "$pass" && return 0
            try_decompress '\211\114\132' xy 'lzop' '-d' lzop "$1" "$mode" "$pass" && return 0
            try_decompress '\177ELF' xxy 'cat' '' cat "$1" "$mode" "$pass" && return 0
            try_decompress '(\265/\375' xxy unzstd '' zstd "$1" "$mode" "$pass" && return 0
        done
    done
    # g_kernel_err might already have been populated by try_decompress() if we're missing one of the tools
    if [ -z "$g_kernel_err" ]; then
        g_kernel_err="kernel compression format is unknown or image is invalid"
    fi
    pr_verbose "Couldn't extract the kernel image ($g_kernel_err), accuracy might be reduced"
    return 1
}

# end of extract-vmlinux functions

# >>>>>> libs/310_cpu_msr_load.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# Mount debugfs if not already available, remembering to unmount on cleanup
# Sets: g_mounted_debugfs
mount_debugfs() {
    if [ ! -e "$DEBUGFS_BASE/sched_features" ]; then
        # try to mount the debugfs hierarchy ourselves and remember it to umount afterwards
        mount -t debugfs debugfs "$DEBUGFS_BASE" 2>/dev/null && g_mounted_debugfs=1
    fi
}

# Load the MSR kernel module (Linux) or cpuctl (BSD) if not already loaded
# Sets: g_insmod_msr, g_kldload_cpuctl
load_msr() {
    [ "${g_load_msr_once:-}" = 1 ] && return
    g_load_msr_once=1

    if [ "$g_os" = Linux ]; then
        if ! grep -qw msr "$g_procfs/modules" 2>/dev/null; then
            modprobe msr 2>/dev/null && g_insmod_msr=1
            pr_debug "attempted to load module msr, g_insmod_msr=$g_insmod_msr"
        else
            pr_debug "msr module already loaded"
        fi
    else
        if ! kldstat -q -m cpuctl; then
            kldload cpuctl 2>/dev/null && g_kldload_cpuctl=1
            pr_debug "attempted to load module cpuctl, g_kldload_cpuctl=$g_kldload_cpuctl"
        else
            pr_debug "cpuctl module already loaded"
        fi
    fi
}

# >>>>>> libs/320_cpu_cpuid.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# Load the CPUID kernel module if not already loaded (Linux only)
# Sets: g_insmod_cpuid
load_cpuid() {
    [ "${g_load_cpuid_once:-}" = 1 ] && return
    g_load_cpuid_once=1

    if [ "$g_os" = Linux ]; then
        if ! grep -qw cpuid "$g_procfs/modules" 2>/dev/null; then
            modprobe cpuid 2>/dev/null && g_insmod_cpuid=1
            pr_debug "attempted to load module cpuid, g_insmod_cpuid=$g_insmod_cpuid"
        else
            pr_debug "cpuid module already loaded"
        fi
    else
        if ! kldstat -q -m cpuctl; then
            kldload cpuctl 2>/dev/null && g_kldload_cpuctl=1
            pr_debug "attempted to load module cpuctl, g_kldload_cpuctl=$g_kldload_cpuctl"
        else
            pr_debug "cpuctl module already loaded"
        fi
    fi
}

# shellcheck disable=SC2034
readonly EAX=1
readonly EBX=2
readonly ECX=3
readonly EDX=4
readonly READ_CPUID_RET_OK=0
readonly READ_CPUID_RET_KO=1
readonly READ_CPUID_RET_ERR=2
# Read a CPUID register value across one or all cores
# Args: $1=leaf $2=subleaf $3=register(EAX|EBX|ECX|EDX) $4=shift $5=bit_width $6=expected_value
# Sets: ret_read_cpuid_value, ret_read_cpuid_msg
# Returns: READ_CPUID_RET_OK | READ_CPUID_RET_KO | READ_CPUID_RET_ERR
read_cpuid() {
    local ret core first_core_ret first_core_value
    if [ "$opt_cpu" != all ]; then
        # we only have one core to read, do it and return the result
        read_cpuid_one_core "$opt_cpu" "$@"
        return $?
    fi

    # otherwise we must read all cores
    for core in $(seq 0 "$g_max_core_id"); do
        read_cpuid_one_core "$core" "$@"
        ret=$?
        if [ "$core" = 0 ]; then
            # save the result of the first core, for comparison with the others
            first_core_ret=$ret
            first_core_value=$ret_read_cpuid_value
        else
            # compare first core with the other ones
            if [ "$first_core_ret" != "$ret" ] || [ "$first_core_value" != "$ret_read_cpuid_value" ]; then
                ret_read_cpuid_msg="result is not homogeneous between all cores, at least core 0 and $core differ!"
                return $READ_CPUID_RET_ERR
            fi
        fi
    done
    # if we're here, all cores agree, return the result
    return "$ret"
}

# Read a CPUID register value from a single CPU core
# Args: $1=core $2=leaf $3=subleaf $4=register(EAX|EBX|ECX|EDX) $5=shift $6=bit_width $7=expected_value
# Sets: ret_read_cpuid_value, ret_read_cpuid_msg
# Returns: READ_CPUID_RET_OK | READ_CPUID_RET_KO | READ_CPUID_RET_ERR
read_cpuid_one_core() {
    local core leaf subleaf register shift mask wanted position ddskip odskip cpuid mockvarname reg reg_shifted
    # on which core to send the CPUID instruction
    core="$1"
    # leaf is the value of the eax register when calling the cpuid instruction:
    leaf="$2"
    # subleaf is the value of the ecx register when calling the cpuid instruction:
    subleaf="$3"
    # eax=1 ebx=2 ecx=3 edx=4:
    register="$4"
    # number of bits to shift the register right to, 0-31:
    shift="$5"
    # mask to apply as an AND operand to the shifted register value
    mask="$6"
    # wanted value (optional), if present we return 0(true) if the obtained value is equal, 1 otherwise:
    wanted="${7:-}"
    # in any case, the read value is globally available in $ret_read_cpuid_value
    ret_read_cpuid_value=''
    ret_read_cpuid_msg='unknown error'

    if [ $# -lt 6 ]; then
        ret_read_cpuid_msg="read_cpuid: missing arguments, got only $#, expected at least 6: $*"
        return $READ_CPUID_RET_ERR
    fi
    if [ "$register" -gt 4 ]; then
        ret_read_cpuid_msg="read_cpuid: register must be 0-4, got $register"
        return $READ_CPUID_RET_ERR
    fi
    if [ "$shift" -gt 32 ]; then
        ret_read_cpuid_msg="read_cpuid: shift must be 0-31, got $shift"
        return $READ_CPUID_RET_ERR
    fi

    if [ ! -e $CPU_DEV_BASE/0/cpuid ] && [ ! -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
        # try to load the module ourselves (and remember it so we can rmmod it afterwards)
        load_cpuid
    fi

    if [ -e $CPU_DEV_BASE/0/cpuid ]; then
        # Linux
        if [ ! -r $CPU_DEV_BASE/0/cpuid ]; then
            ret_read_cpuid_msg="Couldn't load cpuid module"
            return $READ_CPUID_RET_ERR
        fi
        # on some kernel versions, $CPU_DEV_BASE/0/cpuid doesn't imply that the cpuid module is loaded, in that case dd returns an error,
        # we use that fact to load the module if dd returns an error
        if ! dd if=$CPU_DEV_BASE/0/cpuid bs=16 count=1 >/dev/null 2>&1; then
            load_cpuid
        fi
        # we need leaf to be converted to decimal for dd
        leaf=$((leaf))
        subleaf=$((subleaf))
        position=$((leaf + (subleaf << 32)))
        # to avoid using iflag=skip_bytes, which doesn't exist on old versions of dd, seek to the closer multiple-of-16
        ddskip=$((position / 16))
        odskip=$((position - ddskip * 16))
        # now read the value
        cpuid=$(dd if="$CPU_DEV_BASE/$core/cpuid" bs=16 skip=$ddskip count=$((odskip + 1)) 2>/dev/null | od -j $((odskip * 16)) -A n -t u4)
    elif [ -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
        # BSD
        if [ ! -r ${BSD_CPUCTL_DEV_BASE}0 ]; then
            ret_read_cpuid_msg="Couldn't read cpuid info from cpuctl"
            return $READ_CPUID_RET_ERR
        fi
        cpuid=$(cpucontrol -i "$leaf","$subleaf" "${BSD_CPUCTL_DEV_BASE}$core" 2>/dev/null | cut -d: -f2-)
        # cpuid level 0x4, level_type 0x2: 0x1c004143 0x01c0003f 0x000001ff 0x00000000
    else
        ret_read_cpuid_msg="Found no way to read cpuid info"
        return $READ_CPUID_RET_ERR
    fi

    pr_debug "cpuid: leaf$leaf subleaf$subleaf on cpu$core, eax-ebx-ecx-edx: $cpuid"
    mockvarname="SMC_MOCK_CPUID_${leaf}_${subleaf}"
    # shellcheck disable=SC1083
    if [ -n "$(eval echo \${"$mockvarname":-})" ]; then
        cpuid="$(eval echo \$"$mockvarname")"
        pr_debug "read_cpuid: MOCKING enabled for leaf $leaf subleaf $subleaf, will return $cpuid"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPUID_${leaf}_${subleaf}='$cpuid'")
    fi
    if [ -z "$cpuid" ]; then
        ret_read_cpuid_msg="Failed to get cpuid data"
        return $READ_CPUID_RET_ERR
    fi

    # get the value of the register we want
    reg=$(echo "$cpuid" | awk '{print $'"$register"'}')
    # Linux returns it as decimal, BSD as hex, normalize to decimal
    reg=$((reg))
    # shellcheck disable=SC2046
    pr_debug "cpuid: wanted register ($register) has value $reg aka "$(printf "%08x" "$reg")
    reg_shifted=$((reg >> shift))
    # shellcheck disable=SC2046
    pr_debug "cpuid: shifted value by $shift is $reg_shifted aka "$(printf "%x" "$reg_shifted")
    ret_read_cpuid_value=$((reg_shifted & mask))
    # shellcheck disable=SC2046
    pr_debug "cpuid: after AND $mask, final value is $ret_read_cpuid_value aka "$(printf "%x" "$ret_read_cpuid_value")
    if [ -n "$wanted" ]; then
        pr_debug "cpuid: wanted $wanted and got $ret_read_cpuid_value"
        if [ "$ret_read_cpuid_value" = "$wanted" ]; then
            return $READ_CPUID_RET_OK
        else
            return $READ_CPUID_RET_KO
        fi
    fi

    return $READ_CPUID_RET_OK
}

# >>>>>> libs/330_cpu_misc.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# Search dmesg for a pattern, returning nothing if the buffer has been truncated
# Args: $1=grep_pattern
# Sets: ret_dmesg_grep_grepped
# Returns: 0=found, 1=not found, 2=dmesg truncated
dmesg_grep() {
    ret_dmesg_grep_grepped=''
    if ! dmesg 2>/dev/null | grep -qE -e '(^|\] )Linux version [0-9]' -e '^FreeBSD is a registered'; then
        # dmesg truncated
        return 2
    fi
    ret_dmesg_grep_grepped=$(dmesg 2>/dev/null | grep -E "$1" | head -n1)
    # not found:
    [ -z "$ret_dmesg_grep_grepped" ] && return 1
    # found, output is in $ret_dmesg_grep_grepped
    return 0
}

# Check whether the system is running CoreOS/Flatcar
# Returns: 0 if CoreOS, 1 otherwise
is_coreos() {
    command -v coreos-install >/dev/null 2>&1 && command -v toolbox >/dev/null 2>&1 && return 0
    return 1
}

# >>>>>> libs/340_cpu_msr.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
readonly WRITE_MSR_RET_OK=0
readonly WRITE_MSR_RET_KO=1
readonly WRITE_MSR_RET_ERR=2
readonly WRITE_MSR_RET_LOCKDOWN=3
# Write a value to an MSR register across one or all cores
# Args: $1=msr_address $2=value(optional) $3=cpu_index(optional, default 0)
# Sets: ret_write_msr_msg
# Returns: WRITE_MSR_RET_OK | WRITE_MSR_RET_KO | WRITE_MSR_RET_ERR | WRITE_MSR_RET_LOCKDOWN
write_msr() {
    local ret core first_core_ret
    if [ "$opt_cpu" != all ]; then
        # we only have one core to write to, do it and return the result
        write_msr_one_core "$opt_cpu" "$@"
        return $?
    fi

    # otherwise we must write on all cores
    for core in $(seq 0 "$g_max_core_id"); do
        write_msr_one_core "$core" "$@"
        ret=$?
        if [ "$core" = 0 ]; then
            # save the result of the first core, for comparison with the others
            first_core_ret=$ret
        else
            # compare first core with the other ones
            if [ "$first_core_ret" != "$ret" ]; then
                ret_write_msr_msg="result is not homogeneous between all cores, at least core 0 and $core differ!"
                return $WRITE_MSR_RET_ERR
            fi
        fi
    done
    # if we're here, all cores agree, return the result
    return $ret
}

# Write a value to an MSR register on a single CPU core
# Args: $1=core $2=msr_address $3=value
# Sets: ret_write_msr_msg
# Returns: WRITE_MSR_RET_OK | WRITE_MSR_RET_KO | WRITE_MSR_RET_ERR | WRITE_MSR_RET_LOCKDOWN
write_msr_one_core() {
    local ret core msr msr_dec value value_dec mockvarname write_denied
    core="$1"
    msr_dec=$(($2))
    msr=$(printf "0x%x" "$msr_dec")
    value_dec=$(($3))
    value=$(printf "0x%x" "$value_dec")

    ret_write_msr_msg='unknown error'
    : "${g_msr_locked_down:=0}"

    mockvarname="SMC_MOCK_WRMSR_${msr}_RET"
    # shellcheck disable=SC2086,SC1083
    if [ -n "$(eval echo \${$mockvarname:-})" ]; then
        pr_debug "write_msr: MOCKING enabled for msr $msr func returns $(eval echo \$$mockvarname)"
        g_mocked=1
        [ "$(eval echo \$$mockvarname)" = $WRITE_MSR_RET_LOCKDOWN ] && g_msr_locked_down=1
        return "$(eval echo \$$mockvarname)"
    fi

    if [ ! -e $CPU_DEV_BASE/0/msr ] && [ ! -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
        # try to load the module ourselves (and remember it so we can rmmod it afterwards)
        load_msr
    fi
    if [ ! -e $CPU_DEV_BASE/0/msr ] && [ ! -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
        ret_read_msr_msg="is msr kernel module available?"
        return $WRITE_MSR_RET_ERR
    fi

    write_denied=0
    if [ "$g_os" != Linux ]; then
        cpucontrol -m "$msr=$value" "${BSD_CPUCTL_DEV_BASE}$core" >/dev/null 2>&1
        ret=$?
    else
        # for Linux
        # convert to decimal
        if [ ! -w $CPU_DEV_BASE/"$core"/msr ]; then
            ret_write_msr_msg="No write permission on $CPU_DEV_BASE/$core/msr"
            return $WRITE_MSR_RET_ERR
        # if wrmsr is available, use it
        elif command -v wrmsr >/dev/null 2>&1 && [ "${SMC_NO_WRMSR:-}" != 1 ]; then
            pr_debug "write_msr: using wrmsr"
            wrmsr $msr_dec $value_dec 2>/dev/null
            ret=$?
            # ret=4: msr doesn't exist, ret=127: msr.allow_writes=off
            [ "$ret" = 127 ] && write_denied=1
        # or fallback to dd if it supports seek_bytes, we prefer it over perl because we can tell the difference between EPERM and EIO
        elif dd if=/dev/null of=/dev/null bs=8 count=1 seek="$msr_dec" oflag=seek_bytes 2>/dev/null && [ "${SMC_NO_DD:-}" != 1 ]; then
            pr_debug "write_msr: using dd"
            awk "BEGIN{printf \"%c\", $value_dec}" | dd of=$CPU_DEV_BASE/"$core"/msr bs=8 count=1 seek="$msr_dec" oflag=seek_bytes 2>/dev/null
            ret=$?
            # if it failed, inspect stderrto look for EPERM
            if [ "$ret" != 0 ]; then
                if awk "BEGIN{printf \"%c\", $value_dec}" | dd of=$CPU_DEV_BASE/"$core"/msr bs=8 count=1 seek="$msr_dec" oflag=seek_bytes 2>&1 | grep -qF 'Operation not permitted'; then
                    write_denied=1
                fi
            fi
        # or if we have perl, use it, any 5.x version will work
        elif command -v perl >/dev/null 2>&1 && [ "${SMC_NO_PERL:-}" != 1 ]; then
            pr_debug "write_msr: using perl"
            ret=1
            perl -e "open(M,'>','$CPU_DEV_BASE/$core/msr') and seek(M,$msr_dec,0) and exit(syswrite(M,pack(v4,$value_dec)))"
            [ $? -eq 8 ] && ret=0
        else
            pr_debug "write_msr: got no wrmsr, perl or recent enough dd!"
            g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_WRMSR_${msr}_RET=$WRITE_MSR_RET_ERR")
            ret_write_msr_msg="missing tool, install either msr-tools or perl"
            return $WRITE_MSR_RET_ERR
        fi
        if [ "$ret" != 0 ]; then
            # * Fedora (and probably Red Hat) have a "kernel lock down" feature that prevents us to write to MSRs
            # when this mode is enabled and EFI secure boot is enabled (see issue #303)
            # https://src.fedoraproject.org/rpms/kernel/blob/master/f/efi-lockdown.patch
            # when this happens, any write will fail and dmesg will have a msg printed "msr: Direct access to MSR"
            # * A version of this patch also made it to vanilla in 5.4+, in that case the message is: 'raw MSR access is restricted'
            # * we don't use dmesg_grep() because we don't care if dmesg is truncated here, as the message has just been printed
            # yet more recent versions of the msr module can be set to msr.allow_writes=off, in which case no dmesg message is printed,
            # but the write fails
            if [ "$write_denied" = 1 ]; then
                pr_debug "write_msr: writing to msr has been denied"
                g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_WRMSR_${msr}_RET=$WRITE_MSR_RET_LOCKDOWN")
                g_msr_locked_down=1
                ret_write_msr_msg="your kernel is configured to deny writes to MSRs from user space"
                return $WRITE_MSR_RET_LOCKDOWN
            elif dmesg 2>/dev/null | grep -qF "msr: Direct access to MSR"; then
                pr_debug "write_msr: locked down kernel detected (Red Hat / Fedora)"
                g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_WRMSR_${msr}_RET=$WRITE_MSR_RET_LOCKDOWN")
                g_msr_locked_down=1
                ret_write_msr_msg="your kernel is locked down (Fedora/Red Hat), please reboot without secure boot and retry"
                return $WRITE_MSR_RET_LOCKDOWN
            elif dmesg 2>/dev/null | grep -qF "raw MSR access is restricted"; then
                pr_debug "write_msr: locked down kernel detected (vanilla)"
                g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_WRMSR_${msr}_RET=$WRITE_MSR_RET_LOCKDOWN")
                g_msr_locked_down=1
                ret_write_msr_msg="your kernel is locked down, please reboot with lockdown=none in the kernel cmdline and retry"
                return $WRITE_MSR_RET_LOCKDOWN
            fi
            unset write_denied
        fi
    fi

    # normalize ret
    if [ "$ret" = 0 ]; then
        ret=$WRITE_MSR_RET_OK
    else
        ret=$WRITE_MSR_RET_KO
    fi
    pr_debug "write_msr: for cpu $core on msr $msr, value=$value, ret=$ret"
    g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_WRMSR_${msr}_RET=$ret")
    return $ret
}

readonly MSR_IA32_PLATFORM_ID=0x17
readonly MSR_IA32_SPEC_CTRL=0x48
readonly MSR_IA32_ARCH_CAPABILITIES=0x10a
readonly MSR_IA32_TSX_CTRL=0x122
readonly MSR_IA32_MCU_OPT_CTRL=0x123
readonly READ_MSR_RET_OK=0
readonly READ_MSR_RET_KO=1
readonly READ_MSR_RET_ERR=2
# Read an MSR register value across one or all cores
# Args: $1=msr_address $2=cpu_index(optional, default 0)
# Sets: ret_read_msr_value, ret_read_msr_value_hi, ret_read_msr_value_lo, ret_read_msr_msg
# Returns: READ_MSR_RET_OK | READ_MSR_RET_KO | READ_MSR_RET_ERR
read_msr() {
    local ret core first_core_ret first_core_value
    if [ "$opt_cpu" != all ]; then
        # we only have one core to read, do it and return the result
        read_msr_one_core "$opt_cpu" "$@"
        return $?
    fi

    # otherwise we must read all cores
    for core in $(seq 0 "$g_max_core_id"); do
        read_msr_one_core "$core" "$@"
        ret=$?
        if [ "$core" = 0 ]; then
            # save the result of the first core, for comparison with the others
            first_core_ret=$ret
            first_core_value=$ret_read_msr_value
        else
            # compare first core with the other ones
            if [ "$first_core_ret" != "$ret" ] || [ "$first_core_value" != "$ret_read_msr_value" ]; then
                ret_read_msr_msg="result is not homogeneous between all cores, at least core 0 and $core differ!"
                return $READ_MSR_RET_ERR
            fi
        fi
    done
    # if we're here, all cores agree, return the result
    return "$ret"
}

# Read an MSR register value from a single CPU core
# Args: $1=core $2=msr_address
# Sets: ret_read_msr_value, ret_read_msr_value_hi, ret_read_msr_value_lo, ret_read_msr_msg
# Returns: READ_MSR_RET_OK | READ_MSR_RET_KO | READ_MSR_RET_ERR
read_msr_one_core() {
    local ret core msr msr_dec mockvarname msr_h msr_l mockval
    core="$1"
    msr_dec=$(($2))
    msr=$(printf "0x%x" "$msr_dec")

    ret_read_msr_value=''
    ret_read_msr_value_hi=''
    ret_read_msr_value_lo=''
    ret_read_msr_msg='unknown error'

    mockvarname="SMC_MOCK_RDMSR_${msr}"
    # shellcheck disable=SC2086,SC1083
    if [ -n "$(eval echo \${$mockvarname:-})" ]; then
        mockval="$(eval echo \$$mockvarname)"
        # accept both legacy decimal (small values) and new 16-char hex format
        if [ "${#mockval}" -eq 16 ]; then
            ret_read_msr_value="$mockval"
        else
            ret_read_msr_value=$(printf '%016x' "$mockval")
        fi
        ret_read_msr_value_hi=$((0x${ret_read_msr_value%????????}))
        ret_read_msr_value_lo=$((0x${ret_read_msr_value#????????}))
        pr_debug "read_msr: MOCKING enabled for msr $msr, returning $ret_read_msr_value"
        g_mocked=1
        return $READ_MSR_RET_OK
    fi

    mockvarname="SMC_MOCK_RDMSR_${msr}_RET"
    # shellcheck disable=SC2086,SC1083
    if [ -n "$(eval echo \${$mockvarname:-})" ] && [ "$(eval echo \$$mockvarname)" -ne 0 ]; then
        pr_debug "read_msr: MOCKING enabled for msr $msr func returns $(eval echo \$$mockvarname)"
        g_mocked=1
        return "$(eval echo \$$mockvarname)"
    fi

    if [ ! -e $CPU_DEV_BASE/0/msr ] && [ ! -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
        # try to load the module ourselves (and remember it so we can rmmod it afterwards)
        load_msr
    fi
    if [ ! -e $CPU_DEV_BASE/0/msr ] && [ ! -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
        ret_read_msr_msg="is msr kernel module available?"
        return $READ_MSR_RET_ERR
    fi

    if [ "$g_os" != Linux ]; then
        # for BSD
        msr=$(cpucontrol -m "$msr" "${BSD_CPUCTL_DEV_BASE}$core" 2>/dev/null)
        ret=$?
        if [ $ret -ne 0 ]; then
            g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_RDMSR_${msr}_RET=$READ_MSR_RET_KO")
            return $READ_MSR_RET_KO
        fi
        # MSR 0x10: 0x000003e1 0xb106dded
        msr_h=$(echo "$msr" | awk '{print $3}')
        msr_l=$(echo "$msr" | awk '{print $4}')
        ret_read_msr_value=$(printf '%08x%08x' "$((msr_h))" "$((msr_l))")
    else
        # for Linux
        if [ ! -r $CPU_DEV_BASE/"$core"/msr ]; then
            g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_RDMSR_${msr}_RET=$READ_MSR_RET_ERR")
            ret_read_msr_msg="No read permission for $CPU_DEV_BASE/$core/msr"
            return $READ_MSR_RET_ERR
        # if rdmsr is available, use it
        elif command -v rdmsr >/dev/null 2>&1 && [ "${SMC_NO_RDMSR:-}" != 1 ]; then
            pr_debug "read_msr: using rdmsr on $msr"
            ret_read_msr_value=$(rdmsr -r $msr_dec 2>/dev/null | od -A n -t x8)
        # or if we have perl, use it, any 5.x version will work
        elif command -v perl >/dev/null 2>&1 && [ "${SMC_NO_PERL:-}" != 1 ]; then
            pr_debug "read_msr: using perl on $msr"
            ret_read_msr_value=$(perl -e "open(M,'<','$CPU_DEV_BASE/$core/msr') and seek(M,$msr_dec,0) and read(M,\$_,8) and print" | od -A n -t x8)
        # fallback to dd if it supports skip_bytes
        elif dd if=/dev/null of=/dev/null bs=8 count=1 skip="$msr_dec" iflag=skip_bytes 2>/dev/null; then
            pr_debug "read_msr: using dd on $msr"
            ret_read_msr_value=$(dd if=$CPU_DEV_BASE/"$core"/msr bs=8 count=1 skip="$msr_dec" iflag=skip_bytes 2>/dev/null | od -A n -t x8)
        else
            pr_debug "read_msr: got no rdmsr, perl or recent enough dd!"
            g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_RDMSR_${msr}_RET=$READ_MSR_RET_ERR")
            ret_read_msr_msg='missing tool, install either msr-tools or perl'
            return $READ_MSR_RET_ERR
        fi
        if [ -z "$ret_read_msr_value" ]; then
            # MSR doesn't exist, don't check for $? because some versions of dd still return 0!
            g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_RDMSR_${msr}_RET=$READ_MSR_RET_KO")
            return $READ_MSR_RET_KO
        fi
        # remove sparse spaces od might give us
        ret_read_msr_value=$(printf '%s' "$ret_read_msr_value" | tr -d ' \t\n' | tr '[:upper:]' '[:lower:]')
    fi
    ret_read_msr_value_hi=$((0x${ret_read_msr_value%????????}))
    ret_read_msr_value_lo=$((0x${ret_read_msr_value#????????}))
    g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_RDMSR_${msr}='$ret_read_msr_value'")
    pr_debug "read_msr: MSR=$msr value is $ret_read_msr_value"
    return $READ_MSR_RET_OK
}

# >>>>>> libs/350_cpu_detect2.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# Detect and cache CPU vendor, family, model, stepping, microcode, and arch capabilities
# Sets: cpu_vendor, cpu_family, cpu_model, cpu_stepping, cpu_cpuid, cpu_ucode, cpu_friendly_name, g_max_core_id, and many cap_* globals
parse_cpu_details() {
    [ "${g_parse_cpu_details_done:-}" = 1 ] && return 0

    local number_of_cores arch part ret
    if command -v nproc >/dev/null; then
        number_of_cores=$(nproc)
    elif echo "$g_os" | grep -q BSD; then
        number_of_cores=$(sysctl -n hw.ncpu 2>/dev/null || echo 1)
    elif [ -e "$g_procfs/cpuinfo" ]; then
        number_of_cores=$(grep -c ^processor "$g_procfs/cpuinfo" 2>/dev/null || echo 1)
    else
        # if we don't know, default to 1 CPU
        number_of_cores=1
    fi
    g_max_core_id=$((number_of_cores - 1))

    cap_avx2=0
    cap_avx512=0
    if [ -e "$g_procfs/cpuinfo" ]; then
        if grep -qw avx2 "$g_procfs/cpuinfo" 2>/dev/null; then cap_avx2=1; fi
        if grep -qw avx512 "$g_procfs/cpuinfo" 2>/dev/null; then cap_avx512=1; fi
        cpu_vendor=$(grep '^vendor_id' "$g_procfs/cpuinfo" | awk '{print $3}' | head -n1)
        cpu_friendly_name=$(grep '^model name' "$g_procfs/cpuinfo" | cut -d: -f2- | head -n1 | sed -e 's/^ *//')
        # special case for ARM follows
        if grep -qi 'CPU implementer[[:space:]]*:[[:space:]]*0x41' "$g_procfs/cpuinfo"; then
            cpu_vendor='ARM'
            # some devices (phones or other) have several ARMs and as such different part numbers,
            # an example is "bigLITTLE", so we need to store the whole list, this is needed for is_cpu_affected
            cpu_part_list=$(awk '/CPU part/         {print $4}' "$g_procfs/cpuinfo")
            cpu_arch_list=$(awk '/CPU architecture/ {print $3}' "$g_procfs/cpuinfo")
            # take the first one to fill the friendly name, do NOT quote the vars below
            # shellcheck disable=SC2086
            arch=$(echo $cpu_arch_list | awk '{ print $1 }')
            # shellcheck disable=SC2086
            part=$(echo $cpu_part_list | awk '{ print $1 }')
            [ "$arch" = "AArch64" ] && arch=8
            cpu_friendly_name="ARM"
            [ -n "$arch" ] && cpu_friendly_name="$cpu_friendly_name v$arch"
            [ -n "$part" ] && cpu_friendly_name="$cpu_friendly_name model $part"

        elif grep -qi 'CPU implementer[[:space:]]*:[[:space:]]*0x43' "$g_procfs/cpuinfo"; then
            cpu_vendor='CAVIUM'
        elif grep -qi 'CPU implementer[[:space:]]*:[[:space:]]*0x70' "$g_procfs/cpuinfo"; then
            cpu_vendor='PHYTIUM'
        fi

        cpu_family=$(grep '^cpu family' "$g_procfs/cpuinfo" | awk '{print $4}' | grep -E '^[0-9]+$' | head -n1)
        cpu_model=$(grep '^model' "$g_procfs/cpuinfo" | awk '{print $3}' | grep -E '^[0-9]+$' | head -n1)
        cpu_stepping=$(grep '^stepping' "$g_procfs/cpuinfo" | awk '{print $3}' | grep -E '^[0-9]+$' | head -n1)
        cpu_ucode=$(grep '^microcode' "$g_procfs/cpuinfo" | awk '{print $3}' | head -n1)
    else
        cpu_vendor=$(dmesg 2>/dev/null | grep -i -m1 'Origin=' | awk '{print $2}' | cut -f2 -d= | cut -f2 -d\")
        cpu_family=$(dmesg 2>/dev/null | grep -i -m1 'Family=' | awk '{print $4}' | cut -f2 -d=)
        cpu_family=$((cpu_family))
        cpu_model=$(dmesg 2>/dev/null | grep -i -m1 'Model=' | awk '{print $5}' | cut -f2 -d=)
        cpu_model=$((cpu_model))
        cpu_stepping=$(dmesg 2>/dev/null | grep -i -m1 'Stepping=' | awk '{print $6}' | cut -f2 -d=)
        cpu_friendly_name=$(sysctl -n hw.model 2>/dev/null)
    fi

    # Intel processors have a 3bit Platform ID field in MSR(17H) that specifies the platform type for up to 8 types
    # see https://elixir.bootlin.com/linux/v6.0/source/arch/x86/kernel/cpu/microcode/intel.c#L694
    # Set it to 8 (impossible value as it is 3 bit long) by default
    cpu_platformid=8
    if [ "$cpu_vendor" = GenuineIntel ] && [ "$cpu_model" -ge 5 ]; then
        read_msr $MSR_IA32_PLATFORM_ID
        ret=$?
        if [ $ret = $READ_MSR_RET_OK ]; then
            # platform ID (bits 52:50) = bits 18:20 of the upper 32-bit word
            cpu_platformid=$((1 << ((ret_read_msr_value_hi >> 18) & 7)))
        fi
    fi

    if [ -n "${SMC_MOCK_CPU_FRIENDLY_NAME:-}" ]; then
        cpu_friendly_name="$SMC_MOCK_CPU_FRIENDLY_NAME"
        pr_debug "parse_cpu_details: MOCKING cpu friendly name to $cpu_friendly_name"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_FRIENDLY_NAME='$cpu_friendly_name'")
    fi
    if [ -n "${SMC_MOCK_CPU_VENDOR:-}" ]; then
        cpu_vendor="$SMC_MOCK_CPU_VENDOR"
        pr_debug "parse_cpu_details: MOCKING cpu vendor to $cpu_vendor"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_VENDOR='$cpu_vendor'")
    fi
    if [ -n "${SMC_MOCK_CPU_FAMILY:-}" ]; then
        cpu_family="$SMC_MOCK_CPU_FAMILY"
        pr_debug "parse_cpu_details: MOCKING cpu family to $cpu_family"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_FAMILY='$cpu_family'")
    fi
    if [ -n "${SMC_MOCK_CPU_MODEL:-}" ]; then
        cpu_model="$SMC_MOCK_CPU_MODEL"
        pr_debug "parse_cpu_details: MOCKING cpu model to $cpu_model"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_MODEL='$cpu_model'")
    fi
    if [ -n "${SMC_MOCK_CPU_STEPPING:-}" ]; then
        cpu_stepping="$SMC_MOCK_CPU_STEPPING"
        pr_debug "parse_cpu_details: MOCKING cpu stepping to $cpu_stepping"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_STEPPING='$cpu_stepping'")
    fi
    if [ -n "${SMC_MOCK_CPU_PLATFORMID:-}" ]; then
        cpu_platformid="$SMC_MOCK_CPU_PLATFORMID"
        pr_debug "parse_cpu_details: MOCKING cpu platformid name to $cpu_platformid"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_PLATFORMID='$cpu_platformid'")
    fi

    # get raw cpuid, it's always useful (referenced in the Intel doc for firmware updates for example)
    if [ "$g_mocked" != 1 ] && read_cpuid 0x1 0x0 $EAX 0 0xFFFFFFFF; then
        cpu_cpuid="$ret_read_cpuid_value"
    else
        # try to build it by ourselves
        pr_debug "parse_cpu_details: build the CPUID by ourselves"
        cpu_cpuid=$(fms2cpuid "$cpu_family" "$cpu_model" "$cpu_stepping")
    fi

    # under BSD, linprocfs often doesn't export ucode information, so fetch it ourselves the good old way
    if [ -z "$cpu_ucode" ] && [ "$g_os" != Linux ]; then
        load_cpuid
        if [ -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
            # init MSR with NULLs
            cpucontrol -m 0x8b=0 ${BSD_CPUCTL_DEV_BASE}0
            # call CPUID
            cpucontrol -i 1 ${BSD_CPUCTL_DEV_BASE}0 >/dev/null
            # read MSR
            cpu_ucode=$(cpucontrol -m 0x8b ${BSD_CPUCTL_DEV_BASE}0 | awk '{print $3}')
            # convert to decimal
            cpu_ucode=$((cpu_ucode))
            # convert back to hex
            cpu_ucode=$(printf "0x%x" "$cpu_ucode")
        fi
    fi

    # if we got no cpu_ucode (e.g. we're in a vm), fall back to 0x0
    : "${cpu_ucode:=0x0}"

    # on non-x86 systems (e.g. ARM), these fields may not exist in cpuinfo, fall back to 0
    : "${cpu_family:=0}"
    : "${cpu_model:=0}"
    : "${cpu_stepping:=0}"

    if [ -n "${SMC_MOCK_CPU_UCODE:-}" ]; then
        cpu_ucode="$SMC_MOCK_CPU_UCODE"
        pr_debug "parse_cpu_details: MOCKING cpu ucode to $cpu_ucode"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_UCODE='$cpu_ucode'")
    fi

    echo "$cpu_ucode" | grep -q ^0x && cpu_ucode=$((cpu_ucode))
    g_ucode_found=$(printf "family 0x%x model 0x%x stepping 0x%x ucode 0x%x cpuid 0x%x pfid 0x%x" \
        "$cpu_family" "$cpu_model" "$cpu_stepping" "$cpu_ucode" "$cpu_cpuid" "$cpu_platformid")

    g_parse_cpu_details_done=1
}
# Check whether the CPU vendor is Hygon
# Returns: 0 if Hygon, 1 otherwise

# >>>>>> libs/360_cpu_smt.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
is_hygon() {
    parse_cpu_details
    [ "$cpu_vendor" = HygonGenuine ] && return 0
    return 1
}

# Check whether the CPU vendor is AMD
# Returns: 0 if AMD, 1 otherwise
is_amd() {
    parse_cpu_details
    [ "$cpu_vendor" = AuthenticAMD ] && return 0
    return 1
}

# Check whether the CPU vendor is Intel
# Returns: 0 if Intel, 1 otherwise
is_intel() {
    parse_cpu_details
    [ "$cpu_vendor" = GenuineIntel ] && return 0
    return 1
}

# Check whether SMT (HyperThreading) is enabled on the system
# Returns: 0 if SMT enabled, 1 otherwise
is_cpu_smt_enabled() {
    local siblings cpucores
    # SMT / HyperThreading is enabled if siblings != cpucores
    if [ -e "$g_procfs/cpuinfo" ]; then
        siblings=$(awk '/^siblings/  {print $3;exit}' "$g_procfs/cpuinfo")
        cpucores=$(awk '/^cpu cores/ {print $4;exit}' "$g_procfs/cpuinfo")
        if [ -n "$siblings" ] && [ -n "$cpucores" ]; then
            if [ "$siblings" = "$cpucores" ]; then
                return 1
            else
                return 0
            fi
        fi
    fi
    # we can't tell
    return 2
}

# Check whether the current CPU microcode version is on Intel's blacklist
# Returns: 0 if blacklisted, 1 otherwise
is_ucode_blacklisted() {
    local tuple model stepping ucode cpuid
    parse_cpu_details
    # if it's not an Intel, don't bother: it's not blacklisted
    is_intel || return 1
    # it also needs to be family=6
    [ "$cpu_family" = 6 ] || return 1
    # now, check each known bad microcode
    # source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/cpu/intel.c#n105
    # 2018-02-08 update: https://newsroom.intel.com/wp-content/uploads/sites/11/2018/02/microcode-update-guidance.pdf
    # model,stepping,microcode
    for tuple in \
        $INTEL_FAM6_KABYLAKE,0x0B,0x80 \
        $INTEL_FAM6_KABYLAKE,0x0A,0x80 \
        $INTEL_FAM6_KABYLAKE,0x09,0x80 \
        $INTEL_FAM6_KABYLAKE_L,0x0A,0x80 \
        $INTEL_FAM6_KABYLAKE_L,0x09,0x80 \
        $INTEL_FAM6_SKYLAKE_X,0x03,0x0100013e \
        $INTEL_FAM6_SKYLAKE_X,0x04,0x02000036 \
        $INTEL_FAM6_SKYLAKE_X,0x04,0x0200003a \
        $INTEL_FAM6_SKYLAKE_X,0x04,0x0200003c \
        $INTEL_FAM6_BROADWELL,0x04,0x28 \
        $INTEL_FAM6_BROADWELL_G,0x01,0x1b \
        $INTEL_FAM6_BROADWELL_D,0x02,0x14 \
        $INTEL_FAM6_BROADWELL_D,0x03,0x07000011 \
        $INTEL_FAM6_BROADWELL_X,0x01,0x0b000025 \
        $INTEL_FAM6_HASWELL_L,0x01,0x21 \
        $INTEL_FAM6_HASWELL_G,0x01,0x18 \
        $INTEL_FAM6_HASWELL,0x03,0x23 \
        $INTEL_FAM6_HASWELL_X,0x02,0x3b \
        $INTEL_FAM6_HASWELL_X,0x04,0x10 \
        $INTEL_FAM6_IVYBRIDGE_X,0x04,0x42a \
        $INTEL_FAM6_SANDYBRIDGE_X,0x06,0x61b \
        $INTEL_FAM6_SANDYBRIDGE_X,0x07,0x712; do
        model=$(echo "$tuple" | cut -d, -f1)
        stepping=$(($(echo "$tuple" | cut -d, -f2)))
        if [ "$cpu_model" = "$model" ] && [ "$cpu_stepping" = "$stepping" ]; then
            ucode=$(($(echo "$tuple" | cut -d, -f3)))
            if [ "$cpu_ucode" = "$ucode" ]; then
                pr_debug "is_ucode_blacklisted: we have a match! ($cpu_model/$cpu_stepping/$cpu_ucode)"
                return 0
            fi
        fi
    done

    # 2024-01-09 update: https://github.com/speed47/spectre-meltdown-checker/issues/475
    # this time the tuple is cpuid,microcode
    for tuple in \
        0xB0671,0x119 \
        0xB06A2,0x4119 \
        0xB06A3,0x4119; do
        cpuid=$(($(echo "$tuple" | cut -d, -f1)))
        ucode=$(($(echo "$tuple" | cut -d, -f2)))
        if [ "$cpu_cpuid" = "$cpuid" ] && [ "$cpu_ucode" = "$ucode" ]; then
            pr_debug "is_ucode_blacklisted: we have a match! ($cpuid/$ucode)"
            return 0
        fi
    done

    pr_debug "is_ucode_blacklisted: no ($cpu_model/$cpu_stepping/$cpu_ucode)"
    return 1
}

# Check whether the CPU is a Skylake/Kabylake family processor
# Returns: 0 if Skylake-family, 1 otherwise
is_skylake_cpu() {
    # return 0 if yes, 1 otherwise
    #if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL &&
    #		boot_cpu_data.x86 == 6) {
    #		switch (boot_cpu_data.x86_model) {
    #		case INTEL_FAM6_SKYLAKE_MOBILE:
    #		case INTEL_FAM6_SKYLAKE_DESKTOP:
    #		case INTEL_FAM6_SKYLAKE_X:
    #		case INTEL_FAM6_KABYLAKE_MOBILE:
    #		case INTEL_FAM6_KABYLAKE_DESKTOP:
    #			return true;
    parse_cpu_details
    is_intel || return 1
    [ "$cpu_family" = 6 ] || return 1
    if [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_L" ] ||
        [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE" ] ||
        [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_X" ] ||
        [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE_L" ] ||
        [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE" ]; then
        return 0
    fi
    return 1
}

# Check whether the CPU is vulnerable to empty RSB speculation
# Returns: 0 if vulnerable, 1 otherwise
is_vulnerable_to_empty_rsb() {
    if is_intel && [ -z "$cap_rsba" ]; then
        pr_warn "is_vulnerable_to_empty_rsb() called before ARCH CAPABILITIES MSR was read"
    fi
    if is_skylake_cpu || [ "$cap_rsba" = 1 ]; then
        return 0
    fi
    return 1
}

# Check whether the CPU is from the AMD Zen family (Ryzen, EPYC, ...)
# Returns: 0 if Zen, 1 otherwise
is_zen_cpu() {
    parse_cpu_details
    is_amd || return 1
    [ "$cpu_family" = 23 ] && return 0
    return 1
}

# Check whether the CPU is a Hygon Moksha (Dhyana) family processor
# Returns: 0 if Moksha, 1 otherwise
is_moksha_cpu() {
    parse_cpu_details
    is_hygon || return 1
    [ "$cpu_family" = 24 ] && return 0
    return 1
}

# Encode an AMD family/model/stepping range into a single integer (mimics Linux AMD_MODEL_RANGE macro)
# Args: $1=family $2=model_start $3=stepping_start $4=model_end $5=stepping_end
amd_model_range() {
    echo $((($1 << 24) | ($2 << 16) | ($3 << 12) | ($4 << 4) | ($5)))
}

# Check if the current AMD CPU falls within a given model/stepping range (mimics Linux amd_legacy_erratum)
# Args: $1=range (output of amd_model_range)
# Returns: 0 if CPU is in range, 1 otherwise
amd_legacy_erratum() {
    local range ms
    range="$1"
    ms=$((cpu_model << 4 | cpu_stepping))
    if [ "$cpu_family" = $((((range) >> 24) & 0xff)) ] &&
        [ $ms -ge $((((range) >> 12) & 0xfff)) ] &&
        [ $ms -le $(((range) & 0xfff)) ]; then
        return 0
    fi
    return 1
}

# Check whether the CPU has a microcode version that fixes Zenbleed
# Sets: g_zenbleed_fw, g_zenbleed_fw_required
# Returns: 0=fixed, 1=not fixed, 2=not applicable
has_zenbleed_fixed_firmware() {
    local tuples tuple model_low model_high fwver
    # return cached data
    [ -n "$g_zenbleed_fw" ] && return "$g_zenbleed_fw"
    # or compute it:
    g_zenbleed_fw=2 # unknown
    # only amd
    if ! is_amd; then
        g_zenbleed_fw=1
        return $g_zenbleed_fw
    fi
    # list of known fixed firmwares, from commit 522b1d69219d8f083173819fde04f994aa051a98
    tuples="
		0x30,0x3f,0x0830107a
		0x60,0x67,0x0860010b
		0x68,0x6f,0x08608105
		0x70,0x7f,0x08701032
		0xa0,0xaf,0x08a00008
	"
    for tuple in $tuples; do
        model_low=$(echo "$tuple" | cut -d, -f1)
        model_high=$(echo "$tuple" | cut -d, -f2)
        fwver=$(echo "$tuple" | cut -d, -f3)
        if [ $((cpu_model)) -ge $((model_low)) ] && [ $((cpu_model)) -le $((model_high)) ]; then
            if [ $((cpu_ucode)) -ge $((fwver)) ]; then
                g_zenbleed_fw=0 # true
                break
            else
                g_zenbleed_fw=1 # false
                g_zenbleed_fw_required=$fwver
            fi
        fi
    done
    unset tuples
    return $g_zenbleed_fw
}

# >>>>>> libs/370_hw_vmm.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# Check whether the system is running as a Xen paravirtualized guest
# Returns: 0 if Xen PV, 1 otherwise
is_xen() {
    local ret
    if [ ! -d "$g_procfs/xen" ]; then
        return 1
    fi

    # XXX do we have a better way that relying on dmesg?
    dmesg_grep 'Booting paravirtualized kernel on Xen$'
    ret=$?
    if [ "$ret" -eq 2 ]; then
        pr_warn "dmesg truncated, Xen detection will be unreliable. Please reboot and relaunch this script"
        return 1
    elif [ "$ret" -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

# Check whether the system is a Xen Dom0 (privileged domain)
# Returns: 0 if Dom0, 1 otherwise
is_xen_dom0() {
    if ! is_xen; then
        return 1
    fi

    if [ -e "$g_procfs/xen/capabilities" ] && grep -q "control_d" "$g_procfs/xen/capabilities"; then
        return 0
    else
        return 1
    fi
}

# Check whether the system is a Xen DomU (unprivileged PV guest)
# Returns: 0 if DomU, 1 otherwise
is_xen_domU() {
    local ret
    if ! is_xen; then
        return 1
    fi

    # PVHVM guests also print 'Booting paravirtualized kernel', so we need this check.
    dmesg_grep 'Xen HVM callback vector for event delivery is enabled$'
    ret=$?
    if [ "$ret" -eq 0 ]; then
        return 1
    fi

    if ! is_xen_dom0; then
        return 0
    else
        return 1
    fi
}

# >>>>>> libs/380_hw_microcode.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
g_builtin_dbversion=$(awk '/^# %%% MCEDB / { print $4 }' "$0")
if [ -r "$g_mcedb_cache" ]; then
    # we have a local cache file, but it might be older than the builtin version we have
    g_local_dbversion=$(awk '/^# %%% MCEDB / { print $4 }' "$g_mcedb_cache")
    # compare version strings of the form vN+iYYYYMMDD+hash
    local_v=$(echo "$g_local_dbversion" | sed 's/^v\([0-9]*\).*/\1/')
    builtin_v=$(echo "$g_builtin_dbversion" | sed 's/^v\([0-9]*\).*/\1/')
    local_i=$(echo "$g_local_dbversion" | sed 's/.*+i\([0-9]*\).*/\1/')
    builtin_i=$(echo "$g_builtin_dbversion" | sed 's/.*+i\([0-9]*\).*/\1/')
    if [ "$local_v" -gt "$builtin_v" ] ||
        { [ "$local_v" -eq "$builtin_v" ] && [ "$local_i" -gt "$builtin_i" ]; }; then
        g_mcedb_source="$g_mcedb_cache"
        g_mcedb_info="local firmwares DB $g_local_dbversion"
    fi
fi
# if g_mcedb_source is not set, either we don't have a local cached db, or it is older than the builtin db
if [ -z "${g_mcedb_source:-}" ]; then
    g_mcedb_source="$0"
    g_mcedb_info="builtin firmwares DB $g_builtin_dbversion"
fi
# Read the MCExtractor microcode database (from local cache or builtin) to stdout
read_mcedb() {
    awk '{ if (DELIM==1) { print $2 } } /^# %%% MCEDB / { DELIM=1 }' "$g_mcedb_source"
}

# Read the Intel official affected CPUs database (builtin) to stdout
read_inteldb() {
    if [ "$opt_intel_db" = 1 ]; then
        awk '/^# %%% ENDOFINTELDB/ { exit } { if (DELIM==1) { print $2 } } /^# %%% INTELDB/ { DELIM=1 }' "$0"
    fi
    # otherwise don't output nothing, it'll be as if the database is empty
}

# Check whether the CPU is running the latest known microcode version
# Sets: ret_is_latest_known_ucode_latest
# Returns: 0=latest, 1=outdated, 2=unknown
is_latest_known_ucode() {
    local brand_prefix tuple pfmask ucode ucode_date
    parse_cpu_details
    if [ "$cpu_cpuid" = 0 ]; then
        ret_is_latest_known_ucode_latest="couldn't get your cpuid"
        return 2
    fi
    ret_is_latest_known_ucode_latest="latest microcode version for your CPU model is unknown"
    if is_intel; then
        brand_prefix=I
    elif is_amd; then
        brand_prefix=A
    else
        return 2
    fi
    for tuple in $(read_mcedb | grep "$(printf "^$brand_prefix,0x%08X," "$cpu_cpuid")"); do
        # skip if the pfmask doesn't match our platformid
        pfmask=$(echo "$tuple" | cut -d, -f3)
        if is_intel && [ $((cpu_platformid & pfmask)) -eq 0 ]; then
            continue
        fi
        ucode=$(($(echo "$tuple" | cut -d, -f4)))
        ucode_date=$(echo "$tuple" | cut -d, -f5 | sed -E 's=(....)(..)(..)=\1/\2/\3=')
        pr_debug "is_latest_known_ucode: with cpuid $cpu_cpuid has ucode $cpu_ucode, last known is $ucode from $ucode_date"
        ret_is_latest_known_ucode_latest=$(printf "latest version is 0x%x dated $ucode_date according to $g_mcedb_info" "$ucode")
        if [ "$cpu_ucode" -ge "$ucode" ]; then
            return 0
        else
            return 1
        fi
    done
    pr_debug "is_latest_known_ucode: this cpuid is not referenced ($cpu_cpuid)"
    return 2
}

# Read and cache the kernel command line from /proc/cmdline or mock
# Sets: g_kernel_cmdline

# >>>>>> libs/390_kernel_cmdline.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
get_cmdline() {
    if [ -n "${g_kernel_cmdline:-}" ]; then
        return
    fi

    if [ -n "${SMC_MOCK_CMDLINE:-}" ]; then
        g_mocked=1
        pr_debug "get_cmdline: using g_mocked cmdline '$SMC_MOCK_CMDLINE'"
        g_kernel_cmdline="$SMC_MOCK_CMDLINE"
        return
    else
        g_kernel_cmdline=$(cat "$g_procfs/cmdline")
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CMDLINE='$g_kernel_cmdline'")
    fi
}

# >>>>>> libs/400_hw_check.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# ENTRYPOINT

# we can't do anything useful under WSL
if uname -a | grep -qE -- '-Microsoft #[0-9]+-Microsoft '; then
    pr_warn "This script doesn't work under Windows Subsystem for Linux"
    pr_warn "You should use the official Microsoft tool instead."
    pr_warn "It can be found under https://aka.ms/SpeculationControlPS"
    exit 1
fi

# or other UNIX-ish OSes non-Linux non-supported-BSDs
if [ "$g_os" = Darwin ] || [ "$g_os" = VMkernel ]; then
    pr_warn "You're running under the $g_os OS, but this script"
    pr_warn "only works under Linux and some BSD systems, sorry."
    pr_warn "Please read the README and FAQ for more information."
    exit 1
fi

# check for mode selection inconsistency
if [ "$opt_hw_only" = 1 ]; then
    if [ "$opt_cve_all" = 0 ]; then
        show_usage
        echo "$0: error: incompatible modes specified, --hw-only vs --variant" >&2
        exit 255
    else
        opt_cve_all=0
        opt_cve_list=''
    fi
fi

# coreos mode
if [ "$opt_coreos" = 1 ]; then
    if ! is_coreos; then
        pr_warn "CoreOS mode asked, but we're not under CoreOS!"
        exit 255
    fi
    pr_warn "CoreOS mode, starting an ephemeral toolbox to launch the script"
    load_msr
    load_cpuid
    mount_debugfs
    toolbox --ephemeral --bind-ro "$CPU_DEV_BASE:$CPU_DEV_BASE" -- sh -c "dnf install -y binutils which && /media/root$PWD/$0 $* --coreos-within-toolbox"
    g_exitcode=$?
    exit $g_exitcode
else
    if is_coreos; then
        pr_warn "You seem to be running CoreOS, you might want to use the --coreos option for better results"
        pr_warn
    fi
fi

# if we're under a BSD, try to mount linprocfs for "$g_procfs/cpuinfo"
g_procfs=/proc
if echo "$g_os" | grep -q BSD; then
    pr_debug "We're under BSD, check if we have g_procfs"
    g_procfs=$(mount | awk '/^linprocfs/ { print $3; exit; }')
    if [ -z "$g_procfs" ]; then
        pr_debug "we don't, try to mount it"
        g_procfs=/proc
        [ -d /compat/linux/proc ] && g_procfs=/compat/linux/proc
        test -d $g_procfs || mkdir $g_procfs
        if mount -t linprocfs linprocfs $g_procfs 2>/dev/null; then
            g_mounted_procfs=1
            pr_debug "g_procfs just mounted at $g_procfs"
        else
            g_procfs=''
        fi
    else
        pr_debug "We do: $g_procfs"
    fi
fi

# define a few vars we might reference later without these being inited
g_mockme=''
g_mocked=0
g_specex_knob_dir=/dev/no_valid_path

# if /tmp doesn't exist and TMPDIR is not set, try to set it to a sane default for Android
if [ -z "${TMPDIR:-}" ] && ! [ -d "/tmp" ] && [ -d "/data/local/tmp" ]; then
    TMPDIR=/data/local/tmp
    export TMPDIR
fi

parse_cpu_details
get_cmdline

if [ "$opt_cpu" != all ] && [ "$opt_cpu" -gt "$g_max_core_id" ]; then
    echo "$0: error: --cpu can't be higher than $g_max_core_id, got $opt_cpu" >&2
    exit 255
fi

if [ "$opt_live" = 1 ]; then
    pr_info "Checking for vulnerabilities on current system"
    pr_info "Kernel is \033[35m$g_os $(uname -r) $(uname -v) $(uname -m)\033[0m"
    pr_info "CPU is \033[35m$cpu_friendly_name\033[0m"

    # try to find the image of the current running kernel
    if [ -n "$opt_kernel" ]; then
        # specified by user on cmdline, with --live, don't override
        :
    # first, look for the BOOT_IMAGE hint in the kernel cmdline
    elif echo "$g_kernel_cmdline" | grep -q 'BOOT_IMAGE='; then
        opt_kernel=$(echo "$g_kernel_cmdline" | grep -Eo 'BOOT_IMAGE=[^ ]+' | cut -d= -f2)
        pr_debug "found opt_kernel=$opt_kernel in $g_procfs/cmdline"
        # if the boot partition is within a btrfs subvolume, strip the subvolume name
        # if /boot is a separate subvolume, the remainder of the code in this section should handle it
        if echo "$opt_kernel" | grep -q "^/@"; then opt_kernel=$(echo "$opt_kernel" | sed "s:/@[^/]*::"); fi
        # if we have a dedicated /boot partition, our bootloader might have just called it /
        # so try to prepend /boot and see if we find anything
        [ -e "/boot/$opt_kernel" ] && opt_kernel="/boot/$opt_kernel"
        # special case for CoreOS if we're inside the toolbox
        [ -e "/media/root/boot/$opt_kernel" ] && opt_kernel="/media/root/boot/$opt_kernel"
        pr_debug "opt_kernel is now $opt_kernel"
        # else, the full path is already there (most probably /boot/something)
    fi
    # if we didn't find a kernel, default to guessing
    if [ ! -e "$opt_kernel" ]; then
        # Fedora:
        [ -e "/lib/modules/$(uname -r)/vmlinuz" ] && opt_kernel="/lib/modules/$(uname -r)/vmlinuz"
        # Slackware:
        [ -e "/boot/vmlinuz" ] && opt_kernel="/boot/vmlinuz"
        # Arch aarch64:
        [ -e "/boot/Image" ] && opt_kernel="/boot/Image"
        # Arch armv5/armv7:
        [ -e "/boot/zImage" ] && opt_kernel="/boot/zImage"
        # Arch arm7:
        [ -e "/boot/kernel7.img" ] && opt_kernel="/boot/kernel7.img"
        # Linux-Libre:
        [ -e "/boot/vmlinuz-linux-libre" ] && opt_kernel="/boot/vmlinuz-linux-libre"
        # pine64
        [ -e "/boot/pine64/Image" ] && opt_kernel="/boot/pine64/Image"
        # generic:
        [ -e "/boot/vmlinuz-$(uname -r)" ] && opt_kernel="/boot/vmlinuz-$(uname -r)"
        [ -e "/boot/kernel-$(uname -r)" ] && opt_kernel="/boot/kernel-$(uname -r)"
        [ -e "/boot/bzImage-$(uname -r)" ] && opt_kernel="/boot/bzImage-$(uname -r)"
        # Gentoo:
        [ -e "/boot/kernel-genkernel-$(uname -m)-$(uname -r)" ] && opt_kernel="/boot/kernel-genkernel-$(uname -m)-$(uname -r)"
        # NixOS:
        [ -e "/run/booted-system/kernel" ] && opt_kernel="/run/booted-system/kernel"
        # Guix System:
        [ -e "/run/booted-system/kernel/bzImage" ] && opt_kernel="/run/booted-system/kernel/bzImage"
        # systemd kernel-install:
        [ -e "/etc/machine-id" ] && [ -e "/boot/$(cat /etc/machine-id)/$(uname -r)/linux" ] && opt_kernel="/boot/$(cat /etc/machine-id)/$(uname -r)/linux"
        # Clear Linux:
        g_str_uname=$(uname -r)
        g_clear_linux_kernel="/lib/kernel/org.clearlinux.${g_str_uname##*.}.${g_str_uname%.*}"
        [ -e "$g_clear_linux_kernel" ] && opt_kernel=$g_clear_linux_kernel
        # Custom Arch seems to have the kernel path in its cmdline in the form "\directory\kernelimage",
        # with actual \'s instead of /'s:
        g_custom_arch_kernel=$(echo "$g_kernel_cmdline" | grep -Eo "(^|\s)\\\\[\\\\a-zA-Z0-9_.-]+" | tr "\\\\" "/" | tr -d '[:space:]')
        if [ -n "$g_custom_arch_kernel" ] && [ -e "$g_custom_arch_kernel" ]; then
            opt_kernel="$g_custom_arch_kernel"
        fi
        # FreeBSD:
        [ -e "/boot/kernel/kernel" ] && opt_kernel="/boot/kernel/kernel"
    fi

    # system.map
    if [ -n "$opt_map" ]; then
        # specified by user on cmdline, with --live, don't override
        :
    elif [ -e "$g_procfs/kallsyms" ]; then
        opt_map="$g_procfs/kallsyms"
    elif [ -e "/lib/modules/$(uname -r)/System.map" ]; then
        opt_map="/lib/modules/$(uname -r)/System.map"
    elif [ -e "/boot/System.map-$(uname -r)" ]; then
        opt_map="/boot/System.map-$(uname -r)"
    elif [ -e "/lib/kernel/System.map-$(uname -r)" ]; then
        opt_map="/lib/kernel/System.map-$(uname -r)"
    fi

    # config
    if [ -n "$opt_config" ]; then
        # specified by user on cmdline, with --live, don't override
        :
    elif [ -e "$g_procfs/config.gz" ]; then
        g_dumped_config="$(mktemp -t smc-config-XXXXXX)"
        gunzip -c "$g_procfs/config.gz" >"$g_dumped_config"
        # g_dumped_config will be deleted at the end of the script
        opt_config="$g_dumped_config"
    elif [ -e "/lib/modules/$(uname -r)/config" ]; then
        opt_config="/lib/modules/$(uname -r)/config"
    elif [ -e "/boot/config-$(uname -r)" ]; then
        opt_config="/boot/config-$(uname -r)"
    elif [ -e "/etc/kernels/kernel-config-$(uname -m)-$(uname -r)" ]; then
        opt_config="/etc/kernels/kernel-config-$(uname -m)-$(uname -r)"
    elif [ -e "/lib/kernel/config-$(uname -r)" ]; then
        opt_config="/lib/kernel/config-$(uname -r)"
    fi
else
    pr_info "Checking for vulnerabilities against specified kernel"
    pr_info "CPU is \033[35m$cpu_friendly_name\033[0m"
fi

if [ -n "$opt_kernel" ]; then
    pr_verbose "Will use kernel image \033[35m$opt_kernel\033[0m"
else
    pr_verbose "Will use no kernel image (accuracy might be reduced)"
    g_bad_accuracy=1
fi

if [ "$g_os" = Linux ]; then
    if [ -n "$opt_config" ] && ! grep -q '^CONFIG_' "$opt_config"; then
        # given file is invalid!
        pr_warn "The kernel config file seems invalid, was expecting a plain-text file, ignoring it!"
        opt_config=''
    fi

    if [ -n "${g_dumped_config:-}" ] && [ -n "$opt_config" ]; then
        pr_verbose "Will use kconfig \033[35m$g_procfs/config.gz (decompressed)\033[0m"
    elif [ -n "$opt_config" ]; then
        pr_verbose "Will use kconfig \033[35m$opt_config\033[0m"
    else
        pr_verbose "Will use no kconfig (accuracy might be reduced)"
        g_bad_accuracy=1
    fi

    if [ -n "$opt_map" ]; then
        pr_verbose "Will use System.map file \033[35m$opt_map\033[0m"
    else
        pr_verbose "Will use no System.map file (accuracy might be reduced)"
        g_bad_accuracy=1
    fi

    if [ "${g_bad_accuracy:=0}" = 1 ]; then
        pr_warn "We're missing some kernel info (see -v), accuracy might be reduced"
    fi
fi

if [ -e "$opt_kernel" ]; then
    if ! command -v "${opt_arch_prefix}readelf" >/dev/null 2>&1; then
        pr_debug "readelf not found"
        g_kernel_err="missing '${opt_arch_prefix}readelf' tool, please install it, usually it's in the 'binutils' package"
    elif [ "$opt_sysfs_only" = 1 ] || [ "$opt_hw_only" = 1 ]; then
        g_kernel_err='kernel image decompression skipped'
    else
        extract_kernel "$opt_kernel"
    fi
else
    pr_debug "no opt_kernel defined"
    g_kernel_err="couldn't find your kernel image in /boot, if you used netboot, this is normal"
fi
if [ -z "$g_kernel" ] || [ ! -r "$g_kernel" ]; then
    [ -z "$g_kernel_err" ] && g_kernel_err="couldn't extract your kernel from $opt_kernel"
else
    # vanilla kernels have with ^Linux version
    # also try harder with some kernels (such as Red Hat) that don't have ^Linux version before their version string
    # and check for FreeBSD
    g_kernel_version=$("${opt_arch_prefix}strings" "$g_kernel" 2>/dev/null | grep -E \
        -e '^Linux version ' \
        -e '^[[:alnum:]][^[:space:]]+ \([^[:space:]]+\) #[0-9]+ .+ (19|20)[0-9][0-9]$' \
        -e '^FreeBSD [0-9]' | grep -v 'ABI compat' | head -n1)
    if [ -z "$g_kernel_version" ]; then
        # try even harder with some kernels (such as ARM) that split the release (uname -r) and version (uname -v) in 2 adjacent strings
        g_kernel_version=$("${opt_arch_prefix}strings" "$g_kernel" 2>/dev/null | grep -E -B1 '^#[0-9]+ .+ (19|20)[0-9][0-9]$' | tr "\n" " ")
    fi
    if [ -n "$g_kernel_version" ]; then
        # in live mode, check if the img we found is the correct one
        if [ "$opt_live" = 1 ]; then
            pr_verbose "Kernel image is \033[35m$g_kernel_version"
            if ! echo "$g_kernel_version" | grep -qF "$(uname -r)"; then
                pr_warn "Possible discrepancy between your running kernel '$(uname -r)' and the image '$g_kernel_version' we found ($opt_kernel), results might be incorrect"
            fi
        else
            pr_info "Kernel image is \033[35m$g_kernel_version"
        fi
    else
        pr_verbose "Kernel image version is unknown"
    fi
fi

pr_info

# end of header stuff

# now we define some util functions and the check_*() funcs, as
# the user can choose to execute only some of those

# Check a sysfs/procfs file for a vulnerability mitigation status
# Args: $1=file_path $2=regex(optional) $3=mode(optional)
# Sets: ret_sys_interface_check_fullmsg
# Returns: 0 if file matched, 1 otherwise
sys_interface_check() {
    local file regex mode mockvarname
    file="$1"
    regex="${2:-}"
    mode="${3:-}"
    msg=''
    ret_sys_interface_check_fullmsg=''

    if [ "$opt_live" = 1 ] && [ "$opt_no_sysfs" = 0 ] && [ -r "$file" ]; then
        :
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_SYSFS_$(basename "$file")_RET=1")
        return 1
    fi

    mockvarname="SMC_MOCK_SYSFS_$(basename "$file")_RET"
    # shellcheck disable=SC2086,SC1083
    if [ -n "$(eval echo \${$mockvarname:-})" ]; then
        pr_debug "sysfs: MOCKING enabled for $file func returns $(eval echo \$$mockvarname)"
        g_mocked=1
        return "$(eval echo \$$mockvarname)"
    fi

    [ -n "$regex" ] || regex='.*'
    mockvarname="SMC_MOCK_SYSFS_$(basename "$file")"
    # shellcheck disable=SC2086,SC1083
    if [ -n "$(eval echo \${$mockvarname:-})" ]; then
        ret_sys_interface_check_fullmsg="$(eval echo \$$mockvarname)"
        msg=$(echo "$ret_sys_interface_check_fullmsg" | grep -Eo "$regex")
        pr_debug "sysfs: MOCKING enabled for $file, will return $ret_sys_interface_check_fullmsg"
        g_mocked=1
    else
        ret_sys_interface_check_fullmsg=$(cat "$file")
        msg=$(grep -Eo "$regex" "$file")
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_SYSFS_$(basename "$file")='$ret_sys_interface_check_fullmsg'")
    fi
    if [ "$mode" = silent ]; then
        return 0
    elif [ "$mode" = quiet ]; then
        pr_info "* Information from the /sys interface: $ret_sys_interface_check_fullmsg"
        return 0
    fi
    pr_info_nol "* Mitigated according to the /sys interface: "
    if echo "$msg" | grep -qi '^not affected'; then
        # Not affected
        ret_sys_interface_check_status=OK
        pstatus green YES "$ret_sys_interface_check_fullmsg"
    elif echo "$msg" | grep -qEi '^(kvm: )?mitigation'; then
        # Mitigation: PTI
        ret_sys_interface_check_status=OK
        pstatus green YES "$ret_sys_interface_check_fullmsg"
    elif echo "$msg" | grep -qi '^vulnerable'; then
        # Vulnerable
        ret_sys_interface_check_status=VULN
        pstatus yellow NO "$ret_sys_interface_check_fullmsg"
    else
        ret_sys_interface_check_status=UNK
        pstatus yellow UNKNOWN "$ret_sys_interface_check_fullmsg"
    fi
    pr_debug "sys_interface_check: $file=$msg (re=$regex)"
    return 0
}

# Display hardware-level CPU mitigation support (microcode features, ARCH_CAPABILITIES, etc.)
check_cpu() {
    local capabilities ret spec_ctrl_msr
    pr_info "\033[1;34mHardware check\033[0m"

    if ! uname -m | grep -qwE 'x86_64|i[3-6]86|amd64'; then
        return
    fi

    pr_info "* Hardware support (CPU microcode) for mitigation techniques"
    pr_info "  * Indirect Branch Restricted Speculation (IBRS)"
    pr_info_nol "    * SPEC_CTRL MSR is available: "
    read_msr $MSR_IA32_SPEC_CTRL
    ret=$?
    if [ $ret = $READ_MSR_RET_OK ]; then
        spec_ctrl_msr=1
        pstatus green YES
    elif [ $ret = $READ_MSR_RET_KO ]; then
        spec_ctrl_msr=0
        pstatus yellow NO
    else
        spec_ctrl_msr=-1
        pstatus yellow UNKNOWN "$ret_read_msr_msg"
    fi

    pr_info_nol "    * CPU indicates IBRS capability: "
    # from kernel src: { X86_FEATURE_SPEC_CTRL,        CPUID_EDX,26, 0x00000007, 0 },
    # amd: https://developer.amd.com/wp-content/resources/Architecture_Guidelines_Update_Indirect_Branch_Control.pdf
    # amd: 8000_0008 EBX[14]=1
    cap_ibrs=''
    if is_intel; then
        read_cpuid 0x7 0x0 $EDX 26 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES "SPEC_CTRL feature bit"
            cap_spec_ctrl=1
            cap_ibrs='SPEC_CTRL'
        fi
    elif is_amd || is_hygon; then
        read_cpuid 0x80000008 0x0 $EBX 14 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES "IBRS_SUPPORT feature bit"
            cap_ibrs='IBRS_SUPPORT'
        fi
    else
        ret=invalid
        pstatus yellow NO "unknown CPU"
    fi
    if [ $ret = $READ_CPUID_RET_KO ]; then
        pstatus yellow NO
    elif [ $ret = $READ_CPUID_RET_ERR ]; then
        pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        cap_spec_ctrl=-1
    fi

    if is_amd || is_hygon; then
        pr_info_nol "    * CPU indicates preferring IBRS always-on: "
        # amd or hygon
        read_cpuid 0x80000008 0x0 $EBX 16 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES
        elif [ $ret = $READ_CPUID_RET_KO ]; then
            pstatus yellow NO
        else
            pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        fi

        pr_info_nol "    * CPU indicates preferring IBRS over retpoline: "
        # amd or hygon
        read_cpuid 0x80000008 0x0 $EBX 18 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES
        elif [ $ret = $READ_CPUID_RET_KO ]; then
            pstatus yellow NO
        else
            pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        fi
    fi

    # IBPB
    pr_info "  * Indirect Branch Prediction Barrier (IBPB)"

    if [ "$opt_allow_msr_write" = 1 ]; then
        pr_info_nol "    * PRED_CMD MSR is available: "
        # the new MSR 'PRED_CTRL' is at offset 0x49, write-only
        write_msr 0x49
        ret=$?
        if [ $ret = $WRITE_MSR_RET_OK ]; then
            pstatus green YES
        elif [ $ret = $WRITE_MSR_RET_KO ]; then
            pstatus yellow NO
        else
            pstatus yellow UNKNOWN "$ret_write_msr_msg"
        fi
    fi

    pr_info_nol "    * CPU indicates IBPB capability: "
    # CPUID EAX=0x80000008, ECX=0x00 return EBX[12] indicates support for just IBPB.
    if [ "$cap_spec_ctrl" = 1 ]; then
        # spec_ctrl implies ibpb
        cap_ibpb='SPEC_CTRL'
        pstatus green YES "SPEC_CTRL feature bit"
    elif is_intel; then
        if [ "$cap_spec_ctrl" = -1 ]; then
            pstatus yellow UNKNOWN "is cpuid kernel module available?"
        else
            pstatus yellow NO
        fi
    elif is_amd || is_hygon; then
        read_cpuid 0x80000008 0x0 $EBX 12 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            cap_ibpb='IBPB_SUPPORT'
            pstatus green YES "IBPB_SUPPORT feature bit"
        elif [ $ret = $READ_CPUID_RET_KO ]; then
            pstatus yellow NO
        else
            pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        fi
    fi

    # STIBP
    pr_info "  * Single Thread Indirect Branch Predictors (STIBP)"
    pr_info_nol "    * SPEC_CTRL MSR is available: "
    if [ "$spec_ctrl_msr" = 1 ]; then
        pstatus green YES
    elif [ "$spec_ctrl_msr" = 0 ]; then
        pstatus yellow NO
    else
        pstatus yellow UNKNOWN "is msr kernel module available?"
    fi

    pr_info_nol "    * CPU indicates STIBP capability: "
    # intel: A processor supports STIBP if it enumerates CPUID (EAX=7H,ECX=0):EDX[27] as 1
    # amd: 8000_0008 EBX[15]=1
    cap_stibp=''
    if is_intel; then
        read_cpuid 0x7 0x0 $EDX 27 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES "Intel STIBP feature bit"
            cap_stibp='Intel STIBP'
        fi
    elif is_amd; then
        read_cpuid 0x80000008 0x0 $EBX 15 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES "AMD STIBP feature bit"
            cap_stibp='AMD STIBP'
        fi
    elif is_hygon; then
        read_cpuid 0x80000008 0x0 $EBX 15 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES "HYGON STIBP feature bit"
            cap_stibp='HYGON STIBP'
        fi
    else
        ret=invalid
        pstatus yellow UNKNOWN "unknown CPU"
    fi
    if [ $ret = $READ_CPUID_RET_KO ]; then
        pstatus yellow NO
    elif [ $ret = $READ_CPUID_RET_ERR ]; then
        pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
    fi

    if is_amd || is_hygon; then
        pr_info_nol "    * CPU indicates preferring STIBP always-on: "
        read_cpuid 0x80000008 0x0 $EBX 17 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES
        elif [ $ret = $READ_CPUID_RET_KO ]; then
            pstatus yellow NO
        else
            pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        fi
    fi

    # variant 4
    if is_intel; then
        pr_info "  * Speculative Store Bypass Disable (SSBD)"
        pr_info_nol "    * CPU indicates SSBD capability: "
        read_cpuid 0x7 0x0 $EDX 31 1 1
        ret24=$?
        ret25=$ret24
        if [ $ret24 = $READ_CPUID_RET_OK ]; then
            cap_ssbd='Intel SSBD'
        fi
    elif is_amd; then
        pr_info "  * Speculative Store Bypass Disable (SSBD)"
        pr_info_nol "    * CPU indicates SSBD capability: "
        read_cpuid 0x80000008 0x0 $EBX 24 1 1
        ret24=$?
        read_cpuid 0x80000008 0x0 $EBX 25 1 1
        ret25=$?
        if [ $ret24 = $READ_CPUID_RET_OK ]; then
            cap_ssbd='AMD SSBD in SPEC_CTRL'
            #cpuid_ssbd_spec_ctrl=1
        elif [ $ret25 = $READ_CPUID_RET_OK ]; then
            cap_ssbd='AMD SSBD in VIRT_SPEC_CTRL'
            #cpuid_ssbd_virt_spec_ctrl=1
        elif [ "$cpu_family" -ge 21 ] && [ "$cpu_family" -le 23 ]; then
            cap_ssbd='AMD non-architectural MSR'
        fi
    elif is_hygon; then
        pr_info "  * Speculative Store Bypass Disable (SSBD)"
        pr_info_nol "    * CPU indicates SSBD capability: "
        read_cpuid 0x80000008 0x0 $EBX 24 1 1
        ret24=$?
        read_cpuid 0x80000008 0x0 $EBX 25 1 1
        ret25=$?

        if [ $ret24 = $READ_CPUID_RET_OK ]; then
            cap_ssbd='HYGON SSBD in SPEC_CTRL'
            #hygon cpuid_ssbd_spec_ctrl=1
        elif [ $ret25 = $READ_CPUID_RET_OK ]; then
            cap_ssbd='HYGON SSBD in VIRT_SPEC_CTRL'
            #hygon cpuid_ssbd_virt_spec_ctrl=1
        elif [ "$cpu_family" -ge 24 ]; then
            cap_ssbd='HYGON non-architectural MSR'
        fi
    fi

    if [ -n "${cap_ssbd:=}" ]; then
        pstatus green YES "$cap_ssbd"
    elif [ "$ret24" = $READ_CPUID_RET_ERR ] && [ "$ret25" = $READ_CPUID_RET_ERR ]; then
        pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
    else
        pstatus yellow NO
    fi

    cap_amd_ssb_no=0
    cap_hygon_ssb_no=0
    if is_amd; then
        # similar to SSB_NO for intel
        read_cpuid 0x80000008 0x0 $EBX 26 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            cap_amd_ssb_no=1
        elif [ $ret = $READ_CPUID_RET_ERR ]; then
            cap_amd_ssb_no=-1
        fi
    elif is_hygon; then
        # indicate when speculative store bypass disable is no longer needed to prevent speculative loads bypassing older stores
        read_cpuid 0x80000008 0x0 $EBX 26 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            cap_hygon_ssb_no=1
        elif [ $ret = $READ_CPUID_RET_ERR ]; then
            cap_hygon_ssb_no=-1
        fi
    fi

    pr_info "  * L1 data cache invalidation"

    if [ "$opt_allow_msr_write" = 1 ]; then
        pr_info_nol "    * FLUSH_CMD MSR is available: "
        # the new MSR 'FLUSH_CMD' is at offset 0x10b, write-only
        write_msr 0x10b
        ret=$?
        if [ $ret = $WRITE_MSR_RET_OK ]; then
            pstatus green YES
            cap_flush_cmd=1
        elif [ $ret = $WRITE_MSR_RET_KO ]; then
            pstatus yellow NO
            cap_flush_cmd=0
        else
            pstatus yellow UNKNOWN "$ret_write_msr_msg"
            cap_flush_cmd=-1
        fi
    fi

    # CPUID of L1D
    pr_info_nol "    * CPU indicates L1D flush capability: "
    read_cpuid 0x7 0x0 $EDX 28 1 1
    ret=$?
    if [ $ret = $READ_CPUID_RET_OK ]; then
        pstatus green YES "L1D flush feature bit"
        cap_l1df=1
    elif [ $ret = $READ_CPUID_RET_KO ]; then
        pstatus yellow NO
        cap_l1df=0
    else
        pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        cap_l1df=-1
    fi

    # if we weren't allowed to probe the write-only MSR but the CPUID
    # bit says that it shoul be there, make the assumption that it is
    if [ "$opt_allow_msr_write" != 1 ]; then
        cap_flush_cmd=$cap_l1df
    fi

    if is_intel; then
        pr_info "  * Microarchitectural Data Sampling"
        pr_info_nol "    * VERW instruction is available: "
        read_cpuid 0x7 0x0 $EDX 10 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            cap_md_clear=1
            pstatus green YES "MD_CLEAR feature bit"
        elif [ $ret = $READ_CPUID_RET_KO ]; then
            cap_md_clear=0
            pstatus yellow NO
        else
            cap_md_clear=-1
            pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        fi
    fi

    if is_intel; then
        pr_info "  * Indirect Branch Predictor Controls"
        pr_info_nol "    * Indirect Predictor Disable feature is available: "
        read_cpuid 0x7 0x2 $EDX 1 1 1
        ret=$?
        # cap_ipred is not yet used in verdict logic (no kernel sysfs/config to cross-reference)
        # shellcheck disable=SC2034
        if [ $ret = $READ_CPUID_RET_OK ]; then
            cap_ipred=1
            pstatus green YES "IPRED_CTRL feature bit"
        elif [ $ret = $READ_CPUID_RET_KO ]; then
            cap_ipred=0
            pstatus yellow NO
        else
            cap_ipred=-1
            pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        fi

        pr_info_nol "    * Bottomless RSB Disable feature is available: "
        read_cpuid 0x7 0x2 $EDX 2 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            cap_rrsba=1
            pstatus green YES "RRSBA_CTRL feature bit"
        elif [ $ret = $READ_CPUID_RET_KO ]; then
            cap_rrsba=0
            pstatus yellow NO
        else
            cap_rrsba=-1
            pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        fi

        pr_info_nol "    * BHB-Focused Indirect Predictor Disable feature is available: "
        read_cpuid 0x7 0x2 $EDX 2 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            cap_bhi=1
            pstatus green YES "BHI_CTRL feature bit"
        elif [ $ret = $READ_CPUID_RET_KO ]; then
            cap_bhi=0
            pstatus yellow NO
        else
            cap_bhi=-1
            pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        fi
    fi

    if is_intel; then
        pr_info "  * Enhanced IBRS (IBRS_ALL)"
        pr_info_nol "    * CPU indicates ARCH_CAPABILITIES MSR availability: "
        cap_arch_capabilities=-1
        # A processor supports the ARCH_CAPABILITIES MSR if it enumerates CPUID (EAX=7H,ECX=0):EDX[29] as 1
        read_cpuid 0x7 0x0 $EDX 29 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES
            cap_arch_capabilities=1
        elif [ $ret = $READ_CPUID_RET_KO ]; then
            pstatus yellow NO
            cap_arch_capabilities=0
        else
            pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        fi

        pr_info_nol "    * ARCH_CAPABILITIES MSR advertises IBRS_ALL capability: "
        cap_taa_no=-1
        cap_mds_no=-1
        cap_rdcl_no=-1
        cap_ibrs_all=-1
        cap_rsba=-1
        cap_l1dflush_no=-1
        cap_ssb_no=-1
        cap_pschange_msc_no=-1
        cap_tsx_ctrl_msr=-1
        cap_gds_ctrl=-1
        cap_gds_no=-1
        cap_its_no=-1
        if [ "$cap_arch_capabilities" = -1 ]; then
            pstatus yellow UNKNOWN
        elif [ "$cap_arch_capabilities" != 1 ]; then
            cap_rdcl_no=0
            cap_taa_no=0
            cap_mds_no=0
            cap_ibrs_all=0
            cap_rsba=0
            cap_l1dflush_no=0
            cap_ssb_no=0
            cap_pschange_msc_no=0
            cap_tsx_ctrl_msr=0
            cap_gds_ctrl=0
            cap_gds_no=0
            cap_its_no=0
            pstatus yellow NO
        else
            read_msr $MSR_IA32_ARCH_CAPABILITIES
            ret=$?
            cap_rdcl_no=0
            cap_taa_no=0
            cap_mds_no=0
            cap_ibrs_all=0
            cap_rsba=0
            cap_l1dflush_no=0
            cap_ssb_no=0
            cap_pschange_msc_no=0
            cap_tsx_ctrl_msr=0
            cap_gds_ctrl=0
            cap_gds_no=0
            cap_its_no=0
            if [ $ret = $READ_MSR_RET_OK ]; then
                capabilities=$ret_read_msr_value
                # https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/x86/include/asm/msr-index.h#n82
                pr_debug "capabilities MSR is $capabilities (hex)"
                [ $((ret_read_msr_value_lo >> 0 & 1)) -eq 1 ] && cap_rdcl_no=1
                [ $((ret_read_msr_value_lo >> 1 & 1)) -eq 1 ] && cap_ibrs_all=1
                [ $((ret_read_msr_value_lo >> 2 & 1)) -eq 1 ] && cap_rsba=1
                [ $((ret_read_msr_value_lo >> 3 & 1)) -eq 1 ] && cap_l1dflush_no=1
                [ $((ret_read_msr_value_lo >> 4 & 1)) -eq 1 ] && cap_ssb_no=1
                [ $((ret_read_msr_value_lo >> 5 & 1)) -eq 1 ] && cap_mds_no=1
                [ $((ret_read_msr_value_lo >> 6 & 1)) -eq 1 ] && cap_pschange_msc_no=1
                [ $((ret_read_msr_value_lo >> 7 & 1)) -eq 1 ] && cap_tsx_ctrl_msr=1
                [ $((ret_read_msr_value_lo >> 8 & 1)) -eq 1 ] && cap_taa_no=1
                [ $((ret_read_msr_value_lo >> 25 & 1)) -eq 1 ] && cap_gds_ctrl=1
                [ $((ret_read_msr_value_lo >> 26 & 1)) -eq 1 ] && cap_gds_no=1
                [ $((ret_read_msr_value_hi >> 30 & 1)) -eq 1 ] && cap_its_no=1
                pr_debug "capabilities says rdcl_no=$cap_rdcl_no ibrs_all=$cap_ibrs_all rsba=$cap_rsba l1dflush_no=$cap_l1dflush_no ssb_no=$cap_ssb_no mds_no=$cap_mds_no taa_no=$cap_taa_no pschange_msc_no=$cap_pschange_msc_no its_no=$cap_its_no"
                if [ "$cap_ibrs_all" = 1 ]; then
                    pstatus green YES
                else
                    pstatus yellow NO
                fi
            elif [ $ret = $READ_MSR_RET_KO ]; then
                pstatus yellow NO
            else
                pstatus yellow UNKNOWN "$ret_read_msr_msg"
            fi
        fi

        pr_info_nol "  * CPU explicitly indicates not being affected by Meltdown/L1TF (RDCL_NO): "
        if [ "$cap_rdcl_no" = -1 ]; then
            pstatus yellow UNKNOWN
        elif [ "$cap_rdcl_no" = 1 ]; then
            pstatus green YES
        else
            pstatus yellow NO
        fi

        pr_info_nol "  * CPU explicitly indicates not being affected by Variant 4 (SSB_NO): "
        if [ "$cap_ssb_no" = -1 ]; then
            pstatus yellow UNKNOWN
        elif [ "$cap_ssb_no" = 1 ] || [ "$cap_amd_ssb_no" = 1 ] || [ "$cap_hygon_ssb_no" = 1 ]; then
            pstatus green YES
        else
            pstatus yellow NO
        fi

        pr_info_nol "  * CPU/Hypervisor indicates L1D flushing is not necessary on this system: "
        if [ "$cap_l1dflush_no" = -1 ]; then
            pstatus yellow UNKNOWN
        elif [ "$cap_l1dflush_no" = 1 ]; then
            pstatus green YES
        else
            pstatus yellow NO
        fi

        pr_info_nol "  * Hypervisor indicates host CPU might be affected by RSB underflow (RSBA): "
        if [ "$cap_rsba" = -1 ]; then
            pstatus yellow UNKNOWN
        elif [ "$cap_rsba" = 1 ]; then
            pstatus yellow YES
        else
            pstatus blue NO
        fi

        pr_info_nol "  * CPU explicitly indicates not being affected by Microarchitectural Data Sampling (MDS_NO): "
        if [ "$cap_mds_no" = -1 ]; then
            pstatus yellow UNKNOWN
        elif [ "$cap_mds_no" = 1 ]; then
            pstatus green YES
        else
            pstatus yellow NO
        fi

        pr_info_nol "  * CPU explicitly indicates not being affected by TSX Asynchronous Abort (TAA_NO): "
        if [ "$cap_taa_no" = -1 ]; then
            pstatus yellow UNKNOWN
        elif [ "$cap_taa_no" = 1 ]; then
            pstatus green YES
        else
            pstatus yellow NO
        fi

        pr_info_nol "  * CPU explicitly indicates not being affected by iTLB Multihit (PSCHANGE_MSC_NO): "
        if [ "$cap_pschange_msc_no" = -1 ]; then
            pstatus yellow UNKNOWN
        elif [ "$cap_pschange_msc_no" = 1 ]; then
            pstatus green YES
        else
            pstatus yellow NO
        fi

        pr_info_nol "  * CPU explicitly indicates having MSR for TSX control (TSX_CTRL_MSR): "
        if [ "$cap_tsx_ctrl_msr" = -1 ]; then
            pstatus yellow UNKNOWN
        elif [ "$cap_tsx_ctrl_msr" = 1 ]; then
            pstatus green YES
        else
            pstatus yellow NO
        fi

        if [ "$cap_tsx_ctrl_msr" = 1 ]; then
            read_msr $MSR_IA32_TSX_CTRL
            ret=$?
            if [ "$ret" = $READ_MSR_RET_OK ]; then
                cap_tsx_ctrl_rtm_disable=$((ret_read_msr_value_lo >> 0 & 1))
                cap_tsx_ctrl_cpuid_clear=$((ret_read_msr_value_lo >> 1 & 1))
            fi

            pr_info_nol "    * TSX_CTRL MSR indicates TSX RTM is disabled: "
            if [ "$cap_tsx_ctrl_rtm_disable" = 1 ]; then
                pstatus blue YES
            elif [ "$cap_tsx_ctrl_rtm_disable" = 0 ]; then
                pstatus blue NO
            else
                pstatus yellow UNKNOWN "couldn't read MSR"
            fi

            pr_info_nol "    * TSX_CTRL MSR indicates TSX CPUID bit is cleared: "
            if [ "$cap_tsx_ctrl_cpuid_clear" = 1 ]; then
                pstatus blue YES
            elif [ "$cap_tsx_ctrl_cpuid_clear" = 0 ]; then
                pstatus blue NO
            else
                pstatus yellow UNKNOWN "couldn't read MSR"
            fi
        fi

        pr_info_nol "  * CPU explicitly indicates being affected by GDS and having mitigation control (GDS_CTRL): "
        if [ "$cap_gds_ctrl" = -1 ]; then
            pstatus yellow UNKNOWN "couldn't read MSR"
        elif [ "$cap_gds_ctrl" = 1 ]; then
            pstatus green YES
        else
            pstatus blue NO
        fi

        cap_gds_mitg_dis=-1
        cap_gds_mitg_lock=-1
        if [ "$cap_gds_ctrl" = 1 ]; then
            read_msr $MSR_IA32_MCU_OPT_CTRL
            ret=$?
            if [ "$ret" = $READ_MSR_RET_OK ]; then
                cap_gds_mitg_dis=$((ret_read_msr_value_lo >> 4 & 1))
                cap_gds_mitg_lock=$((ret_read_msr_value_lo >> 5 & 1))
            fi

            pr_info_nol "    * GDS microcode mitigation is disabled (GDS_MITG_DIS): "
            if [ "$cap_gds_mitg_dis" = -1 ]; then
                pstatus yellow UNKNOWN "couldn't read MSR"
            elif [ "$cap_gds_mitg_dis" = 1 ]; then
                pstatus yellow YES
            else
                pstatus green NO
            fi

            pr_info_nol "    * GDS microcode mitigation is locked in enabled state (GDS_MITG_LOCK): "
            if [ "$cap_gds_mitg_lock" = -1 ]; then
                pstatus yellow UNKNOWN "couldn't read MSR"
            elif [ "$cap_gds_mitg_lock" = 1 ]; then
                pstatus blue YES
            else
                pstatus blue NO
            fi
        fi

        pr_info_nol "  * CPU explicitly indicates not being affected by GDS (GDS_NO): "
        if [ "$cap_gds_no" = -1 ]; then
            pstatus yellow UNKNOWN "couldn't read MSR"
        elif [ "$cap_gds_no" = 1 ]; then
            pstatus green YES
        else
            pstatus yellow NO
        fi

    fi

    if is_amd || is_hygon; then
        pr_info "  * Selective Branch Predictor Barrier (SBPB)"
        pr_info_nol "    * PRED_CMD MSR supports SBPB bit write: "

        if [ "$opt_allow_msr_write" = 1 ]; then
            # the MSR PRED_SBPB is at offset 0x49, BIT(7), write-only
            write_msr 0x49 128
            ret=$?
            if [ $ret = $WRITE_MSR_RET_OK ]; then
                pstatus green YES
                cap_sbpb=1
            elif [ $ret = $WRITE_MSR_RET_KO ]; then
                pstatus yellow NO
                cap_sbpb=2
            else
                pstatus yellow UNKNOWN "$ret_write_msr_msg"
                cap_sbpb=3
            fi
        else
            pstatus yellow UNKNOWN "not allowed to write msr"
            cap_sbpb=3
        fi
    fi

    if is_amd || is_hygon; then
        pr_info "  * Transient Scheduler Attacks"
        pr_info_nol "    * CPU indicates TSA_SQ_NO: "
        cap_tsa_sq_no=''
        read_cpuid 0x80000021 0x0 $ECX 1 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES
            cap_tsa_sq_no=1
        elif [ $ret = $READ_CPUID_RET_KO ]; then
            pstatus yellow NO
            cap_tsa_sq_no=0
        else
            pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        fi

        pr_info_nol "    * CPU indicates TSA_L1_NO: "
        cap_tsa_l1_no=''
        read_cpuid 0x80000021 0x0 $ECX 2 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES
            cap_tsa_l1_no=1
        elif [ $ret = $READ_CPUID_RET_KO ]; then
            pstatus yellow NO
            cap_tsa_l1_no=0
        else
            pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        fi

        pr_info_nol "    * CPU indicates VERW clears CPU buffers: "
        cap_verw_clear=''
        read_cpuid 0x80000021 0x0 $EAX 5 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES
            cap_verw_clear=1
        elif [ $ret = $READ_CPUID_RET_KO ]; then
            pstatus yellow NO
            cap_verw_clear=0
        else
            pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        fi

        pr_info_nol "    * CPU indicates AutoIBRS capability: "
        cap_autoibrs=''
        read_cpuid 0x80000021 0x0 $EAX 8 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES
            cap_autoibrs=1
        elif [ $ret = $READ_CPUID_RET_KO ]; then
            pstatus yellow NO
            cap_autoibrs=0
        else
            pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        fi
    fi

    pr_info_nol "  * CPU supports Transactional Synchronization Extensions (TSX): "
    ret=$READ_CPUID_RET_KO
    cap_rtm=0
    if is_intel; then
        read_cpuid 0x7 0x0 $EBX 11 1 1
        ret=$?
    fi
    if [ $ret = $READ_CPUID_RET_OK ]; then
        cap_rtm=1
        pstatus green YES "RTM feature bit"
    elif [ $ret = $READ_CPUID_RET_KO ]; then
        pstatus yellow NO
    else
        cap_rtm=-1
        pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
    fi

    pr_info_nol "  * CPU supports Software Guard Extensions (SGX): "
    ret=$READ_CPUID_RET_KO
    cap_sgx=0
    if is_intel; then
        read_cpuid 0x7 0x0 $EBX 2 1 1
        ret=$?
    fi
    if [ $ret = $READ_CPUID_RET_OK ]; then
        pstatus blue YES
        cap_sgx=1
    elif [ $ret = $READ_CPUID_RET_KO ]; then
        pstatus green NO
    else
        cap_sgx=-1
        pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
    fi

    pr_info_nol "  * CPU supports Special Register Buffer Data Sampling (SRBDS): "
    # A processor supports SRBDS if it enumerates CPUID (EAX=7H,ECX=0):EDX[9] as 1
    # That means the mitigation disabling SRBDS exists
    ret=$READ_CPUID_RET_KO
    cap_srbds=0
    cap_srbds_on=0
    if is_intel; then
        read_cpuid 0x7 0x0 $EDX 9 1 1
        ret=$?
    fi
    if [ $ret = $READ_CPUID_RET_OK ]; then
        pstatus blue YES
        cap_srbds=1
        read_msr $MSR_IA32_MCU_OPT_CTRL
        ret=$?
        if [ $ret = $READ_MSR_RET_OK ]; then
            if [ "$ret_read_msr_value" = "0000000000000000" ]; then
                #SRBDS mitigation control exists and is enabled via microcode
                cap_srbds_on=1
            else
                #SRBDS mitigation control exists but is disabled via microcode
                cap_srbds_on=0
            fi
        else
            cap_srbds_on=-1
        fi
    elif [ $ret = $READ_CPUID_RET_KO ]; then
        pstatus green NO
    else
        pstatus yellow UNKNOWN "$ret_read_cpuid_msg"
        cap_srbds=0
    fi

    if is_amd; then
        pr_info_nol "  * CPU microcode is known to fix Zenbleed: "
        has_zenbleed_fixed_firmware
        ret=$?
        if [ $ret -eq 0 ]; then
            # affected CPU, new fw
            pstatus green YES
        elif [ $ret -eq 1 ]; then
            # affected CPU, old fw
            pstatus red NO "required version: $g_zenbleed_fw_required"
        else
            # unaffected CPU
            pstatus yellow NO
        fi
    fi

    pr_info_nol "  * CPU microcode is known to cause stability problems: "
    if is_ucode_blacklisted; then
        pstatus red YES "$g_ucode_found"
        pr_warn
        pr_warn "The microcode your CPU is running on is known to cause instability problems,"
        pr_warn "such as intempestive reboots or random crashes."
        pr_warn "You are advised to either revert to a previous microcode version (that might not have"
        pr_warn "the mitigations for recent vulnerabilities), or upgrade to a newer one if available."
        pr_warn
    else
        pstatus blue NO "$g_ucode_found"
    fi

    pr_info_nol "  * CPU microcode is the latest known available version: "
    is_latest_known_ucode
    ret=$?
    if [ $ret -eq 0 ]; then
        pstatus green YES "$ret_is_latest_known_ucode_latest"
    elif [ $ret -eq 1 ]; then
        pstatus red NO "$ret_is_latest_known_ucode_latest"
    else
        pstatus blue UNKNOWN "$ret_is_latest_known_ucode_latest"
    fi
}

# Display per-CVE CPU vulnerability status based on CPU model/family
check_cpu_vulnerabilities() {
    local cve
    pr_info "* CPU vulnerability to the speculative execution attack variants"
    for cve in $g_supported_cve_list; do
        pr_info_nol "  * Affected by $cve ($(cve2name "$cve")): "
        if is_cpu_affected "$cve"; then
            pstatus yellow YES
        else
            pstatus green NO
        fi
    done
}

# Detect Red Hat/Canonical backported Spectre mitigations in the kernel binary
# Sets: g_redhat_canonical_spectre
check_redhat_canonical_spectre() {
    # if we were already called, don't do it again
    [ -n "${g_redhat_canonical_spectre:-}" ] && return

    if ! command -v "${opt_arch_prefix}strings" >/dev/null 2>&1; then
        g_redhat_canonical_spectre=-1
    elif [ -n "$g_kernel_err" ]; then
        g_redhat_canonical_spectre=-2
    else
        # Red Hat / Ubuntu specific affected_variant1 patch is difficult to detect,
        # let's use the two same tricks than the official Red Hat detection script uses:
        if "${opt_arch_prefix}strings" "$g_kernel" | grep -qw noibrs && "${opt_arch_prefix}strings" "$g_kernel" | grep -qw noibpb; then
            # 1) detect their specific affected_variant2 patch. If it's present, it means
            # that the affected_variant1 patch is also present (both were merged at the same time)
            pr_debug "found redhat/canonical version of the affected_variant2 patch (implies affected_variant1)"
            g_redhat_canonical_spectre=1
        elif "${opt_arch_prefix}strings" "$g_kernel" | grep -q 'x86/pti:'; then
            # 2) detect their specific affected_variant3 patch. If it's present, but the affected_variant2
            # is not, it means that only affected_variant1 is present in addition to affected_variant3
            pr_debug "found redhat/canonical version of the affected_variant3 patch (implies affected_variant1 but not affected_variant2)"
            g_redhat_canonical_spectre=2
        else
            g_redhat_canonical_spectre=0
        fi
    fi
}

# Detect whether this system is hosting virtual machines (hypervisor check).
# Detection runs only on the first call; subsequent calls reuse the cached
# result.  The status line is always printed so each CVE section shows the
# hypervisor context to the user.
# Sets: g_has_vmm, g_has_vmm_reason
check_has_vmm() {
    local binary pid
    pr_info_nol "* This system is a host running a hypervisor: "
    if [ "$g_has_vmm_cached" != 1 ]; then
        g_has_vmm=$opt_vmm
        if [ "$g_has_vmm" != -1 ]; then
            # --vmm was explicitly set on the command line
            g_has_vmm_reason="forced from command line"
        elif [ "$opt_paranoid" = 1 ]; then
            # In paranoid mode, if --vmm was not specified on the command-line,
            # we want to be secure before everything else, so assume we're running
            # a hypervisor, as this requires more mitigations
            g_has_vmm=1
            g_has_vmm_reason="paranoid mode"
        else
            # Here, we want to know if we are hosting a hypervisor, and running some VMs on it.
            # If we find no evidence that this is the case, assume we're not (to avoid scaring users),
            # this can always be overridden with --vmm in any case.
            g_has_vmm=0
            if command -v pgrep >/dev/null 2>&1; then
                # Exclude xenbus/xenwatch (present inside domU guests) and
                # libvirtd (also manages containers, not just VMs).
                # Use pgrep -x (exact match) for most binaries.  QEMU is
                # special: the binary is almost never just "qemu" — it is
                # "qemu-system-x86_64", "qemu-system-aarch64", etc.  We
                # keep "qemu" for the rare wrapper/symlink case and add
                # "qemu-system-" as a substring match via a separate pgrep
                # call (without -x) to catch all qemu-system-* variants.
                # Kernel threads (e.g. [kvm-irqfd-clean]) are filtered out
                # below via the /proc/$pid/exe symlink check.
                # Note: the kernel truncates process names to 15 chars
                # (TASK_COMM_LEN), so pgrep -x can't match longer names.
                # "cloud-hypervisor" (16 chars) is handled in the substring
                # block below alongside qemu-system-*.
                for binary in qemu kvm xenstored xenconsoled \
                    VBoxHeadless VBoxSVC vmware-vmx firecracker bhyve; do
                    for pid in $(pgrep -x "$binary"); do
                        # resolve the exe symlink, if it doesn't resolve with -m,
                        # which doesn't even need the dest to exist, it means the symlink
                        # is null, which is the case for kernel threads: ignore those to
                        # avoid false positives (such as [kvm-irqfd-clean] under at least RHEL 7.6/7.7)
                        if ! [ "$(readlink -m "/proc/$pid/exe")" = "/proc/$pid/exe" ]; then
                            pr_debug "g_has_vmm: found PID $pid ($binary)"
                            g_has_vmm=1
                            g_has_vmm_reason="$binary process found (PID $pid)"
                        fi
                    done
                done
                # substring matches for names that pgrep -x can't handle:
                # - qemu-system-*: variable suffix (x86_64, aarch64, ...)
                # - cloud-hypervisor: 16 chars, exceeds TASK_COMM_LEN (15)
                if [ "$g_has_vmm" = 0 ]; then
                    for binary in "qemu-system-" "cloud-hyperviso"; do
                        for pid in $(pgrep "$binary"); do
                            if ! [ "$(readlink -m "/proc/$pid/exe")" = "/proc/$pid/exe" ]; then
                                pr_debug "g_has_vmm: found PID $pid ($binary*)"
                                g_has_vmm=1
                                g_has_vmm_reason="$binary* process found (PID $pid)"
                            fi
                        done
                    done
                fi
                unset binary pid
            else
                # ignore SC2009 as `ps ax` is actually used as a fallback if `pgrep` isn't installed
                # shellcheck disable=SC2009
                if command -v ps >/dev/null && ps ax | grep -vw grep | grep -q \
                    -e '\<qemu' -e '/qemu' -e '\<kvm' -e '/kvm' \
                    -e '/xenstored' -e '/xenconsoled' \
                    -e '\<VBoxHeadless' -e '\<VBoxSVC' -e '\<vmware-vmx' \
                    -e '\<firecracker' -e '\<cloud-hypervisor' -e '\<bhyve'; then
                    g_has_vmm=1
                    g_has_vmm_reason="hypervisor process found"
                fi
            fi
        fi
        g_has_vmm_cached=1
    fi
    if [ "$g_has_vmm" = 0 ]; then
        pstatus green NO "$g_has_vmm_reason"
    else
        pstatus blue YES "$g_has_vmm_reason"
    fi
}

# >>>>>> vulns-helpers/check_cve.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# Generic CVE check dispatcher: prints CVE header and calls the OS-specific check function
# Args: $1=cve_id $2=func_prefix(optional, default derived from CVE ID)
check_cve() {
    local cve func_prefix
    cve="$1"
    func_prefix="${2:-check_$(echo "$cve" | tr - _)}"
    pr_info "\033[1;34m$cve aka '$(cve2name "$cve")'\033[0m"
    if [ "$g_os" = Linux ]; then
        if type "${func_prefix}_linux" >/dev/null 2>&1; then
            "${func_prefix}_linux"
        else
            pr_warn "Unsupported OS ($g_os)"
        fi
    elif echo "$g_os" | grep -q BSD; then
        if type "${func_prefix}_bsd" >/dev/null 2>&1; then
            "${func_prefix}_bsd"
        else
            pr_warn "Unsupported OS ($g_os)"
        fi
    else
        pr_warn "Unsupported OS ($g_os)"
    fi
}

# >>>>>> vulns-helpers/check_mds.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# MDS (microarchitectural data sampling) - BSD mitigation check
check_mds_bsd() {
    local kernel_md_clear kernel_smt_allowed kernel_mds_enabled kernel_mds_state
    pr_info_nol "* Kernel supports using MD_CLEAR mitigation: "
    if [ "$opt_live" = 1 ]; then
        if sysctl hw.mds_disable >/dev/null 2>&1; then
            pstatus green YES
            kernel_md_clear=1
        else
            pstatus yellow NO
            kernel_md_clear=0
        fi
    else
        if grep -Fq hw.mds_disable "$opt_kernel"; then
            pstatus green YES
            kernel_md_clear=1
        else
            kernel_md_clear=0
            pstatus yellow NO
        fi
    fi

    pr_info_nol "* CPU Hyper-Threading (SMT) is disabled: "
    if sysctl machdep.hyperthreading_allowed >/dev/null 2>&1; then
        kernel_smt_allowed=$(sysctl -n machdep.hyperthreading_allowed 2>/dev/null)
        if [ "$kernel_smt_allowed" = 1 ]; then
            pstatus yellow NO
        else
            pstatus green YES
        fi
    else
        pstatus yellow UNKNOWN "sysctl machdep.hyperthreading_allowed doesn't exist"
    fi

    pr_info_nol "* Kernel mitigation is enabled: "
    if [ "$kernel_md_clear" = 1 ]; then
        kernel_mds_enabled=$(sysctl -n hw.mds_disable 2>/dev/null)
    else
        kernel_mds_enabled=0
    fi
    case "$kernel_mds_enabled" in
        0) pstatus yellow NO ;;
        1) pstatus green YES "with microcode support" ;;
        2) pstatus green YES "software-only support (SLOW)" ;;
        3) pstatus green YES ;;
        *) pstatus yellow UNKNOWN "unknown value $kernel_mds_enabled" ;;
    esac

    pr_info_nol "* Kernel mitigation is active: "
    if [ "$kernel_md_clear" = 1 ]; then
        kernel_mds_state=$(sysctl -n hw.mds_disable_state 2>/dev/null)
    else
        kernel_mds_state=inactive
    fi
    # https://github.com/freebsd/freebsd/blob/master/sys/x86/x86/cpu_machdep.c#L953
    case "$kernel_mds_state" in
        inactive) pstatus yellow NO ;;
        VERW) pstatus green YES "with microcode support" ;;
        software*) pstatus green YES "software-only support (SLOW)" ;;
        *) pstatus yellow UNKNOWN ;;
    esac

    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        if [ "$cap_md_clear" = 1 ]; then
            if [ "$kernel_md_clear" = 1 ]; then
                if [ "$opt_live" = 1 ]; then
                    # mitigation must also be enabled
                    if [ "$kernel_mds_enabled" -ge 1 ]; then
                        if [ "$opt_paranoid" != 1 ] || [ "$kernel_smt_allowed" = 0 ]; then
                            pvulnstatus "$cve" OK "Your microcode and kernel are both up to date for this mitigation, and mitigation is enabled"
                        else
                            pvulnstatus "$cve" VULN "Your microcode and kernel are both up to date for this mitigation, but you must disable SMT (Hyper-Threading) for a complete mitigation"
                        fi
                    else
                        pvulnstatus "$cve" VULN "Your microcode and kernel are both up to date for this mitigation, but the mitigation is not active"
                        explain "To enable mitigation, run \`sysctl hw.mds_disable=1'. To make this change persistent across reboots, you can add 'hw.mds_disable=1' to /etc/sysctl.conf."
                    fi
                else
                    pvulnstatus "$cve" OK "Your microcode and kernel are both up to date for this mitigation"
                fi
            else
                pvulnstatus "$cve" VULN "Your microcode supports mitigation, but your kernel doesn't, upgrade it to mitigate the vulnerability"
            fi
        else
            if [ "$kernel_md_clear" = 1 ]; then
                pvulnstatus "$cve" VULN "Your kernel supports mitigation, but your CPU microcode also needs to be updated to mitigate the vulnerability"
            else
                pvulnstatus "$cve" VULN "Neither your kernel or your microcode support mitigation, upgrade both to mitigate the vulnerability"
            fi
        fi
    fi
}

# MDS (microarchitectural data sampling) - Linux mitigation check
check_mds_linux() {
    local status sys_interface_available msg kernel_md_clear kernel_md_clear_can_tell mds_mitigated mds_smt_mitigated mystatus mymsg
    status=UNK
    sys_interface_available=0
    msg=''
    if sys_interface_check "$VULN_SYSFS_BASE/mds" '^[^;]+'; then
        sys_interface_available=1
        status=$ret_sys_interface_check_status
    fi

    if [ "$opt_sysfs_only" != 1 ]; then
        pr_info_nol "* Kernel supports using MD_CLEAR mitigation: "
        kernel_md_clear=''
        kernel_md_clear_can_tell=1
        if [ "$opt_live" = 1 ] && grep ^flags "$g_procfs/cpuinfo" | grep -qw md_clear; then
            kernel_md_clear="md_clear found in $g_procfs/cpuinfo"
            pstatus green YES "$kernel_md_clear"
        fi
        if [ -z "$kernel_md_clear" ]; then
            if ! command -v "${opt_arch_prefix}strings" >/dev/null 2>&1; then
                kernel_md_clear_can_tell=0
            elif [ -n "$g_kernel_err" ]; then
                kernel_md_clear_can_tell=0
            elif "${opt_arch_prefix}strings" "$g_kernel" | grep -q 'Clear CPU buffers'; then
                pr_debug "md_clear: found 'Clear CPU buffers' string in kernel image"
                kernel_md_clear='found md_clear implementation evidence in kernel image'
                pstatus green YES "$kernel_md_clear"
            fi
        fi
        if [ -z "$kernel_md_clear" ]; then
            if [ "$kernel_md_clear_can_tell" = 1 ]; then
                pstatus yellow NO
            else
                pstatus yellow UNKNOWN
            fi
        fi

        if [ "$opt_live" = 1 ] && [ "$sys_interface_available" = 1 ]; then
            pr_info_nol "* Kernel mitigation is enabled and active: "
            if echo "$ret_sys_interface_check_fullmsg" | grep -qi ^mitigation; then
                mds_mitigated=1
                pstatus green YES
            else
                mds_mitigated=0
                pstatus yellow NO
            fi
            pr_info_nol "* SMT is either mitigated or disabled: "
            if echo "$ret_sys_interface_check_fullmsg" | grep -Eq 'SMT (disabled|mitigated)'; then
                mds_smt_mitigated=1
                pstatus green YES
            else
                mds_smt_mitigated=0
                pstatus yellow NO
            fi
        fi
    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        if [ "$opt_sysfs_only" != 1 ]; then
            # compute mystatus and mymsg from our own logic
            if [ "$cap_md_clear" = 1 ]; then
                if [ -n "$kernel_md_clear" ]; then
                    if [ "$opt_live" = 1 ]; then
                        # mitigation must also be enabled
                        if [ "$mds_mitigated" = 1 ]; then
                            if [ "$opt_paranoid" != 1 ] || [ "$mds_smt_mitigated" = 1 ]; then
                                mystatus=OK
                                mymsg="Your microcode and kernel are both up to date for this mitigation, and mitigation is enabled"
                            else
                                mystatus=VULN
                                mymsg="Your microcode and kernel are both up to date for this mitigation, but you must disable SMT (Hyper-Threading) for a complete mitigation"
                            fi
                        else
                            mystatus=VULN
                            mymsg="Your microcode and kernel are both up to date for this mitigation, but the mitigation is not active"
                        fi
                    else
                        mystatus=OK
                        mymsg="Your microcode and kernel are both up to date for this mitigation"
                    fi
                else
                    mystatus=VULN
                    mymsg="Your microcode supports mitigation, but your kernel doesn't, upgrade it to mitigate the vulnerability"
                fi
            else
                if [ -n "$kernel_md_clear" ]; then
                    mystatus=VULN
                    mymsg="Your kernel supports mitigation, but your CPU microcode also needs to be updated to mitigate the vulnerability"
                else
                    mystatus=VULN
                    mymsg="Neither your kernel or your microcode support mitigation, upgrade both to mitigate the vulnerability"
                fi
            fi
        else
            # sysfs only: return the status/msg we got
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
            return
        fi

        # if we didn't get a msg+status from sysfs, use ours
        if [ -z "$msg" ]; then
            pvulnstatus "$cve" "$mystatus" "$mymsg"
        elif [ "$opt_paranoid" = 1 ]; then
            # if paranoid mode is enabled, we now that we won't agree on status, so take ours
            pvulnstatus "$cve" "$mystatus" "$mymsg"
        elif [ "$status" = "$mystatus" ]; then
            # if we agree on status, we'll print the common status and our message (more detailed than the sysfs one)
            pvulnstatus "$cve" "$status" "$mymsg"
        else
            # if we don't agree on status, maybe our logic is flawed due to a new kernel/mitigation? use the one from sysfs
            pvulnstatus "$cve" "$status" "$msg"
        fi
    fi
}

# >>>>>> vulns/CVE-2017-5715.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2017-5715, Spectre V2, Branch Target Injection

# Sets: vulnstatus
check_CVE_2017_5715() {
    check_cve 'CVE-2017-5715'
}

# Sets: g_ibrs_can_tell, g_ibrs_supported, g_ibrs_enabled, g_ibrs_fw_enabled,
#   g_ibpb_can_tell, g_ibpb_supported, g_ibpb_enabled, g_specex_knob_dir
check_CVE_2017_5715_linux() {
    local status sys_interface_available msg dir bp_harden_can_tell bp_harden retpoline retpoline_compiler retpoline_compiler_reason retp_enabled rsb_filling
    local v2_base_mode v2_stibp_status v2_pbrsb_status v2_bhi_status v2_ibpb_mode v2_vuln_module v2_is_autoibrs smt_enabled
    status=UNK
    sys_interface_available=0
    msg=''
    if sys_interface_check "$VULN_SYSFS_BASE/spectre_v2"; then
        sys_interface_available=1
        status=$ret_sys_interface_check_status
        #
        # Complete sysfs message inventory for spectre_v2, traced via git blame
        # on mainline (~/linux) and stable (~/linux-stable):
        #
        # all versions:
        #   "Not affected"                          (cpu_show_common, 61dc0f555b5c)
        #   "Vulnerable"                            (cpu_show_common fallthrough / spectre_v2_strings[NONE], 61dc0f555b5c)
        #
        # The output is a composite string: <base>[<ibpb>][<ibrs_fw>][<stibp>][<rsb>][<pbrsb>][<bhi>][<module>]
        # where <base> comes from spectre_v2_strings[] (or an early-return override),
        # and the remaining fields are appended by helper functions.
        # Before v6.9-rc4 (0cd01ac5dcb1), fields were separated by ", ".
        # From v6.9-rc4 onward, fields are separated by "; ".
        #
        # --- base string (spectre_v2_strings[]) ---
        #
        # da285121560e (v4.15, initial spectre_v2 sysfs):
        #   "Vulnerable"
        #   "Mitigation: None"                           (documented in spectre.rst 5ad3eb113245,
        #     not found in code but listed as a possible value; treat as vulnerable / sysfs override)
        #   "Vulnerable: Minimal generic ASM retpoline"
        #   "Vulnerable: Minimal AMD ASM retpoline"
        #   "Mitigation: Full generic retpoline"
        #   "Mitigation: Full AMD retpoline"
        # 706d51681d63 (v4.19, added Enhanced IBRS):
        #   + "Mitigation: Enhanced IBRS"
        # ef014aae8f1c (v4.20-rc5, removed minimal retpoline):
        #   - "Vulnerable: Minimal generic ASM retpoline"
        #   - "Vulnerable: Minimal AMD ASM retpoline"
        # d45476d98324 (v5.17-rc8, renamed retpoline variants):
        #   "Mitigation: Full generic retpoline" -> "Mitigation: Retpolines"
        #   "Mitigation: Full AMD retpoline" -> "Mitigation: LFENCE" (in array)
        #   NOTE: "Mitigation: LFENCE" was the actual sysfs output for a brief window
        #   (between d45476d98324 and eafd987d4a82, both in v5.17-rc8) before the
        #   show_state override reclassified it as "Vulnerable: LFENCE". LFENCE alone
        #   is now considered an insufficient mitigation for Spectre v2. Any kernel
        #   reporting "Mitigation: LFENCE" is from this narrow window and should be
        #   treated as vulnerable.
        # 1e19da8522c8 (v5.17-rc8, split Enhanced IBRS into 3 modes):
        #   "Mitigation: Enhanced IBRS" -> "Mitigation: Enhanced IBRS" (EIBRS alone)
        #   + "Mitigation: Enhanced IBRS + LFENCE"
        #   + "Mitigation: Enhanced IBRS + Retpolines"
        # 7c693f54c873 (v5.19-rc7, added kernel IBRS):
        #   + "Mitigation: IBRS"
        # e7862eda309e (v6.3-rc1, AMD Automatic IBRS):
        #   "Mitigation: Enhanced IBRS" -> "Mitigation: Enhanced / Automatic IBRS"
        #   "Mitigation: Enhanced IBRS + LFENCE" -> "Mitigation: Enhanced / Automatic IBRS + LFENCE"
        #   "Mitigation: Enhanced IBRS + Retpolines" -> "Mitigation: Enhanced / Automatic IBRS + Retpolines"
        # d1cc1baef67a (v6.18-rc1, fixed LFENCE in array):
        #   "Mitigation: LFENCE" -> "Vulnerable: LFENCE" (in array, matching the
        #   show_state override that had been correcting the sysfs output since v5.17)
        #
        # --- early-return overrides in spectre_v2_show_state() ---
        #
        # These bypass the base string + suffix format entirely.
        #
        # eafd987d4a82 (v5.17-rc8, LFENCE override):
        #   "Vulnerable: LFENCE"
        #   (overrode the array's "Mitigation: LFENCE"; removed in v6.18-rc1 when the array
        #   was fixed to say "Vulnerable: LFENCE" directly)
        # 44a3918c8245 (v5.17-rc8, created spectre_v2_show_state, eIBRS+eBPF):
        #   "Vulnerable: Unprivileged eBPF enabled"
        #   (immediately renamed below)
        # 0de05d056afd (v5.17-rc8, renamed + added eIBRS+LFENCE case):
        #   "Vulnerable: Unprivileged eBPF enabled" -> "Vulnerable: eIBRS with unprivileged eBPF"
        #   + "Vulnerable: eIBRS+LFENCE with unprivileged eBPF and SMT"
        #
        # --- <ibpb> suffix (ibpb_state()) ---
        #
        # 20ffa1caecca (v4.16-rc1, initial IBPB):
        #   ", IBPB" (present/absent)
        # a8f76ae41cd6 (v4.20-rc5, extracted ibpb_state()):
        #   ", IBPB: disabled" | ", IBPB: always-on"
        # 7cc765a67d8e (v4.20-rc5, conditional IBPB):
        #   + ", IBPB: conditional"
        # 0cd01ac5dcb1 (v6.9-rc4, separator change):
        #   ", IBPB: ..." -> "; IBPB: ..."
        #
        # --- <ibrs_fw> suffix ---
        #
        # dd84441a7971 (v4.16-rc4):
        #   ", IBRS_FW" (present/absent)
        # 0cd01ac5dcb1 (v6.9-rc4, separator change):
        #   ", IBRS_FW" -> "; IBRS_FW"
        #
        # --- <stibp> suffix (stibp_state()) ---
        #
        # 53c613fe6349 (v4.20-rc1, initial STIBP):
        #   ", STIBP" (present/absent)
        # a8f76ae41cd6 (v4.20-rc5, extracted stibp_state()):
        #   ", STIBP: disabled" | ", STIBP: forced"
        # 9137bb27e60e (v4.20-rc5, added prctl):
        #   + ", STIBP: conditional" (when prctl/seccomp + switch_to_cond_stibp)
        # 20c3a2c33e9f (v5.0-rc1, added always-on preferred):
        #   + ", STIBP: always-on"
        # 34bce7c9690b (v4.20-rc5, eIBRS suppresses STIBP):
        #   returns "" when eIBRS is in use
        # fd470a8beed8 (v6.5-rc4, AutoIBRS exception):
        #   returns "" only when eIBRS AND not AutoIBRS (AutoIBRS shows STIBP)
        # 0cd01ac5dcb1 (v6.9-rc4, separator change):
        #   ", STIBP: ..." -> "; STIBP: ..."
        #
        # --- <rsb> suffix ---
        #
        # bb4b3b776273 (v4.20-rc1):
        #   ", RSB filling" (present/absent)
        # 53c613fe6349 (v4.20-rc1, temporarily removed, re-added in a8f76ae41cd6)
        # 0cd01ac5dcb1 (v6.9-rc4, separator change):
        #   ", RSB filling" -> "; RSB filling"
        #
        # --- <pbrsb> suffix (pbrsb_eibrs_state()) ---
        #
        # 2b1299322016 (v6.0-rc1):
        #   ", PBRSB-eIBRS: Not affected" | ", PBRSB-eIBRS: SW sequence" | ", PBRSB-eIBRS: Vulnerable"
        # 0cd01ac5dcb1 (v6.9-rc4, separator change):
        #   ", PBRSB-eIBRS: ..." -> "; PBRSB-eIBRS: ..."
        #
        # --- <bhi> suffix (spectre_bhi_state()) ---
        #
        # ec9404e40e8f (v6.9-rc4):
        #   "; BHI: Not affected" | "; BHI: BHI_DIS_S" | "; BHI: SW loop, KVM: SW loop"
        #   | "; BHI: Retpoline" | "; BHI: Vulnerable"
        # 95a6ccbdc719 (v6.9-rc4, KVM default):
        #   + "; BHI: Vulnerable, KVM: SW loop"
        # 5f882f3b0a8b (v6.9-rc4, clarified syscall hardening):
        #   removed "; BHI: Vulnerable (Syscall hardening enabled)"
        #   removed "; BHI: Syscall hardening, KVM: SW loop"
        #   (both replaced by "; BHI: Vulnerable" / "; BHI: Vulnerable, KVM: SW loop")
        #
        # --- <module> suffix (spectre_v2_module_string()) ---
        #
        # caf7501a1b4e (v4.16-rc1):
        #   " - vulnerable module loaded" (present/absent)
        #
        # --- stable backports ---
        #
        # 3.2.y: old-style base strings ("Full generic/AMD retpoline", "Minimal generic/AMD
        #   ASM retpoline"). Suffixes: ", IBPB" only (no STIBP/IBRS_FW/RSB). Format: %s%s\n.
        #   Has "Mitigation: Enhanced IBRS" (no "/ Automatic") in later releases.
        # 3.16.y, 4.4.y: old-style base strings. ibpb_state()/stibp_state()/IBRS_FW/RSB filling.
        #   3.16.y lacks STIBP "always-on". Comma separators.
        #   Both have "Mitigation: Enhanced IBRS" (no "/ Automatic"). No LFENCE/EIBRS modes.
        # 4.9.y: has spectre_v2_show_state() with LFENCE override ("Vulnerable: LFENCE"),
        #   eIBRS+eBPF overrides. "Mitigation: Enhanced IBRS" (no "/ Automatic").
        #   No SPECTRE_V2_IBRS. No pbrsb or BHI. Comma separators.
        # 4.14.y: like 4.9.y but also has SPECTRE_V2_IBRS and pbrsb_eibrs_state().
        #   "Mitigation: Enhanced IBRS" (no "/ Automatic"). No BHI. Comma separators.
        # 4.19.y: like 4.14.y but has "Enhanced / Automatic IBRS". No BHI. Comma separators.
        # 5.4.y, 5.10.y: like 4.19.y. No BHI. Comma separators.
        # 5.15.y, 6.1.y, 6.6.y, 6.12.y: match mainline (semicolons, BHI, all fields).
        #
        # --- Red Hat / CentOS / Rocky kernels ---
        #
        # Red Hat kernels carry their own spectre_v2 mitigation implementation that differs
        # significantly from mainline. The following strings are unique to Red Hat kernels:
        #
        # centos6 (RHEL 6, kernel 2.6.32): base strings are a superset of mainline v4.15:
        #   "Vulnerable: Minimal ASM retpoline"         (no "generic" qualifier)
        #   "Vulnerable: Minimal AMD ASM retpoline"
        #   "Vulnerable: Retpoline without IBPB"
        #   "Vulnerable: Retpoline on Skylake+"          (removed in later centos6 releases)
        #   "Vulnerable: Retpoline with unsafe module(s)"
        #   "Mitigation: Full AMD retpoline"
        #   "Mitigation: Full retpoline"                 (no "generic" qualifier)
        #   "Mitigation: Full retpoline and IBRS (user space)"
        #   "Mitigation: IBRS (kernel)"
        #   "Mitigation: IBRS (kernel and user space)"
        #   "Mitigation: IBP disabled"
        #   Suffixes: ", IBPB" only. Format: %s%s\n.
        #
        # centos7 (RHEL 7, kernel 3.10): early releases have all centos6 strings plus
        #   "Vulnerable: Retpoline on Skylake+". Later releases removed Skylake+ and
        #   Minimal AMD, and changed AMD retpoline to:
        #   "Vulnerable: AMD retpoline (LFENCE/JMP)"
        #   Added "Mitigation: Enhanced IBRS". Suffixes: ibpb_state() + stibp_state()
        #   with simple ", IBPB" / ", STIBP" strings. No IBRS_FW/RSB/pbrsb/BHI.
        #
        # centos8 (RHEL 8, kernel 4.18): uses mainline v5.17+ style enum names
        #   (RETPOLINE/LFENCE/EIBRS) but retains RHEL-specific entries:
        #   "Mitigation: IBRS (kernel)"                  (SPECTRE_V2_IBRS)
        #   "Mitigation: Full retpoline and IBRS (user space)" (SPECTRE_V2_RETPOLINE_IBRS_USER)
        #   "Mitigation: IBRS (kernel and user space)"   (SPECTRE_V2_IBRS_ALWAYS)
        #   "Mitigation: Enhanced IBRS" (no "/ Automatic"). spectre_v2_show_state() with
        #   LFENCE/eIBRS+eBPF overrides. Comma separators. No pbrsb/BHI.
        #
        # rocky9 (RHEL 9, kernel 5.14): matches mainline. Semicolons, BHI, all fields.
        # rocky10 (RHEL 10, kernel 6.12): matches mainline.
        #
        #
        # --- Kconfig symbols ---
        # 76b043848fd2 (v4.15-rc8): CONFIG_RETPOLINE
        # f43b9876e857 (v5.19-rc7): CONFIG_CPU_IBRS_ENTRY (kernel IBRS on entry)
        # aefb2f2e619b (v6.9-rc1): renamed CONFIG_RETPOLINE => CONFIG_MITIGATION_RETPOLINE
        # 1da8d2172ce5 (v6.9-rc1): renamed CONFIG_CPU_IBRS_ENTRY => CONFIG_MITIGATION_IBRS_ENTRY
        # ec9404e40e8f (v6.9-rc4): CONFIG_SPECTRE_BHI_ON / CONFIG_SPECTRE_BHI_OFF
        # 4f511739c54b (v6.9-rc4): replaced by CONFIG_MITIGATION_SPECTRE_BHI
        # 72c70f480a70 (v6.12-rc1): CONFIG_MITIGATION_SPECTRE_V2 (top-level on/off)
        # 8754e67ad4ac (v6.15-rc7): CONFIG_MITIGATION_ITS (indirect target selection)
        # stable 5.4.y-6.6.y: CONFIG_RETPOLINE (pre-rename)
        # stable 6.12.y: CONFIG_MITIGATION_RETPOLINE, CONFIG_MITIGATION_SPECTRE_V2
        #
        # --- kernel functions (for $opt_map / System.map) ---
        # da285121560e (v4.15-rc8): spectre_v2_select_mitigation(),
        #   spectre_v2_parse_cmdline(), nospectre_v2_parse_cmdline()
        # 20ffa1caecca (v4.16-rc1): spectre_v2_module_string(), retpoline_module_ok()
        # a8f76ae41cd6 (v4.20-rc5): spectre_v2_user_select_mitigation(),
        #   spectre_v2_user_parse_cmdline()
        # 7c693f54c873 (v5.19-rc7): spectre_v2_in_ibrs_mode(), spectre_v2_in_eibrs_mode()
        # 44a3918c8245 (v5.17-rc8): spectre_v2_show_state()
        # 480e803dacf8 (v6.16-rc1): split into spectre_v2_select_mitigation() +
        #   spectre_v2_apply_mitigation() + spectre_v2_update_mitigation() +
        #   spectre_v2_user_apply_mitigation() + spectre_v2_user_update_mitigation()
        #
        # --- CPU affection logic (for is_cpu_affected) ---
        # X86_BUG_SPECTRE_V2 is set for ALL x86 CPUs except:
        #   - CPUs matching NO_SPECULATION: family 4 (all vendors), Centaur/Intel/NSC/Vortex
        #     family 5, Intel Atom Bonnell/Saltwell
        #   - CPUs matching NO_SPECTRE_V2: Centaur family 7, Zhaoxin family 7
        # 99c6fa2511d8 (v4.15-rc8): unconditional for all x86 CPUs
        # 1e41a766c98b (v5.6-rc1): added NO_SPECTRE_V2 exemption for Centaur/Zhaoxin
        # 98c7a713db91 (v6.15-rc1): added X86_BUG_SPECTRE_V2_USER as separate bit
        # No MSR/CPUID immunity bits — purely whitelist-based.
        # vendor scope: all x86 vendors affected (Intel, AMD, Hygon, etc.)
        #   except Centaur family 7 and Zhaoxin family 7.
        #
        # all messages start with either "Not affected", "Mitigation", or "Vulnerable"
    fi
    if [ "$opt_sysfs_only" != 1 ]; then
        check_has_vmm

        v2_base_mode=''
        v2_stibp_status=''
        v2_pbrsb_status=''
        v2_bhi_status=''
        v2_ibpb_mode=''
        v2_vuln_module=''
        v2_is_autoibrs=0

        pr_info "* Mitigation 1"

        g_ibrs_can_tell=0
        g_ibrs_supported=''
        g_ibrs_enabled=''
        g_ibpb_can_tell=0
        g_ibpb_supported=''
        g_ibpb_enabled=''

        if [ "$opt_live" = 1 ]; then
            # in live mode, we can check for the ibrs_enabled file in debugfs
            # all versions of the patches have it (NOT the case of IBPB or KPTI)
            g_ibrs_can_tell=1
            mount_debugfs
            for dir in \
                $DEBUGFS_BASE \
                $DEBUGFS_BASE/x86 \
                "$g_procfs/sys/kernel"; do
                if [ -e "$dir/ibrs_enabled" ]; then
                    # if the file is there, we have IBRS compiled-in
                    # $DEBUGFS_BASE/ibrs_enabled: vanilla
                    # $DEBUGFS_BASE/x86/ibrs_enabled: Red Hat (see https://access.redhat.com/articles/3311301)
                    # /proc/sys/kernel/ibrs_enabled: OpenSUSE tumbleweed
                    g_specex_knob_dir=$dir
                    g_ibrs_supported="$dir/ibrs_enabled exists"
                    g_ibrs_enabled=$(cat "$dir/ibrs_enabled" 2>/dev/null)
                    pr_debug "ibrs: found $dir/ibrs_enabled=$g_ibrs_enabled"
                    # if ibrs_enabled is there, ibpb_enabled will be in the same dir
                    if [ -e "$dir/ibpb_enabled" ]; then
                        # if the file is there, we have IBPB compiled-in (see note above for IBRS)
                        g_ibpb_supported="$dir/ibpb_enabled exists"
                        g_ibpb_enabled=$(cat "$dir/ibpb_enabled" 2>/dev/null)
                        pr_debug "ibpb: found $dir/ibpb_enabled=$g_ibpb_enabled"
                    else
                        pr_debug "ibpb: $dir/ibpb_enabled file doesn't exist"
                    fi
                    break
                else
                    pr_debug "ibrs: $dir/ibrs_enabled file doesn't exist"
                fi
            done
            # on some newer kernels, the spec_ctrl_ibrs flag in "$g_procfs/cpuinfo"
            # is set when ibrs has been administratively enabled (usually from cmdline)
            # which in that case means ibrs is supported *and* enabled for kernel & user
            # as per the ibrs patch series v3
            if [ -z "$g_ibrs_supported" ]; then
                if grep ^flags "$g_procfs/cpuinfo" | grep -qw spec_ctrl_ibrs; then
                    pr_debug "ibrs: found spec_ctrl_ibrs flag in $g_procfs/cpuinfo"
                    g_ibrs_supported="spec_ctrl_ibrs flag in $g_procfs/cpuinfo"
                    # enabled=2 -> kernel & user
                    g_ibrs_enabled=2
                    # XXX and what about ibpb ?
                fi
            fi
            if [ -n "$ret_sys_interface_check_fullmsg" ]; then
                # when IBPB is enabled on 4.15+, we can see it in sysfs
                if echo "$ret_sys_interface_check_fullmsg" | grep -q 'IBPB'; then
                    pr_debug "ibpb: found enabled in sysfs"
                    [ -z "$g_ibpb_supported" ] && g_ibpb_supported='IBPB found enabled in sysfs'
                    [ -z "$g_ibpb_enabled" ] && g_ibpb_enabled=1
                fi
                # when IBRS_FW is enabled on 4.15+, we can see it in sysfs
                if echo "$ret_sys_interface_check_fullmsg" | grep -q '[,;] IBRS_FW'; then
                    pr_debug "ibrs: found IBRS_FW in sysfs"
                    [ -z "$g_ibrs_supported" ] && g_ibrs_supported='found IBRS_FW in sysfs'
                    g_ibrs_fw_enabled=1
                fi
                # when IBRS is enabled on 4.15+, we can see it in sysfs
                # on a more recent kernel, classic "IBRS" is not even longer an option, because of the performance impact.
                # only "Enhanced IBRS" is available (on CPUs with the IBRS_ALL flag)
                if echo "$ret_sys_interface_check_fullmsg" | grep -q -e '\<IBRS\>' -e 'Indirect Branch Restricted Speculation'; then
                    pr_debug "ibrs: found IBRS in sysfs"
                    [ -z "$g_ibrs_supported" ] && g_ibrs_supported='found IBRS in sysfs'
                    [ -z "$g_ibrs_enabled" ] && g_ibrs_enabled=3
                fi
                # checking for 'Enhanced IBRS' in sysfs, enabled on CPUs with IBRS_ALL
                if echo "$ret_sys_interface_check_fullmsg" | grep -q -e 'Enhanced IBRS'; then
                    [ -z "$g_ibrs_supported" ] && g_ibrs_supported='found Enhanced IBRS in sysfs'
                    # 4 isn't actually a valid value of the now extinct "g_ibrs_enabled" flag file,
                    # that only went from 0 to 3, so we use 4 as "enhanced ibrs is enabled"
                    g_ibrs_enabled=4
                fi
            fi
            # in live mode, if ibrs or ibpb is supported and we didn't find these are enabled, then they are not
            [ -n "$g_ibrs_supported" ] && [ -z "$g_ibrs_enabled" ] && g_ibrs_enabled=0
            [ -n "$g_ibpb_supported" ] && [ -z "$g_ibpb_enabled" ] && g_ibpb_enabled=0
        fi
        if [ -z "$g_ibrs_supported" ]; then
            check_redhat_canonical_spectre
            if [ "$g_redhat_canonical_spectre" = 1 ]; then
                g_ibrs_supported="Red Hat/Ubuntu variant"
                g_ibpb_supported="Red Hat/Ubuntu variant"
            fi
        fi
        if [ -z "$g_ibrs_supported" ] && [ -n "$g_kernel" ]; then
            if ! command -v "${opt_arch_prefix}strings" >/dev/null 2>&1; then
                :
            else
                g_ibrs_can_tell=1
                g_ibrs_supported=$("${opt_arch_prefix}strings" "$g_kernel" | grep -Fw -e '[,;] IBRS_FW' | head -n1)
                if [ -n "$g_ibrs_supported" ]; then
                    pr_debug "ibrs: found ibrs evidence in kernel image ($g_ibrs_supported)"
                    g_ibrs_supported="found '$g_ibrs_supported' in kernel image"
                fi
            fi
        fi
        if [ -z "$g_ibrs_supported" ] && [ -n "$opt_map" ]; then
            g_ibrs_can_tell=1
            if grep -q spec_ctrl "$opt_map"; then
                g_ibrs_supported="found spec_ctrl in symbols file"
                pr_debug "ibrs: found '*spec_ctrl*' symbol in $opt_map"
            elif grep -q -e spectre_v2_select_mitigation -e spectre_v2_apply_mitigation "$opt_map"; then
                # spectre_v2_select_mitigation exists since v4.15; split into
                # spectre_v2_select_mitigation + spectre_v2_apply_mitigation in v6.16
                g_ibrs_supported="found spectre_v2 mitigation function in symbols file"
                pr_debug "ibrs: found spectre_v2_*_mitigation symbol in $opt_map"
            fi
        fi
        # CONFIG_CPU_IBRS_ENTRY (v5.19) / CONFIG_MITIGATION_IBRS_ENTRY (v6.9): kernel IBRS on entry
        if [ -z "$g_ibrs_supported" ] && [ -n "$opt_config" ] && [ -r "$opt_config" ]; then
            g_ibrs_can_tell=1
            if grep -q '^CONFIG_\(CPU_\|MITIGATION_\)IBRS_ENTRY=y' "$opt_config"; then
                g_ibrs_supported="CONFIG_CPU_IBRS_ENTRY/CONFIG_MITIGATION_IBRS_ENTRY found in kernel config"
                pr_debug "ibrs: found IBRS entry config option in $opt_config"
            fi
        fi
        # recent (4.15) vanilla kernels have IBPB but not IBRS, and without the debugfs tunables of Red Hat
        # we can detect it directly in the image
        if [ -z "$g_ibpb_supported" ] && [ -n "$g_kernel" ]; then
            if ! command -v "${opt_arch_prefix}strings" >/dev/null 2>&1; then
                :
            else
                g_ibpb_can_tell=1
                g_ibpb_supported=$("${opt_arch_prefix}strings" "$g_kernel" | grep -Fw -e 'ibpb' -e ', IBPB' | head -n1)
                if [ -n "$g_ibpb_supported" ]; then
                    pr_debug "ibpb: found ibpb evidence in kernel image ($g_ibpb_supported)"
                    g_ibpb_supported="found '$g_ibpb_supported' in kernel image"
                fi
            fi
        fi

        pr_info_nol "  * Kernel is compiled with IBRS support: "
        if [ -z "$g_ibrs_supported" ]; then
            if [ "$g_ibrs_can_tell" = 1 ]; then
                pstatus yellow NO
            else
                # problem obtaining/inspecting kernel or strings not installed, but if the later is true,
                # then readelf is not installed either (both in binutils) which makes the former true, so
                # either way g_kernel_err should be set
                pstatus yellow UNKNOWN "couldn't check ($g_kernel_err)"
            fi
        else
            if [ "$opt_verbose" -ge 2 ]; then
                pstatus green YES "$g_ibrs_supported"
            else
                pstatus green YES
            fi
        fi

        pr_info_nol "    * IBRS enabled and active: "
        if [ "$opt_live" = 1 ]; then
            if [ "$g_ibpb_enabled" = 2 ]; then
                # if ibpb=2, ibrs is forcefully=0
                pstatus blue NO "IBPB used instead of IBRS in all kernel entrypoints"
            else
                # 0 means disabled
                # 1 is enabled only for kernel space
                # 2 is enabled for kernel and user space
                # 3 is enabled
                # 4 is enhanced ibrs enabled
                case "$g_ibrs_enabled" in
                    0)
                        if [ "$g_ibrs_fw_enabled" = 1 ]; then
                            pstatus blue YES "for firmware code only"
                        else
                            pstatus yellow NO
                        fi
                        ;;
                    1) if [ "$g_ibrs_fw_enabled" = 1 ]; then pstatus green YES "for kernel space and firmware code"; else pstatus green YES "for kernel space"; fi ;;
                    2) if [ "$g_ibrs_fw_enabled" = 1 ]; then pstatus green YES "for kernel, user space, and firmware code"; else pstatus green YES "for both kernel and user space"; fi ;;
                    3) if [ "$g_ibrs_fw_enabled" = 1 ]; then pstatus green YES "for kernel and firmware code"; else pstatus green YES; fi ;;
                    4) pstatus green YES "Enhanced flavor, performance impact will be greatly reduced" ;;
                    *) if [ "$cap_ibrs" != 'SPEC_CTRL' ] && [ "$cap_ibrs" != 'IBRS_SUPPORT' ] && [ "$cap_spec_ctrl" != -1 ]; then
                        pstatus yellow NO
                        pr_debug "ibrs: known cpu not supporting SPEC-CTRL or IBRS"
                    else
                        pstatus yellow UNKNOWN
                    fi ;;
                esac
            fi
        else
            pstatus blue N/A "not testable in offline mode"
        fi

        pr_info_nol "  * Kernel is compiled with IBPB support: "
        if [ -z "$g_ibpb_supported" ]; then
            if [ "$g_ibpb_can_tell" = 1 ]; then
                pstatus yellow NO
            else
                # if we're in offline mode without System.map, we can't really know
                pstatus yellow UNKNOWN "in offline mode, we need the kernel image to be able to tell"
            fi
        else
            if [ "$opt_verbose" -ge 2 ]; then
                pstatus green YES "$g_ibpb_supported"
            else
                pstatus green YES
            fi
        fi

        pr_info_nol "    * IBPB enabled and active: "
        if [ "$opt_live" = 1 ]; then
            case "$g_ibpb_enabled" in
                "")
                    if [ "$g_ibrs_supported" = 1 ]; then
                        pstatus yellow UNKNOWN
                    else
                        pstatus yellow NO
                    fi
                    ;;
                0)
                    pstatus yellow NO
                    ;;
                1) pstatus green YES ;;
                2) pstatus green YES "IBPB used instead of IBRS in all kernel entrypoints" ;;
                *) pstatus yellow UNKNOWN ;;
            esac
        else
            pstatus blue N/A "not testable in offline mode"
        fi

        pr_info "* Mitigation 2"
        pr_info_nol "  * Kernel has branch predictor hardening (arm): "
        bp_harden_can_tell=0
        bp_harden=''
        if [ -r "$opt_config" ]; then
            bp_harden_can_tell=1
            bp_harden=$(grep -w 'CONFIG_HARDEN_BRANCH_PREDICTOR=y' "$opt_config")
            if [ -n "$bp_harden" ]; then
                pstatus green YES
                pr_debug "bp_harden: found '$bp_harden' in $opt_config"
            fi
        fi
        if [ -z "$bp_harden" ] && [ -n "$opt_map" ]; then
            bp_harden_can_tell=1
            bp_harden=$(grep -w bp_hardening_data "$opt_map")
            if [ -n "$bp_harden" ]; then
                pstatus green YES
                pr_debug "bp_harden: found '$bp_harden' in $opt_map"
            fi
        fi
        if [ -z "$bp_harden" ]; then
            if [ "$bp_harden_can_tell" = 1 ]; then
                pstatus yellow NO
            else
                pstatus yellow UNKNOWN
            fi
        fi

        pr_info_nol "  * Kernel compiled with retpoline option: "
        # We check the RETPOLINE kernel options
        retpoline=0
        if [ -r "$opt_config" ]; then
            if grep -q '^CONFIG_\(MITIGATION_\)\?RETPOLINE=y' "$opt_config"; then
                pstatus green YES
                retpoline=1
                # shellcheck disable=SC2046
                pr_debug 'retpoline: found '$(grep '^CONFIG_\(MITIGATION_\)\?RETPOLINE' "$opt_config")" in $opt_config"
            else
                pstatus yellow NO
            fi
        else
            pstatus yellow UNKNOWN "couldn't read your kernel configuration"
        fi

        if [ "$retpoline" = 1 ]; then
            # Now check if the compiler used to compile the kernel knows how to insert retpolines in generated asm
            # For gcc, this is -mindirect-branch=thunk-extern (detected by the kernel makefiles)
            # See gcc commit https://github.com/hjl-tools/gcc/commit/23b517d4a67c02d3ef80b6109218f2aadad7bd79
            # In latest retpoline LKML patches, the noretpoline_setup symbol exists only if CONFIG_MITIGATION_RETPOLINE is set
            # *AND* if the compiler is retpoline-compliant, so look for that symbol. The name of this kernel config
            # option before version 6.9-rc1 is CONFIG_RETPOLINE.
            #
            # if there is "retpoline" in the file and NOT "minimal", then it's full retpoline
            # (works for vanilla and Red Hat variants)
            #
            # since 5.15.28, this is now "Retpolines" as the implementation was switched to a generic one,
            # so we look for both "retpoline" and "retpolines"
            if [ "$opt_live" = 1 ] && [ -n "$ret_sys_interface_check_fullmsg" ]; then
                if echo "$ret_sys_interface_check_fullmsg" | grep -qwi -e retpoline -e retpolines; then
                    if echo "$ret_sys_interface_check_fullmsg" | grep -qwi minimal; then
                        retpoline_compiler=0
                        retpoline_compiler_reason="kernel reports minimal retpoline compilation"
                    else
                        retpoline_compiler=1
                        retpoline_compiler_reason="kernel reports full retpoline compilation"
                    fi
                fi
            elif [ -n "$opt_map" ]; then
                # look for the symbol
                if grep -qw noretpoline_setup "$opt_map"; then
                    retpoline_compiler=1
                    retpoline_compiler_reason="noretpoline_setup symbol found in System.map"
                fi
            elif [ -n "$g_kernel" ]; then
                # look for the symbol
                if command -v "${opt_arch_prefix}nm" >/dev/null 2>&1; then
                    # the proper way: use nm and look for the symbol
                    if "${opt_arch_prefix}nm" "$g_kernel" 2>/dev/null | grep -qw 'noretpoline_setup'; then
                        retpoline_compiler=1
                        retpoline_compiler_reason="noretpoline_setup found in kernel symbols"
                    fi
                elif grep -q noretpoline_setup "$g_kernel"; then
                    # if we don't have nm, nevermind, the symbol name is long enough to not have
                    # any false positive using good old grep directly on the binary
                    retpoline_compiler=1
                    retpoline_compiler_reason="noretpoline_setup found in kernel"
                fi
            fi
            if [ -n "$retpoline_compiler" ]; then
                pr_info_nol "    * Kernel compiled with a retpoline-aware compiler: "
                if [ "$retpoline_compiler" = 1 ]; then
                    if [ -n "$retpoline_compiler_reason" ]; then
                        pstatus green YES "$retpoline_compiler_reason"
                    else
                        pstatus green YES
                    fi
                else
                    if [ -n "$retpoline_compiler_reason" ]; then
                        pstatus red NO "$retpoline_compiler_reason"
                    else
                        pstatus red NO
                    fi
                fi
            fi
        fi

        # only Red Hat has a tunable to disable it on runtime
        retp_enabled=-1
        if [ "$opt_live" = 1 ]; then
            if [ -e "$g_specex_knob_dir/retp_enabled" ]; then
                retp_enabled=$(cat "$g_specex_knob_dir/retp_enabled" 2>/dev/null)
                pr_debug "retpoline: found $g_specex_knob_dir/retp_enabled=$retp_enabled"
                pr_info_nol "    * Retpoline is enabled: "
                if [ "$retp_enabled" = 1 ]; then
                    pstatus green YES
                else
                    pstatus yellow NO
                fi
            fi
        fi

        # only for information, in verbose mode
        if [ "$opt_verbose" -ge 2 ]; then
            pr_info_nol "    * Local gcc is retpoline-aware: "
            if command -v gcc >/dev/null 2>&1; then
                if [ -n "$(gcc -mindirect-branch=thunk-extern --version 2>&1 >/dev/null)" ]; then
                    pstatus blue NO
                else
                    pstatus green YES
                fi
            else
                pstatus blue NO "gcc is not installed"
            fi
        fi

        if is_vulnerable_to_empty_rsb || [ "$opt_verbose" -ge 2 ]; then
            pr_info_nol "  * Kernel supports RSB filling: "
            rsb_filling=0
            if [ "$opt_live" = 1 ] && [ "$opt_no_sysfs" != 1 ]; then
                # if we're live and we aren't denied looking into /sys, let's do it
                if echo "$ret_sys_interface_check_fullmsg" | grep -qw RSB; then
                    rsb_filling=1
                    pstatus green YES
                fi
            fi
            if [ "$rsb_filling" = 0 ]; then
                if [ -n "$g_kernel_err" ]; then
                    pstatus yellow UNKNOWN "couldn't check ($g_kernel_err)"
                else
                    if grep -qw -e 'Filling RSB on context switch' "$g_kernel"; then
                        rsb_filling=1
                        pstatus green YES
                    else
                        rsb_filling=0
                        pstatus yellow NO
                    fi
                fi
            fi
        fi

        # Mitigation 3: derive structured mitigation variables for the verdict.
        # These are set from sysfs fields (when available) with hardware fallbacks.
        pr_info "* Mitigation 3 (sub-mitigations)"

        # --- v2_base_mode: which base Spectre v2 mitigation is active ---
        pr_info_nol "  * Base Spectre v2 mitigation mode: "
        if [ -n "$ret_sys_interface_check_fullmsg" ]; then
            # Parse from sysfs (handle all mainline, stable, and RHEL variants)
            case "$ret_sys_interface_check_fullmsg" in
                *"Enhanced / Automatic IBRS + LFENCE"* | *"Enhanced IBRS + LFENCE"*) v2_base_mode=eibrs_lfence ;;
                *"Enhanced / Automatic IBRS + Retpolines"* | *"Enhanced IBRS + Retpolines"*) v2_base_mode=eibrs_retpoline ;;
                *"Enhanced / Automatic IBRS"* | *"Enhanced IBRS"*) v2_base_mode=eibrs ;;
                *"Mitigation: IBRS (kernel and user space)"*) v2_base_mode=ibrs ;;
                *"Mitigation: IBRS (kernel)"*) v2_base_mode=ibrs ;;
                *"Mitigation: IBRS"*) v2_base_mode=ibrs ;;
                *"Mitigation: Retpolines"* | *"Full generic retpoline"* | *"Full retpoline"* | *"Full AMD retpoline"*) v2_base_mode=retpoline ;;
                *"Vulnerable: LFENCE"* | *"Mitigation: LFENCE"*) v2_base_mode=lfence ;;
                *"Vulnerable"*) v2_base_mode=none ;;
                *) v2_base_mode=unknown ;;
            esac
        fi
        # Fallback to existing variables if sysfs didn't provide a base mode
        if [ -z "$v2_base_mode" ] || [ "$v2_base_mode" = "unknown" ]; then
            if [ "$g_ibrs_enabled" = 4 ]; then
                v2_base_mode=eibrs
            elif [ -n "$g_ibrs_enabled" ] && [ "$g_ibrs_enabled" -ge 1 ] 2>/dev/null; then
                v2_base_mode=ibrs
            elif [ "$retpoline" = 1 ] && [ "$retpoline_compiler" = 1 ]; then
                v2_base_mode=retpoline
            elif [ "$retpoline" = 1 ]; then
                v2_base_mode=retpoline
            fi
        fi
        case "$v2_base_mode" in
            eibrs) pstatus green "Enhanced / Automatic IBRS" ;;
            eibrs_lfence) pstatus green "Enhanced / Automatic IBRS + LFENCE" ;;
            eibrs_retpoline) pstatus green "Enhanced / Automatic IBRS + Retpolines" ;;
            ibrs) pstatus green "IBRS" ;;
            retpoline) pstatus green "Retpolines" ;;
            lfence) pstatus red "LFENCE (insufficient)" ;;
            none) pstatus yellow "None" ;;
            *) pstatus yellow UNKNOWN ;;
        esac

        # --- v2_is_autoibrs: AMD AutoIBRS vs Intel eIBRS ---
        case "$v2_base_mode" in
            eibrs | eibrs_lfence | eibrs_retpoline)
                if [ "$cap_autoibrs" = 1 ] || { (is_amd || is_hygon) && [ "$cap_ibrs_all" != 1 ]; }; then
                    v2_is_autoibrs=1
                fi
                ;;
        esac

        # --- v2_ibpb_mode ---
        pr_info_nol "  * IBPB mode: "
        if [ -n "$ret_sys_interface_check_fullmsg" ]; then
            case "$ret_sys_interface_check_fullmsg" in
                *"IBPB: always-on"*) v2_ibpb_mode=always-on ;;
                *"IBPB: conditional"*) v2_ibpb_mode=conditional ;;
                *"IBPB: disabled"*) v2_ibpb_mode=disabled ;;
                *", IBPB"* | *"; IBPB"*) v2_ibpb_mode=conditional ;;
                *) v2_ibpb_mode=disabled ;;
            esac
        elif [ "$opt_live" = 1 ]; then
            case "$g_ibpb_enabled" in
                2) v2_ibpb_mode=always-on ;;
                1) v2_ibpb_mode=conditional ;;
                0) v2_ibpb_mode=disabled ;;
                *) v2_ibpb_mode=unknown ;;
            esac
        else
            v2_ibpb_mode=unknown
        fi
        case "$v2_ibpb_mode" in
            always-on) pstatus green YES "always-on" ;;
            conditional) pstatus green YES "conditional" ;;
            disabled) pstatus yellow NO "disabled" ;;
            *) pstatus yellow UNKNOWN ;;
        esac

        # --- SMT state (used in STIBP inference and verdict) ---
        is_cpu_smt_enabled
        smt_enabled=$?
        # smt_enabled: 0=enabled, 1=disabled, 2=unknown

        # --- v2_stibp_status ---
        pr_info_nol "  * STIBP status: "
        if [ -n "$ret_sys_interface_check_fullmsg" ]; then
            case "$ret_sys_interface_check_fullmsg" in
                *"STIBP: always-on"*) v2_stibp_status=always-on ;;
                *"STIBP: forced"*) v2_stibp_status=forced ;;
                *"STIBP: conditional"*) v2_stibp_status=conditional ;;
                *"STIBP: disabled"*) v2_stibp_status=disabled ;;
                *", STIBP"* | *"; STIBP"*) v2_stibp_status=forced ;;
                *)
                    # No STIBP field: Intel eIBRS suppresses it (implicit cross-thread protection)
                    case "$v2_base_mode" in
                        eibrs | eibrs_lfence | eibrs_retpoline)
                            if [ "$v2_is_autoibrs" != 1 ]; then
                                v2_stibp_status=eibrs-implicit
                            else
                                v2_stibp_status=unknown
                            fi
                            ;;
                        *) v2_stibp_status=unknown ;;
                    esac
                    ;;
            esac
        else
            # No sysfs: use hardware capability + context to infer STIBP status
            if [ "$smt_enabled" != 0 ]; then
                # SMT disabled or unknown: STIBP is not needed
                v2_stibp_status=not-needed
            else
                case "$v2_base_mode" in
                    eibrs | eibrs_lfence | eibrs_retpoline)
                        if [ "$v2_is_autoibrs" != 1 ]; then
                            # Intel eIBRS provides implicit cross-thread protection
                            v2_stibp_status=eibrs-implicit
                        elif [ -n "$cap_stibp" ]; then
                            # AMD AutoIBRS: CPU supports STIBP but can't confirm runtime state
                            v2_stibp_status=unknown
                        else
                            # No STIBP support on this CPU
                            v2_stibp_status=unavailable
                        fi
                        ;;
                    *)
                        if [ -n "$cap_stibp" ]; then
                            # CPU supports STIBP but can't confirm runtime state without sysfs
                            v2_stibp_status=unknown
                        else
                            # CPU does not support STIBP at all
                            v2_stibp_status=unavailable
                        fi
                        ;;
                esac
            fi
        fi
        case "$v2_stibp_status" in
            always-on) pstatus green YES "always-on" ;;
            forced) pstatus green YES "forced" ;;
            conditional) pstatus green YES "conditional" ;;
            eibrs-implicit) pstatus green YES "implicit via eIBRS" ;;
            not-needed) pstatus green YES "not needed (SMT disabled)" ;;
            unavailable) pstatus red NO "CPU does not support STIBP" ;;
            disabled) pstatus yellow NO "disabled" ;;
            *) pstatus yellow UNKNOWN ;;
        esac

        # --- v2_pbrsb_status (only relevant for eIBRS) ---
        case "$v2_base_mode" in
            eibrs | eibrs_lfence | eibrs_retpoline)
                pr_info_nol "  * PBRSB-eIBRS mitigation: "
                if [ -n "$ret_sys_interface_check_fullmsg" ]; then
                    case "$ret_sys_interface_check_fullmsg" in
                        *"PBRSB-eIBRS: Not affected"*) v2_pbrsb_status=not-affected ;;
                        *"PBRSB-eIBRS: SW sequence"*) v2_pbrsb_status=sw-sequence ;;
                        *"PBRSB-eIBRS: Vulnerable"*) v2_pbrsb_status=vulnerable ;;
                        *) v2_pbrsb_status=unknown ;;
                    esac
                elif [ "$opt_live" != 1 ] && [ -n "$g_kernel" ]; then
                    if grep -q 'PBRSB-eIBRS' "$g_kernel" 2>/dev/null; then
                        v2_pbrsb_status=sw-sequence
                    else
                        v2_pbrsb_status=unknown
                    fi
                else
                    v2_pbrsb_status=unknown
                fi
                case "$v2_pbrsb_status" in
                    not-affected) pstatus green "Not affected" ;;
                    sw-sequence) pstatus green "SW sequence" ;;
                    vulnerable) pstatus red "Vulnerable" ;;
                    *) pstatus yellow UNKNOWN ;;
                esac
                ;;
            *) v2_pbrsb_status=n/a ;;
        esac

        # --- v2_bhi_status ---
        pr_info_nol "  * BHI mitigation: "
        if [ -n "$ret_sys_interface_check_fullmsg" ]; then
            case "$ret_sys_interface_check_fullmsg" in
                *"BHI: Not affected"*) v2_bhi_status=not-affected ;;
                *"BHI: BHI_DIS_S"*) v2_bhi_status=bhi_dis_s ;;
                *"BHI: SW loop"*) v2_bhi_status=sw-loop ;;
                *"BHI: Retpoline"*) v2_bhi_status=retpoline ;;
                *"BHI: Vulnerable, KVM: SW loop"*) v2_bhi_status=vuln-kvm-loop ;;
                *"BHI: Vulnerable"*) v2_bhi_status=vulnerable ;;
                *) v2_bhi_status=unknown ;;
            esac
        elif [ "$opt_live" != 1 ] && [ -n "$opt_config" ] && [ -r "$opt_config" ]; then
            if grep -q '^CONFIG_\(MITIGATION_\)\?SPECTRE_BHI' "$opt_config"; then
                if [ "$cap_bhi" = 1 ]; then
                    v2_bhi_status=bhi_dis_s
                else
                    v2_bhi_status=sw-loop
                fi
            else
                v2_bhi_status=unknown
            fi
        else
            v2_bhi_status=unknown
        fi
        case "$v2_bhi_status" in
            not-affected) pstatus green "Not affected" ;;
            bhi_dis_s) pstatus green "BHI_DIS_S (hardware)" ;;
            sw-loop) pstatus green "SW loop" ;;
            retpoline) pstatus green "Retpoline" ;;
            vuln-kvm-loop) pstatus yellow "Vulnerable (KVM: SW loop)" ;;
            vulnerable) pstatus red "Vulnerable" ;;
            *) pstatus yellow UNKNOWN ;;
        esac

        # --- v2_vuln_module ---
        if [ "$opt_live" = 1 ] && [ -n "$ret_sys_interface_check_fullmsg" ]; then
            pr_info_nol "  * Non-retpoline module loaded: "
            if echo "$ret_sys_interface_check_fullmsg" | grep -q 'vulnerable module loaded'; then
                v2_vuln_module=1
                pstatus red YES
            else
                v2_vuln_module=0
                pstatus green NO
            fi
        fi

    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        if [ "$opt_sysfs_only" != 1 ]; then
            # --- own logic using Phase 2 variables ---
            # Helper: collect caveats for the verdict message
            _v2_caveats=''
            # Append a caveat string to the _v2_caveats list
            # Callers: check_CVE_2017_5715_linux (eIBRS, IBRS, retpoline verdict paths)
            _v2_add_caveat() { _v2_caveats="${_v2_caveats:+$_v2_caveats; }$1"; }

            # ARM branch predictor hardening (unchanged)
            if [ -n "$bp_harden" ]; then
                pvulnstatus "$cve" OK "Branch predictor hardening mitigates the vulnerability"
            elif [ -z "$bp_harden" ] && [ "$cpu_vendor" = ARM ]; then
                pvulnstatus "$cve" VULN "Branch predictor hardening is needed to mitigate the vulnerability"
                explain "Your kernel has not been compiled with the CONFIG_UNMAP_KERNEL_AT_EL0 option, recompile it with this option enabled."

            # LFENCE-only is always VULN (reclassified in v5.17)
            elif [ "$v2_base_mode" = "lfence" ]; then
                pvulnstatus "$cve" VULN "LFENCE alone is not a sufficient Spectre v2 mitigation"
                explain "LFENCE-based indirect branch mitigation was reclassified as vulnerable starting with Linux v5.17. Use retpoline (spectre_v2=retpoline) or IBRS-based mitigations (spectre_v2=eibrs or spectre_v2=ibrs) instead. If your CPU supports Enhanced IBRS, that is the preferred option."

            # eIBRS paths (eibrs / eibrs_lfence / eibrs_retpoline)
            elif [ "$v2_base_mode" = "eibrs" ] || [ "$v2_base_mode" = "eibrs_lfence" ] || [ "$v2_base_mode" = "eibrs_retpoline" ]; then
                _v2_caveats=''
                _v2_ok=1

                # BHI check: eIBRS alone doesn't protect against BHI
                if [ "$v2_bhi_status" = "vulnerable" ]; then
                    _v2_ok=0
                    _v2_add_caveat "BHI vulnerable"
                elif [ "$v2_bhi_status" = "unknown" ] && is_intel; then
                    if [ "$cap_bhi" = 0 ]; then
                        _v2_ok=0
                        _v2_add_caveat "BHI vulnerable (no BHI_DIS_S hardware support, no kernel mitigation detected)"
                    elif [ "$cap_rrsba" != 0 ]; then
                        _v2_add_caveat "BHI status unknown (kernel may lack BHI mitigation)"
                    fi
                fi

                # PBRSB check (only matters for VMM hosts)
                if [ "$v2_pbrsb_status" = "vulnerable" ]; then
                    if [ "$g_has_vmm" != 0 ] || [ "$opt_paranoid" = 1 ]; then
                        _v2_ok=0
                        _v2_add_caveat "PBRSB-eIBRS vulnerable"
                    fi
                fi

                # AutoIBRS: needs explicit STIBP (does NOT provide implicit cross-thread protection)
                if [ "$v2_is_autoibrs" = 1 ] && [ "$smt_enabled" = 0 ]; then
                    if [ "$v2_stibp_status" = "disabled" ] || [ "$v2_stibp_status" = "unavailable" ]; then
                        _v2_ok=0
                        _v2_add_caveat "STIBP not active with SMT on AMD AutoIBRS"
                    fi
                fi

                # Vulnerable module check
                if [ "$v2_vuln_module" = 1 ]; then
                    _v2_add_caveat "non-retpoline module loaded"
                fi

                # Paranoid mode
                if [ "$opt_paranoid" = 1 ]; then
                    if [ "$v2_ibpb_mode" != "always-on" ]; then
                        _v2_ok=0
                        _v2_add_caveat "IBPB not always-on"
                    fi
                    if [ "$smt_enabled" = 0 ]; then
                        _v2_ok=0
                        _v2_add_caveat "SMT enabled"
                    fi
                fi

                # eBPF caveat: eIBRS without retpoline is insufficient when unprivileged eBPF is enabled
                _ebpf_disabled=''
                if [ "$v2_base_mode" = "eibrs" ] || [ "$v2_base_mode" = "eibrs_lfence" ]; then
                    # shellcheck disable=SC2154
                    if [ -n "${SMC_MOCK_UNPRIVILEGED_BPF_DISABLED:-}" ]; then
                        _ebpf_disabled="$SMC_MOCK_UNPRIVILEGED_BPF_DISABLED"
                        g_mocked=1
                    elif [ "$opt_live" = 1 ] && [ -r "$g_procfs/sys/kernel/unprivileged_bpf_disabled" ]; then
                        _ebpf_disabled=$(cat "$g_procfs/sys/kernel/unprivileged_bpf_disabled" 2>/dev/null)
                        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_UNPRIVILEGED_BPF_DISABLED='$_ebpf_disabled'")
                    fi
                    # In paranoid mode, enabled unprivileged eBPF makes eIBRS insufficient
                    if [ "$_v2_ok" = 1 ] && [ "$_ebpf_disabled" = 0 ] && [ "$opt_paranoid" = 1 ]; then
                        _v2_ok=0
                        _v2_add_caveat "unprivileged eBPF enabled (eIBRS insufficient)"
                    fi
                fi

                # Build the base description
                case "$v2_base_mode" in
                    eibrs) _v2_desc="Enhanced / Automatic IBRS" ;;
                    eibrs_lfence) _v2_desc="Enhanced / Automatic IBRS + LFENCE" ;;
                    eibrs_retpoline) _v2_desc="Enhanced / Automatic IBRS + Retpolines" ;;
                esac

                if [ "$_v2_ok" = 1 ]; then
                    if [ -n "$_v2_caveats" ]; then
                        pvulnstatus "$cve" OK "$_v2_desc mitigates the vulnerability ($_v2_caveats)"
                    else
                        pvulnstatus "$cve" OK "$_v2_desc mitigates the vulnerability"
                    fi
                    if [ "$v2_base_mode" = "eibrs" ] || [ "$v2_base_mode" = "eibrs_lfence" ]; then
                        pr_info "    NOTE: eIBRS is considered vulnerable by the kernel when unprivileged eBPF is enabled."
                        if [ "$_ebpf_disabled" = 0 ]; then
                            pr_info "    Unprivileged eBPF is currently ENABLED (kernel.unprivileged_bpf_disabled=0): this system may be vulnerable!"
                        elif [ "$_ebpf_disabled" = 1 ] || [ "$_ebpf_disabled" = 2 ]; then
                            pr_info "    Unprivileged eBPF is currently disabled (kernel.unprivileged_bpf_disabled=$_ebpf_disabled): eIBRS is sufficient."
                        else
                            pr_info "    Could not read kernel.unprivileged_bpf_disabled, check it manually with \`sysctl kernel.unprivileged_bpf_disabled\`."
                        fi
                    fi
                else
                    pvulnstatus "$cve" VULN "$_v2_desc active but insufficient: $_v2_caveats"
                    explain "Your system uses $_v2_desc but has gaps in sub-mitigations: $_v2_caveats. Update your kernel and microcode to the latest versions. If BHI is vulnerable, a kernel with CONFIG_MITIGATION_SPECTRE_BHI or BHI_DIS_S microcode support is needed. If PBRSB-eIBRS is vulnerable, update the kernel for RSB VM exit mitigation. If STIBP is disabled on AMD AutoIBRS with SMT, add \`spectre_v2_user=on\` or disable SMT with \`nosmt\`. If unprivileged eBPF is enabled, disable it with \`sysctl -w kernel.unprivileged_bpf_disabled=1\`. In paranoid mode, disable SMT with \`nosmt\` and set \`spectre_v2_user=on\` for IBPB always-on."
                fi

            # Kernel IBRS path
            elif [ "$v2_base_mode" = "ibrs" ]; then
                _v2_caveats=''
                _v2_ok=1

                # IBRS needs IBPB for cross-process protection
                if [ "$v2_ibpb_mode" = "disabled" ]; then
                    _v2_ok=0
                    _v2_add_caveat "IBPB disabled"
                fi

                # IBRS needs STIBP or SMT-off for cross-thread protection
                if [ "$smt_enabled" = 0 ] && { [ "$v2_stibp_status" = "disabled" ] || [ "$v2_stibp_status" = "unavailable" ]; }; then
                    _v2_ok=0
                    _v2_add_caveat "STIBP not active with SMT enabled"
                fi

                # RSB filling on Skylake+
                if is_vulnerable_to_empty_rsb && [ "$rsb_filling" != 1 ]; then
                    _v2_ok=0
                    _v2_add_caveat "RSB filling missing on Skylake+"
                fi

                # BHI check
                if [ "$v2_bhi_status" = "vulnerable" ]; then
                    _v2_ok=0
                    _v2_add_caveat "BHI vulnerable"
                elif [ "$v2_bhi_status" = "unknown" ] && is_intel && [ "$cap_bhi" = 0 ]; then
                    _v2_ok=0
                    _v2_add_caveat "BHI vulnerable (no BHI_DIS_S hardware support, no kernel mitigation detected)"
                fi

                # Vulnerable module check
                if [ "$v2_vuln_module" = 1 ]; then
                    _v2_add_caveat "non-retpoline module loaded"
                fi

                # Paranoid mode
                if [ "$opt_paranoid" = 1 ]; then
                    if [ "$v2_ibpb_mode" != "always-on" ]; then
                        _v2_ok=0
                        _v2_add_caveat "IBPB not always-on"
                    fi
                    if [ "$smt_enabled" = 0 ]; then
                        _v2_ok=0
                        _v2_add_caveat "SMT enabled"
                    fi
                fi

                if [ "$_v2_ok" = 1 ]; then
                    pvulnstatus "$cve" OK "IBRS mitigates the vulnerability"
                else
                    pvulnstatus "$cve" VULN "IBRS active but insufficient: $_v2_caveats"
                    explain "Your system uses kernel IBRS but has gaps: $_v2_caveats. Ensure IBPB is enabled (spectre_v2_user=on or spectre_v2_user=prctl,ibpb). If STIBP is disabled with SMT, add spectre_v2_user=on or disable SMT with \`nosmt\`. If RSB filling is missing, update the kernel. If BHI is vulnerable, update kernel/microcode for BHI mitigation."
                fi

            # Retpoline path
            elif [ "$v2_base_mode" = "retpoline" ]; then
                _v2_caveats=''
                _v2_ok=1

                # Retpoline compiler check
                if [ "$retpoline_compiler" = 0 ]; then
                    _v2_ok=0
                    _v2_add_caveat "not compiled with retpoline-aware compiler"
                fi

                # Red Hat runtime disable check
                if [ "$retp_enabled" = 0 ]; then
                    _v2_ok=0
                    _v2_add_caveat "retpoline disabled at runtime"
                fi

                # RSB filling on Skylake+ (empty RSB falls back to BTB)
                if is_vulnerable_to_empty_rsb && [ "$rsb_filling" != 1 ]; then
                    _v2_ok=0
                    _v2_add_caveat "RSB filling missing on Skylake+"
                fi

                # BHI: retpoline only mitigates BHI if RRSBA is disabled
                if [ "$v2_bhi_status" = "vulnerable" ]; then
                    _v2_ok=0
                    _v2_add_caveat "BHI vulnerable"
                elif [ "$v2_bhi_status" = "unknown" ] && is_intel; then
                    if [ "$cap_bhi" = 0 ] && [ "$cap_rrsba" = 1 ]; then
                        _v2_ok=0
                        _v2_add_caveat "BHI vulnerable (no BHI_DIS_S hardware support, RRSBA bypasses retpoline)"
                    elif [ "$cap_rrsba" = 1 ]; then
                        _v2_add_caveat "BHI status unknown with RRSBA"
                    fi
                fi

                # Vulnerable module
                if [ "$v2_vuln_module" = 1 ]; then
                    _v2_ok=0
                    _v2_add_caveat "non-retpoline module loaded"
                fi

                # IBPB check: retpoline without IBPB is weaker
                if [ "$v2_ibpb_mode" = "disabled" ] || { [ -z "$g_ibpb_enabled" ] || [ "$g_ibpb_enabled" = 0 ]; }; then
                    if [ "$opt_paranoid" = 1 ]; then
                        _v2_ok=0
                        _v2_add_caveat "IBPB disabled"
                    else
                        _v2_add_caveat "IBPB disabled (recommended)"
                    fi
                fi

                # Paranoid mode: require SMT off, IBPB always-on
                if [ "$opt_paranoid" = 1 ]; then
                    if [ "$v2_ibpb_mode" != "always-on" ] && [ "$v2_ibpb_mode" != "disabled" ]; then
                        _v2_ok=0
                        _v2_add_caveat "IBPB not always-on"
                    fi
                    if [ "$smt_enabled" = 0 ]; then
                        _v2_ok=0
                        _v2_add_caveat "SMT enabled"
                    fi
                fi

                if [ "$_v2_ok" = 1 ]; then
                    if [ -n "$_v2_caveats" ]; then
                        pvulnstatus "$cve" OK "Retpolines mitigate the vulnerability ($_v2_caveats)"
                        if echo "$_v2_caveats" | grep -q 'IBPB'; then
                            if [ -n "$cap_ibpb" ]; then
                                pr_warn "You should enable IBPB to complete retpoline as a Variant 2 mitigation"
                            else
                                pr_warn "IBPB is considered as a good addition to retpoline for Variant 2 mitigation, but your CPU microcode doesn't support it"
                            fi
                        fi
                    else
                        pvulnstatus "$cve" OK "Retpolines + IBPB mitigate the vulnerability"
                    fi
                else
                    pvulnstatus "$cve" VULN "Retpoline active but insufficient: $_v2_caveats"
                    explain "Your system uses retpoline but has gaps: $_v2_caveats. Ensure the kernel was compiled with a retpoline-aware compiler. Enable IBPB (spectre_v2_user=on). If RSB filling is missing on Skylake+, update the kernel. If BHI is vulnerable, update kernel/microcode. In paranoid mode, disable SMT with \`nosmt\` and set \`spectre_v2_user=on\`."
                fi

            # Legacy fallback: IBRS+IBPB from debugfs on old systems without sysfs
            elif [ -n "$g_ibrs_enabled" ] && [ "$g_ibrs_enabled" -ge 1 ] 2>/dev/null && [ -n "$g_ibpb_enabled" ] && [ "$g_ibpb_enabled" -ge 1 ] 2>/dev/null; then
                if [ "$g_ibrs_enabled" = 4 ]; then
                    pvulnstatus "$cve" OK "Enhanced IBRS + IBPB are mitigating the vulnerability"
                else
                    pvulnstatus "$cve" OK "IBRS + IBPB are mitigating the vulnerability"
                fi
            elif [ "$g_ibpb_enabled" = 2 ] && [ "$smt_enabled" != 0 ]; then
                pvulnstatus "$cve" OK "Full IBPB is mitigating the vulnerability"

            # Offline mode fallback
            elif [ "$opt_live" != 1 ]; then
                if [ "$retpoline" = 1 ] && [ -n "$g_ibpb_supported" ]; then
                    pvulnstatus "$cve" OK "offline mode: kernel supports retpoline + IBPB to mitigate the vulnerability"
                elif [ -n "$g_ibrs_supported" ] && [ -n "$g_ibpb_supported" ]; then
                    pvulnstatus "$cve" OK "offline mode: kernel supports IBRS + IBPB to mitigate the vulnerability"
                elif [ "$cap_ibrs_all" = 1 ] || [ "$cap_autoibrs" = 1 ]; then
                    pvulnstatus "$cve" OK "offline mode: CPU supports Enhanced / Automatic IBRS"
                # CONFIG_MITIGATION_SPECTRE_V2 (v6.12+): top-level on/off for all Spectre V2 mitigations
                elif [ -n "$opt_config" ] && [ -r "$opt_config" ] && grep -q '^CONFIG_MITIGATION_SPECTRE_V2=y' "$opt_config"; then
                    pvulnstatus "$cve" OK "offline mode: kernel has Spectre V2 mitigation framework enabled (CONFIG_MITIGATION_SPECTRE_V2)"
                elif [ "$g_ibrs_can_tell" != 1 ]; then
                    pvulnstatus "$cve" UNK "offline mode: not enough information"
                    explain "Re-run this script with root privileges, and give it the kernel image (--kernel), the kernel configuration (--config) and the System.map file (--map) corresponding to the kernel you would like to inspect."
                fi
            fi

            # Catch-all: if no verdict was reached above, it's VULN
            if [ "$g_pvulnstatus_last_cve" != "$cve" ]; then
                if is_intel || is_amd || is_hygon; then
                    pvulnstatus "$cve" VULN "Your CPU is affected and no sufficient mitigation was detected"
                    explain "To mitigate this vulnerability, you need one of: (1) Enhanced IBRS / Automatic IBRS (eIBRS) -- requires CPU microcode support; preferred for modern CPUs. (2) Kernel IBRS (spectre_v2=ibrs) + IBPB -- requires IBRS-capable microcode. (3) Retpoline (spectre_v2=retpoline) + IBPB -- requires a retpoline-aware compiler and IBPB-capable microcode. For Skylake+ CPUs, options 1 or 2 are preferred as retpoline needs RSB filling. Update your kernel and CPU microcode to the latest versions."
                else
                    if [ "$sys_interface_available" = 1 ]; then
                        pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
                    else
                        pvulnstatus "$cve" VULN "no known mitigation exists for your CPU vendor ($cpu_vendor)"
                    fi
                fi
            fi
        else
            # --sysfs-only: Phase 2 variables are unset, fall back to the
            # raw sysfs result (status + fullmsg were set in Phase 1).
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
        fi
    else
        # msg was explicitly set by the "sysfs not available" elif above.
        pvulnstatus "$cve" "$status" "$msg"
    fi
}

# Sets: vulnstatus
check_CVE_2017_5715_bsd() {
    local ibrs_disabled ibrs_active retpoline nb_thunks
    pr_info "* Mitigation 1"
    pr_info_nol "  * Kernel supports IBRS: "
    ibrs_disabled=$(sysctl -n hw.ibrs_disable 2>/dev/null)
    if [ -z "$ibrs_disabled" ]; then
        pstatus yellow NO
    else
        pstatus green YES
    fi

    pr_info_nol "  * IBRS enabled and active: "
    ibrs_active=$(sysctl -n hw.ibrs_active 2>/dev/null)
    if [ "$ibrs_active" = 1 ]; then
        pstatus green YES
    else
        pstatus yellow NO
    fi

    pr_info "* Mitigation 2"
    pr_info_nol "  * Kernel compiled with RETPOLINE: "
    retpoline=0
    if [ -n "$g_kernel_err" ]; then
        pstatus yellow UNKNOWN "couldn't check ($g_kernel_err)"
    else
        if ! command -v "${opt_arch_prefix}readelf" >/dev/null 2>&1; then
            pstatus yellow UNKNOWN "missing '${opt_arch_prefix}readelf' tool, please install it, usually it's in the binutils package"
        else
            nb_thunks=$("${opt_arch_prefix}readelf" -s "$g_kernel" | grep -c -e __llvm_retpoline_ -e __llvm_external_retpoline_ -e __x86_indirect_thunk_)
            if [ "$nb_thunks" -gt 0 ]; then
                retpoline=1
                pstatus green YES "found $nb_thunks thunk(s)"
            else
                pstatus yellow NO
            fi
        fi
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ "$retpoline" = 1 ]; then
        pvulnstatus "$cve" OK "Retpoline mitigates the vulnerability"
    elif [ "$ibrs_active" = 1 ]; then
        pvulnstatus "$cve" OK "IBRS mitigates the vulnerability"
    elif [ "$ibrs_disabled" = 0 ]; then
        pvulnstatus "$cve" VULN "IBRS is supported by your kernel but your CPU microcode lacks support"
        explain "The microcode of your CPU needs to be upgraded to be able to use IBRS. Availability of a microcode update for you CPU model depends on your CPU vendor. You can usually find out online if a microcode update is available for your CPU by searching for your CPUID (indicated in the Hardware Check section). To do a microcode update, you can search the ports for the \`cpupdate\` tool. Microcode updates done this way are not reboot-proof, so be sure to do it every time the system boots up."
    elif [ "$ibrs_disabled" = 1 ]; then
        pvulnstatus "$cve" VULN "IBRS is supported but administratively disabled on your system"
        explain "To enable IBRS, use \`sysctl hw.ibrs_disable=0\`"
    else
        pvulnstatus "$cve" VULN "IBRS is needed to mitigate the vulnerability but your kernel is missing support"
        explain "You need to either upgrade your kernel or recompile yourself a more recent version having IBRS support"
    fi
}

# >>>>>> vulns/CVE-2017-5753.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2017-5753, Spectre V1, Bounds Check Bypass

# Sets: (none directly, delegates to check_cve)
check_CVE_2017_5753() {
    check_cve 'CVE-2017-5753'
}

# Sets: g_redhat_canonical_spectre (via check_redhat_canonical_spectre)
check_CVE_2017_5753_linux() {
    local status sys_interface_available msg v1_kernel_mitigated v1_kernel_mitigated_err v1_mask_nospec ret explain_text
    status=UNK
    sys_interface_available=0
    msg=''
    if sys_interface_check "$VULN_SYSFS_BASE/spectre_v1"; then
        # this kernel has the /sys interface, trust it over everything
        # v0.33+: don't. some kernels have backported the array_index_mask_nospec() workaround without
        # modifying the vulnerabilities/spectre_v1 file. that's bad. we can't trust it when it says Vulnerable :(
        # see "silent backport" detection at the bottom of this func
        sys_interface_available=1
        #
        # Complete sysfs message inventory for spectre_v1, traced via git blame:
        #
        # all versions:
        #   "Not affected"                                                              (cpu_show_common, pre-existing)
        #
        # --- x86 mainline ---
        # 61dc0f555b5c (v4.15, initial spectre_v1 sysfs):
        #   "Vulnerable"
        # edfbae53dab8 (v4.16, report get_user mitigation):
        #   "Mitigation: __user pointer sanitization"
        # a2059825986a (v5.3, swapgs awareness via spectre_v1_strings[]):
        #   "Vulnerable: __user pointer sanitization and usercopy barriers only; no swapgs barriers"
        #   "Mitigation: usercopy/swapgs barriers and __user pointer sanitization"
        # ca01c0d8d030 (v6.12, CONFIG_MITIGATION_SPECTRE_V1 controls default):
        #   same strings as v5.3+
        # All stable branches (4.4.y through 6.12.y) have v5.3+ strings backported.
        #
        # --- x86 RHEL (centos6, centos7 branches) ---
        #   "Vulnerable: Load fences, __user pointer sanitization and usercopy barriers only; no swapgs barriers"
        #   "Mitigation: Load fences, usercopy/swapgs barriers and __user pointer sanitization"
        #
        # --- ARM64 ---
        # 3891ebccace1 (v5.2, first arm64 spectre_v1 sysfs, backported to 4.14.y+):
        #   "Mitigation: __user pointer sanitization"                                   (hardcoded)
        # 455697adefdb (v5.10, moved to proton-pack.c):
        #   same string
        # Before v5.2: no sysfs override (generic "Not affected" fallback).
        # Actual mitigation (array_index_mask_nospec with CSDB) landed in v4.16.
        #
        # --- ARM32 ---
        # 9dd78194a372 (v5.17+):
        #   "Mitigation: __user pointer sanitization"                                   (hardcoded)
        #
        # all messages start with either "Not affected", "Mitigation", or "Vulnerable"
        status=$ret_sys_interface_check_status
    fi
    if [ "$opt_sysfs_only" != 1 ]; then
        # no /sys interface (or offline mode), fallback to our own ways

        # Primary detection: grep for sysfs mitigation strings in the kernel binary.
        # The string "__user pointer sanitization" is present in all kernel versions
        # that have spectre_v1 sysfs support (x86 v4.16+, ARM64 v5.2+, ARM32 v5.17+),
        # including RHEL "Load fences" variants. This is cheap and works offline.
        pr_info_nol "* Kernel has spectre_v1 mitigation (kernel image): "
        v1_kernel_mitigated=''
        v1_kernel_mitigated_err=''
        if [ -n "$g_kernel_err" ]; then
            v1_kernel_mitigated_err="$g_kernel_err"
        elif grep -q '__user pointer sanitization' "$g_kernel"; then
            if grep -q 'usercopy/swapgs barriers' "$g_kernel"; then
                v1_kernel_mitigated="usercopy/swapgs barriers and target sanitization"
            elif grep -q 'Load fences' "$g_kernel"; then
                v1_kernel_mitigated="RHEL Load fences mitigation"
            else
                v1_kernel_mitigated="__user pointer sanitization"
            fi
        fi
        if [ -z "$v1_kernel_mitigated" ] && [ -r "$opt_config" ]; then
            if grep -q '^CONFIG_MITIGATION_SPECTRE_V1=y' "$opt_config"; then
                v1_kernel_mitigated="CONFIG_MITIGATION_SPECTRE_V1 found in kernel config"
            fi
        fi
        if [ -z "$v1_kernel_mitigated" ] && [ -n "$opt_map" ]; then
            if grep -q 'spectre_v1_select_mitigation' "$opt_map"; then
                v1_kernel_mitigated="found spectre_v1_select_mitigation in System.map"
            fi
        fi
        if [ -n "$v1_kernel_mitigated" ]; then
            pstatus green YES "$v1_kernel_mitigated"
        elif [ -n "$v1_kernel_mitigated_err" ]; then
            pstatus yellow UNKNOWN "couldn't check ($v1_kernel_mitigated_err)"
        else
            pstatus yellow NO
        fi

        # Fallback for v4.15-era kernels: binary pattern matching for array_index_mask_nospec().
        # The sysfs mitigation strings were not present in the kernel image until v4.16 (x86)
        # and v5.2 (ARM64), but the actual mitigation code landed in v4.15 (x86) and v4.16 (ARM64).
        # For offline analysis of these old kernels, match the specific instruction patterns.
        if [ -z "$v1_kernel_mitigated" ]; then
            pr_info_nol "* Kernel has array_index_mask_nospec (v4.15 binary pattern): "
            # vanilla: look for the Linus' mask aka array_index_mask_nospec()
            # that is inlined at least in raw_copy_from_user (__get_user_X symbols)
            #mov PER_CPU_VAR(current_task), %_ASM_DX
            #cmp TASK_addr_limit(%_ASM_DX),%_ASM_AX
            #jae bad_get_user
            # /* array_index_mask_nospec() are the 2 opcodes that follow */
            #+sbb %_ASM_DX, %_ASM_DX
            #+and %_ASM_DX, %_ASM_AX
            #ASM_STAC
            # x86 64bits: jae(0x0f 0x83 0x?? 0x?? 0x?? 0x??) sbb(0x48 0x19 0xd2) and(0x48 0x21 0xd0)
            # x86 32bits: cmp(0x3b 0x82 0x?? 0x?? 0x00 0x00) jae(0x73 0x??) sbb(0x19 0xd2) and(0x21 0xd0)
            #
            # arm32
            ##ifdef CONFIG_THUMB2_KERNEL
            ##define CSDB	".inst.w 0xf3af8014"
            ##else
            ##define CSDB	".inst	0xe320f014"     e320f014
            ##endif
            #asm volatile(
            #	"cmp	%1, %2\n"      e1500003
            #"	sbc	%0, %1, %1\n"  e0c03000
            #CSDB
            #: "=r" (mask)
            #: "r" (idx), "Ir" (sz)
            #: "cc");
            #
            # http://git.arm.linux.org.uk/cgit/linux-arm.git/commit/?h=spectre&id=a78d156587931a2c3b354534aa772febf6c9e855
            v1_mask_nospec=''
            if [ -n "$g_kernel_err" ]; then
                pstatus yellow UNKNOWN "couldn't check ($g_kernel_err)"
            elif ! command -v perl >/dev/null 2>&1; then
                pstatus yellow UNKNOWN "missing 'perl' binary, please install it"
            else
                perl -ne '/\x0f\x83....\x48\x19\xd2\x48\x21\xd0/ and $found++; END { exit($found ? 0 : 1) }' "$g_kernel"
                ret=$?
                if [ "$ret" -eq 0 ]; then
                    pstatus green YES "x86 64 bits array_index_mask_nospec()"
                    v1_mask_nospec="x86 64 bits array_index_mask_nospec"
                else
                    perl -ne '/\x3b\x82..\x00\x00\x73.\x19\xd2\x21\xd0/ and $found++; END { exit($found ? 0 : 1) }' "$g_kernel"
                    ret=$?
                    if [ "$ret" -eq 0 ]; then
                        pstatus green YES "x86 32 bits array_index_mask_nospec()"
                        v1_mask_nospec="x86 32 bits array_index_mask_nospec"
                    else
                        ret=$("${opt_arch_prefix}objdump" "$g_objdump_options" "$g_kernel" | grep -w -e f3af8014 -e e320f014 -B2 | grep -B1 -w sbc | grep -w -c cmp)
                        if [ "$ret" -gt 0 ]; then
                            pstatus green YES "$ret occurrence(s) found of arm 32 bits array_index_mask_nospec()"
                            v1_mask_nospec="arm 32 bits array_index_mask_nospec"
                        else
                            pstatus yellow NO
                        fi
                    fi
                fi
            fi
        fi

        pr_info_nol "* Kernel has the Red Hat/Ubuntu patch: "
        check_redhat_canonical_spectre
        if [ "$g_redhat_canonical_spectre" = -1 ]; then
            pstatus yellow UNKNOWN "missing '${opt_arch_prefix}strings' tool, please install it, usually it's in the binutils package"
        elif [ "$g_redhat_canonical_spectre" = -2 ]; then
            pstatus yellow UNKNOWN "couldn't check ($g_kernel_err)"
        elif [ "$g_redhat_canonical_spectre" = 1 ]; then
            pstatus green YES
        elif [ "$g_redhat_canonical_spectre" = 2 ]; then
            pstatus green YES "but without IBRS"
        else
            pstatus yellow NO
        fi

        pr_info_nol "* Kernel has mask_nospec64 (arm64): "
        #.macro	mask_nospec64, idx, limit, tmp
        #sub	\tmp, \idx, \limit
        #bic	\tmp, \tmp, \idx
        #and	\idx, \idx, \tmp, asr #63
        #csdb
        #.endm
        #$ aarch64-linux-gnu-objdump -d vmlinux | grep -w bic -A1 -B1 | grep -w sub -A2 | grep -w and -B2
        #ffffff8008082e44:       cb190353        sub     x19, x26, x25
        #ffffff8008082e48:       8a3a0273        bic     x19, x19, x26
        #ffffff8008082e4c:       8a93ff5a        and     x26, x26, x19, asr #63
        #ffffff8008082e50:       d503229f        hint    #0x14
        # /!\ can also just be "csdb" instead of "hint #0x14" for native objdump
        #
        # if we already have a detection, don't bother disassembling the kernel, the answer is no.
        if [ -n "$v1_kernel_mitigated" ] || [ -n "$v1_mask_nospec" ] || [ "$g_redhat_canonical_spectre" -gt 0 ]; then
            pstatus yellow NO
        elif [ -n "$g_kernel_err" ]; then
            pstatus yellow UNKNOWN "couldn't check ($g_kernel_err)"
        elif ! command -v perl >/dev/null 2>&1; then
            pstatus yellow UNKNOWN "missing 'perl' binary, please install it"
        elif ! command -v "${opt_arch_prefix}objdump" >/dev/null 2>&1; then
            pstatus yellow UNKNOWN "missing '${opt_arch_prefix}objdump' tool, please install it, usually it's in the binutils package"
        else
            "${opt_arch_prefix}objdump" "$g_objdump_options" "$g_kernel" | perl -ne 'push @r, $_; /\s(hint|csdb)\s/ && $r[0]=~/\ssub\s+(x\d+)/ && $r[1]=~/\sbic\s+$1,\s+$1,/ && $r[2]=~/\sand\s/ && exit(9); shift @r if @r>3'
            ret=$?
            if [ "$ret" -eq 9 ]; then
                pstatus green YES "mask_nospec64 macro is present and used"
                v1_mask_nospec="arm64 mask_nospec64"
            else
                pstatus yellow NO
            fi
        fi

        pr_info_nol "* Kernel has array_index_nospec (arm64): "
        # in 4.19+ kernels, the mask_nospec64 asm64 macro is replaced by array_index_nospec, defined in nospec.h, and used in invoke_syscall()
        # ffffff8008090a4c:       2a0203e2        mov     w2, w2
        # ffffff8008090a50:       eb0200bf        cmp     x5, x2
        # ffffff8008090a54:       da1f03e2        ngc     x2, xzr
        # ffffff8008090a58:       d503229f        hint    #0x14
        # /!\ can also just be "csdb" instead of "hint #0x14" for native objdump
        #
        # if we already have a detection, don't bother disassembling the kernel, the answer is no.
        if [ -n "$v1_kernel_mitigated" ] || [ -n "$v1_mask_nospec" ] || [ "$g_redhat_canonical_spectre" -gt 0 ]; then
            pstatus yellow NO
        elif [ -n "$g_kernel_err" ]; then
            pstatus yellow UNKNOWN "couldn't check ($g_kernel_err)"
        elif ! command -v perl >/dev/null 2>&1; then
            pstatus yellow UNKNOWN "missing 'perl' binary, please install it"
        elif ! command -v "${opt_arch_prefix}objdump" >/dev/null 2>&1; then
            pstatus yellow UNKNOWN "missing '${opt_arch_prefix}objdump' tool, please install it, usually it's in the binutils package"
        else
            "${opt_arch_prefix}objdump" "$g_objdump_options" "$g_kernel" | perl -ne 'push @r, $_; /\s(hint|csdb)\s/ && $r[0]=~/\smov\s+(w\d+),\s+(w\d+)/ && $r[1]=~/\scmp\s+(x\d+),\s+(x\d+)/ && $r[2]=~/\sngc\s+$2,/ && exit(9); shift @r if @r>3'
            ret=$?
            if [ "$ret" -eq 9 ]; then
                pstatus green YES "array_index_nospec macro is present and used"
                v1_mask_nospec="arm64 array_index_nospec"
            else
                pstatus yellow NO
            fi
        fi

    elif [ "$sys_interface_available" = 0 ]; then
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    # report status
    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ "$opt_sysfs_only" != 1 ]; then
            if [ -n "$v1_kernel_mitigated" ]; then
                pvulnstatus "$cve" OK "Kernel source has been patched to mitigate the vulnerability ($v1_kernel_mitigated)"
            elif [ -n "$v1_mask_nospec" ]; then
                pvulnstatus "$cve" OK "Kernel source has been patched to mitigate the vulnerability ($v1_mask_nospec)"
            elif [ "$g_redhat_canonical_spectre" = 1 ] || [ "$g_redhat_canonical_spectre" = 2 ]; then
                pvulnstatus "$cve" OK "Kernel source has been patched to mitigate the vulnerability (Red Hat/Ubuntu patch)"
            elif [ -n "$g_kernel_err" ]; then
                pvulnstatus "$cve" UNK "Couldn't find kernel image or tools missing to execute the checks"
                explain "Re-run this script with root privileges, after installing the missing tools indicated above"
            else
                pvulnstatus "$cve" VULN "Kernel source needs to be patched to mitigate the vulnerability"
                explain "Your kernel is too old to have the mitigation for Variant 1, you should upgrade to a newer kernel. If you're using a Linux distro and didn't compile the kernel yourself, you should upgrade your distro to get a newer kernel."
            fi
        else
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
        fi
    else
        if [ "$msg" = "Vulnerable" ] && { [ -n "$v1_kernel_mitigated" ] || [ -n "$v1_mask_nospec" ]; }; then
            pvulnstatus "$cve" OK "Kernel source has been patched to mitigate the vulnerability (silent backport of spectre_v1 mitigation)"
        else
            if [ "$msg" = "Vulnerable" ]; then
                msg="Kernel source needs to be patched to mitigate the vulnerability"
                explain_text="Your kernel is too old to have the mitigation for Variant 1, you should upgrade to a newer kernel. If you're using a Linux distro and didn't compile the kernel yourself, you should upgrade your distro to get a newer kernel."
            fi
            pvulnstatus "$cve" "$status" "$msg"
            [ -n "${explain_text:-}" ] && explain "$explain_text"
            unset explain_text
        fi
    fi
}

check_CVE_2017_5753_bsd() {
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
    fi
}

# >>>>>> vulns/CVE-2017-5754.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2017-5754, Meltdown, Rogue Data Cache Load

# no security impact but give a hint to the user in verbose mode
# about PCID/INVPCID cpuid features that must be present to avoid
# Check whether PCID/INVPCID are available to reduce PTI performance impact
# refs:
# https://marc.info/?t=151532047900001&r=1&w=2
# https://groups.google.com/forum/m/#!topic/mechanical-sympathy/L9mHTbeQLNU
pti_performance_check() {
    local ret pcid invpcid
    pr_info_nol "  * Reduced performance impact of PTI: "
    if [ -e "$g_procfs/cpuinfo" ] && grep ^flags "$g_procfs/cpuinfo" | grep -qw pcid; then
        pcid=1
    else
        read_cpuid 0x1 0x0 "$ECX" 17 1 1
        ret=$?
        if [ "$ret" = "$READ_CPUID_RET_OK" ]; then
            pcid=1
        fi
    fi

    if [ -e "$g_procfs/cpuinfo" ] && grep ^flags "$g_procfs/cpuinfo" | grep -qw invpcid; then
        invpcid=1
    else
        read_cpuid 0x7 0x0 "$EBX" 10 1 1
        ret=$?
        if [ "$ret" = "$READ_CPUID_RET_OK" ]; then
            invpcid=1
        fi
    fi

    if [ "$invpcid" = 1 ]; then
        pstatus green YES 'CPU supports INVPCID, performance impact of PTI will be greatly reduced'
    elif [ "$pcid" = 1 ]; then
        pstatus green YES 'CPU supports PCID, performance impact of PTI will be reduced'
    else
        pstatus blue NO 'PCID/INVPCID not supported, performance impact of PTI will be significant'
    fi
}

check_CVE_2017_5754() {
    check_cve 'CVE-2017-5754'
}

check_CVE_2017_5754_linux() {
    local status sys_interface_available msg kpti_support kpti_can_tell kpti_enabled dmesg_grep pti_xen_pv_domU xen_pv_domo xen_pv_domu explain_text
    status=UNK
    sys_interface_available=0
    msg=''
    if sys_interface_check "$VULN_SYSFS_BASE/meltdown"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        status=$ret_sys_interface_check_status
    fi
    if [ "$opt_sysfs_only" != 1 ]; then
        pr_info_nol "* Kernel supports Page Table Isolation (PTI): "
        kpti_support=''
        kpti_can_tell=0
        if [ -n "$opt_config" ]; then
            kpti_can_tell=1
            kpti_support=$(grep -E -w -e 'CONFIG_(MITIGATION_)?PAGE_TABLE_ISOLATION=y' -e CONFIG_KAISER=y -e CONFIG_UNMAP_KERNEL_AT_EL0=y "$opt_config")
            if [ -n "$kpti_support" ]; then
                pr_debug "kpti_support: found option '$kpti_support' in $opt_config"
            fi
        fi
        if [ -z "$kpti_support" ] && [ -n "$opt_map" ]; then
            # it's not an elif: some backports don't have the PTI config but still include the patch
            # so we try to find an exported symbol that is part of the PTI patch in System.map
            # parse_kpti: arm
            kpti_can_tell=1
            kpti_support=$(grep -w -e kpti_force_enabled -e parse_kpti "$opt_map")
            if [ -n "$kpti_support" ]; then
                pr_debug "kpti_support: found '$kpti_support' in $opt_map"
            fi
        fi
        if [ -z "$kpti_support" ] && [ -n "$g_kernel" ]; then
            # same as above but in case we don't have System.map and only kernel, look for the
            # nopti option that is part of the patch (kernel command line option)
            # 'kpti=': arm
            kpti_can_tell=1
            if ! command -v "${opt_arch_prefix}strings" >/dev/null 2>&1; then
                pstatus yellow UNKNOWN "missing '${opt_arch_prefix}strings' tool, please install it, usually it's in the binutils package"
            else
                kpti_support=$("${opt_arch_prefix}strings" "$g_kernel" | grep -w -e nopti -e kpti=)
                if [ -n "$kpti_support" ]; then
                    pr_debug "kpti_support: found '$kpti_support' in $g_kernel"
                fi
            fi
        fi

        if [ -n "$kpti_support" ]; then
            if [ "$opt_verbose" -ge 2 ]; then
                pstatus green YES "found '$kpti_support'"
            else
                pstatus green YES
            fi
        elif [ "$kpti_can_tell" = 1 ]; then
            pstatus yellow NO
        else
            pstatus yellow UNKNOWN "couldn't read your kernel configuration nor System.map file"
        fi

        mount_debugfs
        pr_info_nol "  * PTI enabled and active: "
        if [ "$opt_live" = 1 ]; then
            dmesg_grep="Kernel/User page tables isolation: enabled"
            dmesg_grep="$dmesg_grep|Kernel page table isolation enabled"
            dmesg_grep="$dmesg_grep|x86/pti: Unmapping kernel while in userspace"
            # aarch64
            dmesg_grep="$dmesg_grep|CPU features: detected( feature)?: Kernel page table isolation \(KPTI\)"
            if grep ^flags "$g_procfs/cpuinfo" | grep -qw pti; then
                # vanilla PTI patch sets the 'pti' flag in cpuinfo
                pr_debug "kpti_enabled: found 'pti' flag in $g_procfs/cpuinfo"
                kpti_enabled=1
            elif grep ^flags "$g_procfs/cpuinfo" | grep -qw kaiser; then
                # kernel line 4.9 sets the 'kaiser' flag in cpuinfo
                pr_debug "kpti_enabled: found 'kaiser' flag in $g_procfs/cpuinfo"
                kpti_enabled=1
            elif [ -e "$DEBUGFS_BASE/x86/pti_enabled" ]; then
                # Red Hat Backport creates a dedicated file, see https://access.redhat.com/articles/3311301
                kpti_enabled=$(cat "$DEBUGFS_BASE/x86/pti_enabled" 2>/dev/null)
                pr_debug "kpti_enabled: file $DEBUGFS_BASE/x86/pti_enabled exists and says: $kpti_enabled"
            elif is_xen_dom0; then
                pti_xen_pv_domU=$(xl dmesg 2>/dev/null | grep 'XPTI' | grep 'DomU enabled' | head -n1)

                [ -n "$pti_xen_pv_domU" ] && kpti_enabled=1
            fi
            if [ -z "$kpti_enabled" ]; then
                dmesg_grep "$dmesg_grep"
                ret=$?
                if [ "$ret" -eq 0 ]; then
                    pr_debug "kpti_enabled: found hint in dmesg: $ret_dmesg_grep_grepped"
                    kpti_enabled=1
                elif [ "$ret" -eq 2 ]; then
                    pr_debug "kpti_enabled: dmesg truncated"
                    kpti_enabled=-1
                fi
            fi
            if [ -z "$kpti_enabled" ]; then
                pr_debug "kpti_enabled: couldn't find any hint that PTI is enabled"
                kpti_enabled=0
            fi
            if [ "$kpti_enabled" = 1 ]; then
                pstatus green YES
            elif [ "$kpti_enabled" = -1 ]; then
                pstatus yellow UNKNOWN "dmesg truncated, please reboot and relaunch this script"
            else
                pstatus yellow NO
            fi
        else
            pstatus blue N/A "not testable in offline mode"
        fi

        pti_performance_check

    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    # Test if the current host is a Xen PV Dom0 / DomU
    xen_pv_domo=0
    xen_pv_domu=0
    is_xen_dom0 && xen_pv_domo=1
    is_xen_domU && xen_pv_domu=1

    if [ "$opt_live" = 1 ]; then
        # checking whether we're running under Xen PV 64 bits. If yes, we are affected by affected_variant3
        # (unless we are a Dom0)
        pr_info_nol "* Running as a Xen PV DomU: "
        if [ "$xen_pv_domu" = 1 ]; then
            pstatus yellow YES
        else
            pstatus blue NO
        fi
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ "$opt_live" = 1 ]; then
            if [ "$kpti_enabled" = 1 ]; then
                pvulnstatus "$cve" OK "PTI mitigates the vulnerability"
            elif [ "$xen_pv_domo" = 1 ]; then
                pvulnstatus "$cve" OK "Xen Dom0s are safe and do not require PTI"
            elif [ "$xen_pv_domu" = 1 ]; then
                pvulnstatus "$cve" VULN "Xen PV DomUs are vulnerable and need to be run in HVM, PVHVM, PVH mode, or the Xen hypervisor must have the Xen's own PTI patch"
                explain "Go to https://blog.xenproject.org/2018/01/22/xen-project-spectre-meltdown-faq-jan-22-update/ for more information"
            elif [ "$kpti_enabled" = -1 ]; then
                pvulnstatus "$cve" UNK "couldn't find any clue of PTI activation due to a truncated dmesg, please reboot and relaunch this script"
            else
                pvulnstatus "$cve" VULN "PTI is needed to mitigate the vulnerability"
                if [ -n "$kpti_support" ]; then
                    if [ -e "$DEBUGFS_BASE/x86/pti_enabled" ]; then
                        explain "Your kernel supports PTI but it's disabled, you can enable it with \`echo 1 > $DEBUGFS_BASE/x86/pti_enabled\`"
                    elif echo "$g_kernel_cmdline" | grep -q -w -e nopti -e pti=off; then
                        explain "Your kernel supports PTI but it has been disabled on command-line, remove the nopti or pti=off option from your bootloader configuration"
                    else
                        explain "Your kernel supports PTI but it has been disabled, check \`dmesg\` right after boot to find clues why the system disabled it"
                    fi
                else
                    explain "If you're using a distro kernel, upgrade your distro to get the latest kernel available. Otherwise, recompile the kernel with the CONFIG_(MITIGATION_)PAGE_TABLE_ISOLATION option (named CONFIG_KAISER for some kernels), or the CONFIG_UNMAP_KERNEL_AT_EL0 option (for ARM64)"
                fi
            fi
        else
            if [ -n "$kpti_support" ]; then
                pvulnstatus "$cve" OK "offline mode: PTI will mitigate the vulnerability if enabled at runtime"
            elif [ "$kpti_can_tell" = 1 ]; then
                pvulnstatus "$cve" VULN "PTI is needed to mitigate the vulnerability"
                explain "If you're using a distro kernel, upgrade your distro to get the latest kernel available. Otherwise, recompile the kernel with the CONFIG_(MITIGATION_)PAGE_TABLE_ISOLATION option (named CONFIG_KAISER for some kernels), or the CONFIG_UNMAP_KERNEL_AT_EL0 option (for ARM64)"
            else
                pvulnstatus "$cve" UNK "offline mode: not enough information"
                explain "Re-run this script with root privileges, and give it the kernel image (--kernel), the kernel configuration (--config) and the System.map file (--map) corresponding to the kernel you would like to inspect."
            fi
        fi
    else
        if [ "$xen_pv_domo" = 1 ]; then
            msg="Xen Dom0s are safe and do not require PTI"
            status="OK"
        elif [ "$xen_pv_domu" = 1 ]; then
            msg="Xen PV DomUs are vulnerable and need to be run in HVM, PVHVM, PVH mode, or the Xen hypervisor must have the Xen's own PTI patch"
            status="VULN"
            explain_text="Go to https://blog.xenproject.org/2018/01/22/xen-project-spectre-meltdown-faq-jan-22-update/ for more information"
        elif [ "$msg" = "Vulnerable" ]; then
            msg="PTI is needed to mitigate the vulnerability"
            explain_text="If you're using a distro kernel, upgrade your distro to get the latest kernel available. Otherwise, recompile the kernel with the CONFIG_(MITIGATION_)PAGE_TABLE_ISOLATION option (named CONFIG_KAISER for some kernels), or the CONFIG_UNMAP_KERNEL_AT_EL0 option (for ARM64)"
        fi
        pvulnstatus "$cve" "$status" "$msg"
        [ -z "${explain_text:-}" ] && [ "$msg" = "Vulnerable" ] && explain_text="If you're using a distro kernel, upgrade your distro to get the latest kernel available. Otherwise, recompile the kernel with the CONFIG_(MITIGATION_)PAGE_TABLE_ISOLATION option (named CONFIG_KAISER for some kernels), or the CONFIG_UNMAP_KERNEL_AT_EL0 option (for ARM64)"
        [ -n "${explain_text:-}" ] && explain "$explain_text"
        unset explain_text
    fi

    # Warn the user about XSA-254 recommended mitigations
    if [ "$xen_pv_domo" = 1 ]; then
        pr_warn
        pr_warn "This host is a Xen Dom0. Please make sure that you are running your DomUs"
        pr_warn "in HVM, PVHVM or PVH mode to prevent any guest-to-host / host-to-guest attacks."
        pr_warn
        pr_warn "See https://blog.xenproject.org/2018/01/22/xen-project-spectre-meltdown-faq-jan-22-update/ and XSA-254 for details."
    fi
}

check_CVE_2017_5754_bsd() {
    local kpti_enabled
    pr_info_nol "* Kernel supports Page Table Isolation (PTI): "
    kpti_enabled=$(sysctl -n vm.pmap.pti 2>/dev/null)
    if [ -z "$kpti_enabled" ]; then
        pstatus yellow NO
    else
        pstatus green YES
    fi

    pr_info_nol "  * PTI enabled and active: "
    if [ "$kpti_enabled" = 1 ]; then
        pstatus green YES
    else
        pstatus yellow NO
    fi

    pti_performance_check

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ "$kpti_enabled" = 1 ]; then
        pvulnstatus "$cve" OK "PTI mitigates the vulnerability"
    elif [ -n "$kpti_enabled" ]; then
        pvulnstatus "$cve" VULN "PTI is supported but disabled on your system"
    else
        pvulnstatus "$cve" VULN "PTI is needed to mitigate the vulnerability"
    fi
}

# >>>>>> vulns/CVE-2018-12126.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2018-12126, MSBDS, Fallout, Microarchitectural Store Buffer Data Sampling

check_CVE_2018_12126() {
    check_cve 'CVE-2018-12126' check_mds
}

# >>>>>> vulns/CVE-2018-12127.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2018-12127, MLPDS, RIDL, Microarchitectural Load Port Data Sampling

check_CVE_2018_12127() {
    check_cve 'CVE-2018-12127' check_mds
}

# >>>>>> vulns/CVE-2018-12130.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2018-12130, MFBDS, ZombieLoad, Microarchitectural Fill Buffer Data Sampling

check_CVE_2018_12130() {
    check_cve 'CVE-2018-12130' check_mds
}

# >>>>>> vulns/CVE-2018-12207.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2018-12207, iTLB Multihit, No eXcuses, Machine Check Exception on Page Size Changes

check_CVE_2018_12207() {
    check_cve 'CVE-2018-12207'
}

check_CVE_2018_12207_linux() {
    local status sys_interface_available msg kernel_itlbmh kernel_itlbmh_err
    status=UNK
    sys_interface_available=0
    msg=''
    if sys_interface_check "$VULN_SYSFS_BASE/itlb_multihit"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        status=$ret_sys_interface_check_status
    fi
    if [ "$opt_sysfs_only" != 1 ]; then
        check_has_vmm

        pr_info_nol "* iTLB Multihit mitigation is supported by kernel: "
        kernel_itlbmh=''
        if [ -n "$g_kernel_err" ]; then
            kernel_itlbmh_err="$g_kernel_err"
        # commit 5219505fcbb640e273a0d51c19c38de0100ec5a9
        elif grep -q 'itlb_multihit' "$g_kernel"; then
            kernel_itlbmh="found itlb_multihit in kernel image"
        fi
        if [ -n "$kernel_itlbmh" ]; then
            pstatus green YES "$kernel_itlbmh"
        elif [ -n "$kernel_itlbmh_err" ]; then
            pstatus yellow UNKNOWN "$kernel_itlbmh_err"
        else
            pstatus yellow NO
        fi

        pr_info_nol "* iTLB Multihit mitigation enabled and active: "
        if [ "$opt_live" = 1 ]; then
            if [ -n "$ret_sys_interface_check_fullmsg" ]; then
                if echo "$ret_sys_interface_check_fullmsg" | grep -qF 'Mitigation'; then
                    pstatus green YES "$ret_sys_interface_check_fullmsg"
                else
                    pstatus yellow NO
                fi
            else
                pstatus yellow NO "itlb_multihit not found in sysfs hierarchy"
            fi
        else
            pstatus blue N/A "not testable in offline mode"
        fi
    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ "$g_has_vmm" = 0 ]; then
        pvulnstatus "$cve" OK "this system is not running a hypervisor"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ "$opt_sysfs_only" != 1 ]; then
            if [ "$opt_live" = 1 ]; then
                # if we're in live mode and $msg is empty, sysfs file is not there so kernel is too old
                pvulnstatus "$cve" VULN "Your kernel doesn't support iTLB Multihit mitigation, update it"
            else
                if [ -n "$kernel_itlbmh" ]; then
                    pvulnstatus "$cve" OK "Your kernel supports iTLB Multihit mitigation"
                else
                    pvulnstatus "$cve" VULN "Your kernel doesn't support iTLB Multihit mitigation, update it"
                fi
            fi
        else
            # --sysfs-only: sysfs was available (otherwise msg would be set), use its result
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
        fi
    else
        # msg was set explicitly: either sysfs-not-available error, or a sysfs override
        pvulnstatus "$cve" "$status" "$msg"
    fi
}

check_CVE_2018_12207_bsd() {
    local kernel_2m_x_ept
    pr_info_nol "* Kernel supports disabling superpages for executable mappings under EPT: "
    kernel_2m_x_ept=$(sysctl -n vm.pmap.allow_2m_x_ept 2>/dev/null)
    if [ -z "$kernel_2m_x_ept" ]; then
        pstatus yellow NO
    else
        pstatus green YES
    fi

    pr_info_nol "* Superpages are disabled for executable mappings under EPT: "
    if [ "$kernel_2m_x_ept" = 0 ]; then
        pstatus green YES
    else
        pstatus yellow NO
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$kernel_2m_x_ept" ]; then
        pvulnstatus "$cve" VULN "Your kernel doesn't support mitigating this CVE, you should update it"
    elif [ "$kernel_2m_x_ept" != 0 ]; then
        pvulnstatus "$cve" VULN "Your kernel supports mitigating this CVE, but the mitigation is disabled"
        explain "To enable the mitigation, use \`sysctl vm.pmap.allow_2m_x_ept=0\`"
    else
        pvulnstatus "$cve" OK "Your kernel has support for mitigation and the mitigation is enabled"
    fi
}

# >>>>>> vulns/CVE-2018-3615.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2018-3615, Foreshadow (SGX), L1 Terminal Fault

check_CVE_2018_3615() {
    local cve
    cve='CVE-2018-3615'
    pr_info "\033[1;34m$cve aka '$(cve2name "$cve")'\033[0m"

    pr_info_nol "* CPU microcode mitigates the vulnerability: "
    if { [ "$cap_flush_cmd" = 1 ] || { [ "$g_msr_locked_down" = 1 ] && [ "$cap_l1df" = 1 ]; }; } && [ "$cap_sgx" = 1 ]; then
        # no easy way to detect a fixed SGX but we know that
        # microcodes that have the FLUSH_CMD MSR also have the
        # fixed SGX (for CPUs that support it), because Intel
        # delivered fixed microcodes for both issues at the same time
        #
        # if the system we're running on is locked down (no way to write MSRs),
        # make the assumption that if the L1D flush CPUID bit is set, probably
        # that FLUSH_CMD MSR is here too
        pstatus green YES
    elif [ "$cap_sgx" = 1 ]; then
        pstatus red NO
    else
        pstatus blue N/A
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ "$cap_flush_cmd" = 1 ] || { [ "$g_msr_locked_down" = 1 ] && [ "$cap_l1df" = 1 ]; }; then
        pvulnstatus "$cve" OK "your CPU microcode mitigates the vulnerability"
    else
        pvulnstatus "$cve" VULN "your CPU supports SGX and the microcode is not up to date"
    fi
}

# >>>>>> vulns/CVE-2018-3620.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2018-3620, Foreshadow-NG (OS/SMM), L1 Terminal Fault

check_CVE_2018_3620() {
    check_cve 'CVE-2018-3620'
}

check_CVE_2018_3620_linux() {
    local status sys_interface_available msg pteinv_supported pteinv_active
    status=UNK
    sys_interface_available=0
    msg=''
    if sys_interface_check "$VULN_SYSFS_BASE/l1tf"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        status=$ret_sys_interface_check_status
        msg=$ret_sys_interface_check_fullmsg
    fi
    if [ "$opt_sysfs_only" != 1 ]; then
        pr_info_nol "* Kernel supports PTE inversion: "
        if ! command -v "${opt_arch_prefix}strings" >/dev/null 2>&1; then
            pstatus yellow UNKNOWN "missing 'strings' tool, please install it"
            pteinv_supported=-1
        elif [ -n "$g_kernel_err" ]; then
            pstatus yellow UNKNOWN "$g_kernel_err"
            pteinv_supported=-1
        else
            if "${opt_arch_prefix}strings" "$g_kernel" | grep -Fq 'PTE Inversion'; then
                pstatus green YES "found in kernel image"
                pr_debug "pteinv: found pte inversion evidence in kernel image"
                pteinv_supported=1
            else
                pstatus yellow NO
                pteinv_supported=0
            fi
        fi

        pr_info_nol "* PTE inversion enabled and active: "
        if [ "$opt_live" = 1 ]; then
            if [ -n "$ret_sys_interface_check_fullmsg" ]; then
                if echo "$ret_sys_interface_check_fullmsg" | grep -q 'Mitigation: PTE Inversion'; then
                    pstatus green YES
                    pteinv_active=1
                else
                    pstatus yellow NO
                    pteinv_active=0
                fi
            else
                pstatus yellow UNKNOWN "sysfs interface not available"
                pteinv_active=-1
            fi
        else
            pstatus blue N/A "not testable in offline mode"
        fi
    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ "$opt_sysfs_only" != 1 ]; then
            if [ "$pteinv_supported" = 1 ]; then
                if [ "$pteinv_active" = 1 ] || [ "$opt_live" != 1 ]; then
                    pvulnstatus "$cve" OK "PTE inversion mitigates the vulnerability"
                else
                    pvulnstatus "$cve" VULN "Your kernel supports PTE inversion but it doesn't seem to be enabled"
                fi
            else
                pvulnstatus "$cve" VULN "Your kernel doesn't support PTE inversion, update it"
            fi
        else
            # --sysfs-only: sysfs was available (otherwise msg would be set), use its result
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
        fi
    else
        # msg was set explicitly: either sysfs-not-available error, or a sysfs override
        pvulnstatus "$cve" "$status" "$msg"
    fi
}

check_CVE_2018_3620_bsd() {
    local bsd_zero_reserved
    pr_info_nol "* Kernel reserved the memory page at physical address 0x0: "
    if ! kldstat -q -m vmm; then
        kldload vmm 2>/dev/null && g_kldload_vmm=1
        pr_debug "attempted to load module vmm, g_kldload_vmm=$g_kldload_vmm"
    else
        pr_debug "vmm module already loaded"
    fi
    if sysctl hw.vmm.vmx.l1d_flush >/dev/null 2>&1; then
        # https://security.FreeBSD.org/patches/SA-18:09/l1tf-11.2.patch
        # this is very difficult to detect that the kernel reserved the 0 page, but this fix
        # is part of the exact same patch than the other L1TF CVE, so we detect it
        # and deem it as OK if the other patch is there
        pstatus green YES
        bsd_zero_reserved=1
    else
        pstatus yellow NO
        bsd_zero_reserved=0
    fi

    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        if [ "$bsd_zero_reserved" = 1 ]; then
            pvulnstatus "$cve" OK "kernel mitigates the vulnerability"
        else
            pvulnstatus "$cve" VULN "your kernel needs to be updated"
        fi
    fi
}

# >>>>>> vulns/CVE-2018-3639.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2018-3639, Variant 4, SSB, Speculative Store Bypass

check_CVE_2018_3639() {
    check_cve 'CVE-2018-3639'
}

check_CVE_2018_3639_linux() {
    local status sys_interface_available msg kernel_ssb kernel_ssbd_enabled mitigated_processes
    status=UNK
    sys_interface_available=0
    msg=''
    if sys_interface_check "$VULN_SYSFS_BASE/spec_store_bypass"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        status=$ret_sys_interface_check_status
    fi
    if [ "$opt_sysfs_only" != 1 ]; then
        pr_info_nol "* Kernel supports disabling speculative store bypass (SSB): "
        if [ "$opt_live" = 1 ]; then
            if grep -Eq 'Speculation.?Store.?Bypass:' "$g_procfs/self/status" 2>/dev/null; then
                kernel_ssb="found in $g_procfs/self/status"
                pr_debug "found Speculation.Store.Bypass: in $g_procfs/self/status"
            fi
        fi
        # arm64 kernels can have cpu_show_spec_store_bypass with ARM64_SSBD, so exclude them
        if [ -z "$kernel_ssb" ] && [ -n "$g_kernel" ] && ! grep -q 'arm64_sys_' "$g_kernel"; then
            kernel_ssb=$("${opt_arch_prefix}strings" "$g_kernel" | grep spec_store_bypass | head -n1)
            [ -n "$kernel_ssb" ] && kernel_ssb="found $kernel_ssb in kernel"
        fi
        # arm64 kernels can have cpu_show_spec_store_bypass with ARM64_SSBD, so exclude them
        if [ -z "$kernel_ssb" ] && [ -n "$opt_map" ] && ! grep -q 'arm64_sys_' "$opt_map"; then
            kernel_ssb=$(grep spec_store_bypass "$opt_map" | awk '{print $3}' | head -n1)
            [ -n "$kernel_ssb" ] && kernel_ssb="found $kernel_ssb in System.map"
        fi
        # arm64 only:
        if [ -z "$kernel_ssb" ] && [ -n "$opt_map" ]; then
            kernel_ssb=$(grep -w cpu_enable_ssbs "$opt_map" | awk '{print $3}' | head -n1)
            [ -n "$kernel_ssb" ] && kernel_ssb="found $kernel_ssb in System.map"
        fi
        if [ -z "$kernel_ssb" ] && [ -n "$opt_config" ]; then
            kernel_ssb=$(grep -w 'CONFIG_ARM64_SSBD=y' "$opt_config")
            [ -n "$kernel_ssb" ] && kernel_ssb="CONFIG_ARM64_SSBD enabled in kconfig"
        fi
        if [ -z "$kernel_ssb" ] && [ -n "$g_kernel" ]; then
            # this string only appears in kernel if CONFIG_ARM64_SSBD is set
            kernel_ssb=$(grep -w "Speculative Store Bypassing Safe (SSBS)" "$g_kernel")
            [ -n "$kernel_ssb" ] && kernel_ssb="found 'Speculative Store Bypassing Safe (SSBS)' in kernel"
        fi
        # /arm64 only

        if [ -n "$kernel_ssb" ]; then
            pstatus green YES "$kernel_ssb"
        else
            pstatus yellow NO
        fi

        kernel_ssbd_enabled=-1
        if [ "$opt_live" = 1 ]; then
            # https://elixir.bootlin.com/linux/v5.0/source/fs/proc/array.c#L340
            pr_info_nol "* SSB mitigation is enabled and active: "
            if grep -Eq 'Speculation.?Store.?Bypass:[[:space:]]+thread' "$g_procfs/self/status" 2>/dev/null; then
                kernel_ssbd_enabled=1
                pstatus green YES "per-thread through prctl"
            elif grep -Eq 'Speculation.?Store.?Bypass:[[:space:]]+globally mitigated' "$g_procfs/self/status" 2>/dev/null; then
                kernel_ssbd_enabled=2
                pstatus green YES "global"
            elif grep -Eq 'Speculation.?Store.?Bypass:[[:space:]]+vulnerable' "$g_procfs/self/status" 2>/dev/null; then
                kernel_ssbd_enabled=0
                pstatus yellow NO
            elif grep -Eq 'Speculation.?Store.?Bypass:[[:space:]]+not vulnerable' "$g_procfs/self/status" 2>/dev/null; then
                kernel_ssbd_enabled=-2
                pstatus blue NO "not vulnerable"
            elif grep -Eq 'Speculation.?Store.?Bypass:[[:space:]]+unknown' "$g_procfs/self/status" 2>/dev/null; then
                kernel_ssbd_enabled=0
                pstatus blue NO
            else
                pstatus blue UNKNOWN "unknown value: $(grep -E 'Speculation.?Store.?Bypass:' "$g_procfs/self/status" 2>/dev/null | cut -d: -f2-)"
            fi

            if [ "$kernel_ssbd_enabled" = 1 ]; then
                pr_info_nol "* SSB mitigation currently active for selected processes: "
                # silence grep's stderr here to avoid ENOENT errors from processes that have exited since the shell's expansion of the *
                mitigated_processes=$(find /proc -mindepth 2 -maxdepth 2 -type f -name status -print0 2>/dev/null |
                    xargs -r0 grep -El 'Speculation.?Store.?Bypass:[[:space:]]+thread (force )?mitigated' 2>/dev/null |
                    sed s/status/exe/ | xargs -r -n1 readlink -f 2>/dev/null | xargs -r -n1 basename | sort -u | tr "\n" " " | sed 's/ $//')
                if [ -n "$mitigated_processes" ]; then
                    pstatus green YES "$mitigated_processes"
                else
                    pstatus yellow NO "no process found using SSB mitigation through prctl"
                fi
            fi
        fi

    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ] || [ "$msg" = "Vulnerable" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ -n "$cap_ssbd" ]; then
            if [ -n "$kernel_ssb" ]; then
                if [ "$opt_live" = 1 ]; then
                    if [ "$kernel_ssbd_enabled" -gt 0 ]; then
                        pvulnstatus "$cve" OK "your CPU and kernel both support SSBD and mitigation is enabled"
                    else
                        pvulnstatus "$cve" VULN "your CPU and kernel both support SSBD but the mitigation is not active"
                    fi
                else
                    pvulnstatus "$cve" OK "your system provides the necessary tools for software mitigation"
                fi
            else
                pvulnstatus "$cve" VULN "your kernel needs to be updated"
                explain "You have a recent-enough CPU microcode but your kernel is too old to use the new features exported by your CPU's microcode. If you're using a distro kernel, upgrade your distro to get the latest kernel available. Otherwise, recompile the kernel from recent-enough sources."
            fi
        else
            if [ -n "$kernel_ssb" ]; then
                pvulnstatus "$cve" VULN "Your CPU doesn't support SSBD"
                explain "Your kernel is recent enough to use the CPU microcode features for mitigation, but your CPU microcode doesn't actually provide the necessary features for the kernel to use. The microcode of your CPU hence needs to be upgraded. This is usually done at boot time by your kernel (the upgrade is not persistent across reboots which is why it's done at each boot). If you're using a distro, make sure you are up to date, as microcode updates are usually shipped alongside with the distro kernel. Availability of a microcode update for you CPU model depends on your CPU vendor. You can usually find out online if a microcode update is available for your CPU by searching for your CPUID (indicated in the Hardware Check section)."
            else
                pvulnstatus "$cve" VULN "Neither your CPU nor your kernel support SSBD"
                explain "Both your CPU microcode and your kernel are lacking support for mitigation. If you're using a distro kernel, upgrade your distro to get the latest kernel available. Otherwise, recompile the kernel from recent-enough sources. The microcode of your CPU also needs to be upgraded. This is usually done at boot time by your kernel (the upgrade is not persistent across reboots which is why it's done at each boot). If you're using a distro, make sure you are up to date, as microcode updates are usually shipped alongside with the distro kernel. Availability of a microcode update for you CPU model depends on your CPU vendor. You can usually find out online if a microcode update is available for your CPU by searching for your CPUID (indicated in the Hardware Check section)."
            fi
        fi
    else
        pvulnstatus "$cve" "$status" "$msg"
    fi
}

check_CVE_2018_3639_bsd() {
    local kernel_ssb ssb_enabled ssb_active
    pr_info_nol "* Kernel supports speculation store bypass: "
    if sysctl hw.spec_store_bypass_disable >/dev/null 2>&1; then
        kernel_ssb=1
        pstatus green YES
    else
        kernel_ssb=0
        pstatus yellow NO
    fi

    pr_info_nol "* Speculation store bypass is administratively enabled: "
    ssb_enabled=$(sysctl -n hw.spec_store_bypass_disable 2>/dev/null)
    pr_debug "hw.spec_store_bypass_disable=$ssb_enabled"
    case "$ssb_enabled" in
        0) pstatus yellow NO "disabled" ;;
        1) pstatus green YES "enabled" ;;
        2) pstatus green YES "auto mode" ;;
        *) pstatus yellow NO "unavailable" ;;
    esac

    pr_info_nol "* Speculation store bypass is currently active: "
    ssb_active=$(sysctl -n hw.spec_store_bypass_disable_active 2>/dev/null)
    pr_debug "hw.spec_store_bypass_disable_active=$ssb_active"
    case "$ssb_active" in
        1) pstatus green YES ;;
        *) pstatus yellow NO ;;
    esac

    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        if [ "$ssb_active" = 1 ]; then
            pvulnstatus "$cve" OK "SSBD mitigates the vulnerability"
        elif [ -n "$cap_ssbd" ]; then
            if [ "$kernel_ssb" = 1 ]; then
                pvulnstatus "$cve" VULN "you need to enable SSBD through sysctl to mitigate the vulnerability"
                explain "To enable SSBD right now, you can run \`sysctl hw.spec_store_bypass_disable=2'. To make this change persistent across reboots, you can add 'sysctl hw.spec_store_bypass_disable=2' to /etc/sysctl.conf."
            else
                pvulnstatus "$cve" VULN "your kernel needs to be updated"
            fi
        else
            if [ "$kernel_ssb" = 1 ]; then
                pvulnstatus "$cve" VULN "Your CPU doesn't support SSBD"
            else
                pvulnstatus "$cve" VULN "Neither your CPU nor your kernel support SSBD"
            fi
        fi
    fi
}

# >>>>>> vulns/CVE-2018-3640.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2018-3640, Variant 3a, Rogue System Register Read

check_CVE_2018_3640() {
    local status sys_interface_available msg cve
    cve='CVE-2018-3640'
    pr_info "\033[1;34m$cve aka '$(cve2name "$cve")'\033[0m"

    status=UNK
    sys_interface_available=0
    msg=''

    pr_info_nol "* CPU microcode mitigates the vulnerability: "
    if [ -n "$cap_ssbd" ]; then
        # microcodes that ship with SSBD are known to also fix affected_variant3a
        # there is no specific cpuid bit as far as we know
        pstatus green YES
    else
        pstatus yellow NO
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -n "$cap_ssbd" ]; then
        pvulnstatus "$cve" OK "your CPU microcode mitigates the vulnerability"
    else
        pvulnstatus "$cve" VULN "an up-to-date CPU microcode is needed to mitigate this vulnerability"
        explain "The microcode of your CPU needs to be upgraded to mitigate this vulnerability. This is usually done at boot time by your kernel (the upgrade is not persistent across reboots which is why it's done at each boot). If you're using a distro, make sure you are up to date, as microcode updates are usually shipped alongside with the distro kernel. Availability of a microcode update for you CPU model depends on your CPU vendor. You can usually find out online if a microcode update is available for your CPU by searching for your CPUID (indicated in the Hardware Check section). The microcode update is enough, there is no additional OS, kernel or software change needed."
    fi
}

# >>>>>> vulns/CVE-2018-3646.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2018-3646, Foreshadow-NG (VMM), L1 Terminal Fault

check_CVE_2018_3646() {
    check_cve 'CVE-2018-3646'
}

check_CVE_2018_3646_linux() {
    local status sys_interface_available msg l1d_mode ept_disabled l1d_kernel l1d_kernel_err l1d_xen_hardware l1d_xen_hypervisor l1d_xen_pv_domU smt_enabled
    status=UNK
    sys_interface_available=0
    msg=''
    if sys_interface_check "$VULN_SYSFS_BASE/l1tf" '.*' quiet; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        # quiet mode doesn't set ret_sys_interface_check_status, derive it ourselves.
        #
        # Complete sysfs message inventory for l1tf, traced via git blame
        # on mainline (~/linux) and stable (~/linux-stable):
        #
        # all versions:
        #   "Not affected"                          (cpu_show_common, d1059518b4789)
        #   "Vulnerable"                            (cpu_show_common fallthrough, d1059518b4789)
        #
        # --- mainline ---
        # 17dbca119312 (v4.18-rc1, initial l1tf sysfs):
        #   "Mitigation: Page Table Inversion"
        # 72c6d2db64fa (v4.18-rc1, renamed + added VMX reporting):
        #   "Mitigation: PTE Inversion"                                  (no KVM_INTEL, or VMX=AUTO)
        #   "Mitigation: PTE Inversion; VMX: SMT <smt>, L1D <flush>"    (KVM_INTEL enabled)
        #     <flush>: auto | vulnerable | conditional cache flushes | cache flushes
        # a7b9020b06ec (v4.18-rc1, added EPT disabled state):
        #     <flush>: + EPT disabled
        # ea156d192f52 (v4.18-rc7, reordered VMX/SMT fields):
        #   "Mitigation: PTE Inversion; VMX: EPT disabled"              (no SMT part)
        #   "Mitigation: PTE Inversion; VMX: vulnerable"                (NEVER + SMT active, no SMT part)
        #   "Mitigation: PTE Inversion; VMX: <flush>, SMT <smt>"        (all other cases)
        # 8e0b2b916662 (v4.18, added flush not necessary):
        #     <flush>: + flush not necessary
        # 130d6f946f6f (v4.20-rc4, no string change):
        #     SMT detection changed from cpu_smt_control to sched_smt_active()
        #
        # --- stable backports ---
        # 4.4.y: no VMX reporting (only "PTE Inversion" / "Vulnerable" / "Not affected").
        #   initially backported as "Page Table Inversion" (bf0cca01b873),
        #   renamed to "PTE Inversion" in stable-only commit 6db8c0882912 (May 2019).
        # 4.9.y, 4.14.y: full VMX reporting, post-reorder format.
        #   the pre-reorder format ("SMT <smt>, L1D <flush>") and the post-reorder
        #   format ("VMX: <flush>, SMT <smt>") landed in the same stable release
        #   (4.9.120, 4.14.63), so no stable release ever shipped the pre-reorder format.
        #   sched_smt_active() backported (same strings, different runtime behavior).
        # 4.17.y, 4.18.y: full VMX reporting, post-reorder format.
        #   still uses cpu_smt_control (sched_smt_active() not backported to these EOL branches).
        #
        # <smt> is one of: vulnerable | disabled
        #
        # all messages start with either "Not affected", "Mitigation", or "Vulnerable"
        if echo "$ret_sys_interface_check_fullmsg" | grep -qEi '^(Not affected|Mitigation)'; then
            status=OK
        elif echo "$ret_sys_interface_check_fullmsg" | grep -qi '^Vulnerable'; then
            status=VULN
        fi
    fi
    l1d_mode=-1
    if [ "$opt_sysfs_only" != 1 ]; then
        check_has_vmm

        pr_info "* Mitigation 1 (KVM)"
        pr_info_nol "  * EPT is disabled: "
        ept_disabled=-1
        if [ "$opt_live" = 1 ]; then
            if ! [ -r "$SYS_MODULE_BASE/kvm_intel/parameters/ept" ]; then
                pstatus blue N/A "the kvm_intel module is not loaded"
            elif [ "$(cat "$SYS_MODULE_BASE/kvm_intel/parameters/ept")" = N ]; then
                pstatus green YES
                ept_disabled=1
            else
                pstatus yellow NO
            fi
        else
            pstatus blue N/A "not testable in offline mode"
        fi

        pr_info "* Mitigation 2"
        pr_info_nol "  * L1D flush is supported by kernel: "
        if [ "$opt_live" = 1 ] && grep -qw flush_l1d "$g_procfs/cpuinfo"; then
            l1d_kernel="found flush_l1d in $g_procfs/cpuinfo"
        fi
        if [ -z "$l1d_kernel" ]; then
            if ! command -v "${opt_arch_prefix}strings" >/dev/null 2>&1; then
                l1d_kernel_err="missing '${opt_arch_prefix}strings' tool, please install it, usually it's in the binutils package"
            elif [ -n "$g_kernel_err" ]; then
                l1d_kernel_err="$g_kernel_err"
            elif "${opt_arch_prefix}strings" "$g_kernel" | grep -qw flush_l1d; then
                l1d_kernel='found flush_l1d in kernel image'
            fi
        fi

        if [ -n "$l1d_kernel" ]; then
            pstatus green YES "$l1d_kernel"
        elif [ -n "$l1d_kernel_err" ]; then
            pstatus yellow UNKNOWN "$l1d_kernel_err"
        else
            pstatus yellow NO
        fi

        pr_info_nol "  * L1D flush enabled: "
        if [ "$opt_live" = 1 ]; then
            if [ -n "$ret_sys_interface_check_fullmsg" ]; then
                # vanilla: VMX: $l1dstatus, SMT $smtstatus
                # Red Hat: VMX: SMT $smtstatus, L1D $l1dstatus
                # $l1dstatus is one of (auto|vulnerable|conditional cache flushes|cache flushes|EPT disabled|flush not necessary)
                # $smtstatus is one of (vulnerable|disabled)
                # can also just be "Not affected"
                if echo "$ret_sys_interface_check_fullmsg" | grep -Eq -e 'Not affected' -e '(VMX:|L1D) (EPT disabled|vulnerable|flush not necessary)'; then
                    l1d_mode=0
                    pstatus yellow NO
                elif echo "$ret_sys_interface_check_fullmsg" | grep -Eq '(VMX:|L1D) conditional cache flushes'; then
                    l1d_mode=1
                    pstatus green YES "conditional flushes"
                elif echo "$ret_sys_interface_check_fullmsg" | grep -Eq '(VMX:|L1D) cache flushes'; then
                    l1d_mode=2
                    pstatus green YES "unconditional flushes"
                else
                    if is_xen_dom0; then
                        l1d_xen_hardware=$(xl dmesg 2>/dev/null | grep 'Hardware features:' | grep 'L1D_FLUSH' | head -n1)
                        l1d_xen_hypervisor=$(xl dmesg 2>/dev/null | grep 'Xen settings:' | grep 'L1D_FLUSH' | head -n1)
                        l1d_xen_pv_domU=$(xl dmesg 2>/dev/null | grep 'PV L1TF shadowing:' | grep 'DomU enabled' | head -n1)

                        if [ -n "$l1d_xen_hardware" ] && [ -n "$l1d_xen_hypervisor" ] && [ -n "$l1d_xen_pv_domU" ]; then
                            l1d_mode=5
                            pstatus green YES "for XEN guests"
                        elif [ -n "$l1d_xen_hardware" ] && [ -n "$l1d_xen_hypervisor" ]; then
                            l1d_mode=4
                            pstatus yellow YES "for XEN guests (HVM only)"
                        elif [ -n "$l1d_xen_pv_domU" ]; then
                            l1d_mode=3
                            pstatus yellow YES "for XEN guests (PV only)"
                        else
                            l1d_mode=0
                            pstatus yellow NO "for XEN guests"
                        fi
                    else
                        l1d_mode=-1
                        pstatus yellow UNKNOWN "unrecognized mode"
                    fi
                fi
            else
                l1d_mode=-1
                pstatus yellow UNKNOWN "can't find or read $VULN_SYSFS_BASE/l1tf"
            fi
        else
            l1d_mode=-1
            pstatus blue N/A "not testable in offline mode"
        fi

        pr_info_nol "  * Hardware-backed L1D flush supported: "
        if [ "$opt_live" = 1 ]; then
            if grep -qw flush_l1d "$g_procfs/cpuinfo" || [ -n "$l1d_xen_hardware" ]; then
                pstatus green YES "performance impact of the mitigation will be greatly reduced"
            else
                pstatus blue NO "flush will be done in software, this is slower"
            fi
        else
            pstatus blue N/A "not testable in offline mode"
        fi

        pr_info_nol "  * Hyper-Threading (SMT) is enabled: "
        is_cpu_smt_enabled
        smt_enabled=$?
        if [ "$smt_enabled" = 0 ]; then
            pstatus yellow YES
        elif [ "$smt_enabled" = 1 ]; then
            pstatus green NO
        else
            pstatus yellow UNKNOWN
        fi

    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
        l1d_mode=-1
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ "$ret_sys_interface_check_fullmsg" = "Not affected" ]; then
        # just in case a very recent kernel knows better than we do
        pvulnstatus "$cve" OK "your kernel reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        if [ "$opt_sysfs_only" != 1 ]; then
            if [ "$g_has_vmm" = 0 ]; then
                pvulnstatus "$cve" OK "this system is not running a hypervisor"
            elif [ "$ept_disabled" = 1 ]; then
                pvulnstatus "$cve" OK "EPT is disabled which mitigates the vulnerability"
            elif [ "$opt_paranoid" = 0 ]; then
                if [ "$l1d_mode" -ge 1 ]; then
                    pvulnstatus "$cve" OK "L1D flushing is enabled and mitigates the vulnerability"
                else
                    pvulnstatus "$cve" VULN "disable EPT or enable L1D flushing to mitigate the vulnerability"
                fi
            else
                if [ "$l1d_mode" -ge 2 ]; then
                    if [ "$smt_enabled" = 1 ]; then
                        pvulnstatus "$cve" OK "L1D unconditional flushing and Hyper-Threading disabled are mitigating the vulnerability"
                    else
                        pvulnstatus "$cve" VULN "Hyper-Threading must be disabled to fully mitigate the vulnerability"
                    fi
                else
                    if [ "$smt_enabled" = 1 ]; then
                        pvulnstatus "$cve" VULN "L1D unconditional flushing should be enabled to fully mitigate the vulnerability"
                    else
                        pvulnstatus "$cve" VULN "enable L1D unconditional flushing and disable Hyper-Threading to fully mitigate the vulnerability"
                    fi
                fi
            fi

            if [ "$l1d_mode" -gt 3 ]; then
                pr_warn
                pr_warn "This host is a Xen Dom0. Please make sure that you are running your DomUs"
                pr_warn "with a kernel which contains CVE-2018-3646 mitigations."
                pr_warn
                pr_warn "See https://www.suse.com/support/kb/doc/?id=7023078 and XSA-273 for details."
            fi
        else
            # --sysfs-only: sysfs was available (otherwise msg would be set), use its result
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
        fi
    else
        # msg was set explicitly: either sysfs-not-available error, or a sysfs override
        pvulnstatus "$cve" "$status" "$msg"
    fi
}

check_CVE_2018_3646_bsd() {
    local kernel_l1d_supported kernel_l1d_enabled
    pr_info_nol "* Kernel supports L1D flushing: "
    if sysctl hw.vmm.vmx.l1d_flush >/dev/null 2>&1; then
        pstatus green YES
        kernel_l1d_supported=1
    else
        pstatus yellow NO
        kernel_l1d_supported=0
    fi

    pr_info_nol "* L1D flushing is enabled: "
    kernel_l1d_enabled=$(sysctl -n hw.vmm.vmx.l1d_flush 2>/dev/null)
    case "$kernel_l1d_enabled" in
        0) pstatus yellow NO ;;
        1) pstatus green YES ;;
        "") pstatus yellow NO ;;
        *) pstatus yellow UNKNOWN ;;
    esac

    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        if [ "$kernel_l1d_enabled" = 1 ]; then
            pvulnstatus "$cve" OK "L1D flushing mitigates the vulnerability"
        elif [ "$kernel_l1d_supported" = 1 ]; then
            pvulnstatus "$cve" VULN "L1D flushing is supported by your kernel but is disabled"
        else
            pvulnstatus "$cve" VULN "your kernel needs to be updated"
        fi
    fi
}

# >>>>>> vulns/CVE-2019-11091.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2019-11091, MDSUM, RIDL, Microarchitectural Data Sampling Uncacheable Memory

check_CVE_2019_11091() {
    check_cve 'CVE-2019-11091' check_mds
}

# >>>>>> vulns/CVE-2019-11135.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2019-11135, TAA, ZombieLoad V2, TSX Asynchronous Abort

check_CVE_2019_11135() {
    check_cve 'CVE-2019-11135'
}

check_CVE_2019_11135_linux() {
    local status sys_interface_available msg kernel_taa kernel_taa_err
    status=UNK
    sys_interface_available=0
    msg=''
    if sys_interface_check "$VULN_SYSFS_BASE/tsx_async_abort"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        status=$ret_sys_interface_check_status
    fi
    if [ "$opt_sysfs_only" != 1 ]; then
        pr_info_nol "* TAA mitigation is supported by kernel: "
        kernel_taa=''
        if [ -n "$g_kernel_err" ]; then
            kernel_taa_err="$g_kernel_err"
        elif grep -q 'tsx_async_abort' "$g_kernel"; then
            kernel_taa="found tsx_async_abort in kernel image"
        fi
        if [ -n "$kernel_taa" ]; then
            pstatus green YES "$kernel_taa"
        elif [ -n "$kernel_taa_err" ]; then
            pstatus yellow UNKNOWN "$kernel_taa_err"
        else
            pstatus yellow NO
        fi

        pr_info_nol "* TAA mitigation enabled and active: "
        if [ "$opt_live" = 1 ]; then
            if [ -n "$ret_sys_interface_check_fullmsg" ]; then
                if echo "$ret_sys_interface_check_fullmsg" | grep -qE '^Mitigation'; then
                    pstatus green YES "$ret_sys_interface_check_fullmsg"
                else
                    pstatus yellow NO
                fi
            else
                pstatus yellow NO "tsx_async_abort not found in sysfs hierarchy"
            fi
        else
            pstatus blue N/A "not testable in offline mode"
        fi
    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ "$opt_live" = 1 ]; then
            # if we're in live mode and $msg is empty, sysfs file is not there so kernel is too old
            pvulnstatus "$cve" VULN "Your kernel doesn't support TAA mitigation, update it"
        else
            if [ -n "$kernel_taa" ]; then
                pvulnstatus "$cve" OK "Your kernel supports TAA mitigation"
            else
                pvulnstatus "$cve" VULN "Your kernel doesn't support TAA mitigation, update it"
            fi
        fi
    else
        if [ "$opt_paranoid" = 1 ]; then
            # in paranoid mode, TSX or SMT enabled are not OK, even if TAA is mitigated
            if ! echo "$ret_sys_interface_check_fullmsg" | grep -qF 'TSX disabled'; then
                pvulnstatus "$cve" VULN "TSX must be disabled for full mitigation"
            elif echo "$ret_sys_interface_check_fullmsg" | grep -qF 'SMT vulnerable'; then
                pvulnstatus "$cve" VULN "SMT (HyperThreading) must be disabled for full mitigation"
            else
                pvulnstatus "$cve" "$status" "$msg"
            fi
        else
            pvulnstatus "$cve" "$status" "$msg"
        fi
    fi
}

check_CVE_2019_11135_bsd() {
    local taa_enable taa_state mds_disable kernel_taa kernel_mds
    pr_info_nol "* Kernel supports TAA mitigation (machdep.mitigations.taa.enable): "
    taa_enable=$(sysctl -n machdep.mitigations.taa.enable 2>/dev/null)
    if [ -n "$taa_enable" ]; then
        kernel_taa=1
        case "$taa_enable" in
            0) pstatus yellow YES "disabled" ;;
            1) pstatus green YES "TSX disabled via MSR" ;;
            2) pstatus green YES "VERW mitigation" ;;
            3) pstatus green YES "auto" ;;
            *) pstatus yellow YES "unknown value: $taa_enable" ;;
        esac
    else
        kernel_taa=0
        pstatus yellow NO
    fi

    pr_info_nol "* TAA mitigation state: "
    taa_state=$(sysctl -n machdep.mitigations.taa.state 2>/dev/null)
    if [ -n "$taa_state" ]; then
        if echo "$taa_state" | grep -qi 'not.affected\|mitigation'; then
            pstatus green YES "$taa_state"
        else
            pstatus yellow NO "$taa_state"
        fi
    else
        # fallback: TAA is also mitigated by MDS VERW if enabled
        mds_disable=$(sysctl -n hw.mds_disable 2>/dev/null)
        if [ -z "$mds_disable" ]; then
            mds_disable=$(sysctl -n machdep.mitigations.mds.disable 2>/dev/null)
        fi
        if [ -n "$mds_disable" ] && [ "$mds_disable" != 0 ]; then
            kernel_mds=1
            pstatus green YES "MDS VERW mitigation active (also covers TAA)"
        else
            kernel_mds=0
            pstatus yellow NO "no TAA or MDS sysctl found"
        fi
    fi

    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ "$kernel_taa" = 1 ] && [ "$taa_enable" != 0 ]; then
        pvulnstatus "$cve" OK "TAA mitigation is enabled"
    elif [ "$kernel_mds" = 1 ]; then
        pvulnstatus "$cve" OK "MDS VERW mitigation is active and also covers TAA"
    elif [ "$kernel_taa" = 1 ] && [ "$taa_enable" = 0 ]; then
        pvulnstatus "$cve" VULN "TAA mitigation is supported but disabled"
        explain "To enable TAA mitigation, run \`sysctl machdep.mitigations.taa.enable=3' for auto mode.\n " \
            "To make this persistent, add 'machdep.mitigations.taa.enable=3' to /etc/sysctl.conf."
    else
        pvulnstatus "$cve" VULN "your kernel doesn't support TAA mitigation, update it"
    fi
}

# >>>>>> vulns/CVE-2020-0543.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2020-0543, SRBDS, CROSSTalk, Special Register Buffer Data Sampling

check_CVE_2020_0543() {
    check_cve 'CVE-2020-0543'
}

check_CVE_2020_0543_linux() {
    local status sys_interface_available msg kernel_srbds kernel_srbds_err
    status=UNK
    sys_interface_available=0
    msg=''
    if sys_interface_check "$VULN_SYSFS_BASE/srbds"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        status=$ret_sys_interface_check_status
    fi
    if [ "$opt_sysfs_only" != 1 ]; then
        pr_info_nol "* SRBDS mitigation control is supported by the kernel: "
        kernel_srbds=''
        if [ -n "$g_kernel_err" ]; then
            kernel_srbds_err="$g_kernel_err"
        elif grep -q 'Dependent on hypervisor' "$g_kernel"; then
            kernel_srbds="found SRBDS implementation evidence in kernel image. Your kernel is up to date for SRBDS mitigation"
        fi
        if [ -n "$kernel_srbds" ]; then
            pstatus green YES "$kernel_srbds"
        elif [ -n "$kernel_srbds_err" ]; then
            pstatus yellow UNKNOWN "$kernel_srbds_err"
        else
            pstatus yellow NO
        fi
        pr_info_nol "* SRBDS mitigation control is enabled and active: "
        if [ "$opt_live" = 1 ]; then
            if [ -n "$ret_sys_interface_check_fullmsg" ]; then
                if echo "$ret_sys_interface_check_fullmsg" | grep -qE '^Mitigation'; then
                    pstatus green YES "$ret_sys_interface_check_fullmsg"
                else
                    pstatus yellow NO
                fi
            else
                pstatus yellow NO "SRBDS not found in sysfs hierarchy"
            fi
        else
            pstatus blue N/A "not testable in offline mode"
        fi
    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi
    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        if [ "$opt_sysfs_only" != 1 ]; then
            if [ "$cap_srbds" = 1 ]; then
                # SRBDS mitigation control exists
                if [ "$cap_srbds_on" = 1 ]; then
                    # SRBDS mitigation control is enabled
                    if [ -z "$msg" ]; then
                        # if msg is empty, sysfs check didn't fill it, rely on our own test
                        if [ "$opt_live" = 1 ]; then
                            # if we're in live mode and $msg is empty, sysfs file is not there so kernel is too old
                            pvulnstatus "$cve" OK "Your microcode is up to date for SRBDS mitigation control. The kernel needs to be updated"
                        fi
                    else
                        if [ -n "$kernel_srbds" ]; then
                            pvulnstatus "$cve" OK "Your microcode and kernel are both up to date for SRBDS mitigation control. Mitigation is enabled"
                        else
                            pvulnstatus "$cve" OK "Your microcode is up to date for SRBDS mitigation control. The kernel needs to be updated"
                        fi
                    fi
                elif [ "$cap_srbds_on" = 0 ]; then
                    # SRBDS mitigation control is disabled
                    if [ -z "$msg" ]; then
                        if [ "$opt_live" = 1 ]; then
                            # if we're in live mode and $msg is empty, sysfs file is not there so kernel is too old
                            pvulnstatus "$cve" VULN "Your microcode is up to date for SRBDS mitigation control. The kernel needs to be updated. Mitigation is disabled"
                        fi
                    else
                        if [ -n "$kernel_srbds" ]; then
                            pvulnstatus "$cve" VULN "Your microcode and kernel are both up to date for SRBDS mitigation control. Mitigation is disabled"
                        else
                            pvulnstatus "$cve" VULN "Your microcode is up to date for SRBDS mitigation control. The kernel needs to be updated. Mitigation is disabled"
                        fi
                    fi
                else
                    # rdmsr: CPU 0 cannot read MSR 0x00000123
                    pvulnstatus "$cve" UNK "Not able to enumerate MSR for SRBDS mitigation control"
                fi
            else
                # [ $cap_srbds != 1 ]
                pvulnstatus "$cve" VULN "Your CPU microcode may need to be updated to mitigate the vulnerability"
            fi
        else
            # sysfs only: return the status/msg we got
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
            return
        fi
    fi
}

# FreeBSD uses the name "rngds" (Random Number Generator Data Sampling) for SRBDS
check_CVE_2020_0543_bsd() {
    local rngds_enable rngds_state kernel_rngds
    pr_info_nol "* Kernel supports SRBDS mitigation (machdep.mitigations.rngds.enable): "
    rngds_enable=$(sysctl -n machdep.mitigations.rngds.enable 2>/dev/null)
    if [ -n "$rngds_enable" ]; then
        kernel_rngds=1
        case "$rngds_enable" in
            0) pstatus yellow YES "optimized (RDRAND/RDSEED not locked, faster but vulnerable)" ;;
            1) pstatus green YES "mitigated" ;;
            *) pstatus yellow YES "unknown value: $rngds_enable" ;;
        esac
    else
        kernel_rngds=0
        pstatus yellow NO
    fi

    pr_info_nol "* SRBDS mitigation state: "
    rngds_state=$(sysctl -n machdep.mitigations.rngds.state 2>/dev/null)
    if [ -n "$rngds_state" ]; then
        if echo "$rngds_state" | grep -qi 'not.affected\|mitigat'; then
            pstatus green YES "$rngds_state"
        else
            pstatus yellow NO "$rngds_state"
        fi
    else
        pstatus yellow NO "sysctl not available"
    fi

    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ "$kernel_rngds" = 1 ] && [ "$rngds_enable" = 1 ]; then
        pvulnstatus "$cve" OK "SRBDS mitigation is enabled"
    elif [ "$kernel_rngds" = 1 ] && [ "$rngds_enable" = 0 ]; then
        pvulnstatus "$cve" VULN "SRBDS mitigation is supported but set to optimized mode (disabled for RDRAND/RDSEED)"
        explain "To enable full SRBDS mitigation, run \`sysctl machdep.mitigations.rngds.enable=1'.\n " \
            "To make this persistent, add 'machdep.mitigations.rngds.enable=1' to /etc/sysctl.conf."
    else
        pvulnstatus "$cve" VULN "your kernel doesn't support SRBDS mitigation, update it"
    fi
}

# >>>>>> vulns/CVE-2022-29900.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2022-29900, Retbleed (AMD), Arbitrary Speculative Code Execution with Return Instructions

check_CVE_2022_29900() {
    check_cve 'CVE-2022-29900'
}

check_CVE_2022_29900_linux() {
    local status sys_interface_available msg kernel_retbleed kernel_retbleed_err kernel_unret kernel_ibpb_entry smt_enabled
    status=UNK
    sys_interface_available=0
    msg=''

    #
    # Kernel source inventory for retbleed (CVE-2022-29900 / CVE-2022-29901)
    #
    # --- sysfs messages ---
    # all versions:
    #   "Not affected"                                  (cpu_show_common, pre-existing)
    #
    # --- mainline ---
    # 6b80b59b3555 (v5.19-rc7, initial retbleed sysfs):
    #   "Vulnerable\n"                                  (hardcoded, no enum yet)
    # 7fbf47c7ce50 (v5.19-rc7, retbleed= boot parameter):
    #   "Vulnerable"                                    (RETBLEED_MITIGATION_NONE)
    #   "Mitigation: untrained return thunk"            (RETBLEED_MITIGATION_UNRET)
    #   "Vulnerable: untrained return thunk on non-Zen uarch"  (UNRET on non-AMD/Hygon)
    # 6ad0ad2bf8a6 (v5.19-rc7, Intel mitigations):
    #   "Mitigation: IBRS"                              (RETBLEED_MITIGATION_IBRS)
    #   "Mitigation: Enhanced IBRS"                     (RETBLEED_MITIGATION_EIBRS)
    # 3ebc17006888 (v5.19-rc7, retbleed=ibpb):
    #   "Mitigation: IBPB"                              (RETBLEED_MITIGATION_IBPB)
    # e8ec1b6e08a2 (v5.19-rc7, STIBP for JMP2RET):
    #   UNRET now appends SMT status:
    #   "Mitigation: untrained return thunk; SMT disabled"
    #   "Mitigation: untrained return thunk; SMT enabled with STIBP protection"
    #   "Mitigation: untrained return thunk; SMT vulnerable"
    # e6cfcdda8cbe (v6.0-rc1, STIBP for IBPB):
    #   IBPB now appends SMT status, non-AMD message changed:
    #   "Vulnerable: untrained return thunk / IBPB on non-AMD based uarch"
    #   "Mitigation: IBPB; SMT disabled"
    #   "Mitigation: IBPB; SMT enabled with STIBP protection"
    #   "Mitigation: IBPB; SMT vulnerable"
    # d82a0345cf21 (v6.2-rc1, call depth tracking):
    #   "Mitigation: Stuffing"                          (RETBLEED_MITIGATION_STUFF)
    # e3b78a7ad5ea (v6.16-rc1, restructure):
    #   added RETBLEED_MITIGATION_AUTO (internal, resolved before display)
    #   no new sysfs strings
    #
    # all messages start with either "Not affected", "Vulnerable", or "Mitigation"
    #
    # --- stable backports ---
    # 4.14.y, 4.19.y, 5.4.y: Intel-only mitigations (IBRS, eIBRS); no UNRET, IBPB, STUFF;
    #   no SMT status display; simplified retbleed_show_state().
    # 5.10.y, 5.15.y, 6.1.y: full mitigations (NONE, UNRET, IBPB, IBRS, EIBRS);
    #   SMT status appended for UNRET/IBPB; no STUFF.
    # 6.6.y, 6.12.y: adds STUFF (call depth tracking). 6.12.y uses INTEL_ model prefix.
    # all stable: single retbleed_select_mitigation() (no update/apply split).
    #
    # --- RHEL/CentOS ---
    # centos7 (~4.18): NONE, UNRET, IBPB, IBRS, EIBRS; no STUFF; SMT status for UNRET;
    #   no Hygon check; no UNRET_ENTRY/IBPB_ENTRY/IBRS_ENTRY Kconfig symbols;
    #   unique cpu_in_retbleed_whitelist() function for Intel.
    # rocky8 (~4.18/5.14): NONE, UNRET, IBPB, IBRS, EIBRS; no STUFF;
    #   CONFIG_CPU_UNRET_ENTRY, CONFIG_CPU_IBPB_ENTRY, CONFIG_CPU_IBRS_ENTRY (old names).
    # rocky9 (~6.x): same as mainline; CONFIG_MITIGATION_* names; has STUFF.
    # rocky10 (~6.12+): same as mainline; has select/update/apply split.
    #
    # --- Kconfig symbols ---
    # f43b9876e857 (v5.19-rc7): CONFIG_CPU_UNRET_ENTRY, CONFIG_CPU_IBPB_ENTRY,
    #   CONFIG_CPU_IBRS_ENTRY
    # 80e4c1cd42ff (v6.2-rc1): CONFIG_CALL_DEPTH_TRACKING
    # ac61d43983a4 (v6.9-rc1): renamed to CONFIG_MITIGATION_UNRET_ENTRY,
    #   CONFIG_MITIGATION_IBPB_ENTRY, CONFIG_MITIGATION_IBRS_ENTRY,
    #   CONFIG_MITIGATION_CALL_DEPTH_TRACKING
    # 894e28857c11 (v6.12-rc1): CONFIG_MITIGATION_RETBLEED (master switch)
    #
    # --- kernel functions (for $opt_map / System.map) ---
    # 7fbf47c7ce50 (v5.19-rc7): retbleed_select_mitigation()
    # e3b78a7ad5ea (v6.16-rc1): split into retbleed_select_mitigation() +
    #   retbleed_update_mitigation() + retbleed_apply_mitigation()
    # vendor kernels: centos7/rocky8/rocky9 have retbleed_select_mitigation() only;
    #   rocky10 has the full split.
    #
    # --- CPU affection logic (for is_cpu_affected) ---
    # X86_BUG_RETBLEED is set when X86_FEATURE_BTC_NO is NOT set AND either:
    #   (a) CPU matches cpu_vuln_blacklist[] RETBLEED entries, OR
    #   (b) ARCH_CAP_RSBA is set in IA32_ARCH_CAPABILITIES MSR
    # 6b80b59b3555 (v5.19-rc7, initial AMD):
    #   AMD: family 0x15, 0x16, 0x17; Hygon: family 0x18
    # 6ad0ad2bf8a6 (v5.19-rc7, Intel):
    #   Intel: SKYLAKE_L, SKYLAKE, SKYLAKE_X, KABYLAKE_L, KABYLAKE,
    #     ICELAKE_L, COMETLAKE, COMETLAKE_L, LAKEFIELD, ROCKETLAKE
    #   + any Intel with ARCH_CAP_RSBA set
    # 26aae8ccbc19 (v5.19-rc7, BTC_NO):
    #   AMD Zen 3+ with BTC_NO are excluded
    # f54d45372c6a (post-v5.19, Cannon Lake):
    #   Intel: + CANNONLAKE_L
    # immunity: X86_FEATURE_BTC_NO (AMD) — Zen 3+ declare not affected
    # vendor scope: AMD (0x15-0x17), Hygon (0x18), Intel (Skylake through Rocket Lake + RSBA)
    #

    if sys_interface_check "$VULN_SYSFS_BASE/retbleed"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        status=$ret_sys_interface_check_status
    fi

    if [ "$opt_sysfs_only" != 1 ]; then
        pr_info_nol "* Kernel supports mitigation: "
        if [ -n "$g_kernel_err" ]; then
            kernel_retbleed_err="$g_kernel_err"
        elif grep -q 'retbleed' "$g_kernel"; then
            kernel_retbleed="found retbleed mitigation logic in kernel image"
        fi
        if [ -z "$kernel_retbleed" ] && [ -n "$opt_map" ]; then
            if grep -q 'retbleed_select_mitigation' "$opt_map"; then
                kernel_retbleed="found retbleed_select_mitigation in System.map"
            fi
        fi
        if [ -n "$kernel_retbleed" ]; then
            pstatus green YES "$kernel_retbleed"
        elif [ -n "$kernel_retbleed_err" ]; then
            pstatus yellow UNKNOWN "$kernel_retbleed_err"
        else
            pstatus yellow NO
        fi

        pr_info_nol "* Kernel compiled with UNRET_ENTRY support (untrained return thunk): "
        if [ -r "$opt_config" ]; then
            # CONFIG_CPU_UNRET_ENTRY: Linux < 6.9
            # CONFIG_MITIGATION_UNRET_ENTRY: Linux >= 6.9
            if grep -Eq '^CONFIG_(CPU|MITIGATION)_UNRET_ENTRY=y' "$opt_config"; then
                pstatus green YES
                kernel_unret="CONFIG_(CPU|MITIGATION)_UNRET_ENTRY=y found in kernel config"
            else
                pstatus yellow NO
            fi
        else
            if [ -n "$g_kernel_err" ]; then
                pstatus yellow UNKNOWN "$g_kernel_err"
            elif [ -n "$kernel_retbleed" ]; then
                # if the kernel has retbleed logic, assume UNRET_ENTRY is likely compiled in
                # (we can't tell for certain without the config)
                kernel_unret="retbleed mitigation logic present in kernel (UNRET_ENTRY status unknown)"
                pstatus yellow UNKNOWN "kernel has retbleed mitigation but config not available to verify"
            else
                pstatus yellow NO "your kernel is too old and doesn't have the retbleed mitigation logic"
            fi
        fi

        pr_info_nol "* Kernel compiled with IBPB_ENTRY support: "
        if [ -r "$opt_config" ]; then
            # CONFIG_CPU_IBPB_ENTRY: Linux < 6.9
            # CONFIG_MITIGATION_IBPB_ENTRY: Linux >= 6.9
            if grep -Eq '^CONFIG_(CPU|MITIGATION)_IBPB_ENTRY=y' "$opt_config"; then
                pstatus green YES
                kernel_ibpb_entry="CONFIG_(CPU|MITIGATION)_IBPB_ENTRY=y found in kernel config"
            else
                pstatus yellow NO
            fi
        else
            if [ -n "$g_kernel_err" ]; then
                pstatus yellow UNKNOWN "$g_kernel_err"
            elif [ -n "$kernel_retbleed" ]; then
                kernel_ibpb_entry="retbleed mitigation logic present in kernel (IBPB_ENTRY status unknown)"
                pstatus yellow UNKNOWN "kernel has retbleed mitigation but config not available to verify"
            else
                pstatus yellow NO "your kernel is too old and doesn't have the retbleed mitigation logic"
            fi
        fi

        # Zen/Zen+/Zen2: check IBPB microcode support and SMT
        if [ "$cpu_family" = $((0x17)) ]; then
            pr_info_nol "* CPU supports IBPB: "
            if [ "$opt_live" = 1 ]; then
                if [ -n "$cap_ibpb" ]; then
                    pstatus green YES "$cap_ibpb"
                else
                    pstatus yellow NO
                fi
            else
                pstatus blue N/A "not testable in offline mode"
            fi

            pr_info_nol "* Hyper-Threading (SMT) is enabled: "
            is_cpu_smt_enabled
            smt_enabled=$?
            if [ "$smt_enabled" = 0 ]; then
                pstatus yellow YES
            else
                pstatus green NO
            fi
        fi

    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ "$opt_sysfs_only" != 1 ]; then
            if [ "$cpu_family" = $((0x17)) ]; then
                # Zen/Zen+/Zen2
                if [ -z "$kernel_retbleed" ]; then
                    pvulnstatus "$cve" VULN "Your kernel is too old and doesn't have the retbleed mitigation logic"
                elif [ "$opt_paranoid" = 1 ] && [ "$smt_enabled" = 0 ]; then
                    pvulnstatus "$cve" VULN "SMT is enabled, which weakens the IBPB-based mitigation"
                    explain "For Zen/Zen+/Zen2 CPUs in paranoid mode, proper mitigation needs SMT to be disabled\n" \
                        "(this can be done by adding \`nosmt\` to your kernel command line), because IBPB alone\n" \
                        "doesn't fully protect cross-thread speculation."
                elif [ -z "$kernel_unret" ] && [ -z "$kernel_ibpb_entry" ]; then
                    pvulnstatus "$cve" VULN "Your kernel doesn't have either UNRET_ENTRY or IBPB_ENTRY compiled-in"
                elif [ "$smt_enabled" = 0 ] && [ -z "$cap_ibpb" ] && [ "$opt_live" = 1 ]; then
                    pvulnstatus "$cve" VULN "SMT is enabled and your microcode doesn't support IBPB"
                    explain "Update your CPU microcode to get IBPB support, or disable SMT by adding\n" \
                        "\`nosmt\` to your kernel command line."
                else
                    pvulnstatus "$cve" OK "Your kernel and CPU support mitigation"
                fi
            elif [ "$cpu_family" = $((0x15)) ] || [ "$cpu_family" = $((0x16)) ]; then
                # older AMD families: basic mitigation check
                if [ -z "$kernel_retbleed" ]; then
                    pvulnstatus "$cve" VULN "Your kernel is too old and doesn't have the retbleed mitigation logic"
                elif [ -n "$kernel_unret" ] || [ -n "$kernel_ibpb_entry" ]; then
                    pvulnstatus "$cve" OK "Your kernel supports mitigation"
                else
                    pvulnstatus "$cve" VULN "Your kernel doesn't have UNRET_ENTRY or IBPB_ENTRY compiled-in"
                fi
            else
                # not supposed to happen
                pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
            fi
        else
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
        fi
    else
        pvulnstatus "$cve" "$status" "$msg"
    fi
}

check_CVE_2022_29900_bsd() {
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
    fi
}

# >>>>>> vulns/CVE-2022-29901.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2022-29901, Retbleed (Intel), RSB Alternate Behavior (RSBA)

check_CVE_2022_29901() {
    check_cve 'CVE-2022-29901'
}

check_CVE_2022_29901_linux() {
    local status sys_interface_available msg kernel_retbleed kernel_retbleed_err kernel_ibrs_entry
    status=UNK
    sys_interface_available=0
    msg=''

    #
    # Kernel source inventory for retbleed (CVE-2022-29900 / CVE-2022-29901)
    #
    # See CVE-2022-29900.sh for the full sysfs/Kconfig/function/stable/vendor inventory.
    #
    # Intel-specific notes:
    # - eIBRS (IBRS_ALL) mitigates the vulnerability on Intel
    # - plain retpoline does NOT mitigate on RSBA-capable CPUs (Retbleed bypasses retpoline)
    # - IBRS entry also mitigates
    # - call depth tracking / stuffing mitigates (v6.2+)
    #
    # --- Kconfig symbols (Intel-relevant) ---
    # CONFIG_CPU_IBRS_ENTRY (< 6.9) / CONFIG_MITIGATION_IBRS_ENTRY (>= 6.9): Intel IBRS
    # CONFIG_CALL_DEPTH_TRACKING (< 6.9) / CONFIG_MITIGATION_CALL_DEPTH_TRACKING (>= 6.9): stuffing
    #
    # --- CPU affection logic (Intel) ---
    # 6ad0ad2bf8a6 (v5.19-rc7, initial Intel list):
    #   SKYLAKE_L, SKYLAKE, SKYLAKE_X, KABYLAKE_L, KABYLAKE,
    #   ICELAKE_L, COMETLAKE, COMETLAKE_L, LAKEFIELD, ROCKETLAKE
    # f54d45372c6a (post-v5.19): + CANNONLAKE_L
    # + any Intel with ARCH_CAP_RSBA set in IA32_ARCH_CAPABILITIES MSR (bit 2)
    # immunity: none (no _NO bit for RETBLEED on Intel; eIBRS is a mitigation, not immunity)
    #

    if sys_interface_check "$VULN_SYSFS_BASE/retbleed"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        status=$ret_sys_interface_check_status
    fi

    if [ "$opt_sysfs_only" != 1 ]; then
        pr_info_nol "* Kernel supports mitigation: "
        if [ -n "$g_kernel_err" ]; then
            kernel_retbleed_err="$g_kernel_err"
        elif grep -q 'retbleed' "$g_kernel"; then
            kernel_retbleed="found retbleed mitigation logic in kernel image"
        fi
        if [ -z "$kernel_retbleed" ] && [ -n "$opt_map" ]; then
            if grep -q 'retbleed_select_mitigation' "$opt_map"; then
                kernel_retbleed="found retbleed_select_mitigation in System.map"
            fi
        fi
        if [ -n "$kernel_retbleed" ]; then
            pstatus green YES "$kernel_retbleed"
        elif [ -n "$kernel_retbleed_err" ]; then
            pstatus yellow UNKNOWN "$kernel_retbleed_err"
        else
            pstatus yellow NO
        fi

        pr_info_nol "* Kernel compiled with IBRS_ENTRY support: "
        if [ -r "$opt_config" ]; then
            # CONFIG_CPU_IBRS_ENTRY: Linux < 6.9
            # CONFIG_MITIGATION_IBRS_ENTRY: Linux >= 6.9
            if grep -Eq '^CONFIG_(CPU|MITIGATION)_IBRS_ENTRY=y' "$opt_config"; then
                pstatus green YES
                kernel_ibrs_entry="CONFIG_(CPU|MITIGATION)_IBRS_ENTRY=y found in kernel config"
            else
                pstatus yellow NO
            fi
        else
            if [ -n "$g_kernel_err" ]; then
                pstatus yellow UNKNOWN "$g_kernel_err"
            elif [ -n "$kernel_retbleed" ]; then
                kernel_ibrs_entry="retbleed mitigation logic present in kernel (IBRS_ENTRY status unknown)"
                pstatus yellow UNKNOWN "kernel has retbleed mitigation but config not available to verify"
            else
                pstatus yellow NO "your kernel is too old and doesn't have the retbleed mitigation logic"
            fi
        fi

        pr_info_nol "* CPU supports Enhanced IBRS (IBRS_ALL): "
        if [ "$opt_live" = 1 ] || [ "$cap_ibrs_all" != -1 ]; then
            if [ "$cap_ibrs_all" = 1 ]; then
                pstatus green YES
            elif [ "$cap_ibrs_all" = 0 ]; then
                pstatus yellow NO
            else
                pstatus yellow UNKNOWN
            fi
        else
            pstatus blue N/A "not testable in offline mode"
        fi

        pr_info_nol "* CPU has RSB Alternate Behavior (RSBA): "
        if [ "$opt_live" = 1 ] || [ "$cap_rsba" != -1 ]; then
            if [ "$cap_rsba" = 1 ]; then
                pstatus yellow YES "this CPU is affected by RSB underflow"
            elif [ "$cap_rsba" = 0 ]; then
                pstatus green NO
            else
                pstatus yellow UNKNOWN
            fi
        else
            pstatus blue N/A "not testable in offline mode"
        fi

    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ "$opt_sysfs_only" != 1 ]; then
            if [ -z "$kernel_retbleed" ]; then
                pvulnstatus "$cve" VULN "Your kernel is too old and doesn't have the retbleed mitigation logic"
            elif [ "$cap_ibrs_all" = 1 ]; then
                if [ "$opt_paranoid" = 1 ] && [ "$cap_rrsba" = 1 ]; then
                    pvulnstatus "$cve" VULN "eIBRS is enabled but RRSBA is present, which may weaken the mitigation"
                    explain "In paranoid mode, the combination of eIBRS and RRSBA (Restricted RSB Alternate Behavior)\n" \
                        "is flagged because RRSBA means the RSB can still be influenced in some scenarios.\n" \
                        "Check if your firmware/kernel supports disabling RRSBA via RRSBA_CTRL."
                else
                    pvulnstatus "$cve" OK "Enhanced IBRS (IBRS_ALL) mitigates the vulnerability"
                fi
            elif [ -n "$kernel_ibrs_entry" ]; then
                pvulnstatus "$cve" OK "Your kernel has IBRS_ENTRY mitigation compiled-in"
            else
                pvulnstatus "$cve" VULN "Your kernel has retbleed mitigation but IBRS_ENTRY is not compiled-in and eIBRS is not available"
                explain "Retpoline alone does NOT mitigate Retbleed on RSBA-capable Intel CPUs.\n" \
                    "You need either Enhanced IBRS (eIBRS, via firmware/microcode update) or a kernel\n" \
                    "compiled with IBRS_ENTRY support (Linux 5.19+, CONFIG_(CPU|MITIGATION)_IBRS_ENTRY)."
            fi
        else
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
        fi
    else
        pvulnstatus "$cve" "$status" "$msg"
    fi
}

check_CVE_2022_29901_bsd() {
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
    fi
}

# >>>>>> vulns/CVE-2022-40982.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2022-40982, Downfall, GDS, Gather Data Sampling

check_CVE_2022_40982() {
    check_cve 'CVE-2022-40982'
}

check_CVE_2022_40982_linux() {
    local status sys_interface_available msg kernel_gds kernel_gds_err kernel_avx_disabled dmesgret ret
    status=UNK
    sys_interface_available=0
    msg=''

    if sys_interface_check "$VULN_SYSFS_BASE/gather_data_sampling"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        #
        # Kernel source inventory for gather_data_sampling (GDS/Downfall)
        #
        # --- sysfs messages ---
        # all versions:
        #   "Not affected"                                  (cpu_show_common, pre-existing)
        #
        # --- mainline ---
        # 8974eb588283 (v6.5-rc6, initial GDS sysfs):
        #   "Vulnerable"                                    (GDS_MITIGATION_OFF)
        #   "Vulnerable: No microcode"                      (GDS_MITIGATION_UCODE_NEEDED)
        #   "Mitigation: Microcode"                         (GDS_MITIGATION_FULL)
        #   "Mitigation: Microcode (locked)"                (GDS_MITIGATION_FULL_LOCKED)
        #   "Unknown: Dependent on hypervisor status"       (GDS_MITIGATION_HYPERVISOR)
        # 553a5c03e90a (v6.5-rc6, added force option):
        #   "Mitigation: AVX disabled, no microcode"        (GDS_MITIGATION_FORCE)
        # 53cf5797f114 (v6.5-rc6, added CONFIG_GDS_FORCE_MITIGATION):
        #   no string changes; default becomes FORCE when Kconfig enabled
        # 81ac7e5d7417 (v6.5-rc6, KVM GDS_NO plumbing):
        #   no string changes
        # be83e809ca67 (v6.9-rc1, Kconfig rename):
        #   no string changes; CONFIG_GDS_FORCE_MITIGATION => CONFIG_MITIGATION_GDS_FORCE
        # 03267a534bb3 (v6.12-rc1, removed force Kconfig):
        #   no string changes; CONFIG_MITIGATION_GDS_FORCE removed
        # 225f2bd064c3 (v6.12-rc1, added on/off Kconfig):
        #   no string changes; added CONFIG_MITIGATION_GDS (default y)
        # 9dcad2fb31bd (v6.16-rc1, restructured select/apply):
        #   no string changes; added GDS_MITIGATION_AUTO (internal, resolved before display)
        #   split gds_select_mitigation() + gds_apply_mitigation()
        # d4932a1b148b (v6.17-rc3, bug fix):
        #   no string changes; CPUs without ARCH_CAP_GDS_CTRL were incorrectly classified
        #   as OFF ("Vulnerable") instead of UCODE_NEEDED ("Vulnerable: No microcode"),
        #   and locked-mitigation detection was skipped.
        #   NOT backported to any stable or RHEL branch as of 2026-04.
        #
        # --- stable backports ---
        # 5.4.y, 5.10.y, 5.15.y, 6.1.y, 6.6.y: same 7 strings as mainline.
        #   use CONFIG_GDS_FORCE_MITIGATION; no GDS_MITIGATION_AUTO enum;
        #   missing d4932a1b148b bug fix (UCODE_NEEDED vs OFF misclassification).
        # 6.12.y: same 7 strings as mainline.
        #   uses CONFIG_MITIGATION_GDS; no GDS_MITIGATION_AUTO enum;
        #   missing d4932a1b148b bug fix.
        #
        # --- RHEL/CentOS ---
        # centos7 (3.10), rocky8 (4.18): same 7 strings; CONFIG_GDS_FORCE_MITIGATION.
        #   centos7 uses sprintf (not sysfs_emit) and __read_mostly.
        # rocky9 (5.14): same 7 strings; CONFIG_MITIGATION_GDS (skipped FORCE rename).
        # rocky10 (6.12): same 7 strings; CONFIG_MITIGATION_GDS; has gds_apply_mitigation().
        #
        # --- Kconfig symbols ---
        # 53cf5797f114 (v6.5-rc6): CONFIG_GDS_FORCE_MITIGATION (default n)
        # be83e809ca67 (v6.9-rc1): renamed to CONFIG_MITIGATION_GDS_FORCE
        # 03267a534bb3 (v6.12-rc1): CONFIG_MITIGATION_GDS_FORCE removed
        # 225f2bd064c3 (v6.12-rc1): CONFIG_MITIGATION_GDS (default y)
        # vendor kernels: rocky9 uses CONFIG_MITIGATION_GDS on 5.14-based kernel
        #
        # --- kernel functions (for $opt_map / System.map) ---
        # 8974eb588283 (v6.5-rc6): gds_select_mitigation(), update_gds_msr(),
        #   gds_parse_cmdline(), gds_show_state()
        # 81ac7e5d7417 (v6.5-rc6): gds_ucode_mitigated() (exported for KVM)
        # 9dcad2fb31bd (v6.16-rc1): split into gds_select_mitigation() + gds_apply_mitigation()
        # stable 5.4.y-6.12.y: same 5 functions (no gds_apply_mitigation)
        # rocky10 (6.12): has gds_apply_mitigation()
        #
        # --- CPU affection logic (for is_cpu_affected) ---
        # X86_BUG_GDS is set when ALL three conditions are true:
        #   1. CPU matches model blacklist (cpu_vuln_blacklist[] in common.c)
        #   2. ARCH_CAP_GDS_NO (bit 26 of IA32_ARCH_CAPABILITIES) is NOT set
        #   3. X86_FEATURE_AVX is present (GATHER instructions require AVX)
        # 8974eb588283 (v6.5-rc6, initial model list):
        #   Intel: SKYLAKE_X, KABYLAKE_L, KABYLAKE, ICELAKE_L, ICELAKE_D,
        #          ICELAKE_X, COMETLAKE, COMETLAKE_L, TIGERLAKE_L, TIGERLAKE,
        #          ROCKETLAKE (all steppings)
        # c9f4c45c8ec3 (v6.5-rc6, added missing client Skylake):
        #   Intel: + SKYLAKE_L, SKYLAKE
        # 159013a7ca18 (v6.10-rc1, ITS stepping splits):
        #   no GDS model changes; some entries split by stepping for ITS but
        #   GDS flag remains on all stepping ranges for these models
        # immunity: ARCH_CAP_GDS_NO (bit 26 of IA32_ARCH_CAPABILITIES)
        # feature dependency: requires AVX (if AVX absent, CPU is immune)
        # vendor scope: Intel only
        #
        # all messages start with either "Not affected", "Vulnerable", "Mitigation",
        # or "Unknown"
        status=$ret_sys_interface_check_status
    fi

    if [ "$opt_sysfs_only" != 1 ]; then
        pr_info_nol "* GDS is mitigated by microcode: "
        if [ "$cap_gds_ctrl" = 1 ] && [ "$cap_gds_mitg_dis" = 0 ]; then
            pstatus green OK "microcode mitigation is supported and enabled"
        elif [ "$cap_gds_ctrl" = 1 ] && [ "$cap_gds_mitg_dis" = 1 ]; then
            pstatus yellow NO "microcode mitigation is supported but disabled"
        elif [ "$cap_gds_ctrl" = 0 ]; then
            pstatus yellow NO "microcode doesn't support GDS mitigation"
        else
            pstatus yellow UNKNOWN "couldn't read MSR for GDS capability"
        fi

        pr_info_nol "* Kernel supports software mitigation by disabling AVX: "
        kernel_gds=''
        kernel_gds_err=''
        if [ -n "$g_kernel_err" ]; then
            kernel_gds_err="$g_kernel_err"
        elif grep -q 'gather_data_sampling' "$g_kernel"; then
            kernel_gds="found gather_data_sampling in kernel image"
        fi
        if [ -z "$kernel_gds" ] && [ -r "$opt_config" ]; then
            if grep -q '^CONFIG_GDS_FORCE_MITIGATION=y' "$opt_config" ||
                grep -q '^CONFIG_MITIGATION_GDS_FORCE=y' "$opt_config" ||
                grep -q '^CONFIG_MITIGATION_GDS=y' "$opt_config"; then
                kernel_gds="GDS mitigation config option found enabled in kernel config"
            fi
        fi
        if [ -z "$kernel_gds" ] && [ -n "$opt_map" ]; then
            if grep -q 'gds_select_mitigation' "$opt_map"; then
                kernel_gds="found gds_select_mitigation in System.map"
            fi
        fi
        if [ -n "$kernel_gds" ]; then
            pstatus green YES "$kernel_gds"
        elif [ -n "$kernel_gds_err" ]; then
            pstatus yellow UNKNOWN "$kernel_gds_err"
        else
            pstatus yellow NO
        fi

        if [ -n "$kernel_gds" ]; then
            pr_info_nol "* Kernel has disabled AVX as a mitigation: "

            if [ "$opt_live" = 1 ]; then
                # Check dmesg message to see whether AVX has been disabled
                dmesg_grep 'Microcode update needed! Disabling AVX as mitigation'
                dmesgret=$?
                if [ "$dmesgret" -eq 0 ]; then
                    kernel_avx_disabled="AVX disabled by the kernel (dmesg)"
                    pstatus green YES "$kernel_avx_disabled"
                elif [ "$cap_avx2" = 0 ]; then
                    # Find out by ourselves
                    # cpuinfo says we don't have AVX2, query
                    # the CPU directly about AVX2 support
                    read_cpuid 0x7 0x0 "$EBX" 5 1 1
                    ret=$?
                    if [ "$ret" -eq "$READ_CPUID_RET_OK" ]; then
                        kernel_avx_disabled="AVX disabled by the kernel (cpuid)"
                        pstatus green YES "$kernel_avx_disabled"
                    elif [ "$ret" -eq "$READ_CPUID_RET_KO" ]; then
                        pstatus yellow NO "CPU doesn't support AVX"
                    elif [ "$dmesgret" -eq 2 ]; then
                        pstatus yellow UNKNOWN "dmesg truncated, can't tell whether mitigation is active, please reboot and relaunch this script"
                    else
                        pstatus yellow UNKNOWN "No sign of mitigation in dmesg and couldn't read cpuid info"
                    fi
                else
                    pstatus yellow NO "AVX support is enabled"
                fi
            else
                pstatus blue N/A "not testable in offline mode"
            fi
        fi

    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ "$opt_sysfs_only" != 1 ]; then
            if [ "$cap_gds_ctrl" = 1 ] && [ "$cap_gds_mitg_dis" = 0 ]; then
                if [ "$opt_paranoid" = 1 ] && [ "$cap_gds_mitg_lock" != 1 ]; then
                    pvulnstatus "$cve" VULN "Microcode mitigation is enabled but not locked"
                    explain "In paranoid mode, the GDS mitigation must be locked to prevent a privileged attacker\n " \
                        "(e.g. in a guest VM) from disabling it. Check your firmware/BIOS for an option to lock the\n " \
                        "GDS mitigation, or update your microcode."
                else
                    pvulnstatus "$cve" OK "Your microcode is up to date and mitigation is enabled"
                fi
            elif [ "$cap_gds_ctrl" = 1 ] && [ "$cap_gds_mitg_dis" = 1 ]; then
                pvulnstatus "$cve" VULN "Your microcode is up to date but mitigation is disabled"
                explain "The GDS mitigation has been explicitly disabled (gather_data_sampling=off or mitigations=off).\n " \
                    "Remove the kernel parameter to re-enable it."
            elif [ -z "$kernel_gds" ]; then
                pvulnstatus "$cve" VULN "Your microcode doesn't mitigate the vulnerability, and your kernel doesn't support mitigation"
                explain "Update both your CPU microcode (via BIOS/firmware update from your OEM) and your kernel\n " \
                    "to a version that supports GDS mitigation (Linux 6.5+, or check if your distro has a backport)."
            elif [ -z "$kernel_avx_disabled" ]; then
                pvulnstatus "$cve" VULN "Your microcode doesn't mitigate the vulnerability, your kernel supports the mitigation but AVX was not disabled"
                explain "Update your CPU microcode (via BIOS/firmware update from your OEM). If no microcode update\n " \
                    "is available, use gather_data_sampling=force on the kernel command line to disable AVX as a workaround."
            else
                pvulnstatus "$cve" OK "Your microcode doesn't mitigate the vulnerability, but your kernel has disabled AVX support"
            fi
        else
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
        fi
    else
        pvulnstatus "$cve" "$status" "$msg"
    fi
}

check_CVE_2022_40982_bsd() {
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
    fi
}

# >>>>>> vulns/CVE-2023-20569.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2023-20569, Inception, SRSO, Return Address Security

check_CVE_2023_20569() {
    check_cve 'CVE-2023-20569'
}

check_CVE_2023_20569_linux() {
    local status sys_interface_available msg kernel_sro kernel_sro_err kernel_srso kernel_ibpb_entry smt_enabled
    status=UNK
    sys_interface_available=0
    msg=''

    if sys_interface_check "$VULN_SYSFS_BASE/spec_rstack_overflow"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        status=$ret_sys_interface_check_status
        # kernels before the fix from dc6306ad5b0d (v6.6-rc6, backported to v6.5.6)
        # incorrectly reported "Mitigation: safe RET, no microcode" as mitigated,
        # when in fact userspace is still vulnerable because IBPB doesn't flush
        # branch type predictions without the extending microcode.
        # override the sysfs status in that case.
        if echo "$ret_sys_interface_check_fullmsg" | grep -qi 'Mitigation:.*safe RET.*no microcode'; then
            status=VULN
            msg="Vulnerable: Safe RET, no microcode (your kernel incorrectly reports this as mitigated, it was fixed in more recent kernels)"
        fi
    fi

    if [ "$opt_sysfs_only" != 1 ]; then
        pr_info_nol "* Kernel supports mitigation: "
        if [ -n "$g_kernel_err" ]; then
            kernel_sro_err="$g_kernel_err"
        elif grep -q 'spec_rstack_overflow' "$g_kernel"; then
            kernel_sro="found spec_rstack_overflow in kernel image"
        fi
        if [ -n "$kernel_sro" ]; then
            pstatus green YES "$kernel_sro"
        elif [ -n "$kernel_sro_err" ]; then
            pstatus yellow UNKNOWN "$kernel_sro_err"
        else
            pstatus yellow NO
        fi

        pr_info_nol "* Kernel compiled with SRSO support: "
        if [ -r "$opt_config" ]; then
            # CONFIG_CPU_SRSO: Linux < 6.9
            # CONFIG_MITIGATION_SRSO: Linux >= 6.9
            if grep -Eq '^CONFIG_(CPU|MITIGATION)_SRSO=y' "$opt_config"; then
                pstatus green YES
                kernel_srso="CONFIG_(CPU|MITIGATION)_SRSO=y found in kernel config"
            else
                pstatus yellow NO "required for safe RET and ibpb_on_vmexit mitigations"
            fi
        else
            # https://github.com/torvalds/linux/commit/138bcddb86d8a4f842e4ed6f0585abc9b1a764ff#diff-17bd24a7a7850613cced545790ac30646097e8d6207348c2bd1845f397acb390R2313
            if [ -n "$g_kernel_err" ]; then
                pstatus yellow UNKNOWN "$g_kernel_err"
            elif grep -Eq 'WARNING: kernel not compiled with (CPU|MITIGATION)_SRSO' "$g_kernel"; then
                # this msg is optimized out at compile time if the option is not enabled, see commit referenced above
                # if it's present, then SRSO is NOT compiled in
                pstatus yellow NO "kernel not compiled with (CPU|MITIGATION)_SRSO"
            else
                # if it's not present, then SRSO is compiled in IF kernel_sro is set, otherwise we're just
                # in front of an old kernel that doesn't have the mitigation logic at all
                if [ -n "$kernel_sro" ]; then
                    kernel_srso="SRSO mitigation logic is compiled in the kernel"
                    pstatus green OK "$kernel_srso"
                else
                    pstatus yellow NO "your kernel is too old and doesn't have the mitigation logic"
                fi
            fi
        fi

        # check whether the running kernel has the corrected SRSO reporting
        # (dc6306ad5b0d, v6.6-rc6, backported to v6.5.6): kernels with the fix
        # contain the string "Vulnerable: Safe RET, no microcode" in their image,
        # while older kernels only have "safe RET" (and append ", no microcode" dynamically).
        pr_info_nol "* Kernel has accurate SRSO reporting: "
        if [ -n "$g_kernel_err" ]; then
            pstatus yellow UNKNOWN "$g_kernel_err"
        elif grep -q 'Vulnerable: Safe RET, no microcode' "$g_kernel"; then
            pstatus green YES
        elif [ -n "$kernel_sro" ]; then
            pstatus yellow NO "your kernel reports partial SRSO mitigations as fully mitigated, upgrade recommended"
        else
            pstatus yellow NO "your kernel is too old and doesn't have the SRSO mitigation logic"
        fi

        pr_info_nol "* Kernel compiled with IBPB_ENTRY support: "
        if [ -r "$opt_config" ]; then
            # CONFIG_CPU_IBPB_ENTRY: Linux < 6.9
            # CONFIG_MITIGATION_IBPB_ENTRY: Linux >= 6.9
            if grep -Eq '^CONFIG_(CPU|MITIGATION)_IBPB_ENTRY=y' "$opt_config"; then
                pstatus green YES
                kernel_ibpb_entry="CONFIG_(CPU|MITIGATION)_IBPB_ENTRY=y found in kernel config"
            else
                pstatus yellow NO
            fi
        else
            # https://github.com/torvalds/linux/commit/138bcddb86d8a4f842e4ed6f0585abc9b1a764ff#diff-17bd24a7a7850613cced545790ac30646097e8d6207348c2bd1845f397acb390R2325
            if [ -n "$g_kernel_err" ]; then
                pstatus yellow UNKNOWN "$g_kernel_err"
            elif grep -Eq 'WARNING: kernel not compiled with (CPU|MITIGATION)_IBPB_ENTRY' "$g_kernel"; then
                # this msg is optimized out at compile time if the option is not enabled, see commit referenced above
                # if it's present, then IBPB_ENTRY is NOT compiled in
                pstatus yellow NO "kernel not compiled with (CPU|MITIGATION)_IBPB_ENTRY"
            else
                # if it's not present, then IBPB_ENTRY is compiled in IF kernel_sro is set, otherwise we're just
                # in front of an old kernel that doesn't have the mitigation logic at all
                if [ -n "$kernel_sro" ]; then
                    kernel_ibpb_entry="IBPB_ENTRY mitigation logic is compiled in the kernel"
                    pstatus green OK "$kernel_ibpb_entry"
                else
                    pstatus yellow NO "your kernel is too old and doesn't have the mitigation logic"
                fi
            fi
        fi

        # Zen & Zen2 : if the right IBPB microcode applied + SMT off --> not vuln
        if [ "$cpu_family" = $((0x17)) ]; then
            pr_info_nol "* CPU supports IBPB: "
            if [ -n "$cap_ibpb" ]; then
                pstatus green YES "$cap_ibpb"
            else
                pstatus yellow NO
            fi

            pr_info_nol "* Hyper-Threading (SMT) is enabled: "
            is_cpu_smt_enabled
            smt_enabled=$?
            if [ "$smt_enabled" = 0 ]; then
                pstatus yellow YES
            else
                pstatus green NO
            fi
        # Zen 3/4 microcode brings SBPB mitigation
        elif [ "$cpu_family" = $((0x19)) ]; then
            pr_info_nol "* CPU supports SBPB: "
            if [ "$cap_sbpb" = 1 ]; then
                pstatus green YES
            elif [ "$cap_sbpb" = 3 ]; then
                pstatus yellow UNKNOWN "cannot write MSR, rerun with --allow-msr-write"
            else
                pstatus yellow NO
            fi
        fi

    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ "$opt_sysfs_only" != 1 ]; then
            # Zen/Zen2
            if [ "$cpu_family" = $((0x17)) ]; then
                if [ "$smt_enabled" = 0 ]; then
                    pvulnstatus "$cve" VULN "SMT is enabled on your Zen/Zen2 CPU, which makes mitigation ineffective"
                    explain "For Zen/Zen2 CPUs, proper mitigation needs an up to date microcode, and SMT needs to be disabled (this can be done by adding \`nosmt\` to your kernel command line)"
                elif [ -z "$kernel_sro" ]; then
                    pvulnstatus "$cve" VULN "Your kernel is too old and doesn't have the SRSO mitigation logic"
                elif [ -n "$cap_ibpb" ]; then
                    pvulnstatus "$cve" OK "SMT is disabled and both your kernel and microcode support mitigation"
                else
                    pvulnstatus "$cve" VULN "Your microcode is too old"
                fi
            # Zen3/Zen4
            elif [ "$cpu_family" = $((0x19)) ]; then
                if [ -z "$kernel_sro" ]; then
                    pvulnstatus "$cve" VULN "Your kernel is too old and doesn't have the SRSO mitigation logic"
                elif [ -z "$kernel_srso" ] && [ -z "$kernel_ibpb_entry" ]; then
                    pvulnstatus "$cve" VULN "Your kernel doesn't have either SRSO or IBPB_ENTRY compiled-in"
                elif [ "$cap_sbpb" = 3 ]; then
                    pvulnstatus "$cve" UNK "Couldn't verify if your microcode supports IBPB (rerun with --allow-msr-write)"
                elif [ "$cap_sbpb" = 2 ]; then
                    pvulnstatus "$cve" VULN "Your microcode doesn't support SBPB"
                else
                    pvulnstatus "$cve" OK "Your kernel and microcode both support mitigation"
                fi
            else
                # not supposed to happen, as normally this CPU should not be affected and not run this code
                pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
            fi
        else
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
        fi
    else
        pvulnstatus "$cve" "$status" "$msg"
        if echo "$msg" | grep -qi 'your kernel incorrectly reports this as mitigated'; then
            explain "Your kernel's /sys interface reports 'Mitigation: safe RET, no microcode' for the SRSO vulnerability.\n" \
                "This was a bug in the kernel's reporting (fixed in v6.5.6/v6.6-rc6, commit dc6306ad5b0d):\n" \
                "the Safe RET mitigation alone only protects the kernel from userspace attacks, but without\n" \
                "the IBPB-extending microcode, userspace itself remains vulnerable because IBPB doesn't flush\n" \
                "branch type predictions. Newer kernels correctly report this as 'Vulnerable: Safe RET, no microcode'.\n" \
                "To fully mitigate, you need both the Safe RET kernel support AND an updated CPU microcode.\n" \
                "Updating your kernel to v6.5.6+ or v6.6+ will also give you accurate vulnerability reporting."
        fi
    fi
}

check_CVE_2023_20569_bsd() {
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
    fi
}

# >>>>>> vulns/CVE-2023-20593.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2023-20593, Zenbleed, Cross-Process Information Leak

check_CVE_2023_20593() {
    check_cve 'CVE-2023-20593'
}

check_CVE_2023_20593_linux() {
    local status sys_interface_available msg kernel_zenbleed kernel_zenbleed_err fp_backup_fix ucode_zenbleed zenbleed_print_vuln ret
    status=UNK
    sys_interface_available=0
    msg=''
    if [ "$opt_sysfs_only" != 1 ]; then
        pr_info_nol "* Zenbleed mitigation is supported by kernel: "
        kernel_zenbleed=''
        if [ -n "$g_kernel_err" ]; then
            kernel_zenbleed_err="$g_kernel_err"
        # commit 522b1d69219d8f083173819fde04f994aa051a98
        elif grep -q 'Zenbleed:' "$g_kernel"; then
            kernel_zenbleed="found zenbleed message in kernel image"
        fi
        if [ -n "$kernel_zenbleed" ]; then
            pstatus green YES "$kernel_zenbleed"
        elif [ -n "$kernel_zenbleed_err" ]; then
            pstatus yellow UNKNOWN "$kernel_zenbleed_err"
        else
            pstatus yellow NO
        fi
        pr_info_nol "* Zenbleed kernel mitigation enabled and active: "
        if [ "$opt_live" = 1 ]; then
            # read the DE_CFG MSR, we want to check the 9th bit
            # don't do it on non-Zen2 AMD CPUs or later, aka Family 17h,
            # as the behavior could be unknown on others
            if is_amd && [ "$cpu_family" -ge $((0x17)) ]; then
                read_msr 0xc0011029
                ret=$?
                if [ "$ret" = "$READ_MSR_RET_OK" ]; then
                    if [ $((ret_read_msr_value_lo >> 9 & 1)) -eq 1 ]; then
                        pstatus green YES "FP_BACKUP_FIX bit set in DE_CFG"
                        fp_backup_fix=1
                    else
                        pstatus yellow NO "FP_BACKUP_FIX is cleared in DE_CFG"
                        fp_backup_fix=0
                    fi
                elif [ "$ret" = "$READ_MSR_RET_KO" ]; then
                    pstatus yellow UNKNOWN "Couldn't read the DE_CFG MSR"
                else
                    pstatus yellow UNKNOWN "$ret_read_msr_msg"
                fi
            else
                fp_backup_fix=0
                pstatus blue N/A "CPU is incompatible"
            fi
        else
            pstatus blue N/A "not testable in offline mode"
        fi

        pr_info_nol "* Zenbleed mitigation is supported by CPU microcode: "
        has_zenbleed_fixed_firmware
        ret=$?
        if [ "$ret" -eq 0 ]; then
            pstatus green YES
            ucode_zenbleed=1
        elif [ "$ret" -eq 1 ]; then
            pstatus yellow NO
            ucode_zenbleed=2
        else
            pstatus yellow UNKNOWN
            ucode_zenbleed=3
        fi

    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        zenbleed_print_vuln=0
        if [ "$opt_live" = 1 ]; then
            if [ "$fp_backup_fix" = 1 ] && [ "$ucode_zenbleed" = 1 ]; then
                # this should never happen, but if it does, it's interesting to know
                pvulnstatus "$cve" OK "Both your CPU microcode and kernel are mitigating Zenbleed"
            elif [ "$ucode_zenbleed" = 1 ]; then
                pvulnstatus "$cve" OK "Your CPU microcode mitigates Zenbleed"
            elif [ "$fp_backup_fix" = 1 ]; then
                pvulnstatus "$cve" OK "Your kernel mitigates Zenbleed"
            else
                zenbleed_print_vuln=1
            fi
        else
            if [ "$ucode_zenbleed" = 1 ]; then
                pvulnstatus "$cve" OK "Your CPU microcode mitigates Zenbleed"
            elif [ -n "$kernel_zenbleed" ]; then
                pvulnstatus "$cve" OK "Your kernel mitigates Zenbleed"
            else
                zenbleed_print_vuln=1
            fi
        fi
        if [ "$zenbleed_print_vuln" = 1 ]; then
            pvulnstatus "$cve" VULN "Your kernel is too old to mitigate Zenbleed and your CPU microcode doesn't mitigate it either"
            explain "Your CPU vendor may have a new microcode for your CPU model that mitigates this issue (refer to the hardware section above).\n " \
                "Otherwise, the Linux kernel is able to mitigate this issue regardless of the microcode version you have, but in this case\n " \
                "your kernel is too old to support this, your Linux distribution vendor might have a more recent version you should upgrade to.\n " \
                "Note that either having an up to date microcode OR an up to date kernel is enough to mitigate this issue.\n " \
                "To manually mitigate the issue right now, you may use the following command: \`wrmsr -a 0xc0011029 \$((\$(rdmsr -c 0xc0011029) | (1<<9)))\`,\n " \
                "however note that this manual mitigation will only be active until the next reboot."
        fi
        unset zenbleed_print_vuln
    else
        pvulnstatus "$cve" "$status" "$msg"
    fi
}

check_CVE_2023_20593_bsd() {
    local zenbleed_enable zenbleed_state kernel_zenbleed
    pr_info_nol "* Kernel supports Zenbleed mitigation (machdep.mitigations.zenbleed.enable): "
    zenbleed_enable=$(sysctl -n machdep.mitigations.zenbleed.enable 2>/dev/null)
    if [ -n "$zenbleed_enable" ]; then
        kernel_zenbleed=1
        case "$zenbleed_enable" in
            0) pstatus yellow YES "force disabled" ;;
            1) pstatus green YES "force enabled" ;;
            2) pstatus green YES "automatic (default)" ;;
            *) pstatus yellow YES "unknown value: $zenbleed_enable" ;;
        esac
    else
        kernel_zenbleed=0
        pstatus yellow NO
    fi

    pr_info_nol "* Zenbleed mitigation state: "
    zenbleed_state=$(sysctl -n machdep.mitigations.zenbleed.state 2>/dev/null)
    if [ -n "$zenbleed_state" ]; then
        if echo "$zenbleed_state" | grep -qi 'not.applicable\|mitigation.enabled'; then
            pstatus green YES "$zenbleed_state"
        elif echo "$zenbleed_state" | grep -qi 'mitigation.disabled'; then
            pstatus yellow NO "$zenbleed_state"
        else
            pstatus yellow UNKNOWN "$zenbleed_state"
        fi
    else
        pstatus yellow NO "sysctl not available"
    fi

    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ "$kernel_zenbleed" = 1 ] && [ "$zenbleed_enable" != 0 ]; then
        if [ -n "$zenbleed_state" ] && echo "$zenbleed_state" | grep -qi 'mitigation.enabled'; then
            pvulnstatus "$cve" OK "Zenbleed mitigation is enabled ($zenbleed_state)"
        elif [ -n "$zenbleed_state" ] && echo "$zenbleed_state" | grep -qi 'not.applicable'; then
            pvulnstatus "$cve" OK "Zenbleed mitigation not applicable to this CPU ($zenbleed_state)"
        else
            pvulnstatus "$cve" OK "Zenbleed mitigation is enabled"
        fi
    elif [ "$kernel_zenbleed" = 1 ] && [ "$zenbleed_enable" = 0 ]; then
        pvulnstatus "$cve" VULN "Zenbleed mitigation is supported but force disabled"
        explain "To re-enable Zenbleed mitigation, run \`sysctl machdep.mitigations.zenbleed.enable=2' for automatic mode.\n " \
            "To make this persistent, add 'machdep.mitigations.zenbleed.enable=2' to /etc/sysctl.conf."
    else
        pvulnstatus "$cve" VULN "your kernel doesn't support Zenbleed mitigation, update it"
        explain "Your CPU vendor may also have a new microcode for your CPU model that mitigates this issue.\n " \
            "Updating to FreeBSD 14.0 or later will provide kernel-level Zenbleed mitigation via the\n " \
            "machdep.mitigations.zenbleed sysctl."
    fi
}

# >>>>>> vulns/CVE-2023-23583.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2023-23583, Reptar, Redundant Prefix Issue

check_CVE_2023_23583() {
    check_cve 'CVE-2023-23583'
}

check_CVE_2023_23583_linux() {
    local status sys_interface_available msg
    status=UNK
    sys_interface_available=0
    msg=''

    # there is no sysfs file for this vuln, and no kernel patch,
    # the mitigation is only ucode-based and there's no flag exposed,
    # so most of the work has already been done by is_cpu_affected()
    # shellcheck disable=SC2154
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$g_reptar_fixed_ucode_version" ]; then
        # CPU matched the model blacklist but has no known fixing microcode
        # (likely an EOL stepping that Intel won't release a fix for)
        pvulnstatus "$cve" VULN "your CPU is affected and no microcode update is available for your CPU stepping"
    else
        pr_info_nol "* Reptar is mitigated by microcode: "
        if [ "$cpu_ucode" -lt "$g_reptar_fixed_ucode_version" ]; then
            pstatus yellow NO "You have ucode $(printf "0x%x" "$cpu_ucode") and version $(printf "0x%x" "$g_reptar_fixed_ucode_version") minimum is required"
            pvulnstatus "$cve" VULN "Your microcode is too old to mitigate the vulnerability"
        else
            pstatus green YES "You have ucode $(printf "0x%x" "$cpu_ucode") which is recent enough (>= $(printf "0x%x" "$g_reptar_fixed_ucode_version"))"
            pvulnstatus "$cve" OK "Your microcode mitigates the vulnerability"
        fi
    fi
}

check_CVE_2023_23583_bsd() {
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
    fi
}

# >>>>>> vulns/CVE-2024-28956.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2024-28956, ITS, Indirect Target Selection

check_CVE_2024_28956() {
    check_cve 'CVE-2024-28956'
}

check_CVE_2024_28956_linux() {
    local status sys_interface_available msg kernel_its kernel_its_err ret
    status=UNK
    sys_interface_available=0
    msg=''

    if sys_interface_check "$VULN_SYSFS_BASE/indirect_target_selection"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        #
        # Kernel source inventory for indirect_target_selection (ITS)
        #
        # --- sysfs messages ---
        # all versions:
        #   "Not affected"                                       (cpu_show_common, pre-existing)
        #
        # --- mainline ---
        # f4818881c47f (v6.15-rc2, initial ITS sysfs):
        #   "Vulnerable"                                         (ITS_MITIGATION_OFF)
        #   "Mitigation: Aligned branch/return thunks"           (ITS_MITIGATION_ALIGNED_THUNKS)
        #   "Mitigation: Retpolines, Stuffing RSB"               (ITS_MITIGATION_RETPOLINE_STUFF)
        # 2665281a07e1 (v6.15-rc2, added vmexit option):
        #   "Mitigation: Vulnerable, KVM: Not affected"          (ITS_MITIGATION_VMEXIT_ONLY)
        # facd226f7e0c (v6.15-rc2, added stuff cmdline option):
        #   no string changes; added "stuff" boot param value
        # 61ab72c2c6bf (v6.16-rc1, restructured select/update/apply):
        #   no string changes; added ITS_MITIGATION_AUTO (internal, resolved before display)
        #   split into its_select_mitigation() + its_update_mitigation() + its_apply_mitigation()
        # 0cdd2c4f35cf (v6.18-rc1, attack vector controls):
        #   no string changes; added per-vector on/off control
        #
        # --- stable backports ---
        # 5.10.y, 5.15.y, 6.1.y: 3 strings only (no VMEXIT_ONLY, no RETPOLINE_STUFF
        #   in 5.10/5.15/6.1). Uses CONFIG_RETPOLINE/CONFIG_RETHUNK (not CONFIG_MITIGATION_*).
        # 6.6.y, 6.12.y, 6.14.y, 6.15.y: all 4 strings, full vmexit+stuff support.
        # 6.16.y+: restructured 3-phase select/update/apply.
        # Not backported to: 5.4.y, 6.11.y, 6.13.y.
        #
        # --- RHEL/CentOS ---
        # rocky9 (5.14): all 4 strings, restructured 3-phase version.
        # rocky10 (6.12): all 4 strings, restructured 3-phase version.
        # Not backported to: centos7, rocky8.
        #
        # --- Kconfig symbols ---
        # f4818881c47f (v6.15-rc2): CONFIG_MITIGATION_ITS (default y)
        #   depends on CPU_SUP_INTEL && X86_64 && MITIGATION_RETPOLINE && MITIGATION_RETHUNK
        # stable 5.10.y, 5.15.y, 6.1.y: CONFIG_MITIGATION_ITS
        #   depends on CONFIG_RETPOLINE && CONFIG_RETHUNK (pre-rename names)
        #
        # --- kernel functions (for $opt_map / System.map) ---
        # f4818881c47f (v6.15-rc2): its_select_mitigation(), its_parse_cmdline(),
        #   its_show_state()
        # 61ab72c2c6bf (v6.16-rc1): split into its_select_mitigation() +
        #   its_update_mitigation() + its_apply_mitigation()
        # stable 5.10.y-6.15.y: its_select_mitigation() (no split)
        # rocky9, rocky10: its_select_mitigation() + its_update_mitigation() +
        #   its_apply_mitigation()
        #
        # --- CPU affection logic (for is_cpu_affected) ---
        # X86_BUG_ITS is set when ALL conditions are true:
        #   1. Intel vendor, family 6
        #   2. CPU matches model blacklist (with stepping constraints)
        #   3. ARCH_CAP_ITS_NO (bit 62 of IA32_ARCH_CAPABILITIES) is NOT set
        #   4. X86_FEATURE_BHI_CTRL is NOT present
        # 159013a7ca18 (v6.15-rc2, initial model list):
        #   Intel: SKYLAKE_X (stepping > 5), KABYLAKE_L (stepping > 0xb),
        #          KABYLAKE (stepping > 0xc), ICELAKE_L, ICELAKE_D, ICELAKE_X,
        #          COMETLAKE, COMETLAKE_L, TIGERLAKE_L, TIGERLAKE, ROCKETLAKE
        #          (all steppings unless noted)
        # ITS_NATIVE_ONLY flag (X86_BUG_ITS_NATIVE_ONLY): set for
        #   ICELAKE_L, ICELAKE_D, ICELAKE_X, TIGERLAKE_L, TIGERLAKE, ROCKETLAKE
        #   These CPUs are affected for user-to-kernel but NOT guest-to-host (VMX)
        # immunity: ARCH_CAP_ITS_NO (bit 62 of IA32_ARCH_CAPABILITIES)
        # immunity: X86_FEATURE_BHI_CTRL (none of the affected CPUs have this)
        # vendor scope: Intel only
        #
        # all messages start with either "Not affected", "Vulnerable", or "Mitigation"
        status=$ret_sys_interface_check_status
    fi

    if [ "$opt_sysfs_only" != 1 ]; then
        pr_info_nol "* Kernel supports ITS mitigation: "
        kernel_its=''
        kernel_its_err=''
        if [ -n "$g_kernel_err" ]; then
            kernel_its_err="$g_kernel_err"
        elif grep -q 'indirect_target_selection' "$g_kernel"; then
            kernel_its="found indirect_target_selection in kernel image"
        fi
        if [ -z "$kernel_its" ] && [ -r "$opt_config" ]; then
            if grep -q '^CONFIG_MITIGATION_ITS=y' "$opt_config"; then
                kernel_its="ITS mitigation config option found enabled in kernel config"
            fi
        fi
        if [ -z "$kernel_its" ] && [ -n "$opt_map" ]; then
            if grep -q 'its_select_mitigation' "$opt_map"; then
                kernel_its="found its_select_mitigation in System.map"
            fi
        fi
        if [ -n "$kernel_its" ]; then
            pstatus green YES "$kernel_its"
        elif [ -n "$kernel_its_err" ]; then
            pstatus yellow UNKNOWN "$kernel_its_err"
        else
            pstatus yellow NO
        fi

        pr_info_nol "* CPU explicitly indicates not being affected by ITS (ITS_NO): "
        if [ "$cap_its_no" = -1 ]; then
            pstatus yellow UNKNOWN
        elif [ "$cap_its_no" = 1 ]; then
            pstatus green YES
        else
            pstatus yellow NO
        fi

    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ "$opt_sysfs_only" != 1 ]; then
            if [ "$cap_its_no" = 1 ]; then
                pvulnstatus "$cve" OK "CPU is not affected (ITS_NO)"
            elif [ -n "$kernel_its" ]; then
                pvulnstatus "$cve" OK "Kernel mitigates the vulnerability"
            elif [ -z "$kernel_its" ] && [ -z "$kernel_its_err" ]; then
                pvulnstatus "$cve" VULN "Your kernel doesn't support ITS mitigation"
                explain "Update your kernel to a version that includes ITS mitigation (Linux 6.15+, or check\n" \
                    "if your distro has a backport). Also update your CPU microcode to ensure IBPB fully\n" \
                    "flushes indirect branch predictions (microcode-20250512+)."
            else
                pvulnstatus "$cve" UNK "couldn't determine mitigation status: $kernel_its_err"
            fi
        else
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
        fi
    else
        pvulnstatus "$cve" "$status" "$msg"
    fi
}

check_CVE_2024_28956_bsd() {
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
    fi
}

# >>>>>> vulns/CVE-2024-36350.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2024-36350, TSA-SQ, Transient Scheduler Attack Store Queue

check_CVE_2024_36350() {
    check_cve 'CVE-2024-36350'
}

check_CVE_2024_36350_linux() {
    local status sys_interface_available msg kernel_tsa kernel_tsa_err smt_enabled
    status=UNK
    sys_interface_available=0
    msg=''

    if sys_interface_check "$VULN_SYSFS_BASE/tsa"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        #
        # Complete sysfs message inventory for tsa
        #
        # all versions:
        #   "Not affected"                                                  (cpu_show_common, pre-existing)
        #
        # --- mainline ---
        # d8010d4ba43e (v6.16-rc6, initial TSA sysfs):
        #   "Vulnerable"                                                    (TSA_MITIGATION_NONE)
        #   "Vulnerable: No microcode"                                      (TSA_MITIGATION_UCODE_NEEDED)
        #   "Mitigation: Clear CPU buffers: user/kernel boundary"           (TSA_MITIGATION_USER_KERNEL)
        #   "Mitigation: Clear CPU buffers: VM"                             (TSA_MITIGATION_VM)
        #   "Mitigation: Clear CPU buffers"                                 (TSA_MITIGATION_FULL)
        # 6b21d2f0dc73 (v6.17-rc1, attack vector controls):
        #   no string changes; only mitigation selection logic changed
        #   (AUTO can now resolve to USER_KERNEL or VM based on attack vector config)
        #
        # --- stable backports ---
        # 6.16.y: d8010d4ba43e (same as mainline), same strings.
        # 6.17.y: has 6b21d2f0dc73 (attack vector controls), same strings.
        # 5.10.y (78192f511f40), 5.15.y (f2b75f1368af), 6.1.y (d12145e8454f),
        # 6.6.y (90293047df18), 6.12.y (7a0395f6607a), 6.15.y (ab0f6573b211):
        #   different UCODE_NEEDED string:
        #   "Vulnerable: Clear CPU buffers attempted, no microcode"         (TSA_MITIGATION_UCODE_NEEDED)
        #   all other strings identical to mainline.
        #   default is FULL (no AUTO enum); USER_KERNEL/VM only via cmdline tsa=user/tsa=vm.
        #   VM-forced mitigation: when UCODE_NEEDED and running in a VM, forces FULL
        #   (stable-only logic, not in mainline).
        #
        # --- RHEL/CentOS ---
        # rocky9 (5.14-based), rocky10 (6.12-based): same strings as mainline.
        #   "Vulnerable: No microcode" for UCODE_NEEDED (matches mainline, NOT the stable variant).
        # rocky8 (4.18-based), centos7 (3.10-based): no TSA support.
        #
        # all messages start with either "Not affected", "Mitigation", or "Vulnerable"
        status=$ret_sys_interface_check_status
    fi

    if [ "$opt_sysfs_only" != 1 ]; then
        check_has_vmm
        # Override: when running as a hypervisor, "user/kernel boundary" mode
        # (tsa=user) leaves the VM exit boundary uncovered — guests can exploit
        # TSA to leak host data.  The kernel correctly reports its own mode, but
        # the script must flag this as insufficient for a VMM host.
        if [ "$sys_interface_available" = 1 ] && [ "$g_has_vmm" != 0 ]; then
            if echo "$ret_sys_interface_check_fullmsg" | grep -q 'user/kernel boundary'; then
                status=VULN
                msg="Vulnerable: TSA mitigation limited to user/kernel boundary (tsa=user), VM exit boundary is not covered"
            fi
        fi

        pr_info_nol "* Kernel supports TSA mitigation: "
        kernel_tsa=''
        kernel_tsa_err=''
        if [ -n "$g_kernel_err" ]; then
            kernel_tsa_err="$g_kernel_err"
        # commit d8010d4ba43e: "Transient Scheduler Attacks:" is printed by tsa_select_mitigation()
        elif grep -q 'Transient Scheduler Attacks' "$g_kernel"; then
            kernel_tsa="found TSA mitigation message in kernel image"
        fi
        if [ -z "$kernel_tsa" ] && [ -r "$opt_config" ]; then
            if grep -q '^CONFIG_MITIGATION_TSA=y' "$opt_config"; then
                kernel_tsa="CONFIG_MITIGATION_TSA=y found in kernel config"
            fi
        fi
        if [ -z "$kernel_tsa" ] && [ -n "$opt_map" ]; then
            if grep -q 'tsa_select_mitigation' "$opt_map"; then
                kernel_tsa="found tsa_select_mitigation in System.map"
            fi
        fi
        if [ -n "$kernel_tsa" ]; then
            pstatus green YES "$kernel_tsa"
        elif [ -n "$kernel_tsa_err" ]; then
            pstatus yellow UNKNOWN "$kernel_tsa_err"
        else
            pstatus yellow NO
        fi

        pr_info_nol "* CPU explicitly indicates not vulnerable to TSA-SQ (TSA_SQ_NO): "
        if [ "$cap_tsa_sq_no" = 1 ]; then
            pstatus green YES
        elif [ "$cap_tsa_sq_no" = 0 ]; then
            pstatus yellow NO
        else
            pstatus yellow UNKNOWN "couldn't read CPUID leaf 0x80000021"
        fi

        pr_info_nol "* Microcode supports VERW buffer clearing: "
        if [ "$cap_verw_clear" = 1 ]; then
            pstatus green YES
        elif [ "$cap_verw_clear" = 0 ]; then
            pstatus yellow NO
        else
            pstatus yellow UNKNOWN "couldn't read CPUID leaf 0x80000021"
        fi

        pr_info_nol "* Hyper-Threading (SMT) is enabled: "
        is_cpu_smt_enabled
        smt_enabled=$?
        if [ "$smt_enabled" = 0 ]; then
            pstatus yellow YES
        else
            pstatus green NO
        fi

    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ "$opt_sysfs_only" != 1 ]; then
            if [ "$cap_verw_clear" = 1 ] && [ -n "$kernel_tsa" ]; then
                if [ "$opt_paranoid" = 1 ] && [ "$smt_enabled" = 0 ]; then
                    pvulnstatus "$cve" VULN "Mitigation active but SMT must be disabled for full TSA-SQ protection"
                    explain "Disable SMT by adding \`nosmt\` to your kernel command line for complete protection against cross-thread TSA-SQ leakage."
                else
                    pvulnstatus "$cve" OK "Both kernel and microcode mitigate the vulnerability"
                fi
            elif [ "$cap_verw_clear" = 1 ]; then
                pvulnstatus "$cve" VULN "Microcode supports mitigation but kernel is too old"
                explain "Update your kernel to a version that supports CONFIG_MITIGATION_TSA (Linux 6.16+),\n " \
                    "or check if your distribution has backported the TSA mitigation."
            elif [ -n "$kernel_tsa" ]; then
                pvulnstatus "$cve" VULN "Kernel supports mitigation but microcode is too old"
                explain "Update your CPU microcode via a BIOS/firmware update from your OEM.\n " \
                    "The microcode must expose the VERW_CLEAR capability (CPUID 0x80000021 EAX bit 5)."
            else
                pvulnstatus "$cve" VULN "Neither kernel nor microcode mitigate the vulnerability"
                explain "Both a kernel update (CONFIG_MITIGATION_TSA, Linux 6.16+) and a microcode/firmware update\n " \
                    "from your OEM are needed to mitigate this vulnerability."
            fi
        else
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
        fi
    else
        pvulnstatus "$cve" "$status" "$msg"
        if echo "$msg" | grep -q 'VM exit boundary'; then
            explain "This system runs a hypervisor but TSA mitigation only clears CPU buffers at\n " \
                "user/kernel transitions (tsa=user). Guests can exploit TSA to leak host data\n " \
                "across VM exit. Use \`tsa=on\` (or remove \`tsa=user\`) to cover both boundaries."
        fi
    fi
}

check_CVE_2024_36350_bsd() {
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
    fi
}

# >>>>>> vulns/CVE-2024-36357.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2024-36357, TSA-L1, Transient Scheduler Attack L1

check_CVE_2024_36357() {
    check_cve 'CVE-2024-36357'
}

check_CVE_2024_36357_linux() {
    local status sys_interface_available msg kernel_tsa kernel_tsa_err
    status=UNK
    sys_interface_available=0
    msg=''

    if sys_interface_check "$VULN_SYSFS_BASE/tsa"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        #
        # Complete sysfs message inventory for tsa
        #
        # all versions:
        #   "Not affected"                                                  (cpu_show_common, pre-existing)
        #
        # --- mainline ---
        # d8010d4ba43e (v6.16-rc6, initial TSA sysfs):
        #   "Vulnerable"                                                    (TSA_MITIGATION_NONE)
        #   "Vulnerable: No microcode"                                      (TSA_MITIGATION_UCODE_NEEDED)
        #   "Mitigation: Clear CPU buffers: user/kernel boundary"           (TSA_MITIGATION_USER_KERNEL)
        #   "Mitigation: Clear CPU buffers: VM"                             (TSA_MITIGATION_VM)
        #   "Mitigation: Clear CPU buffers"                                 (TSA_MITIGATION_FULL)
        # 6b21d2f0dc73 (v6.17-rc1, attack vector controls):
        #   no string changes; only mitigation selection logic changed
        #   (AUTO can now resolve to USER_KERNEL or VM based on attack vector config)
        #
        # --- stable backports ---
        # 6.16.y: d8010d4ba43e (same as mainline), same strings.
        # 6.17.y: has 6b21d2f0dc73 (attack vector controls), same strings.
        # 5.10.y (78192f511f40), 5.15.y (f2b75f1368af), 6.1.y (d12145e8454f),
        # 6.6.y (90293047df18), 6.12.y (7a0395f6607a), 6.15.y (ab0f6573b211):
        #   different UCODE_NEEDED string:
        #   "Vulnerable: Clear CPU buffers attempted, no microcode"         (TSA_MITIGATION_UCODE_NEEDED)
        #   all other strings identical to mainline.
        #   default is FULL (no AUTO enum); USER_KERNEL/VM only via cmdline tsa=user/tsa=vm.
        #   VM-forced mitigation: when UCODE_NEEDED and running in a VM, forces FULL
        #   (stable-only logic, not in mainline).
        #
        # --- RHEL/CentOS ---
        # rocky9 (5.14-based), rocky10 (6.12-based): same strings as mainline.
        #   "Vulnerable: No microcode" for UCODE_NEEDED (matches mainline, NOT the stable variant).
        # rocky8 (4.18-based), centos7 (3.10-based): no TSA support.
        #
        # all messages start with either "Not affected", "Mitigation", or "Vulnerable"
        status=$ret_sys_interface_check_status
    fi

    if [ "$opt_sysfs_only" != 1 ]; then
        check_has_vmm
        # Override: when running as a hypervisor, "user/kernel boundary" mode
        # (tsa=user) leaves the VM exit boundary uncovered — guests can exploit
        # TSA to leak host data.  The kernel correctly reports its own mode, but
        # the script must flag this as insufficient for a VMM host.
        if [ "$sys_interface_available" = 1 ] && [ "$g_has_vmm" != 0 ]; then
            if echo "$ret_sys_interface_check_fullmsg" | grep -q 'user/kernel boundary'; then
                status=VULN
                msg="Vulnerable: TSA mitigation limited to user/kernel boundary (tsa=user), VM exit boundary is not covered"
            fi
        fi

        pr_info_nol "* Kernel supports TSA mitigation: "
        kernel_tsa=''
        kernel_tsa_err=''
        if [ -n "$g_kernel_err" ]; then
            kernel_tsa_err="$g_kernel_err"
        # commit d8010d4ba43e: "Transient Scheduler Attacks:" is printed by tsa_select_mitigation()
        elif grep -q 'Transient Scheduler Attacks' "$g_kernel"; then
            kernel_tsa="found TSA mitigation message in kernel image"
        fi
        if [ -z "$kernel_tsa" ] && [ -r "$opt_config" ]; then
            if grep -q '^CONFIG_MITIGATION_TSA=y' "$opt_config"; then
                kernel_tsa="CONFIG_MITIGATION_TSA=y found in kernel config"
            fi
        fi
        if [ -z "$kernel_tsa" ] && [ -n "$opt_map" ]; then
            if grep -q 'tsa_select_mitigation' "$opt_map"; then
                kernel_tsa="found tsa_select_mitigation in System.map"
            fi
        fi
        if [ -n "$kernel_tsa" ]; then
            pstatus green YES "$kernel_tsa"
        elif [ -n "$kernel_tsa_err" ]; then
            pstatus yellow UNKNOWN "$kernel_tsa_err"
        else
            pstatus yellow NO
        fi

        pr_info_nol "* CPU explicitly indicates not vulnerable to TSA-L1 (TSA_L1_NO): "
        if [ "$cap_tsa_l1_no" = 1 ]; then
            pstatus green YES
        elif [ "$cap_tsa_l1_no" = 0 ]; then
            pstatus yellow NO
        else
            pstatus yellow UNKNOWN "couldn't read CPUID leaf 0x80000021"
        fi

        pr_info_nol "* Microcode supports VERW buffer clearing: "
        if [ "$cap_verw_clear" = 1 ]; then
            pstatus green YES
        elif [ "$cap_verw_clear" = 0 ]; then
            pstatus yellow NO
        else
            pstatus yellow UNKNOWN "couldn't read CPUID leaf 0x80000021"
        fi

    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ "$opt_sysfs_only" != 1 ]; then
            # No --paranoid SMT check here, unlike TSA-SQ (CVE-2024-36350).
            # The kernel's cpu_bugs_smt_update() enables cpu_buf_idle_clear
            # (VERW before idle) specifically for TSA-SQ cross-thread leakage,
            # with the comment "TSA-SQ can potentially lead to info leakage
            # between SMT threads" — TSA-L1 is not mentioned. Until the kernel
            # flags TSA-L1 as having cross-thread SMT exposure, we follow its
            # assessment and do not require SMT disabled in paranoid mode.
            if [ "$cap_verw_clear" = 1 ] && [ -n "$kernel_tsa" ]; then
                pvulnstatus "$cve" OK "Both kernel and microcode mitigate the vulnerability"
            elif [ "$cap_verw_clear" = 1 ]; then
                pvulnstatus "$cve" VULN "Microcode supports mitigation but kernel is too old"
                explain "Update your kernel to a version that supports CONFIG_MITIGATION_TSA (Linux 6.16+),\n " \
                    "or check if your distribution has backported the TSA mitigation."
            elif [ -n "$kernel_tsa" ]; then
                pvulnstatus "$cve" VULN "Kernel supports mitigation but microcode is too old"
                explain "Update your CPU microcode via a BIOS/firmware update from your OEM.\n " \
                    "The microcode must expose the VERW_CLEAR capability (CPUID 0x80000021 EAX bit 5)."
            else
                pvulnstatus "$cve" VULN "Neither kernel nor microcode mitigate the vulnerability"
                explain "Both a kernel update (CONFIG_MITIGATION_TSA, Linux 6.16+) and a microcode/firmware update\n " \
                    "from your OEM are needed to mitigate this vulnerability."
            fi
        else
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
        fi
    else
        pvulnstatus "$cve" "$status" "$msg"
        if echo "$msg" | grep -q 'VM exit boundary'; then
            explain "This system runs a hypervisor but TSA mitigation only clears CPU buffers at\n " \
                "user/kernel transitions (tsa=user). Guests can exploit TSA to leak host data\n " \
                "across VM exit. Use \`tsa=on\` (or remove \`tsa=user\`) to cover both boundaries."
        fi
    fi
}

check_CVE_2024_36357_bsd() {
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
    fi
}

# >>>>>> vulns/CVE-2024-45332.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2024-45332, BPI, Branch Privilege Injection

check_CVE_2024_45332() {
    check_cve 'CVE-2024-45332'
}

check_CVE_2024_45332_linux() {
    local status sys_interface_available msg
    status=UNK
    sys_interface_available=0
    msg=''

    # There is no dedicated sysfs file for this vulnerability, and no kernel
    # mitigation code.  The fix is purely a microcode update that corrects the
    # asynchronous branch predictor update timing so that eIBRS and IBPB work
    # as originally intended.  There is no new CPUID bit, MSR bit, or ARCH_CAP
    # flag to detect the fix, so we hardcode known-fixing microcode versions
    # per CPU (see bpi_ucode_list in is_cpu_affected).

    # shellcheck disable=SC2154
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$g_bpi_fixed_ucode_version" ]; then
        # CPU matched the model blacklist but has no known fixing microcode
        # (likely an EOL stepping that Intel won't release a fix for)
        pvulnstatus "$cve" VULN "your CPU is affected and no microcode update is available for your CPU stepping"
        explain "CVE-2024-45332 (Branch Privilege Injection) is a race condition in the branch predictor\n" \
            "that undermines eIBRS and IBPB protections. The fix is a microcode update, but no\n" \
            "update is available for your specific CPU stepping."
    else
        pr_info_nol "* BPI is mitigated by microcode: "
        if [ "$cpu_ucode" -lt "$g_bpi_fixed_ucode_version" ]; then
            pstatus yellow NO "You have ucode $(printf "0x%x" "$cpu_ucode") and version $(printf "0x%x" "$g_bpi_fixed_ucode_version") minimum is required"
            pvulnstatus "$cve" VULN "Your microcode is too old to mitigate the vulnerability"
            explain "CVE-2024-45332 (Branch Privilege Injection) is a race condition in the branch predictor\n" \
                "that undermines eIBRS and IBPB protections. The fix is a microcode update only.\n" \
                "No kernel changes are required."
        else
            pstatus green YES "You have ucode $(printf "0x%x" "$cpu_ucode") which is recent enough (>= $(printf "0x%x" "$g_bpi_fixed_ucode_version"))"
            pvulnstatus "$cve" OK "Your microcode mitigates the vulnerability"
        fi
    fi
}

check_CVE_2024_45332_bsd() {
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
    fi
}

# >>>>>> vulns/CVE-2025-40300.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
###############################
# CVE-2025-40300, VMScape, VM-Exit Stale Branch Prediction

check_CVE_2025_40300() {
    check_cve 'CVE-2025-40300'
}

check_CVE_2025_40300_linux() {
    local status sys_interface_available msg kernel_vmscape kernel_vmscape_err
    status=UNK
    sys_interface_available=0
    msg=''

    if sys_interface_check "$VULN_SYSFS_BASE/vmscape"; then
        # this kernel has the /sys interface, trust it over everything
        sys_interface_available=1
        #
        # Kernel source inventory for vmscape, traced via git blame:
        #
        # --- sysfs messages ---
        # all versions:
        #   "Not affected"                              (cpu_show_common, pre-existing)
        #
        # --- mainline ---
        # a508cec6e521 (v6.17-rc6, initial vmscape sysfs):
        #   "Vulnerable"                                (VMSCAPE_MITIGATION_NONE)
        #   "Mitigation: IBPB before exit to userspace" (VMSCAPE_MITIGATION_IBPB_EXIT_TO_USER)
        # 2f8f17341 (v6.17-rc6, vmscape_update_mitigation):
        #   "Mitigation: IBPB on VMEXIT"                (VMSCAPE_MITIGATION_IBPB_ON_VMEXIT)
        #     (when retbleed uses IBPB or srso uses IBPB_ON_VMEXIT)
        #
        # --- stable backports ---
        # 6.16.x (v6.16.7): identical to mainline (d83e6111337f)
        # 6.12.x (v6.12.47): identical to mainline (7c62c442b6eb)
        # 6.6.x (v6.6.106): identical to mainline (813cb831439c)
        # 6.1.x (v6.1.152): identical strings; uses VULNBL_INTEL_STEPPINGS macro,
        #   missing ARROWLAKE_U, ATOM_CRESTMONT_X, AMD 0x1a.
        #   Uses ALDERLAKE_N instead of type-specific ALDERLAKE split. (304d1fb275af)
        #
        # --- RHEL/CentOS ---
        # Not yet backported.
        #
        # --- Kconfig symbols ---
        # a508cec6e521 (v6.17-rc6): CONFIG_MITIGATION_VMSCAPE (default y)
        #   depends on KVM
        #
        # --- kernel functions (for $opt_map / System.map) ---
        # a508cec6e521 (v6.17-rc6): vmscape_select_mitigation(),
        #   vmscape_update_mitigation(), vmscape_apply_mitigation(),
        #   vmscape_parse_cmdline(), vmscape_show_state()
        #
        # --- CPU affection logic (for is_cpu_affected) ---
        # X86_BUG_VMSCAPE is set when ALL conditions are true:
        #   1. CPU matches model blacklist
        #   2. X86_FEATURE_HYPERVISOR is NOT set (bare metal only)
        # a508cec6e521 (v6.17-rc6, initial model list):
        #   Intel: SKYLAKE_X, SKYLAKE_L, SKYLAKE, KABYLAKE_L, KABYLAKE,
        #          CANNONLAKE_L, COMETLAKE, COMETLAKE_L, ALDERLAKE,
        #          ALDERLAKE_L, RAPTORLAKE, RAPTORLAKE_P, RAPTORLAKE_S,
        #          METEORLAKE_L, ARROWLAKE_H, ARROWLAKE, ARROWLAKE_U,
        #          LUNARLAKE_M, SAPPHIRERAPIDS_X, GRANITERAPIDS_X,
        #          EMERALDRAPIDS_X, ATOM_GRACEMONT, ATOM_CRESTMONT_X
        #   AMD: family 0x17 (Zen 1/+/2), family 0x19 (Zen 3/4),
        #        family 0x1a (Zen 5)
        #   Hygon: family 0x18
        # 8a68d64bb103 (v6.17-rc6, added old Intel CPUs):
        #   Intel: + SANDYBRIDGE_X, SANDYBRIDGE, IVYBRIDGE_X, IVYBRIDGE,
        #          HASWELL, HASWELL_L, HASWELL_G, HASWELL_X,
        #          BROADWELL_D, BROADWELL_X, BROADWELL_G, BROADWELL
        # Intel NOT affected: ICELAKE_*, TIGERLAKE_*, LAKEFIELD, ROCKETLAKE,
        #   ATOM_TREMONT_*, ATOM_GOLDMONT_*
        # immunity: no ARCH_CAP bits — determination is purely via blacklist
        # note: bare metal only (X86_FEATURE_HYPERVISOR excludes guests)
        # vendor scope: Intel + AMD + Hygon
        #
        # all messages start with either "Not affected", "Vulnerable", or "Mitigation"
        status=$ret_sys_interface_check_status
    fi

    if [ "$opt_sysfs_only" != 1 ]; then
        check_has_vmm
        pr_info_nol "* Kernel supports VMScape mitigation: "
        kernel_vmscape=''
        kernel_vmscape_err=''
        if [ -n "$g_kernel_err" ]; then
            kernel_vmscape_err="$g_kernel_err"
        elif grep -q 'vmscape' "$g_kernel"; then
            kernel_vmscape="found vmscape in kernel image"
        fi
        if [ -z "$kernel_vmscape" ] && [ -r "$opt_config" ]; then
            if grep -q '^CONFIG_MITIGATION_VMSCAPE=y' "$opt_config"; then
                kernel_vmscape="VMScape mitigation config option found enabled in kernel config"
            fi
        fi
        if [ -z "$kernel_vmscape" ] && [ -n "$opt_map" ]; then
            if grep -q 'vmscape_select_mitigation' "$opt_map"; then
                kernel_vmscape="found vmscape_select_mitigation in System.map"
            fi
        fi
        if [ -n "$kernel_vmscape" ]; then
            pstatus green YES "$kernel_vmscape"
        elif [ -n "$kernel_vmscape_err" ]; then
            pstatus yellow UNKNOWN "$kernel_vmscape_err"
        else
            pstatus yellow NO
        fi

    elif [ "$sys_interface_available" = 0 ]; then
        # we have no sysfs but were asked to use it only!
        msg="/sys vulnerability interface use forced, but it's not available!"
        status=UNK
    fi

    if ! is_cpu_affected "$cve"; then
        # override status & msg in case CPU is not vulnerable after all
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    elif [ -z "$msg" ]; then
        # if msg is empty, sysfs check didn't fill it, rely on our own test
        if [ "$opt_sysfs_only" != 1 ]; then
            if [ "$g_has_vmm" = 0 ]; then
                pvulnstatus "$cve" OK "this system is not running a hypervisor"
            elif [ -n "$kernel_vmscape" ]; then
                pvulnstatus "$cve" OK "Kernel mitigates the vulnerability"
            elif [ -z "$kernel_vmscape" ] && [ -z "$kernel_vmscape_err" ]; then
                pvulnstatus "$cve" VULN "Your kernel doesn't support VMScape mitigation"
                explain "Update your kernel to a version that includes the VMScape mitigation (Linux 6.18+, or check\n" \
                    "if your distro has a backport). The mitigation issues IBPB before returning to userspace\n" \
                    "after a VM exit, preventing stale guest branch predictions from leaking host kernel memory."
            else
                pvulnstatus "$cve" UNK "couldn't determine mitigation status: $kernel_vmscape_err"
            fi
        else
            pvulnstatus "$cve" "$status" "$ret_sys_interface_check_fullmsg"
        fi
    else
        pvulnstatus "$cve" "$status" "$msg"
    fi
}

check_CVE_2025_40300_bsd() {
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
    fi
}

# >>>>>> main.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:

if [ "$opt_no_hw" = 0 ] && [ -z "$opt_arch_prefix" ]; then
    check_cpu
    check_cpu_vulnerabilities
    pr_info
fi

# now run the checks the user asked for
for cve in $g_supported_cve_list; do
    if [ "$opt_cve_all" = 1 ] || echo "$opt_cve_list" | grep -qw "$cve"; then
        check_"$(echo "$cve" | tr - _)"
        pr_info
    fi
done

if [ -n "$g_final_summary" ]; then
    pr_info "> \033[46m\033[30mSUMMARY:\033[0m$g_final_summary"
    pr_info ""
fi

if [ "$g_bad_accuracy" = 1 ]; then
    pr_warn "We're missing some kernel info (see -v), accuracy might be reduced"
fi

g_vars=$(set | grep -Ev '^[A-Z_[:space:]]' | grep -v -F 'g_mockme=' | sort | tr "\n" '|')
pr_debug "variables at end of script: $g_vars"

if [ -n "$g_mockme" ] && [ "$opt_mock" = 1 ]; then
    if command -v "gzip" >/dev/null 2>&1; then
        # not a useless use of cat: gzipping cpuinfo directly doesn't work well
        # shellcheck disable=SC2002
        if command -v "base64" >/dev/null 2>&1; then
            g_mock_cpuinfo="$(cat /proc/cpuinfo | gzip -c | base64 -w0)"
        elif command -v "uuencode" >/dev/null 2>&1; then
            g_mock_cpuinfo="$(cat /proc/cpuinfo | gzip -c | uuencode -m - | grep -Fv 'begin-base64' | grep -Fxv -- '====' | tr -d "\n")"
        fi
    fi
    if [ -n "$g_mock_cpuinfo" ]; then
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPUINFO='$g_mock_cpuinfo'")
        unset g_mock_cpuinfo
    fi
    pr_info ""
    # shellcheck disable=SC2046
    pr_warn "To mock this CPU, set those vars: "$(echo "$g_mockme" | sort -u)
fi

# root check
if [ "$(id -u)" -ne 0 ]; then
    pr_warn "Note that you should launch this script with root privileges to get completely accurate information."
    pr_warn "To run it as root, you can try the following command: sudo $0"
    pr_warn
fi

if [ "$opt_explain" = 0 ]; then
    pr_info "Need more detailed information about mitigation options? Use --explain"
fi

pr_info "A false sense of security is worse than no security at all, see --disclaimer"

if [ "$g_mocked" = 1 ]; then
    pr_info ""
    pr_warn "One or several values have been g_mocked. This should only be done when debugging/testing this script."
    pr_warn "The results do NOT reflect the actual status of the system we're running on."
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "nrpe" ]; then
    if [ -n "$g_nrpe_vuln" ]; then
        echo "Vulnerable:$g_nrpe_vuln"
    else
        echo "OK"
    fi
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "short" ]; then
    _pr_echo 0 "${g_short_output% }"
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "json" ]; then
    _pr_echo 0 "${g_json_output%?}]"
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "prometheus" ]; then
    echo "# TYPE specex_vuln_status untyped"
    echo "# HELP specex_vuln_status Exposure of system to speculative execution vulnerabilities"
    printf "%b\n" "$g_prometheus_output"
fi

# exit with the proper exit code
[ "$g_critical" = 1 ] && exit 2 # critical
[ "$g_unknown" = 1 ] && exit 3  # unknown
exit 0                          # ok

# >>>>>> db/100_inteldb.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# Dump from Intel affected CPU page:
# - https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/processors-affected-consolidated-product-cpu-model.html
# Only currently-supported CPUs are listed, so only rely on it if the current CPU happens to be in the list.
# We merge it with info from the following file:
# - https://software.intel.com/content/dam/www/public/us/en/documents/affected-processors-transient-execution-attacks-by-cpu-aug02.xlsx
# As it contains some information from older processors, however when information is contradictory between the two sources, the HTML takes precedence as
# it is expected to be updated, whereas the xslx seems to be frozen.
#
# N: Not affected
# S: Affected, software fix
# H: Affected, hardware fix
# M: Affected, MCU update needed
# B: Affected, BIOS update needed
# X: Affected, no planned mitigation
# Y: Affected (this is from the xlsx, no details are available)
#
# %%% INTELDB
# 0x000206A7,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=Y,2018-12130=Y,2018-12207=Y,2018-3615=Y,2018-3620=Y,2018-3639=Y,2018-3640=Y,2018-3646=Y,2019-11135=N,2020-0543=N,
# 0x000206D6,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=Y,2018-12130=Y,2018-12207=Y,2018-3615=Y,2018-3620=Y,2018-3639=Y,2018-3640=Y,2018-3646=Y,2019-11135=N,2020-0543=N,
# 0x000206D7,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=Y,2018-12130=Y,2018-12207=Y,2018-3615=Y,2018-3620=Y,2018-3639=Y,2018-3640=Y,2018-3646=Y,2019-11135=N,2020-0543=N,
# 0x00030673,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=N,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x00030678,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=N,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x00030679,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=N,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x000306A9,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=Y,2018-12130=Y,2018-12207=Y,2018-3615=Y,2018-3620=Y,2018-3639=Y,2018-3640=Y,2018-3646=Y,2019-11135=N,2020-0543=Y,
# 0x000306C3,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=Y,2018-12130=Y,2018-12207=Y,2018-3615=Y,2018-3620=Y,2018-3639=Y,2018-3640=Y,2018-3646=Y,2019-11135=N,2020-0543=Y,
# 0x000306D4,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=Y,2018-12130=Y,2018-12207=Y,2018-3615=Y,2018-3620=Y,2018-3639=Y,2018-3640=Y,2018-3646=Y,2019-11135=Y,2020-0543=Y,
# 0x000306E4,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=Y,2018-12130=Y,2018-12207=Y,2018-3615=Y,2018-3620=Y,2018-3639=Y,2018-3640=Y,2018-3646=Y,2019-11135=N,2020-0543=N,
# 0x000306E7,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=Y,2018-12130=Y,2018-12207=Y,2018-3615=Y,2018-3620=Y,2018-3639=Y,2018-3640=Y,2018-3646=Y,2019-11135=N,2020-0543=N,
# 0x000306F2,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000306F4,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=N,2022-40982=N,
# 0x00040651,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=Y,2018-12130=Y,2018-12207=Y,2018-3615=Y,2018-3620=Y,2018-3639=Y,2018-3640=Y,2018-3646=Y,2019-11135=N,2020-0543=Y,
# 0x00040661,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=Y,2018-12130=Y,2018-12207=Y,2018-3615=Y,2018-3620=Y,2018-3639=Y,2018-3640=Y,2018-3646=Y,2019-11135=N,2020-0543=Y,
# 0x00040671,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=Y,2018-12130=Y,2018-12207=Y,2018-3615=Y,2018-3620=Y,2018-3639=Y,2018-3640=Y,2018-3646=Y,2019-11135=Y,2020-0543=Y,
# 0x000406A0,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=N,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x000406C3,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=N,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x000406C4,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=N,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x000406D8,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=N,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x000406E3,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=MS,
# 0x000406F1,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=N,2022-40982=N,
# 0x00050653,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=N,2022-40982=M,
# 0x00050654,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=N,2022-40982=M,
# 0x00050656,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=MS,2020-0543=N,2022-40982=M,
# 0x00050657,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=MS,2020-0543=N,2022-40982=M,
# 0x0005065A,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x0005065B,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x00050662,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=Y,2018-12130=Y,2018-12207=Y,2018-3615=Y,2018-3620=Y,2018-3639=Y,2018-3640=Y,2018-3646=Y,2019-11135=Y,2020-0543=N,
# 0x00050663,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=N,2022-40982=N,
# 0x00050664,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=N,2022-40982=N,
# 0x00050665,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=N,2022-40982=N,
# 0x000506A0,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=N,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x000506C9,2017-5715=MS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=MS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000506CA,2017-5715=MS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=MS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000506D0,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=N,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x000506E3,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=MS,2022-40982=N,
# 0x000506F1,2017-5715=MS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=MS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x00060650,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=N,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x000606A0,2017-5715=Y,2017-5753=Y,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=Y,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x000606A4,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000606A5,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000606A6,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000606C1,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000606E1,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=N,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x0007065A,2017-5715=Y,2017-5753=Y,2017-5754=Y,2018-12126=Y,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=N,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x000706A1,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=MS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000706A8,2017-5715=MS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000706E5,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=HM,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x00080660,2017-5715=Y,2017-5753=Y,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=Y,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x00080664,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x00080665,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=MS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x00080667,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=MS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000806A0,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=HM,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000806A1,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=HM,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000806C0,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000806C1,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000806C2,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000806D0,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000806D1,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000806E9,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=M,2022-40982=M,
# 0x000806EA,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=MS,2022-40982=M,
# 0x000806EB,2017-5715=MS,2017-5753=S,2017-5754=N,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=MS,2018-3640=M,2018-3646=N,2019-11135=MS,2020-0543=MS,2022-40982=M,
# 0x000806EC,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=MS,2020-0543=MS,2022-40982=M,
# 0x000806F7,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000806F8,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x00090660,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x00090661,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x00090670,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x00090671,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x00090672,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x00090673,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x00090674,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x00090675,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=MS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000906A0,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=MS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000906A2,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=MS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000906A3,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=MS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000906A4,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=MS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000906C0,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000906E9,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=MS,2022-40982=M,
# 0x000906EA,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=MS,2022-40982=M,
# 0x000906EB,2017-5715=MS,2017-5753=S,2017-5754=S,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=MS,2018-3620=MS,2018-3639=MS,2018-3640=M,2018-3646=MS,2019-11135=MS,2020-0543=MS,2022-40982=M,
# 0x000906EC,2017-5715=MS,2017-5753=S,2017-5754=N,2018-12126=MS,2018-12127=MS,2018-12130=MS,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=M,2018-3646=N,2019-11135=MS,2020-0543=MS,2022-40982=M,
# 0x000906ED,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=M,2018-3646=N,2019-11135=MS,2020-0543=MS,2022-40982=M,
# 0x000A0650,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=M,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000A0651,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=M,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000A0652,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=M,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000A0653,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=M,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000A0655,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=M,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000A0660,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=M,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000A0661,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=S,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=M,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000A0670,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000A0671,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=M,
# 0x000A0680,2017-5715=Y,2017-5753=Y,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=Y,2018-3615=N,2018-3620=N,2018-3639=Y,2018-3640=Y,2018-3646=N,2019-11135=N,2020-0543=N,
# 0x000B0671,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000B06A2,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000B06A3,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000B06F2,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# 0x000B06F5,2017-5715=HS,2017-5753=S,2017-5754=N,2018-12126=N,2018-12127=N,2018-12130=N,2018-12207=N,2018-3615=N,2018-3620=N,2018-3639=HS,2018-3640=N,2018-3646=N,2019-11135=N,2020-0543=N,2022-40982=N,
# %%% ENDOFINTELDB

# >>>>>> db/200_mcedb.sh <<<<<<

# vim: set ts=4 sw=4 sts=4 et:
# We're using MCE.db from the excellent platomav's MCExtractor project
# The builtin version follows, but the user can download an up-to-date copy (to be stored in their $HOME) by using --update-fwdb
# To update the builtin version itself (by *modifying* this very file), use --update-builtin-fwdb
#
# The format below is:
# X,CPUID_HEX,MICROCODE_VERSION_HEX,YYYYMMDD
# with X being either I for Intel, or A for AMD
# When the date is unknown it defaults to 20000101

# %%% MCEDB v349+i20260227+615b
# I,0x00000611,0xFF,0x00000B27,19961218
# I,0x00000612,0xFF,0x000000C6,19961210
# I,0x00000616,0xFF,0x000000C6,19961210
# I,0x00000617,0xFF,0x000000C6,19961210
# I,0x00000619,0xFF,0x000000D2,19980218
# I,0x00000630,0xFF,0x00000013,19960827
# I,0x00000632,0xFF,0x00000020,19960903
# I,0x00000633,0xFF,0x00000036,19980923
# I,0x00000634,0xFF,0x00000037,19980923
# I,0x00000650,0x01,0x00000040,19990525
# I,0x00000650,0x02,0x00000041,19990525
# I,0x00000650,0x08,0x00000045,19990525
# I,0x00000651,0x01,0x00000040,19990525
# I,0x00000652,0x01,0x0000002A,19990512
# I,0x00000652,0x02,0x0000002C,19990517
# I,0x00000652,0x04,0x0000002B,19990512
# I,0x00000653,0x01,0x00000010,19990628
# I,0x00000653,0x02,0x0000000C,19990518
# I,0x00000653,0x04,0x0000000B,19990520
# I,0x00000653,0x08,0x0000000D,19990518
# I,0x00000660,0x01,0x0000000A,19990505
# I,0x00000665,0x10,0x00000003,19990505
# I,0x0000066A,0x02,0x0000000C,19990505
# I,0x0000066A,0x08,0x0000000D,19990505
# I,0x0000066A,0x20,0x0000000B,19990505
# I,0x0000066D,0x02,0x00000005,19990312
# I,0x0000066D,0x08,0x00000006,19990312
# I,0x0000066D,0x20,0x00000007,19990505
# I,0x00000670,0xFF,0x00000007,19980602
# I,0x00000671,0x04,0x00000014,19980811
# I,0x00000672,0x04,0x00000038,19990922
# I,0x00000673,0x04,0x0000002E,19990910
# I,0x00000680,0xFF,0x00000017,19990610
# I,0x00000681,0x01,0x0000000D,19990921
# I,0x00000681,0x04,0x00000010,19990921
# I,0x00000681,0x08,0x0000000F,19990921
# I,0x00000681,0x10,0x00000011,19990921
# I,0x00000681,0x20,0x0000000E,19990921
# I,0x00000683,0x08,0x00000008,19991015
# I,0x00000683,0x20,0x00000007,19991015
# I,0x00000686,0x01,0x00000007,20000505
# I,0x00000686,0x02,0x0000000A,20000504
# I,0x00000686,0x04,0x00000002,20000504
# I,0x00000686,0x10,0x00000008,20000505
# I,0x00000686,0x80,0x0000000C,20000504
# I,0x0000068A,0x10,0x00000001,20001102
# I,0x0000068A,0x20,0x00000004,20001207
# I,0x0000068A,0x80,0x00000005,20001207
# I,0x00000690,0xFF,0x00000004,20000206
# I,0x00000691,0xFF,0x00000001,20020527
# I,0x00000692,0xFF,0x00000001,20020620
# I,0x00000694,0xFF,0x00000002,20020926
# I,0x00000695,0x10,0x00000007,20041109
# I,0x00000695,0x20,0x00000007,20041109
# I,0x00000695,0x80,0x00000047,20041109
# I,0x00000696,0xFF,0x00000001,20000707
# I,0x000006A0,0x04,0x00000003,20000110
# I,0x000006A1,0x04,0x00000001,20000306
# I,0x000006A4,0xFF,0x00000001,20000616
# I,0x000006B0,0xFF,0x0000001A,20010129
# I,0x000006B1,0x10,0x0000001C,20010215
# I,0x000006B1,0x20,0x0000001D,20010220
# I,0x000006B4,0x10,0x00000001,20020110
# I,0x000006B4,0x20,0x00000002,20020111
# I,0x000006D0,0xFF,0x00000006,20030522
# I,0x000006D1,0xFF,0x00000009,20030709
# I,0x000006D2,0xFF,0x00000010,20030814
# I,0x000006D6,0x20,0x00000018,20041017
# I,0x000006D8,0xFF,0x00000021,20060831
# I,0x000006E0,0xFF,0x00000008,20050215
# I,0x000006E1,0xFF,0x0000000C,20050413
# I,0x000006E4,0xFF,0x00000026,20050816
# I,0x000006E8,0x20,0x00000039,20051115
# I,0x000006EC,0x20,0x00000054,20060501
# I,0x000006EC,0x80,0x00000059,20060912
# I,0x000006F0,0xFF,0x00000005,20050818
# I,0x000006F1,0xFF,0x00000012,20051129
# I,0x000006F2,0x01,0x0000005D,20101002
# I,0x000006F2,0x20,0x0000005C,20101002
# I,0x000006F4,0xFF,0x00000028,20060417
# I,0x000006F5,0xFF,0x00000039,20060727
# I,0x000006F6,0x01,0x000000D0,20100930
# I,0x000006F6,0x04,0x000000D2,20101001
# I,0x000006F6,0x20,0x000000D1,20101001
# I,0x000006F7,0x10,0x0000006A,20101002
# I,0x000006F7,0x40,0x0000006B,20101002
# I,0x000006F9,0xFF,0x00000084,20061012
# I,0x000006FA,0x80,0x00000095,20101002
# I,0x000006FB,0x01,0x000000BA,20101003
# I,0x000006FB,0x04,0x000000BC,20101003
# I,0x000006FB,0x08,0x000000BB,20101003
# I,0x000006FB,0x10,0x000000BA,20101003
# I,0x000006FB,0x20,0x000000BA,20101003
# I,0x000006FB,0x40,0x000000BC,20101003
# I,0x000006FB,0x80,0x000000BA,20101003
# I,0x000006FD,0x01,0x000000A4,20101002
# I,0x000006FD,0x20,0x000000A4,20101002
# I,0x000006FD,0x80,0x000000A4,20101002
# I,0x00000F00,0xFF,0xFFFF0001,20000130
# I,0x00000F01,0xFF,0xFFFF0007,20000404
# I,0x00000F02,0xFF,0xFFFF000B,20000518
# I,0x00000F03,0xFF,0xFFFF0001,20000518
# I,0x00000F04,0xFF,0xFFFF0010,20000803
# I,0x00000F05,0xFF,0x0000000C,20000824
# I,0x00000F06,0xFF,0x00000004,20000911
# I,0x00000F07,0x01,0x00000012,20020716
# I,0x00000F07,0x02,0x00000008,20001115
# I,0x00000F08,0xFF,0x00000008,20001101
# I,0x00000F09,0xFF,0x00000008,20010104
# I,0x00000F0A,0x01,0x00000013,20020716
# I,0x00000F0A,0x02,0x00000015,20020821
# I,0x00000F0A,0x04,0x00000014,20020716
# I,0x00000F11,0xFF,0x0000000A,20030729
# I,0x00000F12,0x04,0x0000002E,20030502
# I,0x00000F13,0xFF,0x00000005,20030508
# I,0x00000F20,0xFF,0x00000001,20010423
# I,0x00000F21,0xFF,0x00000003,20010529
# I,0x00000F22,0xFF,0x00000005,20030729
# I,0x00000F23,0xFF,0x0000000D,20010817
# I,0x00000F24,0x02,0x0000001F,20030605
# I,0x00000F24,0x04,0x0000001E,20030605
# I,0x00000F24,0x10,0x00000021,20030610
# I,0x00000F25,0x01,0x00000029,20040811
# I,0x00000F25,0x02,0x0000002A,20040811
# I,0x00000F25,0x04,0x0000002B,20040811
# I,0x00000F25,0x10,0x0000002C,20040826
# I,0x00000F26,0x02,0x00000010,20040805
# I,0x00000F27,0x02,0x00000038,20030604
# I,0x00000F27,0x04,0x00000037,20030604
# I,0x00000F27,0x08,0x00000039,20030604
# I,0x00000F29,0x02,0x0000002D,20040811
# I,0x00000F29,0x04,0x0000002E,20040811
# I,0x00000F29,0x08,0x0000002F,20040811
# I,0x00000F30,0xFF,0x00000013,20030815
# I,0x00000F31,0xFF,0x0000000B,20031021
# I,0x00000F32,0x0D,0x0000000A,20040511
# I,0x00000F33,0x0D,0x0000000C,20050421
# I,0x00000F34,0x1D,0x00000017,20050421
# I,0x00000F36,0xFF,0x00000007,20040309
# I,0x00000F37,0xFF,0x00000003,20031218
# I,0x00000F40,0xFF,0x00000006,20040318
# I,0x00000F41,0x02,0x00000016,20050421
# I,0x00000F41,0xBD,0x00000017,20050422
# I,0x00000F42,0xFF,0x00000003,20050421
# I,0x00000F43,0x9D,0x00000005,20050421
# I,0x00000F44,0x9D,0x00000006,20050421
# I,0x00000F46,0xFF,0x00000004,20050411
# I,0x00000F47,0x9D,0x00000003,20050421
# I,0x00000F48,0x01,0x0000000C,20060508
# I,0x00000F48,0x02,0x0000000E,20080115
# I,0x00000F48,0x5F,0x00000007,20050630
# I,0x00000F49,0xBD,0x00000003,20050421
# I,0x00000F4A,0x5C,0x00000004,20051214
# I,0x00000F4A,0x5D,0x00000002,20050610
# I,0x00000F60,0xFF,0x00000005,20050124
# I,0x00000F61,0xFF,0x00000008,20050610
# I,0x00000F62,0x04,0x0000000F,20051215
# I,0x00000F63,0xFF,0x00000005,20051010
# I,0x00000F64,0x01,0x00000002,20051215
# I,0x00000F64,0x34,0x00000004,20051223
# I,0x00000F65,0x01,0x00000008,20060426
# I,0x00000F66,0xFF,0x0000001B,20060310
# I,0x00000F68,0x22,0x00000009,20060714
# I,0x00001632,0x00,0x00000002,19980610
# I,0x00010650,0xFF,0x00000002,20060513
# I,0x00010660,0xFF,0x00000004,20060612
# I,0x00010661,0x01,0x00000043,20101004
# I,0x00010661,0x02,0x00000042,20101004
# I,0x00010661,0x80,0x00000044,20101004
# I,0x00010670,0xFF,0x00000005,20070209
# I,0x00010671,0xFF,0x00000106,20070329
# I,0x00010674,0xFF,0x84050100,20070726
# I,0x00010676,0x01,0x0000060F,20100929
# I,0x00010676,0x04,0x0000060F,20100929
# I,0x00010676,0x10,0x0000060F,20100929
# I,0x00010676,0x40,0x0000060F,20100929
# I,0x00010676,0x80,0x0000060F,20100929
# I,0x00010677,0x10,0x0000070A,20100929
# I,0x0001067A,0x11,0x00000A0B,20100928
# I,0x0001067A,0x44,0x00000A0B,20100928
# I,0x0001067A,0xA0,0x00000A0B,20100928
# I,0x000106A0,0xFF,0xFFFF001A,20071128
# I,0x000106A1,0xFF,0xFFFF000B,20080220
# I,0x000106A2,0xFF,0xFFFF0019,20080714
# I,0x000106A4,0x03,0x00000012,20130621
# I,0x000106A5,0x03,0x0000001D,20180511
# I,0x000106C0,0xFF,0x00000007,20070824
# I,0x000106C1,0xFF,0x00000109,20071203
# I,0x000106C2,0x01,0x00000217,20090410
# I,0x000106C2,0x04,0x00000218,20090410
# I,0x000106C2,0x08,0x00000219,20090410
# I,0x000106C9,0xFF,0x00000007,20090213
# I,0x000106CA,0x01,0x00000107,20090825
# I,0x000106CA,0x04,0x00000107,20090825
# I,0x000106CA,0x08,0x00000107,20090825
# I,0x000106CA,0x10,0x00000107,20090825
# I,0x000106D0,0xFF,0x00000005,20071204
# I,0x000106D1,0x08,0x00000029,20100930
# I,0x000106E0,0xFF,0xFFFF0022,20090116
# I,0x000106E1,0xFF,0xFFFF000D,20090206
# I,0x000106E2,0xFF,0xFFFF0011,20090924
# I,0x000106E3,0xFF,0xFFFF0011,20090512
# I,0x000106E4,0xFF,0x00000003,20130701
# I,0x000106E5,0x13,0x0000000A,20180508
# I,0x000106F0,0xFF,0xFFFF0009,20090210
# I,0x000106F1,0xFF,0xFFFF0007,20090210
# I,0x00020650,0xFF,0xFFFF0008,20090218
# I,0x00020651,0xFF,0xFFFF0018,20090818
# I,0x00020652,0x12,0x00000011,20180508
# I,0x00020654,0xFF,0xFFFF0007,20091124
# I,0x00020655,0x92,0x00000007,20180423
# I,0x00020661,0x01,0x00000104,20091023
# I,0x00020661,0x02,0x00000105,20110718
# I,0x000206A0,0xFF,0x00000029,20091102
# I,0x000206A1,0xFF,0x00000007,20091223
# I,0x000206A2,0xFF,0x00000027,20100502
# I,0x000206A3,0xFF,0x00000009,20100609
# I,0x000206A4,0xFF,0x00000022,20100414
# I,0x000206A5,0xFF,0x00000007,20100722
# I,0x000206A6,0xFF,0x90030028,20100924
# I,0x000206A7,0x12,0x0000002F,20190217
# I,0x000206C0,0xFF,0xFFFF001C,20091214
# I,0x000206C1,0xFF,0x00000006,20091222
# I,0x000206C2,0x03,0x0000001F,20180508
# I,0x000206D0,0xFF,0x80000006,20100816
# I,0x000206D1,0xFF,0x80000106,20101201
# I,0x000206D2,0xFF,0xAF506958,20110714
# I,0x000206D3,0xFF,0xAF50696A,20110816
# I,0x000206D5,0xFF,0xAF5069E5,20120118
# I,0x000206D6,0x6D,0x00000621,20200304
# I,0x000206D7,0x6D,0x0000071A,20200324
# I,0x000206E0,0xFF,0xE3493401,20090108
# I,0x000206E1,0xFF,0xE3493402,20090224
# I,0x000206E2,0xFF,0xFFFF0004,20081001
# I,0x000206E3,0xFF,0xE4486547,20090701
# I,0x000206E4,0xFF,0xFFFF0008,20090619
# I,0x000206E5,0xFF,0xFFFF0018,20091215
# I,0x000206E6,0x04,0x0000000D,20180515
# I,0x000206F0,0xFF,0x00000005,20100729
# I,0x000206F1,0xFF,0x00000008,20101013
# I,0x000206F2,0x05,0x0000003B,20180516
# I,0x00030650,0xFF,0x00000009,20120118
# I,0x00030651,0xFF,0x00000110,20131014
# I,0x00030660,0xFF,0x00000003,20101103
# I,0x00030661,0xFF,0x0000010F,20150721
# I,0x00030669,0xFF,0x0000010D,20130515
# I,0x00030671,0xFF,0x00000117,20130410
# I,0x00030672,0xFF,0x0000022E,20140401
# I,0x00030673,0xFF,0x83290100,20190916
# I,0x00030678,0x02,0x00000838,20190422
# I,0x00030678,0x0C,0x00000838,20190422
# I,0x00030679,0x0F,0x0000090D,20190710
# I,0x000306A0,0xFF,0x00000007,20110407
# I,0x000306A2,0xFF,0x0000000C,20110725
# I,0x000306A4,0xFF,0x00000007,20110908
# I,0x000306A5,0xFF,0x00000009,20111110
# I,0x000306A6,0xFF,0x00000004,20111114
# I,0x000306A8,0xFF,0x00000010,20120220
# I,0x000306A9,0x12,0x00000021,20190213
# I,0x000306C0,0xFF,0xFFFF0013,20111110
# I,0x000306C1,0xFF,0xFFFF0014,20120725
# I,0x000306C2,0xFF,0xFFFF0006,20121017
# I,0x000306C3,0x32,0x00000028,20191112
# I,0x000306D1,0xFF,0xFFFF0009,20131015
# I,0x000306D2,0xFF,0xFFFF0009,20131219
# I,0x000306D3,0xFF,0xE3121338,20140825
# I,0x000306D4,0xC0,0x0000002F,20191112
# I,0x000306E0,0xFF,0xE920080F,20121113
# I,0x000306E2,0xFF,0xE9220827,20130523
# I,0x000306E3,0xFF,0x00000308,20130321
# I,0x000306E4,0xED,0x0000042E,20190314
# I,0x000306E6,0xED,0x00000600,20130619
# I,0x000306E7,0xED,0x00000715,20190314
# I,0x000306F0,0xFF,0xFFFF0017,20130730
# I,0x000306F1,0xFF,0xD141D629,20140416
# I,0x000306F2,0x6F,0x00000049,20210811
# I,0x000306F3,0xFF,0x0000000D,20160211
# I,0x000306F4,0x80,0x0000001A,20210524
# I,0x00040650,0xFF,0xFFFF000B,20121206
# I,0x00040651,0x72,0x00000026,20191112
# I,0x00040660,0xFF,0xFFFF0011,20121012
# I,0x00040661,0x32,0x0000001C,20191112
# I,0x00040670,0xFF,0xFFFF0006,20140304
# I,0x00040671,0x22,0x00000022,20191112
# I,0x000406A0,0xFF,0x80124001,20130521
# I,0x000406A8,0xFF,0x0000081F,20140812
# I,0x000406A9,0xFF,0x0000081F,20140812
# I,0x000406C1,0xFF,0x0000010B,20140814
# I,0x000406C2,0xFF,0x00000221,20150218
# I,0x000406C3,0x01,0x00000368,20190423
# I,0x000406C4,0x01,0x00000411,20190423
# I,0x000406D0,0xFF,0x0000000E,20130612
# I,0x000406D8,0x01,0x0000012D,20190916
# I,0x000406E1,0xFF,0x00000020,20141111
# I,0x000406E2,0xFF,0x0000002C,20150521
# I,0x000406E3,0xC0,0x000000F0,20211112
# I,0x000406E8,0xFF,0x00000026,20160414
# I,0x000406F0,0xFF,0x00000014,20150702
# I,0x000406F1,0xFF,0x0B000041,20240216
# I,0x00050650,0xFF,0x8000002B,20160208
# I,0x00050651,0xFF,0x8000002B,20160208
# I,0x00050652,0xFF,0x80000037,20170502
# I,0x00050653,0x97,0x01000191,20230728
# I,0x00050654,0xB7,0x02007006,20230306
# I,0x00050655,0xB7,0x03000010,20181116
# I,0x00050656,0xFF,0x04003901,20241212
# I,0x00050657,0xBF,0x05003901,20241212
# I,0x0005065A,0xFF,0x86002302,20210416
# I,0x0005065B,0xBF,0x07002B01,20241212
# I,0x00050661,0xFF,0xF1000008,20150130
# I,0x00050662,0x10,0x0000001C,20190617
# I,0x00050663,0x10,0x0700001C,20210612
# I,0x00050664,0x10,0x0F00001A,20210612
# I,0x00050665,0x10,0x0E000015,20230803
# I,0x00050670,0xFF,0xFFFF0030,20151113
# I,0x00050671,0xFF,0x000001B6,20180108
# I,0x000506A0,0xFF,0x00000038,20150112
# I,0x000506C0,0xFF,0x00000002,20140613
# I,0x000506C2,0x01,0x00000014,20180511
# I,0x000506C8,0xFF,0x90011010,20160323
# I,0x000506C9,0x03,0x00000048,20211116
# I,0x000506CA,0x03,0x00000028,20211116
# I,0x000506D1,0xFF,0x00000102,20150605
# I,0x000506E0,0xFF,0x00000018,20141119
# I,0x000506E1,0xFF,0x0000002A,20150602
# I,0x000506E2,0xFF,0x0000002E,20150815
# I,0x000506E3,0x36,0x000000F0,20211112
# I,0x000506E8,0xFF,0x00000034,20160710
# I,0x000506F0,0xFF,0x00000010,20160607
# I,0x000506F1,0x01,0x0000003E,20231005
# I,0x00060660,0xFF,0x0000000C,20160821
# I,0x00060661,0xFF,0x0000000E,20170128
# I,0x00060662,0xFF,0x00000022,20171129
# I,0x00060663,0x80,0x0000002A,20180417
# I,0x000606A0,0xFF,0x80000031,20200308
# I,0x000606A4,0xFF,0x0B000280,20200817
# I,0x000606A5,0x87,0x0C0002F0,20210308
# I,0x000606A6,0x87,0x0D000421,20250819
# I,0x000606C0,0xFF,0xFD000220,20210629
# I,0x000606C1,0x10,0x010002F1,20250819
# I,0x000606E0,0xFF,0x0000000B,20161104
# I,0x000606E1,0xFF,0x00000108,20190423
# I,0x000606E4,0xFF,0x0000000C,20190124
# I,0x000706A0,0xFF,0x00000026,20170712
# I,0x000706A1,0x01,0x00000042,20240419
# I,0x000706A8,0x01,0x00000026,20241205
# I,0x000706E0,0xFF,0x0000002C,20180614
# I,0x000706E1,0xFF,0x00000042,20190420
# I,0x000706E2,0xFF,0x00000042,20190420
# I,0x000706E3,0xFF,0x81000008,20181002
# I,0x000706E4,0xFF,0x00000046,20190905
# I,0x000706E5,0x80,0x000000CC,20250724
# I,0x00080650,0xFF,0x00000018,20180108
# I,0x00080664,0xFF,0x4C000025,20230926
# I,0x00080665,0xFF,0x4C000026,20240228
# I,0x00080667,0xFF,0x4C000026,20240228
# I,0x000806A0,0xFF,0x00000010,20190507
# I,0x000806A1,0x10,0x00000033,20230113
# I,0x000806C0,0xFF,0x00000068,20200402
# I,0x000806C1,0x80,0x000000BE,20250724
# I,0x000806C2,0xC2,0x0000003E,20250724
# I,0x000806D0,0xFF,0x00000054,20210507
# I,0x000806D1,0xC2,0x00000058,20250724
# I,0x000806E9,0x10,0x000000F6,20240201
# I,0x000806E9,0xC0,0x000000F6,20240201
# I,0x000806EA,0xC0,0x000000F6,20240201
# I,0x000806EB,0xD0,0x000000F6,20240201
# I,0x000806EC,0x94,0x00000100,20241117
# I,0x000806F1,0xFF,0x800003C0,20220327
# I,0x000806F2,0xFF,0x8C0004E0,20211112
# I,0x000806F3,0xFF,0x8D000520,20220812
# I,0x000806F4,0x10,0x2C000421,20250825
# I,0x000806F4,0x87,0x2B000661,20250825
# I,0x000806F5,0x10,0x2C000421,20250825
# I,0x000806F5,0x87,0x2B000661,20250825
# I,0x000806F6,0x10,0x2C000421,20250825
# I,0x000806F6,0x87,0x2B000661,20250825
# I,0x000806F7,0x87,0x2B000661,20250825
# I,0x000806F8,0x10,0x2C000421,20250825
# I,0x000806F8,0x87,0x2B000661,20250825
# I,0x00090660,0xFF,0x00000009,20200617
# I,0x00090661,0x01,0x0000001A,20240405
# I,0x00090670,0xFF,0x00000019,20201111
# I,0x00090671,0xFF,0x0000001C,20210614
# I,0x00090672,0x07,0x0000003E,20251012
# I,0x00090674,0xFF,0x00000219,20210425
# I,0x00090675,0x07,0x0000003E,20251012
# I,0x000906A0,0xFF,0x0000001C,20210614
# I,0x000906A1,0xFF,0x0000011F,20211104
# I,0x000906A2,0xFF,0x00000315,20220102
# I,0x000906A3,0x80,0x0000043B,20251012
# I,0x000906A4,0x40,0x0000000C,20250710
# I,0x000906A4,0x80,0x0000043B,20251012
# I,0x000906C0,0x01,0x24000026,20230926
# I,0x000906E9,0x2A,0x000000F8,20230928
# I,0x000906EA,0x22,0x000000FA,20240728
# I,0x000906EB,0x02,0x000000F6,20240201
# I,0x000906EC,0x22,0x000000F8,20240201
# I,0x000906ED,0x22,0x00000104,20241114
# I,0x000A0650,0xFF,0x000000BE,20191010
# I,0x000A0651,0xFF,0x000000C2,20191113
# I,0x000A0652,0x20,0x00000100,20241114
# I,0x000A0653,0x22,0x00000100,20241114
# I,0x000A0654,0xFF,0x000000C6,20200123
# I,0x000A0655,0x22,0x00000100,20241114
# I,0x000A0660,0x80,0x00000102,20241114
# I,0x000A0661,0x80,0x00000100,20241114
# I,0x000A0670,0xFF,0x0000002C,20201124
# I,0x000A0671,0x02,0x00000065,20250724
# I,0x000A0680,0xFF,0x80000002,20200121
# I,0x000A06A1,0xFF,0x00000017,20230518
# I,0x000A06A2,0xFF,0x00000011,20230627
# I,0x000A06A4,0xE6,0x00000028,20250924
# I,0x000A06C0,0xFF,0x00000013,20230901
# I,0x000A06C1,0xFF,0x00000005,20231201
# I,0x000A06D0,0xFF,0x10000680,20240818
# I,0x000A06D1,0x20,0x0A000133,20251009
# I,0x000A06D1,0x95,0x01000405,20251031
# I,0x000A06E1,0x97,0x01000303,20251202
# I,0x000A06F0,0xFF,0x80000360,20240130
# I,0x000A06F3,0x01,0x03000382,20250730
# I,0x000B0650,0x80,0x0000000D,20250925
# I,0x000B0664,0xFF,0x00000030,20250529
# I,0x000B0670,0xFF,0x0000000E,20220220
# I,0x000B0671,0x32,0x00000133,20251008
# I,0x000B0674,0x32,0x00000133,20251008
# I,0x000B06A2,0xE0,0x00006134,20251008
# I,0x000B06A3,0xE0,0x00006134,20251008
# I,0x000B06A8,0xE0,0x00006134,20251008
# I,0x000B06D0,0xFF,0x0000001A,20240610
# I,0x000B06D1,0x80,0x00000125,20250828
# I,0x000B06E0,0x19,0x00000021,20250912
# I,0x000B06F2,0x07,0x0000003E,20251012
# I,0x000B06F5,0x07,0x0000003E,20251012
# I,0x000B06F6,0x07,0x0000003E,20251012
# I,0x000B06F7,0x07,0x0000003E,20251012
# I,0x000C0652,0x82,0x0000011B,20250803
# I,0x000C0660,0xFF,0x00000018,20240516
# I,0x000C0662,0x82,0x0000011B,20250803
# I,0x000C0664,0x82,0x0000011B,20250803
# I,0x000C06A2,0x82,0x0000011B,20250803
# I,0x000C06C0,0xFF,0x00000012,20250325
# I,0x000C06C1,0xFF,0x00000115,20251203
# I,0x000C06C2,0xFF,0x00000115,20251203
# I,0x000C06C3,0xFF,0x00000115,20251203
# I,0x000C06F1,0x87,0x210002D3,20250825
# I,0x000C06F2,0x87,0x210002D3,20250825
# I,0x000D0670,0xFF,0x00000003,20250825
# I,0x000D06D0,0xFF,0x00000340,20250807
# I,0x00FF0671,0xFF,0x0000010E,20220907
# I,0x00FF0672,0xFF,0x0000000D,20210816
# I,0x00FF0675,0xFF,0x0000000D,20210816
# A,0x00000F00,0xFF,0x02000008,20070614
# A,0x00000F01,0xFF,0x0000001C,20021031
# A,0x00000F10,0xFF,0x00000003,20020325
# A,0x00000F11,0xFF,0x0000001F,20030220
# A,0x00000F48,0xFF,0x00000046,20040719
# A,0x00000F4A,0xFF,0x00000047,20040719
# A,0x00000F50,0xFF,0x00000024,20021212
# A,0x00000F51,0xFF,0x00000025,20030115
# A,0x00010F50,0xFF,0x00000041,20040225
# A,0x00020F10,0xFF,0x0000004D,20050428
# A,0x00040F01,0xFF,0xC0012102,20050916
# A,0x00040F0A,0xFF,0x00000068,20060920
# A,0x00040F13,0xFF,0x0000007A,20080508
# A,0x00040F14,0xFF,0x00000062,20060127
# A,0x00040F1B,0xFF,0x0000006D,20060920
# A,0x00040F33,0xFF,0x0000007B,20080514
# A,0x00060F80,0xFF,0x00000083,20060929
# A,0x000C0F1B,0xFF,0x0000006E,20060921
# A,0x000F0F00,0xFF,0x00000005,20020627
# A,0x000F0F01,0xFF,0x00000015,20020627
# A,0x00100F00,0xFF,0x01000020,20070326
# A,0x00100F20,0xFF,0x010000CA,20100331
# A,0x00100F22,0xFF,0x010000C9,20100331
# A,0x00100F2A,0xFF,0x01000084,20000101
# A,0x00100F40,0xFF,0x01000085,20080501
# A,0x00100F41,0xFF,0x010000DB,20111024
# A,0x00100F42,0xFF,0x01000092,20081021
# A,0x00100F43,0xFF,0x010000C8,20100311
# A,0x00100F52,0xFF,0x010000DB,20000101
# A,0x00100F53,0xFF,0x010000C8,20000101
# A,0x00100F62,0xFF,0x010000C7,20100311
# A,0x00100F80,0xFF,0x010000DA,20111024
# A,0x00100F81,0xFF,0x010000D9,20111012
# A,0x00100F91,0xFF,0x010000D9,20000101
# A,0x00100FA0,0xFF,0x010000DC,20111024
# A,0x00120F00,0xFF,0x03000002,20100324
# A,0x00200F30,0xFF,0x02000018,20070921
# A,0x00200F31,0xFF,0x02000057,20080502
# A,0x00200F32,0xFF,0x02000034,20080307
# A,0x00300F01,0xFF,0x0300000E,20101004
# A,0x00300F10,0xFF,0x03000027,20111209
# A,0x00500F00,0xFF,0x0500000B,20100601
# A,0x00500F01,0xFF,0x0500001A,20100908
# A,0x00500F10,0xFF,0x05000029,20130121
# A,0x00500F20,0xFF,0x05000119,20130118
# A,0x00580F00,0xFF,0x0500000B,20100601
# A,0x00580F01,0xFF,0x0500001A,20100908
# A,0x00580F10,0xFF,0x05000028,20101124
# A,0x00580F20,0xFF,0x05000103,20110526
# A,0x00600F00,0xFF,0x06000017,20101029
# A,0x00600F01,0xFF,0x0600011F,20110227
# A,0x00600F10,0xFF,0x06000425,20110408
# A,0x00600F11,0xFF,0x0600050D,20110627
# A,0x00600F12,0xFF,0x0600063E,20180207
# A,0x00600F20,0xFF,0x06000852,20180206
# A,0x00610F00,0xFF,0x0600100E,20111102
# A,0x00610F01,0xFF,0x0600111F,20180305
# A,0x00630F00,0xFF,0x0600301C,20130817
# A,0x00630F01,0xFF,0x06003109,20180227
# A,0x00660F00,0xFF,0x06006108,20150302
# A,0x00660F01,0xFF,0x0600611A,20180126
# A,0x00670F00,0xFF,0x06006705,20180220
# A,0x00680F00,0xFF,0x06000017,20101029
# A,0x00680F01,0xFF,0x0600011F,20110227
# A,0x00680F10,0xFF,0x06000410,20110314
# A,0x00690F00,0xFF,0x06001009,20110613
# A,0x00700F00,0xFF,0x0700002A,20121218
# A,0x00700F01,0xFF,0x07000110,20180209
# A,0x00730F00,0xFF,0x07030009,20131206
# A,0x00730F01,0xFF,0x07030106,20180209
# A,0x00800F00,0xFF,0x0800002A,20161006
# A,0x00800F10,0xFF,0x0800100C,20170131
# A,0x00800F11,0xFF,0x08001139,20240822
# A,0x00800F12,0xFF,0x08001279,20241111
# A,0x00800F82,0xFF,0x0800820E,20240815
# A,0x00810F00,0xFF,0x08100004,20161120
# A,0x00810F10,0xFF,0x0810101B,20240716
# A,0x00810F11,0xFF,0x08101104,20240703
# A,0x00810F80,0xFF,0x08108002,20180605
# A,0x00810F81,0xFF,0x0810810E,20241112
# A,0x00820F00,0xFF,0x08200002,20180214
# A,0x00820F01,0xFF,0x08200105,20241111
# A,0x00830F00,0xFF,0x08300027,20190401
# A,0x00830F10,0xFF,0x0830107F,20241111
# A,0x00850F00,0xFF,0x08500004,20180212
# A,0x00860F00,0xFF,0x0860000E,20200127
# A,0x00860F01,0xFF,0x0860010F,20241118
# A,0x00860F81,0xFF,0x08608109,20241118
# A,0x00870F00,0xFF,0x08700004,20181206
# A,0x00870F10,0xFF,0x08701035,20241118
# A,0x00880F40,0xFF,0x08804005,20210312
# A,0x00890F00,0xFF,0x08900007,20200921
# A,0x00890F01,0xFF,0x08900103,20201105
# A,0x00890F02,0xFF,0x08900203,20230915
# A,0x00890F10,0xFF,0x08901003,20230919
# A,0x008A0F00,0xFF,0x08A0000B,20241125
# A,0x00A00F00,0xFF,0x0A000033,20200413
# A,0x00A00F10,0xFF,0x0A00107A,20240226
# A,0x00A00F11,0xFF,0x0A0011DE,20250418
# A,0x00A00F12,0xFF,0x0A001247,20250327
# A,0x00A00F80,0xFF,0x0A008005,20230707
# A,0x00A00F82,0xFF,0x0A00820F,20241111
# A,0x00A10F00,0xFF,0x0A10004B,20220309
# A,0x00A10F01,0xFF,0x0A100104,20220207
# A,0x00A10F0B,0xFF,0x0A100B07,20220610
# A,0x00A10F10,0xFF,0x0A101020,20220913
# A,0x00A10F11,0xFF,0x0A101158,20250609
# A,0x00A10F12,0xFF,0x0A101253,20250612
# A,0x00A10F80,0xFF,0x0A108005,20230613
# A,0x00A10F81,0xFF,0x0A10810C,20241112
# A,0x00A20F00,0xFF,0x0A200025,20200121
# A,0x00A20F10,0xFF,0x0A201030,20241111
# A,0x00A20F12,0xFF,0x0A201213,20241205
# A,0x00A40F00,0xFF,0x0A400016,20210330
# A,0x00A40F40,0xFF,0x0A404002,20210408
# A,0x00A40F41,0xFF,0x0A40410A,20241111
# A,0x00A50F00,0xFF,0x0A500014,20241111
# A,0x00A60F00,0xFF,0x0A600005,20211220
# A,0x00A60F11,0xFF,0x0A601119,20230613
# A,0x00A60F12,0xFF,0x0A60120C,20241110
# A,0x00A60F13,0xFF,0x0A601302,20250228
# A,0x00A70F00,0xFF,0x0A700003,20220517
# A,0x00A70F40,0xFF,0x0A704001,20220721
# A,0x00A70F41,0xFF,0x0A70410A,20241108
# A,0x00A70F42,0xFF,0x0A704202,20230713
# A,0x00A70F52,0xFF,0x0A70520A,20241111
# A,0x00A70F80,0xFF,0x0A70800A,20241111
# A,0x00A70FC0,0xFF,0x0A70C00A,20241111
# A,0x00A80F00,0xFF,0x0A80000B,20241122
# A,0x00A80F01,0xFF,0x0A80010A,20241119
# A,0x00A90F00,0xFF,0x0A90000C,20250710
# A,0x00A90F01,0xFF,0x0A90010D,20250612
# A,0x00AA0F00,0xFF,0x0AA00009,20221006
# A,0x00AA0F01,0xFF,0x0AA00116,20230619
# A,0x00AA0F02,0xFF,0x0AA0021C,20250612
# A,0x00B00F00,0xFF,0x0B00004D,20240318
# A,0x00B00F10,0xFF,0x0B001016,20240318
# A,0x00B00F20,0xFF,0x0B002032,20241003
# A,0x00B00F21,0xFF,0x0B002161,20251105
# A,0x00B00F80,0xFF,0x0B008011,20241211
# A,0x00B00F81,0xFF,0x0B008121,20251020
# A,0x00B10F00,0xFF,0x0B10000F,20240320
# A,0x00B10F10,0xFF,0x0B101058,20251105
# A,0x00B20F40,0xFF,0x0B204037,20251019
# A,0x00B40F00,0xFF,0x0B400034,20240318
# A,0x00B40F40,0xFF,0x0B404035,20251020
# A,0x00B40F41,0xFF,0x0B404108,20251020
# A,0x00B60F00,0xFF,0x0B600037,20251019
# A,0x00B60F80,0xFF,0x0B608038,20251019
# A,0x00B70F00,0xFF,0x0B700037,20251019
