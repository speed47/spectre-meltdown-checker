#! /bin/sh
# SPDX-License-Identifier: GPL-3.0-only
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
VERSION='0.40'

trap 'exit_cleanup' EXIT
trap '_warn "interrupted, cleaning up..."; exit_cleanup; exit 1' INT
exit_cleanup()
{
	# cleanup the temp decompressed config & kernel image
	[ -n "$dumped_config" ] && [ -f "$dumped_config" ] && rm -f "$dumped_config"
	[ -n "$kerneltmp"     ] && [ -f "$kerneltmp"     ] && rm -f "$kerneltmp"
	[ -n "$kerneltmp2"    ] && [ -f "$kerneltmp2"    ] && rm -f "$kerneltmp2"
	[ -n "$mcedb_tmp"     ] && [ -f "$mcedb_tmp"     ] && rm -f "$mcedb_tmp"
	[ "$mounted_debugfs" = 1 ] && umount /sys/kernel/debug 2>/dev/null
	[ "$mounted_procfs"  = 1 ] && umount "$procfs" 2>/dev/null
	[ "$insmod_cpuid"    = 1 ] && rmmod cpuid 2>/dev/null
	[ "$insmod_msr"      = 1 ] && rmmod msr 2>/dev/null
	[ "$kldload_cpuctl"  = 1 ] && kldunload cpuctl 2>/dev/null
}

# if we were git clone'd, adjust VERSION
if [ -d "$(dirname "$0")/.git" ] && which git >/dev/null 2>&1; then
	describe=$(git -C "$(dirname "$0")" describe --tags --dirty 2>/dev/null)
	[ -n "$describe" ] && VERSION=$(echo "$describe" | sed -e s/^v//)
fi

show_usage()
{
	# shellcheck disable=SC2086
	cat <<EOF
	Usage:
		Live mode:    $(basename $0) [options] [--live]
		Offline mode: $(basename $0) [options] [--kernel <kernel_file>] [--config <kernel_config>] [--map <kernel_map_file>]

	Modes:
		Two modes are available.

		First mode is the "live" mode (default), it does its best to find information about the currently running kernel.
		To run under this mode, just start the script without any option (you can also use --live explicitly)

		Second mode is the "offline" mode, where you can inspect a non-running kernel.
		You'll need to specify the location of the kernel file, config and System.map files:

		--kernel kernel_file	specify a (possibly compressed) Linux or BSD kernel file
		--config kernel_config	specify a kernel config file (Linux only)
		--map kernel_map_file	specify a kernel System.map file (Linux only)

	Options:
		--no-color		don't use color codes
		--verbose, -v		increase verbosity level, possibly several times
		--explain		produce an additional human-readable explanation of actions to take to mitigate a vulnerability
		--paranoid		require IBPB to deem Variant 2 as mitigated
					also require SMT disabled + unconditional L1D flush to deem Foreshadow-NG VMM as mitigated

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

		--variant [1,2,3,3a,4,l1tf]	specify which variant you'd like to check, by default all variants are checked
		--cve [cve1,cve2,...]		specify which CVE you'd like to check, by default all supported CVEs are checked
					can be specified multiple times (e.g. --variant 2 --variant 3)
		--hw-only		only check for CPU information, don't check for any variant
		--no-hw			skip CPU information and checks, if you're inspecting a kernel not to be run on this host
		--vmm [auto,yes,no]	override the detection of the presence of a hypervisor (for CVE-2018-3646), default: auto
		--update-mcedb		update our local copy of the CPU microcodes versions database (from the awesome MCExtractor project)
		--update-builtin-mcedb	same as --update-mcedb but update builtin DB inside the script itself

	Return codes:
		0 (not vulnerable), 2 (vulnerable), 3 (unknown), 255 (error)

	IMPORTANT:
	A false sense of security is worse than no security at all.
	Please use the --disclaimer option to understand exactly what this script does.

EOF
}

show_disclaimer()
{
	cat <<EOF
Disclaimer:

This tool does its best to determine whether your system is immune (or has proper mitigations in place) for the
collectively named "speculative execution" vulnerabilities. It doesn't attempt to run any kind of exploit, and can't guarantee
that your system is secure, but rather helps you verifying whether your system has the known correct mitigations in place.
However, some mitigations could also exist in your kernel that this script doesn't know (yet) how to detect, or it might
falsely detect mitigations that in the end don't work as expected (for example, on backported or modified kernels).

Your system exposure also depends on your CPU. As of now, AMD and ARM processors are marked as immune to some or all of these
vulnerabilities (except some specific ARM models). All Intel processors manufactured since circa 1995 are thought to be vulnerable,
except some specific/old models, such as some early Atoms. Whatever processor one uses, one might seek more information
from the manufacturer of that processor and/or of the device in which it runs.

The nature of the discovered vulnerabilities being quite new, the landscape of vulnerable processors can be expected
to change over time, which is why this script makes the assumption that all CPUs are vulnerable, except if the manufacturer
explicitly stated otherwise in a verifiable public announcement.

Please also note that for Spectre vulnerabilities, all software can possibly be exploited, this tool only verifies that the
kernel (which is the core of the system) you're using has the proper protections in place. Verifying all the other software
is out of the scope of this tool. As a general measure, ensure you always have the most up to date stable versions of all
the software you use, especially for those who are exposed to the world, such as network daemons and browsers.

This tool has been released in the hope that it'll be useful, but don't use it to jump to conclusions about your security.

EOF
}

os=$(uname -s)

# parse options
opt_kernel=''
opt_config=''
opt_map=''
opt_live_explicit=0
opt_live=1
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
opt_explain=0
opt_paranoid=0

global_critical=0
global_unknown=0
nrpe_vuln=''

supported_cve_list='CVE-2017-5753 CVE-2017-5715 CVE-2017-5754 CVE-2018-3640 CVE-2018-3639 CVE-2018-3615 CVE-2018-3620 CVE-2018-3646'

# find a sane command to print colored messages, we prefer `printf` over `echo`
# because `printf` behavior is more standard across Linux/BSD
# we'll try to avoid using shell builtins that might not take options
echo_cmd_type=echo
if which printf >/dev/null 2>&1; then
	echo_cmd=$(which printf)
	echo_cmd_type=printf
elif which echo >/dev/null 2>&1; then
	echo_cmd=$(which echo)
else
	# maybe the `which` command is broken?
	[ -x /bin/echo        ] && echo_cmd=/bin/echo
	# for Android
	[ -x /system/bin/echo ] && echo_cmd=/system/bin/echo
fi
# still empty? fallback to builtin
[ -z "$echo_cmd" ] && echo_cmd=echo
__echo()
{
	opt="$1"
	shift
	_msg="$*"

	if [ "$opt_no_color" = 1 ] ; then
		# strip ANSI color codes
		# some sed versions (i.e. toybox) can't seem to handle
		# \033 aka \x1B correctly, so do it for them.
		if [ "$echo_cmd_type" = printf ]; then
			_interpret_chars=''
		else
			_interpret_chars='-e'
		fi
		_ctrlchar=$($echo_cmd $_interpret_chars "\033")
		_msg=$($echo_cmd $_interpret_chars "$_msg" | sed -r "s/$_ctrlchar\[([0-9][0-9]?(;[0-9][0-9]?)?)?m//g")
	fi
	if [ "$echo_cmd_type" = printf ]; then
		if [ "$opt" = "-n" ]; then
			$echo_cmd "$_msg"
		else
			$echo_cmd "$_msg\n"
		fi
	else
		# shellcheck disable=SC2086
		$echo_cmd $opt -e "$_msg"
	fi
}

_echo()
{
	if [ "$opt_verbose" -ge "$1" ]; then
		shift
		__echo '' "$*"
	fi
}

_echo_nol()
{
	if [ "$opt_verbose" -ge "$1" ]; then
		shift
		__echo -n "$*"
	fi
}

_warn()
{
	_echo 0 "\033[31m$*\033[0m" >&2
}

_info()
{
	_echo 1 "$*"
}

_info_nol()
{
	_echo_nol 1 "$*"
}

_verbose()
{
	_echo 2 "$*"
}

_verbose_nol()
{
	_echo_nol 2 "$*"
}

_debug()
{
	_echo 3 "\033[34m(debug) $*\033[0m"
}

explain()
{
	if [ "$opt_explain" = 1 ] ; then
		_info ''
		_info "> \033[41m\033[30mHow to fix:\033[0m $*"
	fi
}

cve2name()
{
	case "$1" in
		CVE-2017-5753) echo "Spectre Variant 1, bounds check bypass";;
		CVE-2017-5715) echo "Spectre Variant 2, branch target injection";;
		CVE-2017-5754) echo "Variant 3, Meltdown, rogue data cache load";;
		CVE-2018-3640) echo "Variant 3a, rogue system register read";;
		CVE-2018-3639) echo "Variant 4, speculative store bypass";;
		CVE-2018-3615) echo "Foreshadow (SGX), L1 terminal fault";;
		CVE-2018-3620) echo "Foreshadow-NG (OS), L1 terminal fault";;
		CVE-2018-3646) echo "Foreshadow-NG (VMM), L1 terminal fault";;
	esac
}

is_cpu_vulnerable_cached=0
_is_cpu_vulnerable_cached()
{
	# shellcheck disable=SC2086
	case "$1" in
		CVE-2017-5753) return $variant1;;
		CVE-2017-5715) return $variant2;;
		CVE-2017-5754) return $variant3;;
		CVE-2018-3640) return $variant3a;;
		CVE-2018-3639) return $variant4;;
		CVE-2018-3615) return $variantl1tf_sgx;;
		CVE-2018-3620) return $variantl1tf;;
		CVE-2018-3646) return $variantl1tf;;
	esac
	echo "$0: error: invalid variant '$1' passed to is_cpu_vulnerable()" >&2
	exit 255
}

is_cpu_vulnerable()
{
	# param: one of the $supported_cve_list items
	# returns 0 if vulnerable, 1 if not vulnerable
	# (note that in shell, a return of 0 is success)
	# by default, everything is vulnerable, we work in a "whitelist" logic here.
	# usage: is_cpu_vulnerable CVE-xxxx-yyyy && do something if vulnerable
	if [ "$is_cpu_vulnerable_cached" = 1 ]; then
		_is_cpu_vulnerable_cached "$1"
		return $?
	fi

	variant1=''
	variant2=''
	variant3=''
	variant3a=''
	variant4=''
	variantl1tf=''

	if is_cpu_specex_free; then
		variant1=immune
		variant2=immune
		variant3=immune
		variant3a=immune
		variant4=immune
		variantl1tf=immune
	elif is_intel; then
		# Intel
		# https://github.com/crozone/SpectrePoC/issues/1 ^F E5200 => spectre 2 not vulnerable
		# https://github.com/paboldin/meltdown-exploit/issues/19 ^F E5200 => meltdown vulnerable
		# model name : Pentium(R) Dual-Core  CPU      E5200  @ 2.50GHz
		if grep -qE '^model name.+ Pentium\(R\) Dual-Core[[:space:]]+CPU[[:space:]]+E[0-9]{4}K? ' "$procfs/cpuinfo"; then
			variant1=vuln
			[ -z "$variant2" ] && variant2=immune
			variant3=vuln
		fi
		if [ "$capabilities_rdcl_no" = 1 ]; then
			# capability bit for future Intel processor that will explicitly state
			# that they're not vulnerable to Meltdown
			# this var is set in check_cpu()
			[ -z "$variant3" ]    && variant3=immune
			[ -z "$variantl1tf" ] && variantl1tf=immune
			_debug "is_cpu_vulnerable: RDCL_NO is set so not vuln to meltdown nor l1tf"
		fi
		if [ "$capabilities_ssb_no" = 1 ]; then
			# capability bit for future Intel processor that will explicitly state
			# that they're not vulnerable to Variant 4
			# this var is set in check_cpu()
			[ -z "$variant4" ] && variant4=immune
			_debug "is_cpu_vulnerable: SSB_NO is set so not vuln to variant4"
		fi
		if is_cpu_ssb_free; then
			[ -z "$variant4" ] && variant4=immune
			_debug "is_cpu_vulnerable: cpu not affected by speculative store bypass so not vuln to variant4"
		fi
		# variant 4a for xeon phi
		if [ "$cpu_family" = 6 ]; then
			if [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNL" ] || [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNM" ]; then
				_debug "is_cpu_vulnerable: xeon phi immune to variant 3a"
				[ -z "$variant3a" ] && variant3a=immune
			fi
		fi
		# L1TF (RDCL_NO already checked above)
		if [ "$cpu_family" = 6 ]; then
			if [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL"          ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_TABLET" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_MID" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL_MID" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_MID" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_X" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_AIRMONT" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_AIRMONT_MID" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_X" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_PLUS" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNL"     ] || \
				[ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNM" ]; then

				_debug "is_cpu_vulnerable: intel family 6 but model known to be immune"
				[ -z "$variantl1tf" ] && variantl1tf=immune
			else
				_debug "is_cpu_vulnerable: intel family 6 is vuln"
				variantl1tf=vuln
			fi
		elif [ "$cpu_family" -lt 6 ]; then
			_debug "is_cpu_vulnerable: intel family < 6 is immune"
			[ -z "$variantl1tf" ] && variantl1tf=immune
		fi
	elif is_amd; then
		# AMD revised their statement about variant2 => vulnerable
		# https://www.amd.com/en/corporate/speculative-execution
		variant1=vuln
		variant2=vuln
		[ -z "$variant3"  ] && variant3=immune
		# https://www.amd.com/en/corporate/security-updates
		# "We have not identified any AMD x86 products susceptible to the Variant 3a vulnerability in our analysis to-date."
		[ -z "$variant3a" ] && variant3a=immune
		if is_cpu_ssb_free; then
			[ -z "$variant4" ] && variant4=immune
			_debug "is_cpu_vulnerable: cpu not affected by speculative store bypass so not vuln to variant4"
		fi
		variantl1tf=immune
	elif [ "$cpu_vendor" = CAVIUM ]; then
		variant3=immune
		variant3a=immune
		variantl1tf=immune
	elif [ "$cpu_vendor" = ARM ]; then
		# ARM
		# reference: https://developer.arm.com/support/security-update
		# some devices (phones or other) have several ARMs and as such different part numbers,
		# an example is "bigLITTLE". we shouldn't rely on the first CPU only, so we check the whole list
		i=0
		for cpupart in $cpu_part_list
		do
			i=$(( i + 1 ))
			# do NOT quote $cpu_arch_list below
			# shellcheck disable=SC2086
			cpuarch=$(echo $cpu_arch_list | awk '{ print $'$i' }')
			_debug "checking cpu$i: <$cpupart> <$cpuarch>"
			# some kernels report AArch64 instead of 8
			[ "$cpuarch" = "AArch64" ] && cpuarch=8
			if [ -n "$cpupart" ] && [ -n "$cpuarch" ]; then
				# Cortex-R7 and Cortex-R8 are real-time and only used in medical devices or such
				# I can't find their CPU part number, but it's probably not that useful anyway
				# model R7 R8 A8  A9  A12 A15 A17 A57 A72 A73 A75 A76
				# part   ?  ? c08 c09 c0d c0f c0e d07 d08 d09 d0a d0b?
				# arch  7? 7? 7   7   7   7   7   8   8   8   8   8
				#
				# Whitelist identified non-vulnerable processors, use vulnerability information from 
				# https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability
				#
				# Maintain cumulative check of vulnerabilities -
				# if at least one of the cpu is vulnerable, then the system is vulnerable
				if [ "$cpuarch" = 7 ] && echo "$cpupart" | grep -q -w -e 0xc08 -e 0xc09 -e 0xc0d -e 0xc0e; then
					variant1=vuln
					variant2=vuln
					[ -z "$variant3" ] && variant3=immune
					[ -z "$variant3a" ] && variant3a=immune
					[ -z "$variant4" ] && variant4=immune
					_debug "checking cpu$i: armv7 A8/A9/A12/A17 non vulnerable to variants 3, 3a & 4"
				elif [ "$cpuarch" = 7 ] && echo "$cpupart" | grep -q -w -e 0xc0f; then
					variant1=vuln
					variant2=vuln
					[ -z "$variant3" ] && variant3=immune
					variant3a=vuln
					[ -z "$variant4" ] && variant4=immune
					_debug "checking cpu$i: armv7 A15 non vulnerable to variants 3 & 4"
				elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd07 -e 0xd08; then
					variant1=vuln
					variant2=vuln
					[ -z "$variant3" ] && variant3=immune
					variant3a=vuln
					variant4=vuln
					_debug "checking cpu$i: armv8 A57/A72 non vulnerable to variants 3"
				elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd09; then
					variant1=vuln
					variant2=vuln
					[ -z "$variant3" ] && variant3=immune
					[ -z "$variant3a" ] && variant3a=immune
					variant4=vuln
					_debug "checking cpu$i: armv8 A73 non vulnerable to variants 3 & 3a"
				elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd0a; then
					variant1=vuln
					variant2=vuln
					variant3=vuln
					[ -z "$variant3a" ] && variant3a=immune
					variant4=vuln
					_debug "checking cpu$i: armv8 A75 non vulnerable to variant 3a"
				elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd0b; then
					variant1=vuln
					[ -z "$variant2" ] && variant2=immune
					[ -z "$variant3" ] && variant3=immune
					[ -z "$variant3a" ] && variant3a=immune
					variant4=vuln
					_debug "checking cpu$i: armv8 A76 non vulnerable to variant 2, 3 & 3a"
				elif [ "$cpuarch" -le 7 ] || ( [ "$cpuarch" = 8 ] && [ $(( cpupart )) -lt $(( 0xd07 )) ] ) ; then
					[ -z "$variant1" ] && variant1=immune
					[ -z "$variant2" ] && variant2=immune
					[ -z "$variant3" ] && variant3=immune
					[ -z "$variant3a" ] && variant3a=immune
					[ -z "$variant4" ] && variant4=immune
					_debug "checking cpu$i: arm arch$cpuarch, all immune (v7 or v8 and model < 0xd07)"
				else
					variant1=vuln
					variant2=vuln
					variant3=vuln
					variant3a=vuln
					variant4=vuln
					_debug "checking cpu$i: arm unknown arch$cpuarch part$cpupart, considering vuln"
				fi
			fi
			_debug "is_cpu_vulnerable: for cpu$i and so far, we have <$variant1> <$variant2> <$variant3> <$variant3a> <$variant4>"
		done
		variantl1tf=immune
	fi
	_debug "is_cpu_vulnerable: temp results are <$variant1> <$variant2> <$variant3> <$variant3a> <$variant4> <$variantl1tf>"
	[ "$variant1"    = "immune" ] && variant1=1    || variant1=0
	[ "$variant2"    = "immune" ] && variant2=1    || variant2=0
	[ "$variant3"    = "immune" ] && variant3=1    || variant3=0
	[ "$variant3a"   = "immune" ] && variant3a=1   || variant3a=0
	[ "$variant4"    = "immune" ] && variant4=1    || variant4=0
	[ "$variantl1tf" = "immune" ] && variantl1tf=1 || variantl1tf=0
	variantl1tf_sgx="$variantl1tf"
	# even if we are vulnerable to L1TF, if there's no SGX, we're safe for the original foreshadow
	[ "$cpuid_sgx" = 0 ] && variantl1tf_sgx=1
	_debug "is_cpu_vulnerable: final results are <$variant1> <$variant2> <$variant3> <$variant3a> <$variant4> <$variantl1tf> <$variantl1tf_sgx>"
	is_cpu_vulnerable_cached=1
	_is_cpu_vulnerable_cached "$1"
	return $?
}

is_cpu_specex_free()
{
	# return true (0) if the CPU doesn't do speculative execution, false (1) if it does.
	# if it's not in the list we know, return false (1).
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
			if [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL"	] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_TABLET"	] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL_MID"		] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_MID"	] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL"	]; then
				return 0
			fi
		elif [ "$cpu_family" = 5 ]; then
			return 0
		fi
	fi
	[ "$cpu_family" = 4 ] && return 0
	return 1
}

is_cpu_ssb_free()
{
	# return true (0) if the CPU isn't affected by speculative store bypass, false (1) if it does.
	# if it's not in the list we know, return false (1).
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
			if [ "$cpu_model" = "$INTEL_FAM6_ATOM_AIRMONT"          ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_X" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_MID"  ]; then
				return 0
			elif [ "$cpu_model" = "$INTEL_FAM6_CORE_YONAH"          ] || \
				[ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNL"     ] || \
				[ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNM"     ]; then
				return 0
			fi
		fi
	fi
	if is_amd; then
		if [ "$cpu_family" = "18" ] || \
			[ "$cpu_family" = "17" ] || \
			[ "$cpu_family" = "16" ] || \
			[ "$cpu_family" = "15" ]; then 
			return 0
		fi
	fi			
	[ "$cpu_family" = 4 ] && return 0
	return 1
}

show_header()
{
	_info "Spectre and Meltdown mitigation detection tool v$VERSION"
	_info
}

[ -z "$HOME" ] && HOME="$(getent passwd "$(whoami)" | cut -d: -f6)"
mcedb_cache="$HOME/.mcedb"
update_mcedb()
{
	# We're using MCE.db from the excellent platomav's MCExtractor project
	show_header

	if [ -r "$mcedb_cache" ]; then
		previous_mcedb_revision=$(awk '/^# %%% MCEDB / { print $4 }' "$mcedb_cache")
	fi

	# first download the database
	mcedb_tmp="$(mktemp /tmp/mcedb-XXXXXX)"
	mcedb_url='https://github.com/platomav/MCExtractor/raw/master/MCE.db'
	_info_nol "Fetching MCE.db from the MCExtractor project... "
	if which wget >/dev/null 2>&1; then
		wget -q "$mcedb_url" -O "$mcedb_tmp"; ret=$?
	elif which curl >/dev/null 2>&1; then
		curl -sL "$mcedb_url" -o "$mcedb_tmp"; ret=$?
	elif which fetch >/dev/null 2>&1; then
		fetch -q "$mcedb_url" -o "$mcedb_tmp"; ret=$?
	else
		echo ERROR "please install one of \`wget\`, \`curl\` of \`fetch\` programs"
		return 1
	fi
	if [ "$ret" != 0 ]; then
		echo ERROR "error $ret while downloading MCE.db"
		return $ret
	fi
	echo DONE

	# now extract contents using sqlite
	_info_nol "Extracting data... "
	if ! which sqlite3 >/dev/null 2>&1; then
		echo ERROR "please install the \`sqlite3\` program"
		return 1
	fi
	mcedb_revision=$(sqlite3 "$mcedb_tmp" "select revision from MCE")
	mcedb_date=$(sqlite3 "$mcedb_tmp" "select strftime('%Y/%m/%d', date, 'unixepoch') from MCE")
	if [ -z "$mcedb_revision" ]; then
		echo ERROR "downloaded file seems invalid"
		return 1
	fi
	echo OK "MCExtractor database revision $mcedb_revision dated $mcedb_date"
	if [ -n "$previous_mcedb_revision" ]; then
		if [ "$previous_mcedb_revision" = "v$mcedb_revision" ]; then
			echo "We already have this version locally, no update needed"
			[ "$1" != builtin ] && return 0
		fi
	fi
	echo "# Spectre & Meltdown Checker" > "$mcedb_cache"
	echo "# %%% MCEDB v$mcedb_revision - $mcedb_date" >> "$mcedb_cache"
	sqlite3 "$mcedb_tmp" "select '# I,0x'||cpuid||',0x'||version||','||max(yyyymmdd) from Intel group by cpuid order by cpuid asc; select '# A,0x'||cpuid||',0x'||version||','||max(yyyymmdd) from AMD group by cpuid order by cpuid asc" | grep -v '^# .,0x00000000,' >> "$mcedb_cache"
	echo OK "local version updated"

	if [ "$1" = builtin ]; then
		newfile=$(mktemp /tmp/smc-XXXXXX)
		awk '/^# %%% MCEDB / { exit }; { print }' "$0" > "$newfile"
		awk '{ if (NR>1) { print } }' "$mcedb_cache" >> "$newfile"
		cat "$newfile" > "$0"
		rm -f "$newfile"
	fi
}

parse_opt_file()
{
	# parse_opt_file option_name option_value
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

while [ -n "$1" ]; do
	if [ "$1" = "--kernel" ]; then
		opt_kernel=$(parse_opt_file kernel "$2"); ret=$?
		[ $ret -ne 0 ] && exit 255
		shift 2
		opt_live=0
	elif [ "$1" = "--config" ]; then
		opt_config=$(parse_opt_file config "$2"); ret=$?
		[ $ret -ne 0 ] && exit 255
		shift 2
		opt_live=0
	elif [ "$1" = "--map" ]; then
		opt_map=$(parse_opt_file map "$2"); ret=$?
		[ $ret -ne 0 ] && exit 255
		shift 2
		opt_live=0
	elif [ "$1" = "--arch-prefix" ]; then
		opt_arch_prefix="$2"
		shift 2
	elif [ "$1" = "--live" ]; then
		opt_live_explicit=1
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
	elif [ "$1" = "--no-explain" ]; then
		# deprecated, kept for compatibility
		opt_explain=0
		shift
	elif [ "$1" = "--update-mcedb" ]; then
		update_mcedb
		exit $?
	elif [ "$1" = "--update-builtin-mcedb" ]; then
		update_mcedb builtin
		exit $?
	elif [ "$1" = "--explain" ]; then
		opt_explain=1
		shift
	elif [ "$1" = "--batch" ]; then
		opt_batch=1
		opt_verbose=0
		opt_no_color=1
		shift
		case "$1" in
			text|short|nrpe|json|prometheus) opt_batch_format="$1"; shift;;
			--*) ;;    # allow subsequent flags
			'') ;;     # allow nothing at all
			*)
				echo "$0: error: unknown batch format '$1'" >&2
				echo "$0: error: --batch expects a format from: text, nrpe, json" >&2
				exit 255
				;;
		esac
	elif [ "$1" = "-v" ] || [ "$1" = "--verbose" ]; then
		opt_verbose=$(( opt_verbose + 1 ))
		shift
	elif [ "$1" = "--cve" ]; then
		if [ -z "$2" ]; then
			echo "$0: error: option --cve expects a parameter, supported CVEs are: $supported_cve_list" >&2
			exit 255
		fi
		selected_cve=$(echo "$supported_cve_list" | grep -iwo "$2")
		if [ -n "$selected_cve" ]; then
			opt_cve_list="$opt_cve_list $selected_cve"
			opt_cve_all=0
		else
			echo "$0: error: unsupported CVE specified ('$2'), supported CVEs are: $supported_cve_list" >&2
			exit 255
		fi
		shift 2
	elif [ "$1" = "--vmm" ]; then
		if [ -z "$2" ]; then
			echo "$0: error: option --vmm (auto, yes, no)" >&2
			exit 255
		fi
		case "$2" in
			auto) opt_vmm=-1;;
			yes)  opt_vmm=1;;
			no)   opt_vmm=0;;
		esac
		shift 2
	elif [ "$1" = "--variant" ]; then
		if [ -z "$2" ]; then
			echo "$0: error: option --variant expects a parameter (1, 2, 3, 3a, 4 or l1tf)" >&2
			exit 255
		fi
		case "$2" in
			1)    opt_cve_list="$opt_cve_list CVE-2017-5753"; opt_cve_all=0;;
			2)    opt_cve_list="$opt_cve_list CVE-2017-5715"; opt_cve_all=0;;
			3)    opt_cve_list="$opt_cve_list CVE-2017-5754"; opt_cve_all=0;;
			3a)   opt_cve_list="$opt_cve_list CVE-2018-3640"; opt_cve_all=0;;
			4)    opt_cve_list="$opt_cve_list CVE-2018-3639"; opt_cve_all=0;;
			l1tf) opt_cve_list="$opt_cve_list CVE-2018-3615 CVE-2018-3620 CVE-2018-3646"; opt_cve_all=0;;
			*)
				echo "$0: error: invalid parameter '$2' for --variant, expected either 1, 2, 3, 3a, 4 or l1tf" >&2;
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
	_warn "Incompatible options specified (--no-sysfs and --sysfs-only), aborting"
	exit 255
fi

if [ "$opt_no_hw" = 1 ] && [ "$opt_hw_only" = 1 ]; then
	_warn "Incompatible options specified (--no-hw and --hw-only), aborting"
	exit 255
fi

# print status function
pstatus()
{
	if [ "$opt_no_color" = 1 ]; then
		_info_nol "$2"
	else
		case "$1" in
			red)    col="\033[41m\033[30m";;
			green)  col="\033[42m\033[30m";;
			yellow) col="\033[43m\033[30m";;
			blue)   col="\033[44m\033[30m";;
			*)      col="";;
		esac
		_info_nol "$col $2 \033[0m"
	fi
	[ -n "$3" ] && _info_nol " ($3)"
	_info
	unset col
}

# Print the final status of a vulnerability (incl. batch mode)
# Arguments are: CVE UNK/OK/VULN description
pvulnstatus()
{
	pvulnstatus_last_cve="$1"
	if [ "$opt_batch" = 1 ]; then
		case "$1" in
			CVE-2017-5753) aka="SPECTRE VARIANT 1";;
			CVE-2017-5715) aka="SPECTRE VARIANT 2";;
			CVE-2017-5754) aka="MELTDOWN";;
			CVE-2018-3640) aka="VARIANT 3A";;
			CVE-2018-3639) aka="VARIANT 4";;
			CVE-2018-3615/3620/3646) aka="L1TF";;
		esac

		case "$opt_batch_format" in
			text) _echo 0 "$1: $2 ($3)";;
			short) short_output="${short_output}$1 ";;
			json)
				case "$2" in
					UNK)  is_vuln="null";;
					VULN) is_vuln="true";;
					OK)   is_vuln="false";;
				esac
				json_output="${json_output:-[}{\"NAME\":\"$aka\",\"CVE\":\"$1\",\"VULNERABLE\":$is_vuln,\"INFOS\":\"$3\"},"
				;;

			nrpe)	[ "$2" = VULN ] && nrpe_vuln="$nrpe_vuln $1";;
			prometheus)
				prometheus_output="${prometheus_output:+$prometheus_output\n}specex_vuln_status{name=\"$aka\",cve=\"$1\",status=\"$2\",info=\"$3\"} 1"
				;;
		esac
	fi

	# always fill global_* vars because we use that do decide the program exit code
	case "$2" in
		UNK)  global_unknown="1";;
		VULN) global_critical="1";;
	esac

	# display info if we're not in quiet/batch mode
	vulnstatus="$2"
	shift 2
	_info_nol "> \033[46m\033[30mSTATUS:\033[0m "
	case "$vulnstatus" in
		UNK)  pstatus yellow 'UNKNOWN'        "$@"; final_summary="$final_summary \033[43m\033[30m$pvulnstatus_last_cve:??\033[0m";;
		VULN) pstatus red    'VULNERABLE'     "$@"; final_summary="$final_summary \033[41m\033[30m$pvulnstatus_last_cve:KO\033[0m";;
		OK)   pstatus green  'NOT VULNERABLE' "$@"; final_summary="$final_summary \033[42m\033[30m$pvulnstatus_last_cve:OK\033[0m";;
	esac
}


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

kernel=''
kernel_err=''
check_kernel()
{
	_file="$1"
	_desperate_mode="$2"
	# checking the return code of readelf -h is not enough, we could get
	# a damaged ELF file and validate it, check for stderr warnings too
	_readelf_warnings=$("${opt_arch_prefix}readelf" -S "$_file" 2>&1 >/dev/null | tr "\n" "/"); ret=$?
	_readelf_sections=$("${opt_arch_prefix}readelf" -S "$_file" 2>/dev/null | grep -c -e data -e text -e init)
	_kernel_size=$(stat -c %s "$_file" 2>/dev/null || stat -f %z "$_file" 2>/dev/null || echo 10000)
	_debug "check_kernel: ret=$? size=$_kernel_size sections=$_readelf_sections warnings=$_readelf_warnings"
	if [ -n "$_desperate_mode" ]; then
		if "${opt_arch_prefix}strings" "$_file" | grep -Eq '^Linux version '; then
			_debug "check_kernel (desperate): ... matched!"
			return 0
		else
			_debug "check_kernel (desperate): ... invalid"
		fi
	else
		if [ $ret -eq 0 ] && [ -z "$_readelf_warnings" ] && [ "$_readelf_sections" -gt 0 ]; then
			if [ "$_kernel_size" -ge 100000 ]; then
				_debug "check_kernel: ... file is valid"
				return 0
			else
				_debug "check_kernel: ... file seems valid but is too small, ignoring"
			fi
		else
			_debug "check_kernel: ... file is invalid"
		fi
	fi
	return 1
}

try_decompress()
{
	# The obscure use of the "tr" filter is to work around older versions of
	# "grep" that report the byte offset of the line instead of the pattern.

	# Try to find the header ($1) and decompress from here
	_debug "try_decompress: looking for $3 magic in $6"
	for     pos in $(tr "$1\n$2" "\n$2=" < "$6" | grep -abo "^$2")
	do
		_debug "try_decompress: magic for $3 found at offset $pos"
		if ! which "$3" >/dev/null 2>&1; then
			kernel_err="missing '$3' tool, please install it, usually it's in the '$5' package"
			return 0
		fi
		pos=${pos%%:*}
		# shellcheck disable=SC2086
		tail -c+$pos "$6" 2>/dev/null | $3 $4 > "$kerneltmp" 2>/dev/null; ret=$?
		if [ ! -s "$kerneltmp" ]; then
			# don't rely on $ret, sometimes it's != 0 but worked
			# (e.g. gunzip ret=2 just means there was trailing garbage)
			_debug "try_decompress: decompression with $3 failed (err=$ret)"
		elif check_kernel "$kerneltmp" "$7"; then
			kernel="$kerneltmp"
			_debug "try_decompress: decompressed with $3 successfully!"
			return 0
		elif [ "$3" != "cat" ]; then
			_debug "try_decompress: decompression with $3 worked but result is not a kernel, trying with an offset"
			[ -z "$kerneltmp2" ] && kerneltmp2=$(mktemp /tmp/kernel-XXXXXX)
			cat "$kerneltmp" > "$kerneltmp2"
			try_decompress '\177ELF' xxy 'cat' '' cat "$kerneltmp2" && return 0
		else
			_debug "try_decompress: decompression with $3 worked but result is not a kernel"
		fi
	done
	return 1
}

extract_kernel()
{
	[ -n "$1" ] || return 1
	# Prepare temp files:
	kerneltmp="$(mktemp /tmp/kernel-XXXXXX)"

	# Initial attempt for uncompressed images or objects:
	if check_kernel "$1"; then
		cat "$1" > "$kerneltmp"
		kernel=$kerneltmp
		return 0
	fi

	# That didn't work, so retry after decompression.
	for mode in '' 'desperate'; do
		try_decompress '\037\213\010'     xy    gunzip  ''      gunzip      "$1" "$mode" && return 0
		try_decompress '\3757zXZ\000'     abcde unxz    ''      xz-utils    "$1" "$mode" && return 0
		try_decompress 'BZh'              xy    bunzip2 ''      bzip2       "$1" "$mode" && return 0
		try_decompress '\135\0\0\0'       xxx   unlzma  ''      xz-utils    "$1" "$mode" && return 0
		try_decompress '\211\114\132'     xy    'lzop'  '-d'    lzop        "$1" "$mode" && return 0
		try_decompress '\002\041\114\030' xyy   'lz4'   '-d -l' liblz4-tool "$1" "$mode" && return 0
		try_decompress '\177ELF'          xxy   'cat'   ''      cat         "$1" "$mode" && return 0
	done
	_verbose "Couldn't extract the kernel image, accuracy might be reduced"
	return 1
}

# end of extract-vmlinux functions

mount_debugfs()
{
	if [ ! -e /sys/kernel/debug/sched_features ]; then
		# try to mount the debugfs hierarchy ourselves and remember it to umount afterwards
		mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null && mounted_debugfs=1
	fi
}

load_msr()
{
	if [ "$os" = Linux ]; then
		if ! grep -e msr "$procfs/modules" 2>/dev/null; then
			modprobe msr 2>/dev/null && insmod_msr=1
			_debug "attempted to load module msr, insmod_msr=$insmod_msr"
		else
			_debug "msr module already loaded"
		fi	
	else
		if ! kldstat -q -m cpuctl; then
			kldload cpuctl 2>/dev/null && kldload_cpuctl=1
			_debug "attempted to load module cpuctl, kldload_cpuctl=$kldload_cpuctl"
		else
			_debug "cpuctl module already loaded"
		fi
	fi
}

load_cpuid()
{
	if [ "$os" = Linux ]; then
		if ! grep -e cpuid "$procfs/modules" 2>/dev/null; then
			modprobe cpuid 2>/dev/null && insmod_cpuid=1
			_debug "attempted to load module cpuid, insmod_cpuid=$insmod_cpuid"
		else
			_debug "cpuid module already loaded"
		fi	
	else
		if ! kldstat -q -m cpuctl; then
			kldload cpuctl 2>/dev/null && kldload_cpuctl=1
			_debug "attempted to load module cpuctl, kldload_cpuctl=$kldload_cpuctl"
		else
			_debug "cpuctl module already loaded"
		fi
	fi
}

# shellcheck disable=SC2034
EAX=1; EBX=2; ECX=3; EDX=4;
read_cpuid()
{
	# leaf is the value of the eax register when calling the cpuid instruction:
	_leaf="$1"
	# eax=1 ebx=2 ecx=3 edx=4:
	_register="$2"
	# number of bits to shift the register right to:
	_shift="$3"
	# mask to apply as an AND operand to the shifted register value
	_mask="$4"
	# wanted value (optional), if present we return 0(true) if the obtained value is equal, 1 otherwise:
	_wanted="$5"
	# in any case, the read value is globally available in $read_cpuid_value

	read_cpuid_value=''
	if [ ! -e /dev/cpu/0/cpuid ] && [ ! -e /dev/cpuctl0 ]; then
		# try to load the module ourselves (and remember it so we can rmmod it afterwards)
		load_cpuid
	fi

	if [ -e /dev/cpu/0/cpuid ]; then
		# Linux
		if [ ! -r /dev/cpu/0/cpuid ]; then
			return 2
		fi
		# on some kernel versions, /dev/cpu/0/cpuid doesn't imply that the cpuid module is loaded, in that case dd returns an error
		dd if=/dev/cpu/0/cpuid bs=16 count=1 >/dev/null 2>&1 || load_cpuid
		# we need _leaf to be converted to decimal for dd
		_leaf=$(( _leaf ))
		# to avoid using iflag=skip_bytes, which doesn't exist on old versions of dd, seek to the closer multiple-of-16
		_ddskip=$(( _leaf / 16 ))
		_odskip=$(( _leaf - _ddskip * 16 ))
		# now read the value
		_cpuid=$(dd if=/dev/cpu/0/cpuid bs=16 skip=$_ddskip count=$((_odskip + 1)) 2>/dev/null | od -j $((_odskip * 16)) -A n -t u4)
	elif [ -e /dev/cpuctl0 ]; then
		# BSD
		if [ ! -r /dev/cpuctl0 ]; then
			return 2
		fi
		_cpuid=$(cpucontrol -i "$_leaf" /dev/cpuctl0 2>/dev/null | awk '{print $4,$5,$6,$7}')
		# cpuid level 0x1: 0x000306d4 0x00100800 0x4dfaebbf 0xbfebfbff
	else
		return 2
	fi

	_debug "cpuid: leaf$_leaf on cpu0, eax-ebx-ecx-edx: $_cpuid"
	[ -z "$_cpuid" ] && return 2
	# get the value of the register we want
	_reg=$(echo "$_cpuid" | awk '{print $'"$_register"'}')
	# Linux returns it as decimal, BSD as hex, normalize to decimal
	_reg=$(( _reg ))
	# shellcheck disable=SC2046
	_debug "cpuid: wanted register ($_register) has value $_reg aka "$(printf "%08x" "$_reg")
	_reg_shifted=$(( _reg >> _shift ))
	# shellcheck disable=SC2046
	_debug "cpuid: shifted value by $_shift is $_reg_shifted aka "$(printf "%x" "$_reg_shifted")
	read_cpuid_value=$(( _reg_shifted & _mask ))
	# shellcheck disable=SC2046
	_debug "cpuid: after AND $_mask, final value is $read_cpuid_value aka "$(printf "%x" "$read_cpuid_value")
	if [ -n "$_wanted" ]; then
		_debug "cpuid: wanted $_wanted and got $read_cpuid_value"
		if [ "$read_cpuid_value" = "$_wanted" ]; then
			return 0
		else
			return 1
		fi
	fi

	return 0
}

dmesg_grep()
{
	# grep for something in dmesg, ensuring that the dmesg buffer
	# has not been truncated
	dmesg_grepped=''
	if ! dmesg | grep -qE -e '(^|\] )Linux version [0-9]' -e '^FreeBSD is a registered' ; then
		# dmesg truncated
		return 2
	fi
	dmesg_grepped=$(dmesg | grep -E "$1" | head -1)
	# not found:
	[ -z "$dmesg_grepped" ] && return 1
	# found, output is in $dmesg_grepped
	return 0
}

is_coreos()
{
	which coreos-install >/dev/null 2>&1 && which toolbox >/dev/null 2>&1 && return 0
	return 1
}

parse_cpu_details()
{
	[ "$parse_cpu_details_done" = 1 ] && return 0

	if [ -e "$procfs/cpuinfo" ]; then
		cpu_vendor=$(  grep '^vendor_id'  "$procfs/cpuinfo" | awk '{print $3}' | head -1)
		cpu_friendly_name=$(grep '^model name' "$procfs/cpuinfo" | cut -d: -f2- | head -1 | sed -e 's/^ *//')
		# special case for ARM follows
		if grep -qi 'CPU implementer[[:space:]]*:[[:space:]]*0x41' "$procfs/cpuinfo"; then
			cpu_vendor='ARM'
			# some devices (phones or other) have several ARMs and as such different part numbers,
			# an example is "bigLITTLE", so we need to store the whole list, this is needed for is_cpu_vulnerable
			cpu_part_list=$(awk '/CPU part/         {print $4}' "$procfs/cpuinfo")
			cpu_arch_list=$(awk '/CPU architecture/ {print $3}' "$procfs/cpuinfo")
			# take the first one to fill the friendly name, do NOT quote the vars below
			# shellcheck disable=SC2086
			cpu_arch=$(echo $cpu_arch_list | awk '{ print $1 }')
			# shellcheck disable=SC2086
			cpu_part=$(echo $cpu_part_list | awk '{ print $1 }')
			[ "$cpu_arch" = "AArch64" ] && cpu_arch=8
			cpu_friendly_name="ARM"
			[ -n "$cpu_arch" ] && cpu_friendly_name="$cpu_friendly_name v$cpu_arch"
			[ -n "$cpu_part" ] && cpu_friendly_name="$cpu_friendly_name model $cpu_part"

		elif grep -qi 'CPU implementer[[:space:]]*:[[:space:]]*0x43' "$procfs/cpuinfo"; then
			cpu_vendor='CAVIUM'
		fi

		cpu_family=$(  grep '^cpu family' "$procfs/cpuinfo" | awk '{print $4}' | grep -E '^[0-9]+$' | head -1)
		cpu_model=$(   grep '^model'      "$procfs/cpuinfo" | awk '{print $3}' | grep -E '^[0-9]+$' | head -1)
		cpu_stepping=$(grep '^stepping'   "$procfs/cpuinfo" | awk '{print $3}' | grep -E '^[0-9]+$' | head -1)
		cpu_ucode=$(   grep '^microcode'  "$procfs/cpuinfo" | awk '{print $3}' | head -1)
	else
		cpu_friendly_name=$(sysctl -n hw.model)
	fi

	# get raw cpuid, it's always useful (referenced in the Intel doc for firmware updates for example)
	if read_cpuid 0x1 $EAX 0 0xFFFFFFFF; then
		cpu_cpuid="$read_cpuid_value"
	else
		cpu_cpuid=0
	fi

	# under BSD, linprocfs often doesn't export ucode information, so fetch it ourselves the good old way
	if [ -z "$cpu_ucode" ] && [ "$os" != Linux ]; then
		load_cpuid
		if [ -e /dev/cpuctl0 ]; then
			# init MSR with NULLs
			cpucontrol -m 0x8b=0 /dev/cpuctl0
			# call CPUID
			cpucontrol -i 1 /dev/cpuctl0 >/dev/null
			# read MSR
			cpu_ucode=$(cpucontrol -m 0x8b /dev/cpuctl0 | awk '{print $3}')
			# convert to decimal
			cpu_ucode=$(( cpu_ucode ))
			# convert back to hex
			cpu_ucode=$(printf "0x%x" "$cpu_ucode")
		fi
	fi

	# if we got no cpu_ucode (e.g. we're in a vm), fall back to 0x0
	[ -z "$cpu_ucode" ] && cpu_ucode=0x0

	echo "$cpu_ucode" | grep -q ^0x && cpu_ucode=$(( cpu_ucode ))
	ucode_found=$(printf "model 0x%x family 0x%x stepping 0x%x ucode 0x%x cpuid 0x%x" "$cpu_model" "$cpu_family" "$cpu_stepping" "$cpu_ucode" "$cpu_cpuid")

	# also define those that we will need in other funcs
	# taken from ttps://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/intel-family.h
	# shellcheck disable=SC2034
	{
	INTEL_FAM6_CORE_YONAH=$(( 0x0E ))

	INTEL_FAM6_CORE2_MEROM=$(( 0x0F ))
	INTEL_FAM6_CORE2_MEROM_L=$(( 0x16 ))
	INTEL_FAM6_CORE2_PENRYN=$(( 0x17 ))
	INTEL_FAM6_CORE2_DUNNINGTON=$(( 0x1D ))

	INTEL_FAM6_NEHALEM=$(( 0x1E ))
	INTEL_FAM6_NEHALEM_G=$(( 0x1F ))
	INTEL_FAM6_NEHALEM_EP=$(( 0x1A ))
	INTEL_FAM6_NEHALEM_EX=$(( 0x2E ))

	INTEL_FAM6_WESTMERE=$(( 0x25 ))
	INTEL_FAM6_WESTMERE_EP=$(( 0x2C ))
	INTEL_FAM6_WESTMERE_EX=$(( 0x2F ))

	INTEL_FAM6_SANDYBRIDGE=$(( 0x2A ))
	INTEL_FAM6_SANDYBRIDGE_X=$(( 0x2D ))
	INTEL_FAM6_IVYBRIDGE=$(( 0x3A ))
	INTEL_FAM6_IVYBRIDGE_X=$(( 0x3E ))

	INTEL_FAM6_HASWELL_CORE=$(( 0x3C ))
	INTEL_FAM6_HASWELL_X=$(( 0x3F ))
	INTEL_FAM6_HASWELL_ULT=$(( 0x45 ))
	INTEL_FAM6_HASWELL_GT3E=$(( 0x46 ))

	INTEL_FAM6_BROADWELL_CORE=$(( 0x3D ))
	INTEL_FAM6_BROADWELL_GT3E=$(( 0x47 ))
	INTEL_FAM6_BROADWELL_X=$(( 0x4F ))
	INTEL_FAM6_BROADWELL_XEON_D=$(( 0x56 ))

	INTEL_FAM6_SKYLAKE_MOBILE=$(( 0x4E ))
	INTEL_FAM6_SKYLAKE_DESKTOP=$(( 0x5E ))
	INTEL_FAM6_SKYLAKE_X=$(( 0x55 ))
	INTEL_FAM6_KABYLAKE_MOBILE=$(( 0x8E ))
	INTEL_FAM6_KABYLAKE_DESKTOP=$(( 0x9E ))

	# /* "Small Core" Processors (Atom) */

	INTEL_FAM6_ATOM_BONNELL=$(( 0x1C ))
	INTEL_FAM6_ATOM_BONNELL_MID=$(( 0x26 ))
	INTEL_FAM6_ATOM_SALTWELL_MID=$(( 0x27 ))
	INTEL_FAM6_ATOM_SALTWELL_TABLET=$(( 0x35 ))
	INTEL_FAM6_ATOM_SALTWELL=$(( 0x36 ))
	INTEL_FAM6_ATOM_SILVERMONT=$(( 0x37 ))
	INTEL_FAM6_ATOM_SILVERMONT_MID=$(( 0x4A ))
	INTEL_FAM6_ATOM_SILVERMONT_X=$(( 0x4D ))
	INTEL_FAM6_ATOM_AIRMONT=$(( 0x4C ))
	INTEL_FAM6_ATOM_AIRMONT_MID=$(( 0x5A ))
	INTEL_FAM6_ATOM_GOLDMONT=$(( 0x5C ))
	INTEL_FAM6_ATOM_GOLDMONT_X=$(( 0x5F ))
	INTEL_FAM6_ATOM_GOLDMONT_PLUS=$(( 0x7A ))

	# /* Xeon Phi */

	INTEL_FAM6_XEON_PHI_KNL=$(( 0x57 ))
	INTEL_FAM6_XEON_PHI_KNM=$(( 0x85 ))
	}
	parse_cpu_details_done=1
}

is_amd()
{
	[ "$cpu_vendor" = AuthenticAMD ] && return 0
	return 1
}

is_intel()
{
	[ "$cpu_vendor" = GenuineIntel ] && return 0
	return 1
}

is_cpu_smt_enabled()
{
	# SMT / HyperThreading is enabled if siblings != cpucores
	if [ -e "$procfs/cpuinfo" ]; then
		_siblings=$(awk '/^siblings/  {print $3;exit}' "$procfs/cpuinfo")
		_cpucores=$(awk '/^cpu cores/ {print $4;exit}' "$procfs/cpuinfo")
		if [ -n "$_siblings" ] && [ -n "$_cpucores" ]; then
			if [ "$_siblings" = "$_cpucores" ]; then
				return 1
			else
				return 0
			fi
		fi
	fi
	# we can't tell
	return 2
}

is_ucode_blacklisted()
{
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
		$INTEL_FAM6_KABYLAKE_DESKTOP,0x0B,0x80 \
		$INTEL_FAM6_KABYLAKE_DESKTOP,0x0A,0x80 \
		$INTEL_FAM6_KABYLAKE_DESKTOP,0x09,0x80 \
		$INTEL_FAM6_KABYLAKE_MOBILE,0x0A,0x80  \
		$INTEL_FAM6_KABYLAKE_MOBILE,0x09,0x80  \
		$INTEL_FAM6_SKYLAKE_X,0x03,0x0100013e  \
		$INTEL_FAM6_SKYLAKE_X,0x04,0x02000036  \
		$INTEL_FAM6_SKYLAKE_X,0x04,0x0200003a  \
		$INTEL_FAM6_SKYLAKE_X,0x04,0x0200003c  \
		$INTEL_FAM6_BROADWELL_CORE,0x04,0x28   \
		$INTEL_FAM6_BROADWELL_GT3E,0x01,0x1b   \
		$INTEL_FAM6_BROADWELL_XEON_D,0x02,0x14 \
		$INTEL_FAM6_BROADWELL_XEON_D,0x03,0x07000011 \
		$INTEL_FAM6_BROADWELL_X,0x01,0x0b000023 \
		$INTEL_FAM6_BROADWELL_X,0x01,0x0b000025 \
		$INTEL_FAM6_HASWELL_ULT,0x01,0x21      \
		$INTEL_FAM6_HASWELL_GT3E,0x01,0x18     \
		$INTEL_FAM6_HASWELL_CORE,0x03,0x23     \
		$INTEL_FAM6_HASWELL_X,0x02,0x3b        \
		$INTEL_FAM6_HASWELL_X,0x04,0x10        \
		$INTEL_FAM6_IVYBRIDGE_X,0x04,0x42a     \
		$INTEL_FAM6_SANDYBRIDGE_X,0x06,0x61b   \
		$INTEL_FAM6_SANDYBRIDGE_X,0x07,0x712
	do
		model=$(echo $tuple | cut -d, -f1)
		stepping=$(( $(echo $tuple | cut -d, -f2) ))
		if [ "$cpu_model" = "$model" ] && [ "$cpu_stepping" = "$stepping" ]; then
			ucode=$(( $(echo $tuple | cut -d, -f3) ))
			if [ "$cpu_ucode" = "$ucode" ]; then
				_debug "is_ucode_blacklisted: we have a match! ($cpu_model/$cpu_stepping/$cpu_ucode)"
				return 0
			fi
		fi
	done
	_debug "is_ucode_blacklisted: no ($cpu_model/$cpu_stepping/$cpu_ucode)"
	return 1
}

is_skylake_cpu()
{
	# is this a skylake cpu?
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
	if [ "$cpu_model" = $INTEL_FAM6_SKYLAKE_MOBILE        ] || \
		[ "$cpu_model" = $INTEL_FAM6_SKYLAKE_DESKTOP  ] || \
		[ "$cpu_model" = $INTEL_FAM6_SKYLAKE_X        ] || \
		[ "$cpu_model" = $INTEL_FAM6_KABYLAKE_MOBILE  ] || \
		[ "$cpu_model" = $INTEL_FAM6_KABYLAKE_DESKTOP ]; then
		return 0
	fi
	return 1
}

is_vulnerable_to_empty_rsb()
{
	if is_intel && [ -z "$capabilities_rsba" ]; then
		_warn "is_vulnerable_to_empty_rsb() called before ARCH CAPABILITIES MSR was read"
	fi
	if is_skylake_cpu || [ "$capabilities_rsba" = 1 ]; then
		return 0
	fi
	return 1
}

is_zen_cpu()
{
	# is this CPU from the AMD ZEN family ? (ryzen, epyc, ...)
	parse_cpu_details
	is_amd || return 1
	[ "$cpu_family" = 23 ] && return 0
	return 1
}

if [ -r "$mcedb_cache" ]; then
	mcedb_source="$mcedb_cache"
	mcedb_info="local MCExtractor DB "$(grep -E '^# %%% MCEDB ' "$mcedb_source" | cut -c13-)
else
	mcedb_source="$0"
	mcedb_info="builtin MCExtractor DB "$(grep -E '^# %%% MCEDB ' "$mcedb_source" | cut -c13-)
fi
read_mcedb()
{
	awk '{ if (DELIM==1) { print $2 } } /^# %%% MCEDB / { DELIM=1 }' "$mcedb_source"
}

is_latest_known_ucode()
{
	# 0: yes, 1: no, 2: unknown
	parse_cpu_details
	if [ "$cpu_cpuid" = 0 ]; then
		ucode_latest="couldn't get your cpuid"
		return 2
	fi
	ucode_latest="latest microcode version for your CPU model is unknown"
	if is_intel; then
		cpu_brand_prefix=I
	elif is_amd; then
		cpu_brand_prefix=A
	else
		return 2
	fi
	for tuple in $(read_mcedb | grep "$(printf "^$cpu_brand_prefix,0x%08X," "$cpu_cpuid")")
	do
		ucode=$((  $(echo "$tuple" | cut -d, -f3) ))
		ucode_date=$(echo "$tuple" | cut -d, -f4 | sed -r 's=(....)(..)(..)=\1/\2/\3=')
		_debug "is_latest_known_ucode: with cpuid $cpu_cpuid has ucode $cpu_ucode, last known is $ucode from $ucode_date"
		ucode_latest=$(printf "latest version is 0x%x dated $ucode_date according to $mcedb_info" "$ucode")
		if [ "$cpu_ucode" -ge "$ucode" ]; then
			return 0
		else
			return 1
		fi
	done
	_debug "is_latest_known_ucode: this cpuid is not referenced ($cpu_cpuid)"
	return 2
}

# ENTRYPOINT

# we can't do anything useful under WSL
if uname -a | grep -qE -- '-Microsoft #[0-9]+-Microsoft '; then
	_warn "This script doesn't work under Windows Subsystem for Linux"
	_warn "You should use the official Microsoft tool instead."
	_warn "It can be found under https://aka.ms/SpeculationControlPS"
	exit 1
fi

# check for mode selection inconsistency
if [ "$opt_live_explicit" = 1 ]; then
	if [ -n "$opt_kernel" ] || [ -n "$opt_config" ] || [ -n "$opt_map" ]; then
		show_usage
		echo "$0: error: incompatible modes specified, use either --live or --kernel/--config/--map" >&2
		exit 255
	fi
fi
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
		_warn "CoreOS mode asked, but we're not under CoreOS!"
		exit 255
	fi
	_warn "CoreOS mode, starting an ephemeral toolbox to launch the script"
	load_msr
	load_cpuid
	mount_debugfs
	toolbox --ephemeral --bind-ro /dev/cpu:/dev/cpu -- sh -c "dnf install -y binutils which && /media/root$PWD/$0 $* --coreos-within-toolbox"
	exitcode=$?
	exit $exitcode
else
	if is_coreos; then
		_warn "You seem to be running CoreOS, you might want to use the --coreos option for better results"
		_warn
	fi
fi

# if we're under a BSD, try to mount linprocfs for "$procfs/cpuinfo"
procfs=/proc
if echo "$os" | grep -q BSD; then
	_debug "We're under BSD, check if we have procfs"
	procfs=$(mount | awk '/^linprocfs/ { print $3; exit; }')
	if [ -z "$procfs" ]; then
		_debug "we don't, try to mount it"
		procfs=/proc
		[ -d /compat/linux/proc ] && procfs=/compat/linux/proc
		test -d $procfs || mkdir $procfs
		if mount -t linprocfs linprocfs $procfs 2>/dev/null; then
			mounted_procfs=1
			_debug "procfs just mounted at $procfs"
		else
			procfs=''
		fi
	else
		_debug "We do: $procfs"
	fi
fi

parse_cpu_details
if [ "$opt_live" = 1 ]; then
	# root check (only for live mode, for offline mode, we already checked if we could read the files)
	if [ "$(id -u)" -ne 0 ]; then
		_warn "Note that you should launch this script with root privileges to get accurate information."
		_warn "We'll proceed but you might see permission denied errors."
		_warn "To run it as root, you can try the following command: sudo $0"
		_warn
	fi
	_info "Checking for vulnerabilities on current system"
	_info "Kernel is \033[35m$(uname -s) $(uname -r) $(uname -v) $(uname -m)\033[0m"
	_info "CPU is \033[35m$cpu_friendly_name\033[0m"

	# try to find the image of the current running kernel
	# first, look for the BOOT_IMAGE hint in the kernel cmdline
	if [ -r "$procfs/cmdline" ] && grep -q 'BOOT_IMAGE=' "$procfs/cmdline"; then
		opt_kernel=$(grep -Eo 'BOOT_IMAGE=[^ ]+' "$procfs/cmdline" | cut -d= -f2)
		_debug "found opt_kernel=$opt_kernel in $procfs/cmdline"
		# if the boot partition is within a btrfs subvolume, strip the subvolume name
		# if /boot is a separate subvolume, the remainder of the code in this section should handle it
		if echo "$opt_kernel" | grep -q "^/@"; then opt_kernel=$(echo "$opt_kernel" | sed "s:/@[^/]*::"); fi
		# if we have a dedicated /boot partition, our bootloader might have just called it /
		# so try to prepend /boot and see if we find anything
		[ -e "/boot/$opt_kernel" ] && opt_kernel="/boot/$opt_kernel"
		# special case for CoreOS if we're inside the toolbox
		[ -e "/media/root/boot/$opt_kernel" ] && opt_kernel="/media/root/boot/$opt_kernel"
		_debug "opt_kernel is now $opt_kernel"
		# else, the full path is already there (most probably /boot/something)
	fi
	# if we didn't find a kernel, default to guessing
	if [ ! -e "$opt_kernel" ]; then
		# Fedora:
		[ -e "/lib/modules/$(uname -r)/vmlinuz" ] && opt_kernel="/lib/modules/$(uname -r)/vmlinuz"
		# Slackare:
		[ -e "/boot/vmlinuz"             ] && opt_kernel="/boot/vmlinuz"
		# Arch aarch64:
		[ -e "/boot/Image"               ] && opt_kernel="/boot/Image"
		# Arch armv5/armv7:
		[ -e "/boot/zImage"              ] && opt_kernel="/boot/zImage"
		# Arch arm7:
		[ -e "/boot/kernel7.img"         ] && opt_kernel="/boot/kernel7.img"
		# Linux-Libre:
		[ -e "/boot/vmlinuz-linux-libre" ] && opt_kernel="/boot/vmlinuz-linux-libre"
		# pine64
		[ -e "/boot/pine64/Image"        ] && opt_kernel="/boot/pine64/Image"
		# generic:
		[ -e "/boot/vmlinuz-$(uname -r)" ] && opt_kernel="/boot/vmlinuz-$(uname -r)"
		[ -e "/boot/kernel-$( uname -r)" ] && opt_kernel="/boot/kernel-$( uname -r)"
		[ -e "/boot/bzImage-$(uname -r)" ] && opt_kernel="/boot/bzImage-$(uname -r)"
		# Gentoo:
		[ -e "/boot/kernel-genkernel-$(uname -m)-$(uname -r)" ] && opt_kernel="/boot/kernel-genkernel-$(uname -m)-$(uname -r)"
		# NixOS:
		[ -e "/run/booted-system/kernel" ] && opt_kernel="/run/booted-system/kernel"
		# systemd kernel-install:
		[ -e "/etc/machine-id" ] && [ -e "/boot/$(cat /etc/machine-id)/$(uname -r)/linux" ] && opt_kernel="/boot/$(cat /etc/machine-id)/$(uname -r)/linux"
		# Clear Linux:
		str_uname=$(uname -r)
		clear_linux_kernel="/lib/kernel/org.clearlinux.${str_uname##*.}.${str_uname%.*}"
		[ -e "$clear_linux_kernel" ] && opt_kernel=$clear_linux_kernel
	fi

	# system.map
	if [ -e "$procfs/kallsyms" ] ; then
		opt_map="$procfs/kallsyms"
	elif [ -e "/lib/modules/$(uname -r)/System.map" ] ; then
		opt_map="/lib/modules/$(uname -r)/System.map"
	elif [ -e "/boot/System.map-$(uname -r)" ] ; then
		opt_map="/boot/System.map-$(uname -r)"
	elif [ -e "/lib/kernel/System.map-$(uname -r)" ]; then
		opt_map="/lib/kernel/System.map-$(uname -r)"
	fi

	# config
	if [ -e "$procfs/config.gz" ] ; then
		dumped_config="$(mktemp /tmp/config-XXXXXX)"
		gunzip -c "$procfs/config.gz" > "$dumped_config"
		# dumped_config will be deleted at the end of the script
		opt_config="$dumped_config"
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
	_info "Checking for vulnerabilities against specified kernel"
	_info "CPU is \033[35m$cpu_friendly_name\033[0m"
fi

if [ -n "$opt_kernel" ]; then
	_verbose "Will use kernel image \033[35m$opt_kernel\033[0m"
else
	_verbose "Will use no kernel image (accuracy might be reduced)"
	bad_accuracy=1
fi

if [ "$os" = Linux ]; then
	if [ -n "$opt_config" ] && ! grep -q '^CONFIG_' "$opt_config"; then
		# given file is invalid!
		_warn "The kernel config file seems invalid, was expecting a plain-text file, ignoring it!"
		opt_config=''
	fi

	if [ -n "$dumped_config" ] && [ -n "$opt_config" ]; then
		_verbose "Will use kconfig \033[35m$procfs/config.gz (decompressed)\033[0m"
	elif [ -n "$opt_config" ]; then
		_verbose "Will use kconfig \033[35m$opt_config\033[0m"
	else
		_verbose "Will use no kconfig (accuracy might be reduced)"
		bad_accuracy=1
	fi

	if [ -n "$opt_map" ]; then
		_verbose "Will use System.map file \033[35m$opt_map\033[0m"
	else
		_verbose "Will use no System.map file (accuracy might be reduced)"
		bad_accuracy=1
	fi

	if [ "$bad_accuracy" = 1 ]; then
		_warn "We're missing some kernel info (see -v), accuracy might be reduced"
	fi
fi

if [ -e "$opt_kernel" ]; then
	if ! which "${opt_arch_prefix}readelf" >/dev/null 2>&1; then
		_debug "readelf not found"
		kernel_err="missing '${opt_arch_prefix}readelf' tool, please install it, usually it's in the 'binutils' package"
	elif [ "$opt_sysfs_only" = 1 ] || [ "$opt_hw_only" = 1 ]; then
		kernel_err='kernel image decompression skipped'
	else
		extract_kernel "$opt_kernel"
	fi
else
	_debug "no opt_kernel defined"
	kernel_err="couldn't find your kernel image in /boot, if you used netboot, this is normal"
fi
if [ -z "$kernel" ] || [ ! -r "$kernel" ]; then
	[ -z "$kernel_err" ] && kernel_err="couldn't extract your kernel from $opt_kernel"
else
	# vanilla kernels have with ^Linux version
	# also try harder with some kernels (such as Red Hat) that don't have ^Linux version before their version string
	# and check for FreeBSD
	kernel_version=$("${opt_arch_prefix}strings" "$kernel" 2>/dev/null | grep -E \
		-e '^Linux version ' \
		-e '^[[:alnum:]][^[:space:]]+ \([^[:space:]]+\) #[0-9]+ .+ (19|20)[0-9][0-9]$' \
		-e '^FreeBSD [0-9]' | head -1)
	if [ -z "$kernel_version" ]; then
		# try even harder with some kernels (such as ARM) that split the release (uname -r) and version (uname -v) in 2 adjacent strings
		kernel_version=$("${opt_arch_prefix}strings" "$kernel" 2>/dev/null | grep -E -B1 '^#[0-9]+ .+ (19|20)[0-9][0-9]$' | tr "\n" " ")
	fi
	if [ -n "$kernel_version" ]; then
		# in live mode, check if the img we found is the correct one
		if [ "$opt_live" = 1 ]; then
			_verbose "Kernel image is \033[35m$kernel_version"
			if ! echo "$kernel_version" | grep -qF "$(uname -r)"; then
				_warn "Possible disrepancy between your running kernel '$(uname -r)' and the image '$kernel_version' we found ($opt_kernel), results might be incorrect"
			fi
		else
			_info "Kernel image is \033[35m$kernel_version"
		fi
	else
		_verbose "Kernel image version is unknown"
	fi
fi

_info

# end of header stuff

# now we define some util functions and the check_*() funcs, as
# the user can choose to execute only some of those

sys_interface_check()
{
	file="$1"
	regex="$2"
	mode="$3"
	[ "$opt_live" = 1 ] && [ "$opt_no_sysfs" = 0 ] && [ -r "$file" ] || return 1
	[ -n "$regex" ] || regex='.*'
	msg=$(grep -Eo "$regex" "$file")
	if [ "$mode" = silent ]; then
		_info "* Information from the /sys interface: $msg"
		return 0
	fi
	_info_nol "* Mitigated according to the /sys interface: "
	if echo "$msg" | grep -qi '^not affected'; then
		# Not affected
		status=OK
		pstatus green YES "$msg"
	elif echo "$msg" | grep -qi '^mitigation'; then
		# Mitigation: PTI
		status=OK
		pstatus green YES "$msg"
	elif echo "$msg" | grep -qi '^vulnerable'; then
		# Vulnerable
		status=VULN
		pstatus yellow NO "$msg"
	else
		status=UNK
		pstatus yellow UNKNOWN "$msg"
	fi
	_debug "sys_interface_check: $file=$msg (re=$regex)"
	return 0
}

number_of_cpus()
{
	if echo "$os" | grep -q BSD; then
		n=$(sysctl -n hw.ncpu 2>/dev/null || echo 1)
	elif [ -e "$procfs/cpuinfo" ]; then
		n=$(grep -c ^processor "$procfs/cpuinfo" 2>/dev/null || echo 1)
	else
		# if we don't know, default to 1 CPU
		n=1
	fi
	return "$n"
}

# $1 - msr number
# $2 - cpu index
write_msr()
{
	# _msr must be in hex, in the form 0x1234:
	_msr="$1"
	# cpu index, starting from 0:
	_cpu="$2"
	if [ "$os" != Linux ]; then
		cpucontrol -m "$_msr=0" "/dev/cpuctl$_cpu" >/dev/null 2>&1; ret=$?
	else
		# for Linux
		# convert to decimal
		_msr=$(( _msr ))
		if [ ! -w /dev/cpu/"$_cpu"/msr ]; then
			ret=200 # permission error
		# if wrmsr is available, use it
		elif which wrmsr >/dev/null 2>&1 && [ "$SMC_NO_WRMSR" != 1 ]; then
			_debug "write_msr: using wrmsr"
			wrmsr $_msr 0 2>/dev/null; ret=$?
		# or if we have perl, use it, any 5.x version will work
		elif which perl >/dev/null 2>&1 && [ "$SMC_NO_PERL" != 1 ]; then
			_debug "write_msr: using perl"
			ret=1
			perl -e "open(M,'>','/dev/cpu/$_cpu/msr') and seek(M,$_msr,0) and exit(syswrite(M,pack('H16',0)))"; [ $? -eq 8 ] && ret=0
		# fallback to dd if it supports seek_bytes
		elif dd if=/dev/null of=/dev/null bs=8 count=1 seek="$_msr" oflag=seek_bytes 2>/dev/null; then
			_debug "write_msr: using dd"
			dd if=/dev/zero of=/dev/cpu/"$_cpu"/msr bs=8 count=1 seek="$_msr" oflag=seek_bytes 2>/dev/null; ret=$?
		else
			_debug "write_msr: got no wrmsr, perl or recent enough dd!"
			return 201 # missing tool error
		fi
	fi
	# normalize ret
	[ "$ret" != 0 ] && ret=1
	_debug "write_msr: for cpu $_cpu on msr $_msr, ret=$ret"
	return $ret
}

read_msr()
{
	# _msr must be in hex, in the form 0x1234:
	_msr="$1"
	# cpu index, starting from 0:
	_cpu="$2"
	read_msr_value=''
	if [ "$os" != Linux ]; then
		_msr=$(cpucontrol -m "$_msr" "/dev/cpuctl$_cpu" 2>/dev/null); ret=$?
		[ $ret -ne 0 ] && return 1
		# MSR 0x10: 0x000003e1 0xb106dded
		_msr_h=$(echo "$_msr" | awk '{print $3}');
		_msr_h="$(( _msr_h >> 24 & 0xFF )) $(( _msr_h >> 16 & 0xFF )) $(( _msr_h >> 8 & 0xFF )) $(( _msr_h & 0xFF ))"
		_msr_l=$(echo "$_msr" | awk '{print $4}');
		_msr_l="$(( _msr_l >> 24 & 0xFF )) $(( _msr_l >> 16 & 0xFF )) $(( _msr_l >> 8 & 0xFF )) $(( _msr_l & 0xFF ))"
		read_msr_value="$_msr_h $_msr_l"
	else
		# for Linux
		# convert to decimal
		_msr=$(( _msr ))
		if [ ! -r /dev/cpu/"$_cpu"/msr ]; then
			return 200 # permission error
		# if rdmsr is available, use it
		elif which rdmsr >/dev/null 2>&1 && [ "$SMC_NO_RDMSR" != 1 ]; then
			_debug "read_msr: using rdmsr"
			read_msr_value=$(rdmsr -r $_msr 2>/dev/null | od -t u8 -A n)
		# or if we have perl, use it, any 5.x version will work
		elif which perl >/dev/null 2>&1 && [ "$SMC_NO_PERL" != 1 ]; then
			_debug "read_msr: using perl"
			read_msr_value=$(perl -e "open(M,'<','/dev/cpu/$_cpu/msr') and seek(M,$_msr,0) and read(M,\$_,8) and print" | od -t u8 -A n)
		# fallback to dd if it supports skip_bytes
		elif dd if=/dev/null of=/dev/null bs=8 count=1 skip="$_msr" iflag=skip_bytes 2>/dev/null; then
			_debug "read_msr: using dd"
			read_msr_value=$(dd if=/dev/cpu/"$_cpu"/msr bs=8 count=1 skip="$_msr" iflag=skip_bytes 2>/dev/null | od -t u8 -A n)
		else
			_debug "read_msr: got no rdmsr, perl or recent enough dd!"
			return 201 # missing tool error
		fi
		if [ -z "$read_msr_value" ]; then
			# MSR doesn't exist, don't check for $? because some versions of dd still return 0!
			return 1
		fi
	fi
	_debug "read_msr: MSR=$1 value is $read_msr_value"
	return 0
}

check_cpu()
{
	_info "\033[1;34mHardware check\033[0m"

	if ! uname -m | grep -qwE 'x86_64|i[3-6]86|amd64'; then
		return
	fi

	_info     "* Hardware support (CPU microcode) for mitigation techniques"
	_info     "  * Indirect Branch Restricted Speculation (IBRS)"
	_info_nol "    * SPEC_CTRL MSR is available: "
	number_of_cpus
	ncpus=$?
	idx_max_cpu=$((ncpus-1))
	if [ ! -e /dev/cpu/0/msr ] && [ ! -e /dev/cpuctl0 ]; then
		# try to load the module ourselves (and remember it so we can rmmod it afterwards)
		load_msr
	fi
	if [ ! -e /dev/cpu/0/msr ] && [ ! -e /dev/cpuctl0 ]; then
		spec_ctrl_msr=-1
		pstatus yellow UNKNOWN "is msr kernel module available?"
	else
		# the new MSR 'SPEC_CTRL' is at offset 0x48
		# we check if we have it for all cpus
		val=0
		cpu_mismatch=0
		for i in $(seq 0 "$idx_max_cpu")
		do
			read_msr 0x48 "$i"; ret=$?
			if [ "$i" -eq 0 ]; then
				val=$ret
			else
				if [ "$ret" -eq $val ]; then
					continue
				else
					cpu_mismatch=1
				fi
			fi
		done
		if [ $val -eq 0 ]; then
			if [ $cpu_mismatch -eq 0 ]; then
				spec_ctrl_msr=1
				pstatus green YES
			else
				spec_ctrl_msr=1
				pstatus green YES "But not in all CPUs"
			fi
		elif [ $val -eq 200 ]; then
			pstatus yellow UNKNOWN "is msr kernel module available?"
			spec_ctrl_msr=-1
		elif [ $val -eq 201 ]; then
			pstatus yellow UNKNOWN "missing tool, install either msr-tools or perl"
			spec_ctrl_msr=-1
		else
			spec_ctrl_msr=0
			pstatus yellow NO
		fi
	fi

	_info_nol "    * CPU indicates IBRS capability: "
	# from kernel src: { X86_FEATURE_SPEC_CTRL,        CPUID_EDX,26, 0x00000007, 0 },
	# amd: https://developer.amd.com/wp-content/resources/Architecture_Guidelines_Update_Indirect_Branch_Control.pdf
	# amd: 8000_0008 EBX[14]=1
	if is_intel; then
		read_cpuid 0x7 $EDX 26 1 1; ret=$?
		if [ $ret -eq 0 ]; then
			pstatus green YES "SPEC_CTRL feature bit"
			cpuid_spec_ctrl=1
			cpuid_ibrs='SPEC_CTRL'
		fi
	elif is_amd; then
		read_cpuid 0x80000008 $EBX 14 1 1; ret=$?
		if [ $ret -eq 0 ]; then
			pstatus green YES "IBRS_SUPPORT feature bit"
			cpuid_ibrs='IBRS_SUPPORT'
		fi
	else
		ret=-1
		pstatus yellow UNKNOWN "unknown CPU"
	fi
	if [ $ret -eq 1 ]; then
		pstatus yellow NO
	elif [ $ret -eq 2 ]; then
		pstatus yellow UNKNOWN "is cpuid kernel module available?"
		cpuid_spec_ctrl=-1
	fi

	if is_amd; then
		_info_nol "    * CPU indicates preferring IBRS always-on: "
		# amd
		read_cpuid 0x80000008 $EBX 16 1 1; ret=$?
		if [ $ret -eq 0 ]; then
			pstatus green YES
		else
			pstatus yellow NO
		fi

		_info_nol "    * CPU indicates preferring IBRS over retpoline: "
		# amd
		read_cpuid 0x80000008 $EBX 18 1 1; ret=$?
		if [ $ret -eq 0 ]; then
			pstatus green YES
		else
			pstatus yellow NO
		fi
	fi

	# IBPB
	_info     "  * Indirect Branch Prediction Barrier (IBPB)"
	_info_nol "    * PRED_CMD MSR is available: "
	if [ ! -e /dev/cpu/0/msr ] && [ ! -e /dev/cpuctl0 ]; then
		pstatus yellow UNKNOWN "is msr kernel module available?"
	elif [ ! -r /dev/cpu/0/msr ] && [ ! -w /dev/cpuctl0 ]; then
		pstatus yellow UNKNOWN "are you root?"
	else
		# the new MSR 'PRED_CTRL' is at offset 0x49, write-only
		# we test if of all cpus
		val=0
		cpu_mismatch=0
		for i in $(seq 0 "$idx_max_cpu")
		do
			write_msr 0x49 "$i"; ret=$?
			if [ "$i" -eq 0 ]; then
				val=$ret
			else
				if [ "$ret" -eq $val ]; then
					continue
				else
					cpu_mismatch=1
				fi
			fi
		done

		if [ $val -eq 0 ]; then
			if [ $cpu_mismatch -eq 0 ]; then
				pstatus green YES
			else
				pstatus green YES "But not in all CPUs"
			fi
		elif [ $val -eq 200 ]; then
			pstatus yellow UNKNOWN "is msr kernel module available?"
		else
			pstatus yellow NO
		fi
	fi

	_info_nol "    * CPU indicates IBPB capability: "
	# CPUID EAX=0x80000008, ECX=0x00 return EBX[12] indicates support for just IBPB.
	if [ "$cpuid_spec_ctrl" = 1 ]; then
		# spec_ctrl implies ibpb
		cpuid_ibpb='SPEC_CTRL'
		pstatus green YES "SPEC_CTRL feature bit"
	elif is_intel; then
		if [ "$cpuid_spec_ctrl" = -1 ]; then
			pstatus yellow UNKNOWN "is cpuid kernel module available?"
		else
			pstatus yellow NO
		fi
	elif is_amd; then
		read_cpuid 0x80000008 $EBX 12 1 1; ret=$?
		if [ $ret -eq 0 ]; then
			cpuid_ibpb='IBPB_SUPPORT'
			pstatus green YES "IBPB_SUPPORT feature bit"
		elif [ $ret -eq 1 ]; then
			pstatus yellow NO
		else
			pstatus yellow UNKNOWN "is cpuid kernel module available?"
		fi
	fi

	# STIBP
	_info     "  * Single Thread Indirect Branch Predictors (STIBP)"
	_info_nol "    * SPEC_CTRL MSR is available: "
	if [ "$spec_ctrl_msr" = 1 ]; then
		pstatus green YES
	elif [ "$spec_ctrl_msr" = 0 ]; then
		pstatus yellow NO
	else
		pstatus yellow UNKNOWN "is msr kernel module available?"
	fi

	_info_nol "    * CPU indicates STIBP capability: "
	# intel: A processor supports STIBP if it enumerates CPUID (EAX=7H,ECX=0):EDX[27] as 1
	# amd: 8000_0008 EBX[15]=1
	if is_intel; then
		read_cpuid 0x7 $EDX 27 1 1; ret=$?
		if [ $ret -eq 0 ]; then
			pstatus green YES "Intel STIBP feature bit"
			#cpuid_stibp='Intel STIBP'
		fi
	elif is_amd; then
		read_cpuid 0x80000008 $EBX 15 1 1; ret=$?
		if [ $ret -eq 0 ]; then
			pstatus green YES "AMD STIBP feature bit"
			#cpuid_stibp='AMD STIBP'
		fi
	else
		ret=-1
		pstatus yellow UNKNOWN "unknown CPU"
	fi
	if [ $ret -eq 1 ]; then
		pstatus yellow NO
	elif [ $ret -eq 2 ]; then
		pstatus yellow UNKNOWN "is cpuid kernel module available?"
	fi


	if is_amd; then
		_info_nol "    * CPU indicates preferring STIBP always-on: "
		read_cpuid 0x80000008 $EBX 17 1 1; ret=$?
		if [ $ret -eq 0 ]; then
			pstatus green YES
		else
			pstatus yellow NO
		fi
	fi

	# variant 4
	if is_intel; then
		_info     "  * Speculative Store Bypass Disable (SSBD)"
		_info_nol "    * CPU indicates SSBD capability: "
		read_cpuid 0x7 $EDX 31 1 1; ret24=$?; ret25=$ret24
		if [ $ret24 -eq 0 ]; then
			cpuid_ssbd='Intel SSBD'
		fi
	elif is_amd; then
		_info     "  * Speculative Store Bypass Disable (SSBD)"
		_info_nol "    * CPU indicates SSBD capability: "
		read_cpuid 0x80000008 $EBX 24 1 1; ret24=$?
		read_cpuid 0x80000008 $EBX 25 1 1; ret25=$?
		if [ $ret24 -eq 0 ]; then
			cpuid_ssbd='AMD SSBD in SPEC_CTRL'
			#cpuid_ssbd_spec_ctrl=1
		elif [ $ret25 -eq 0 ]; then
			cpuid_ssbd='AMD SSBD in VIRT_SPEC_CTRL'
			#cpuid_ssbd_virt_spec_ctrl=1
		elif [ "$cpu_family" -ge 21 ] && [ "$cpu_family" -le 23 ]; then
			cpuid_ssbd='AMD non-architectural MSR'
		fi
	fi

	if [ -n "$cpuid_ssbd" ]; then
		pstatus green YES "$cpuid_ssbd"
	elif [ "$ret24" = 2 ] && [ "$ret25" = 2 ]; then
		pstatus yellow UNKNOWN "is cpuid kernel module available?"
	else
		pstatus yellow NO
	fi

	if is_amd; then
		# similar to SSB_NO for intel
		read_cpuid 0x80000008 $EBX 26 1 1; ret=$?
		if [ $ret -eq 0 ]; then
			amd_ssb_no=1
		fi
	fi

	_info "  * L1 data cache invalidation"
	_info_nol "    * FLUSH_CMD MSR is available: "
	if [ ! -e /dev/cpu/0/msr ] && [ ! -e /dev/cpuctl0 ]; then
		pstatus yellow UNKNOWN "is msr kernel module available?"
	elif [ ! -r /dev/cpu/0/msr ] && [ ! -w /dev/cpuctl0 ]; then
		pstatus yellow UNKNOWN "are you root?"
	else
		# the new MSR 'FLUSH_CMD' is at offset 0x10b, write-only
		# we test if of all cpus
		val=0
		cpu_mismatch=0
		for i in $(seq 0 "$idx_max_cpu")
		do
			write_msr 0x10b "$i"; ret=$?
			if [ "$i" -eq 0 ]; then
				val=$ret
			else
				if [ "$ret" -eq $val ]; then
					continue
				else
					cpu_mismatch=1
				fi
			fi
		done

		if [ $val -eq 0 ]; then
			if [ $cpu_mismatch -eq 0 ]; then
				pstatus green YES
				cpu_flush_cmd=1
			else
				pstatus green YES "But not in all CPUs"
			fi
		elif [ $val -eq 200 ]; then
			pstatus yellow UNKNOWN "is msr kernel module available?"
		else
			pstatus yellow NO
		fi
	fi
	# CPUID of L1D
	_info_nol "    * CPU indicates L1D flush capability: "
	read_cpuid 0x7 $EDX 28 1 1; ret=$?
	if [ $ret -eq 0 ]; then
		pstatus green YES "L1D flush feature bit"
	elif [ $ret -eq 1 ]; then
		pstatus yellow NO
	elif [ $ret -eq 2 ]; then
		pstatus yellow UNKNOWN "is cpuid kernel module available?"
	fi

	if is_intel; then
		_info     "  * Enhanced IBRS (IBRS_ALL)"
		_info_nol "    * CPU indicates ARCH_CAPABILITIES MSR availability: "
		cpuid_arch_capabilities=-1
		# A processor supports the ARCH_CAPABILITIES MSR if it enumerates CPUID (EAX=7H,ECX=0):EDX[29] as 1
		read_cpuid 0x7 $EDX 29 1 1; ret=$?
		if [ $ret -eq 0 ]; then
			pstatus green YES
			cpuid_arch_capabilities=1
		elif [ $ret -eq 2 ]; then
			pstatus yellow UNKNOWN "is cpuid kernel module available?"
		else
			pstatus yellow NO
			cpuid_arch_capabilities=0
		fi

		_info_nol "    * ARCH_CAPABILITIES MSR advertises IBRS_ALL capability: "
		capabilities_rdcl_no=-1
		capabilities_ibrs_all=-1
		capabilities_rsba=-1
		capabilities_l1dflush_no=-1
		capabilities_ssb_no=-1
		if [ "$cpuid_arch_capabilities" = -1 ]; then
			pstatus yellow UNKNOWN
		elif [ "$cpuid_arch_capabilities" != 1 ]; then
			capabilities_rdcl_no=0
			capabilities_ibrs_all=0
			capabilities_rsba=0
			capabilities_l1dflush_no=0
			capabilities_ssb_no=0
			pstatus yellow NO
		elif [ ! -e /dev/cpu/0/msr ] && [ ! -e /dev/cpuctl0 ]; then
			spec_ctrl_msr=-1
			pstatus yellow UNKNOWN "is msr kernel module available?"
		else
			# the new MSR 'ARCH_CAPABILITIES' is at offset 0x10a
			# we check if we have it for all cpus
			val=0
			val_cap_msr=0
			cpu_mismatch=0
			for i in $(seq 0 "$idx_max_cpu")
			do
				read_msr 0x10a "$i"; ret=$?
				capabilities=$read_msr_value
				if [ "$i" -eq 0 ]; then
					val=$ret
					val_cap_msr=$capabilities
				else
					if [ "$ret" -eq "$val" ] && [ "$capabilities" -eq "$val_cap_msr" ]; then
						continue
					else
						cpu_mismatch=1
					fi
				fi
			done
			capabilities=$val_cap_msr
			capabilities_rdcl_no=0
			capabilities_ibrs_all=0
			capabilities_rsba=0
			capabilities_l1dflush_no=0
			capabilities_ssb_no=0
			if [ $val -eq 0 ]; then
				_debug "capabilities MSR is $capabilities (decimal)"
				[ $(( capabilities >> 0 & 1 )) -eq 1 ] && capabilities_rdcl_no=1
				[ $(( capabilities >> 1 & 1 )) -eq 1 ] && capabilities_ibrs_all=1
				[ $(( capabilities >> 2 & 1 )) -eq 1 ] && capabilities_rsba=1
				[ $(( capabilities >> 3 & 1 )) -eq 1 ] && capabilities_l1dflush_no=1
				[ $(( capabilities >> 4 & 1 )) -eq 1 ] && capabilities_ssb_no=1
				_debug "capabilities says rdcl_no=$capabilities_rdcl_no ibrs_all=$capabilities_ibrs_all rsba=$capabilities_rsba l1dflush_no=$capabilities_l1dflush_no ssb_no=$capabilities_ssb_no"
				if [ "$capabilities_ibrs_all" = 1 ]; then
					if [ $cpu_mismatch -eq 0 ]; then
						pstatus green YES
					else
						pstatus green YES "But not in all CPUs"
					fi
				else
					pstatus yellow NO
				fi
			elif [ $val -eq 200 ]; then
				pstatus yellow UNKNOWN "is msr kernel module available?"
			elif [ $val -eq 201 ]; then
				pstatus yellow UNKNOWN "missing tool, install either msr-tools or perl"
			else
				pstatus yellow NO
			fi
		fi

		_info_nol "  * CPU explicitly indicates not being vulnerable to Meltdown (RDCL_NO): "
		if [ "$capabilities_rdcl_no" = -1 ]; then
			pstatus yellow UNKNOWN
		elif [ "$capabilities_rdcl_no" = 1 ]; then
			pstatus green YES
		else
			pstatus yellow NO
		fi

		_info_nol "  * CPU explicitly indicates not being vulnerable to Variant 4 (SSB_NO): "
		if [ "$capabilities_ssb_no" = -1 ]; then
			pstatus yellow UNKNOWN
		elif [ "$capabilities_ssb_no" = 1 ] || [ "$amd_ssb_no" = 1 ]; then
			pstatus green YES
		else
			pstatus yellow NO
		fi

		_info_nol "  * CPU/Hypervisor indicates L1D flushing is not necessary on this system: "
		if [ "$capabilities_l1dflush_no" = -1 ]; then
			pstatus yellow UNKNOWN
		elif [ "$capabilities_l1dflush_no" = 1 ]; then
			pstatus green YES
		else
			pstatus yellow NO
		fi

		_info_nol "  * Hypervisor indicates host CPU might be vulnerable to RSB underflow (RSBA): "
		if [ "$capabilities_rsba" = -1 ]; then
			pstatus yellow UNKNOWN
		elif [ "$capabilities_rsba" = 1 ]; then
			pstatus yellow YES
		else
			pstatus blue NO
		fi
	fi

	_info_nol "  * CPU supports Software Guard Extensions (SGX): "
	ret=1
	cpuid_sgx=0
	if is_intel; then
		read_cpuid 0x7 $EBX 2 1 1; ret=$?
	fi
	if [ $ret -eq 0 ]; then
		pstatus blue YES
		cpuid_sgx=1
	elif [ $ret -eq 2 ]; then
		pstatus yellow UNKNOWN "is cpuid kernel module available?"
		cpuid_sgx=-1
	else
		pstatus green NO
	fi

	_info_nol "  * CPU microcode is known to cause stability problems: "
	if is_ucode_blacklisted; then
		pstatus red YES "$ucode_found"
		_warn
		_warn "The microcode your CPU is running on is known to cause instability problems,"
		_warn "such as intempestive reboots or random crashes."
		_warn "You are advised to either revert to a previous microcode version (that might not have"
		_warn "the mitigations for Spectre), or upgrade to a newer one if available."
		_warn
	else
		pstatus blue NO "$ucode_found"
	fi

	_info_nol "  * CPU microcode is the latest known available version: "
	is_latest_known_ucode; ret=$?
	if [ $ret -eq 0 ]; then
		pstatus green YES "$ucode_latest"
	elif [ $ret -eq 1 ]; then
		pstatus red NO "$ucode_latest"
	else
		pstatus blue UNKNOWN "$ucode_latest"
	fi
}

check_cpu_vulnerabilities()
{
	_info     "* CPU vulnerability to the speculative execution attack variants"
	for cve in $supported_cve_list; do
		_info_nol "  * Vulnerable to $cve ($(cve2name "$cve")): "
		if is_cpu_vulnerable "$cve"; then
			pstatus yellow YES
		else
			pstatus green NO
		fi
	done
}

check_redhat_canonical_spectre()
{
	# if we were already called, don't do it again
	[ -n "$redhat_canonical_spectre" ] && return

	if ! which "${opt_arch_prefix}strings" >/dev/null 2>&1; then
		redhat_canonical_spectre=-1
	elif [ -n "$kernel_err" ]; then
		redhat_canonical_spectre=-2
	else
		# Red Hat / Ubuntu specific variant1 patch is difficult to detect,
		# let's use the two same tricks than the official Red Hat detection script uses:
		if "${opt_arch_prefix}strings" "$kernel" | grep -qw noibrs && "${opt_arch_prefix}strings" "$kernel" | grep -qw noibpb; then
			# 1) detect their specific variant2 patch. If it's present, it means
			# that the variant1 patch is also present (both were merged at the same time)
			_debug "found redhat/canonical version of the variant2 patch (implies variant1)"
			redhat_canonical_spectre=1
		elif "${opt_arch_prefix}strings" "$kernel" | grep -q 'x86/pti:'; then
			# 2) detect their specific variant3 patch. If it's present, but the variant2
			# is not, it means that only variant1 is present in addition to variant3
			_debug "found redhat/canonical version of the variant3 patch (implies variant1 but not variant2)"
			redhat_canonical_spectre=2
		else
			redhat_canonical_spectre=0
		fi
	fi
}

###################
# SPECTRE 1 SECTION

# bounds check bypass aka 'Spectre Variant 1'
check_CVE_2017_5753()
{
	cve='CVE-2017-5753'
	_info "\033[1;34m$cve aka '$(cve2name "$cve")'\033[0m"
	if [ "$os" = Linux ]; then
		check_CVE_2017_5753_linux
	elif echo "$os" | grep -q BSD; then
		check_CVE_2017_5753_bsd
	else
		_warn "Unsupported OS ($os)"
	fi
}

check_CVE_2017_5753_linux()
{
	status=UNK
	sys_interface_available=0
	msg=''
	if sys_interface_check "/sys/devices/system/cpu/vulnerabilities/spectre_v1"; then
		# this kernel has the /sys interface, trust it over everything
		# v0.33+: don't. some kernels have backported the array_index_mask_nospec() workaround without
		# modifying the vulnerabilities/spectre_v1 file. that's bad. we can't trust it when it says Vulnerable :(
		# see "silent backport" detection at the bottom of this func
		sys_interface_available=1
	fi
	if [ "$opt_sysfs_only" != 1 ]; then
		# no /sys interface (or offline mode), fallback to our own ways
		_info_nol "* Kernel has array_index_mask_nospec: "
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
		if [ -n "$kernel_err" ]; then
			pstatus yellow UNKNOWN "couldn't check ($kernel_err)"
		elif ! which perl >/dev/null 2>&1; then
			pstatus yellow UNKNOWN "missing 'perl' binary, please install it"
		else
			perl -ne '/\x0f\x83....\x48\x19\xd2\x48\x21\xd0/ and $found++; END { exit($found) }' "$kernel"; ret=$?
			if [ $ret -gt 0 ]; then
				pstatus green YES "$ret occurrence(s) found of x86 64 bits array_index_mask_nospec()"
				v1_mask_nospec="x86 64 bits array_index_mask_nospec"
			else
				perl -ne '/\x3b\x82..\x00\x00\x73.\x19\xd2\x21\xd0/ and $found++; END { exit($found) }' "$kernel"; ret=$?
				if [ $ret -gt 0 ]; then
					pstatus green YES "$ret occurrence(s) found of x86 32 bits array_index_mask_nospec()"
					v1_mask_nospec="x86 32 bits array_index_mask_nospec"
				else
					ret=$("${opt_arch_prefix}objdump" -d "$kernel" | grep -w -e f3af8014 -e e320f014 -B2 | grep -B1 -w sbc | grep -w -c cmp)
					if [ "$ret" -gt 0 ]; then
						pstatus green YES "$ret occurrence(s) found of arm 32 bits array_index_mask_nospec()"
						v1_mask_nospec="arm 32 bits array_index_mask_nospec"
					else
						pstatus yellow NO
					fi
				fi
			fi
		fi

		_info_nol "* Kernel has the Red Hat/Ubuntu patch: "
		check_redhat_canonical_spectre
		if [ "$redhat_canonical_spectre" = -1 ]; then
			pstatus yellow UNKNOWN "missing '${opt_arch_prefix}strings' tool, please install it, usually it's in the binutils package"
		elif [ "$redhat_canonical_spectre" = -2 ]; then
			pstatus yellow UNKNOWN "couldn't check ($kernel_err)"
		elif [ "$redhat_canonical_spectre" = 1 ]; then
			pstatus green YES
		elif [ "$redhat_canonical_spectre" = 2 ]; then
			pstatus green YES "but without IBRS"
		else
			pstatus yellow NO
		fi

		_info_nol "* Kernel has mask_nospec64 (arm64): "
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
		# if we have v1_mask_nospec or redhat_canonical_spectre>0, don't bother disassembling the kernel, the answer is no.
		if [ -n "$v1_mask_nospec" ] || [ "$redhat_canonical_spectre" -gt 0 ]; then
			pstatus yellow NO
		elif [ -n "$kernel_err" ]; then
			pstatus yellow UNKNOWN "couldn't check ($kernel_err)"
		elif ! which perl >/dev/null 2>&1; then
			pstatus yellow UNKNOWN "missing 'perl' binary, please install it"
		elif ! which "${opt_arch_prefix}objdump" >/dev/null 2>&1; then
			pstatus yellow UNKNOWN "missing '${opt_arch_prefix}objdump' tool, please install it, usually it's in the binutils package"
		else
			"${opt_arch_prefix}objdump" -d "$kernel" | perl -ne 'push @r, $_; /\s(hint|csdb)\s/ && $r[0]=~/\ssub\s+(x\d+)/ && $r[1]=~/\sbic\s+$1,\s+$1,/ && $r[2]=~/\sand\s/ && exit(9); shift @r if @r>3'; ret=$?
			if [ "$ret" -eq 9 ]; then
				pstatus green YES "mask_nospec64 macro is present and used"
				v1_mask_nospec="arm64 mask_nospec64"
			else
				pstatus yellow NO
			fi
		fi

		if [ "$opt_verbose" -ge 2 ] || ( [ -z "$v1_mask_nospec" ] && [ "$redhat_canonical_spectre" != 1 ] && [ "$redhat_canonical_spectre" != 2 ] ); then
			# this is a slow heuristic and we don't need it if we already know the kernel is patched
			# but still show it in verbose mode
			_info_nol "* Checking count of LFENCE instructions following a jump in kernel... "
			if [ -n "$kernel_err" ]; then
				pstatus yellow UNKNOWN "couldn't check ($kernel_err)"
			else
				if ! which "${opt_arch_prefix}objdump" >/dev/null 2>&1; then
					pstatus yellow UNKNOWN "missing '${opt_arch_prefix}objdump' tool, please install it, usually it's in the binutils package"
				else
					# here we disassemble the kernel and count the number of occurrences of the LFENCE opcode
					# in non-patched kernels, this has been empirically determined as being around 40-50
					# in patched kernels, this is more around 70-80, sometimes way higher (100+)
					# v0.13: 68 found in a 3.10.23-xxxx-std-ipv6-64 (with lots of modules compiled-in directly), which doesn't have the LFENCE patches,
					# so let's push the threshold to 70.
					# v0.33+: now only count lfence opcodes after a jump, way less error-prone
					# non patched kernel have between 0 and 20 matches, patched ones have at least 40-45
					nb_lfence=$("${opt_arch_prefix}objdump" -d "$kernel" 2>/dev/null | grep -w -B1 lfence | grep -Ewc 'jmp|jne|je')
					if [ "$nb_lfence" -lt 30 ]; then
						pstatus yellow NO "only $nb_lfence jump-then-lfence instructions found, should be >= 30 (heuristic)"
					else
						v1_lfence=1
						pstatus green YES "$nb_lfence jump-then-lfence instructions found, which is >= 30 (heuristic)"
					fi
				fi
			fi
		fi

	else
		# we have no sysfs but were asked to use it only!
		msg="/sys vulnerability interface use forced, but it's not available!"
		status=UNK
	fi

	# report status
	if ! is_cpu_vulnerable "$cve"; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	elif [ -z "$msg" ]; then
		# if msg is empty, sysfs check didn't fill it, rely on our own test
		if [ -n "$v1_mask_nospec" ]; then
			pvulnstatus $cve OK "Kernel source has been patched to mitigate the vulnerability ($v1_mask_nospec)"
		elif [ "$redhat_canonical_spectre" = 1 ] || [ "$redhat_canonical_spectre" = 2 ]; then
			pvulnstatus $cve OK "Kernel source has been patched to mitigate the vulnerability (Red Hat/Ubuntu patch)"
		elif [ "$v1_lfence" = 1 ]; then
			pvulnstatus $cve OK "Kernel source has PROBABLY been patched to mitigate the vulnerability (jump-then-lfence instructions heuristic)"
		elif [ "$kernel_err" ]; then
			pvulnstatus $cve UNK "Couldn't find kernel image or tools missing to execute the checks"
			explain "Re-run this script with root privileges, after installing the missing tools indicated above"
		else
			pvulnstatus $cve VULN "Kernel source needs to be patched to mitigate the vulnerability"
			explain "Your kernel is too old to have the mitigation for Variant 1, you should upgrade to a newer kernel. If you're using a Linux distro and didn't compile the kernel yourself, you should upgrade your distro to get a newer kernel."
		fi
	else
		if [ "$msg" = "Vulnerable" ] && [ -n "$v1_mask_nospec" ]; then
			pvulnstatus $cve OK "Kernel source has been patched to mitigate the vulnerability (silent backport of array_index_mask_nospec)"
		else
			if [ "$msg" = "Vulnerable" ]; then
				msg="Kernel source needs to be patched to mitigate the vulnerability"
				_explain="Your kernel is too old to have the mitigation for Variant 1, you should upgrade to a newer kernel. If you're using a Linux distro and didn't compile the kernel yourself, you should upgrade your distro to get a newer kernel."
			fi
			pvulnstatus $cve "$status" "$msg"
			[ -n "$_explain" ] && explain "$_explain"
			unset _explain
		fi
	fi
}

check_CVE_2017_5753_bsd()
{
	if ! is_cpu_vulnerable "$cve"; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	else
		pvulnstatus $cve VULN "no mitigation for BSD yet"
	fi
}

###################
# SPECTRE 2 SECTION

# branch target injection aka 'Spectre Variant 2'
check_CVE_2017_5715()
{
	cve='CVE-2017-5715'
	_info "\033[1;34m$cve aka '$(cve2name "$cve")'\033[0m"
	if [ "$os" = Linux ]; then
		check_CVE_2017_5715_linux
	elif echo "$os" | grep -q BSD; then
		check_CVE_2017_5715_bsd
	else
		_warn "Unsupported OS ($os)"
	fi
}

check_CVE_2017_5715_linux()
{
	status=UNK
	sys_interface_available=0
	msg=''
	if sys_interface_check "/sys/devices/system/cpu/vulnerabilities/spectre_v2"; then
		# this kernel has the /sys interface, trust it over everything
		sys_interface_available=1
	fi
	if [ "$opt_sysfs_only" != 1 ]; then
		_info "* Mitigation 1"

		ibrs_can_tell=0
		ibrs_supported=''
		ibrs_enabled=''
		ibpb_can_tell=0
		ibpb_supported=''
		ibpb_enabled=''

		if [ "$opt_live" = 1 ]; then
			# in live mode, we can check for the ibrs_enabled file in debugfs
			# all versions of the patches have it (NOT the case of IBPB or KPTI)
			ibrs_can_tell=1
			mount_debugfs
			for dir in \
				/sys/kernel/debug \
				/sys/kernel/debug/x86 \
				"$procfs/sys/kernel"; do
				if [ -e "$dir/ibrs_enabled" ]; then
					# if the file is there, we have IBRS compiled-in
					# /sys/kernel/debug/ibrs_enabled: vanilla
					# /sys/kernel/debug/x86/ibrs_enabled: Red Hat (see https://access.redhat.com/articles/3311301)
					# /proc/sys/kernel/ibrs_enabled: OpenSUSE tumbleweed
					specex_knob_dir=$dir
					ibrs_supported="$dir/ibrs_enabled exists"
					ibrs_enabled=$(cat "$dir/ibrs_enabled" 2>/dev/null)
					_debug "ibrs: found $dir/ibrs_enabled=$ibrs_enabled"
					# if ibrs_enabled is there, ibpb_enabled will be in the same dir
					if [ -e "$dir/ibpb_enabled" ]; then
						# if the file is there, we have IBPB compiled-in (see note above for IBRS)
						ibpb_supported="$dir/ibpb_enabled exists"
						ibpb_enabled=$(cat "$dir/ibpb_enabled" 2>/dev/null)
						_debug "ibpb: found $dir/ibpb_enabled=$ibpb_enabled"
					else
						_debug "ibpb: $dir/ibpb_enabled file doesn't exist"
					fi
					break
				else
					_debug "ibrs: $dir/ibrs_enabled file doesn't exist"
				fi
			done
			# on some newer kernels, the spec_ctrl_ibrs flag in "$procfs/cpuinfo"
			# is set when ibrs has been administratively enabled (usually from cmdline)
			# which in that case means ibrs is supported *and* enabled for kernel & user
			# as per the ibrs patch series v3
			if [ -z "$ibrs_supported" ]; then
				if grep ^flags "$procfs/cpuinfo" | grep -qw spec_ctrl_ibrs; then
					_debug "ibrs: found spec_ctrl_ibrs flag in $procfs/cpuinfo"
					ibrs_supported="spec_ctrl_ibrs flag in $procfs/cpuinfo"
					# enabled=2 -> kernel & user
					ibrs_enabled=2
					# XXX and what about ibpb ?
				fi
			fi
			if [ -e "/sys/devices/system/cpu/vulnerabilities/spectre_v2" ]; then
				# when IBPB is enabled on 4.15+, we can see it in sysfs
				if grep -q 'IBPB' "/sys/devices/system/cpu/vulnerabilities/spectre_v2"; then
					_debug "ibpb: found enabled in sysfs"
					[ -z "$ibpb_supported" ] && ibpb_supported='IBPB found enabled in sysfs'
					[ -z "$ibpb_enabled"   ] && ibpb_enabled=1
				fi
				# when IBRS_FW is enabled on 4.15+, we can see it in sysfs
				if grep -q ', IBRS_FW' "/sys/devices/system/cpu/vulnerabilities/spectre_v2"; then
					_debug "ibrs: found IBRS_FW in sysfs"
					[ -z "$ibrs_supported" ] && ibrs_supported='found IBRS_FW in sysfs'
					ibrs_fw_enabled=1
				fi
				# when IBRS is enabled on 4.15+, we can see it in sysfs
				if grep -q -e 'IBRS' -e 'Indirect Branch Restricted Speculation' "/sys/devices/system/cpu/vulnerabilities/spectre_v2"; then
					_debug "ibrs: found IBRS in sysfs"
					[ -z "$ibrs_supported" ] && ibrs_supported='found IBRS in sysfs'
					[ -z "$ibrs_enabled"   ] && ibrs_enabled=3
				fi
			fi
			# in live mode, if ibrs or ibpb is supported and we didn't find these are enabled, then they are not
			[ -n "$ibrs_supported" ] && [ -z "$ibrs_enabled" ] && ibrs_enabled=0
			[ -n "$ibpb_supported" ] && [ -z "$ibpb_enabled" ] && ibpb_enabled=0
		fi
		if [ -z "$ibrs_supported" ]; then
			check_redhat_canonical_spectre
			if [ "$redhat_canonical_spectre" = 1 ]; then
				ibrs_supported="Red Hat/Ubuntu variant"
				ibpb_supported="Red Hat/Ubuntu variant"
			fi
		fi
		if [ -z "$ibrs_supported" ] && [ -n "$kernel" ]; then
			if ! which "${opt_arch_prefix}strings" >/dev/null 2>&1; then
				:
			else
				ibrs_can_tell=1
				ibrs_supported=$("${opt_arch_prefix}strings" "$kernel" | grep -Fw -e ', IBRS_FW' | head -1)
				if [ -n "$ibrs_supported" ]; then
					_debug "ibrs: found ibrs evidence in kernel image ($ibrs_supported)"
					ibrs_supported="found '$ibrs_supported' in kernel image"
				fi
			fi
		fi
		if [ -z "$ibrs_supported" ] && [ -n "$opt_map" ]; then
			ibrs_can_tell=1
			if grep -q spec_ctrl "$opt_map"; then
				ibrs_supported="found spec_ctrl in symbols file"
				_debug "ibrs: found '*spec_ctrl*' symbol in $opt_map"
			fi
		fi
		# recent (4.15) vanilla kernels have IBPB but not IBRS, and without the debugfs tunables of Red Hat
		# we can detect it directly in the image
		if [ -z "$ibpb_supported" ] && [ -n "$kernel" ]; then
			if ! which "${opt_arch_prefix}strings" >/dev/null 2>&1; then
				:
			else
				ibpb_can_tell=1
				ibpb_supported=$("${opt_arch_prefix}strings" "$kernel" | grep -Fw -e 'ibpb' -e ', IBPB' | head -1)
				if [ -n "$ibpb_supported" ]; then
					_debug "ibpb: found ibpb evidence in kernel image ($ibpb_supported)"
					ibpb_supported="found '$ibpb_supported' in kernel image"
				fi
			fi
		fi

		_info_nol "  * Kernel is compiled with IBRS support: "
		if [ -z "$ibrs_supported" ]; then
			if [ "$ibrs_can_tell" = 1 ]; then
				pstatus yellow NO
			else
				# if we're in offline mode without System.map, we can't really know
				pstatus yellow UNKNOWN "in offline mode, we need the kernel image and System.map to be able to tell"
			fi
		else
			if [ "$opt_verbose" -ge 2 ]; then
				pstatus green YES "$ibrs_supported"
			else
				pstatus green YES
			fi
		fi

		_info_nol "    * IBRS enabled and active: "
		if [ "$opt_live" = 1 ]; then
			if [ "$ibpb_enabled" = 2 ]; then
				# if ibpb=2, ibrs is forcefully=0
				pstatus blue NO "IBPB used instead of IBRS in all kernel entrypoints"
			else
				# 0 means disabled
				# 1 is enabled only for kernel space
				# 2 is enabled for kernel and user space
				# 3 is enabled
				case "$ibrs_enabled" in
					0)
						if [ "$ibrs_fw_enabled" = 1 ]; then
							pstatus blue YES "for firmware code only"
						else
							pstatus yellow NO
						fi
						;;
					1)	if [ "$ibrs_fw_enabled" = 1 ]; then pstatus green YES "for kernel space and firmware code"; else pstatus green YES "for kernel space"; fi;;
					2)	if [ "$ibrs_fw_enabled" = 1 ]; then pstatus green YES "for kernel, user space, and firmware code" ; else pstatus green YES "for both kernel and user space"; fi;;
					3)	if [ "$ibrs_fw_enabled" = 1 ]; then pstatus green YES "for kernel and firmware code"; else pstatus green YES; fi;;
					*)	if [ "$cpuid_ibrs" != 'SPEC_CTRL' ] && [ "$cpuid_ibrs" != 'IBRS_SUPPORT' ] && [ "$cpuid_spec_ctrl" != -1 ]; 
							then pstatus yellow NO; _debug "ibrs: known cpu not supporting SPEC-CTRL or IBRS"; 
						else 
							pstatus yellow UNKNOWN; fi;;
				esac
			fi
		else
			pstatus blue N/A "not testable in offline mode"
		fi

		_info_nol "  * Kernel is compiled with IBPB support: "
		if [ -z "$ibpb_supported" ]; then
			if [ "$ibpb_can_tell" = 1 ]; then
				pstatus yellow NO
			else
				# if we're in offline mode without System.map, we can't really know
				pstatus yellow UNKNOWN "in offline mode, we need the kernel image to be able to tell"
			fi
		else
			if [ "$opt_verbose" -ge 2 ]; then
				pstatus green YES "$ibpb_supported"
			else
				pstatus green YES
			fi
		fi

		_info_nol "    * IBPB enabled and active: "
		if [ "$opt_live" = 1 ]; then
			case "$ibpb_enabled" in
				"")
					if [ "$ibrs_supported" = 1 ]; then
						pstatus yellow UNKNOWN
					else
						pstatus yellow NO
					fi
					;;
				0)
					pstatus yellow NO
					;;
				1) pstatus green YES;;
				2) pstatus green YES "IBPB used instead of IBRS in all kernel entrypoints";;
				*) pstatus yellow UNKNOWN;;
			esac
		else
			pstatus blue N/A "not testable in offline mode"
		fi

		_info "* Mitigation 2"
		_info_nol "  * Kernel has branch predictor hardening (arm): "
		if [ -r "$opt_config" ]; then
			bp_harden_can_tell=1
			bp_harden=$(grep -w 'CONFIG_HARDEN_BRANCH_PREDICTOR=y' "$opt_config")
			if [ -n "$bp_harden" ]; then
				pstatus green YES
				_debug "bp_harden: found '$bp_harden' in $opt_config"
			fi
		fi
		if [ -z "$bp_harden" ] && [ -n "$opt_map" ]; then
			bp_harden_can_tell=1
			bp_harden=$(grep -w bp_hardening_data "$opt_map")
			if [ -n "$bp_harden" ]; then
				pstatus green YES
				_debug "bp_harden: found '$bp_harden' in $opt_map"
			fi
		fi
		if [ -z "$bp_harden" ]; then
			if [ "$bp_harden_can_tell" = 1 ]; then
				pstatus yellow NO
			else
				pstatus yellow UNKNOWN
			fi
		fi

		_info_nol "  * Kernel compiled with retpoline option: "
		# We check the RETPOLINE kernel options
		if [ -r "$opt_config" ]; then
			if grep -q '^CONFIG_RETPOLINE=y' "$opt_config"; then
				pstatus green YES
				retpoline=1
				# shellcheck disable=SC2046
				_debug 'retpoline: found '$(grep '^CONFIG_RETPOLINE' "$opt_config")" in $opt_config"
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
			# In latest retpoline LKML patches, the noretpoline_setup symbol exists only if CONFIG_RETPOLINE is set
			# *AND* if the compiler is retpoline-compliant, so look for that symbol
			#
			# if there is "retpoline" in the file and NOT "minimal", then it's full retpoline
			# (works for vanilla and Red Hat variants)
			if [ "$opt_live" = 1 ] && [ -e "/sys/devices/system/cpu/vulnerabilities/spectre_v2" ]; then
				if grep -qwi retpoline /sys/devices/system/cpu/vulnerabilities/spectre_v2; then
					if grep -qwi minimal /sys/devices/system/cpu/vulnerabilities/spectre_v2; then
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
			elif [ -n "$kernel" ]; then
				# look for the symbol
				if which "${opt_arch_prefix}nm" >/dev/null 2>&1; then
					# the proper way: use nm and look for the symbol
					if "${opt_arch_prefix}nm" "$kernel" 2>/dev/null | grep -qw 'noretpoline_setup'; then
						retpoline_compiler=1
						retpoline_compiler_reason="noretpoline_setup found in kernel symbols"
					fi
				elif grep -q noretpoline_setup "$kernel"; then
					# if we don't have nm, nevermind, the symbol name is long enough to not have
					# any false positive using good old grep directly on the binary
					retpoline_compiler=1
					retpoline_compiler_reason="noretpoline_setup found in kernel"
				fi
			fi
			if [ -n "$retpoline_compiler" ]; then
				_info_nol "    * Kernel compiled with a retpoline-aware compiler: "
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
		if [ "$opt_live" = 1 ]; then
			if [ -e "$specex_knob_dir/retp_enabled" ]; then
				retp_enabled=$(cat "$specex_knob_dir/retp_enabled" 2>/dev/null)
				_debug "retpoline: found $specex_knob_dir/retp_enabled=$retp_enabled"
				_info_nol "    * Retpoline is enabled: "
				if [ "$retp_enabled" = 1 ]; then
					pstatus green YES
				else
					pstatus yellow NO
				fi
			fi
		fi

		# only for information, in verbose mode
		if [ "$opt_verbose" -ge 2 ]; then
			_info_nol "    * Local gcc is retpoline-aware: "
			if which gcc >/dev/null 2>&1; then
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
			_info_nol "  * Kernel supports RSB filling: "
			if ! which "${opt_arch_prefix}strings" >/dev/null 2>&1; then
				pstatus yellow UNKNOWN "missing '${opt_arch_prefix}strings' tool, please install it, usually it's in the binutils package"
			elif [ -z "$kernel" ]; then
				pstatus yellow UNKNOWN "kernel image missing"
			else
				rsb_filling=$("${opt_arch_prefix}strings" "$kernel" | grep -w 'Filling RSB on context switch')
				if [ -n "$rsb_filling" ]; then
					pstatus green YES
				else
					pstatus yellow NO
				fi
			fi
		fi

	elif [ "$sys_interface_available" = 0 ]; then
		# we have no sysfs but were asked to use it only!
		msg="/sys vulnerability interface use forced, but it's not available!"
		status=UNK
	fi

	if ! is_cpu_vulnerable "$cve"; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	else
		if [ "$retpoline" = 1 ] && [ "$retpoline_compiler" = 1 ] && [ "$retp_enabled" != 0 ] && [ -n "$ibpb_enabled" ] && [ "$ibpb_enabled" -ge 1 ] && ( ! is_vulnerable_to_empty_rsb || [ -n "$rsb_filling" ] ); then
			pvulnstatus $cve OK "Full retpoline + IBPB are mitigating the vulnerability"
		elif [ "$retpoline" = 1 ] && [ "$retpoline_compiler" = 1 ] && [ "$retp_enabled" != 0 ] && [ "$opt_paranoid" = 0 ] && ( ! is_vulnerable_to_empty_rsb || [ -n "$rsb_filling" ] ); then
			pvulnstatus $cve OK "Full retpoline is mitigating the vulnerability"
			if [ -n "$cpuid_ibpb" ]; then
				_warn "You should enable IBPB to complete retpoline as a Variant 2 mitigation"
			else
				_warn "IBPB is considered as a good addition to retpoline for Variant 2 mitigation, but your CPU microcode doesn't support it"
			fi
		elif [ -n "$ibrs_enabled" ] && [ -n "$ibpb_enabled" ] && [ "$ibrs_enabled" -ge 1 ] && [ "$ibpb_enabled" -ge 1 ]; then
			pvulnstatus $cve OK "IBRS + IBPB are mitigating the vulnerability"
		elif [ "$ibpb_enabled" = 2 ] && ! is_cpu_smt_enabled; then
			pvulnstatus $cve OK "Full IBPB is mitigating the vulnerability"
		elif [ -n "$bp_harden" ]; then
			pvulnstatus $cve OK "Branch predictor hardening mitigates the vulnerability"
		elif [ -z "$bp_harden" ] && [ "$cpu_vendor" = ARM ]; then
			pvulnstatus $cve VULN "Branch predictor hardening is needed to mitigate the vulnerability"
			explain "Your kernel has not been compiled with the CONFIG_UNMAP_KERNEL_AT_EL0 option, recompile it with this option enabled."
		elif [ "$opt_live" != 1 ]; then
			if [ "$retpoline" = 1 ] && [ -n "$ibpb_supported" ]; then
				pvulnstatus $cve OK "offline mode: kernel supports retpoline + IBPB to mitigate the vulnerability"
			elif [ -n "$ibrs_supported" ] && [ -n "$ibpb_supported" ]; then
				pvulnstatus $cve OK "offline mode: kernel supports IBRS + IBPB to mitigate the vulnerability"
			elif [ "$ibrs_can_tell" != 1 ]; then
				pvulnstatus $cve UNK "offline mode: not enough information"
				explain "Re-run this script with root privileges, and give it the kernel image (--kernel), the kernel configuration (--config) and the System.map file (--map) corresponding to the kernel you would like to inspect."
			fi
		fi

		# if we arrive here and didn't already call pvulnstatus, then it's VULN, let's explain why
		if [ "$pvulnstatus_last_cve" != "$cve" ]; then
			# explain what's needed for this CPU
			if is_vulnerable_to_empty_rsb; then
				pvulnstatus $cve VULN "IBRS+IBPB or retpoline+IBPB+RSB filling, is needed to mitigate the vulnerability"
				explain "To mitigate this vulnerability, you need either IBRS + IBPB, both requiring hardware support from your CPU microcode in addition to kernel support, or a kernel compiled with retpoline and IBPB, with retpoline requiring a retpoline-aware compiler (re-run this script with -v to know if your version of gcc is retpoline-aware) and IBPB requiring hardware support from your CPU microcode. You also need a recent-enough kernel that supports RSB filling if you plan to use retpoline. For Skylake+ CPUs, the IBRS + IBPB approach is generally preferred as it guarantees complete protection, and the performance impact is not as high as with older CPUs in comparison with retpoline. More information about how to enable the missing bits for those two possible mitigations on your system follow. You only need to take one of the two approaches."
			elif is_zen_cpu; then
				pvulnstatus $cve VULN "retpoline+IBPB is needed to mitigate the vulnerability"
				explain "To mitigate this vulnerability, You need a kernel compiled with retpoline + IBPB support, with retpoline requiring a retpoline-aware compiler (re-run this script with -v to know if your version of gcc is retpoline-aware) and IBPB requiring hardware support from your CPU microcode."
			elif is_intel || is_amd; then
				pvulnstatus $cve VULN "IBRS+IBPB or retpoline+IBPB is needed to mitigate the vulnerability"
				explain "To mitigate this vulnerability, you need either IBRS + IBPB, both requiring hardware support from your CPU microcode in addition to kernel support, or a kernel compiled with retpoline and IBPB, with retpoline requiring a retpoline-aware compiler (re-run this script with -v to know if your version of gcc is retpoline-aware) and IBPB requiring hardware support from your CPU microcode. The retpoline + IBPB approach is generally preferred as the performance impact is lower. More information about how to enable the missing bits for those two possible mitigations on your system follow. You only need to take one of the two approaches."
			else
				# in that case, we might want to trust sysfs if it's there
				if [ -n "$msg" ]; then
					[ "$msg" = Vulnerable ] && msg="no known mitigation exists for your CPU vendor ($cpu_vendor)"
					pvulnstatus $cve $status "$msg"
				else
					pvulnstatus $cve VULN "no known mitigation exists for your CPU vendor ($cpu_vendor)"
				fi
			fi
		fi

		# if we are in live mode, we can check for a lot more stuff and explain further
		if [ "$opt_live" = 1 ] && [ "$vulnstatus" != "OK" ]; then
			_explain_hypervisor="An updated CPU microcode will have IBRS/IBPB capabilities indicated in the Hardware Check section above. If you're running under a hypervisor (KVM, Xen, VirtualBox, VMware, ...), the hypervisor needs to be up to date to be able to export the new host CPU flags to the guest. You can run this script on the host to check if the host CPU is IBRS/IBPB. If it is, and it doesn't show up in the guest, upgrade the hypervisor. You may need to reconfigure your VM to use a CPU model that has IBRS capability; in Libvirt, such CPUs are listed with an IBRS suffix."
			# IBPB (amd & intel)
			if ( [ -z "$ibpb_enabled" ] || [ "$ibpb_enabled" = 0 ] ) && ( is_intel || is_amd ); then
				if [ -z "$cpuid_ibpb" ]; then
					explain "The microcode of your CPU needs to be upgraded to be able to use IBPB. This is usually done at boot time by your kernel (the upgrade is not persistent across reboots which is why it's done at each boot). If you're using a distro, make sure you are up to date, as microcode updates are usually shipped alongside with the distro kernel. Availability of a microcode update for you CPU model depends on your CPU vendor. You can usually find out online if a microcode update is available for your CPU by searching for your CPUID (indicated in the Hardware Check section). $_explain_hypervisor"
				fi
				if [ -z "$ibpb_supported" ]; then
					explain "Your kernel doesn't have IBPB support, so you need to either upgrade your kernel (if you're using a distro) or recompiling a more recent kernel."
				fi
				if [ -n "$cpuid_ibpb" ] && [ -n "$ibpb_supported" ]; then
					if [ -e "$specex_knob_dir/ibpb_enabled" ]; then
						# newer (April 2018) Red Hat kernels have ibpb_enabled as ro, and automatically enables it with retpoline
						if [ ! -w "$specex_knob_dir/ibpb_enabled" ] && [ -e "$specex_knob_dir/retp_enabled" ]; then
							explain "Both your CPU and your kernel have IBPB support, but it is currently disabled. You kernel should enable IBPB automatically if you enable retpoline. You may enable it with \`echo 1 > $specex_knob_dir/retp_enabled\`."
						else
							explain "Both your CPU and your kernel have IBPB support, but it is currently disabled. You may enable it with \`echo 1 > $specex_knob_dir/ibpb_enabled\`."
						fi
					else
						explain "Both your CPU and your kernel have IBPB support, but it is currently disabled. You may enable it. Check in your distro's documentation on how to do this."
					fi
				fi
			elif [ "$ibpb_enabled" = 2 ] && is_cpu_smt_enabled; then
				explain "You have ibpb_enabled set to 2, but it only offers sufficient protection when simultaneous multi-threading (aka SMT or HyperThreading) is disabled. You should reboot your system with the kernel parameter \`nosmt\`."
			fi
			# /IBPB

			# IBRS (amd & intel)
			if ( [ -z "$ibrs_enabled" ] || [ "$ibrs_enabled" = 0 ] ) && ( is_intel || is_amd ); then
				if [ -z "$cpuid_ibrs" ]; then
					explain "The microcode of your CPU needs to be upgraded to be able to use IBRS. This is usually done at boot time by your kernel (the upgrade is not persistent across reboots which is why it's done at each boot). If you're using a distro, make sure you are up to date, as microcode updates are usually shipped alongside with the distro kernel. Availability of a microcode update for you CPU model depends on your CPU vendor. You can usually find out online if a microcode update is available for your CPU by searching for your CPUID (indicated in the Hardware Check section). $_explain_hypervisor"
				fi
				if [ -z "$ibrs_supported" ]; then
					explain "Your kernel doesn't have IBRS support, so you need to either upgrade your kernel (if you're using a distro) or recompiling a more recent kernel."
				fi
				if [ -n "$cpuid_ibrs" ] && [ -n "$ibrs_supported" ]; then
					if [ -e "$specex_knob_dir/ibrs_enabled" ]; then
						explain "Both your CPU and your kernel have IBRS support, but it is currently disabled. You may enable it with \`echo 1 > $specex_knob_dir/ibrs_enabled\`."
					else
						explain "Both your CPU and your kernel have IBRS support, but it is currently disabled. You may enable it. Check in your distro's documentation on how to do this."
					fi
				fi
			fi
			# /IBRS
			unset _explain_hypervisor

			# RETPOLINE (amd & intel)
			if is_amd || is_intel; then
				if [ "$retpoline" = 0 ]; then
					explain "Your kernel is not compiled with retpoline support, so you need to either upgrade your kernel (if you're using a distro) or recompile your kernel with the CONFIG_RETPOLINE option enabled. You also need to compile your kernel with  a retpoline-aware compiler (re-run this script with -v to know if your version of gcc is retpoline-aware)."
				elif [ "$retpoline" = 1 ] && [ "$retpoline_compiler" = 0 ]; then
					explain "Your kernel is compiled with retpoline, but without a retpoline-aware compiler (re-run this script with -v to know if your version of gcc is retpoline-aware)."
				elif [ "$retpoline" = 1 ] && [ "$retpoline_compiler" = 1 ] && [ "$retp_enabled" = 0 ]; then
					explain "Your kernel has retpoline support and has been compiled with a retpoline-aware compiler, but retpoline is disabled. You should enable it with \`echo 1 > $specex_knob_dir/retp_enabled\`."
				fi
			fi
			# /RETPOLINE
		fi
	fi
	# sysfs msgs:
	#1 "Vulnerable"
	#2 "Vulnerable: Minimal generic ASM retpoline"
	#2 "Vulnerable: Minimal AMD ASM retpoline"
	# "Mitigation: Full generic retpoline"
	# "Mitigation: Full AMD retpoline"
	# $MITIGATION + ", IBPB"
	# $MITIGATION + ", IBRS_FW"
	#5 $MITIGATION + " - vulnerable module loaded"
	# Red Hat only:
	#2 "Vulnerable: Minimal ASM retpoline",
	#3 "Vulnerable: Retpoline without IBPB",
	#4 "Vulnerable: Retpoline on Skylake+",
	#5 "Vulnerable: Retpoline with unsafe module(s)",
	# "Mitigation: Full retpoline",
	# "Mitigation: Full retpoline and IBRS (user space)",
	# "Mitigation: IBRS (kernel)",
	# "Mitigation: IBRS (kernel and user space)",
	# "Mitigation: IBP disabled",
}

check_CVE_2017_5715_bsd()
{
	_info     "* Mitigation 1"
	_info_nol "  * Kernel supports IBRS: "
	ibrs_disabled=$(sysctl -n hw.ibrs_disable 2>/dev/null)
	if [ -z "$ibrs_disabled" ]; then
		pstatus yellow NO
	else
		pstatus green YES
	fi

	_info_nol "  * IBRS enabled and active: "
	ibrs_active=$(sysctl -n hw.ibrs_active 2>/dev/null)
	if [ "$ibrs_active" = 1 ]; then
		pstatus green YES
	else
		pstatus yellow NO
	fi

	_info     "* Mitigation 2"
	_info_nol "  * Kernel compiled with RETPOLINE: "
	if [ -n "$kernel_err" ]; then
		pstatus yellow UNKNOWN "couldn't check ($kernel_err)"
	else
		if ! which "${opt_arch_prefix}readelf" >/dev/null 2>&1; then
			pstatus yellow UNKNOWN "missing '${opt_arch_prefix}readelf' tool, please install it, usually it's in the binutils package"
		else
			nb_thunks=$("${opt_arch_prefix}readelf" -s "$kernel" | grep -c -e __llvm_retpoline_ -e __llvm_external_retpoline_ -e __x86_indirect_thunk_)
			if [ "$nb_thunks" -gt 0 ]; then
				retpoline=1
				pstatus green YES "found $nb_thunks thunk(s)"
			else
				pstatus yellow NO
			fi
		fi
	fi

	if ! is_cpu_vulnerable "$cve"; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	elif [ "$retpoline" = 1 ]; then
		pvulnstatus $cve OK "Retpoline mitigates the vulnerability"
	elif [ "$ibrs_active" = 1 ]; then
		pvulnstatus $cve OK "IBRS mitigates the vulnerability"
	elif [ "$ibrs_disabled" = 0 ]; then
		pvulnstatus $cve VULN "IBRS is supported by your kernel but your CPU microcode lacks support"
		explain "The microcode of your CPU needs to be upgraded to be able to use IBRS. Availability of a microcode update for you CPU model depends on your CPU vendor. You can usually find out online if a microcode update is available for your CPU by searching for your CPUID (indicated in the Hardware Check section). To do a microcode update, you can search the ports for the \`cpupdate\` tool. Microcode updates done this way are not reboot-proof, so be sure to do it every time the system boots up."
	elif [ "$ibrs_disabled" = 1 ]; then
		pvulnstatus $cve VULN "IBRS is supported but administratively disabled on your system"
		explain "To enable IBRS, use \`sysctl hw.ibrs_disable=0\`"
	else
		pvulnstatus $cve VULN "IBRS is needed to mitigate the vulnerability but your kernel is missing support"
		explain "You need to either upgrade your kernel or recompile yourself a more recent version having IBRS support"
	fi
}

##################
# MELTDOWN SECTION

# no security impact but give a hint to the user in verbose mode
# about PCID/INVPCID cpuid features that must be present to avoid
# too big a performance impact with PTI
# refs:
# https://marc.info/?t=151532047900001&r=1&w=2
# https://groups.google.com/forum/m/#!topic/mechanical-sympathy/L9mHTbeQLNU
pti_performance_check()
{
	_info_nol "  * Reduced performance impact of PTI: "
	if [ -e "$procfs/cpuinfo" ] && grep ^flags "$procfs/cpuinfo" | grep -qw pcid; then
		cpu_pcid=1
	else
		read_cpuid 0x1 $ECX 17 1 1; ret=$?
		[ $ret -eq 0 ] && cpu_pcid=1
	fi

	if [ -e "$procfs/cpuinfo" ] && grep ^flags "$procfs/cpuinfo" | grep -qw invpcid; then
		cpu_invpcid=1
	else
		read_cpuid 0x7 $EBX 10 1 1; ret=$?
		[ $ret -eq 0 ] && cpu_invpcid=1
	fi

	if [ "$cpu_invpcid" = 1 ]; then
		pstatus green YES 'CPU supports INVPCID, performance impact of PTI will be greatly reduced'
	elif [ "$cpu_pcid" = 1 ]; then
		pstatus green YES 'CPU supports PCID, performance impact of PTI will be reduced'
	else
		pstatus blue NO 'PCID/INVPCID not supported, performance impact of PTI will be significant'
	fi
}

# rogue data cache load aka 'Meltdown' aka 'Variant 3'
check_CVE_2017_5754()
{
	cve='CVE-2017-5754'
	_info "\033[1;34m$cve aka '$(cve2name "$cve")'\033[0m"
	if [ "$os" = Linux ]; then
		check_CVE_2017_5754_linux
	elif echo "$os" | grep -q BSD; then
		check_CVE_2017_5754_bsd
	else
		_warn "Unsupported OS ($os)"
	fi
}

check_CVE_2017_5754_linux()
{
	status=UNK
	sys_interface_available=0
	msg=''
	if sys_interface_check "/sys/devices/system/cpu/vulnerabilities/meltdown"; then
		# this kernel has the /sys interface, trust it over everything
		sys_interface_available=1
	fi
	if [ "$opt_sysfs_only" != 1 ]; then
		_info_nol "* Kernel supports Page Table Isolation (PTI): "
		kpti_support=''
		kpti_can_tell=0
		if [ -n "$opt_config" ]; then
			kpti_can_tell=1
			kpti_support=$(grep -w -e CONFIG_PAGE_TABLE_ISOLATION=y -e CONFIG_KAISER=y -e CONFIG_UNMAP_KERNEL_AT_EL0=y "$opt_config")
			if [ -n "$kpti_support" ]; then
				_debug "kpti_support: found option '$kpti_support' in $opt_config"
			fi
		fi
		if [ -z "$kpti_support" ] && [ -n "$opt_map" ]; then
			# it's not an elif: some backports don't have the PTI config but still include the patch
			# so we try to find an exported symbol that is part of the PTI patch in System.map
			# parse_kpti: arm
			kpti_can_tell=1
			kpti_support=$(grep -w -e kpti_force_enabled -e parse_kpti "$opt_map")
			if [ -n "$kpti_support" ]; then
				_debug "kpti_support: found '$kpti_support' in $opt_map"
			fi
		fi
		if [ -z "$kpti_support" ] && [ -n "$kernel" ]; then
			# same as above but in case we don't have System.map and only kernel, look for the
			# nopti option that is part of the patch (kernel command line option)
			# 'kpti=': arm
			kpti_can_tell=1
			if ! which "${opt_arch_prefix}strings" >/dev/null 2>&1; then
				pstatus yellow UNKNOWN "missing '${opt_arch_prefix}strings' tool, please install it, usually it's in the binutils package"
			else
				kpti_support=$("${opt_arch_prefix}strings" "$kernel" | grep -w -e nopti -e kpti=)
				if [ -n "$kpti_support" ]; then
					_debug "kpti_support: found '$kpti_support' in $kernel"
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
		_info_nol "  * PTI enabled and active: "
		if [ "$opt_live" = 1 ]; then
			dmesg_grep="Kernel/User page tables isolation: enabled"
			dmesg_grep="$dmesg_grep|Kernel page table isolation enabled"
			dmesg_grep="$dmesg_grep|x86/pti: Unmapping kernel while in userspace"
			# aarch64
			dmesg_grep="$dmesg_grep|CPU features: detected( feature)?: Kernel page table isolation \(KPTI\)"
			if grep ^flags "$procfs/cpuinfo" | grep -qw pti; then
				# vanilla PTI patch sets the 'pti' flag in cpuinfo
				_debug "kpti_enabled: found 'pti' flag in $procfs/cpuinfo"
				kpti_enabled=1
			elif grep ^flags "$procfs/cpuinfo" | grep -qw kaiser; then
				# kernel line 4.9 sets the 'kaiser' flag in cpuinfo
				_debug "kpti_enabled: found 'kaiser' flag in $procfs/cpuinfo"
				kpti_enabled=1
			elif [ -e /sys/kernel/debug/x86/pti_enabled ]; then
				# Red Hat Backport creates a dedicated file, see https://access.redhat.com/articles/3311301
				kpti_enabled=$(cat /sys/kernel/debug/x86/pti_enabled 2>/dev/null)
				_debug "kpti_enabled: file /sys/kernel/debug/x86/pti_enabled exists and says: $kpti_enabled"
			fi
			if [ -z "$kpti_enabled" ]; then
				dmesg_grep "$dmesg_grep"; ret=$?
				if [ $ret -eq 0 ]; then
					_debug "kpti_enabled: found hint in dmesg: $dmesg_grepped"
					kpti_enabled=1
				elif [ $ret -eq 2 ]; then
					_debug "kpti_enabled: dmesg truncated"
					kpti_enabled=-1
				fi
			fi
			if [ -z "$kpti_enabled" ]; then
				_debug "kpti_enabled: couldn't find any hint that PTI is enabled"
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
	if [ -d "$procfs/xen" ]; then
		# XXX do we have a better way that relying on dmesg?
		dmesg_grep 'Booting paravirtualized kernel on Xen$'; ret=$?
		if [ $ret -eq 2 ]; then
			_warn "dmesg truncated, Xen detection will be unreliable. Please reboot and relaunch this script"
		elif [ $ret -eq 0 ]; then
			if [ -e "$procfs/xen/capabilities" ] && grep -q "control_d" "$procfs/xen/capabilities"; then
				xen_pv_domo=1
			else
				xen_pv_domu=1
			fi
			# PVHVM guests also print 'Booting paravirtualized kernel', so we need this check.
			dmesg_grep 'Xen HVM callback vector for event delivery is enabled$'; ret=$?
			if [ $ret -eq 0 ]; then
				xen_pv_domu=0
			fi
		fi
	fi

	if [ "$opt_live" = 1 ]; then
		# checking whether we're running under Xen PV 64 bits. If yes, we are affected by variant3
		# (unless we are a Dom0)
		_info_nol "* Running as a Xen PV DomU: "
		if [ "$xen_pv_domu" = 1 ]; then
			pstatus yellow YES
		else
			pstatus blue NO
		fi
	fi

	if ! is_cpu_vulnerable "$cve"; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	elif [ -z "$msg" ]; then
		# if msg is empty, sysfs check didn't fill it, rely on our own test
		if [ "$opt_live" = 1 ]; then
			if [ "$kpti_enabled" = 1 ]; then
				pvulnstatus $cve OK "PTI mitigates the vulnerability"
			elif [ "$xen_pv_domo" = 1 ]; then
				pvulnstatus $cve OK "Xen Dom0s are safe and do not require PTI"
			elif [ "$xen_pv_domu" = 1 ]; then
				pvulnstatus $cve VULN "Xen PV DomUs are vulnerable and need to be run in HVM, PVHVM, PVH mode, or the Xen hypervisor must have the Xen's own PTI patch"
				explain "Go to https://blog.xenproject.org/2018/01/22/xen-project-spectre-meltdown-faq-jan-22-update/ for more information"
			elif [ "$kpti_enabled" = -1 ]; then
				pvulnstatus $cve UNK "couldn't find any clue of PTI activation due to a truncated dmesg, please reboot and relaunch this script"
			else
				pvulnstatus $cve VULN "PTI is needed to mitigate the vulnerability"
				if [ -n "$kpti_support" ]; then
					if [ -e "/sys/kernel/debug/x86/pti_enabled" ]; then
						explain "Your kernel supports PTI but it's disabled, you can enable it with \`echo 1 > /sys/kernel/debug/x86/pti_enabled\`"
					elif grep -q -w -e nopti -e pti=off "$procfs/cmdline"; then
						explain "Your kernel supports PTI but it has been disabled on command-line, remove the nopti or pti=off option from your bootloader configuration"
					else
						explain "Your kernel supports PTI but it has been disabled, check \`dmesg\` right after boot to find clues why the system disabled it"
					fi
				else
					explain "If you're using a distro kernel, upgrade your distro to get the latest kernel available. Otherwise, recompile the kernel with the CONFIG_PAGE_TABLE_ISOLATION option (named CONFIG_KAISER for some kernels), or the CONFIG_UNMAP_KERNEL_AT_EL0 option (for ARM64)"
				fi
			fi
		else
			if [ -n "$kpti_support" ]; then
				pvulnstatus $cve OK "offline mode: PTI will mitigate the vulnerability if enabled at runtime"
			elif [ "$kpti_can_tell" = 1 ]; then
				pvulnstatus $cve VULN "PTI is needed to mitigate the vulnerability"
				explain "If you're using a distro kernel, upgrade your distro to get the latest kernel available. Otherwise, recompile the kernel with the CONFIG_PAGE_TABLE_ISOLATION option (named CONFIG_KAISER for some kernels), or the CONFIG_UNMAP_KERNEL_AT_EL0 option (for ARM64)"
			else
				pvulnstatus $cve UNK "offline mode: not enough information"
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
			_explain="Go to https://blog.xenproject.org/2018/01/22/xen-project-spectre-meltdown-faq-jan-22-update/ for more information"
		elif [ "$msg" = "Vulnerable" ]; then
			msg="PTI is needed to mitigate the vulnerability"
			_explain="If you're using a distro kernel, upgrade your distro to get the latest kernel available. Otherwise, recompile the kernel with the CONFIG_PAGE_TABLE_ISOLATION option (named CONFIG_KAISER for some kernels), or the CONFIG_UNMAP_KERNEL_AT_EL0 option (for ARM64)"
		fi
		pvulnstatus $cve "$status" "$msg"
		[ -z "$_explain" ] && [ "$msg" = "Vulnerable" ] && _explain="If you're using a distro kernel, upgrade your distro to get the latest kernel available. Otherwise, recompile the kernel with the CONFIG_PAGE_TABLE_ISOLATION option (named CONFIG_KAISER for some kernels), or the CONFIG_UNMAP_KERNEL_AT_EL0 option (for ARM64)"
		[ -n "$_explain" ] && explain "$_explain"
		unset _explain
	fi

	# Warn the user about XSA-254 recommended mitigations
	if [ "$xen_pv_domo" = 1 ]; then
		_warn
		_warn "This host is a Xen Dom0. Please make sure that you are running your DomUs"
		_warn "in HVM, PVHVM or PVH mode to prevent any guest-to-host / host-to-guest attacks."
		_warn
		_warn "See https://blog.xenproject.org/2018/01/22/xen-project-spectre-meltdown-faq-jan-22-update/ and XSA-254 for details."
	fi
}

check_CVE_2017_5754_bsd()
{
	_info_nol "* Kernel supports Page Table Isolation (PTI): "
	kpti_enabled=$(sysctl -n vm.pmap.pti 2>/dev/null)
	if [ -z "$kpti_enabled" ]; then
		pstatus yellow NO
	else
		pstatus green YES
	fi

	_info_nol "  * PTI enabled and active: "
	if [ "$kpti_enabled" = 1 ]; then
		pstatus green YES
	else
		pstatus yellow NO
	fi

	pti_performance_check

	if ! is_cpu_vulnerable "$cve"; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	elif [ "$kpti_enabled" = 1 ]; then
		pvulnstatus $cve OK "PTI mitigates the vulnerability"
	elif [ -n "$kpti_enabled" ]; then
		pvulnstatus $cve VULN "PTI is supported but disabled on your system"
	else
		pvulnstatus $cve VULN "PTI is needed to mitigate the vulnerability"
	fi
}

####################
# VARIANT 3A SECTION

# rogue system register read aka 'Variant 3a'
check_CVE_2018_3640()
{
	cve='CVE-2018-3640'
	_info "\033[1;34m$cve aka '$(cve2name "$cve")'\033[0m"

	status=UNK
	sys_interface_available=0
	msg=''

	_info_nol "* CPU microcode mitigates the vulnerability: "
	if [ -n "$cpuid_ssbd" ]; then
		# microcodes that ship with SSBD are known to also fix variant3a
		# there is no specific cpuid bit as far as we know
		pstatus green YES
	else
		pstatus yellow NO
	fi

	if ! is_cpu_vulnerable "$cve"; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	elif [ -n "$cpuid_ssbd" ]; then
		pvulnstatus $cve OK "your CPU microcode mitigates the vulnerability"
	else
		pvulnstatus $cve VULN "an up-to-date CPU microcode is needed to mitigate this vulnerability"
		explain "The microcode of your CPU needs to be upgraded to mitigate this vulnerability. This is usually done at boot time by your kernel (the upgrade is not persistent across reboots which is why it's done at each boot). If you're using a distro, make sure you are up to date, as microcode updates are usually shipped alongside with the distro kernel. Availability of a microcode update for you CPU model depends on your CPU vendor. You can usually find out online if a microcode update is available for your CPU by searching for your CPUID (indicated in the Hardware Check section). The microcode update is enough, there is no additional OS, kernel or software change needed."
	fi
}

###################
# VARIANT 4 SECTION

# speculative store bypass aka 'Variant 4'
check_CVE_2018_3639()
{
	cve='CVE-2018-3639'
	_info "\033[1;34m$cve aka '$(cve2name "$cve")'\033[0m"
	if [ "$os" = Linux ]; then
		check_CVE_2018_3639_linux
	elif echo "$os" | grep -q BSD; then
		check_CVE_2018_3639_bsd
	else
		_warn "Unsupported OS ($os)"
	fi
}

check_CVE_2018_3639_linux()
{
	status=UNK
	sys_interface_available=0
	msg=''
	if sys_interface_check "/sys/devices/system/cpu/vulnerabilities/spec_store_bypass"; then
		# this kernel has the /sys interface, trust it over everything
		sys_interface_available=1
	fi
	if [ "$opt_sysfs_only" != 1 ]; then
		_info_nol "* Kernel supports speculation store bypass: "
		if [ "$opt_live" = 1 ]; then
			if grep -Eq 'Speculation.?Store.?Bypass:' "$procfs/self/status" 2>/dev/null; then
				kernel_ssb="found in $procfs/self/status"
				_debug "found Speculation.Store.Bypass: in $procfs/self/status"
			fi
		fi
		if [ -z "$kernel_ssb" ] && [ -n "$kernel" ]; then
			kernel_ssb=$("${opt_arch_prefix}strings" "$kernel" | grep spec_store_bypass | head -n1);
			[ -n "$kernel_ssb" ] && _debug "found $kernel_ssb in kernel"
		fi
		if [ -z "$kernel_ssb" ] && [ -n "$opt_map" ]; then
			kernel_ssb=$(grep spec_store_bypass "$opt_map" | head -n1)
			[ -n "$kernel_ssb" ] && _debug "found $kernel_ssb in System.map"
		fi

		if [ -n "$kernel_ssb" ]; then
			pstatus green YES "$kernel_ssb"
		else
			pstatus yellow NO
		fi

	elif [ "$sys_interface_available" = 0 ]; then
		# we have no sysfs but were asked to use it only!
		msg="/sys vulnerability interface use forced, but it's not available!"
		status=UNK
	fi

	if ! is_cpu_vulnerable "$cve"; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	elif [ -z "$msg" ] || [ "$msg" = "Vulnerable" ]; then
		# if msg is empty, sysfs check didn't fill it, rely on our own test
		if [ -n "$cpuid_ssbd" ]; then
			if [ -n "$kernel_ssb" ]; then
				pvulnstatus $cve OK "your system provides the necessary tools for software mitigation"
			else
				pvulnstatus $cve VULN "your kernel needs to be updated"
				explain "You have a recent-enough CPU microcode but your kernel is too old to use the new features exported by your CPU's microcode. If you're using a distro kernel, upgrade your distro to get the latest kernel available. Otherwise, recompile the kernel from recent-enough sources."
			fi
		else
			if [ -n "$kernel_ssb" ]; then
				pvulnstatus $cve VULN "Your CPU doesn't support SSBD"
				explain "Your kernel is recent enough to use the CPU microcode features for mitigation, but your CPU microcode doesn't actually provide the necessary features for the kernel to use. The microcode of your CPU hence needs to be upgraded. This is usually done at boot time by your kernel (the upgrade is not persistent across reboots which is why it's done at each boot). If you're using a distro, make sure you are up to date, as microcode updates are usually shipped alongside with the distro kernel. Availability of a microcode update for you CPU model depends on your CPU vendor. You can usually find out online if a microcode update is available for your CPU by searching for your CPUID (indicated in the Hardware Check section)."
			else
				pvulnstatus $cve VULN "Neither your CPU nor your kernel support SSBD"
				explain "Both your CPU microcode and your kernel are lacking support for mitigation. If you're using a distro kernel, upgrade your distro to get the latest kernel available. Otherwise, recompile the kernel from recent-enough sources. The microcode of your CPU also needs to be upgraded. This is usually done at boot time by your kernel (the upgrade is not persistent across reboots which is why it's done at each boot). If you're using a distro, make sure you are up to date, as microcode updates are usually shipped alongside with the distro kernel. Availability of a microcode update for you CPU model depends on your CPU vendor. You can usually find out online if a microcode update is available for your CPU by searching for your CPUID (indicated in the Hardware Check section)."
			fi
		fi
	else
		pvulnstatus $cve "$status" "$msg"
	fi
}

check_CVE_2018_3639_bsd()
{
	_info_nol "* Kernel supports speculation store bypass: "
	if sysctl hw.spec_store_bypass_disable >/dev/null 2>&1; then
		kernel_ssb=1
		pstatus green YES
	else
		kernel_ssb=0
		pstatus yellow NO
	fi

	_info_nol "* Speculation store bypass is administratively enabled: "
	ssb_enabled=$(sysctl -n hw.spec_store_bypass_disable 2>/dev/null)
	_debug "hw.spec_store_bypass_disable=$ssb_enabled"
	case "$ssb_enabled" in
		0) pstatus yellow NO "disabled";;
		1) pstatus green YES "enabled";;
		2) pstatus green YES "auto mode";;
		*) pstatus yellow NO "unavailable";;
	esac

	_info_nol "* Speculation store bypass is currently active: "
	ssb_active=$(sysctl -n hw.spec_store_bypass_disable_active 2>/dev/null)
	_debug "hw.spec_store_bypass_disable_active=$ssb_active"
	case "$ssb_active" in
		1) pstatus green YES;;
		*) pstatus yellow NO;;
	esac

	if ! is_cpu_vulnerable "$cve"; then
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	else
		if [ "$ssb_active" = 1 ]; then
				pvulnstatus $cve OK "SSBD mitigates the vulnerability"
		elif [ -n "$cpuid_ssbd" ]; then
			if [ "$kernel_ssb" = 1 ]; then
				pvulnstatus $cve VULN "you need to enable ssbd through sysctl to mitigate the vulnerability"
			else
				pvulnstatus $cve VULN "your kernel needs to be updated"
			fi
		else
			if [ "$kernel_ssb" = 1 ]; then
				pvulnstatus $cve VULN "Your CPU doesn't support SSBD"
			else
				pvulnstatus $cve VULN "Neither your CPU nor your kernel support SSBD"
			fi
		fi
	fi
}

###########################
# L1TF / FORESHADOW SECTION

# L1 terminal fault (SGX) aka 'Foreshadow'
check_CVE_2018_3615()
{
	cve='CVE-2018-3615'
	_info "\033[1;34m$cve aka '$(cve2name "$cve")'\033[0m"

	_info_nol "* CPU microcode mitigates the vulnerability: "
	if [ "$cpu_flush_cmd" = 1 ] && [ "$cpuid_sgx" = 1 ]; then
		# no easy way to detect a fixed SGX but we know that
		# microcodes that have the FLUSH_CMD MSR also have the
		# fixed SGX (for CPUs that support it)
		pstatus green YES
	elif [ "$cpuid_sgx" = 1 ]; then
		pstatus red NO
	else
		pstatus blue N/A
	fi

	if ! is_cpu_vulnerable "$cve"; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	elif [ "$cpu_flush_cmd" = 1 ]; then
		pvulnstatus $cve OK "your CPU microcode mitigates the vulnerability"
	else
		pvulnstatus $cve VULN "your CPU supports SGX and the microcode is not up to date"
	fi
}

# L1 terminal fault (OS) aka 'Foreshadow-NG (OS)'
check_CVE_2018_3620()
{
	cve='CVE-2018-3620'
	_info "\033[1;34m$cve aka '$(cve2name "$cve")'\033[0m"
	if [ "$os" = Linux ]; then
		check_CVE_2018_3620_linux
	elif echo "$os" | grep -q BSD; then
		check_CVE_2018_3620_bsd
	else
		_warn "Unsupported OS ($os)"
	fi
}

check_CVE_2018_3620_linux()
{
	status=UNK
	sys_interface_available=0
	msg=''
	if sys_interface_check "/sys/devices/system/cpu/vulnerabilities/l1tf" '^[^;]+'; then
		# this kernel has the /sys interface, trust it over everything
		sys_interface_available=1
	fi
	if [ "$opt_sysfs_only" != 1 ]; then
		_info_nol "* Kernel supports PTE inversion: "
		if ! which "${opt_arch_prefix}strings" >/dev/null 2>&1; then
			pteinv_supported=-1
		else
			if "${opt_arch_prefix}strings" "$kernel" | grep -Fq 'PTE Inversion'; then
				pstatus green YES "found in kernel image"
				_debug "pteinv: found pte inversion evidence in kernel image"
				pteinv_supported=1
			else
				pstatus yellow NO
				pteinv_supported=0
			fi
		fi

		_info_nol "* PTE inversion enabled and active: "
		if [ "$opt_live" = 1 ]; then
			if [ "$sys_interface_available" = 1 ]; then
				if grep -q 'Mitigation: PTE Inversion' /sys/devices/system/cpu/vulnerabilities/l1tf; then
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

	if ! is_cpu_vulnerable "$cve"; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	elif [ -z "$msg" ]; then
		# if msg is empty, sysfs check didn't fill it, rely on our own test
		if [ "$pteinv_supported" = 1 ]; then
			if [ "$pteinv_active" = 1 ] || [ "$opt_live" != 1 ]; then
				pvulnstatus $cve OK "PTE inversion mitigates the vunerability"
			else
				pvulnstatus $cve VULN "Your kernel supports PTE inversion but it doesn't seem to be enabled"
			fi
		else
			pvulnstatus $cve VULN "Your kernel doesn't support PTE inversion, update it"
		fi
	else
		pvulnstatus $cve "$status" "$msg"
	fi
}

check_CVE_2018_3620_bsd()
{
	_info_nol "* Kernel reserved the memory page at physical address 0x0: "
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

	if ! is_cpu_vulnerable "$cve"; then
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	else
		if [ "$bsd_zero_reserved" = 1 ]; then
			pvulnstatus $cve OK "kernel mitigates the vulnerability"
		else
			pvulnstatus $cve VULN "your kernel needs to be updated"
		fi
	fi
}

# L1TF VMM
check_CVE_2018_3646()
{
	cve='CVE-2018-3646'
	_info "\033[1;34m$cve aka '$(cve2name "$cve")'\033[0m"
	if [ "$os" = Linux ]; then
		check_CVE_2018_3646_linux
	elif echo "$os" | grep -q BSD; then
		check_CVE_2018_3646_bsd
	else
		_warn "Unsupported OS ($os)"
	fi
}

check_CVE_2018_3646_linux()
{
	status=UNK
	sys_interface_available=0
	msg=''
	if sys_interface_check "/sys/devices/system/cpu/vulnerabilities/l1tf" 'VMX:.*' silent; then
		# this kernel has the /sys interface, trust it over everything
		sys_interface_available=1
	fi
	if [ "$opt_sysfs_only" != 1 ]; then
		_info_nol "* This system is a host running a hypervisor: "
		has_vmm=$opt_vmm
		if [ "$has_vmm" = -1 ]; then
			# Assumed to be running on bare metal unless evidence of vm is found.
			has_vmm=0
			# test for presence of hypervisor flag - definitive if set
			if [ -e "$procfs/cpuinfo" ] && grep ^flags "$procfs/cpuinfo" | grep -qw hypervisor; then
				has_vmm=1
				_debug "hypervisor: present - hypervisor flag set in $procfs/cpuinfo"
			else
				_debug "hypervisor: unknown - hypervisor flag not set in $procfs/cpuinfo"
			fi
			# test for kernel detected hypervisor
			dmesg_grep "Hypervisor detected:" ; ret=$?
			if [ $ret -eq 0 ]; then
				_debug "hypervisor: present - found in dmesg: $dmesg_grepped"
				has_vmm=1
			elif [ $ret -eq 2 ]; then
				_debug "hypervisor: dmesg truncated"
			fi
			# test for kernel detected paravirtualization 
			dmesg_grep "Booting paravirtualized kernel on bare hardware" ; ret=$?
			if [ $ret -eq 0 ]; then
				_debug "hypervisor: not present (bare hardware)- found in dmesg: $dmesg_grepped"
			elif [ $ret -eq 2 ]; then
				_debug "hypervisor: dmesg truncated"
			else
				dmesg_grep "Booting paravirtualized kernel on" ; ret=$?
				if [ $ret -eq 0 ]; then
					_debug "hypervisor: present - found in dmesg: $dmesg_grepped"
					has_vmm=1
				elif [ $ret -eq 2 ]; then
					_debug "hypervisor: dmesg truncated"
				fi
			fi
		fi
		if [ "$has_vmm" = 0 ]; then
			if [ "$opt_vmm" != -1 ]; then
				pstatus green NO "forced from command line"
			else
				pstatus green NO
			fi
		else
			if [ "$opt_vmm" != -1 ]; then
				pstatus blue YES "forced from command line"
			else
				pstatus blue YES
			fi
		fi

		_info "* Mitigation 1 (KVM)"
		_info_nol "  * EPT is disabled: "
		if [ "$opt_live" = 1 ]; then
			if ! [ -r /sys/module/kvm_intel/parameters/ept ]; then
				pstatus blue N/A "the kvm_intel module is not loaded"
			elif [ "$(cat /sys/module/kvm_intel/parameters/ept)" = N ]; then
				pstatus green YES
				ept_disabled=1
			else
				pstatus yellow NO
			fi
		else
			pstatus blue N/A "not testable in offline mode"
		fi

		_info "* Mitigation 2"
		_info_nol "  * L1D flush is supported by kernel: "
		if [ "$opt_live" = 1 ] && grep -qw flush_l1d "$procfs/cpuinfo"; then
			l1d_kernel="found flush_l1d in $procfs/cpuinfo"
		fi
		if [ -z "$l1d_kernel" ]; then
			if ! which "${opt_arch_prefix}strings" >/dev/null 2>&1; then
				l1d_kernel_err="missing '${opt_arch_prefix}strings' tool, please install it, usually it's in the binutils package"
			elif [ -n "$kernel_err" ]; then
				l1d_kernel_err="$kernel_err"
			elif "${opt_arch_prefix}strings" "$kernel" | grep -qw flush_l1d; then
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

		_info_nol "  * L1D flush enabled: "
		if [ "$opt_live" = 1 ]; then
			if [ -r "/sys/devices/system/cpu/vulnerabilities/l1tf" ]; then
				# vanilla: VMX: $l1dstatus, SMT $smtstatus
				# Red Hat: VMX: SMT $smtstatus, L1D $l1dstatus
				# $l1dstatus is one of (auto|vulnerable|conditional cache flushes|cache flushes|EPT disabled|flush not necessary)
				# $smtstatus is one of (vulnerable|disabled)
				if grep -Eq '(VMX:|L1D) (EPT disabled|vulnerable|flush not necessary)' "/sys/devices/system/cpu/vulnerabilities/l1tf"; then
					l1d_mode=0
					pstatus yellow NO
				elif grep -Eq '(VMX:|L1D) conditional cache flushes' "/sys/devices/system/cpu/vulnerabilities/l1tf"; then
					l1d_mode=1
					pstatus green YES "conditional flushes"
				elif grep -Eq '(VMX:|L1D) cache flushes' "/sys/devices/system/cpu/vulnerabilities/l1tf"; then
					l1d_mode=2
					pstatus green YES "unconditional flushes"
				else
					l1d_mode=-1
					pstatus yellow UNKNOWN "unrecognized mode"
				fi
			else
				l1d_mode=-1
				pstatus yellow UNKNOWN "can't find or read /sys/devices/system/cpu/vulnerabilities/l1tf"
			fi
		else
			l1d_mode=-1
			pstatus blue N/A "not testable in offline mode"
		fi

		_info_nol "  * Hardware-backed L1D flush supported: "
		if [ "$opt_live" = 1 ]; then
			if grep -qw flush_l1d "$procfs/cpuinfo"; then
				pstatus green YES "performance impact of the mitigation will be greatly reduced"
			else
				pstatus blue NO "flush will be done in software, this is slower"
			fi
		else
			pstatus blue N/A "not testable in offline mode"
		fi

		_info_nol "  * Hyper-Threading (SMT) is enabled: "
		is_cpu_smt_enabled; smt_enabled=$?
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

	if ! is_cpu_vulnerable "$cve"; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	elif [ "$has_vmm" = 0 ]; then
		pvulnstatus $cve OK "this system is not running a hypervisor"
	else
		if [ "$ept_disabled" = 1 ]; then
			pvulnstatus $cve OK "EPT is disabled which mitigates the vulnerability"
		elif [ "$opt_paranoid" = 0 ]; then
			if [ "$l1d_mode" -ge 1 ]; then
				pvulnstatus $cve OK "L1D flushing is enabled and mitigates the vulnerability"
			else
				pvulnstatus $cve VULN "disable EPT or enabled L1D flushing to mitigate the vulnerability"
			fi
		else
			if [ "$l1d_mode" -ge 2 ]; then
				if [ "$smt_enabled" = 1 ]; then
					pvulnstatus $cve OK "L1D unconditional flushing and Hyper-Threading disabled are mitigating the vulnerability"
				else
					pvulnstatus $cve VULN "Hyper-Threading must be disabled to fully mitigate the vulnerability"
				fi
			else
				if [ "$smt_enabled" = 1 ]; then
					pvulnstatus $cve VULN "L1D unconditional flushing should be enabled to fully mitigate the vulnerability"
				else
					pvulnstatus $cve VULN "enable L1D unconditional flushing and disable Hyper-Threading to fully mitigate the vulnerability"
				fi
			fi
		fi
	fi
}

check_CVE_2018_3646_bsd()
{
	_info_nol "* Kernel supports L1D flushing: "
	if sysctl hw.vmm.vmx.l1d_flush >/dev/null 2>&1; then
		pstatus green YES
		kernel_l1d_supported=1
	else
		pstatus yellow NO
		kernel_l1d_supported=0
	fi

	_info_nol "* L1D flushing is enabled: "
	kernel_l1d_enabled=$(sysctl -n hw.vmm.vmx.l1d_flush 2>/dev/null)
	case "$kernel_l1d_enabled" in
		0) pstatus yellow NO;;
		1) pstatus green YES;;
		"") pstatus yellow NO;;
		*) pstatus yellow UNKNOWN;;
	esac

	if ! is_cpu_vulnerable "$cve"; then
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	else
		if [ "$kernel_l1d_enabled" = 1 ]; then
			pvulnstatus $cve OK "L1D flushing mitigates the vulnerability"
		elif [ "$kernel_l1d_supported" = 1 ]; then
			pvulnstatus $cve VULN "L1D flushing is supported by your kernel but is disabled"
		else
			pvulnstatus $cve VULN "your kernel needs to be updated"
		fi
	fi
}

if [ "$opt_no_hw" = 0 ] && [ -z "$opt_arch_prefix" ]; then
	check_cpu
	check_cpu_vulnerabilities
	_info
fi

# now run the checks the user asked for
for cve in $supported_cve_list
do
	if [ "$opt_cve_all" = 1 ] || echo "$opt_cve_list" | grep -qw "$cve"; then
		check_"$(echo "$cve" | tr - _)"
		_info
	fi
done

if [ -n "$final_summary" ]; then
	_info "> \033[46m\033[30mSUMMARY:\033[0m$final_summary"
	_info ""
fi

if [ "$bad_accuracy" = 1 ]; then
	_warn "We're missing some kernel info (see -v), accuracy might be reduced"
fi

_vars=$(set | grep -Ev '^[A-Z_[:space:]]' | sort | tr "\n" '|')
_debug "variables at end of script: $_vars"

if [ "$opt_explain" = 0 ]; then
	_info "Need more detailed information about mitigation options? Use --explain"
fi

_info "A false sense of security is worse than no security at all, see --disclaimer"

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "nrpe" ]; then
	if [ -n "$nrpe_vuln" ]; then
		echo "Vulnerable:$nrpe_vuln"
	else
		echo "OK"
	fi
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "short" ]; then
	_echo 0 "${short_output% }"
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "json" ]; then
	_echo 0 "${json_output%?}]"
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "prometheus" ]; then
	echo "# TYPE specex_vuln_status untyped"
	echo "# HELP specex_vuln_status Exposure of system to speculative execution vulnerabilities"
	printf "%b\n" "$prometheus_output"
fi

# exit with the proper exit code
[ "$global_critical" = 1 ] && exit 2  # critical
[ "$global_unknown"  = 1 ] && exit 3  # unknown
exit 0  # ok

# We're using MCE.db from the excellent platomav's MCExtractor project
# The builtin version follows, the user can update it with --update-mcedb

# wget https://github.com/platomav/MCExtractor/raw/master/MCE.db
# sqlite3 MCE.db "select '%%% MCEDB v'||revision||' - '||strftime('%Y/%m/%d', date, 'unixepoch') from MCE; select '# I,0x'||cpuid||',0x'||version||','||max(yyyymmdd) from Intel group by cpuid order by cpuid asc; select '# A,0x'||cpuid||',0x'||version||','||max(yyyymmdd) from AMD group by cpuid order by cpuid asc"
# %%% MCEDB v84 - 2018/09/27
# I,0x00000611,0x00000B27,19961218
# I,0x00000612,0x000000C6,19961210
# I,0x00000616,0x000000C6,19961210
# I,0x00000617,0x000000C6,19961210
# I,0x00000619,0x000000D2,19980218
# I,0x00000630,0x00000013,19960827
# I,0x00000632,0x00000020,19960903
# I,0x00000633,0x00000036,19980923
# I,0x00000634,0x00000037,19980923
# I,0x00000650,0x00000040,19990525
# I,0x00000651,0x00000040,19990525
# I,0x00000652,0x0000002D,19990518
# I,0x00000653,0x00000010,19990628
# I,0x00000660,0x0000000A,19990505
# I,0x00000665,0x00000003,19990505
# I,0x0000066A,0x0000000C,19990505
# I,0x0000066D,0x00000007,19990505
# I,0x00000670,0x00000007,19980602
# I,0x00000671,0x00000003,19980811
# I,0x00000672,0x00000010,19990922
# I,0x00000673,0x0000000E,19990910
# I,0x00000680,0x00000014,19990610
# I,0x00000681,0x00000014,19991209
# I,0x00000683,0x00000013,20010206
# I,0x00000686,0x00000007,20000505
# I,0x0000068A,0x00000004,20001207
# I,0x00000690,0x00000004,20000206
# I,0x00000691,0x00000001,20020527
# I,0x00000692,0x00000001,20020620
# I,0x00000694,0x00000002,20020926
# I,0x00000695,0x00000007,20041109
# I,0x00000696,0x00000001,20000707
# I,0x000006A0,0x00000003,20000110
# I,0x000006A1,0x00000001,20000306
# I,0x000006A4,0x00000001,20000616
# I,0x000006B0,0x0000001A,20010129
# I,0x000006B1,0x0000001D,20010220
# I,0x000006B4,0x00000002,20020111
# I,0x000006D0,0x00000006,20030522
# I,0x000006D1,0x00000009,20030709
# I,0x000006D2,0x00000010,20030814
# I,0x000006D6,0x00000018,20041017
# I,0x000006D8,0x00000021,20060831
# I,0x000006E0,0x00000008,20050215
# I,0x000006E1,0x0000000C,20050413
# I,0x000006E4,0x00000026,20050816
# I,0x000006E8,0x0000003C,20060208
# I,0x000006EC,0x0000005B,20070208
# I,0x000006F0,0x00000005,20050818
# I,0x000006F1,0x00000012,20051129
# I,0x000006F2,0x0000005D,20101002
# I,0x000006F4,0x00000028,20060417
# I,0x000006F5,0x00000039,20060727
# I,0x000006F6,0x000000D2,20101001
# I,0x000006F7,0x0000006A,20101002
# I,0x000006F9,0x00000084,20061012
# I,0x000006FA,0x00000095,20101002
# I,0x000006FB,0x000000C1,20111004
# I,0x000006FD,0x000000A4,20101002
# I,0x00000F00,0xFFFF0001,20000130
# I,0x00000F01,0xFFFF0007,20000404
# I,0x00000F02,0xFFFF000B,20000518
# I,0x00000F03,0xFFFF0001,20000518
# I,0x00000F04,0xFFFF0010,20000803
# I,0x00000F05,0x0000000B,20000824
# I,0x00000F06,0x00000004,20000911
# I,0x00000F07,0x00000012,20020716
# I,0x00000F08,0x00000008,20001101
# I,0x00000F09,0x00000008,20010104
# I,0x00000F0A,0x00000015,20020821
# I,0x00000F11,0x0000000A,20030729
# I,0x00000F12,0x0000002D,20030502
# I,0x00000F13,0x00000005,20030508
# I,0x00000F20,0x00000001,20010423
# I,0x00000F21,0x00000002,20010529
# I,0x00000F22,0x00000005,20030729
# I,0x00000F23,0x0000000D,20010817
# I,0x00000F24,0x00000021,20030610
# I,0x00000F25,0x0000002C,20040826
# I,0x00000F26,0x00000010,20040805
# I,0x00000F27,0x00000038,20030604
# I,0x00000F29,0x0000002D,20040811
# I,0x00000F30,0x00000013,20030815
# I,0x00000F31,0x0000000B,20031021
# I,0x00000F32,0x0000000A,20040511
# I,0x00000F33,0x0000000C,20050421
# I,0x00000F34,0x00000017,20050421
# I,0x00000F36,0x00000007,20040309
# I,0x00000F37,0x00000003,20031218
# I,0x00000F40,0x00000006,20040318
# I,0x00000F41,0x00000017,20050422
# I,0x00000F42,0x00000003,20050421
# I,0x00000F43,0x00000005,20050421
# I,0x00000F44,0x00000006,20050421
# I,0x00000F46,0x00000004,20050411
# I,0x00000F47,0x00000003,20050421
# I,0x00000F48,0x0000000E,20080115
# I,0x00000F49,0x00000003,20050421
# I,0x00000F4A,0x00000004,20051214
# I,0x00000F60,0x00000005,20050124
# I,0x00000F61,0x00000008,20050610
# I,0x00000F62,0x0000000F,20051215
# I,0x00000F63,0x00000005,20051010
# I,0x00000F64,0x00000004,20051223
# I,0x00000F65,0x0000000B,20070510
# I,0x00000F66,0x0000001B,20060310
# I,0x00000F68,0x00000009,20060714
# I,0x00001632,0x00000002,19980610
# I,0x00010650,0x00000002,20060513
# I,0x00010660,0x00000004,20060612
# I,0x00010661,0x00000043,20101004
# I,0x00010670,0x00000005,20070209
# I,0x00010671,0x00000106,20070329
# I,0x00010674,0x84050100,20070726
# I,0x00010676,0x00000612,20150802
# I,0x00010677,0x0000070D,20150802
# I,0x0001067A,0x00000A0E,20150729
# I,0x000106A0,0xFFFF001A,20071128
# I,0x000106A1,0xFFFF000B,20080220
# I,0x000106A2,0xFFFF0019,20080714
# I,0x000106A4,0x00000013,20150630
# I,0x000106A5,0x0000001D,20180511
# I,0x000106C0,0x00000007,20070824
# I,0x000106C1,0x00000109,20071203
# I,0x000106C2,0x00000217,20090410
# I,0x000106C9,0x00000007,20090213
# I,0x000106CA,0x00000107,20090825
# I,0x000106D0,0x00000005,20071204
# I,0x000106D1,0x0000002A,20150803
# I,0x000106E0,0xFFFF0022,20090116
# I,0x000106E1,0xFFFF000D,20090206
# I,0x000106E3,0xFFFF0011,20090512
# I,0x000106E4,0x00000003,20130701
# I,0x000106E5,0x0000000A,20180508
# I,0x000106F0,0xFFFF0009,20090210
# I,0x000106F1,0xFFFF0007,20090210
# I,0x00020650,0xFFFF0008,20090218
# I,0x00020651,0xFFFF0018,20090818
# I,0x00020652,0x00000011,20180508
# I,0x00020654,0xFFFF0007,20091124
# I,0x00020655,0x00000007,20180423
# I,0x00020661,0x00000105,20110718
# I,0x000206A0,0x00000029,20091102
# I,0x000206A1,0x00000007,20091223
# I,0x000206A2,0x00000027,20100502
# I,0x000206A3,0x00000009,20100609
# I,0x000206A4,0x00000022,20100414
# I,0x000206A5,0x00000007,20100722
# I,0x000206A6,0x90030028,20100924
# I,0x000206A7,0x0000002E,20180410
# I,0x000206C0,0xFFFF001C,20091214
# I,0x000206C1,0x00000006,20091222
# I,0x000206C2,0x0000001F,20180508
# I,0x000206D0,0x80000006,20100816
# I,0x000206D1,0x80000106,20101201
# I,0x000206D2,0x9584020C,20110622
# I,0x000206D3,0x80000304,20110420
# I,0x000206D5,0x00000513,20111013
# I,0x000206D6,0x0000061D,20180508
# I,0x000206D7,0x00000714,20180508
# I,0x000206E0,0xE3493401,20090108
# I,0x000206E1,0xE3493402,20090224
# I,0x000206E2,0xFFFF0004,20081001
# I,0x000206E3,0xE4486547,20090701
# I,0x000206E4,0xFFFF0008,20090619
# I,0x000206E5,0xFFFF0018,20091215
# I,0x000206E6,0x0000000D,20180515
# I,0x000206F0,0x00000004,20100630
# I,0x000206F1,0x00000008,20101013
# I,0x000206F2,0x0000003B,20180516
# I,0x00030650,0x00000009,20120118
# I,0x00030651,0x00000110,20131014
# I,0x00030660,0x00000003,20101103
# I,0x00030661,0x0000010F,20150721
# I,0x00030669,0x0000010D,20130515
# I,0x00030671,0x00000117,20130410
# I,0x00030672,0x0000022E,20140401
# I,0x00030673,0x00000326,20180110
# I,0x00030678,0x00000837,20180125
# I,0x00030679,0x0000090A,20180110
# I,0x000306A0,0x00000007,20110407
# I,0x000306A2,0x0000000C,20110725
# I,0x000306A4,0x00000007,20110908
# I,0x000306A5,0x00000009,20111110
# I,0x000306A6,0x00000004,20111114
# I,0x000306A8,0x00000010,20120220
# I,0x000306A9,0x00000020,20180410
# I,0x000306C0,0xFFFF0013,20111110
# I,0x000306C1,0xFFFF0014,20120725
# I,0x000306C2,0xFFFF0006,20121017
# I,0x000306C3,0x00000025,20180402
# I,0x000306D1,0xFFFF0009,20131015
# I,0x000306D2,0xFFFF0009,20131219
# I,0x000306D3,0xE3121338,20140825
# I,0x000306D4,0x0000002B,20180322
# I,0x000306E0,0x00000008,20120726
# I,0x000306E2,0x0000020D,20130321
# I,0x000306E3,0x00000308,20130321
# I,0x000306E4,0x0000042D,20180425
# I,0x000306E6,0x00000600,20130619
# I,0x000306E7,0x00000714,20180425
# I,0x000306F0,0xFFFF0017,20130730
# I,0x000306F1,0x00000014,20140110
# I,0x000306F2,0x0000003D,20180420
# I,0x000306F3,0x0000000D,20160211
# I,0x000306F4,0x00000012,20180420
# I,0x00040650,0xFFFF000B,20121206
# I,0x00040651,0x00000024,20180402
# I,0x00040660,0xFFFF0011,20121012
# I,0x00040661,0x0000001A,20180402
# I,0x00040670,0xFFFF0006,20140304
# I,0x00040671,0x0000001E,20180403
# I,0x000406A0,0x80124001,20130521
# I,0x000406A8,0x0000081F,20140812
# I,0x000406A9,0x0000081F,20140812
# I,0x000406C1,0x0000010B,20140814
# I,0x000406C2,0x00000221,20150218
# I,0x000406C3,0x00000367,20171225
# I,0x000406C4,0x00000410,20180104
# I,0x000406D0,0x0000000E,20130612
# I,0x000406D8,0x0000012A,20180104
# I,0x000406E1,0x00000020,20141111
# I,0x000406E2,0x0000002C,20150521
# I,0x000406E3,0x000000C6,20180417
# I,0x000406E8,0x00000026,20160414
# I,0x000406F0,0x00000014,20150702
# I,0x000406F1,0x0B00002E,20180419
# I,0x00050650,0x8000002B,20160208
# I,0x00050651,0x8000002B,20160208
# I,0x00050652,0x80000037,20170502
# I,0x00050653,0x01000144,20180420
# I,0x00050654,0x0200004D,20180515
# I,0x00050655,0x0300000B,20180427
# I,0x00050661,0xF1000008,20150130
# I,0x00050662,0x00000017,20180525
# I,0x00050663,0x07000013,20180420
# I,0x00050664,0x0F000012,20180420
# I,0x00050665,0x0E00000A,20180420
# I,0x00050670,0xFFFF0030,20151113
# I,0x00050671,0x000001B6,20180108
# I,0x000506A0,0x00000038,20150112
# I,0x000506C2,0x00000014,20180511
# I,0x000506C8,0x90011010,20160323
# I,0x000506C9,0x00000032,20180511
# I,0x000506CA,0x0000000C,20180511
# I,0x000506D1,0x00000102,20150605
# I,0x000506E0,0x00000018,20141119
# I,0x000506E1,0x0000002A,20150602
# I,0x000506E2,0x0000002E,20150815
# I,0x000506E3,0x000000C6,20180417
# I,0x000506E8,0x00000034,20160710
# I,0x000506F1,0x00000024,20180511
# I,0x00060660,0x0000000C,20160821
# I,0x00060661,0x0000000E,20170128
# I,0x00060662,0x00000022,20171129
# I,0x00060663,0x0000002A,20180417
# I,0x000706A0,0x00000026,20170712
# I,0x000706A1,0x0000002A,20180725
# I,0x00080650,0x00000018,20180108
# I,0x000806E9,0x00000098,20180626
# I,0x000806EA,0x00000096,20180515
# I,0x000806EB,0x00000098,20180530
# I,0x000906E9,0x0000008E,20180324
# I,0x000906EA,0x00000096,20180502
# I,0x000906EB,0x0000008E,20180324
# I,0x000906EC,0x0000009E,20180826
# A,0x00000F00,0x02000008,20070614
# A,0x00000F01,0x0000001C,20021031
# A,0x00000F10,0x00000003,20020325
# A,0x00000F11,0x0000001F,20030220
# A,0x00000F48,0x00000046,20040719
# A,0x00000F4A,0x00000047,20040719
# A,0x00000F50,0x00000024,20021212
# A,0x00000F51,0x00000025,20030115
# A,0x00010F50,0x00000041,20040225
# A,0x00020F10,0x0000004D,20050428
# A,0x00040F01,0xC0012102,20050916
# A,0x00040F0A,0x00000068,20060920
# A,0x00040F13,0x0000007A,20080508
# A,0x00040F14,0x00000062,20060127
# A,0x00040F1B,0x0000006D,20060920
# A,0x00040F33,0x0000007B,20080514
# A,0x00060F80,0x00000083,20060929
# A,0x000C0F1B,0x0000006E,20060921
# A,0x000F0F00,0x00000005,20020627
# A,0x000F0F01,0x00000015,20020627
# A,0x00100F00,0x01000020,20070326
# A,0x00100F20,0x010000CA,20100331
# A,0x00100F22,0x010000C9,20100331
# A,0x00100F40,0x01000085,20080501
# A,0x00100F41,0x010000DB,20111024
# A,0x00100F42,0x01000092,20081021
# A,0x00100F43,0x010000C8,20100311
# A,0x00100F62,0x010000C7,20100311
# A,0x00100F80,0x010000DA,20111024
# A,0x00100F81,0x010000D9,20111012
# A,0x00100FA0,0x010000DC,20111024
# A,0x00120F00,0x03000002,20100324
# A,0x00200F30,0x02000018,20070921
# A,0x00200F31,0x02000057,20080502
# A,0x00200F32,0x02000034,20080307
# A,0x00300F01,0x0300000E,20101004
# A,0x00300F10,0x03000027,20111309
# A,0x00500F00,0x0500000B,20100601
# A,0x00500F01,0x0500001A,20100908
# A,0x00500F10,0x05000029,20130121
# A,0x00500F20,0x05000119,20130118
# A,0x00580F00,0x0500000B,20100601
# A,0x00580F01,0x0500001A,20100908
# A,0x00580F10,0x05000028,20101124
# A,0x00580F20,0x05000101,20110406
# A,0x00600F00,0x06000017,20101029
# A,0x00600F01,0x0600011F,20110227
# A,0x00600F10,0x06000425,20110408
# A,0x00600F11,0x0600050D,20110627
# A,0x00600F12,0x0600063E,20180207
# A,0x00600F20,0x06000852,20180206
# A,0x00610F00,0x0600100E,20111102
# A,0x00610F01,0x0600111F,20180305
# A,0x00630F00,0x0600301C,20130817
# A,0x00630F01,0x06003109,20180227
# A,0x00660F00,0x06006012,20141014
# A,0x00660F01,0x0600611A,20180126
# A,0x00670F00,0x06006705,20180220
# A,0x00680F00,0x06000017,20101029
# A,0x00680F01,0x0600011F,20110227
# A,0x00680F10,0x06000410,20110314
# A,0x00700F00,0x0700002A,20121218
# A,0x00700F01,0x07000110,20180209
# A,0x00730F00,0x07030009,20131206
# A,0x00730F01,0x07030106,20180209
# A,0x00800F00,0x0800002A,20161006
# A,0x00800F10,0x0800100C,20170131
# A,0x00800F11,0x08001137,20180214
# A,0x00800F12,0x08001227,20180209
# A,0x00800F82,0x0800820B,20180620
# A,0x00810F00,0x08100004,20161120
# A,0x00810F10,0x0810100B,20180212
# A,0x00810F80,0x08108002,20180605
# A,0x00820F00,0x08200002,20180214
