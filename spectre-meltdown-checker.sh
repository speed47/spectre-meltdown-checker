#! /bin/sh
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
VERSION='0.37+'

trap 'exit_cleanup' EXIT
trap '_warn "interrupted, cleaning up..."; exit_cleanup; exit 1' INT
exit_cleanup()
{
	# cleanup the temp decompressed config & kernel image
	[ -n "$dumped_config" ] && [ -f "$dumped_config" ] && rm -f "$dumped_config"
	[ -n "$kerneltmp"     ] && [ -f "$kerneltmp"     ] && rm -f "$kerneltmp"
	[ -n "$kerneltmp2"    ] && [ -f "$kerneltmp2"    ] && rm -f "$kerneltmp2"
	[ "$mounted_debugfs" = 1 ] && umount /sys/kernel/debug 2>/dev/null
	[ "$mounted_procfs"  = 1 ] && umount "$procfs" 2>/dev/null
	[ "$insmod_cpuid"    = 1 ] && rmmod cpuid 2>/dev/null
	[ "$insmod_msr"      = 1 ] && rmmod msr 2>/dev/null
	[ "$kldload_cpuctl"  = 1 ] && kldunload cpuctl 2>/dev/null
}

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
		--no-explain		don't produce a human-readable explanation of actions to take to mitigate a vulnerability
		--paranoid		require IBPB to deem Variant 2 as mitigated

		--no-sysfs		don't use the /sys interface even if present [Linux]
		--sysfs-only		only use the /sys interface, don't run our own checks [Linux]
		--coreos		special mode for CoreOS (use an ephemeral toolbox to inspect kernel) [Linux]

		--arch-prefix PREFIX	specify a prefix for cross-inspecting a kernel of a different arch, for example "aarch64-linux-gnu-",
					so that invoked tools will be prefixed with this (i.e. aarch64-linux-gnu-objdump)
		--batch text		produce machine readable output, this is the default if --batch is specified alone
		--batch json		produce JSON output formatted for Puppet, Ansible, Chef...
		--batch nrpe		produce machine readable output formatted for NRPE
		--batch prometheus      produce output for consumption by prometheus-node-exporter

		--variant [1,2,3,3a,4]	specify which variant you'd like to check, by default all variants are checked,
					can be specified multiple times (e.g. --variant 2 --variant 3)
		--hw-only		only check for CPU information, don't check for any variant
		--no-hw			skip CPU information and checks, if you're inspecting a kernel not to be run on this host

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
opt_batch_format="text"
opt_verbose=1
opt_variant1=0
opt_variant2=0
opt_variant3=0
opt_allvariants=1
opt_no_sysfs=0
opt_sysfs_only=0
opt_coreos=0
opt_arch_prefix=''
opt_hw_only=0
opt_no_hw=0
opt_no_explain=0
opt_paranoid=0

global_critical=0
global_unknown=0
nrpe_vuln=""

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
	# which command is broken?
	[ -x /bin/echo        ] && echo_cmd=/bin/echo
	# for Android
	[ -x /system/bin/echo ] && echo_cmd=/system/bin/echo
fi
# still empty ? fallback to builtin
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
	if [ "$opt_no_explain" != 1 ] ; then
		_info ''
		_info "> \033[41m\033[30mHow to fix:\033[0m $*"
	fi
}

is_cpu_vulnerable_cached=0
_is_cpu_vulnerable_cached()
{
	# shellcheck disable=SC2086
	[ "$1" = 1  ] && return $variant1
	# shellcheck disable=SC2086
	[ "$1" = 2  ] && return $variant2
	# shellcheck disable=SC2086
	[ "$1" = 3  ] && return $variant3
	# shellcheck disable=SC2086
	[ "$1" = 3a ] && return $variant3a
	# shellcheck disable=SC2086
	[ "$1" = 4  ] && return $variant4
	echo "$0: error: invalid variant '$1' passed to is_cpu_vulnerable()" >&2
	exit 255
}

is_cpu_vulnerable()
{
	# param: 1, 2, 3, 3a or 4 (variant)
	# returns 0 if vulnerable, 1 if not vulnerable
	# (note that in shell, a return of 0 is success)
	# by default, everything is vulnerable, we work in a "whitelist" logic here.
	# usage: is_cpu_vulnerable 2 && do something if vulnerable
	if [ "$is_cpu_vulnerable_cached" = 1 ]; then
		_is_cpu_vulnerable_cached "$1"
		return $?
	fi

	variant1=''
	variant2=''
	variant3=''
	variant3a=''
	variant4=''

	if is_cpu_specex_free; then
		variant1=immune
		variant2=immune
		variant3=immune
		variant3a=immune
		variant4=immune
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
			variant3=immune
			_debug "is_cpu_vulnerable: RDCL_NO is set so not vuln to meltdown"
		fi
		if [ "$capabilities_ssb_no" = 1 ]; then
			# capability bit for future Intel processor that will explicitly state
			# that they're not vulnerable to Variant 4
			# this var is set in check_cpu()
			variant4=immune
			_debug "is_cpu_vulnerable: SSB_NO is set so not vuln to variant4"
		fi
	elif is_amd; then
		# AMD revised their statement about variant2 => vulnerable
		# https://www.amd.com/en/corporate/speculative-execution
		variant1=vuln
		variant2=vuln
		[ -z "$variant3" ] && variant3=immune
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
				# model R7 R8 A9    A15   A17   A57   A72    A73    A75
				# part   ?  ? 0xc09 0xc0f 0xc0e 0xd07 0xd08  0xd09  0xd0a
				# arch  7? 7? 7     7     7     8     8      8      8
				#
				# variant 1 & variant 2
				if [ "$cpuarch" = 7 ] && echo "$cpupart" | grep -Eq '^0x(c09|c0f|c0e)$'; then
					# armv7 vulnerable chips
					_debug "checking cpu$i: this armv7 vulnerable to spectre 1 & 2"
					variant1=vuln
					variant2=vuln
				elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -Eq '^0x(d07|d08|d09|d0a)$'; then
					# armv8 vulnerable chips
					_debug "checking cpu$i: this armv8 vulnerable to spectre 1 & 2"
					variant1=vuln
					variant2=vuln
				else
					_debug "checking cpu$i: this arm non vulnerable to 1 & 2"
					# others are not vulnerable
					[ -z "$variant1" ] && variant1=immune
					[ -z "$variant2" ] && variant2=immune
				fi

				# for variant3, only A75 is vulnerable
				if [ "$cpuarch" = 8 ] && [ "$cpupart" = 0xd0a ]; then
					_debug "checking cpu$i: arm A75 vulnerable to meltdown"
					variant3=vuln
				else
					_debug "checking cpu$i: this arm non vulnerable to meltdown"
					[ -z "$variant3" ] && variant3=immune
				fi

				# for variant3a, only A15/A57/A72 are vulnerable
				if [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -Eq '^0x(c0f|d07|d0a)$'; then
					_debug "checking cpu$i: arm A15-A57-A72 vulnerable to variant3a"
					variant3a=vuln
				else
					_debug "checking cpu$i: this arm non vulnerable to variant3a"
					[ -z "$variant3a" ] && variant3a=immune
				fi

				# for variant4, only A57-72-73-75 are vulnerable
				if [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -Eq '^0xd0[789a]$'; then
					_debug "checking cpu$i: arm A57-A72-A73-A75 vulnerable to variant4"
					variant4=vuln
				else
					_debug "checking cpu$i: this arm non vulnerable to variant4"
					[ -z "$variant4" ] && variant4=immune
				fi
			fi
			_debug "is_cpu_vulnerable: for cpu$i and so far, we have <$variant1> <$variant2> <$variant3> <$variant3a> <$variant4>"
		done
	fi
	# from the information we have for now, it seems that CPUs that are vulnerable to variant1 are also vulnerable to variant4
	[ -z "$variant4" ] && variant4=$variant1
	_debug "is_cpu_vulnerable: temp results are <$variant1> <$variant2> <$variant3> <$variant3a> <$variant4>"
	# if at least one of the cpu is vulnerable, then the system is vulnerable
	[ "$variant1"  = "immune" ] && variant1=1  || variant1=0
	[ "$variant2"  = "immune" ] && variant2=1  || variant2=0
	[ "$variant3"  = "immune" ] && variant3=1  || variant3=0
	[ "$variant3a" = "immune" ] && variant3a=1 || variant3a=0
	[ "$variant4"  = "immune" ] && variant4=1  || variant4=0
	_debug "is_cpu_vulnerable: final results are <$variant1> <$variant2> <$variant3> <$variant3a> <$variant4>"
	is_cpu_vulnerable_cached=1
	_is_cpu_vulnerable_cached "$1"
	return $?
}

is_cpu_specex_free()
{
	# return true (0) if the CPU doesn't do speculative execution, false (1) if it does.
	# if it's not in the list we know, return false (1).
	# source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/cpu/common.c#n882
	# { X86_VENDOR_INTEL,     6, INTEL_FAM6_ATOM_CEDARVIEW,   X86_FEATURE_ANY },
	# { X86_VENDOR_INTEL,     6, INTEL_FAM6_ATOM_CLOVERVIEW,  X86_FEATURE_ANY },
	# { X86_VENDOR_INTEL,     6, INTEL_FAM6_ATOM_LINCROFT,    X86_FEATURE_ANY },
	# { X86_VENDOR_INTEL,     6, INTEL_FAM6_ATOM_PENWELL,     X86_FEATURE_ANY },
	# { X86_VENDOR_INTEL,     6, INTEL_FAM6_ATOM_PINEVIEW,    X86_FEATURE_ANY },
	# { X86_VENDOR_CENTAUR,   5 },
	# { X86_VENDOR_INTEL,     5 },
	# { X86_VENDOR_NSC,       5 },
	# { X86_VENDOR_ANY,       4 },
	parse_cpu_details
	if is_intel; then
		if [ "$cpu_family" = 6 ]; then
			if [ "$cpu_model" = "$INTEL_FAM6_ATOM_CEDARVIEW"  ]      || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_CLOVERVIEW" ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_LINCROFT"   ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_PENWELL"    ] || \
				[ "$cpu_model" = "$INTEL_FAM6_ATOM_PINEVIEW"   ]; then
				return 0
			fi
		elif [ "$cpu_family" = 5 ]; then
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
		opt_no_explain=1
		shift
	elif [ "$1" = "--batch" ]; then
		opt_batch=1
		opt_verbose=0
		shift
		case "$1" in
			text|nrpe|json|prometheus) opt_batch_format="$1"; shift;;
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
	elif [ "$1" = "--variant" ]; then
		if [ -z "$2" ]; then
			echo "$0: error: option --variant expects a parameter (1, 2 or 3)" >&2
			exit 255
		fi
		case "$2" in
			1)  opt_variant1=1;  opt_allvariants=0;;
			2)  opt_variant2=1;  opt_allvariants=0;;
			3)  opt_variant3=1;  opt_allvariants=0;;
			3a) opt_variant3a=1; opt_allvariants=0;;
			4)  opt_variant4=1;  opt_allvariants=0;;
			*)
				echo "$0: error: invalid parameter '$2' for --variant, expected either 1, 2, 3, 3a or 4" >&2;
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
		esac

		case "$opt_batch_format" in
			text) _echo 0 "$1: $2 ($3)";;
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
		UNK)  pstatus yellow 'UNKNOWN'        "$@";;
		VULN) pstatus red    'VULNERABLE'     "$@";;
		OK)   pstatus green  'NOT VULNERABLE' "$@";;
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
		if ! grep -e msr /proc/modules 2>/dev/null; then
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
		if ! grep -e cpuid /proc/modules 2>/dev/null; then
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
{
EAX=1; EBX=2; ECX=3; EDX=4;
}
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
		# we need _leaf to be converted to decimal for dd
		_leaf=$(( _leaf ))
		_cpuid=$(dd if=/dev/cpu/0/cpuid bs=16 skip="$_leaf" iflag=skip_bytes count=1 2>/dev/null | od -A n -t u4)
	elif [ -e /dev/cpuctl0 ]; then
		# BSD
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
		fi

		cpu_family=$(  grep '^cpu family' "$procfs/cpuinfo" | awk '{print $4}' | grep -E '^[0-9]+$' | head -1)
		cpu_model=$(   grep '^model'      "$procfs/cpuinfo" | awk '{print $3}' | grep -E '^[0-9]+$' | head -1)
		cpu_stepping=$(grep '^stepping'   "$procfs/cpuinfo" | awk '{print $3}' | grep -E '^[0-9]+$' | head -1)
		cpu_ucode=$(  grep '^microcode'   "$procfs/cpuinfo" | awk '{print $3}' | head -1)
	else
		cpu_friendly_name=$(sysctl -n hw.model)
	fi

	# get raw cpuid, it's always useful (referenced in the Intel doc for firmware updates for example)
	if read_cpuid 0x1 $EAX 0 0xFFFFFFFF; then
		cpuid="$read_cpuid_value"
		#cpuid_hex=$(printf "%X" "$cpuid")
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

	echo "$cpu_ucode" | grep -q ^0x && cpu_ucode_decimal=$(( cpu_ucode ))
	ucode_found="model $cpu_model stepping $cpu_stepping ucode $cpu_ucode cpuid "$(printf "0x%x" "$cpuid")

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

	INTEL_FAM6_ATOM_PINEVIEW=$(( 0x1C ))
	INTEL_FAM6_ATOM_LINCROFT=$(( 0x26 ))
	INTEL_FAM6_ATOM_PENWELL=$(( 0x27 ))
	INTEL_FAM6_ATOM_CLOVERVIEW=$(( 0x35 ))
	INTEL_FAM6_ATOM_CEDARVIEW=$(( 0x36 ))
	INTEL_FAM6_ATOM_SILVERMONT1=$(( 0x37 ))
	INTEL_FAM6_ATOM_SILVERMONT2=$(( 0x4D ))
	INTEL_FAM6_ATOM_AIRMONT=$(( 0x4C ))
	INTEL_FAM6_ATOM_MERRIFIELD=$(( 0x4A ))
	INTEL_FAM6_ATOM_MOOREFIELD=$(( 0x5A ))
	INTEL_FAM6_ATOM_GOLDMONT=$(( 0x5C ))
	INTEL_FAM6_ATOM_DENVERTON=$(( 0x5F ))
	INTEL_FAM6_ATOM_GEMINI_LAKE=$(( 0x7A ))

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
		ucode=$(echo $tuple | cut -d, -f3)
		echo "$ucode" | grep -q ^0x && ucode_decimal=$(( ucode ))
		if [ "$cpu_model" = "$model" ] && [ "$cpu_stepping" = "$stepping" ]; then
			if [ "$cpu_ucode_decimal" = "$ucode_decimal" ] || [ "$cpu_ucode" = "$ucode" ]; then
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
	#	    boot_cpu_data.x86 == 6) {
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

is_zen_cpu()
{
	# is this CPU from the AMD ZEN family ? (ryzen, epyc, ...)
	parse_cpu_details
	is_amd || return 1
	[ "$cpu_family" = 23 ] && return 0
	return 1
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
	if [ "$opt_allvariants" = 0 ]; then
		show_usage
		echo "$0: error: incompatible modes specified, --hw-only vs --variant" >&2
		exit 255
	else
		opt_allvariants=0
		opt_variant1=0
		opt_variant2=0
		opt_variant3=0
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
	if [ -r /proc/cmdline ] && grep -q 'BOOT_IMAGE=' /proc/cmdline; then
		opt_kernel=$(grep -Eo 'BOOT_IMAGE=[^ ]+' /proc/cmdline | cut -d= -f2)
		_debug "found opt_kernel=$opt_kernel in /proc/cmdline"
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
		# Arch:
		[ -e "/boot/vmlinuz-linux"       ] && opt_kernel="/boot/vmlinuz-linux"
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
	fi

	# system.map
	if [ -e /proc/kallsyms ] ; then
		opt_map=/proc/kallsyms
	elif [ -e "/lib/modules/$(uname -r)/System.map" ] ; then
		opt_map="/lib/modules/$(uname -r)/System.map"
	elif [ -e "/boot/System.map-$(uname -r)" ] ; then
		opt_map="/boot/System.map-$(uname -r)"
	fi

	# config
	if [ -e /proc/config.gz ] ; then
		dumped_config="$(mktemp /tmp/config-XXXXXX)"
		gunzip -c /proc/config.gz > "$dumped_config"
		# dumped_config will be deleted at the end of the script
		opt_config="$dumped_config"
	elif [ -e "/lib/modules/$(uname -r)/config" ]; then
		opt_config="/lib/modules/$(uname -r)/config"
	elif [ -e "/boot/config-$(uname -r)" ]; then
		opt_config="/boot/config-$(uname -r)"
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
		_verbose "Will use kconfig \033[35m/proc/config.gz (decompressed)\033[0m"
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
		_info "We're missing some kernel info (see -v), accuracy might be reduced"
	fi
fi

if [ -e "$opt_kernel" ]; then
	if ! which "${opt_arch_prefix}readelf" >/dev/null 2>&1; then
		_debug "readelf not found"
		kernel_err="missing '${opt_arch_prefix}readelf' tool, please install it, usually it's in the 'binutils' package"
	elif [ "$opt_sysfs_only" = 1 ]; then
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
	[ "$opt_live" = 1 ] && [ "$opt_no_sysfs" = 0 ] && [ -r "$1" ] || return 1
	_info_nol "* Mitigated according to the /sys interface: "
	msg=$(cat "$1")
	if grep -qi '^not affected' "$1"; then
		# Not affected
		status=OK
		pstatus green YES "$msg"
	elif grep -qi '^mitigation' "$1"; then
		# Mitigation: PTI
		status=OK
		pstatus green YES "$msg"
	elif grep -qi '^vulnerable' "$1"; then
		# Vulnerable
		status=VULN
		pstatus yellow NO "$msg"
	else
		status=UNK
		pstatus yellow UNKNOWN "$msg"
	fi
	_debug "sys_interface_check: $1=$msg"
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
	if [ "$os" != Linux ]; then
		cpucontrol -m "$1=0" "/dev/cpuctl$2" >/dev/null 2>&1; ret=$?
	else
		# convert to decimal
		_msrindex=$(( $1 ))
		if [ ! -w /dev/cpu/"$2"/msr ]; then
			ret=200 # permission error
		else
			dd if=/dev/zero of=/dev/cpu/"$2"/msr bs=8 count=1 seek="$_msrindex" oflag=seek_bytes 2>/dev/null; ret=$?
		fi
	fi
	_debug "write_msr: for cpu $2 on msr $1 ($_msrindex), ret=$ret"
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
		# convert to decimal
		_msr=$(( _msr ))
		if [ ! -r /dev/cpu/"$_cpu"/msr ]; then
			return 200 # permission error
		fi
		read_msr_value=$(dd if=/dev/cpu/"$_cpu"/msr bs=8 count=1 skip="$_msr" iflag=skip_bytes 2>/dev/null | od -t u1 -A n)
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
		# here we use dd, it's the same as using 'rdmsr 0x48' but without needing the rdmsr tool
		# if we get a read error, the MSR is not there. bs has to be 8 for msr
		# skip=9 because 8*9=72=0x48
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
	else
		# the new MSR 'PRED_CTRL' is at offset 0x49, write-only
		# here we use dd, it's the same as using 'wrmsr 0x49 0' but without needing the wrmsr tool
		# if we get a write error, the MSR is not there
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
	_info     "  * Speculative Store Bypass Disable (SSBD)"
	_info_nol "    * CPU indicates SSBD capability: "
	read_cpuid 0x7 $EDX 31 1 1; ret=$?
	if [ $ret -eq 0 ]; then
		cpuid_ssbd=1
		pstatus green YES "SSBD feature bit"
	elif [ $ret -eq 1 ]; then
		pstatus yellow NO
	else
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
		if [ "$cpuid_arch_capabilities" = -1 ]; then
			pstatus yellow UNKNOWN
		elif [ "$cpuid_arch_capabilities" != 1 ]; then
			capabilities_rdcl_no=0
			capabilities_ibrs_all=0
			pstatus yellow NO
		elif [ ! -e /dev/cpu/0/msr ] && [ ! -e /dev/cpuctl0 ]; then
			spec_ctrl_msr=-1
			pstatus yellow UNKNOWN "is msr kernel module available?"
		else
			# the new MSR 'ARCH_CAPABILITIES' is at offset 0x10a
			# here we use dd, it's the same as using 'rdmsr 0x10a' but without needing the rdmsr tool
			# if we get a read error, the MSR is not there. bs has to be 8 for msr
			val=0
			val_cap_msr=0
			cpu_mismatch=0
			for i in $(seq 0 "$idx_max_cpu")
			do
				read_msr 0x10a "$i"; ret=$?
				capabilities=$(echo "$read_msr_value" | awk '{print $8}')
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
			capabilities_ssb_no=0
			if [ $val -eq 0 ]; then
				_debug "capabilities MSR lower byte is $capabilities (decimal)"
				[ $(( capabilities &  1 )) -eq 1  ] && capabilities_rdcl_no=1
				[ $(( capabilities &  2 )) -eq 2  ] && capabilities_ibrs_all=1
				[ $(( capabilities & 16 )) -eq 16 ] && capabilities_ssb_no=1
				_debug "capabilities says rdcl_no=$capabilities_rdcl_no ibrs_all=$capabilities_ibrs_all ssb_no=$capabilities_ssb_no"
				if [ "$capabilities_ibrs_all" = 1 ]; then
					if [ $cpu_mismatch -eq 0 ]; then
						pstatus green YES
					else:
						pstatus green YES "But not in all CPUs"
					fi
				else
					pstatus yellow NO
				fi
			elif [ $val -eq 200 ]; then
				pstatus yellow UNKNOWN "is msr kernel module available?"
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
		elif [ "$capabilities_ssb_no" = 1 ]; then
			pstatus green YES
		else
			pstatus yellow NO
		fi
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
}

check_cpu_vulnerabilities()
{
	_info     "* CPU vulnerability to the speculative execution attack variants"
	for v in 1 2 3 3a 4; do
		_info_nol "  * Vulnerable to Variant $v: "
		if is_cpu_vulnerable $v; then
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
# SPECTRE VARIANT 1
check_variant1()
{
	_info "\033[1;34mCVE-2017-5753 [bounds check bypass] aka 'Spectre Variant 1'\033[0m"
	if [ "$os" = Linux ]; then
		check_variant1_linux
	elif echo "$os" | grep -q BSD; then
		check_variant1_bsd
	else
		_warn "Unsupported OS ($os)"
	fi
}

check_variant1_linux()
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
		_info_nol "* Kernel has array_index_mask_nospec (x86): "
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
		if [ -n "$kernel_err" ]; then
			pstatus yellow UNKNOWN "couldn't check ($kernel_err)"
		elif ! which perl >/dev/null 2>&1; then
			pstatus yellow UNKNOWN "missing 'perl' binary, please install it"
		else
			perl -ne '/\x0f\x83....\x48\x19\xd2\x48\x21\xd0/ and $found++; END { exit($found) }' "$kernel"; ret=$?
			if [ $ret -gt 0 ]; then
				pstatus green YES "$ret occurrence(s) found of 64 bits array_index_mask_nospec()"
				v1_mask_nospec="64 bits array_index_mask_nospec"
			else
				perl -ne '/\x3b\x82..\x00\x00\x73.\x19\xd2\x21\xd0/ and $found++; END { exit($found) }' "$kernel"; ret=$?
				if [ $ret -gt 0 ]; then
					pstatus green YES "$ret occurrence(s) found of 32 bits array_index_mask_nospec()"
					v1_mask_nospec="32 bits array_index_mask_nospec"
				else
					pstatus yellow NO
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

		_info_nol "* Kernel has mask_nospec64 (arm): "
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
				v1_mask_nospec="arm mask_nospec64"
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
	cve='CVE-2017-5753'

	if ! is_cpu_vulnerable 1; then
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

check_variant1_bsd()
{
	cve='CVE-2017-5753'
	if ! is_cpu_vulnerable 1; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	else
		pvulnstatus $cve VULN "no mitigation for BSD yet"
	fi
}


###################
# SPECTRE VARIANT 2
check_variant2()
{
	_info "\033[1;34mCVE-2017-5715 [branch target injection] aka 'Spectre Variant 2'\033[0m"
	if [ "$os" = Linux ]; then
		check_variant2_linux
	elif echo "$os" | grep -q BSD; then
		check_variant2_bsd
	else
		_warn "Unsupported OS ($os)"
	fi
}

check_variant2_linux()
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
				/proc/sys/kernel; do
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

		if is_skylake_cpu || [ "$opt_verbose" -ge 2 ]; then
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

	cve='CVE-2017-5715'
	if ! is_cpu_vulnerable 2; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	else
		if [ "$retpoline" = 1 ] && [ "$retpoline_compiler" = 1 ] && [ "$retp_enabled" != 0 ] && [ -n "$ibpb_enabled" ] && [ "$ibpb_enabled" -ge 1 ] && ( ! is_skylake_cpu || [ -n "$rsb_filling" ] ); then
			pvulnstatus $cve OK "Full retpoline + IBPB are mitigating the vulnerability"
		elif [ "$retpoline" = 1 ] && [ "$retpoline_compiler" = 1 ] && [ "$retp_enabled" != 0 ] && [ "$opt_paranoid" = 0 ] && ( ! is_skylake_cpu || [ -n "$rsb_filling" ] ); then
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
			if is_skylake_cpu; then
				pvulnstatus $cve VULN "IBRS+IBPB or retpoline+IBPB+RBS filling, is needed to mitigate the vulnerability"
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
			_explain_hypervisor="An updated CPU microcode will have IBRS/IBPB capabilities indicated in the Hardware Check section above. If you're running under an hypervisor (KVM, Xen, VirtualBox, VMware, ...), the hypervisor needs to be up to date to be able to export the new host CPU flags to the guest. You can run this script on the host to check if the host CPU is IBRS/IBPB. If it is, and it doesn't show up in the guest, upgrade the hypervisor. You may need to reconfigure your VM to use a CPU model that has IBRS capability; in Libvirt, such CPUs are listed with an IBRS suffix."
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

check_variant2_bsd()
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

	cve='CVE-2017-5715'
	if ! is_cpu_vulnerable 2; then
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

########################
# MELTDOWN aka VARIANT 3

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

check_variant3()
{
	_info "\033[1;34mCVE-2017-5754 [rogue data cache load] aka 'Meltdown' aka 'Variant 3'\033[0m"
	if [ "$os" = Linux ]; then
		check_variant3_linux
	elif echo "$os" | grep -q BSD; then
		check_variant3_bsd
	else
		_warn "Unsupported OS ($os)"
	fi
}

check_variant3_linux()
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
	if [ -d "/proc/xen" ]; then
		# XXX do we have a better way that relying on dmesg?
		dmesg_grep 'Booting paravirtualized kernel on Xen$'; ret=$?
		if [ $ret -eq 2 ]; then
			_warn "dmesg truncated, Xen detection will be unreliable. Please reboot and relaunch this script"
		elif [ $ret -eq 0 ]; then
			if [ -e /proc/xen/capabilities ] && grep -q "control_d" /proc/xen/capabilities; then
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

	cve='CVE-2017-5754'
	if ! is_cpu_vulnerable 3; then
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
					elif grep -q -w nopti -w pti=off /proc/cmdline; then
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

check_variant3_bsd()
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

	cve='CVE-2017-5754'
	if ! is_cpu_vulnerable 3; then
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

check_variant3a()
{
	_info "\033[1;34mCVE-2018-3640 [rogue system register read] aka 'Variant 3a'\033[0m"

	status=UNK
	sys_interface_available=0
	msg=''

	_info_nol "  * CPU microcode mitigates the vulnerability: "
	pstatus yellow UNKNOWN "an up to date microcode is sufficient to mitigate this vulnerability, detection will be implemented soon"

	cve='CVE-2018-3640'
	if ! is_cpu_vulnerable 3a; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	else
		pvulnstatus $cve VULN "a new microcode will mitigate this vulnerability"
	fi
}

check_variant4()
{
	_info "\033[1;34mCVE-2018-3639 [speculative store bypass] aka 'Variant 4'\033[0m"

	status=UNK
	sys_interface_available=0
	msg=''
	if sys_interface_check "/sys/devices/system/cpu/vulnerabilities/spec_store_bypass"; then
		# this kernel has the /sys interface, trust it over everything
		sys_interface_available=1
	fi
	if [ "$opt_sysfs_only" != 1 ]; then
		_info_nol "  * Kernel supports speculation store bypass: "
		if [ "$opt_live" = 1 ]; then
			if grep -q 'Speculation.Store.Bypass:' /proc/self/status 2>/dev/null; then
				kernel_ssb='found in /proc/self/status'
				_debug "found Speculation.Store.Bypass: in /proc/self/status"
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

	cve='CVE-2018-3639'
	if ! is_cpu_vulnerable 4; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	elif [ -z "$msg" ] || [ "$msg" = "Vulnerable" ]; then
		# if msg is empty, sysfs check didn't fill it, rely on our own test
		if [ "$cpuid_ssbd" = 1 ]; then
			if [ -n "$kernel_ssb" ]; then
				pvulnstatus $cve OK "your system provides the necessary tools for software mitigation"
			else
				pvulnstatus $cve VULN "your kernel needs to be updated"
				explain "You have a recent-enough microcode but your kernel is too old to use the new features exported by your CPU's microcode"
			fi
		else
			if [ -n "$kernel_ssb" ]; then
				pvulnstatus $cve VULN "Your CPU doesn't support SSBD"
				explain "Your kernel is recent enough to be able to export features for mitigation, but your CPU microcode doesn't provide the necessary tools"
			else
				pvulnstatus $cve VULN "Neither your CPU nor your kernel support SSBD"
				explain "You need to update your CPU microcode and use a more recent kernel to provide the necessary mitigation tools to the software running on your machine"
			fi
		fi
	else
		pvulnstatus $cve "$status" "$msg"
	fi
}

if [ "$opt_no_hw" = 0 ] && [ -z "$opt_arch_prefix" ]; then
	check_cpu
	check_cpu_vulnerabilities
	_info
fi

# now run the checks the user asked for
if [ "$opt_variant1" = 1 ] || [ "$opt_allvariants" = 1 ]; then
	check_variant1
	_info
fi
if [ "$opt_variant2" = 1 ] || [ "$opt_allvariants" = 1 ]; then
	check_variant2
	_info
fi
if [ "$opt_variant3" = 1 ] || [ "$opt_allvariants" = 1 ]; then
	check_variant3
	_info
fi
if [ "$opt_variant3a" = 1 ] || [ "$opt_allvariants" = 1 ]; then
	check_variant3a
	_info
fi
if [ "$opt_variant4" = 1 ] || [ "$opt_allvariants" = 1 ]; then
	check_variant4
	_info
fi

_vars=$(set | grep -Ev '^[A-Z_[:space:]]' | sort | tr "\n" '|')
_debug "variables at end of script: $_vars"

_info "A false sense of security is worse than no security at all, see --disclaimer"

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "nrpe" ]; then
	if [ ! -z "$nrpe_vuln" ]; then
		echo "Vulnerable:$nrpe_vuln"
	else
		echo "OK"
	fi
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "json" ]; then
	_echo 0 "${json_output%?}]"
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "prometheus" ]; then
	echo "# TYPE specex_vuln_status untyped"
	echo "# HELP specex_vuln_status Exposure of system to speculative execution vulnerabilities"
	echo "$prometheus_output"
fi

# exit with the proper exit code
[ "$global_critical" = 1 ] && exit 2  # critical
[ "$global_unknown"  = 1 ] && exit 3  # unknown
exit 0  # ok
