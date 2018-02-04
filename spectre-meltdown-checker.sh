#! /bin/sh
# Spectre & Meltdown checker
#
# Check for the latest version at:
# https://github.com/speed47/spectre-meltdown-checker
# git clone https://github.com/speed47/spectre-meltdown-checker.git
# or wget https://raw.githubusercontent.com/speed47/spectre-meltdown-checker/master/spectre-meltdown-checker.sh
#
# Stephane Lesimple
#
VERSION='0.34+'

trap 'exit_cleanup' EXIT
trap '_warn "interrupted, cleaning up..."; exit_cleanup; exit 1' INT
exit_cleanup()
{
	# cleanup the temp decompressed config & kernel image
	[ -n "$dumped_config" ] && [ -f "$dumped_config" ] && rm -f "$dumped_config"
	[ -n "$vmlinuxtmp"    ] && [ -f "$vmlinuxtmp"    ] && rm -f "$vmlinuxtmp"
	[ "$mounted_debugfs" = 1 ] && umount /sys/kernel/debug 2>/dev/null
	[ "$insmod_cpuid"    = 1 ] && rmmod cpuid 2>/dev/null
	[ "$insmod_msr"      = 1 ] && rmmod msr 2>/dev/null
}

show_usage()
{
	# shellcheck disable=SC2086
	cat <<EOF
	Usage:
		Live mode:    $(basename $0) [options] [--live]
		Offline mode: $(basename $0) [options] [--kernel <vmlinux_file>] [--config <kernel_config>] [--map <kernel_map_file>]

	Modes:
		Two modes are available.

		First mode is the "live" mode (default), it does its best to find information about the currently running kernel.
		To run under this mode, just start the script without any option (you can also use --live explicitly)

		Second mode is the "offline" mode, where you can inspect a non-running kernel.
		You'll need to specify the location of the vmlinux file, config and System.map files:

		--kernel vmlinux_file		Specify a (possibly compressed) vmlinux file
		--config kernel_config		Specify a kernel config file
		--map	 kernel_map_file	Specify a kernel System.map file

	Options:
		--no-color			Don't use color codes
		--verbose, -v			Increase verbosity level
		--no-sysfs			Don't use the /sys interface even if present
		--sysfs-only			Only use the /sys interface, don't run our own checks
		--coreos			Special mode for CoreOS (use an ephemeral toolbox to inspect kernel)
		--batch text			Produce machine readable output, this is the default if --batch is specified alone
		--batch json			Produce JSON output formatted for Puppet, Ansible, Chef...
		--batch nrpe			Produce machine readable output formatted for NRPE
		--variant [1,2,3]		Specify which variant you'd like to check, by default all variants are checked
						Can be specified multiple times (e.g. --variant 2 --variant 3)

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
the softwares you use, especially for those who are exposed to the world, such as network daemons and browsers.

This tool has been released in the hope that it'll be useful, but don't use it to jump to conclusions about your security.

EOF
}

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

global_critical=0
global_unknown=0
nrpe_vuln=""

# find a sane `echo` command
# we'll try to avoid using shell builtins that might not take options
if which echo >/dev/null 2>&1; then
	echo_cmd=$(which echo)
else
	[ -x /bin/echo        ] && echo_cmd=/bin/echo
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
		_ctrlchar=$($echo_cmd -e "\033")
		_msg=$($echo_cmd -e "$_msg" | sed -r "s/$_ctrlchar\[([0-9][0-9]?(;[0-9][0-9]?)?)?m//g")
	fi
	# shellcheck disable=SC2086
	$echo_cmd $opt -e "$_msg"
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

is_cpu_vulnerable_cached=0
_is_cpu_vulnerable_cached()
{
	# shellcheck disable=SC2086
	[ "$1" = 1 ] && return $variant1
	# shellcheck disable=SC2086
	[ "$1" = 2 ] && return $variant2
	# shellcheck disable=SC2086
	[ "$1" = 3 ] && return $variant3
	echo "$0: error: invalid variant '$1' passed to is_cpu_vulnerable()" >&2
	exit 255
}

is_cpu_vulnerable()
{
	# param: 1, 2 or 3 (variant)
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

	if is_cpu_specex_free; then
		variant1=immune
		variant2=immune
		variant3=immune
	elif [ "$cpu_vendor" = GenuineIntel ]; then
		# Intel
		# https://github.com/crozone/SpectrePoC/issues/1 ^F E5200 => spectre 2 not vulnerable
		# https://github.com/paboldin/meltdown-exploit/issues/19 ^F E5200 => meltdown vulnerable
		# model name : Pentium(R) Dual-Core  CPU      E5200  @ 2.50GHz
		if grep -qE '^model name.+ Pentium\(R\) Dual-Core[[:space:]]+CPU[[:space:]]+E[0-9]{4}K? ' /proc/cpuinfo; then
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
	elif [ "$cpu_vendor" = AuthenticAMD ]; then
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
			fi
			_debug "is_cpu_vulnerable: for cpu$i and so far, we have <$variant1> <$variant2> <$variant3>"
		done
	fi
	_debug "is_cpu_vulnerable: temp results are <$variant1> <$variant2> <$variant3>"
	# if at least one of the cpu is vulnerable, then the system is vulnerable
	[ "$variant1" = "immune" ] && variant1=1 || variant1=0
	[ "$variant2" = "immune" ] && variant2=1 || variant2=0
	[ "$variant3" = "immune" ] && variant3=1 || variant3=0
	_debug "is_cpu_vulnerable: final results are <$variant1> <$variant2> <$variant3>"
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
	if [ "$cpu_vendor" = GenuineIntel ]; then
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
	[ "$cpu_family" -eq 4 ] && return 0
	return 1
}

show_header()
{
	_info "\033[1;34mSpectre and Meltdown mitigation detection tool v$VERSION\033[0m"
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
	elif [ "$1" = "--batch" ]; then
		opt_batch=1
		opt_verbose=0
		shift
		case "$1" in
			text|nrpe|json) opt_batch_format="$1"; shift;;
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
			1) opt_variant1=1; opt_allvariants=0;;
			2) opt_variant2=1; opt_allvariants=0;;
			3) opt_variant3=1; opt_allvariants=0;;
			*)
				echo "$0: error: invalid parameter '$2' for --variant, expected either 1, 2 or 3" >&2;
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
}

# Print the final status of a vulnerability (incl. batch mode)
# Arguments are: CVE UNK/OK/VULN description
pvulnstatus()
{
	if [ "$opt_batch" = 1 ]; then
		case "$opt_batch_format" in
			text) _echo 0 "$1: $2 ($3)";;
			json)
				case "$1" in
					CVE-2017-5753) aka="SPECTRE VARIANT 1";;
					CVE-2017-5715) aka="SPECTRE VARIANT 2";;
					CVE-2017-5754) aka="MELTDOWN";;
				esac
				case "$2" in
					UNK)  is_vuln="null";;
					VULN) is_vuln="true";;
					OK)   is_vuln="false";;
				esac
				json_output="${json_output:-[}{\"NAME\":\"$aka\",\"CVE\":\"$1\",\"VULNERABLE\":$is_vuln,\"INFOS\":\"$3\"},"
				;;

			nrpe)	[ "$2" = VULN ] && nrpe_vuln="$nrpe_vuln $1";;
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

vmlinux=''
vmlinux_err=''
check_vmlinux()
{
	readelf -h "$1" >/dev/null 2>&1 && return 0
	return 1
}

try_decompress()
{
	# The obscure use of the "tr" filter is to work around older versions of
	# "grep" that report the byte offset of the line instead of the pattern.

	# Try to find the header ($1) and decompress from here
	for     pos in $(tr "$1\n$2" "\n$2=" < "$6" | grep -abo "^$2")
	do
		_debug "try_decompress: magic for $3 found at offset $pos"
		if ! which "$3" >/dev/null 2>&1; then
			vmlinux_err="missing '$3' tool, please install it, usually it's in the '$5' package"
			return 0
		fi
		pos=${pos%%:*}
		# shellcheck disable=SC2086
		tail -c+$pos "$6" 2>/dev/null | $3 $4 > "$vmlinuxtmp" 2>/dev/null
		if check_vmlinux "$vmlinuxtmp"; then
			vmlinux="$vmlinuxtmp"
			_debug "try_decompress: decompressed with $3 successfully!"
			return 0
		else
			_debug "try_decompress: decompression with $3 did not work"
		fi
	done
	return 1
}

extract_vmlinux()
{
	[ -n "$1" ] || return 1
	# Prepare temp files:
	vmlinuxtmp="$(mktemp /tmp/vmlinux-XXXXXX)"

	# Initial attempt for uncompressed images or objects:
	if check_vmlinux "$1"; then
		cat "$1" > "$vmlinuxtmp"
		vmlinux=$vmlinuxtmp
		return 0
	fi

	# That didn't work, so retry after decompression.
	try_decompress '\037\213\010'     xy    gunzip  ''      gunzip      "$1" && return 0
	try_decompress '\3757zXZ\000'     abcde unxz    ''      xz-utils    "$1" && return 0
	try_decompress 'BZh'              xy    bunzip2 ''      bzip2       "$1" && return 0
	try_decompress '\135\0\0\0'       xxx   unlzma  ''      xz-utils    "$1" && return 0
	try_decompress '\211\114\132'     xy    'lzop'  '-d'    lzop        "$1" && return 0
	try_decompress '\002\041\114\030' xyy   'lz4'   '-d -l' liblz4-tool "$1" && return 0
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
	modprobe msr 2>/dev/null && insmod_msr=1
	_debug "attempted to load module msr, insmod_msr=$insmod_msr"
}

load_cpuid()
{
	modprobe cpuid 2>/dev/null && insmod_cpuid=1
	_debug "attempted to load module cpuid, insmod_cpuid=$insmod_cpuid"
}

read_cpuid()
{
	_leaf="$1"
	_bytenum="$2"
	_and_operand="$3"

	if [ ! -e /dev/cpu/0/cpuid ]; then
		# try to load the module ourselves (and remember it so we can rmmod it afterwards)
		load_cpuid
	fi
	if [ ! -e /dev/cpu/0/cpuid ]; then
		return 2
	fi

	if [ "$opt_verbose" -ge 3 ]; then
		dd if=/dev/cpu/0/cpuid bs=16 skip="$_leaf" iflag=skip_bytes count=1 >/dev/null 2>/dev/null
		_debug "cpuid: reading leaf$_leaf of cpuid on cpu0, ret=$?"
		_debug "cpuid: leaf$_leaf eax-ebx-ecx-edx: $(   dd if=/dev/cpu/0/cpuid bs=16 skip="$_leaf" iflag=skip_bytes count=1 2>/dev/null | od -x -A n)"
		_debug "cpuid: leaf$_leaf edx higher byte is: $(dd if=/dev/cpu/0/cpuid bs=16 skip="$_leaf" iflag=skip_bytes count=1 2>/dev/null | dd bs=1 skip="$_bytenum" count=1 2>/dev/null | od -x -A n)"
	fi
	# getting proper byte of edx on leaf$_leaf of cpuinfo in decimal
	_reg_byte=$(dd if=/dev/cpu/0/cpuid bs=16 skip="$_leaf" iflag=skip_bytes count=1 2>/dev/null | dd bs=1 skip="$_bytenum" count=1 2>/dev/null | od -t u1 -A n | awk '{print $1}')
	_debug "cpuid: leaf$_leaf byte $_bytenum: $_reg_byte (decimal)"
	_reg_bit=$(( _reg_byte & _and_operand ))
	_debug "cpuid: leaf$_leaf byte $_bytenum & $_and_operand = $_reg_bit"
	[ "$_reg_bit" -eq 0 ] && return 1
	# $_reg_bit is > 0, so the bit was found: return true (aka 0)
	return 0
}

dmesg_grep()
{
	# grep for something in dmesg, ensuring that the dmesg buffer
	# has not been truncated
	dmesg_grepped=''
	if ! dmesg | grep -qE '(^|\] )Linux version [0-9]'; then
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
	cpu_vendor=$(  grep '^vendor_id'  /proc/cpuinfo | awk '{print $3}' | head -1)
	cpu_friendly_name=$(grep '^model name' /proc/cpuinfo | cut -d: -f2- | head -1 | sed -e 's/^ *//')
	# special case for ARM follows
	if grep -qi 'CPU implementer[[:space:]]*:[[:space:]]*0x41' /proc/cpuinfo; then
		cpu_vendor='ARM'
		# some devices (phones or other) have several ARMs and as such different part numbers,
		# an example is "bigLITTLE", so we need to store the whole list, this is needed for is_cpu_vulnerable
		cpu_part_list=$(awk '/CPU part/         {print $4}' /proc/cpuinfo)
		cpu_arch_list=$(awk '/CPU architecture/ {print $3}' /proc/cpuinfo)
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

	cpu_family=$(  grep '^cpu family' /proc/cpuinfo | awk '{print $4}' | grep -E '^[0-9]+$' | head -1)
	cpu_model=$(   grep '^model'      /proc/cpuinfo | awk '{print $3}' | grep -E '^[0-9]+$' | head -1)
	cpu_stepping=$(grep '^stepping'   /proc/cpuinfo | awk '{print $3}' | grep -E '^[0-9]+$' | head -1)
	cpu_ucode=$(  grep '^microcode'   /proc/cpuinfo | awk '{print $3}' | head -1)

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

is_ucode_blacklisted()
{
	parse_cpu_details
	# if it's not an Intel, don't bother: it's not blacklisted
	[ "$cpu_vendor" = GenuineIntel ] || return 1
	# it also needs to be family=6
	[ "$cpu_family" = 6 ] || return 1
	# now, check each known bad microcode
	# source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/cpu/intel.c#n105
	# model,stepping,microcode
	ucode_found="model $cpu_model stepping $cpu_stepping ucode $cpu_ucode"
	for tuple in \
		$INTEL_FAM6_KABYLAKE_DESKTOP,0x0B,0x84 \
		$INTEL_FAM6_KABYLAKE_DESKTOP,0x0A,0x84 \
		$INTEL_FAM6_KABYLAKE_DESKTOP,0x09,0x84 \
		$INTEL_FAM6_KABYLAKE_MOBILE,0x0A,0x84  \
		$INTEL_FAM6_KABYLAKE_MOBILE,0x09,0x84  \
		$INTEL_FAM6_SKYLAKE_X,0x03,0x0100013e  \
		$INTEL_FAM6_SKYLAKE_X,0x04,0x0200003c  \
		$INTEL_FAM6_SKYLAKE_MOBILE,0x03,0xc2   \
		$INTEL_FAM6_SKYLAKE_DESKTOP,0x03,0xc2  \
		$INTEL_FAM6_BROADWELL_CORE,0x04,0x28   \
		$INTEL_FAM6_BROADWELL_GT3E,0x01,0x1b   \
		$INTEL_FAM6_BROADWELL_XEON_D,0x02,0x14 \
		$INTEL_FAM6_BROADWELL_XEON_D,0x03,0x07000011 \
		$INTEL_FAM6_BROADWELL_X,0x01,0x0b000025 \
		$INTEL_FAM6_HASWELL_ULT,0x01,0x21      \
		$INTEL_FAM6_HASWELL_GT3E,0x01,0x18     \
		$INTEL_FAM6_HASWELL_CORE,0x03,0x23     \
		$INTEL_FAM6_HASWELL_X,0x02,0x3b        \
		$INTEL_FAM6_HASWELL_X,0x04,0x10        \
		$INTEL_FAM6_IVYBRIDGE_X,0x04,0x42a     \
		$INTEL_FAM6_ATOM_GEMINI_LAKE,0x01,0x22 \
		$INTEL_FAM6_SANDYBRIDGE_X,0x06,0x61b   \
		$INTEL_FAM6_SANDYBRIDGE_X,0x07,0x712
	do
		model=$(echo $tuple | cut -d, -f1)
		stepping=$(( $(echo $tuple | cut -d, -f2) ))
		ucode=$(echo $tuple | cut -d, -f3)
		if [ "$cpu_model" = "$model" ] && [ "$cpu_stepping" = "$stepping" ] && echo "$cpu_ucode" | grep -qi "^$ucode$"; then
			_debug "is_ucode_blacklisted: we have a match! ($cpu_model/$cpu_stepping/$cpu_ucode)"
			return 0
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
	[ "$cpu_vendor" = GenuineIntel ] || return 1
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

# check for mode selection inconsistency
if [ "$opt_live_explicit" = 1 ]; then
	if [ -n "$opt_kernel" ] || [ -n "$opt_config" ] || [ -n "$opt_map" ]; then
		show_usage
		echo "$0: error: incompatible modes specified, use either --live or --kernel/--config/--map" >&2
		exit 255
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
		# generic:
		[ -e "/boot/vmlinuz-$(uname -r)" ] && opt_kernel="/boot/vmlinuz-$(uname -r)"
		[ -e "/boot/kernel-$( uname -r)" ] && opt_kernel="/boot/kernel-$( uname -r)"
		[ -e "/boot/bzImage-$(uname -r)" ] && opt_kernel="/boot/bzImage-$(uname -r)"
		# Gentoo:
		[ -e "/boot/kernel-genkernel-$(uname -m)-$(uname -r)" ] && opt_kernel="/boot/kernel-genkernel-$(uname -m)-$(uname -r)"
		# NixOS:
		[ -e "/run/booted-system/kernel" ] && opt_kernel="/run/booted-system/kernel"
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
	_verbose "Will use vmlinux image \033[35m$opt_kernel\033[0m"
else
	_verbose "Will use no vmlinux image (accuracy might be reduced)"
	bad_accuracy=1
fi

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

if [ -e "$opt_kernel" ]; then
	if ! which readelf >/dev/null 2>&1; then
		_debug "readelf not found"
		vmlinux_err="missing 'readelf' tool, please install it, usually it's in the 'binutils' package"
	elif [ "$opt_sysfs_only" = 1 ]; then
		vmlinux_err='kernel image decompression skipped'
	else
		extract_vmlinux "$opt_kernel"
	fi
else
	_debug "no opt_kernel defined"
	vmlinux_err="couldn't find your kernel image in /boot, if you used netboot, this is normal"
fi
if [ -z "$vmlinux" ] || [ ! -r "$vmlinux" ]; then
	[ -z "$vmlinux_err" ] && vmlinux_err="couldn't extract your kernel from $opt_kernel"
else
	vmlinux_version=$(strings "$vmlinux" 2>/dev/null | grep '^Linux version ' | head -1)
	if [ -n "$vmlinux_version" ]; then
		# in live mode, check if the img we found is the correct one
		if [ "$opt_live" = 1 ]; then
			_verbose "Kernel image is \033[35m$vmlinux_version"
			if ! echo "$vmlinux_version" | grep -qF "$(uname -r)" || \
				! echo "$vmlinux_version" | grep -qF "$(uname -v)"; then
				_warn "Possible disrepancy between your running kernel and the image we found ($opt_kernel), results might be incorrect"
			fi
		else
			_info "Kernel image is \033[35m$vmlinux_version"
		fi
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
	if grep -qi '^not affected' "$1"; then
		# Not affected
		status=OK
		pstatus green YES "kernel confirms that your CPU is unaffected"
	elif grep -qi '^mitigation' "$1"; then
		# Mitigation: PTI
		status=OK
		pstatus green YES "kernel confirms that the mitigation is active"
	elif grep -qi '^vulnerable' "$1"; then
		# Vulnerable
		status=VULN
		pstatus red NO "kernel confirms your system is vulnerable"
	else
		status=UNK
		pstatus yellow UNKNOWN "unknown value reported by kernel"
	fi
	msg=$(cat "$1")
	_debug "sys_interface_check: $1=$msg"
	return 0
}

check_cpu()
{
	_info "\033[1;34mHardware check\033[0m"

	_info     "* Hardware support (CPU microcode) for mitigation techniques"
	_info     "  * Indirect Branch Restricted Speculation (IBRS)"
	_info_nol "    * SPEC_CTRL MSR is available: "
	if [ ! -e /dev/cpu/0/msr ]; then
		# try to load the module ourselves (and remember it so we can rmmod it afterwards)
		load_msr
	fi
	if [ ! -e /dev/cpu/0/msr ]; then
		spec_ctrl_msr=-1
		pstatus yellow UNKNOWN "couldn't read /dev/cpu/0/msr, is msr support enabled in your kernel?"
	else
		# the new MSR 'SPEC_CTRL' is at offset 0x48
		# here we use dd, it's the same as using 'rdmsr 0x48' but without needing the rdmsr tool
		# if we get a read error, the MSR is not there. bs has to be 8 for msr
		# skip=9 because 8*9=72=0x48
		dd if=/dev/cpu/0/msr of=/dev/null bs=8 count=1 skip=9 2>/dev/null; ret=$?
		if [ $ret -eq 0 ]; then
			spec_ctrl_msr=1
			pstatus green YES
		else
			spec_ctrl_msr=0
			pstatus red NO
		fi
	fi

	_info_nol "    * CPU indicates IBRS capability: "
	# from kernel src: { X86_FEATURE_SPEC_CTRL,        CPUID_EDX,26, 0x00000007, 0 },
	read_cpuid 7 15 4; ret=$?
	if [ $ret -eq 0 ]; then
		pstatus green YES "SPEC_CTRL feature bit"
		cpuid_spec_ctrl=1
	elif [ $ret -eq 2 ]; then
		pstatus yellow UNKNOWN "couldn't read /dev/cpu/0/cpuid, is cpuid support enabled in your kernel?"
	else
		pstatus red NO
	fi

	# hardware support according to kernel
	if [ "$opt_verbose" -ge 2 ]; then
		# the spec_ctrl flag in cpuinfo is set if and only if the kernel sees
		# that the spec_ctrl cpuinfo bit set. we already check that ourselves above
		# but let's check it anyway (in verbose mode only)
		_verbose_nol "    * Kernel has set the spec_ctrl flag in cpuinfo: "
		if [ "$opt_live" = 1 ]; then
			if grep ^flags /proc/cpuinfo | grep -qw spec_ctrl; then
				pstatus green YES
			else
				pstatus blue NO
			fi
		else
			pstatus blue N/A "not testable in offline mode"
		fi
	fi

	# IBPB
	_info     "  * Indirect Branch Prediction Barrier (IBPB)"
	_info_nol "    * PRED_CMD MSR is available: "
	if [ ! -e /dev/cpu/0/msr ]; then
		pstatus yellow UNKNOWN "couldn't read /dev/cpu/0/msr, is msr support enabled in your kernel?"
	else
		# the new MSR 'PRED_CTRL' is at offset 0x49, write-only
		# here we use dd, it's the same as using 'wrmsr 0x49 0' but without needing the wrmsr tool
		# if we get a write error, the MSR is not there
		$echo_cmd -ne "\0\0\0\0\0\0\0\0" | dd of=/dev/cpu/0/msr bs=8 count=1 seek=73 oflag=seek_bytes 2>/dev/null; ret=$?
		if [ $ret -eq 0 ]; then
			pstatus green YES
		else
			pstatus red NO
		fi
	fi


	_info_nol "    * CPU indicates IBPB capability: "
	# CPUID EAX=0x80000008, ECX=0x00 return EBX[12] indicates support for just IBPB.
	read_cpuid 2147483656 5 16; ret=$?
	if [ $ret -eq 0 ]; then
		pstatus green YES "IBPB_SUPPORT feature bit"
	elif [ "$cpuid_spec_ctrl" = 1 ]; then
		pstatus green YES "SPEC_CTRL feature bit"
	elif [ $ret -eq 2 ]; then
		pstatus yellow UNKNOWN "couldn't read /dev/cpu/0/cpuid, is cpuid support enabled in your kernel?"
	else
		pstatus red NO
	fi

	# STIBP
	_info     "  * Single Thread Indirect Branch Predictors (STIBP)"
	_info_nol "    * SPEC_CTRL MSR is available: "
	if [ "$spec_ctrl_msr" = 1 ]; then
		pstatus green YES
	elif [ "$spec_ctrl_msr" = 0 ]; then
		pstatus red NO
	else
		pstatus yellow UNKNOWN "couldn't read /dev/cpu/0/msr, is msr support enabled in your kernel?"
	fi

	_info_nol "    * CPU indicates STIBP capability: "
	# A processor supports STIBP if it enumerates CPUID (EAX=7H,ECX=0):EDX[27] as 1
	read_cpuid 7 15 8; ret=$?
	if [ $ret -eq 0 ]; then
		pstatus green YES
	elif [ $ret -eq 2 ]; then
		pstatus yellow UNKNOWN "couldn't read /dev/cpu/0/cpuid, is cpuid support enabled in your kernel?"
	else
		pstatus red NO
	fi

	_info     "  * Enhanced IBRS (IBRS_ALL)"
	_info_nol "    * CPU indicates ARCH_CAPABILITIES MSR availability: "
	cpuid_arch_capabilities=-1
	# A processor supports STIBP if it enumerates CPUID (EAX=7H,ECX=0):EDX[27] as 1
	read_cpuid 7 15 32; ret=$?
	if [ $ret -eq 0 ]; then
		pstatus green YES
		cpuid_arch_capabilities=1
	elif [ $ret -eq 2 ]; then
		pstatus yellow UNKNOWN "couldn't read /dev/cpu/0/cpuid, is cpuid support enabled in your kernel?"
	else
		pstatus red NO
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
		pstatus red NO
	elif [ ! -e /dev/cpu/0/msr ]; then
		spec_ctrl_msr=-1
		pstatus yellow UNKNOWN "couldn't read /dev/cpu/0/msr, is msr support enabled in your kernel?"
	else
		# the new MSR 'ARCH_CAPABILITIES' is at offset 0x10a
		# here we use dd, it's the same as using 'rdmsr 0x10a' but without needing the rdmsr tool
		# if we get a read error, the MSR is not there. bs has to be 8 for msr
		capabilities=$(dd if=/dev/cpu/0/msr bs=8 count=1 skip=266 iflag=skip_bytes 2>/dev/null | od -t u1 -A n | awk '{print $8}'); ret=$?
		capabilities_rdcl_no=0
		capabilities_ibrs_all=0
		if [ $ret -eq 0 ]; then
			_debug "capabilities MSR lower byte is $capabilities (decimal)"
			[ $(( capabilities & 1 )) -eq 1 ] && capabilities_rdcl_no=1
			[ $(( capabilities & 2 )) -eq 2 ] && capabilities_ibrs_all=1
			_debug "capabilities says rdcl_no=$capabilities_rdcl_no ibrs_all=$capabilities_ibrs_all"
			if [ "$capabilities_ibrs_all" = 1 ]; then
				pstatus green YES
			else
				pstatus red NO
			fi
		else
			pstatus yellow UNKNOWN
		fi
	fi

	_info_nol "  * CPU explicitly indicates not being vulnerable to Meltdown (RDCL_NO): "
	if [ "$capabilities_rdcl_no" = -1 ]; then
		pstatus yellow UNKNOWN
	elif [ "$capabilities_rdcl_no" = 1 ]; then
		pstatus green YES
	else
		pstatus blue NO
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
		pstatus green NO "$ucode_found"
	fi

	_info     "* CPU vulnerability to the three speculative execution attacks variants"
	for v in 1 2 3; do
		_info_nol "  * Vulnerable to Variant $v: "
		if is_cpu_vulnerable $v; then
			pstatus red YES
		else
			pstatus green NO
		fi
	done

	_info
}

###################
# SPECTRE VARIANT 1
check_variant1()
{
	_info "\033[1;34mCVE-2017-5753 [bounds check bypass] aka 'Spectre Variant 1'\033[0m"

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
		if [ -n "$vmlinux_err" ]; then
			pstatus yellow UNKNOWN "couldn't check ($vmlinux_err)"
		elif ! which perl >/dev/null 2>&1; then
			pstatus yellow UNKNOWN "missing 'perl' binary, please install it"
		else
			perl -ne '/\x0f\x83....\x48\x19\xd2\x48\x21\xd0/ and $found++; END { exit($found) }' "$vmlinux"; ret=$?
			if [ $ret -gt 0 ]; then
				pstatus green YES "$ret occurence(s) found of 64 bits array_index_mask_nospec()"
				v1_mask_nospec=1
			else
				perl -ne '/\x3b\x82..\x00\x00\x73.\x19\xd2\x21\xd0/ and $found++; END { exit($found) }' "$vmlinux"; ret=$?
				if [ $ret -gt 0 ]; then
					pstatus green YES "$ret occurence(s) found of 32 bits array_index_mask_nospec()"
					v1_mask_nospec=1
				else
					pstatus red NO
				fi
			fi
		fi

		if [ "$opt_verbose" -ge 2 ] || [ "$v1_mask_nospec" != 1 ]; then
			# this is a slow heuristic and we don't need it if we already know the kernel is patched
			# but still show it in verbose mode
			_info_nol "* Checking count of LFENCE instructions following a jump in kernel... "
			if [ -n "$vmlinux_err" ]; then
				pstatus yellow UNKNOWN "couldn't check ($vmlinux_err)"
			else
				if ! which objdump >/dev/null 2>&1; then
					pstatus yellow UNKNOWN "missing 'objdump' tool, please install it, usually it's in the binutils package"
				else
					# here we disassemble the kernel and count the number of occurrences of the LFENCE opcode
					# in non-patched kernels, this has been empirically determined as being around 40-50
					# in patched kernels, this is more around 70-80, sometimes way higher (100+)
					# v0.13: 68 found in a 3.10.23-xxxx-std-ipv6-64 (with lots of modules compiled-in directly), which doesn't have the LFENCE patches,
					# so let's push the threshold to 70.
					# v0.33+: now only count lfence opcodes after a jump, way less error-prone
					# non patched kernel have between 0 and 20 matches, patched ones have at least 40-45
					nb_lfence=$(objdump -d "$vmlinux" | grep -w -B1 lfence | grep -Ewc 'jmp|jne|je')
					if [ "$nb_lfence" -lt 30 ]; then
						pstatus red NO "only $nb_lfence jump-then-lfence instructions found, should be >= 30 (heuristic)"
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
		if [ "$v1_mask_nospec" = 1 ]; then
			pvulnstatus $cve OK "Kernel source has been patched to mitigate the vulnerability (array_index_mask_nospec)"
		elif [ "$v1_lfence" = 1 ]; then
			pvulnstatus $cve OK "Kernel source has PROBABLY been patched to mitigate the vulnerability (jump-then-lfence instructions heuristic)"
		elif [ "$vmlinux_err" ]; then
			pvulnstatus $cve UNK "Couldn't find kernel image or tools missing to execute the checks"
		else
			pvulnstatus $cve VULN "Kernel source needs to be patched to mitigate the vulnerability"
		fi
	else
		if [ "$msg" = "Vulnerable" ] && [ "$v1_mask_nospec" = 1 ]; then
			pvulnstatus $cve OK "Kernel source has been patched to mitigate the vulnerability (silent backport of array_index_mask_nospec)"
		else
			[ "$msg" = "Vulnerable" ] && msg="Kernel source needs to be patched to mitigate the vulnerability"
			pvulnstatus $cve "$status" "$msg"
		fi
	fi
}

###################
# SPECTRE VARIANT 2
check_variant2()
{
	_info "\033[1;34mCVE-2017-5715 [branch target injection] aka 'Spectre Variant 2'\033[0m"

	status=UNK
	sys_interface_available=0
	msg=''
	if sys_interface_check "/sys/devices/system/cpu/vulnerabilities/spectre_v2"; then
		# this kernel has the /sys interface, trust it over everything
		sys_interface_available=1
	fi
	if [ "$opt_sysfs_only" != 1 ]; then
		_info     "* Mitigation 1"
		_info_nol "  * Kernel is compiled with IBRS/IBPB support: "
		ibrs_can_tell=0

		if [ "$opt_live" = 1 ]; then
			ibrs_can_tell=1
			mount_debugfs
			for dir in \
				/sys/kernel/debug \
				/sys/kernel/debug/x86 \
				/proc/sys/kernel; do
				if [ -e "$dir/ibrs_enabled" ]; then
					# if the file is there, we have IBRS compiled-in
					# /sys/kernel/debug/ibrs_enabled: vanilla
					# /sys/kernel/debug/x86/ibrs_enabled: RedHat (see https://access.redhat.com/articles/3311301)
					# /proc/sys/kernel/ibrs_enabled: OpenSUSE tumbleweed
					pstatus green YES
					ibrs_knob_dir=$dir
					ibrs_supported=1
					ibrs_enabled=$(cat "$dir/ibrs_enabled" 2>/dev/null)
					_debug "ibrs: found $dir/ibrs_enabled=$ibrs_enabled"
					if [ -e "$dir/ibpb_enabled" ]; then
						ibpb_enabled=$(cat "$dir/ibpb_enabled" 2>/dev/null)
						_debug "ibpb: found $dir/ibpb_enabled=$ibpb_enabled"
					else
						ibpb_enabled=-1
						_debug "ibpb: no ibpb_enabled file in $dir"
					fi
					break
				else
					_debug "ibrs: $dir/ibrs_enabled file doesn't exist"
				fi
			done
			# on some newer kernels, the spec_ctrl_ibrs flag in /proc/cpuinfo
			# is set when ibrs has been administratively enabled (usually from cmdline)
			# which in that case means ibrs is supported *and* enabled for kernel & user
			# as per the ibrs patch series v3
			if [ "$ibrs_supported" = 0 ]; then
				if grep ^flags /proc/cpuinfo | grep -qw spec_ctrl_ibrs; then
					_debug "ibrs: found spec_ctrl_ibrs flag in /proc/cpuinfo"
					ibrs_supported=1
					# enabled=2 -> kernel & user
					ibrs_enabled=2
					# XXX and what about ibpb ?
				fi
			fi
		fi
		if [ "$ibrs_supported" != 1 ] && [ -n "$opt_map" ]; then
			ibrs_can_tell=1
			if grep -q spec_ctrl "$opt_map"; then
				pstatus green YES
				ibrs_supported=1
				_debug "ibrs: found '*spec_ctrl*' symbol in $opt_map"
			fi
		fi
		if [ "$ibrs_supported" != 1 ]; then
			if [ "$ibrs_can_tell" = 1 ]; then
				pstatus red NO
			else
				# if we're in offline mode without System.map, we can't really know
				pstatus yellow UNKNOWN "in offline mode, we need System.map to be able to tell"
			fi
		fi

		_info     "  * Currently enabled features"
		_info_nol "    * IBRS enabled for Kernel space: "
		if [ "$opt_live" = 1 ]; then
			if [ "$ibpb_enabled" = 2 ]; then
				# if ibpb=2, ibrs is forcefully=0
				pstatus blue NO "IBPB used instead of IBRS in all kernel entrypoints"
			else
				# 0 means disabled
				# 1 is enabled only for kernel space
				# 2 is enabled for kernel and user space
				case "$ibrs_enabled" in
					"")
						if [ "$ibrs_supported" = 1 ]; then
							pstatus yellow UNKNOWN
						else
							pstatus red NO
						fi
						;;
					0)
						pstatus red NO
						_verbose "    - To enable, \`echo 1 > $ibrs_knob_dir/ibrs_enabled' as root. If you don't have hardware support, you'll get an error."
						;;
					1 | 2) pstatus green YES;;
					*)     pstatus yellow UNKNOWN;;
				esac
			fi
		else
			pstatus blue N/A "not testable in offline mode"
		fi

		_info_nol "    * IBRS enabled for User space: "
		if [ "$opt_live" = 1 ]; then
			if [ "$ibpb_enabled" = 2 ]; then
				# if ibpb=2, ibrs is forcefully=0
				pstatus blue NO "IBPB used instead of IBRS in all kernel entrypoints"
			else
				case "$ibrs_enabled" in
					"")
						if [ "$ibrs_supported" = 1 ]; then
							pstatus yellow UNKNOWN
						else
							pstatus red NO
						fi
						;;
					0 | 1)
						pstatus red NO
						_verbose "    - To enable, \`echo 2 > $ibrs_knob_dir/ibrs_enabled' as root. If you don't have hardware support, you'll get an error."
						;;
					2) pstatus green YES;;
					*) pstatus yellow UNKNOWN;;
				esac
			fi
		else
			pstatus blue N/A "not testable in offline mode"
		fi

		_info_nol "    * IBPB enabled: "
		if [ "$opt_live" = 1 ]; then
			case "$ibpb_enabled" in
				"")
					if [ "$ibrs_supported" = 1 ]; then
						pstatus yellow UNKNOWN
					else
						pstatus red NO
					fi
					;;
				0)
					pstatus red NO
					_verbose "    - To enable, \`echo 1 > $ibrs_knob_dir/ibpb_enabled' as root. If you don't have hardware support, you'll get an error."
					;;
				1) pstatus green YES;;
				2) pstatus green YES "IBPB used instead of IBRS in all kernel entrypoints";;
				*) pstatus yellow UNKNOWN;;
			esac
		else
			pstatus blue N/A "not testable in offline mode"
		fi

		_info "* Mitigation 2"
		_info_nol "  * Kernel compiled with retpoline option: "
		# We check the RETPOLINE kernel options
		if [ -r "$opt_config" ]; then
			if grep -q '^CONFIG_RETPOLINE=y' "$opt_config"; then
				pstatus green YES
				retpoline=1
				# shellcheck disable=SC2046
				_debug 'retpoline: found '$(grep '^CONFIG_RETPOLINE' "$opt_config")" in $opt_config"
			else
				pstatus red NO
			fi
		else
			pstatus yellow UNKNOWN "couldn't read your kernel configuration"
		fi

		_info_nol "  * Kernel compiled with a retpoline-aware compiler: "
		# Now check if the compiler used to compile the kernel knows how to insert retpolines in generated asm
		# For gcc, this is -mindirect-branch=thunk-extern (detected by the kernel makefiles)
		# See gcc commit https://github.com/hjl-tools/gcc/commit/23b517d4a67c02d3ef80b6109218f2aadad7bd79
		# In latest retpoline LKML patches, the noretpoline_setup symbol exists only if CONFIG_RETPOLINE is set
		# *AND* if the compiler is retpoline-compliant, so look for that symbol
		if [ -e "/sys/devices/system/cpu/vulnerabilities/spectre_v2" ]; then
			if grep -qw Minimal /sys/devices/system/cpu/vulnerabilities/spectre_v2; then
				pstatus red NO "kernel reports minimal retpoline compilation"
			elif grep -qw Full /sys/devices/system/cpu/vulnerabilities/spectre_v2; then
				retpoline_compiler=1
				pstatus green YES "kernel reports full retpoline compilation"
			else
				if [ "$retpoline" = 1 ]; then
					pstatus yellow UNKNOWN
				else
					pstatus red NO
				fi
			fi
		elif [ -n "$opt_map" ]; then
			# look for the symbol
			if grep -qw noretpoline_setup "$opt_map"; then
				retpoline_compiler=1
				pstatus green YES "noretpoline_setup symbol found in System.map"
			else
				if [ "$retpoline" = 1 ]; then
					pstatus yellow UNKNOWN
				else
					pstatus red NO
				fi
			fi
		elif [ -n "$vmlinux" ]; then
			# look for the symbol
			if which nm >/dev/null 2>&1; then
				# the proper way: use nm and look for the symbol
				if nm "$vmlinux" 2>/dev/null | grep -qw 'noretpoline_setup'; then
					retpoline_compiler=1
					pstatus green YES "noretpoline_setup found in vmlinux symbols"
				else
					if [ "$retpoline" = 1 ]; then
						pstatus yellow UNKNOWN
					else
						pstatus red NO
					fi
				fi
			elif grep -q noretpoline_setup "$vmlinux"; then
				# if we don't have nm, nevermind, the symbol name is long enough to not have
				# any false positive using good old grep directly on the binary
				retpoline_compiler=1
				pstatus green YES "noretpoline_setup found in vmlinux"
			else
				if [ "$retpoline" = 1 ]; then
					pstatus yellow UNKNOWN
				else
					pstatus red NO
				fi
			fi
		else
			if [ "$retpoline" = 1 ]; then
				pstatus yellow UNKNOWN "couldn't find your kernel image or System.map"
			else
				pstatus red NO
			fi
		fi

		_info_nol "  * Retpoline enabled: "
		if [ "$opt_live" = 1 ]; then
			# kernel adds this flag when retpoline is supported and enabled,
			# regardless of the fact that it's minimal / full and generic / amd
			if grep -qw retpoline /proc/cpuinfo; then
				pstatus green YES
			else
				pstatus red NO
			fi
		else
			pstatus blue N/A "can't check this in offline mode"
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
	elif [ -z "$msg" ]; then
		# if msg is empty, sysfs check didn't fill it, rely on our own test
		if [ "$retpoline" = 1 ] && [ "$retpoline_compiler" = 1 ]; then
			pvulnstatus $cve OK "retpoline mitigates the vulnerability"
		elif [ "$opt_live" = 1 ]; then
			if ( [ "$ibrs_enabled" = 1 ] || [ "$ibrs_enabled" = 2 ] ) && [ "$ibpb_enabled" = 1 ]; then
				pvulnstatus $cve OK "IBRS/IBPB are mitigating the vulnerability"
			elif ( [ "$ibrs_enabled" = 1 ] || [ "$ibrs_enabled" = 2 ] ) && [ "$ibpb_enabled" = -1 ]; then
				# IBPB doesn't seem here on this kernel
				pvulnstatus $cve OK "IBRS is mitigating the vulnerability"
			elif [ "$ibpb_enabled" = 2 ]; then
				pvulnstatus $cve OK "Full IBPB is mitigating the vulnerability"
			else
				pvulnstatus $cve VULN "IBRS hardware + kernel support OR kernel with retpoline are needed to mitigate the vulnerability"
			fi
		else
			if [ "$ibrs_supported" = 1 ]; then
				pvulnstatus $cve OK "offline mode: IBRS/IBPB will mitigate the vulnerability if enabled at runtime"
			elif [ "$ibrs_can_tell" = 1 ]; then
				pvulnstatus $cve VULN "IBRS hardware + kernel support OR kernel with retpoline are needed to mitigate the vulnerability"
			else
				pvulnstatus $cve UNK "offline mode: not enough information"
			fi
		fi
	else
		[ "$msg" = "Vulnerable" ] && msg="IBRS hardware + kernel support OR kernel with retpoline are needed to mitigate the vulnerability"
		pvulnstatus $cve "$status" "$msg"
	fi
}

########################
# MELTDOWN aka VARIANT 3
check_variant3()
{
	_info "\033[1;34mCVE-2017-5754 [rogue data cache load] aka 'Meltdown' aka 'Variant 3'\033[0m"

	status=UNK
	sys_interface_available=0
	msg=''
	if sys_interface_check "/sys/devices/system/cpu/vulnerabilities/meltdown"; then
		# this kernel has the /sys interface, trust it over everything
		sys_interface_available=1
	fi
	if [ "$opt_sysfs_only" != 1 ]; then
		_info_nol "* Kernel supports Page Table Isolation (PTI): "
		kpti_support=0
		kpti_can_tell=0
		if [ -n "$opt_config" ]; then
			kpti_can_tell=1
			if grep -Eq '^(CONFIG_PAGE_TABLE_ISOLATION|CONFIG_KAISER)=y' "$opt_config"; then
				# shellcheck disable=SC2046
				_debug 'kpti_support: found option '$(grep -E '^(CONFIG_PAGE_TABLE_ISOLATION|CONFIG_KAISER)=y' "$opt_config")" in $opt_config"
				kpti_support=1
			fi
		fi
		if [ "$kpti_support" = 0 ] && [ -n "$opt_map" ]; then
			# it's not an elif: some backports don't have the PTI config but still include the patch
			# so we try to find an exported symbol that is part of the PTI patch in System.map
			kpti_can_tell=1
			if grep -qw kpti_force_enabled "$opt_map"; then
				_debug "kpti_support: found kpti_force_enabled in $opt_map"
				kpti_support=1
			fi
		fi
		if [ "$kpti_support" = 0 ] && [ -n "$vmlinux" ]; then
			# same as above but in case we don't have System.map and only vmlinux, look for the
			# nopti option that is part of the patch (kernel command line option)
			kpti_can_tell=1
			if ! which strings >/dev/null 2>&1; then
				pstatus yellow UNKNOWN "missing 'strings' tool, please install it, usually it's in the binutils package"
			else
				if strings "$vmlinux" | grep -qw nopti; then
					_debug "kpti_support: found nopti string in $vmlinux"
					kpti_support=1
				fi
			fi
		fi

		if [ "$kpti_support" = 1 ]; then
			pstatus green YES
		elif [ "$kpti_can_tell" = 1 ]; then
			pstatus red NO
		else
			pstatus yellow UNKNOWN "couldn't read your kernel configuration nor System.map file"
		fi

		mount_debugfs
		_info_nol "* PTI enabled and active: "
		if [ "$opt_live" = 1 ]; then
			dmesg_grep="Kernel/User page tables isolation: enabled"
			dmesg_grep="$dmesg_grep|Kernel page table isolation enabled"
			dmesg_grep="$dmesg_grep|x86/pti: Unmapping kernel while in userspace"
			if grep ^flags /proc/cpuinfo | grep -qw pti; then
				# vanilla PTI patch sets the 'pti' flag in cpuinfo
				_debug "kpti_enabled: found 'pti' flag in /proc/cpuinfo"
				kpti_enabled=1
			elif grep ^flags /proc/cpuinfo | grep -qw kaiser; then
				# kernel line 4.9 sets the 'kaiser' flag in cpuinfo
				_debug "kpti_enabled: found 'kaiser' flag in /proc/cpuinfo"
				kpti_enabled=1
			elif [ -e /sys/kernel/debug/x86/pti_enabled ]; then
				# RedHat Backport creates a dedicated file, see https://access.redhat.com/articles/3311301
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
				pstatus red NO
			fi
		else
			pstatus blue N/A "can't verify if PTI is enabled in offline mode"
		fi

		# no security impact but give a hint to the user in verbose mode
		# about PCID/INVPCID cpuid features that must be present to avoid
		# too big a performance impact with PTI
		# refs:
		# https://marc.info/?t=151532047900001&r=1&w=2
		# https://groups.google.com/forum/m/#!topic/mechanical-sympathy/L9mHTbeQLNU
		if [ "$opt_verbose" -ge 2 ]; then
			_info "* Performance impact if PTI is enabled"
			_info_nol "  * CPU supports PCID: "
			if grep ^flags /proc/cpuinfo | grep -qw pcid; then
				pstatus green YES 'performance degradation with PTI will be limited'
			else
				pstatus blue NO 'no security impact but performance will be degraded with PTI'
			fi
			_info_nol "  * CPU supports INVPCID: "
			if grep ^flags /proc/cpuinfo | grep -qw invpcid; then
				pstatus green YES 'performance degradation with PTI will be limited'
			else
				pstatus blue NO 'no security impact but performance will be degraded with PTI'
			fi
		fi
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
		fi
	fi

	if [ "$opt_live" = 1 ]; then
		# checking whether we're running under Xen PV 64 bits. If yes, we are affected by variant3
		# (unless we are a Dom0)
		_info_nol "* Running as a Xen PV DomU: "
		if [ "$xen_pv_domu" = 1 ]; then
			pstatus red YES
		else
			pstatus green NO
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
				pvulnstatus $cve VULN "Xen PV DomUs are vulnerable and need to be run in HVM, PVHVM or PVH mode"
			else
				pvulnstatus $cve VULN "PTI is needed to mitigate the vulnerability"
			fi
		else
			if [ "$kpti_support" = 1 ]; then
				pvulnstatus $cve OK "offline mode: PTI will mitigate the vulnerability if enabled at runtime"
			elif [ "$kpti_can_tell" = 1 ]; then
				pvulnstatus $cve VULN "PTI is needed to mitigate the vulnerability"
			else
				pvulnstatus $cve UNK "offline mode: not enough information"
			fi
		fi
	else
		if [ "$xen_pv_domo" = 1 ]; then
			msg="Xen Dom0s are safe and do not require PTI"
			status="OK"
		elif [ "$xen_pv_domu" = 1 ]; then
			msg="Xen PV DomUs are vulnerable and need to be run in HVM, PVHVM or PVH mode"
			status="VULN"
		elif [ "$msg" = "Vulnerable" ]; then
			msg="PTI is needed to mitigate the vulnerability"
		fi
		pvulnstatus $cve "$status" "$msg"
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

check_cpu
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

# exit with the proper exit code
[ "$global_critical" = 1 ] && exit 2  # critical
[ "$global_unknown"  = 1 ] && exit 3  # unknown
exit 0  # ok
