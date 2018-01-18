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
VERSION=0.31

show_usage()
{
	cat <<EOF
	Usage:
		Live mode:    `basename $0` [options] [--live]
		Offline mode: `basename $0` [options] [--kernel <vmlinux_file>] [--config <kernel_config>] [--map <kernel_map_file>]

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
vulnerabilities (except some specific ARM models). All Intel processors manufactured since circa 1995 are thought to be vulnerable.
Whatever processor one uses, one might seek more information from the manufacturer of that processor and/or of the device
in which it runs.

The nature of the discovered vulnerabilities being quite new, the landscape of vulnerable processors can be expected
to change over time, which is why this script makes the assumption that all CPUs are vulnerable, except if the manufacturer
explicitly stated otherwise in a verifiable public announcement.

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
opt_coreos=0

global_critical=0
global_unknown=0
nrpe_vuln=""

__echo()
{
	opt="$1"
	shift
	_msg="$@"
	if [ "$opt_no_color" = 1 ] ; then
		# strip ANSI color codes
		_msg=$(/bin/echo -e  "$_msg" | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g")
	fi
	# explicitly call /bin/echo to avoid shell builtins that might not take options
	/bin/echo $opt -e "$_msg"
}

_echo()
{
	if [ $opt_verbose -ge $1 ]; then
		shift
		__echo '' "$@"
	fi
}

_echo_nol()
{
	if [ $opt_verbose -ge $1 ]; then
		shift
		__echo -n "$@"
	fi
}

_warn()
{
	_echo 0 "\033[31m${@}\033[0m" >&2
}

_info()
{
	_echo 1 "$@"
}

_info_nol()
{
	_echo_nol 1 "$@"
}

_verbose()
{
	_echo 2 "$@"
}

_verbose_nol()
{
	_echo_nol 2 "$@"
}

_debug()
{
	_echo 3 "\033[34m(debug) $@\033[0m"
}

is_cpu_vulnerable()
{
	# param: 1, 2 or 3 (variant)
	# returns 0 if vulnerable, 1 if not vulnerable
	# (note that in shell, a return of 0 is success)
	# by default, everything is vulnerable, we work in a "whitelist" logic here.
	# usage: is_cpu_vulnerable 2 && do something if vulnerable
	variant1=0
	variant2=0
	variant3=0

	if grep -q GenuineIntel /proc/cpuinfo; then
		# Intel
		# Old Atoms are not vulnerable to spectre 2 nor meltdown
		# https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00088&languageid=en-fr
		# model name : Genuine Intel(R) CPU N270 @ 1.60GHz
		# model name : Intel(R) Atom(TM) CPU 330 @ 1.60GHz
		if grep -qE '^model name.+ Intel\(R\) (Atom\(TM\) CPU +(S|D|230|330)|CPU N[0-9]{3} )' /proc/cpuinfo; then
			variant2=1
			variant3=1
		fi
	elif grep -q AuthenticAMD /proc/cpuinfo; then
		# AMD revised their statement about variant2 => vulnerable
		# https://www.amd.com/en/corporate/speculative-execution
		variant3=1
	elif grep -qi 'CPU implementer\s*:\s*0x41' /proc/cpuinfo; then
		# ARM
		# reference: https://developer.arm.com/support/security-update
		cpupart=$(awk '/CPU part/         {print $4;exit}' /proc/cpuinfo)
		cpuarch=$(awk '/CPU architecture/ {print $3;exit}' /proc/cpuinfo)
		if [ -n "$cpupart" -a -n "$cpuarch" ]; then
			# Cortex-R7 and Cortex-R8 are real-time and only used in medical devices or such
			# I can't find their CPU part number, but it's probably not that useful anyway
			# model R7 R8 A9    A15   A17   A57   A72    A73    A75
			# part   ?  ? 0xc09 0xc0f 0xc0e 0xd07 0xd08  0xd09  0xd0a
			# arch  7? 7? 7     7     7     8     8      8      8
			if [ "$cpuarch" = 7 ] && echo "$cpupart" | grep -Eq '^0x(c09|c0f|c0e)$'; then
				# armv7 vulnerable chips
				:
			elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -Eq '^0x(d07|d08|d09|d0a)$'; then
				# armv8 vulnerable chips
				:
			else
				# others are not vulnerable
				variant1=1
				variant2=1
			fi
			# for variant3, only A75 is vulnerable
			if ! [ "$cpuarch" = 8 -a "$cpupart" = 0xd0a ]; then
				variant3=1
			fi
		fi
	fi

	[ "$1" = 1 ] && return $variant1
	[ "$1" = 2 ] && return $variant2
	[ "$1" = 3 ] && return $variant3
	echo "$0: error: invalid variant '$1' passed to is_cpu_vulnerable()" >&2
	exit 255
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
		opt_kernel=$(parse_opt_file kernel "$2")
		[ $? -ne 0 ] && exit 255
		shift 2
		opt_live=0
	elif [ "$1" = "--config" ]; then
		opt_config=$(parse_opt_file config "$2")
		[ $? -ne 0 ] && exit 255
		shift 2
		opt_live=0
	elif [ "$1" = "--map" ]; then
		opt_map=$(parse_opt_file map "$2")
		[ $? -ne 0 ] && exit 255
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
	elif [ "$1" = "-v" -o "$1" = "--verbose" ]; then
		opt_verbose=$(expr $opt_verbose + 1)
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
	elif [ "$1" = "-h" -o "$1" = "--help" ]; then
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

# print status function
pstatus()
{
	if [ "$opt_no_color" = 1 ]; then
		_info_nol "$2"
	else
		case "$1" in
			red)    col="\033[101m\033[30m";;
			green)  col="\033[102m\033[30m";;
			yellow) col="\033[103m\033[30m";;
			blue)   col="\033[104m\033[30m";;
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
				json_output="${json_output:-[}{\"NAME\":\""$aka"\",\"CVE\":\""$1"\",\"VULNERABLE\":$is_vuln,\"INFOS\":\""$3"\"},"
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
	readelf -h "$1" > /dev/null 2>&1 || return 1
	return 0
}

try_decompress()
{
	# The obscure use of the "tr" filter is to work around older versions of
	# "grep" that report the byte offset of the line instead of the pattern.

	# Try to find the header ($1) and decompress from here
	for     pos in `tr "$1\n$2" "\n$2=" < "$6" | grep -abo "^$2"`
	do
		_debug "try_decompress: magic for $3 found at offset $pos"
		if ! which "$3" >/dev/null 2>&1; then
			vmlinux_err="missing '$3' tool, please install it, usually it's in the '$5' package"
			return 0
		fi
		pos=${pos%%:*}
		tail -c+$pos "$6" 2>/dev/null | $3 $4 > $vmlinuxtmp 2>/dev/null
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
	trap "rm -f $vmlinuxtmp" EXIT

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

umount_debugfs()
{
	if [ "$mounted_debugfs" = 1 ]; then
		# umount debugfs if we did mount it ourselves
		umount /sys/kernel/debug
	fi
}

load_msr()
{
	modprobe msr 2>/dev/null && insmod_msr=1
	_debug "attempted to load module msr, insmod_msr=$insmod_msr"
}

unload_msr()
{
	if [ "$insmod_msr" = 1 ]; then
		# if we used modprobe ourselves, rmmod the module
		rmmod msr 2>/dev/null
		_debug "attempted to unload module msr, ret=$?"
	fi
}

load_cpuid()
{
	modprobe cpuid 2>/dev/null && insmod_cpuid=1
	_debug "attempted to load module cpuid, insmod_cpuid=$insmod_cpuid"
}

unload_cpuid()
{
	if [ "$insmod_cpuid" = 1 ]; then
		# if we used modprobe ourselves, rmmod the module
		rmmod cpuid 2>/dev/null
		_debug "attempted to unload module cpuid, ret=$?"
	fi
}

is_coreos()
{
	which coreos-install >/dev/null 2>&1 && which toolbox >/dev/null 2>&1 && return 0
	return 1
}

# check for mode selection inconsistency
if [ "$opt_live_explicit" = 1 ]; then
	if [ -n "$opt_kernel" -o -n "$opt_config" -o -n "$opt_map" ]; then
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
	toolbox --ephemeral --bind-ro /dev/cpu:/dev/cpu -- sh -c "dnf install -y binutils which && /media/root$PWD/$0 $@ --coreos-within-toolbox"
	exitcode=$?
	mount_debugfs
	unload_cpuid
	unload_msr
	exit $exitcode
else
	if is_coreos; then
		_warn "You seem to be running CoreOS, you might want to use the --coreos option for better results"
		_warn
	fi
fi

# root check (only for live mode, for offline mode, we already checked if we could read the files)

if [ "$opt_live" = 1 ]; then
	if [ "$(id -u)" -ne 0 ]; then
		_warn "Note that you should launch this script with root privileges to get accurate information."
		_warn "We'll proceed but you might see permission denied errors."
		_warn "To run it as root, you can try the following command: sudo $0"
		_warn
	fi
	_info "Checking for vulnerabilities against running kernel \033[35m"$(uname -s) $(uname -r) $(uname -v) $(uname -m)"\033[0m"
	_info "CPU is\033[35m"$(grep '^model name' /proc/cpuinfo | cut -d: -f2 | head -1)"\033[0m"

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
		[ -e /boot/vmlinuz             ] && opt_kernel=/boot/vmlinuz
		[ -e /boot/vmlinuz-linux       ] && opt_kernel=/boot/vmlinuz-linux
		[ -e /boot/vmlinuz-linux-libre ] && opt_kernel=/boot/vmlinuz-linux-libre
		[ -e /boot/vmlinuz-$(uname -r) ] && opt_kernel=/boot/vmlinuz-$(uname -r)
		[ -e /boot/kernel-$( uname -r) ] && opt_kernel=/boot/kernel-$( uname -r)
		[ -e /boot/bzImage-$(uname -r) ] && opt_kernel=/boot/bzImage-$(uname -r)
		[ -e /boot/kernel-genkernel-$(uname -m)-$(uname -r) ] && opt_kernel=/boot/kernel-genkernel-$(uname -m)-$(uname -r)
		[ -e /run/booted-system/kernel ] && opt_kernel=/run/booted-system/kernel
	fi

	# system.map
	if [ -e /proc/kallsyms ] ; then
		opt_map="/proc/kallsyms"
	elif [ -e /boot/System.map-$(uname -r) ] ; then
		opt_map=/boot/System.map-$(uname -r)
	fi

	# config
	if [ -e /proc/config.gz ] ; then
		dumped_config="$(mktemp /tmp/config-XXXXXX)"
		gunzip -c /proc/config.gz > $dumped_config
		# dumped_config will be deleted at the end of the script
		opt_config=$dumped_config
	elif [ -e /boot/config-$(uname -r) ]; then
		opt_config=/boot/config-$(uname -r)
	fi
else
	_info "Checking for vulnerabilities against specified kernel"
fi

if [ -n "$opt_kernel" ]; then
	_verbose "Will use vmlinux image \033[35m$opt_kernel\033[0m"
else
	_verbose "Will use no vmlinux image (accuracy might be reduced)"
	bad_accuracy=1
fi
if [ -n "$dumped_config" ]; then
	_verbose "Will use kconfig \033[35m/proc/config.gz\033[0m"
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
	else
		extract_vmlinux "$opt_kernel"
	fi
else
	_debug "no opt_kernel defined"
	vmlinux_err="couldn't find your kernel image in /boot, if you used netboot, this is normal"
fi
if [ -z "$vmlinux" -o ! -r "$vmlinux" ]; then
	[ -z "$vmlinux_err" ] && vmlinux_err="couldn't extract your kernel from $opt_kernel"
fi

_info

# end of header stuff

# now we define some util functions and the check_*() funcs, as
# the user can choose to execute only some of those

sys_interface_check()
{
	[ "$opt_live" = 1 -a "$opt_no_sysfs" = 0 -a -r "$1" ] || return 1
	_info_nol "* Checking whether we're safe according to the /sys interface: "
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
		sys_interface_available=1
	else
		# no /sys interface (or offline mode), fallback to our own ways
		_info_nol "* Checking count of LFENCE opcodes in kernel: "
		if [ -n "$vmlinux_err" ]; then
			msg="couldn't check ($vmlinux_err)"
			status=UNK
			pstatus yellow UNKNOWN
		else
			if ! which objdump >/dev/null 2>&1; then
				msg="missing 'objdump' tool, please install it, usually it's in the binutils package"
				status=UNK
				pstatus yellow UNKNOWN
			else
				# here we disassemble the kernel and count the number of occurrences of the LFENCE opcode
				# in non-patched kernels, this has been empirically determined as being around 40-50
				# in patched kernels, this is more around 70-80, sometimes way higher (100+)
				# v0.13: 68 found in a 3.10.23-xxxx-std-ipv6-64 (with lots of modules compiled-in directly), which doesn't have the LFENCE patches,
				# so let's push the threshold to 70.
				nb_lfence=$(objdump -d "$vmlinux" | grep -wc lfence)
				if [ "$nb_lfence" -lt 70 ]; then
					msg="only $nb_lfence opcodes found, should be >= 70, heuristic to be improved when official patches become available"
					status=VULN
					pstatus red NO
				else
					msg="$nb_lfence opcodes found, which is >= 70, heuristic to be improved when official patches become available"
					status=OK
					pstatus green YES
				fi
			fi
		fi
	fi

	# if we have the /sys interface, don't even check is_cpu_vulnerable ourselves, the kernel already does it
	if [ "$sys_interface_available" = 0 ] && ! is_cpu_vulnerable 1; then
		# override status & msg in case CPU is not vulnerable after all
		msg="your CPU vendor reported your CPU model as not vulnerable"
		status=OK
	fi

	# report status
	pvulnstatus CVE-2017-5753 "$status" "$msg"
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
	else
		_info "* Mitigation 1"
		_info "*   Hardware (CPU microcode) support for mitigation"
		_info_nol "*     The SPEC_CTRL MSR is available: "
		if [ ! -e /dev/cpu/0/msr ]; then
			# try to load the module ourselves (and remember it so we can rmmod it afterwards)
			load_msr
		fi
		if [ ! -e /dev/cpu/0/msr ]; then
			pstatus yellow UNKNOWN "couldn't read /dev/cpu/0/msr, is msr support enabled in your kernel?"
		else
			# the new MSR 'SPEC_CTRL' is at offset 0x48
			# here we use dd, it's the same as using 'rdmsr 0x48' but without needing the rdmsr tool
			# if we get a read error, the MSR is not there
			dd if=/dev/cpu/0/msr of=/dev/null bs=8 count=1 skip=9 2>/dev/null
			if [ $? -eq 0 ]; then
				pstatus green YES
			else
				pstatus red NO
			fi
		fi

		unload_msr

		# CPUID test
		_info_nol "*     The SPEC_CTRL CPUID feature bit is set: "
		if [ ! -e /dev/cpu/0/cpuid ]; then
			# try to load the module ourselves (and remember it so we can rmmod it afterwards)
			load_cpuid
		fi
		if [ ! -e /dev/cpu/0/cpuid ]; then
			pstatus yellow UNKNOWN "couldn't read /dev/cpu/0/cpuidr, is cpuid support enabled in your kernel?"
		else
			# from kernel src: { X86_FEATURE_SPEC_CTRL,        CPUID_EDX,26, 0x00000007, 0 },
			if [ "$opt_verbose" -ge 3 ]; then
				dd if=/dev/cpu/0/cpuid bs=16 skip=7 iflag=skip_bytes count=1 >/dev/null 2>/dev/null
				_debug "cpuid: reading leaf7 of cpuid on cpu0, ret=$?"
				_debug "cpuid: leaf7 eax-ebx-ecd-edx: "$(dd if=/dev/cpu/0/cpuid bs=16 skip=7 iflag=skip_bytes count=1 2>/dev/null | od -x -A n)
				_debug "cpuid: leaf7 edx higher-half is: "$(dd if=/dev/cpu/0/cpuid bs=16 skip=7 iflag=skip_bytes count=1 2>/dev/null | dd bs=1 skip=15 count=1 2>/dev/null | od -x -A n)
			fi
			# getting high byte of edx on leaf7 of cpuinfo in decimal
			edx_hb=$(dd if=/dev/cpu/0/cpuid bs=16 skip=7 iflag=skip_bytes count=1 2>/dev/null | dd bs=1 skip=15 count=1 2>/dev/null | od -t u -A n | awk '{print $1}')
			_debug "cpuid: leaf7 edx higher byte: $edx_hb (decimal)"
			edx_bit26=$(( edx_hb & 8 ))
			_debug "cpuid: edx_bit26=$edx_bit26"
			if [ "$edx_bit26" -eq 8 ]; then
				pstatus green YES
			else
				pstatus red NO
			fi
		fi
		unload_cpuid

		# hardware support according to kernel
		if [ "$opt_verbose" -ge 2 ]; then
			_verbose_nol "*     The kernel has set the spec_ctrl flag in cpuinfo: "
			if [ "$opt_live" = 1 ]; then
				if grep ^flags /proc/cpuinfo | grep -qw spec_ctrl; then
					pstatus green YES
				else
					pstatus red NO
				fi
			else
				pstatus blue N/A "not testable in offline mode"
			fi
		fi

		_info_nol "*   Kernel support for IBRS: "
		if [ "$opt_live" = 1 ]; then
			mount_debugfs
			for ibrs_file in \
				/sys/kernel/debug/ibrs_enabled \
				/sys/kernel/debug/x86/ibrs_enabled \
				/proc/sys/kernel/ibrs_enabled; do
				if [ -e "$ibrs_file" ]; then
					# if the file is there, we have IBRS compiled-in
					# /sys/kernel/debug/ibrs_enabled: vanilla
					# /sys/kernel/debug/x86/ibrs_enabled: RedHat (see https://access.redhat.com/articles/3311301)
					# /proc/sys/kernel/ibrs_enabled: OpenSUSE tumbleweed
					pstatus green YES
					ibrs_supported=1
					ibrs_enabled=$(cat "$ibrs_file" 2>/dev/null)
					_debug "ibrs: found $ibrs_file=$ibrs_enabled"
					break
				else
					_debug "ibrs: file $ibrs_file doesn't exist"
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
				fi
			fi
		fi
		if [ "$ibrs_supported" != 1 -a -n "$opt_map" ]; then
			if grep -q spec_ctrl "$opt_map"; then
				pstatus green YES
				ibrs_supported=1
				_debug "ibrs: found '*spec_ctrl*' symbol in $opt_map"
			fi
		fi
		if [ "$ibrs_supported" != 1 ]; then
			pstatus red NO
		fi

		_info_nol "*   IBRS enabled for Kernel space: "
		if [ "$opt_live" = 1 ]; then
			# 0 means disabled
			# 1 is enabled only for kernel space
			# 2 is enabled for kernel and user space
			case "$ibrs_enabled" in
				"") [ "$ibrs_supported" = 1 ] && pstatus yellow UNKNOWN || pstatus red NO;;
				0)     pstatus red NO;;
				1 | 2) pstatus green YES;;
				*)     pstatus yellow UNKNOWN;;
			esac
		else
			pstatus blue N/A "not testable in offline mode"
		fi

		_info_nol "*   IBRS enabled for User space: "
		if [ "$opt_live" = 1 ]; then
			case "$ibrs_enabled" in
				"") [ "$ibrs_supported" = 1 ] && pstatus yellow UNKNOWN || pstatus red NO;;
				0 | 1) pstatus red NO;;
				2) pstatus green YES;;
				*) pstatus yellow UNKNOWN;;
			esac
		else
			pstatus blue N/A "not testable in offline mode"
		fi

		_info "* Mitigation 2"
		_info_nol "*   Kernel compiled with retpoline option: "
		# We check the RETPOLINE kernel options
		if [ -r "$opt_config" ]; then
			if grep -q '^CONFIG_RETPOLINE=y' "$opt_config"; then
				pstatus green YES
				retpoline=1
				_debug "retpoline: found "$(grep '^CONFIG_RETPOLINE' "$opt_config")" in $opt_config"
			else
				pstatus red NO
			fi
		else
			pstatus yellow UNKNOWN "couldn't read your kernel configuration"
		fi

		_info_nol "*   Kernel compiled with a retpoline-aware compiler: "
		# Now check if the compiler used to compile the kernel knows how to insert retpolines in generated asm
		# For gcc, this is -mindirect-branch=thunk-extern (detected by the kernel makefiles)
		# See gcc commit https://github.com/hjl-tools/gcc/commit/23b517d4a67c02d3ef80b6109218f2aadad7bd79
		# In latest retpoline LKML patches, the noretpoline_setup symbol exists only if CONFIG_RETPOLINE is set
		# *AND* if the compiler is retpoline-compliant, so look for that symbol
		if [ -n "$opt_map" ]; then
			# look for the symbol
			if grep -qw noretpoline_setup "$opt_map"; then
				retpoline_compiler=1
				pstatus green YES "noretpoline_setup symbol found in System.map"
			else
				pstatus red NO
			fi
		elif [ -n "$vmlinux" ]; then
			# look for the symbol
			if which nm >/dev/null 2>&1; then
				# the proper way: use nm and look for the symbol
				if nm "$vmlinux" 2>/dev/null | grep -qw 'noretpoline_setup'; then
					retpoline_compiler=1
					pstatus green YES "noretpoline_setup found in vmlinux symbols"
				else
					pstatus red NO
				fi
			elif grep -q noretpoline_setup "$vmlinux"; then
				# if we don't have nm, nevermind, the symbol name is long enough to not have
				# any false positive using good old grep directly on the binary
				retpoline_compiler=1
				pstatus green YES "noretpoline_setup found in vmlinux"
			else
				pstatus red NO
			fi
		else
			pstatus yellow UNKNOWN "couldn't find your kernel image or System.map"
		fi
	fi

	# if we have the /sys interface, don't even check is_cpu_vulnerable ourselves, the kernel already does it
	if [ "$sys_interface_available" = 0 ] && ! is_cpu_vulnerable 2; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus CVE-2017-5715 OK "your CPU vendor reported your CPU model as not vulnerable"
	elif [ -z "$msg" ]; then
		# if msg is empty, sysfs check didn't fill it, rely on our own test
		if [ "$retpoline" = 1 -a "$retpoline_compiler" = 1 ]; then
			pvulnstatus CVE-2017-5715 OK "retpoline mitigate the vulnerability"
		elif [ "$opt_live" = 1 ]; then
			if [ "$ibrs_enabled" = 1 -o "$ibrs_enabled" = 2 ]; then
				pvulnstatus CVE-2017-5715 OK "IBRS mitigates the vulnerability"
			else
				pvulnstatus CVE-2017-5715 VULN "IBRS hardware + kernel support OR kernel with retpoline are needed to mitigate the vulnerability"
			fi
		else
			if [ "$ibrs_supported" = 1 ]; then
				pvulnstatus CVE-2017-5715 OK "offline mode: IBRS will mitigate the vulnerability if enabled at runtime"
			else
				pvulnstatus CVE-2017-5715 VULN "IBRS hardware + kernel support OR kernel with retpoline are needed to mitigate the vulnerability"
			fi
		fi
	else
		pvulnstatus CVE-2017-5715 "$status" "$msg"
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
	else
		_info_nol "* Kernel supports Page Table Isolation (PTI): "
		kpti_support=0
		kpti_can_tell=0
		if [ -n "$opt_config" ]; then
			kpti_can_tell=1
			if grep -Eq '^(CONFIG_PAGE_TABLE_ISOLATION|CONFIG_KAISER)=y' "$opt_config"; then
				_debug "kpti_support: found option "$(grep -E '^(CONFIG_PAGE_TABLE_ISOLATION|CONFIG_KAISER)=y' "$opt_config")" in $opt_config"
				kpti_support=1
			fi
		fi
		if [ "$kpti_support" = 0 -a -n "$opt_map" ]; then
			# it's not an elif: some backports don't have the PTI config but still include the patch
			# so we try to find an exported symbol that is part of the PTI patch in System.map
			kpti_can_tell=1
			if grep -qw kpti_force_enabled "$opt_map"; then
				_debug "kpti_support: found kpti_force_enabled in $opt_map"
				kpti_support=1
			fi
		fi
		if [ "$kpti_support" = 0 -a -n "$vmlinux" ]; then
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
			elif dmesg | grep -Eq "$dmesg_grep"; then
				# if we can't find the flag, grep dmesg output
				_debug "kpti_enabled: found hint in dmesg: "$(dmesg | grep -E "$dmesg_grep")
				kpti_enabled=1
			elif [ -r /var/log/dmesg ] && grep -Eq "$dmesg_grep" /var/log/dmesg; then
				# if we can't find the flag in dmesg output, grep in /var/log/dmesg when readable
				_debug "kpti_enabled: found hint in /var/log/dmesg: "$(grep -E "$dmesg_grep" /var/log/dmesg)
				kpti_enabled=1
			elif [ -r /var/log/kern.log ] && grep -Eq "$dmesg_grep" /var/log/kern.log; then
				# if we can't find the flag in dmesg output, grep in /var/log/kern.log when readable
				_debug "kpti_enabled: found hint in /var/log/kern.log: "$(grep -E "$dmesg_grep" /var/log/kern.log)
				kpti_enabled=1
			else
				_debug "kpti_enabled: couldn't find any hint that PTI is enabled"
				kpti_enabled=0
			fi
			if [ "$kpti_enabled" = 1 ]; then
				pstatus green YES
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
			_info_nol "*   CPU supports PCID: "
			if grep ^flags /proc/cpuinfo | grep -qw pcid; then
				pstatus green YES 'performance degradation with PTI will be limited'
			else
				pstatus blue NO 'no security impact but performance will be degraded with PTI'
			fi
			_info_nol "*   CPU supports INVPCID: "
			if grep ^flags /proc/cpuinfo | grep -qw invpcid; then
				pstatus green YES 'performance degradation with PTI will be limited'
			else
				pstatus blue NO 'no security impact but performance will be degraded with PTI'
			fi
		fi

		if [ "$opt_live" = 1 ]; then
			# checking whether we're running under Xen PV 64 bits. If yes, we're not affected by variant3
			_info_nol "* Checking if we're running under Xen PV (64 bits): "
			if [ "$(uname -m)" = "x86_64" ]; then
				# XXX do we have a better way that relying on dmesg?
				if dmesg | grep -q 'Booting paravirtualized kernel on Xen$' ; then
					pstatus green YES 'Xen PV is not vulnerable'
					xen_pv=1
				elif [ -r /var/log/dmesg ] && grep -q 'Booting paravirtualized kernel on Xen$' /var/log/dmesg; then
					pstatus green YES 'Xen PV is not vulnerable'
					xen_pv=1
				elif [ -r /var/log/kern.log ] && grep -q 'Booting paravirtualized kernel on Xen$' /var/log/kern.log; then
					pstatus green YES 'Xen PV is not vulnerable'
					xen_pv=1
				else
					pstatus blue NO
				fi
			else
				pstatus blue NO
			fi
		fi
	fi

	# if we have the /sys interface, don't even check is_cpu_vulnerable ourselves, the kernel already does it
	cve='CVE-2017-5754'
	if [ "$sys_interface_available" = 0 ] && ! is_cpu_vulnerable 3; then
		# override status & msg in case CPU is not vulnerable after all
		pvulnstatus $cve OK "your CPU vendor reported your CPU model as not vulnerable"
	elif [ -z "$msg" ]; then
		# if msg is empty, sysfs check didn't fill it, rely on our own test
		if [ "$opt_live" = 1 ]; then
			if [ "$kpti_enabled" = 1 ]; then
				pvulnstatus $cve OK "PTI mitigates the vulnerability"
			elif [ "$xen_pv" = 1 ]; then
				pvulnstatus $cve OK "Xen PV 64 bits is not vulnerable"
			else
				pvulnstatus $cve VULN "PTI is needed to mitigate the vulnerability"
			fi
		else
			if [ "$kpti_support" = 1 ]; then
				pvulnstatus $cve OK "offline mode: PTI will mitigate the vulnerability if enabled at runtime"
			else
				pvulnstatus $cve VULN "PTI is needed to mitigate the vulnerability"
			fi
		fi
	else
		pvulnstatus $cve "$status" "$msg"
	fi
}

# now run the checks the user asked for
if [ "$opt_variant1" = 1 -o "$opt_allvariants" = 1 ]; then
	check_variant1
	_info
fi
if [ "$opt_variant2" = 1 -o "$opt_allvariants" = 1 ]; then
	check_variant2
	_info
fi
if [ "$opt_variant3" = 1 -o "$opt_allvariants" = 1 ]; then
	check_variant3
	_info
fi

_info "A false sense of security is worse than no security at all, see --disclaimer"

# this'll umount only if we mounted debugfs ourselves
umount_debugfs

# cleanup the temp decompressed config
[ -n "$dumped_config" ] && rm -f "$dumped_config"

if [ "$opt_batch" = 1 -a "$opt_batch_format" = "nrpe" ]; then
	if [ ! -z "$nrpe_vuln" ]; then
		echo "Vulnerable:$nrpe_vuln"
	else
		echo "OK"
	fi
fi

if [ "$opt_batch" = 1 -a "$opt_batch_format" = "json" ]; then
	_echo 0 ${json_output%?}']'
fi

# exit with the proper exit code
[ "$global_critical" = 1 ] && exit 2  # critical
[ "$global_unknown"  = 1 ] && exit 3  # unknown
exit 0  # ok
