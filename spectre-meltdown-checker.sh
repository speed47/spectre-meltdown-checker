#! /bin/sh
# Spectre & Meltdown checker
# Stephane Lesimple
VERSION=0.17

# print status function
pstatus()
{
	case "$1" in
		red)    col="\033[101m\033[30m";;
		green)  col="\033[102m\033[30m";;
		yellow) col="\033[103m\033[30m";;
		blue)   col="\033[104m\033[30m";;
		*)      col="";;
	esac
	/bin/echo -ne "$col $2 \033[0m"
	[ -n "$3" ] && /bin/echo -n " ($3)"
	/bin/echo
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
	readelf -h $1 > /dev/null 2>&1 || return 1
	return 0
}

try_decompress()
{
	# The obscure use of the "tr" filter is to work around older versions of
	# "grep" that report the byte offset of the line instead of the pattern.

	# Try to find the header ($1) and decompress from here
	for     pos in `tr "$1\n$2" "\n$2=" < "$5" | grep -abo "^$2"`
	do
		if ! which $3 >/dev/null 2>&1; then
			vmlinux_err="missing '$3' tool, please install it, usually it's in the '$4' package"
			return 0
		fi
		pos=${pos%%:*}
		tail -c+$pos "$5" | $3 > $vmlinuxtmp 2> /dev/null
		check_vmlinux "$vmlinuxtmp" && vmlinux=$vmlinuxtmp && return 0
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
	try_decompress '\037\213\010' xy    gunzip     gunzip	"$1" && return 0
	try_decompress '\3757zXZ\000' abcde unxz       xz-utils	"$1" && return 0
	try_decompress 'BZh'          xy    bunzip2    bzip2	"$1" && return 0
	try_decompress '\135\0\0\0'   xxx   unlzma     xz-utils	"$1" && return 0
	try_decompress '\211\114\132' xy    'lzop -d'  lzop	"$1" && return 0
	return 1
}

# end of extract-vmlinux functions

show_usage()
{
	cat <<EOF
	Usage:
		Live mode:    $0
		Offline mode: $0 [--kernel <vmlinux_file>] [--config <kernel_config>] [--map <kernel_map_file>]
	Options:
		Two modes are available.

		First mode is the "live" mode (default), it does its best to find information about the currently running kernel.
		To run under this mode, just start the script without any option.

		Second mode is the "offline" mode, where you can inspect a non-running kernel.
		You'll need to specify the location of the vmlinux file, and if possible, the corresponding config and System.map files:

		--kernel vmlinux_file		Specify a (possibly compressed) vmlinux file
		--config kernel_config		Specify a kernel config file
		--map	 kernel_map_file	Specify a kernel System.map file

EOF
}

/bin/echo -e "\033[1;34mSpectre and Meltdown mitigation detection tool v$VERSION\033[0m"
/bin/echo

# parse options
opt_kernel=''
opt_config=''
opt_map=''
opt_live=1

parse_opt_file()
{
	# parse_opt_file option_name option_value
	option_name="$1"
	option_value="$2"
	if [ -z "$option_value" ]; then
		show_usage
		echo "$0: error: --$option_name expects one parameter (a file)" >&2
		exit 1
	elif [ ! -e "$option_value" ]; then
		echo "$0: error: couldn't find file $option_value" >&2
		exit 1
	elif [ ! -f "$option_value" ]; then
		echo "$0: error: $option_value is not a file" >&2
		exit 1
	elif [ ! -e "$option_value" ]; then
		echo "$0: error: couldn't read $option_value (are you root?)" >&2
		exit 1
	fi
	echo "$option_value"
	exit 0
}

while [ -n "$1" ]; do
	if [ "$1" = "--kernel" ]; then
		opt_kernel=$(parse_opt_file kernel "$2")
		[ $? -ne 0 ] && exit $?
		shift 2
		opt_live=0
	elif [ "$1" = "--config" ]; then
		opt_config=$(parse_opt_file config "$2")
		[ $? -ne 0 ] && exit $?
		shift 2
		opt_live=0
	elif [ "$1" = "--map" ]; then
		opt_map=$(parse_opt_file map "$2")
		[ $? -ne 0 ] && exit $?
		shift 2
		opt_live=0
	elif [ "$1" = "-h" -o "$1" = "--help" ]; then
		show_usage
		exit 0
	else
		show_usage
		echo "$0: error: unknown option '$1'"
		exit 1
	fi
done

# root check (only for live mode, for offline mode, we already checked if we could read the files)

if [ "$opt_live" = 1 ]; then
	if [ "$(id -u)" -ne 0 ]; then
		/bin/echo -e "\033[31mNote that you should launch this script with root privileges to get accurate information.\033[0m"
		/bin/echo -e "\033[31mWe'll proceed but you might see permission denied errors.\033[0m"
		/bin/echo -e "\033[31mTo run it as root, you can try the following command: sudo $0\033[0m"
		/bin/echo
	fi
	/bin/echo -e "Checking for vulnerabilities against live running kernel \033[35m"$(uname -s) $(uname -r) $(uname -v) $(uname -m)"\033[0m"

	# try to find the image of the current running kernel
	[ -e /boot/vmlinuz-linux       ] && opt_kernel=/boot/vmlinuz-linux
	[ -e /boot/vmlinuz-linux-libre ] && opt_kernel=/boot/vmlinuz-linux-libre
	[ -e /boot/vmlinuz-$(uname -r) ] && opt_kernel=/boot/vmlinuz-$(uname -r)
	[ -e /boot/kernel-$( uname -r) ] && opt_kernel=/boot/kernel-$( uname -r)
	[ -e /boot/bzImage-$(uname -r) ] && opt_kernel=/boot/bzImage-$(uname -r)
	[ -e /boot/kernel-genkernel-$(uname -m)-$(uname -r) ] && opt_kernel=/boot/kernel-genkernel-$(uname -m)-$(uname -r)

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
	/bin/echo "Checking for vulnerabilities against specified kernel"
fi
if [ -n "$opt_kernel" ]; then
	/bin/echo -e "Will use vmlinux image \033[35m$opt_kernel\033[0m"
else
	/bin/echo "Will use no vmlinux image (accuracy might be reduced"
fi
if [ -n "$opt_config" ]; then
	/bin/echo -e "Will use kconfig \033[35m$opt_config\033[0m"
else
	/bin/echo "Will use no kconfig (accuracy might be reduced)"
fi
if [ -n "$opt_map" ]; then
	/bin/echo -e "Will use System.map file \033[35m$opt_map\033[0m"
else
	/bin/echo "Will use no System.map file (accuracy might be reduced)"
fi

if [ -e "$opt_kernel" ]; then
	if ! which readelf >/dev/null 2>&1; then
		vmlinux_err="missing 'readelf' tool, please install it, usually it's in the 'binutils' package"
	else
		extract_vmlinux "$opt_kernel"
	fi
else
	vmlinux_err="couldn't find your kernel image in /boot, if you used neboot, this is normal"
fi
if [ -z "$vmlinux" -o ! -r "$vmlinux" ]; then
	[ -z "$vmlinux_err" ] && vmlinux_err="couldn't extract your kernel from $opt_kernel"
fi

/bin/echo

###########
# SPECTRE 1
/bin/echo -e "\033[1;34mCVE-2017-5753 [bounds check bypass] aka 'Spectre Variant 1'\033[0m"
/bin/echo -n "* Kernel compiled with LFENCE opcode inserted at the proper places: "

status=0
if [ -n "$vmlinux_err" ]; then
	pstatus yellow UNKNOWN "$vmlinux_err"
else
	if ! which objdump >/dev/null 2>&1; then
		pstatus yellow UNKNOWN "missing 'objdump' tool, please install it, usually it's in the binutils package"
	else
		# here we disassemble the kernel and count the number of occurences of the LFENCE opcode
		# in non-patched kernels, this has been empirically determined as being around 40-50
		# in patched kernels, this is more around 70-80, sometimes way higher (100+)
		# v0.13: 68 found in a 3.10.23-xxxx-std-ipv6-64 (with lots of modules compiled-in directly), which doesn't have the LFENCE patches,
		# so let's push the threshold to 70.
		# TODO LKML patch is starting to dump LFENCE in favor of the PAUSE opcode, we might need to check that (patch not stabilized yet)
		nb_lfence=$(objdump -D "$vmlinux" | grep -wc lfence)
		if [ "$nb_lfence" -lt 70 ]; then
			pstatus red NO "only $nb_lfence opcodes found, should be >= 70"
			status=1
		else
			pstatus green YES "$nb_lfence opcodes found, which is >= 70"
			status=2
		fi
	fi
fi

/bin/echo -ne "> \033[46m\033[30mSTATUS:\033[0m "
[ "$status" = 0 ] && pstatus yellow UNKNOWN
[ "$status" = 1 ] && pstatus red VULNERABLE
[ "$status" = 2 ] && pstatus green 'NOT VULNERABLE'

###########
# VARIANT 2
/bin/echo
/bin/echo -e "\033[1;34mCVE-2017-5715 [branch target injection] aka 'Spectre Variant 2'\033[0m"
/bin/echo "* Mitigation 1"
/bin/echo -n "*   Hardware (CPU microcode) support for mitigation: "
if [ ! -e /dev/cpu/0/msr ]; then
	# try to load the module ourselves (and remember it so we can rmmod it afterwards)
	modprobe msr 2>/dev/null && insmod_msr=1
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

if [ "$insmod_msr" = 1 ]; then
	# if we used modprobe ourselves, rmmod the module
	rmmod msr 2>/dev/null
fi

/bin/echo -n "*   Kernel support for IBRS: "
if [ "$opt_live" = 1 ]; then
	if [ ! -e /sys/kernel/debug/sched_features ]; then
		# try to mount the debugfs hierarchy ourselves and remember it to umount afterwards
		mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null && mounted_debugfs=1
	fi
	if [ -e /sys/kernel/debug/ibrs_enabled ]; then
		# if the file is there, we have IBRS compiled-in
		pstatus green YES
		ibrs_supported=1
		ibrs_enabled=$(cat /sys/kernel/debug/ibrs_enabled 2>/dev/null)
	elif [ -e /sys/kernel/debug/x86/ibrs_enabled ]; then
		# RedHat uses a different path (see https://access.redhat.com/articles/3311301)
		pstatus green YES
		ibrs_supported=1
		ibrs_enabled=$(cat /sys/kernel/debug/x86/ibrs_enabled 2>/dev/null)
	fi
fi
if [ "$ibrs_supported " != 1 -a -n "$opt_map" ]; then
	if grep -q spec_ctrl "$opt_map"; then
		pstatus green YES
		ibrs_supported=1
	fi
fi
if [ "$ibrs_supported" != 1 ]; then
	pstatus red NO
fi

/bin/echo -n "*   IBRS enabled for Kernel space: "
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

/bin/echo -n "*   IBRS enabled for User space: "
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

/bin/echo "* Mitigation 2"
/bin/echo -n "*   Kernel compiled with retpoline option: "
# We check the RETPOLINE kernel options
if [ -r "$opt_config" ]; then
	if grep -q '^CONFIG_RETPOLINE=y' "$opt_config"; then
		pstatus green YES
		retpoline=1
	else
		pstatus red NO
	fi
else
	pstatus yellow UNKNOWN "couldn't read your kernel configuration"
fi

/bin/echo -n "*   Kernel compiled with a retpoline-aware compiler: "
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

/bin/echo -ne "> \033[46m\033[30mSTATUS:\033[0m "
if grep -q AMD /proc/cpuinfo; then
	pstatus green "NOT VULNERABLE" "your CPU is not vulnerable as per the vendor"
elif [ "$retpoline" = 1 -a "$retpoline_compiler" = 1 ]; then
	pstatus green "NOT VULNERABLE" "retpoline mitigate the vulnerability"
elif [ "$opt_live" = 1 ]; then
	if [ "$ibrs_enabled" = 1 -o "$ibrs_enabled" = 2 ]; then
		pstatus green "NOT VULNERABLE" "IBRS mitigates the vulnerability"
	else
		pstatus red VULNERABLE "IBRS hardware + kernel support OR kernel with retpoline are needed to mitigate the vulnerability"
	fi
else
	if [ "$ibrs_supported" = 1 ]; then
		pstatus green "NOT VULNERABLE" "offline mode: IBRS will mitigate the vulnerability if enabled at runtime"
	else
		pstatus red VULNERABLE "IBRS hardware + kernel support OR kernel with retpoline are needed to mitigate the vulnerability"
	fi
fi

##########
# MELTDOWN
/bin/echo
/bin/echo -e "\033[1;34mCVE-2017-5754 [rogue data cache load] aka 'Meltdown' aka 'Variant 3'\033[0m"
/bin/echo -n "* Kernel supports Page Table Isolation (PTI): "
kpti_support=0
kpti_can_tell=0
if [ -n "$opt_config" ]; then
	kpti_can_tell=1
	if grep -Eq '^\(CONFIG_PAGE_TABLE_ISOLATION\|CONFIG_KAISER\)=y' "$opt_config"; then
		kpti_support=1
	fi
fi
if [ "$kpti_support" = 0 -a -n "$opt_map" ]; then
	# it's not an elif: some backports don't have the PTI config but still include the patch
	# so we try to find an exported symbol that is part of the PTI patch in System.map
	kpti_can_tell=1
	if grep -qw kpti_force_enabled "$opt_map"; then
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

/bin/echo -n "* PTI enabled and active: "
if [ "$opt_live" = 1 ]; then
	if grep ^flags /proc/cpuinfo | grep -qw pti; then
		# vanilla PTI patch sets the 'pti' flag in cpuinfo
		kpti_enabled=1
	elif grep ^flags /proc/cpuinfo | grep -qw kaiser; then
		# kernel line 4.9 sets the 'kaiser' flag in cpuinfo
		kpti_enabled=1
	elif [ -e /sys/kernel/debug/x86/pti_enabled ]; then
		# RedHat Backport creates a dedicated file, see https://access.redhat.com/articles/3311301
		kpti_enabled=$(cat /sys/kernel/debug/x86/pti_enabled 2>/dev/null)
	elif dmesg | grep -Eq 'Kernel/User page tables isolation: enabled|Kernel page table isolation enabled'; then
		# if we can't find the flag, grep in dmesg
		kpti_enabled=1
	else
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

if [ "$mounted_debugfs" = 1 ]; then
	# umount debugfs if we did mount it ourselves
	umount /sys/kernel/debug
fi

/bin/echo -ne "> \033[46m\033[30mSTATUS:\033[0m "
if grep -q AMD /proc/cpuinfo; then
	pstatus green "NOT VULNERABLE" "your CPU is not vulnerable as per the vendor"
elif [ "$opt_live" = 1 ]; then
	if [ "$kpti_enabled" = 1 ]; then
		pstatus green "NOT VULNERABLE" "PTI mitigates the vulnerability"
	else
		pstatus red "VULNERABLE" "PTI is needed to mitigate the vulnerability"
	fi
else
	if [ "$kpti_support" = 1 ]; then
		pstatus green "NOT VULNERABLE" "offline mode: PTI will mitigate the vulnerability if enabled at runtime"
	else
		pstatus red "VULNERABLE" "PTI is needed to mitigate the vulnerability"
	fi
fi

/bin/echo

[ -n "$dumped_config" ] && rm -f "$dumped_config"
