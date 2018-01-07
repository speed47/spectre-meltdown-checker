#! /bin/sh
# Spectre & Meltdown checker
# Stephane Lesimple
VERSION=0.03

pstatus()
{
	case "$1" in
		red)    col="\033[101m\033[30m";;
		green)  col="\033[102m\033[30m";;
		yellow) col="\033[103m\033[30m";;
		*)      col="";;
	esac
	/bin/echo -ne "$col$2\033[0m"
	[ -n "$3" ] && /bin/echo -n " ($3)"
	/bin/echo
}

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

check_vmlinux()
{
	file "$1" 2>/dev/null | grep -q ELF || return 1
	return 0
}

try_decompress()
{
        # The obscure use of the "tr" filter is to work around older versions of
        # "grep" that report the byte offset of the line instead of the pattern.

        # Try to find the header ($1) and decompress from here
        for     pos in `tr "$1\n$2" "\n$2=" < "$img" | grep -abo "^$2"`
        do
                pos=${pos%%:*}
                tail -c+$pos "$img" | $3 > $vmlinuxtmp 2> /dev/null
                check_vmlinux $vmlinuxtmp && echo $vmlinuxtmp || rm -f $vmlinuxtmp
        done
}

extract_vmlinux()
{
	img="$1"

	# Prepare temp files:
	vmlinuxtmp=$(mktemp /tmp/vmlinux-XXX)

	# Initial attempt for uncompressed images or objects:
	check_vmlinux $img

	# That didn't work, so retry after decompression.
	try_decompress '\037\213\010' xy    gunzip     || \
	try_decompress '\3757zXZ\000' abcde unxz       || \
	try_decompress 'BZh'          xy    bunzip2    || \
	try_decompress '\135\0\0\0'   xxx   unlzma     || \
	try_decompress '\211\114\132' xy    'lzop -d'
}


/bin/echo "Spectre and Meltdown mitigation detection tool v$VERSION"
/bin/echo

# SPECTRE 1
/bin/echo -e "\033[1;34mCVE-2017-5753 [bounds check bypass] aka 'Spectre Variant 1'\033[0m"
/bin/echo -n "* Kernel compiled with LFENCE opcode inserted at the proper places: "

status=0
img=''
[ -e /boot/vmlinuz-$(uname -r) ] && img=/boot/vmlinuz-$(uname -r)
[ -e /boot/vmlinux-$(uname -r) ] && img=/boot/vmlinux-$(uname -r)
[ -e /boot/bzImage-$(uname -r) ] && img=/boot/bzImage-$(uname -r)
if [ -z "$img" ]; then
	pstatus yellow UNKNOWN "couldn't find your kernel image in /boot"
else
	vmlinux=$(extract_vmlinux $img)
	if [ -z "$vmlinux" -o ! -r "$vmlinux" ]; then
		pstatus yellow UNKNOWN "couldn't extract your kernel"
	elif ! which objdump >/dev/null 2>&1; then
		pstatus yellow UNKNOWN "missing 'objdump' tool, please install it, usually it's in the binutils package"
	else
		nb_lfence=$(objdump -D "$vmlinux" | grep -wc lfence)
		if [ "$nb_lfence" -lt 60 ]; then
			pstatus red NO "only $nb_lfence opcodes found, should be >= 60"
			status=1
		else
			pstatus green YES "$nb_lfence opcodes found, which is >= 60"
			status=2
		fi
		rm -f $vmlinux
	fi
fi

/bin/echo -ne "> \033[46m\033[30mSTATUS:\033[0m "
[ "$status" = 0 ] && pstatus yellow UNKNOWN
[ "$status" = 1 ] && pstatus red VULNERABLE
[ "$status" = 2 ] && pstatus green 'NOT VULNERABLE'


# VARIANT 2
/bin/echo
/bin/echo -e "\033[1;34mCVE-2017-5715 [branch target injection] aka 'Spectre Variant 2'\033[0m"
/bin/echo "* Mitigation 1"
/bin/echo -n "*   Hardware (CPU microcode) support for mitigation: "
if [ ! -e /dev/cpu/0/msr ]; then
	modprobe msr 2>/dev/null && insmod_msr=1
fi
if [ ! -e /dev/cpu/0/msr ]; then
	pstatus yellow UNKNOWN "couldn't read /dev/cpu/0/msr, is msr support enabled in your kernel?"
else
	dd if=/dev/cpu/0/msr of=/dev/null bs=1 count=8 skip=72 2>/dev/null
	if [ $? -eq 0 ]; then
		pstatus green YES
	else
		pstatus red NO
	fi
	#dd if=/dev/cpu/0/msr of=/dev/null bs=1 count=8 skip=73 2>/dev/null
	#/bin/echo $?
fi

if [ "$insmod_msr" = 1 ]; then
	rmmod msr 2>/dev/null
fi

/bin/echo -n "*   Kernel support for IBRS: "
if [ -e /sys/kernel/debug/sched_features ]; then
	mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null && mounted_debugfs=1
fi
if [ -e /sys/kernel/debug/ibrs_enabled ]; then
	pstatus green YES
	ibrs_supported=1
else
	pstatus red NO
fi

ibrs_enabled=$(cat /sys/kernel/debug/ibrs_enabled 2>/dev/null)
/bin/echo -n "*   IBRS enabled for Kernel space: "
case "$ibrs_enabled" in
	"") [ "$ibrs_supported" = 1 ] && pstatus yellow UNKNOWN || pstatus red NO;;
	0)     pstatus red NO;;
	1 | 2) pstatus green YES;;
	*)     pstatus yellow UNKNOWN;;
esac

/bin/echo -n "*   IBRS enabled for User space: "
case "$ibrs_enabled" in
	"") [ "$ibrs_supported" = 1 ] && pstatus yellow UNKNOWN || pstatus red NO;;
	0 | 1) pstatus red NO;;
	2) pstatus green YES;;
	*) pstatus yellow unknown;;
esac

if [ "$mounted_debugfs" = 1 ]; then
	umount /sys/kernel/debug
fi

/bin/echo "* Mitigation 2"
/bin/echo -n "*   Kernel recompiled with retpolines: "
pstatus yellow UNKNOWN "check not yet implemented"

/bin/echo -ne "> \033[46m\033[30mSTATUS:\033[0m "
if grep -q AMD /proc/cpuinfo; then
	pstatus green "NOT VULNERABLE" "your CPU is not vulnerable as per the vendor"
elif [ "$ibrs_enabled" = 1 -o "$ibrs_enabled" = 2 ]; then
	pstatus green "NOT VULNERABLE" "IBRS mitigates the vulnerability"
else
	pstatus red VULNERABLE "IBRS hardware + kernel support OR retpolines-compiled kernel are needed to mitigate the vulnerability"
fi

# MELTDOWN
/bin/echo
/bin/echo -e "\033[1;34mCVE-2017-5754 [rogue data cache load] aka 'Meltdown' aka 'Variant 3'\033[0m"
/bin/echo -n "* Kernel supports Page Table Isolation (PTI): "
if [ -e /proc/config.gz ]; then
	if zgrep -q '^CONFIG_PAGE_TABLE_ISOLATION=y' /proc/config.gz; then
		pstatus green YES
		kpti_support=1
	else
		pstatus red NO
	fi
elif [ -e /boot/config-$(uname -r) ]; then
	if grep  -q '^CONFIG_PAGE_TABLE_ISOLATION=y' /boot/config-$(uname -r); then
		pstatus green YES
		kpti_support=1
	else
		pstatus red NO
	fi
elif [ -e /boot/System.map-$(uname -r) ]; then
	if grep -qw kpti_force_enabled /boot/System.map-$(uname -r); then
		pstatus green YES
		kpti_support=1
	else
		pstatus red NO
	fi
else
	pstatus yellow UNKNOWN
fi

/bin/echo -n "* PTI enabled and active: "
if grep ^flags /proc/cpuinfo | grep -qw pti; then
	pstatus green YES
	kpti_enabled=1
elif dmesg | grep -q 'Kernel/User page tables isolation: enabled'; then
	pstatus green YES
	kpti_enabled=1
else
	pstatus red NO
fi

/bin/echo -ne "> \033[46m\033[30mSTATUS:\033[0m "
if grep -q AMD /proc/cpuinfo; then
	pstatus green "NOT VULNERABLE" "your CPU is not vulnerable as per the vendor"
elif [ "$kpti_enabled" = 1 ]; then
	pstatus green "NOT VULNERABLE" "PTI mitigates the vulnerability"
else
	pstatus red "VULNERABLE" "PTI is needed to mitigate the vulnerability"
fi


/bin/echo
if [ "$USER" != root ]; then
	/bin/echo "Note that you should launch this script with root privileges to get accurate information"
	/bin/echo "You can try the following command: sudo $0"
fi

