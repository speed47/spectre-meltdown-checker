#! /bin/sh
# Spectre & Meltdown checker
# Stephane Lesimple, v0.00.01
VERSION=0.01

pstatus()
{
	case "$1" in
		red)    col="\033[101m\033[30m";;
		green)  col="\033[102m\033[30m";;
		yellow) col="\033[103m\033[30m";;
		*)      col="";;
	esac
	echo -n "$col$2\033[0m"
	[ -n "$3" ] && echo -n " ($3)"
	echo
}

echo "Spectre and Meltdown mitigation detection tool v$VERSION"
echo

# SPECTRE 1
echo "\033[1;34mCVE-2017-5753 [bounds check bypass] aka 'Spectre Variant 1'\033[0m"
echo -n "* Kernel recompiled with LFENCE opcode insertion: "
pstatus yellow UNKNOWN "check not yet implemented"
echo -n "> \033[46m\033[30mSTATUS:\033[0m "
pstatus yellow UNKNOWN "not implemented, but real answer is most probably VULNERABLE at this stage"


# VARIANT 2
echo
echo "\033[1;34mCVE-2017-5715 [branch target injection] aka 'Spectre Variant 2'\033[0m"
echo "* Mitigation 1"
echo -n "*   Hardware (CPU microcode) support for mitigation: "
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
	#echo $?
fi

if [ "$insmod_msr" = 1 ]; then
	rmmod msr 2>/dev/null
fi

echo -n "*   Kernel support for IBRS: "
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
echo -n "*   IBRS enabled for Kernel space: "
case "$ibrs_enabled" in
	"") [ "$ibrs_supported" = 1 ] && pstatus yellow UNKNOWN || pstatus red NO;;
	0)     pstatus red NO;;
	1 | 2) pstatus green YES;;
	*)     pstatus yellow UNKNOWN;;
esac

echo -n "*   IBRS enabled for User space: "
case "$ibrs_enabled" in
	"") [ "$ibrs_supported" = 1 ] && pstatus yellow UNKNOWN || pstatus red NO;;
	0 | 1) pstatus red NO;;
	2) pstatus green YES;;
	*) pstatus yellow unknown;;
esac

if [ "$mounted_debugfs" = 1 ]; then
	umount /sys/kernel/debug
fi

echo "* Mitigation 2"
echo -n "*   Kernel recompiled with retpoline: "
pstatus yellow UNKNOWN "check not yet implemented"

echo -n "> \033[46m\033[30mSTATUS:\033[0m "
if grep -q AMD /proc/cpuinfo; then
	pstatus green "NOT VULNERABLE" "your CPU is not vulnerable as per the vendor"
elif [ "$ibrs_enabled" = 1 -o "$ibrs_enabled" = 2 ]; then
	pstatus green "NOT VULNERABLE" "IBRS mitigates the vulnerability"
else
	pstatus red VULNERABLE "IBRS hardware + kernel support OR retpoline-compiled kernel are needed to mitigate the vulnerability"
fi

# MELTDOWN
echo
echo "\033[1;34mCVE-2017-5754 [rogue data cache load] aka 'Meltdown' aka 'Variant 3'\033[0m"
echo -n "* Kernel supports Page Table Isolation (PTI): "
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
else
	pstatus yellow UNKNOWN
fi

echo -n "* PTI enabled and active: "
if grep ^flags /proc/cpuinfo | grep -qw pti; then
	pstatus green YES
	kpti_enabled=1
elif dmesg | grep -q 'Kernel/User page tables isolation: enabled'; then
	pstatus green YES
	kpti_enabled=1
else
	pstatus red NO
fi

echo -n "> \033[46m\033[30mSTATUS:\033[0m "
if grep -q AMD /proc/cpuinfo; then
	pstatus green "NOT VULNERABLE" "your CPU is not vulnerable as per the vendor"
elif [ "$kpti_enabled" = 1 ]; then
	pstatus green "NOT VULNERABLE" "PTI mitigates the vulnerability"
else
	pstatus red "VULNERABLE" "PTI is needed to mitigate the vulnerability"
fi


echo
if [ "$USER" != root ]; then
	echo "Note that you should launch this script with root privileges to get accurate information"
	echo "You can try the following command: sudo $0"
fi


