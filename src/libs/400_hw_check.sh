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
    local file regex mode msg mockvarname
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
    # the new MSR 'SPEC_CTRL' is at offset 0x48
    read_msr 0x48
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
    if is_intel; then
        read_cpuid 0x7 0x0 $EDX 27 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES "Intel STIBP feature bit"
            #cpuid_stibp='Intel STIBP'
        fi
    elif is_amd; then
        read_cpuid 0x80000008 0x0 $EBX 15 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES "AMD STIBP feature bit"
            #cpuid_stibp='AMD STIBP'
        fi
    elif is_hygon; then
        read_cpuid 0x80000008 0x0 $EBX 15 1 1
        ret=$?
        if [ $ret = $READ_CPUID_RET_OK ]; then
            pstatus green YES "HYGON STIBP feature bit"
            #cpuid_stibp='HYGON STIBP'
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

        # make shellcheck happy while we're not yet using these new cpuid values in our checks
        export cap_ipred cap_rrsba cap_bhi
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
            pstatus yellow NO
        else
            # the new MSR 'ARCH_CAPABILITIES' is at offset 0x10a
            read_msr 0x10a
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
            if [ $ret = $READ_MSR_RET_OK ]; then
                capabilities=$ret_read_msr_value
                # https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/x86/include/asm/msr-index.h#n82
                pr_debug "capabilities MSR is $capabilities (decimal)"
                [ $((capabilities >> 0 & 1)) -eq 1 ] && cap_rdcl_no=1
                [ $((capabilities >> 1 & 1)) -eq 1 ] && cap_ibrs_all=1
                [ $((capabilities >> 2 & 1)) -eq 1 ] && cap_rsba=1
                [ $((capabilities >> 3 & 1)) -eq 1 ] && cap_l1dflush_no=1
                [ $((capabilities >> 4 & 1)) -eq 1 ] && cap_ssb_no=1
                [ $((capabilities >> 5 & 1)) -eq 1 ] && cap_mds_no=1
                [ $((capabilities >> 6 & 1)) -eq 1 ] && cap_pschange_msc_no=1
                [ $((capabilities >> 7 & 1)) -eq 1 ] && cap_tsx_ctrl_msr=1
                [ $((capabilities >> 8 & 1)) -eq 1 ] && cap_taa_no=1
                [ $((capabilities >> 25 & 1)) -eq 1 ] && cap_gds_ctrl=1
                [ $((capabilities >> 26 & 1)) -eq 1 ] && cap_gds_no=1
                pr_debug "capabilities says rdcl_no=$cap_rdcl_no ibrs_all=$cap_ibrs_all rsba=$cap_rsba l1dflush_no=$cap_l1dflush_no ssb_no=$cap_ssb_no mds_no=$cap_mds_no taa_no=$cap_taa_no pschange_msc_no=$cap_pschange_msc_no"
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
            read_msr 0x122
            ret=$?
            if [ "$ret" = $READ_MSR_RET_OK ]; then
                g_tsx_ctrl_msr=$ret_read_msr_value
                cap_tsx_ctrl_rtm_disable=$((g_tsx_ctrl_msr >> 0 & 1))
                cap_tsx_ctrl_cpuid_clear=$((g_tsx_ctrl_msr >> 1 & 1))
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
            # read the IA32_MCU_OPT_CTRL MSR
            read_msr 0x123
            ret=$?
            if [ "$ret" = $READ_MSR_RET_OK ]; then
                g_mcu_opt_ctrl=$ret_read_msr_value
                cap_gds_mitg_dis=$((g_mcu_opt_ctrl >> 4 & 1))
                cap_gds_mitg_lock=$((g_mcu_opt_ctrl >> 5 & 1))
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
        read_msr 0x123
        ret=$?
        if [ $ret = $READ_MSR_RET_OK ]; then
            if [ "$ret_read_msr_value" = 0 ]; then
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

# Detect whether this system is hosting virtual machines (hypervisor check)
# Sets: g_has_vmm
check_has_vmm() {
    local binary pid
    pr_info_nol "* This system is a host running a hypervisor: "
    g_has_vmm=$opt_vmm
    if [ "$g_has_vmm" = -1 ] && [ "$opt_paranoid" = 1 ]; then
        # In paranoid mode, if --vmm was not specified on the command-line,
        # we want to be secure before everything else, so assume we're running
        # a hypervisor, as this requires more mitigations
        g_has_vmm=2
    elif [ "$g_has_vmm" = -1 ]; then
        # Here, we want to know if we are hosting a hypervisor, and running some VMs on it.
        # If we find no evidence that this is the case, assume we're not (to avoid scaring users),
        # this can always be overridden with --vmm in any case.
        g_has_vmm=0
        if command -v pgrep >/dev/null 2>&1; then
            # remove xenbus and xenwatch, also present inside domU
            # remove libvirtd as it can also be used to manage containers and not VMs
            # for each binary we want to grep, get the pids
            for binary in qemu kvm xenstored xenconsoled; do
                for pid in $(pgrep -x "$binary"); do
                    # resolve the exe symlink, if it doesn't resolve with -m,
                    # which doesn't even need the dest to exist, it means the symlink
                    # is null, which is the case for kernel threads: ignore those to
                    # avoid false positives (such as [kvm-irqfd-clean] under at least RHEL 7.6/7.7)
                    if ! [ "$(readlink -m "/proc/$pid/exe")" = "/proc/$pid/exe" ]; then
                        pr_debug "g_has_vmm: found PID $pid"
                        g_has_vmm=1
                    fi
                done
            done
            unset binary pid
        else
            # ignore SC2009 as `ps ax` is actually used as a fallback if `pgrep` isn't installed
            # shellcheck disable=SC2009
            if command -v ps >/dev/null && ps ax | grep -vw grep | grep -q -e '\<qemu' -e '/qemu' -e '<\kvm' -e '/kvm' -e '/xenstored' -e '/xenconsoled'; then
                g_has_vmm=1
            fi
        fi
    fi
    if [ "$g_has_vmm" = 0 ]; then
        if [ "$opt_vmm" != -1 ]; then
            pstatus green NO "forced from command line"
        else
            pstatus green NO
        fi
    else
        if [ "$opt_vmm" != -1 ]; then
            pstatus blue YES "forced from command line"
        elif [ "$g_has_vmm" = 2 ]; then
            pstatus blue YES "paranoid mode"
        else
            pstatus blue YES
        fi
    fi
}
