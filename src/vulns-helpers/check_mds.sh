# vim: set ts=4 sw=4 sts=4 et:
# MDS (microarchitectural data sampling) - BSD mitigation check
check_mds_bsd() {
    local kernel_md_clear kernel_smt_allowed kernel_mds_enabled kernel_mds_state
    pr_info_nol "* Kernel supports using MD_CLEAR mitigation: "
    if [ "$g_mode" = live ]; then
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
    # possible values for hw.mds_disable_state (FreeBSD cpu_machdep.c):
    # - inactive: no mitigation (non-Intel, disabled, or not needed)
    # - VERW: microcode-based VERW instruction
    # - software IvyBridge: SW sequence for Ivy Bridge
    # - software Broadwell: SW sequence for Broadwell
    # - software Skylake SSE: SW sequence for Skylake (SSE)
    # - software Skylake AVX: SW sequence for Skylake (AVX)
    # - software Skylake AVX512: SW sequence for Skylake (AVX-512)
    # - software Silvermont: SW sequence for Silvermont
    # - unknown: fallback if handler doesn't match any known
    # ref: https://github.com/freebsd/freebsd-src/blob/main/sys/x86/x86/cpu_machdep.c
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
                if [ "$g_mode" = live ]; then
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
            if [ "$kernel_md_clear" = 1 ] && [ "$g_mode" = live ]; then
                # no MD_CLEAR in microcode, but FreeBSD may still have software-only mitigation active
                case "$kernel_mds_state" in
                    software*)
                        if [ "$opt_paranoid" = 1 ]; then
                            pvulnstatus "$cve" VULN "Software-only mitigation is active, but in paranoid mode a microcode-based mitigation is required"
                        elif [ "$kernel_smt_allowed" = 1 ]; then
                            pvulnstatus "$cve" OK "Software-only mitigation is active, but SMT is enabled so cross-thread attacks are still possible"
                        else
                            pvulnstatus "$cve" OK "Software-only mitigation is active (no microcode update required for this CPU)"
                        fi
                        ;;
                    *)
                        pvulnstatus "$cve" VULN "Your kernel supports mitigation, but your CPU microcode also needs to be updated to mitigate the vulnerability"
                        ;;
                esac
            elif [ "$kernel_md_clear" = 1 ]; then
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
        # MDS is Intel-only; skip x86-specific kernel/cpuinfo checks on non-x86 kernels
        kernel_md_clear=''
        kernel_md_clear_can_tell=0
        if is_x86_kernel; then
            pr_info_nol "* Kernel supports using MD_CLEAR mitigation: "
            kernel_md_clear_can_tell=1
            if [ "$g_mode" = live ] && grep ^flags "$g_procfs/cpuinfo" | grep -qw md_clear; then
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

            if [ "$g_mode" = live ] && [ "$sys_interface_available" = 1 ]; then
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
        fi # is_x86_kernel
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
                    if [ "$g_mode" = live ]; then
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
