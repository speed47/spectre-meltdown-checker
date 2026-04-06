# vim: set ts=4 sw=4 sts=4 et:
# MMIO Stale Data (Processor MMIO Stale Data Vulnerabilities) - BSD mitigation check
check_mmio_bsd() {
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
    fi
}

# MMIO Stale Data (Processor MMIO Stale Data Vulnerabilities) - Linux mitigation check
check_mmio_linux() {
    local status sys_interface_available msg kernel_mmio kernel_mmio_can_tell mmio_mitigated mmio_smt_mitigated mystatus mymsg
    status=UNK
    sys_interface_available=0
    msg=''
    if sys_interface_check "$VULN_SYSFS_BASE/mmio_stale_data" '^[^;]+'; then
        # Kernel source inventory for MMIO Stale Data, traced via git blame walkback
        # across /shared/linux, /shared/linux-stable, and /shared/linux-centos-redhat:
        #
        # --- sysfs messages ---
        # all versions:
        #   "Not affected"                                                      (cpu_show_common, generic)
        #
        # 8cb861e9e3c9 (v5.19, initial MMIO mitigation, Pawan Gupta 2022-05-19):
        #   enum mmio_mitigations: MMIO_MITIGATION_OFF, MMIO_MITIGATION_UCODE_NEEDED, MMIO_MITIGATION_VERW
        #   mmio_strings[]:
        #     "Vulnerable"                                                      (MMIO_MITIGATION_OFF)
        #     "Vulnerable: Clear CPU buffers attempted, no microcode"           (MMIO_MITIGATION_UCODE_NEEDED)
        #     "Mitigation: Clear CPU buffers"                                   (MMIO_MITIGATION_VERW)
        #
        # 8d50cdf8b834 (v5.19, sysfs reporting, Pawan Gupta 2022-05-19):
        #   mmio_stale_data_show_state() added with SMT suffix:
        #     "{mmio_strings[state]}; SMT vulnerable"                           (sched_smt_active() true)
        #     "{mmio_strings[state]}; SMT disabled"                             (sched_smt_active() false)
        #     "{mmio_strings[state]}; SMT Host state unknown"                   (boot_cpu_has(HYPERVISOR))
        #   No SMT suffix when MMIO_MITIGATION_OFF.
        #   Uses sysfs_emit() in mainline. CentOS 7 backport uses sprintf().
        #
        # 7df548840c49 (v6.0, "unknown" reporting, Pawan Gupta 2022-08-03):
        #   Added X86_BUG_MMIO_UNKNOWN handling:
        #     "Unknown: No mitigations"                                         (X86_BUG_MMIO_UNKNOWN set)
        #   Present in: v6.0 through v6.15, stable 5.10.y/5.15.y/6.1.y/6.6.y, rocky8, rocky9
        #
        # dd86a1d013e0 (v6.16, removed MMIO_UNKNOWN, Borislav Petkov 2025-04-14):
        #   Removed X86_BUG_MMIO_UNKNOWN -- "Unknown" message no longer produced.
        #   Replaced by general X86_BUG_OLD_MICROCODE mechanism.
        #
        # 4a5a04e61d7f (v6.16, restructured, David Kaplan 2025-04-18):
        #   Split into select/update/apply pattern. Same strings, same output.
        #
        # all messages start with "Not affected", "Vulnerable", "Mitigation", or "Unknown"
        #
        # --- stable backports ---
        # Stable branches 5.4.y through 6.15.y: identical mmio_strings[] array.
        # 5.4.y uses sprintf(); 5.10.y+ uses sysfs_emit().
        # v6.0.y through v6.15.y include "Unknown: No mitigations" branch.
        # v6.16.y+: restructured, no "Unknown" message.
        #
        # --- RHEL/CentOS ---
        # centos7: sprintf() instead of sysfs_emit(), otherwise identical strings.
        # rocky8: sysfs_emit(), includes X86_BUG_MMIO_UNKNOWN.
        # rocky9: sysfs_emit(), includes X86_BUG_MMIO_UNKNOWN.
        # rocky10: restructured, matches mainline v6.16+.
        # All RHEL branches use identical mmio_strings[] array.
        #
        # --- Kconfig symbols ---
        # No Kconfig symbol: v5.19 through v6.11 (mitigation always compiled in when CPU_SUP_INTEL)
        # 163f9fe6b625 (v6.12, Breno Leitao 2024-07-29): CONFIG_MITIGATION_MMIO_STALE_DATA (bool, default y, depends CPU_SUP_INTEL)
        # No other name variants exist (no renames). Single symbol throughout history.
        #
        # --- stable ---
        # Only linux-rolling-lts and linux-rolling-stable have the Kconfig symbol.
        # Stable branches 5.x through 6.11.y: no Kconfig (always compiled in).
        #
        # --- RHEL ---
        # rocky9, rocky10: CONFIG_MITIGATION_MMIO_STALE_DATA present.
        # rocky8, centos7: no Kconfig symbol.
        #
        # --- kernel functions (for $opt_map / System.map) ---
        # 8cb861e9e3c9 (v5.19): mmio_select_mitigation() [static __init]
        # 8cb861e9e3c9 (v5.19): mmio_stale_data_parse_cmdline() [static __init]
        # 8d50cdf8b834 (v5.19): mmio_stale_data_show_state() [static]
        # 8d50cdf8b834 (v5.19): cpu_show_mmio_stale_data() [global, non-static -- visible in System.map]
        # 4a5a04e61d7f (v6.16): + mmio_update_mitigation() [static __init]
        # 4a5a04e61d7f (v6.16): + mmio_apply_mitigation() [static __init]
        #
        # Best grep targets for $opt_map: mmio_select_mitigation, cpu_show_mmio_stale_data
        # Best grep targets for $g_kernel: mmio_stale_data (appears in sysfs strings and parameter name)
        #
        # --- stable ---
        # 5.4.y-6.15.y: mmio_select_mitigation, mmio_stale_data_parse_cmdline, mmio_stale_data_show_state
        # 6.16.y+: + mmio_update_mitigation, mmio_apply_mitigation
        #
        # --- RHEL ---
        # rocky8/rocky9: mmio_select_mitigation, mmio_stale_data_parse_cmdline, mmio_stale_data_show_state
        # rocky10: + mmio_update_mitigation, mmio_apply_mitigation
        #
        # --- CPU affection logic (for is_cpu_affected) ---
        # 51802186158c (v5.19, initial model list, Pawan Gupta 2022-05-19):
        #   Intel Family 6:
        #     HASWELL_X (0x3F)
        #     BROADWELL_D (0x56), BROADWELL_X (0x4F)
        #     SKYLAKE_X (0x55), SKYLAKE_L (0x4E), SKYLAKE (0x5E)
        #     KABYLAKE_L (0x8E), KABYLAKE (0x9E)
        #     ICELAKE_L (0x7E), ICELAKE_D (0x6C), ICELAKE_X (0x6A)
        #     COMETLAKE (0xA5), COMETLAKE_L (0xA6)
        #     LAKEFIELD (0x8A)
        #     ROCKETLAKE (0xA7)
        #     ATOM_TREMONT (0x96), ATOM_TREMONT_D (0x86), ATOM_TREMONT_L (0x9C)
        #   All steppings. No stepping restrictions for MMIO flag itself.
        #
        # No models have been added to or removed from the MMIO blacklist since v5.19.
        #
        # immunity: ARCH_CAP_SBDR_SSDP_NO (bit 13) AND ARCH_CAP_FBSDP_NO (bit 14) AND ARCH_CAP_PSDP_NO (bit 15)
        #   All three must be set. Checked via arch_cap_mmio_immune() in common.c.
        #   Bug is set only when: cpu_matches(blacklist, MMIO) AND NOT arch_cap_mmio_immune().
        #
        # microcode mitigation: ARCH_CAP_FB_CLEAR (bit 17) -- VERW clears fill buffers.
        #   Alternative: MD_CLEAR CPUID + FLUSH_L1D CPUID when MDS_NO is not set (legacy path).
        #
        # vendor scope: Intel only. Non-Intel CPUs never set X86_BUG_MMIO_STALE_DATA.
        sys_interface_available=1
        status=$ret_sys_interface_check_status
    fi

    if [ "$opt_sysfs_only" != 1 ]; then
        pr_info_nol "* Kernel supports MMIO Stale Data mitigation: "
        kernel_mmio=''
        kernel_mmio_can_tell=1
        if [ -n "$g_kernel_err" ]; then
            kernel_mmio_can_tell=0
        elif grep -q 'mmio_stale_data' "$g_kernel" 2>/dev/null; then
            pr_debug "mmio: found 'mmio_stale_data' string in kernel image"
            kernel_mmio='found MMIO Stale Data mitigation evidence in kernel image'
            pstatus green YES "$kernel_mmio"
        fi
        if [ -z "$kernel_mmio" ] && [ -n "$opt_config" ] && grep -q '^CONFIG_MITIGATION_MMIO_STALE_DATA=y' "$opt_config"; then
            kernel_mmio='found MMIO Stale Data mitigation config option enabled'
            pstatus green YES "$kernel_mmio"
        fi
        if [ -z "$kernel_mmio" ] && [ -n "$opt_map" ]; then
            if grep -qE 'mmio_select_mitigation|cpu_show_mmio_stale_data' "$opt_map"; then
                kernel_mmio='found MMIO Stale Data mitigation function in System.map'
                pstatus green YES "$kernel_mmio"
            fi
        fi
        if [ -z "$kernel_mmio" ]; then
            if [ "$kernel_mmio_can_tell" = 1 ]; then
                pstatus yellow NO
            else
                pstatus yellow UNKNOWN
            fi
        fi

        pr_info_nol "* CPU microcode supports Fill Buffer clearing: "
        if [ "$cap_fb_clear" = -1 ]; then
            pstatus yellow UNKNOWN
        elif [ "$cap_fb_clear" = 1 ]; then
            pstatus green YES
        else
            pstatus yellow NO
        fi

        if [ "$opt_live" = 1 ] && [ "$sys_interface_available" = 1 ]; then
            pr_info_nol "* Kernel mitigation is enabled and active: "
            if echo "$ret_sys_interface_check_fullmsg" | grep -qi ^mitigation; then
                mmio_mitigated=1
                pstatus green YES
            else
                mmio_mitigated=0
                pstatus yellow NO
            fi
            pr_info_nol "* SMT is either mitigated or disabled: "
            if echo "$ret_sys_interface_check_fullmsg" | grep -Eq 'SMT (disabled|mitigated)'; then
                mmio_smt_mitigated=1
                pstatus green YES
            else
                mmio_smt_mitigated=0
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
            if [ "$cap_fb_clear" = 1 ]; then
                if [ -n "$kernel_mmio" ]; then
                    if [ "$opt_live" = 1 ]; then
                        # mitigation must also be enabled
                        if [ "$mmio_mitigated" = 1 ]; then
                            if [ "$opt_paranoid" != 1 ] || [ "$mmio_smt_mitigated" = 1 ]; then
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
                if [ -n "$kernel_mmio" ]; then
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
            # if paranoid mode is enabled, we know that we won't agree on status, so take ours
            pvulnstatus "$cve" "$mystatus" "$mymsg"
        elif [ "$status" = "$mystatus" ]; then
            # if we agree on status, we'll print the common status and our message (more detailed than the sysfs one)
            pvulnstatus "$cve" "$status" "$mymsg"
        else
            # if we don't agree on status, maybe our logic is flawed due to a new kernel/mitigation? use the one from sysfs
            pvulnstatus "$cve" "$status" "$msg"
        fi

        if [ "$mystatus" = VULN ]; then
            explain "Update your kernel to a version that includes MMIO Stale Data mitigation (Linux 5.19+), and update your CPU microcode. If you are using a distribution kernel, make sure you are up to date. To enforce full mitigation including SMT, boot with 'mmio_stale_data=full,nosmt'."
        fi
    fi
}
