# vim: set ts=4 sw=4 sts=4 et:
# Check whether the CPU is known to not perform speculative execution
# Returns: 0 if the CPU is speculation-free, 1 otherwise
is_cpu_specex_free() {
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
            if [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_TABLET" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL" ]; then
                return 0
            fi
        elif [ "$cpu_family" = 5 ]; then
            return 0
        fi
    fi
    # Centaur family 5 and NSC family 5 are also non-speculative
    if [ "$cpu_vendor" = "CentaurHauls" ] && [ "$cpu_family" = 5 ]; then
        return 0
    fi
    if [ "$cpu_vendor" = "Geode by NSC" ] && [ "$cpu_family" = 5 ]; then
        return 0
    fi
    [ "$cpu_family" = 4 ] && return 0
    return 1
}

# Check whether the CPU is known to be unaffected by microarchitectural data sampling (MDS)
# Returns: 0 if MDS-free, 1 if affected or unknown
is_cpu_mds_free() {
    # source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/cpu/common.c
    #VULNWL_INTEL(ATOM_GOLDMONT,             NO_MDS | NO_L1TF),
    #VULNWL_INTEL(ATOM_GOLDMONT_X,           NO_MDS | NO_L1TF),
    #VULNWL_INTEL(ATOM_GOLDMONT_PLUS,        NO_MDS | NO_L1TF),

    #/* AMD Family 0xf - 0x12 */
    #VULNWL_AMD(0x0f,        NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS),
    #VULNWL_AMD(0x10,        NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS),
    #VULNWL_AMD(0x11,        NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS),
    #VULNWL_AMD(0x12,        NO_MELTDOWN | NO_SSB | NO_L1TF | NO_MDS),

    #/* FAMILY_ANY must be last, otherwise 0x0f - 0x12 matches won't work */
    #VULNWL_AMD(X86_FAMILY_ANY,      NO_MELTDOWN | NO_L1TF | NO_MDS),
    #VULNWL_HYGON(X86_FAMILY_ANY,    NO_MELTDOWN | NO_L1TF | NO_MDS),
    parse_cpu_details
    if is_intel; then
        if [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_PLUS" ]; then
                return 0
            fi
        fi
        [ "$cap_mds_no" = 1 ] && return 0
    fi

    # official statement from AMD says none of their CPUs are affected
    # https://www.amd.com/en/corporate/product-security
    # https://www.amd.com/system/files/documents/security-whitepaper.pdf
    if is_amd; then
        return 0
    elif is_hygon; then
        return 0
    elif [ "$cpu_vendor" = CAVIUM ]; then
        return 0
    elif [ "$cpu_vendor" = PHYTIUM ]; then
        return 0
    elif [ "$cpu_vendor" = ARM ]; then
        return 0
    fi

    return 1
}

# Check whether the CPU is known to be unaffected by TSX Asynchronous Abort (TAA)
# Returns: 0 if TAA-free, 1 if affected or unknown
is_cpu_taa_free() {

    if ! is_intel; then
        return 0
    # is intel
    elif [ "$cap_taa_no" = 1 ] || [ "$cap_rtm" = 0 ]; then
        return 0
    fi

    return 1
}

# Check whether the CPU is known to be unaffected by Special Register Buffer Data Sampling (SRBDS)
# Returns: 0 if SRBDS-free, 1 if affected or unknown
is_cpu_srbds_free() {
    # source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/cpu/common.c
    #
    # A processor is affected by SRBDS if its Family_Model and stepping is in the
    # following list, with the exception of the listed processors
    # exporting MDS_NO while Intel TSX is available yet not enabled. The
    # latter class of processors are only affected when Intel TSX is enabled
    # by software using TSX_CTRL_MSR otherwise they are not affected.
    #
    # =============  ============  ========
    # common name    Family_Model  Stepping
    # =============  ============  ========
    # IvyBridge      06_3AH        All              (INTEL_FAM6_IVYBRIDGE)
    #
    # Haswell        06_3CH        All              (INTEL_FAM6_HASWELL)
    # Haswell_L      06_45H        All              (INTEL_FAM6_HASWELL_L)
    # Haswell_G      06_46H        All              (INTEL_FAM6_HASWELL_G)
    #
    # Broadwell_G    06_47H        All              (INTEL_FAM6_BROADWELL_G)
    # Broadwell      06_3DH        All              (INTEL_FAM6_BROADWELL)
    #
    # Skylake_L      06_4EH        All              (INTEL_FAM6_SKYLAKE_L)
    # Skylake        06_5EH        All              (INTEL_FAM6_SKYLAKE)
    #
    # Kabylake_L     06_8EH        <=0xC (MDS_NO)   (INTEL_FAM6_KABYLAKE_L)
    #
    # Kabylake       06_9EH        <=0xD (MDS_NO)   (INTEL_FAM6_KABYLAKE)
    # =============  ============  ========
    parse_cpu_details
    if is_intel; then
        if [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_IVYBRIDGE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_HASWELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_HASWELL_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_HASWELL_G" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_BROADWELL_G" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_BROADWELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE" ]; then
                return 1
            elif [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE_L" ] && [ "$cpu_stepping" -le 12 ] ||
                [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE" ] && [ "$cpu_stepping" -le 13 ]; then
                if [ "$cap_mds_no" -eq 1 ] && { [ "$cap_rtm" -eq 0 ] || [ "$cap_tsx_ctrl_rtm_disable" -eq 1 ]; }; then
                    return 0
                else
                    return 1
                fi
            fi
        fi
    fi

    return 0

}

# Check whether the CPU is known to be unaffected by Speculative Store Bypass (SSB)
# Returns: 0 if SSB-free, 1 if affected or unknown
is_cpu_ssb_free() {
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
            if [ "$cpu_model" = "$INTEL_FAM6_ATOM_AIRMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_MID" ]; then
                return 0
            elif [ "$cpu_model" = "$INTEL_FAM6_CORE_YONAH" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNM" ]; then
                return 0
            fi
        fi
    fi
    if is_amd; then
        if [ "$cpu_family" = "18" ] ||
            [ "$cpu_family" = "17" ] ||
            [ "$cpu_family" = "16" ] ||
            [ "$cpu_family" = "15" ]; then
            return 0
        fi
    fi
    if is_hygon; then
        return 1
    fi
    [ "$cpu_family" = 4 ] && return 0
    return 1
}
