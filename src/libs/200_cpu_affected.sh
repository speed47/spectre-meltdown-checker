# vim: set ts=4 sw=4 sts=4 et:
# Return the cached affected_* status for a given CVE
# Args: $1=cve_id
# Returns: 0 if affected, 1 if not affected
# Callers: is_cpu_affected
_is_cpu_affected_cached() {
    local suffix
    suffix=$(_cve_registry_field "$1" 3)
    # shellcheck disable=SC2086
    eval "return \$affected_${suffix}"
}

# Determine whether the current CPU is affected by a given CVE using whitelist logic
# Args: $1=cve_id (one of the $g_supported_cve_list items)
# Returns: 0 if affected, 1 if not affected
is_cpu_affected() {
    local result cpuid_hex reptar_ucode_list tuple fixed_ucode_ver affected_fmspi affected_fms ucode_platformid_mask affected_cpuid i cpupart cpuarch

    # if CPU is Intel and is in our dump of the Intel official affected CPUs page, use it:
    if is_intel; then
        cpuid_hex=$(printf "0x%08X" $((cpu_cpuid)))
        if [ "${g_intel_line:-}" = "no" ]; then
            pr_debug "is_cpu_affected: $cpuid_hex not in Intel database (cached)"
        elif [ -z "$g_intel_line" ]; then
            g_intel_line=$(read_inteldb | grep -F "$cpuid_hex," | head -n1)
            if [ -z "$g_intel_line" ]; then
                g_intel_line=no
                pr_debug "is_cpu_affected: $cpuid_hex not in Intel database"
            fi
        fi
        if [ "$g_intel_line" != "no" ]; then
            result=$(echo "$g_intel_line" | grep -Eo ,"$(echo "$1" | cut -c5-)"'=[^,]+' | cut -d= -f2)
            pr_debug "is_cpu_affected: inteldb for $1 says '$result'"

            # handle special case for Foreshadow SGX (CVE-2018-3615):
            # even if we are affected to L1TF (CVE-2018-3620/CVE-2018-3646), if there's no SGX on our CPU,
            # then we're not affected to the original Foreshadow.
            if [ "$1" = "CVE-2018-3615" ] && [ "$cap_sgx" = 0 ]; then
                # not affected
                return 1
            fi
            # /special case

            if [ "$result" = "N" ]; then
                # not affected
                return 1
            elif [ -n "$result" ]; then
                # non-empty string != N means affected
                return 0
            fi
        fi
    fi

    # Otherwise, do it ourselves

    if [ "$g_is_cpu_affected_cached" = 1 ]; then
        _is_cpu_affected_cached "$1"
        return $?
    fi

    affected_variant1=''
    affected_variant2=''
    affected_variant3=''
    affected_variant3a=''
    affected_variant4=''
    affected_variantl1tf=''
    affected_msbds=''
    affected_mfbds=''
    affected_mlpds=''
    affected_mdsum=''
    affected_taa=''
    affected_itlbmh=''
    affected_srbds=''
    # Zenbleed and Inception are both AMD specific, look for "is_amd" below:
    affected_zenbleed=immune
    affected_inception=immune
    # Downfall & Reptar are Intel specific, look for "is_intel" below:
    affected_downfall=immune
    affected_reptar=immune

    if is_cpu_mds_free; then
        [ -z "$affected_msbds" ] && affected_msbds=immune
        [ -z "$affected_mfbds" ] && affected_mfbds=immune
        [ -z "$affected_mlpds" ] && affected_mlpds=immune
        [ -z "$affected_mdsum" ] && affected_mdsum=immune
        pr_debug "is_cpu_affected: cpu not affected by Microarchitectural Data Sampling"
    fi

    if is_cpu_taa_free; then
        [ -z "$affected_taa" ] && affected_taa=immune
        pr_debug "is_cpu_affected: cpu not affected by TSX Asynhronous Abort"
    fi

    if is_cpu_srbds_free; then
        [ -z "$affected_srbds" ] && affected_srbds=immune
        pr_debug "is_cpu_affected: cpu not affected by Special Register Buffer Data Sampling"
    fi

    if is_cpu_specex_free; then
        affected_variant1=immune
        affected_variant2=immune
        affected_variant3=immune
        affected_variant3a=immune
        affected_variant4=immune
        affected_variantl1tf=immune
        affected_msbds=immune
        affected_mfbds=immune
        affected_mlpds=immune
        affected_mdsum=immune
        affected_taa=immune
        affected_srbds=immune
    elif is_intel; then
        # Intel
        # https://github.com/crozone/SpectrePoC/issues/1 ^F E5200 => spectre 2 not affected
        # https://github.com/paboldin/meltdown-exploit/issues/19 ^F E5200 => meltdown affected
        # model name : Pentium(R) Dual-Core  CPU      E5200  @ 2.50GHz
        if echo "$cpu_friendly_name" | grep -qE 'Pentium\(R\) Dual-Core[[:space:]]+CPU[[:space:]]+E[0-9]{4}K?'; then
            affected_variant1=vuln
            [ -z "$affected_variant2" ] && affected_variant2=immune
            affected_variant3=vuln
        fi
        if [ "$cap_rdcl_no" = 1 ]; then
            # capability bit for future Intel processor that will explicitly state
            # that they're not affected to Meltdown
            # this var is set in check_cpu()
            [ -z "$affected_variant3" ] && affected_variant3=immune
            [ -z "$affected_variantl1tf" ] && affected_variantl1tf=immune
            pr_debug "is_cpu_affected: RDCL_NO is set so not vuln to meltdown nor l1tf"
        fi
        if [ "$cap_ssb_no" = 1 ]; then
            # capability bit for future Intel processor that will explicitly state
            # that they're not affected to Variant 4
            # this var is set in check_cpu()
            [ -z "$affected_variant4" ] && affected_variant4=immune
            pr_debug "is_cpu_affected: SSB_NO is set so not vuln to affected_variant4"
        fi
        if is_cpu_ssb_free; then
            [ -z "$affected_variant4" ] && affected_variant4=immune
            pr_debug "is_cpu_affected: cpu not affected by speculative store bypass so not vuln to affected_variant4"
        fi
        # variant 3a
        if [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNL" ] || [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNM" ]; then
                pr_debug "is_cpu_affected: xeon phi immune to variant 3a"
                [ -z "$affected_variant3a" ] && affected_variant3a=immune
            elif [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_D" ]; then
                # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00115.html
                # https://github.com/speed47/spectre-meltdown-checker/issues/310
                # => silvermont CPUs (aka cherry lake for tablets and brawsell for mobile/desktop) don't seem to be affected
                # => goldmont ARE affected
                pr_debug "is_cpu_affected: silvermont immune to variant 3a"
                [ -z "$affected_variant3a" ] && affected_variant3a=immune
            fi
        fi
        # L1TF (RDCL_NO already checked above)
        if [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_TABLET" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_AIRMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_AIRMONT_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_AIRMONT_NP" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_PLUS" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_TREMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNM" ]; then

                pr_debug "is_cpu_affected: intel family 6 but model known to be immune to l1tf"
                [ -z "$affected_variantl1tf" ] && affected_variantl1tf=immune
            else
                pr_debug "is_cpu_affected: intel family 6 is vuln to l1tf"
                affected_variantl1tf=vuln
            fi
        elif [ "$cpu_family" -lt 6 ]; then
            pr_debug "is_cpu_affected: intel family < 6 is immune to l1tf"
            [ -z "$affected_variantl1tf" ] && affected_variantl1tf=immune
        fi
        # Downfall
        if [ "$cap_gds_no" = 1 ]; then
            # capability bit for future Intel processors that will explicitly state
            # that they're unaffected by GDS. Also set by hypervisors on virtual CPUs
            # so that the guest kernel doesn't try to mitigate GDS when it's already mitigated on the host
            pr_debug "is_cpu_affected: downfall: not affected (GDS_NO)"
        elif [ "$cpu_family" = 6 ]; then
            # list from https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=64094e7e3118aff4b0be8ff713c242303e139834
            set -u
            if [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ICELAKE_X" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_COMETLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_COMETLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_TIGERLAKE_L" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_TIGERLAKE" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ROCKETLAKE" ]; then
                pr_debug "is_cpu_affected: downfall: affected"
                affected_downfall=vuln
            elif [ "$cap_avx2" = 0 ] && [ "$cap_avx512" = 0 ]; then
                pr_debug "is_cpu_affected: downfall: no avx; immune"
            else
                # old Intel CPU (not in their DB), not listed as being affected by the Linux kernel,
                # but with AVX2 or AVX512: unclear for now
                pr_debug "is_cpu_affected: downfall: unclear, defaulting to non-affected for now"
            fi
            set +u
        fi
        # Reptar
        # the only way to know whether a CPU is vuln, is to check whether there is a known ucode update for it,
        # as the mitigation is only ucode-based and there's no flag exposed by the kernel or by an updated ucode.
        # we have to hardcode the truthtable of affected CPUs vs updated ucodes...
        # https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/redundant-prefix-issue.html
        # list taken from:
        # https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/commit/ece0d294a29a1375397941a4e6f2f7217910bc89#diff-e6fad0f2abbac6c9603b2e8f88fe1d151a83de708aeca1c1d93d881c958ecba4R26
        # both pages have a lot of inconsistencies, I've tried to fix the errors the best I could, the logic being: if it's not in the
        # blog page, then the microcode update in the commit is not related to reptar, if microcode versions differ, then the one in github is correct,
        # if a stepping exists in the blog page but not in the commit, then the blog page is right
        reptar_ucode_list='
06-97-02/07,00000032
06-97-05/07,00000032
06-9a-03/80,00000430
06-9a-04/80,00000430
06-6c-01/10,01000268
06-6a-06/87,0d0003b9
06-7e-05/80,000000c2
06-ba-02/e0,0000411c
06-b7-01/32,0000011d
06-a7-01/02,0000005d
06-bf-05/07,00000032
06-bf-02/07,00000032
06-ba-03/e0,0000411c
06-8f-08/87,2b0004d0
06-8f-07/87,2b0004d0
06-8f-06/87,2b0004d0
06-8f-05/87,2b0004d0
06-8f-04/87,2b0004d0
06-8f-08/10,2c000290
06-8c-01/80,000000b4
06-8c-00/ff,000000b4
06-8d-01/c2,0000004e
06-8d-00/c2,0000004e
06-8c-02/c2,00000034
'
        for tuple in $reptar_ucode_list; do
            fixed_ucode_ver=$((0x$(echo "$tuple" | cut -d, -f2)))
            affected_fmspi=$(echo "$tuple" | cut -d, -f1)
            affected_fms=$(echo "$affected_fmspi" | cut -d/ -f1)
            ucode_platformid_mask=0x$(echo "$affected_fmspi" | cut -d/ -f2)
            affected_cpuid=$(
                fms2cpuid \
                    0x"$(echo "$affected_fms" | cut -d- -f1)" \
                    0x"$(echo "$affected_fms" | cut -d- -f2)" \
                    0x"$(echo "$affected_fms" | cut -d- -f3)"
            )
            if [ "$cpu_cpuid" = "$affected_cpuid" ] && [ $((cpu_platformid & ucode_platformid_mask)) -gt 0 ]; then
                # this is not perfect as Intel never tells about their EOL CPUs, so more CPUs might be affected but there's no way to tell
                affected_reptar=vuln
                g_reptar_fixed_ucode_version=$fixed_ucode_ver
                break
            fi
        done

    elif is_amd || is_hygon; then
        # AMD revised their statement about affected_variant2 => affected
        # https://www.amd.com/en/corporate/speculative-execution
        affected_variant1=vuln
        affected_variant2=vuln
        [ -z "$affected_variant3" ] && affected_variant3=immune
        # https://www.amd.com/en/corporate/security-updates
        # "We have not identified any AMD x86 products susceptible to the Variant 3a vulnerability in our analysis to-date."
        [ -z "$affected_variant3a" ] && affected_variant3a=immune
        if is_cpu_ssb_free; then
            [ -z "$affected_variant4" ] && affected_variant4=immune
            pr_debug "is_cpu_affected: cpu not affected by speculative store bypass so not vuln to affected_variant4"
        fi
        affected_variantl1tf=immune

        # Zenbleed
        amd_legacy_erratum "$(amd_model_range 0x17 0x30 0x0 0x4f 0xf)" && affected_zenbleed=vuln
        amd_legacy_erratum "$(amd_model_range 0x17 0x60 0x0 0x7f 0xf)" && affected_zenbleed=vuln
        amd_legacy_erratum "$(amd_model_range 0x17 0xa0 0x0 0xaf 0xf)" && affected_zenbleed=vuln

        # Inception (according to kernel, zen 1 to 4)
        if [ "$cpu_family" = $((0x17)) ] || [ "$cpu_family" = $((0x19)) ]; then
            affected_inception=vuln
        fi

    elif [ "$cpu_vendor" = CAVIUM ]; then
        affected_variant3=immune
        affected_variant3a=immune
        affected_variantl1tf=immune
    elif [ "$cpu_vendor" = PHYTIUM ]; then
        affected_variant3=immune
        affected_variant3a=immune
        affected_variantl1tf=immune
    elif [ "$cpu_vendor" = ARM ]; then
        # ARM
        # reference: https://developer.arm.com/support/security-update
        # some devices (phones or other) have several ARMs and as such different part numbers,
        # an example is "bigLITTLE". we shouldn't rely on the first CPU only, so we check the whole list
        i=0
        for cpupart in $cpu_part_list; do
            i=$((i + 1))
            # do NOT quote $cpu_arch_list below
            # shellcheck disable=SC2086
            cpuarch=$(echo $cpu_arch_list | awk '{ print $'$i' }')
            pr_debug "checking cpu$i: <$cpupart> <$cpuarch>"
            # some kernels report AArch64 instead of 8
            [ "$cpuarch" = "AArch64" ] && cpuarch=8
            # some kernels report architecture with suffix (e.g. "5TEJ" for ARMv5TEJ), extract numeric prefix
            cpuarch=$(echo "$cpuarch" | grep -oE '^[0-9]+')
            if [ -n "$cpupart" ] && [ -n "$cpuarch" ]; then
                # Cortex-R7 and Cortex-R8 are real-time and only used in medical devices or such
                # I can't find their CPU part number, but it's probably not that useful anyway
                # model R7 R8 A8  A9  A12 A15 A17 A57 A72 A73 A75 A76 A77 Neoverse-N1 Neoverse-V1 Neoverse-N1 Neoverse-V2
                # part   ?  ? c08 c09 c0d c0f c0e d07 d08 d09 d0a d0b d0d d0c         d40	  d49	      d4f
                # arch  7? 7? 7   7   7   7   7   8   8   8   8   8   8   8           8		  8	      8
                #
                # Whitelist identified non-affected processors, use vulnerability information from
                # https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability
                # Partnumbers can be found here:
                # https://github.com/gcc-mirror/gcc/blob/master/gcc/config/arm/arm-cpus.in
                #
                # Maintain cumulative check of vulnerabilities -
                # if at least one of the cpu is affected, then the system is affected
                if [ "$cpuarch" = 7 ] && echo "$cpupart" | grep -q -w -e 0xc08 -e 0xc09 -e 0xc0d -e 0xc0e; then
                    affected_variant1=vuln
                    affected_variant2=vuln
                    [ -z "$affected_variant3" ] && affected_variant3=immune
                    [ -z "$affected_variant3a" ] && affected_variant3a=immune
                    [ -z "$affected_variant4" ] && affected_variant4=immune
                    pr_debug "checking cpu$i: armv7 A8/A9/A12/A17 non affected to variants 3, 3a & 4"
                elif [ "$cpuarch" = 7 ] && echo "$cpupart" | grep -q -w -e 0xc0f; then
                    affected_variant1=vuln
                    affected_variant2=vuln
                    [ -z "$affected_variant3" ] && affected_variant3=immune
                    affected_variant3a=vuln
                    [ -z "$affected_variant4" ] && affected_variant4=immune
                    pr_debug "checking cpu$i: armv7 A15 non affected to variants 3 & 4"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd07 -e 0xd08; then
                    affected_variant1=vuln
                    affected_variant2=vuln
                    [ -z "$affected_variant3" ] && affected_variant3=immune
                    affected_variant3a=vuln
                    affected_variant4=vuln
                    pr_debug "checking cpu$i: armv8 A57/A72 non affected to variants 3"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd09; then
                    affected_variant1=vuln
                    affected_variant2=vuln
                    [ -z "$affected_variant3" ] && affected_variant3=immune
                    [ -z "$affected_variant3a" ] && affected_variant3a=immune
                    affected_variant4=vuln
                    pr_debug "checking cpu$i: armv8 A73 non affected to variants 3 & 3a"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd0a; then
                    affected_variant1=vuln
                    affected_variant2=vuln
                    affected_variant3=vuln
                    [ -z "$affected_variant3a" ] && affected_variant3a=immune
                    affected_variant4=vuln
                    pr_debug "checking cpu$i: armv8 A75 non affected to variant 3a"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd0b -e 0xd0c -e 0xd0d; then
                    affected_variant1=vuln
                    [ -z "$affected_variant2" ] && affected_variant2=immune
                    [ -z "$affected_variant3" ] && affected_variant3=immune
                    [ -z "$affected_variant3a" ] && affected_variant3a=immune
                    affected_variant4=vuln
                    pr_debug "checking cpu$i: armv8 A76/A77/NeoverseN1 non affected to variant 2, 3 & 3a"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd40 -e 0xd49 -e 0xd4f; then
                    affected_variant1=vuln
                    [ -z "$affected_variant2" ] && affected_variant2=immune
                    [ -z "$affected_variant3" ] && affected_variant3=immune
                    [ -z "$affected_variant3a" ] && affected_variant3a=immune
                    [ -z "$affected_variant4" ] && affected_variant4=immune
                    pr_debug "checking cpu$i: armv8 NeoverseN2/V1/V2 non affected to variant 2, 3, 3a & 4"
                elif [ "$cpuarch" -le 7 ] || { [ "$cpuarch" = 8 ] && [ $((cpupart)) -lt $((0xd07)) ]; }; then
                    [ -z "$affected_variant1" ] && affected_variant1=immune
                    [ -z "$affected_variant2" ] && affected_variant2=immune
                    [ -z "$affected_variant3" ] && affected_variant3=immune
                    [ -z "$affected_variant3a" ] && affected_variant3a=immune
                    [ -z "$affected_variant4" ] && affected_variant4=immune
                    pr_debug "checking cpu$i: arm arch$cpuarch, all immune (v7 or v8 and model < 0xd07)"
                else
                    affected_variant1=vuln
                    affected_variant2=vuln
                    affected_variant3=vuln
                    affected_variant3a=vuln
                    affected_variant4=vuln
                    pr_debug "checking cpu$i: arm unknown arch$cpuarch part$cpupart, considering vuln"
                fi
            fi
            pr_debug "is_cpu_affected: for cpu$i and so far, we have <$affected_variant1> <$affected_variant2> <$affected_variant3> <$affected_variant3a> <$affected_variant4>"
        done
        affected_variantl1tf=immune
    fi

    # we handle iTLB Multihit here (not linked to is_specex_free)
    if is_intel; then
        # commit f9aa6b73a407b714c9aac44734eb4045c893c6f7
        if [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_TABLET" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SALTWELL_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_BONNELL_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_AIRMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNL" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNM" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_AIRMONT_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_D" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_GOLDMONT_PLUS" ]; then
                pr_debug "is_cpu_affected: intel family 6 but model known to be immune to itlbmh"
                [ -z "$affected_itlbmh" ] && affected_itlbmh=immune
            else
                pr_debug "is_cpu_affected: intel family 6 is vuln to itlbmh"
                affected_itlbmh=vuln
            fi
        elif [ "$cpu_family" -lt 6 ]; then
            pr_debug "is_cpu_affected: intel family < 6 is immune to itlbmh"
            [ -z "$affected_itlbmh" ] && affected_itlbmh=immune
        fi
    else
        pr_debug "is_cpu_affected: non-intel not affected to itlbmh"
        [ -z "$affected_itlbmh" ] && affected_itlbmh=immune
    fi

    pr_debug "is_cpu_affected: temp results are <$affected_variant1> <$affected_variant2> <$affected_variant3> <$affected_variant3a> <$affected_variant4> <$affected_variantl1tf>"
    [ "$affected_variant1" = "immune" ] && affected_variant1=1 || affected_variant1=0
    [ "$affected_variant2" = "immune" ] && affected_variant2=1 || affected_variant2=0
    [ "$affected_variant3" = "immune" ] && affected_variant3=1 || affected_variant3=0
    [ "$affected_variant3a" = "immune" ] && affected_variant3a=1 || affected_variant3a=0
    [ "$affected_variant4" = "immune" ] && affected_variant4=1 || affected_variant4=0
    [ "$affected_variantl1tf" = "immune" ] && affected_variantl1tf=1 || affected_variantl1tf=0
    [ "$affected_msbds" = "immune" ] && affected_msbds=1 || affected_msbds=0
    [ "$affected_mfbds" = "immune" ] && affected_mfbds=1 || affected_mfbds=0
    [ "$affected_mlpds" = "immune" ] && affected_mlpds=1 || affected_mlpds=0
    [ "$affected_mdsum" = "immune" ] && affected_mdsum=1 || affected_mdsum=0
    [ "$affected_taa" = "immune" ] && affected_taa=1 || affected_taa=0
    [ "$affected_itlbmh" = "immune" ] && affected_itlbmh=1 || affected_itlbmh=0
    [ "$affected_srbds" = "immune" ] && affected_srbds=1 || affected_srbds=0
    [ "$affected_zenbleed" = "immune" ] && affected_zenbleed=1 || affected_zenbleed=0
    [ "$affected_downfall" = "immune" ] && affected_downfall=1 || affected_downfall=0
    [ "$affected_inception" = "immune" ] && affected_inception=1 || affected_inception=0
    [ "$affected_reptar" = "immune" ] && affected_reptar=1 || affected_reptar=0
    affected_variantl1tf_sgx="$affected_variantl1tf"
    # even if we are affected to L1TF, if there's no SGX, we're not affected to the original foreshadow
    [ "$cap_sgx" = 0 ] && affected_variantl1tf_sgx=1
    pr_debug "is_cpu_affected: final results are <$affected_variant1> <$affected_variant2> <$affected_variant3> <$affected_variant3a> <$affected_variant4> <$affected_variantl1tf> <$affected_variantl1tf_sgx>"
    g_is_cpu_affected_cached=1
    _is_cpu_affected_cached "$1"
    return $?
}
