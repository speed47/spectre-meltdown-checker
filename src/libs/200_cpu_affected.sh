# vim: set ts=4 sw=4 sts=4 et:

# Helpers for is_cpu_affected: encode the 4 patterns for setting affected_* variables.
# Each function takes the variable suffix as $1 (e.g. "variantl1tf", not "affected_variantl1tf").
# Variables hold 1 (not affected / immune) or 0 (affected / vuln); empty = not yet decided.

# Set affected_$1 to 1 (not affected) unconditionally.
# Use for: hardware capability bits (cap_rdcl_no, cap_ssb_no, cap_gds_no, cap_tsa_*_no),
#          is_cpu_specex_free results, and vendor-wide immune facts (AMD/L1TF, Cavium, etc.).
# This always wins and cannot be overridden by _infer_vuln (which only fires on empty).
# Must not be followed by _set_vuln for the same variable in the same code path.
_set_immune() { eval "affected_$1=1"; }

# Set affected_$1 to 0 (affected) unconditionally.
# Use for: confirmed-vuln model/erratum lists, ARM unknown-CPU fallback.
# Note: intentionally overrides a prior _infer_immune (1) — this is required for ARM
#       big.LITTLE cumulative logic where a second vuln core must override a prior safe core.
# Must not be called after _set_immune for the same variable in the same code path.
_set_vuln() { eval "affected_$1=0"; }

# Set affected_$1 to 1 (not affected) only if not yet decided (currently empty).
# Use for: model/family whitelists, per-part ARM immune inferences,
#          AMD/ARM partial immunity (immune on this variant axis but not others).
_infer_immune() { eval "[ -z \"\$affected_$1\" ] && affected_$1=1 || :"; }

# Set affected_$1 to 0 (affected) only if not yet decided (currently empty).
# Use for: family-level catch-all fallbacks (Intel L1TF non-whitelist, itlbmh non-whitelist).
_infer_vuln() { eval "[ -z \"\$affected_$1\" ] && affected_$1=0 || :"; }

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
    _set_immune zenbleed
    _set_immune inception
    # TSA is AMD specific (Zen 3/4), look for "is_amd" below:
    _set_immune tsa
    # Downfall & Reptar are Intel specific, look for "is_intel" below:
    _set_immune downfall
    _set_immune reptar

    if is_cpu_mds_free; then
        _infer_immune msbds
        _infer_immune mfbds
        _infer_immune mlpds
        _infer_immune mdsum
        pr_debug "is_cpu_affected: cpu not affected by Microarchitectural Data Sampling"
    fi

    if is_cpu_taa_free; then
        _infer_immune taa
        pr_debug "is_cpu_affected: cpu not affected by TSX Asynhronous Abort"
    fi

    if is_cpu_srbds_free; then
        _infer_immune srbds
        pr_debug "is_cpu_affected: cpu not affected by Special Register Buffer Data Sampling"
    fi

    if is_cpu_specex_free; then
        _set_immune variant1
        _set_immune variant2
        _set_immune variant3
        _set_immune variant3a
        _set_immune variant4
        _set_immune variantl1tf
        _set_immune msbds
        _set_immune mfbds
        _set_immune mlpds
        _set_immune mdsum
        _set_immune taa
        _set_immune srbds
    elif is_intel; then
        # Intel
        # https://github.com/crozone/SpectrePoC/issues/1 ^F E5200 => spectre 2 not affected
        # https://github.com/paboldin/meltdown-exploit/issues/19 ^F E5200 => meltdown affected
        # model name : Pentium(R) Dual-Core  CPU      E5200  @ 2.50GHz
        if echo "$cpu_friendly_name" | grep -qE 'Pentium\(R\) Dual-Core[[:space:]]+CPU[[:space:]]+E[0-9]{4}K?'; then
            _set_vuln variant1
            _infer_immune variant2
            _set_vuln variant3
        fi
        if [ "$cap_rdcl_no" = 1 ]; then
            # capability bit for future Intel processor that will explicitly state
            # that they're not affected to Meltdown
            # this var is set in check_cpu()
            _set_immune variant3
            _set_immune variantl1tf
            pr_debug "is_cpu_affected: RDCL_NO is set so not vuln to meltdown nor l1tf"
        fi
        if [ "$cap_ssb_no" = 1 ]; then
            # capability bit for future Intel processor that will explicitly state
            # that they're not affected to Variant 4
            # this var is set in check_cpu()
            _set_immune variant4
            pr_debug "is_cpu_affected: SSB_NO is set so not vuln to affected_variant4"
        fi
        if is_cpu_ssb_free; then
            _infer_immune variant4
            pr_debug "is_cpu_affected: cpu not affected by speculative store bypass so not vuln to affected_variant4"
        fi
        # variant 3a
        if [ "$cpu_family" = 6 ]; then
            if [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNL" ] || [ "$cpu_model" = "$INTEL_FAM6_XEON_PHI_KNM" ]; then
                pr_debug "is_cpu_affected: xeon phi immune to variant 3a"
                _infer_immune variant3a
            elif [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_MID" ] ||
                [ "$cpu_model" = "$INTEL_FAM6_ATOM_SILVERMONT_D" ]; then
                # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00115.html
                # https://github.com/speed47/spectre-meltdown-checker/issues/310
                # => silvermont CPUs (aka cherry lake for tablets and brawsell for mobile/desktop) don't seem to be affected
                # => goldmont ARE affected
                pr_debug "is_cpu_affected: silvermont immune to variant 3a"
                _infer_immune variant3a
            fi
        fi
        # L1TF (cap_rdcl_no already checked above)
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
                _infer_immune variantl1tf
            else
                pr_debug "is_cpu_affected: intel family 6 is vuln to l1tf"
                _infer_vuln variantl1tf
            fi
        elif [ "$cpu_family" -lt 6 ]; then
            pr_debug "is_cpu_affected: intel family < 6 is immune to l1tf"
            _infer_immune variantl1tf
        fi
        # Downfall
        if [ "$cap_gds_no" = 1 ]; then
            # capability bit for future Intel processors that will explicitly state
            # that they're unaffected by GDS. Also set by hypervisors on virtual CPUs
            # so that the guest kernel doesn't try to mitigate GDS when it's already mitigated on the host
            pr_debug "is_cpu_affected: downfall: not affected (GDS_NO)"
            _set_immune downfall
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
                _set_vuln downfall
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
                _set_vuln reptar
                g_reptar_fixed_ucode_version=$fixed_ucode_ver
                break
            fi
        done

    elif is_amd || is_hygon; then
        # AMD revised their statement about affected_variant2 => affected
        # https://www.amd.com/en/corporate/speculative-execution
        _set_vuln variant1
        _set_vuln variant2
        _infer_immune variant3
        # https://www.amd.com/en/corporate/security-updates
        # "We have not identified any AMD x86 products susceptible to the Variant 3a vulnerability in our analysis to-date."
        _infer_immune variant3a
        if is_cpu_ssb_free; then
            _infer_immune variant4
            pr_debug "is_cpu_affected: cpu not affected by speculative store bypass so not vuln to affected_variant4"
        fi
        _set_immune variantl1tf

        # Zenbleed
        amd_legacy_erratum "$(amd_model_range 0x17 0x30 0x0 0x4f 0xf)" && _set_vuln zenbleed
        amd_legacy_erratum "$(amd_model_range 0x17 0x60 0x0 0x7f 0xf)" && _set_vuln zenbleed
        amd_legacy_erratum "$(amd_model_range 0x17 0xa0 0x0 0xaf 0xf)" && _set_vuln zenbleed

        # Inception (according to kernel, zen 1 to 4)
        if [ "$cpu_family" = $((0x17)) ] || [ "$cpu_family" = $((0x19)) ]; then
            _set_vuln inception
        fi

        # TSA (Zen 3/4 are affected, unless CPUID says otherwise)
        if [ "$cap_tsa_sq_no" = 1 ] && [ "$cap_tsa_l1_no" = 1 ]; then
            # capability bits for AMD processors that explicitly state
            # they're not affected to TSA-SQ and TSA-L1
            # these vars are set in check_cpu()
            pr_debug "is_cpu_affected: TSA_SQ_NO and TSA_L1_NO are set so not vuln to TSA"
            _set_immune tsa
        elif [ "$cpu_family" = $((0x19)) ]; then
            _set_vuln tsa
        fi

    elif [ "$cpu_vendor" = CAVIUM ]; then
        _set_immune variant3
        _set_immune variant3a
        _set_immune variantl1tf
    elif [ "$cpu_vendor" = PHYTIUM ]; then
        _set_immune variant3
        _set_immune variant3a
        _set_immune variantl1tf
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
                    _set_vuln variant1
                    _set_vuln variant2
                    _infer_immune variant3
                    _infer_immune variant3a
                    _infer_immune variant4
                    pr_debug "checking cpu$i: armv7 A8/A9/A12/A17 non affected to variants 3, 3a & 4"
                elif [ "$cpuarch" = 7 ] && echo "$cpupart" | grep -q -w -e 0xc0f; then
                    _set_vuln variant1
                    _set_vuln variant2
                    _infer_immune variant3
                    _set_vuln variant3a
                    _infer_immune variant4
                    pr_debug "checking cpu$i: armv7 A15 non affected to variants 3 & 4"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd07 -e 0xd08; then
                    _set_vuln variant1
                    _set_vuln variant2
                    _infer_immune variant3
                    _set_vuln variant3a
                    _set_vuln variant4
                    pr_debug "checking cpu$i: armv8 A57/A72 non affected to variants 3"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd09; then
                    _set_vuln variant1
                    _set_vuln variant2
                    _infer_immune variant3
                    _infer_immune variant3a
                    _set_vuln variant4
                    pr_debug "checking cpu$i: armv8 A73 non affected to variants 3 & 3a"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd0a; then
                    _set_vuln variant1
                    _set_vuln variant2
                    _set_vuln variant3
                    _infer_immune variant3a
                    _set_vuln variant4
                    pr_debug "checking cpu$i: armv8 A75 non affected to variant 3a"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd0b -e 0xd0c -e 0xd0d; then
                    _set_vuln variant1
                    _infer_immune variant2
                    _infer_immune variant3
                    _infer_immune variant3a
                    _set_vuln variant4
                    pr_debug "checking cpu$i: armv8 A76/A77/NeoverseN1 non affected to variant 2, 3 & 3a"
                elif [ "$cpuarch" = 8 ] && echo "$cpupart" | grep -q -w -e 0xd40 -e 0xd49 -e 0xd4f; then
                    _set_vuln variant1
                    _infer_immune variant2
                    _infer_immune variant3
                    _infer_immune variant3a
                    _infer_immune variant4
                    pr_debug "checking cpu$i: armv8 NeoverseN2/V1/V2 non affected to variant 2, 3, 3a & 4"
                elif [ "$cpuarch" -le 7 ] || { [ "$cpuarch" = 8 ] && [ $((cpupart)) -lt $((0xd07)) ]; }; then
                    _infer_immune variant1
                    _infer_immune variant2
                    _infer_immune variant3
                    _infer_immune variant3a
                    _infer_immune variant4
                    pr_debug "checking cpu$i: arm arch$cpuarch, all immune (v7 or v8 and model < 0xd07)"
                else
                    _set_vuln variant1
                    _set_vuln variant2
                    _set_vuln variant3
                    _set_vuln variant3a
                    _set_vuln variant4
                    pr_debug "checking cpu$i: arm unknown arch$cpuarch part$cpupart, considering vuln"
                fi
            fi
            pr_debug "is_cpu_affected: for cpu$i and so far, we have <$affected_variant1> <$affected_variant2> <$affected_variant3> <$affected_variant3a> <$affected_variant4>"
        done
        _set_immune variantl1tf
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
                _infer_immune itlbmh
            else
                pr_debug "is_cpu_affected: intel family 6 is vuln to itlbmh"
                _infer_vuln itlbmh
            fi
        elif [ "$cpu_family" -lt 6 ]; then
            pr_debug "is_cpu_affected: intel family < 6 is immune to itlbmh"
            _infer_immune itlbmh
        fi
    else
        pr_debug "is_cpu_affected: non-intel not affected to itlbmh"
        _infer_immune itlbmh
    fi

    # shellcheck disable=SC2154  # affected_zenbleed/inception/tsa/downfall/reptar set via eval (_set_immune)
    {
        pr_debug "is_cpu_affected: final results: variant1=$affected_variant1 variant2=$affected_variant2 variant3=$affected_variant3 variant3a=$affected_variant3a"
        pr_debug "is_cpu_affected: final results: variant4=$affected_variant4 variantl1tf=$affected_variantl1tf msbds=$affected_msbds mfbds=$affected_mfbds"
        pr_debug "is_cpu_affected: final results: mlpds=$affected_mlpds mdsum=$affected_mdsum taa=$affected_taa itlbmh=$affected_itlbmh srbds=$affected_srbds"
        pr_debug "is_cpu_affected: final results: zenbleed=$affected_zenbleed inception=$affected_inception tsa=$affected_tsa downfall=$affected_downfall reptar=$affected_reptar"
    }
    affected_variantl1tf_sgx="$affected_variantl1tf"
    # even if we are affected to L1TF, if there's no SGX, we're not affected to the original foreshadow
    [ "$cap_sgx" = 0 ] && _set_immune variantl1tf_sgx
    pr_debug "is_cpu_affected: variantl1tf_sgx=<$affected_variantl1tf_sgx>"
    g_is_cpu_affected_cached=1
    _is_cpu_affected_cached "$1"
    return $?
}
