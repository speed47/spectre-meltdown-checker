# vim: set ts=4 sw=4 sts=4 et:
###############################
# Straight-Line Speculation (SLS) supplementary check (--extra only)
#
# SLS: x86 CPUs may speculatively execute instructions past unconditional
# control flow changes (RET, indirect JMP/CALL). Mitigated at compile time
# by CONFIG_MITIGATION_SLS (formerly CONFIG_SLS before kernel 6.8), which
# enables -mharden-sls=all to insert INT3 after these instructions.
# No sysfs interface, no MSR, no CPU feature flag.
# Related: CVE-2021-26341 (AMD Zen1/Zen2 direct-branch SLS subset).

# Heuristic: scan the kernel .text section for indirect call/jmp thunks
# (retpoline-style stubs), then check whether tail-call JMPs to those thunks
# are followed by INT3 (0xcc). With SLS enabled: >80%. Without: <20%.
#
# Thunk signature: e8 01 00 00 00 cc 48 89 XX 24
#   call +1; int3; mov <reg>,(%rsp); ...
# Tail-call pattern: e9 XX XX XX XX [cc?]
#   jmp <thunk>; [int3 if SLS]

# Perl implementation of the SLS heuristic byte scanner.
# Args: $1 = path to raw .text binary (from objcopy -O binary -j .text)
# Output: thunks=N jmps=N sls=N
#
# The heuristic looks for two types of thunks and counts how many jmp rel32
# instructions targeting them are followed by INT3 (the SLS mitigation):
#
# 1. Indirect call/jmp thunks (retpoline stubs used for indirect tail calls):
#    e8 01 00 00 00 cc 48 89 XX 24  (call +1; int3; mov <reg>,(%rsp))
#
# 2. Return thunk (used for all function returns via jmp __x86_return_thunk):
#    c3 90 90 90 90 cc cc cc cc cc  (ret; nop*4; int3*5+)
#    This is the most common jmp target in retpoline-enabled kernels.
#
# Some kernels only use indirect thunks, some only the return thunk, and some
# use both. We check both and combine the results.
_sls_heuristic_perl() {
    perl -e '
        use strict;
        use warnings;
        local $/;
        open my $fh, "<:raw", $ARGV[0] or die "open: $!";
        my $text = <$fh>;
        close $fh;
        my $len = length($text);

        # Collect two types of thunks separately, as different kernels
        # apply SLS to different thunk types.

        my (%indirect_thunks, %return_thunks);

        # Pattern 1: indirect call/jmp thunks (retpoline stubs)
        while ($text =~ /\xe8\x01\x00\x00\x00\xcc\x48\x89.\x24/gs) {
            $indirect_thunks{ pos($text) - length($&) } = 1;
        }

        # Pattern 2: return thunk (ret; nop*4; int3*5)
        while ($text =~ /\xc3\x90\x90\x90\x90\xcc\xcc\xcc\xcc\xcc/gs) {
            $return_thunks{ pos($text) - length($&) } = 1;
        }

        my $n_indirect = scalar keys %indirect_thunks;
        my $n_return = scalar keys %return_thunks;

        if ($n_indirect + $n_return == 0) {
            print "thunks=0 jmps=0 sls=0\n";
            exit 0;
        }

        # Count jmps to each thunk type separately
        my ($ind_total, $ind_sls) = (0, 0);
        my ($ret_total, $ret_sls) = (0, 0);

        for (my $i = 0; $i + 5 < $len; $i++) {
            next unless substr($text, $i, 1) eq "\xe9";
            my $rel = unpack("V", substr($text, $i + 1, 4));
            $rel -= 4294967296 if $rel >= 2147483648;
            my $target = $i + 5 + $rel;
            my $has_int3 = ($i + 5 < $len && substr($text, $i + 5, 1) eq "\xcc") ? 1 : 0;
            if (exists $indirect_thunks{$target}) {
                $ind_total++;
                $ind_sls += $has_int3;
            }
            if (exists $return_thunks{$target}) {
                $ret_total++;
                $ret_sls += $has_int3;
            }
        }

        # Use whichever thunk type has jmps; prefer indirect thunks if both have data
        my ($total, $sls, $n_thunks);
        if ($ind_total > 0) {
            ($total, $sls, $n_thunks) = ($ind_total, $ind_sls, $n_indirect);
        } elsif ($ret_total > 0) {
            ($total, $sls, $n_thunks) = ($ret_total, $ret_sls, $n_return);
        } else {
            ($total, $sls, $n_thunks) = (0, 0, $n_indirect + $n_return);
        }

        printf "thunks=%d jmps=%d sls=%d\n", $n_thunks, $total, $sls;
    ' "$1" 2>/dev/null
}

# Awk fallback implementation of the SLS heuristic byte scanner.
# Slower than perl but uses only POSIX tools (od + awk).
# Args: $1 = path to raw .text binary (from objcopy -O binary -j .text)
# Output: thunks=N jmps=N sls=N
_sls_heuristic_awk() {
    od -An -tu1 -v "$1" | awk '
    {
        for (i = 1; i <= NF; i++) b[n++] = $i + 0
    }
    END {
        # Pattern 1: indirect call/jmp thunks
        # 232 1 0 0 0 204 72 137 XX 36  (e8 01 00 00 00 cc 48 89 XX 24)
        for (i = 0; i + 9 < n; i++) {
            if (b[i]==232 && b[i+1]==1 && b[i+2]==0 && b[i+3]==0 && \
                b[i+4]==0 && b[i+5]==204 && b[i+6]==72 && b[i+7]==137 && \
                b[i+9]==36) {
                ind[i] = 1
                n_ind++
            }
        }
        # Pattern 2: return thunk (ret; nop*4; int3*5)
        # 195 144 144 144 144 204 204 204 204 204  (c3 90 90 90 90 cc cc cc cc cc)
        for (i = 0; i + 9 < n; i++) {
            if (b[i]==195 && b[i+1]==144 && b[i+2]==144 && b[i+3]==144 && \
                b[i+4]==144 && b[i+5]==204 && b[i+6]==204 && b[i+7]==204 && \
                b[i+8]==204 && b[i+9]==204) {
                ret[i] = 1
                n_ret++
            }
        }
        if (n_ind + n_ret == 0) { print "thunks=0 jmps=0 sls=0"; exit }

        # Count jmps to each thunk type separately
        ind_total = 0; ind_sls = 0
        ret_total = 0; ret_sls = 0
        for (i = 0; i + 5 < n; i++) {
            if (b[i] != 233) continue
            rel = b[i+1] + b[i+2]*256 + b[i+3]*65536 + b[i+4]*16777216
            if (rel >= 2147483648) rel -= 4294967296
            target = i + 5 + rel
            has_int3 = (b[i+5] == 204) ? 1 : 0
            if (target in ind) { ind_total++; ind_sls += has_int3 }
            if (target in ret) { ret_total++; ret_sls += has_int3 }
        }

        # Prefer indirect thunks if they have data, else fall back to return thunk
        if (ind_total > 0)
            printf "thunks=%d jmps=%d sls=%d\n", n_ind, ind_total, ind_sls
        else if (ret_total > 0)
            printf "thunks=%d jmps=%d sls=%d\n", n_ret, ret_total, ret_sls
        else
            printf "thunks=%d jmps=0 sls=0\n", n_ind + n_ret
    }' 2>/dev/null
}

check_CVE_0000_0001_linux() {
    local status sys_interface_available msg
    status=UNK
    sys_interface_available=0
    msg=''

    # No sysfs interface for SLS
    # sys_interface_available stays 0

    if [ "$opt_sysfs_only" != 1 ]; then

        # --- CPU affection check ---
        if ! is_cpu_affected "$cve"; then
            pvulnstatus "$cve" OK "your CPU is not affected"
            return
        fi

        # --- ARM: no kernel mitigation available ---
        if is_arm_kernel; then
            pvulnstatus "$cve" VULN "no kernel mitigation available for arm64 SLS (CVE-2020-13844)"
            explain "Your ARM processor is affected by Straight-Line Speculation (CVE-2020-13844).\n" \
                "GCC and Clang support -mharden-sls=all for aarch64, which inserts SB (Speculation Barrier)\n" \
                "or DSB+ISB after RET and BR instructions. However, the Linux kernel does not enable this flag:\n" \
                "patches to add CONFIG_HARDEN_SLS_ALL were submitted in 2021 but were rejected upstream.\n" \
                "There is currently no kernel-level mitigation for SLS on arm64."
            return
        fi

        # --- x86: config check and binary heuristic ---
        if ! is_x86_kernel; then
            pvulnstatus "$cve" UNK "SLS mitigation detection not supported for this kernel architecture"
            return
        fi

        local _sls_config=''
        if [ -n "$opt_config" ] && [ -r "$opt_config" ]; then
            pr_info_nol "  * Kernel compiled with SLS mitigation: "
            if grep -qE '^CONFIG_(MITIGATION_)?SLS=y' "$opt_config"; then
                _sls_config=1
                pstatus green YES
            else
                _sls_config=0
                pstatus yellow NO
            fi
        fi

        # --- method 2: kernel image heuristic (fallback when no config) ---
        local _sls_heuristic=''
        if [ -z "$_sls_config" ]; then
            pr_info_nol "  * Kernel compiled with SLS mitigation: "
            if [ -n "$g_kernel_err" ]; then
                pstatus yellow UNKNOWN "$g_kernel_err"
            elif [ -z "$g_kernel" ]; then
                pstatus yellow UNKNOWN "no kernel image available"
            elif ! command -v "${opt_arch_prefix}objcopy" >/dev/null 2>&1; then
                pstatus yellow UNKNOWN "missing '${opt_arch_prefix}objcopy' tool, usually in the binutils package"
            else
                local _sls_result
                g_sls_text_tmp=$(mktemp -t smc-sls-text-XXXXXX)

                if ! "${opt_arch_prefix}objcopy" -O binary -j .text "$g_kernel" "$g_sls_text_tmp" 2>/dev/null || [ ! -s "$g_sls_text_tmp" ]; then
                    pstatus yellow UNKNOWN "failed to extract .text section from kernel image"
                    rm -f "$g_sls_text_tmp"
                    g_sls_text_tmp=''
                else
                    _sls_result=''
                    if command -v perl >/dev/null 2>&1; then
                        _sls_result=$(_sls_heuristic_perl "$g_sls_text_tmp")
                    elif command -v awk >/dev/null 2>&1; then
                        _sls_result=$(_sls_heuristic_awk "$g_sls_text_tmp")
                    fi
                    rm -f "$g_sls_text_tmp"
                    g_sls_text_tmp=''

                    if [ -z "$_sls_result" ]; then
                        pstatus yellow UNKNOWN "missing 'perl' or 'awk' tool for heuristic scan"
                    else
                        local _sls_thunks _sls_jmps _sls_int3
                        _sls_thunks=$(echo "$_sls_result" | sed -n 's/.*thunks=\([0-9]*\).*/\1/p')
                        _sls_jmps=$(echo "$_sls_result" | sed -n 's/.*jmps=\([0-9]*\).*/\1/p')
                        _sls_int3=$(echo "$_sls_result" | sed -n 's/.*sls=\([0-9]*\).*/\1/p')
                        pr_debug "sls heuristic: thunks=$_sls_thunks jmps=$_sls_jmps int3=$_sls_int3"

                        if [ "${_sls_thunks:-0}" = 0 ] || [ "${_sls_jmps:-0}" = 0 ]; then
                            pstatus yellow UNKNOWN "no retpoline indirect thunks found in kernel image"
                        else
                            local _sls_pct=$((_sls_int3 * 100 / _sls_jmps))
                            if [ "$_sls_pct" -ge 80 ]; then
                                _sls_heuristic=1
                                pstatus green YES "$_sls_int3/$_sls_jmps indirect tail-call JMPs hardened (${_sls_pct}%%)"
                            elif [ "$_sls_pct" -le 20 ]; then
                                _sls_heuristic=0
                                pstatus yellow NO "$_sls_int3/$_sls_jmps indirect tail-call JMPs hardened (${_sls_pct}%%)"
                            else
                                pstatus yellow UNKNOWN "$_sls_int3/$_sls_jmps indirect tail-call JMPs hardened (${_sls_pct}%%, inconclusive)"
                            fi
                        fi
                    fi
                fi
            fi
        fi

        # --- verdict (x86_64) ---
        if [ "$_sls_config" = 1 ] || [ "$_sls_heuristic" = 1 ]; then
            pvulnstatus "$cve" OK "kernel compiled with SLS mitigation"
        elif [ "$_sls_config" = 0 ] || [ "$_sls_heuristic" = 0 ]; then
            pvulnstatus "$cve" VULN "kernel not compiled with SLS mitigation"
            explain "Recompile your kernel with CONFIG_MITIGATION_SLS=y (or CONFIG_SLS=y on kernels before 6.8).\n" \
                "This enables the GCC flag -mharden-sls=all, which inserts INT3 after unconditional control flow\n" \
                "instructions to block straight-line speculation. Note: this option defaults to off in most kernels\n" \
                "and incurs ~2.4%% text size overhead."
        else
            pvulnstatus "$cve" UNK "couldn't determine SLS mitigation status"
        fi
    elif [ "$sys_interface_available" = 0 ]; then
        msg="/sys vulnerability interface use forced, but there is no sysfs entry for SLS"
        status=UNK
        pvulnstatus "$cve" "$status" "$msg"
    fi
}

check_CVE_0000_0001_bsd() {
    if ! is_cpu_affected "$cve"; then
        pvulnstatus "$cve" OK "your CPU vendor reported your CPU model as not affected"
    else
        pvulnstatus "$cve" UNK "your CPU is affected, but mitigation detection has not yet been implemented for BSD in this script"
    fi
}
