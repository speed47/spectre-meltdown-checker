# vim: set ts=4 sw=4 sts=4 et:

check_kernel_info

# Build JSON meta and system sections early (after kernel info is resolved)
if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "json" ]; then
    _build_json_meta
fi

pr_info

if [ "$opt_no_hw" = 0 ] && [ -z "$opt_arch_prefix" ]; then
    pr_info "\033[1;34mHardware check\033[0m"
    check_cpu
    check_cpu_vulnerabilities
    pr_info
fi

# Build JSON system/cpu/microcode sections (after check_cpu has populated cap_* vars and VMM detection)
if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "json" ]; then
    _build_json_system
    if [ "$opt_no_hw" = 0 ] && [ -z "$opt_arch_prefix" ]; then
        _build_json_cpu
        _build_json_cpu_microcode
    fi
fi

# Build Prometheus info metric lines (same timing requirement as JSON builders above)
if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "prometheus" ]; then
    _build_prometheus_system_info
    if [ "$opt_no_hw" = 0 ] && [ -z "$opt_arch_prefix" ]; then
        _build_prometheus_cpu_info
    fi
fi

# now run the checks the user asked for
for cve in $g_supported_cve_list; do
    if [ "$opt_cve_all" = 1 ] || echo "$opt_cve_list" | grep -qw "$cve"; then
        check_"$(echo "$cve" | tr - _)"
        pr_info
    fi
done

if [ -n "$g_final_summary" ]; then
    pr_info "> \033[46m\033[30mSUMMARY:\033[0m$g_final_summary"
    pr_info ""
fi

if [ "$g_bad_accuracy" = 1 ]; then
    pr_warn "We're missing some kernel information (see kernel section at the top), accuracy might be reduced"
fi

g_vars=$(set | grep -Ev '^[A-Z_[:space:]]' | grep -v -F 'g_mockme=' | sort | tr "\n" '|')
pr_debug "variables at end of script: $g_vars"

if [ -n "$g_mockme" ] && [ "$opt_mock" = 1 ]; then
    if command -v "gzip" >/dev/null 2>&1; then
        # not a useless use of cat: gzipping cpuinfo directly doesn't work well
        # shellcheck disable=SC2002
        if command -v "base64" >/dev/null 2>&1; then
            g_mock_cpuinfo="$(cat /proc/cpuinfo | gzip -c | base64 | tr -d '\n')"
        elif command -v "uuencode" >/dev/null 2>&1; then
            g_mock_cpuinfo="$(cat /proc/cpuinfo | gzip -c | uuencode -m - | grep -Fv 'begin-base64' | grep -Fxv -- '====' | tr -d "\n")"
        fi
    fi
    if [ -n "$g_mock_cpuinfo" ]; then
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPUINFO='$g_mock_cpuinfo'")
        unset g_mock_cpuinfo
    fi
    pr_info ""
    # shellcheck disable=SC2046
    pr_warn "To mock this CPU, set those vars: "$(echo "$g_mockme" | sort -u)
fi

# root check
if [ "$(id -u)" -ne 0 ]; then
    pr_warn "Note that you should launch this script with root privileges to get completely accurate information."
    pr_warn "To run it as root, you can try the following command: sudo $0"
    pr_warn
fi

if [ "$opt_explain" = 0 ]; then
    pr_info "Need more detailed information about mitigation options? Use --explain"
fi

pr_info "A false sense of security is worse than no security at all, see --disclaimer"

if [ "$g_mocked" = 1 ]; then
    pr_info ""
    pr_warn "One or several values have been g_mocked. This should only be done when debugging/testing this script."
    pr_warn "The results do NOT reflect the actual status of the system we're running on."
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "nrpe" ]; then
    _nrpe_is_root=0
    [ "$(id -u)" -eq 0 ] && _nrpe_is_root=1

    # Non-root + VULN: demote to UNKNOWN, MSR reads were skipped so VULN findings
    # may be false positives or genuine mitigations may have gone undetected
    _nrpe_demoted=0
    [ "$g_nrpe_vuln_count" -gt 0 ] && [ "$_nrpe_is_root" = 0 ] && _nrpe_demoted=1

    # Determine status word and build the one-line summary
    if [ "$_nrpe_demoted" = 1 ]; then
        _nrpe_status_word='UNKNOWN'
        _nrpe_summary="${g_nrpe_vuln_count}/${g_nrpe_total} CVE(s) appear vulnerable (unconfirmed, not root): ${g_nrpe_vuln_ids}"
        [ "$g_nrpe_unk_count" -gt 0 ] && _nrpe_summary="${_nrpe_summary}, ${g_nrpe_unk_count} inconclusive"
    elif [ "$g_nrpe_vuln_count" -gt 0 ]; then
        _nrpe_status_word='CRITICAL'
        _nrpe_summary="${g_nrpe_vuln_count}/${g_nrpe_total} CVE(s) vulnerable: ${g_nrpe_vuln_ids}"
        [ "$g_nrpe_unk_count" -gt 0 ] && _nrpe_summary="${_nrpe_summary}, ${g_nrpe_unk_count} inconclusive"
    elif [ "$g_nrpe_unk_count" -gt 0 ]; then
        _nrpe_status_word='UNKNOWN'
        _nrpe_summary="${g_nrpe_unk_count}/${g_nrpe_total} CVE checks inconclusive"
    else
        _nrpe_status_word='OK'
        _nrpe_summary="All ${g_nrpe_total} CVE checks passed"
    fi

    # Line 1: status word + summary + performance data (Nagios plugin spec)
    echo "${_nrpe_status_word}: ${_nrpe_summary} | checked=${g_nrpe_total} vulnerable=${g_nrpe_vuln_count} unknown=${g_nrpe_unk_count}"

    # Long output (lines 2+): context notes, then per-CVE details
    [ "$opt_paranoid" = 1 ] && echo "NOTE: paranoid mode active, stricter mitigation requirements applied"
    case "${g_has_vmm:-}" in
        1) echo "NOTE: hypervisor host detected (${g_has_vmm_reason:-VMM}); L1TF/MDS severity is elevated" ;;
        0) echo "NOTE: not a hypervisor host" ;;
    esac
    [ "$_nrpe_is_root" = 0 ] && echo "NOTE: not running as root; MSR reads skipped, results may be incomplete"

    # VULN details first, then UNK details (each group in CVE-registry order)
    [ -n "${g_nrpe_vuln_details:-}" ] && printf "%b\n" "$g_nrpe_vuln_details"
    [ -n "${g_nrpe_unk_details:-}" ] && printf "%b\n" "$g_nrpe_unk_details"

    # Exit with the correct Nagios code when we demoted VULN→UNKNOWN due to non-root
    # (g_critical=1 would otherwise cause exit 2 below)
    [ "$_nrpe_demoted" = 1 ] && exit 3
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "short" ]; then
    _pr_echo 0 "${g_short_output% }"
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "json-terse" ]; then
    _pr_echo 0 "${g_json_output%?}]"
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "json" ]; then
    # Assemble the comprehensive JSON output from pre-built sections
    # Inject mocked flag into meta (g_mocked can be set at any point during the run)
    g_json_meta="${g_json_meta%\}},\"mocked\":$(_json_bool "${g_mocked:-0}")}"
    _json_final='{'
    _json_final="${_json_final}\"meta\":${g_json_meta:-null}"
    _json_final="${_json_final},\"system\":${g_json_system:-null}"
    _json_final="${_json_final},\"cpu\":${g_json_cpu:-null}"
    _json_final="${_json_final},\"cpu_microcode\":${g_json_cpu_microcode:-null}"
    if [ -n "${g_json_vulns:-}" ]; then
        _json_final="${_json_final},\"vulnerabilities\":[${g_json_vulns%,}]"
    else
        _json_final="${_json_final},\"vulnerabilities\":[]"
    fi
    _json_final="${_json_final}}"
    _pr_echo 0 "$_json_final"
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "prometheus" ]; then
    prom_run_as_root='false'
    [ "$(id -u)" -eq 0 ] && prom_run_as_root='true'
    if [ "$opt_no_hw" = 1 ]; then
        prom_mode='no-hw'
    elif [ "$opt_runtime" = 0 ]; then
        prom_mode='no-runtime'
    else
        prom_mode='live'
    fi
    prom_paranoid='false'
    [ "$opt_paranoid" = 1 ] && prom_paranoid='true'
    prom_sysfs_only='false'
    [ "$opt_sysfs_only" = 1 ] && prom_sysfs_only='true'
    prom_reduced_accuracy='false'
    [ "${g_bad_accuracy:-0}" = 1 ] && prom_reduced_accuracy='true'
    prom_mocked='false'
    [ "${g_mocked:-0}" = 1 ] && prom_mocked='true'
    echo "# HELP smc_build_info spectre-meltdown-checker script metadata (always 1)"
    echo "# TYPE smc_build_info gauge"
    printf 'smc_build_info{version="%s",mode="%s",run_as_root="%s",paranoid="%s",sysfs_only="%s",reduced_accuracy="%s",mocked="%s"} 1\n' \
        "$(_prom_escape "$VERSION")" \
        "$prom_mode" \
        "$prom_run_as_root" \
        "$prom_paranoid" \
        "$prom_sysfs_only" \
        "$prom_reduced_accuracy" \
        "$prom_mocked"
    if [ -n "${g_smc_system_info_line:-}" ]; then
        echo "# HELP smc_system_info Operating system and kernel metadata (always 1)"
        echo "# TYPE smc_system_info gauge"
        echo "$g_smc_system_info_line"
    fi
    if [ -n "${g_smc_cpu_info_line:-}" ]; then
        echo "# HELP smc_cpu_info CPU hardware and microcode metadata (always 1)"
        echo "# TYPE smc_cpu_info gauge"
        echo "$g_smc_cpu_info_line"
    fi
    echo "# HELP smc_vulnerability_status Vulnerability check result per CVE: 0=not_vulnerable, 1=vulnerable, 2=unknown"
    echo "# TYPE smc_vulnerability_status gauge"
    printf "%b\n" "$g_smc_vuln_output"
    echo "# HELP smc_vulnerable_count Number of CVEs with vulnerable status"
    echo "# TYPE smc_vulnerable_count gauge"
    echo "smc_vulnerable_count $g_smc_vuln_count"
    echo "# HELP smc_unknown_count Number of CVEs with unknown status"
    echo "# TYPE smc_unknown_count gauge"
    echo "smc_unknown_count $g_smc_unk_count"
    echo "# HELP smc_last_scan_timestamp_seconds Unix timestamp when this scan completed"
    echo "# TYPE smc_last_scan_timestamp_seconds gauge"
    echo "smc_last_scan_timestamp_seconds $(date +%s 2>/dev/null || echo 0)"
fi

# exit with the proper exit code
[ "$g_critical" = 1 ] && exit 2 # critical
[ "$g_unknown" = 1 ] && exit 3  # unknown
exit 0                          # ok
