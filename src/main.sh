# vim: set ts=4 sw=4 sts=4 et:

if [ "$opt_no_hw" = 0 ] && [ -z "$opt_arch_prefix" ]; then
    check_cpu
    check_cpu_vulnerabilities
    pr_info
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
    pr_warn "We're missing some kernel info (see -v), accuracy might be reduced"
fi

g_vars=$(set | grep -Ev '^[A-Z_[:space:]]' | grep -v -F 'g_mockme=' | sort | tr "\n" '|')
pr_debug "variables at end of script: $g_vars"

if [ -n "$g_mockme" ] && [ "$opt_mock" = 1 ]; then
    if command -v "gzip" >/dev/null 2>&1; then
        # not a useless use of cat: gzipping cpuinfo directly doesn't work well
        # shellcheck disable=SC2002
        if command -v "base64" >/dev/null 2>&1; then
            g_mock_cpuinfo="$(cat /proc/cpuinfo | gzip -c | base64 -w0)"
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
    if [ -n "$g_nrpe_vuln" ]; then
        echo "Vulnerable:$g_nrpe_vuln"
    else
        echo "OK"
    fi
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "short" ]; then
    _pr_echo 0 "${g_short_output% }"
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "json" ]; then
    _pr_echo 0 "${g_json_output%?}]"
fi

if [ "$opt_batch" = 1 ] && [ "$opt_batch_format" = "prometheus" ]; then
    echo "# TYPE specex_vuln_status untyped"
    echo "# HELP specex_vuln_status Exposure of system to speculative execution vulnerabilities"
    printf "%b\n" "$g_prometheus_output"
fi

# exit with the proper exit code
[ "$g_critical" = 1 ] && exit 2 # critical
[ "$g_unknown" = 1 ] && exit 3  # unknown
exit 0                          # ok
