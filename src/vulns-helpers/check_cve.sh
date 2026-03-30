# vim: set ts=4 sw=4 sts=4 et:
# Generic CVE check dispatcher: prints CVE header and calls the OS-specific check function
# Args: $1=cve_id $2=func_prefix(optional, default derived from CVE ID)
check_cve() {
    local cve func_prefix
    cve="$1"
    func_prefix="${2:-check_$(echo "$cve" | tr - _)}"
    pr_info "\033[1;34m$cve aka '$(cve2name "$cve")'\033[0m"
    if [ "$g_os" = Linux ]; then
        if type "${func_prefix}_linux" >/dev/null 2>&1; then
            "${func_prefix}_linux"
        else
            pr_warn "Unsupported OS ($g_os)"
        fi
    elif echo "$g_os" | grep -q BSD; then
        if type "${func_prefix}_bsd" >/dev/null 2>&1; then
            "${func_prefix}_bsd"
        else
            pr_warn "Unsupported OS ($g_os)"
        fi
    else
        pr_warn "Unsupported OS ($g_os)"
    fi
}
