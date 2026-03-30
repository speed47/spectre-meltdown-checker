# vim: set ts=4 sw=4 sts=4 et:
get_cmdline() {
    if [ -n "${g_kernel_cmdline:-}" ]; then
        return
    fi

    if [ -n "${SMC_MOCK_CMDLINE:-}" ]; then
        g_mocked=1
        pr_debug "get_cmdline: using g_mocked cmdline '$SMC_MOCK_CMDLINE'"
        g_kernel_cmdline="$SMC_MOCK_CMDLINE"
        return
    else
        g_kernel_cmdline=$(cat "$g_procfs/cmdline")
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CMDLINE='$g_kernel_cmdline'")
    fi
}
