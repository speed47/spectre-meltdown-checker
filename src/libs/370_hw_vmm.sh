# vim: set ts=4 sw=4 sts=4 et:
# Check whether the system is running as a Xen paravirtualized guest
# Returns: 0 if Xen PV, 1 otherwise
is_xen() {
    local ret
    if [ ! -d "$g_procfs/xen" ]; then
        return 1
    fi

    # XXX do we have a better way that relying on dmesg?
    dmesg_grep 'Booting paravirtualized kernel on Xen$'
    ret=$?
    if [ "$ret" -eq 2 ]; then
        pr_warn "dmesg truncated, Xen detection will be unreliable. Please reboot and relaunch this script"
        return 1
    elif [ "$ret" -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

# Check whether the system is a Xen Dom0 (privileged domain)
# Returns: 0 if Dom0, 1 otherwise
is_xen_dom0() {
    if ! is_xen; then
        return 1
    fi

    if [ -e "$g_procfs/xen/capabilities" ] && grep -q "control_d" "$g_procfs/xen/capabilities"; then
        return 0
    else
        return 1
    fi
}

# Check whether the system is a Xen DomU (unprivileged PV guest)
# Returns: 0 if DomU, 1 otherwise
is_xen_domU() {
    local ret
    if ! is_xen; then
        return 1
    fi

    # PVHVM guests also print 'Booting paravirtualized kernel', so we need this check.
    dmesg_grep 'Xen HVM callback vector for event delivery is enabled$'
    ret=$?
    if [ "$ret" -eq 0 ]; then
        return 1
    fi

    if ! is_xen_dom0; then
        return 0
    else
        return 1
    fi
}
