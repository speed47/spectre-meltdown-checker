# vim: set ts=4 sw=4 sts=4 et:
# Mount debugfs if not already available, remembering to unmount on cleanup
# Sets: g_mounted_debugfs
mount_debugfs() {
    if [ ! -e "$DEBUGFS_BASE/sched_features" ]; then
        # try to mount the debugfs hierarchy ourselves and remember it to umount afterwards
        mount -t debugfs debugfs "$DEBUGFS_BASE" 2>/dev/null && g_mounted_debugfs=1
    fi
}

# Load the MSR kernel module (Linux) or cpuctl (BSD) if not already loaded
# Sets: g_insmod_msr, g_kldload_cpuctl
load_msr() {
    [ "${g_load_msr_once:-}" = 1 ] && return
    g_load_msr_once=1

    if [ "$g_os" = Linux ]; then
        if ! grep -qw msr "$g_procfs/modules" 2>/dev/null; then
            modprobe msr 2>/dev/null && g_insmod_msr=1
            pr_debug "attempted to load module msr, g_insmod_msr=$g_insmod_msr"
        else
            pr_debug "msr module already loaded"
        fi
    else
        if ! kldstat -q -m cpuctl; then
            kldload cpuctl 2>/dev/null && g_kldload_cpuctl=1
            pr_debug "attempted to load module cpuctl, g_kldload_cpuctl=$g_kldload_cpuctl"
        else
            pr_debug "cpuctl module already loaded"
        fi
    fi
}
