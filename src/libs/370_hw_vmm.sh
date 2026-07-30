# vim: set ts=4 sw=4 sts=4 et:

# Probe Xen presence and guest type using the most reliable sources available.
# Prefer /sys/hypervisor when avalable, fallback to dmesg otherwise.
# Caches results in g_xen (1/0) and g_xen_guest_type (PV|PVH|HVM|'').
_detect_xen() {
    [ "${g_xen_cached:-0}" = 1 ] && return
    g_xen=0
    g_xen_guest_type=''
    g_xen_cached=1

    # Most reliable: /sys/hypervisor/type is 'xen' on any Xen domain (dom0
    # included), and /sys/hypervisor/guest_type reports PV, PVH or HVM.
    if [ -r /sys/hypervisor/type ] && [ "$(cat /sys/hypervisor/type 2>/dev/null)" = xen ]; then
        g_xen=1
        if [ -r /sys/hypervisor/guest_type ]; then
            g_xen_guest_type=$(cat /sys/hypervisor/guest_type 2>/dev/null)
        fi
        return
    fi

    # Fallback for kernels without /sys/hypervisor: /proc/xen plus a dmesg probe.
    if [ -d "$g_procfs/xen" ]; then
        dmesg_grep 'Booting paravirtualized kernel on Xen$'
        case $? in
            0) g_xen=1 ;;
            2) pr_warn "dmesg truncated, Xen detection will be unreliable. Please reboot and relaunch this script" ;;
        esac
    fi
}

# Check whether the system is running on Xen (any domain type, dom0 included).
# Returns: 0 if Xen, 1 otherwise
is_xen() {
    _detect_xen
    [ "$g_xen" = 1 ]
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

# Check whether the system is running as a Xen PV DomU (the only Xen guest type
# affected by Meltdown, which needs Xen-level mitigation).
# Returns: 0 if PV DomU, 1 otherwise
is_xen_domU() {
    local ret
    if ! is_xen; then
        return 1
    fi

    if is_xen_dom0; then
        return 1
    fi

    # When the reliable guest type is known, only PV domains (which aren't
    # dom0, checked above) are the PV DomU case. PVH and HVM guests are not.
    if [ -n "$g_xen_guest_type" ]; then
        [ "$g_xen_guest_type" = PV ] && return 0
        return 1
    fi

    # Fallback (no /sys/hypervisor/guest_type): PVHVM guests also print the
    # 'Booting paravirtualized kernel' line, so exclude them via dmesg.
    dmesg_grep 'Xen HVM callback vector for event delivery is enabled$'
    ret=$?
    if [ "$ret" -eq 0 ]; then
        return 1
    fi

    return 0
}

# Check whether we're running inside an OS-level container (LXC, Docker,
# systemd-nspawn, etc.). Containers share the host kernel, so host/hypervisor
# introspection (e.g. telling a Xen dom0 from a domU) is unreliable from inside
# one: /proc/xen is exposed but empty, dmesg is the host's, etc. (issue #173)
# Returns: 0 if in a container, 1 otherwise
# Sets: g_is_container (1/0), g_container_reason
is_running_in_container() {
    local ctype
    if [ "${g_is_container_cached:-0}" != 1 ]; then
        g_is_container=0
        g_container_reason=''
        # systemd and most runtimes export 'container=' to PID 1's environment
        if [ -r "$g_procfs/1/environ" ]; then
            ctype=$(tr '\0' '\n' <"$g_procfs/1/environ" 2>/dev/null | sed -n 's/^container=//p' | head -n1)
            if [ -n "$ctype" ]; then
                g_is_container=1
                g_container_reason="container=$ctype in $g_procfs/1/environ"
            fi
        fi
        # Docker (and some others) drop a marker file at the filesystem root
        if [ "$g_is_container" = 0 ] && [ -e /.dockerenv ]; then
            g_is_container=1
            g_container_reason="/.dockerenv present"
        fi
        # cgroup membership often reveals the runtime (lxc, docker, kubepods, ...)
        if [ "$g_is_container" = 0 ] && [ -r "$g_procfs/1/cgroup" ]; then
            if grep -qE '(^|[:/])(lxc|docker|kubepods|libpod|containerd|machine\.slice)([/.]|$)' "$g_procfs/1/cgroup" 2>/dev/null; then
                g_is_container=1
                g_container_reason="container runtime found in $g_procfs/1/cgroup"
            fi
        fi
        g_is_container_cached=1
    fi
    [ "$g_is_container" = 1 ]
}

# Check whether the system is running as a guest inside a VM.
# Uses the 'hypervisor' CPUID feature flag exposed in /proc/cpuinfo by KVM,
# VMware, Hyper-V, VirtualBox, and most other type-1 and type-2 hypervisors.
# Xen PV/PVH DomUs don't set that flag, so they're detected separately.
# Returns: 0 if running as a VM guest, 1 otherwise
# Sets: g_is_guest_vm (1=guest, 0=not a guest), g_is_guest_vm_reason
is_running_as_guest() {
    if [ "${g_is_guest_vm_cached:-0}" != 1 ]; then
        g_is_guest_vm=0
        g_is_guest_vm_reason=''
        # A Xen dom0 runs on top of the hypervisor and therefore also has the
        # 'hypervisor' CPUID flag set, but it's the privileged control domain:
        # it has direct hardware access and a truthful view of the host CPU
        # topology, so it must not be classified as a guest (#343). Check it
        # before the cpuinfo probe below, which would otherwise match.
        if is_xen_dom0; then
            g_is_guest_vm=0
        elif [ -e "$g_procfs/cpuinfo" ] && grep -qw 'hypervisor' "$g_procfs/cpuinfo" 2>/dev/null; then
            g_is_guest_vm=1
            g_is_guest_vm_reason="'hypervisor' flag in $g_procfs/cpuinfo"
        fi
        # Xen PV/PVH DomUs don't expose the 'hypervisor' CPUID flag. Don't
        # classify a container on a Xen host as a guest here: we can't tell
        # dom0 from domU from inside a container (handled separately).
        if [ "$g_is_guest_vm" = 0 ] && is_xen && ! is_xen_dom0 && ! is_running_in_container; then
            g_is_guest_vm=1
            g_is_guest_vm_reason="Xen ${g_xen_guest_type:-PV} DomU"
        fi
        g_is_guest_vm_cached=1
    fi
    [ "$g_is_guest_vm" = 1 ]
}
