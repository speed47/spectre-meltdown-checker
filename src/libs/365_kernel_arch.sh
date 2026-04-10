# vim: set ts=4 sw=4 sts=4 et:
###############################
# Kernel architecture detection helpers.
# Detects the target kernel's architecture regardless of the host system,
# enabling correct behavior in offline cross-inspection (e.g. x86 host
# analyzing an ARM kernel image or System.map).

# Global cache; populated by _detect_kernel_arch on first call.
# Values: 'arm', 'x86', 'unknown'
g_kernel_arch=''

# Internal: populate g_kernel_arch using all available information sources,
# in order from most to least reliable.
_detect_kernel_arch() {
    # Return immediately if already detected
    [ -n "$g_kernel_arch" ] && return 0

    # arm64_sys_ is the ARM64 syscall table symbol prefix; present in any
    # ARM64 System.map (or /proc/kallsyms) and in the kernel image itself.
    # sys_call_table + vector_swi is the ARM (32-bit) equivalent.
    if [ -n "$opt_map" ]; then
        if grep -q 'arm64_sys_' "$opt_map" 2>/dev/null; then
            g_kernel_arch='arm'
            return 0
        fi
        if grep -q ' vector_swi$' "$opt_map" 2>/dev/null; then
            g_kernel_arch='arm'
            return 0
        fi
    fi
    if [ -n "$g_kernel" ]; then
        if grep -q 'arm64_sys_' "$g_kernel" 2>/dev/null; then
            g_kernel_arch='arm'
            return 0
        fi
    fi

    # Kconfig is definitive when available
    if [ -n "$opt_config" ]; then
        if grep -qE '^CONFIG_(ARM64|ARM)=y' "$opt_config" 2>/dev/null; then
            g_kernel_arch='arm'
            return 0
        fi
        if grep -qE '^CONFIG_X86(_64)?=y' "$opt_config" 2>/dev/null; then
            g_kernel_arch='x86'
            return 0
        fi
    fi

    # Cross-compilation prefix as a last resort (e.g. --arch-prefix aarch64-linux-gnu-)
    case "${opt_arch_prefix:-}" in
        aarch64-* | arm64-* | arm-* | armv*-)
            g_kernel_arch='arm'
            return 0
            ;;
        x86_64-* | i686-* | i?86-*)
            g_kernel_arch='x86'
            return 0
            ;;
    esac

    # Last resort: if no artifacts identified the arch, assume the target
    # kernel matches the host CPU. This covers live mode when no kernel
    # image, config, or System.map is available.
    if is_x86_cpu; then
        g_kernel_arch='x86'
        return 0
    fi
    if is_arm_cpu; then
        g_kernel_arch='arm'
        return 0
    fi

    g_kernel_arch='unknown'
    return 0
}

# Return 0 (true) if the target kernel is ARM (32 or 64-bit), 1 otherwise.
is_arm_kernel() {
    _detect_kernel_arch
    [ "$g_kernel_arch" = 'arm' ]
}

# Return 0 (true) if the target kernel is x86/x86_64, 1 otherwise.
is_x86_kernel() {
    _detect_kernel_arch
    [ "$g_kernel_arch" = 'x86' ]
}

# Compare the target kernel's architecture against the host CPU.
# If they differ, hardware reads (CPUID, MSR, sysfs) would reflect the host,
# not the target kernel — force no-hw mode to avoid misleading results.
# Sets: g_mode (when mismatch detected)
# Callers: src/main.sh (after check_kernel_info, before check_cpu)
check_kernel_cpu_arch_mismatch() {
    local host_arch
    _detect_kernel_arch

    host_arch='unknown'
    if is_x86_cpu; then
        host_arch='x86'
    elif is_arm_cpu; then
        host_arch='arm'
    fi

    # Unsupported CPU architecture (MIPS, RISC-V, PowerPC, ...): force no-hw
    # since we have no hardware-level checks for these platforms
    if [ "$host_arch" = 'unknown' ]; then
        pr_warn "Unsupported CPU architecture (vendor: $cpu_vendor), forcing no-hw mode"
        g_mode='no-hw'
        return 0
    fi

    # If kernel arch is unknown, we can't tell if there's a mismatch
    [ "$g_kernel_arch" = 'unknown' ] && return 0
    [ "$host_arch" = "$g_kernel_arch" ] && return 0

    pr_warn "Target kernel architecture ($g_kernel_arch) differs from host CPU ($host_arch), forcing no-hw mode"
    g_mode='no-hw'
}
