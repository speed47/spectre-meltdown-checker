#! /bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# vim: set ts=4 sw=4 sts=4 et:
# shellcheck disable=SC2317,SC2329,SC3043
#
# Spectre & Meltdown checker
#
# Check for the latest version at:
# https://github.com/speed47/spectre-meltdown-checker
# git clone https://github.com/speed47/spectre-meltdown-checker.git
# or wget https://meltdown.ovh -O spectre-meltdown-checker.sh
# or curl -L https://meltdown.ovh -o spectre-meltdown-checker.sh
#
# Stephane Lesimple
#
VERSION='0.46+'

# --- Common paths and basedirs ---
readonly VULN_SYSFS_BASE="/sys/devices/system/cpu/vulnerabilities"
readonly DEBUGFS_BASE="/sys/kernel/debug"
readonly SYS_MODULE_BASE="/sys/module"
readonly CPU_DEV_BASE="/dev/cpu"
readonly BSD_CPUCTL_DEV_BASE="/dev/cpuctl"

trap 'exit_cleanup' EXIT
trap 'pr_warn "interrupted, cleaning up..."; exit_cleanup; exit 1' INT
# Clean up temporary files and undo module/mount side effects on exit
exit_cleanup() {
    local saved_ret
    saved_ret=$?
    # cleanup the temp decompressed config & kernel image
    [ -n "${g_dumped_config:-}" ] && [ -f "$g_dumped_config" ] && rm -f "$g_dumped_config"
    [ -n "${g_kerneltmp:-}" ] && [ -f "$g_kerneltmp" ] && rm -f "$g_kerneltmp"
    [ -n "${g_kerneltmp2:-}" ] && [ -f "$g_kerneltmp2" ] && rm -f "$g_kerneltmp2"
    [ -n "${g_mcedb_tmp:-}" ] && [ -f "$g_mcedb_tmp" ] && rm -f "$g_mcedb_tmp"
    [ -n "${g_intel_tmp:-}" ] && [ -d "$g_intel_tmp" ] && rm -rf "$g_intel_tmp"
    [ -n "${g_linuxfw_tmp:-}" ] && [ -f "$g_linuxfw_tmp" ] && rm -f "$g_linuxfw_tmp"
    [ "${g_mounted_debugfs:-}" = 1 ] && umount "$DEBUGFS_BASE" 2>/dev/null
    [ "${g_mounted_procfs:-}" = 1 ] && umount "$g_procfs" 2>/dev/null
    [ "${g_insmod_cpuid:-}" = 1 ] && rmmod cpuid 2>/dev/null
    [ "${g_insmod_msr:-}" = 1 ] && rmmod msr 2>/dev/null
    [ "${g_kldload_cpuctl:-}" = 1 ] && kldunload cpuctl 2>/dev/null
    [ "${g_kldload_vmm:-}" = 1 ] && kldunload vmm 2>/dev/null
    exit "$saved_ret"
}

# if we were git clone'd, adjust VERSION
if [ -d "$(dirname "$0")/.git" ] && command -v git >/dev/null 2>&1; then
    g_describe=$(git -C "$(dirname "$0")" describe --tags --dirty 2>/dev/null)
    [ -n "$g_describe" ] && VERSION=$(echo "$g_describe" | sed -e s/^v//)
fi
