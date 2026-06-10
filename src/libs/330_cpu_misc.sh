# vim: set ts=4 sw=4 sts=4 et:
# Search dmesg for a pattern, returning nothing if the buffer has been truncated
# Args: $1=grep_pattern
# Sets: ret_dmesg_grep_grepped
# Returns: 0=found, 1=not found, 2=dmesg truncated
dmesg_grep() {
    ret_dmesg_grep_grepped=''
    if ! dmesg 2>/dev/null | grep -qE -e '(^|\] )Linux version [0-9]' -e '^FreeBSD is a registered'; then
        # dmesg truncated
        return 2
    fi
    ret_dmesg_grep_grepped=$(dmesg 2>/dev/null | grep -m 1 -E "$1")
    # not found:
    [ -z "$ret_dmesg_grep_grepped" ] && return 1
    # found, output is in $ret_dmesg_grep_grepped
    return 0
}

# Check whether the system is running CoreOS/Flatcar
# Returns: 0 if CoreOS, 1 otherwise
is_coreos() {
    command -v coreos-install >/dev/null 2>&1 && command -v toolbox >/dev/null 2>&1 && return 0
    return 1
}

# Check whether /proc/cpuinfo has $1 in the flags line
# Returns: 0 if flag found, 1 otherwise
cpuinfo_has_flag() {
    grep -Eq '^flags\b.+\b'"$1"'\b' "$g_procfs/cpuinfo" 2>/dev/null
}
