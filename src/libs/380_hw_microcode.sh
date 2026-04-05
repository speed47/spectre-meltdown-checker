# vim: set ts=4 sw=4 sts=4 et:
g_builtin_dbversion=$(awk '/^# %%% MCEDB / { print $4 }' "$0")
if [ -r "$g_mcedb_cache" ]; then
    # we have a local cache file, but it might be older than the builtin version we have
    g_local_dbversion=$(awk '/^# %%% MCEDB / { print $4 }' "$g_mcedb_cache")
    # compare version strings of the form vN+iYYYYMMDD+hash
    local_v=$(echo "$g_local_dbversion" | sed 's/^v\([0-9]*\).*/\1/')
    builtin_v=$(echo "$g_builtin_dbversion" | sed 's/^v\([0-9]*\).*/\1/')
    local_i=$(echo "$g_local_dbversion" | sed 's/.*+i\([0-9]*\).*/\1/')
    builtin_i=$(echo "$g_builtin_dbversion" | sed 's/.*+i\([0-9]*\).*/\1/')
    if [ "$local_v" -gt "$builtin_v" ] ||
        { [ "$local_v" -eq "$builtin_v" ] && [ "$local_i" -gt "$builtin_i" ]; }; then
        g_mcedb_source="$g_mcedb_cache"
        g_mcedb_info="local firmwares DB $g_local_dbversion"
    fi
fi
# if g_mcedb_source is not set, either we don't have a local cached db, or it is older than the builtin db
if [ -z "${g_mcedb_source:-}" ]; then
    g_mcedb_source="$0"
    g_mcedb_info="builtin firmwares DB $g_builtin_dbversion"
fi
# Read the MCExtractor microcode database (from local cache or builtin) to stdout
read_mcedb() {
    awk '{ if (DELIM==1) { print $2 } } /^# %%% MCEDB / { DELIM=1 }' "$g_mcedb_source"
}

# Read the Intel official affected CPUs database (builtin) to stdout
read_inteldb() {
    if [ "$opt_intel_db" = 1 ]; then
        awk '/^# %%% ENDOFINTELDB/ { exit } { if (DELIM==1) { print $2 } } /^# %%% INTELDB/ { DELIM=1 }' "$0"
    fi
    # otherwise don't output nothing, it'll be as if the database is empty
}

# Check whether the CPU is running the latest known microcode version
# Sets: ret_is_latest_known_ucode_latest
# Returns: 0=latest, 1=outdated, 2=unknown
is_latest_known_ucode() {
    local brand_prefix tuple pfmask ucode ucode_date
    parse_cpu_details
    if [ "$cpu_cpuid" = 0 ]; then
        ret_is_latest_known_ucode_latest="couldn't get your cpuid"
        return 2
    fi
    if [ -z "$cpu_ucode" ]; then
        ret_is_latest_known_ucode_latest="couldn't get your microcode version"
        return 2
    fi
    ret_is_latest_known_ucode_latest="latest microcode version for your CPU model is unknown"
    if is_intel; then
        brand_prefix=I
    elif is_amd; then
        brand_prefix=A
    else
        return 2
    fi
    for tuple in $(read_mcedb | grep "$(printf "^$brand_prefix,0x%08X," "$cpu_cpuid")"); do
        # skip if the pfmask doesn't match our platformid
        pfmask=$(echo "$tuple" | cut -d, -f3)
        if is_intel && [ $((cpu_platformid & pfmask)) -eq 0 ]; then
            continue
        fi
        ucode=$(($(echo "$tuple" | cut -d, -f4)))
        ucode_date=$(echo "$tuple" | cut -d, -f5 | sed -E 's=(....)(..)(..)=\1/\2/\3=')
        pr_debug "is_latest_known_ucode: with cpuid $cpu_cpuid has ucode $cpu_ucode, last known is $ucode from $ucode_date"
        ret_is_latest_known_ucode_latest=$(printf "latest version is 0x%x dated $ucode_date according to $g_mcedb_info" "$ucode")
        if [ "$cpu_ucode" -ge "$ucode" ]; then
            return 0
        else
            return 1
        fi
    done
    pr_debug "is_latest_known_ucode: this cpuid is not referenced ($cpu_cpuid)"
    return 2
}

# Read and cache the kernel command line from /proc/cmdline or mock
# Sets: g_kernel_cmdline
