# vim: set ts=4 sw=4 sts=4 et:
is_hygon() {
    parse_cpu_details
    [ "$cpu_vendor" = HygonGenuine ] && return 0
    return 1
}

# Check whether the CPU vendor is AMD
# Returns: 0 if AMD, 1 otherwise
is_amd() {
    parse_cpu_details
    [ "$cpu_vendor" = AuthenticAMD ] && return 0
    return 1
}

# Check whether the CPU vendor is Intel
# Returns: 0 if Intel, 1 otherwise
is_intel() {
    parse_cpu_details
    [ "$cpu_vendor" = GenuineIntel ] && return 0
    return 1
}

# Check whether SMT (HyperThreading) is enabled on the system
# Returns: 0 if SMT enabled, 1 otherwise
is_cpu_smt_enabled() {
    local siblings cpucores
    # SMT / HyperThreading is enabled if siblings != cpucores
    if [ -e "$g_procfs/cpuinfo" ]; then
        siblings=$(awk '/^siblings/  {print $3;exit}' "$g_procfs/cpuinfo")
        cpucores=$(awk '/^cpu cores/ {print $4;exit}' "$g_procfs/cpuinfo")
        if [ -n "$siblings" ] && [ -n "$cpucores" ]; then
            if [ "$siblings" = "$cpucores" ]; then
                return 1
            else
                return 0
            fi
        fi
    fi
    # we can't tell
    return 2
}

# Check whether the current CPU microcode version is on Intel's blacklist
# Returns: 0 if blacklisted, 1 otherwise
is_ucode_blacklisted() {
    local tuple model stepping ucode cpuid
    parse_cpu_details
    # if it's not an Intel, don't bother: it's not blacklisted
    is_intel || return 1
    # it also needs to be family=6
    [ "$cpu_family" = 6 ] || return 1
    # now, check each known bad microcode
    # source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/cpu/intel.c#n105
    # 2018-02-08 update: https://newsroom.intel.com/wp-content/uploads/sites/11/2018/02/microcode-update-guidance.pdf
    # model,stepping,microcode
    for tuple in \
        $INTEL_FAM6_KABYLAKE,0x0B,0x80 \
        $INTEL_FAM6_KABYLAKE,0x0A,0x80 \
        $INTEL_FAM6_KABYLAKE,0x09,0x80 \
        $INTEL_FAM6_KABYLAKE_L,0x0A,0x80 \
        $INTEL_FAM6_KABYLAKE_L,0x09,0x80 \
        $INTEL_FAM6_SKYLAKE_X,0x03,0x0100013e \
        $INTEL_FAM6_SKYLAKE_X,0x04,0x02000036 \
        $INTEL_FAM6_SKYLAKE_X,0x04,0x0200003a \
        $INTEL_FAM6_SKYLAKE_X,0x04,0x0200003c \
        $INTEL_FAM6_BROADWELL,0x04,0x28 \
        $INTEL_FAM6_BROADWELL_G,0x01,0x1b \
        $INTEL_FAM6_BROADWELL_D,0x02,0x14 \
        $INTEL_FAM6_BROADWELL_D,0x03,0x07000011 \
        $INTEL_FAM6_BROADWELL_X,0x01,0x0b000025 \
        $INTEL_FAM6_HASWELL_L,0x01,0x21 \
        $INTEL_FAM6_HASWELL_G,0x01,0x18 \
        $INTEL_FAM6_HASWELL,0x03,0x23 \
        $INTEL_FAM6_HASWELL_X,0x02,0x3b \
        $INTEL_FAM6_HASWELL_X,0x04,0x10 \
        $INTEL_FAM6_IVYBRIDGE_X,0x04,0x42a \
        $INTEL_FAM6_SANDYBRIDGE_X,0x06,0x61b \
        $INTEL_FAM6_SANDYBRIDGE_X,0x07,0x712; do
        model=$(echo "$tuple" | cut -d, -f1)
        stepping=$(($(echo "$tuple" | cut -d, -f2)))
        if [ "$cpu_model" = "$model" ] && [ "$cpu_stepping" = "$stepping" ]; then
            ucode=$(($(echo "$tuple" | cut -d, -f3)))
            if [ "$cpu_ucode" = "$ucode" ]; then
                pr_debug "is_ucode_blacklisted: we have a match! ($cpu_model/$cpu_stepping/$cpu_ucode)"
                return 0
            fi
        fi
    done

    # 2024-01-09 update: https://github.com/speed47/spectre-meltdown-checker/issues/475
    # this time the tuple is cpuid,microcode
    for tuple in \
        0xB0671,0x119 \
        0xB06A2,0x4119 \
        0xB06A3,0x4119; do
        cpuid=$(($(echo "$tuple" | cut -d, -f1)))
        ucode=$(($(echo "$tuple" | cut -d, -f2)))
        if [ "$cpu_cpuid" = "$cpuid" ] && [ "$cpu_ucode" = "$ucode" ]; then
            pr_debug "is_ucode_blacklisted: we have a match! ($cpuid/$ucode)"
            return 0
        fi
    done

    pr_debug "is_ucode_blacklisted: no ($cpu_model/$cpu_stepping/$cpu_ucode)"
    return 1
}

# Check whether the CPU is a Skylake/Kabylake family processor
# Returns: 0 if Skylake-family, 1 otherwise
is_skylake_cpu() {
    # return 0 if yes, 1 otherwise
    #if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL &&
    #		boot_cpu_data.x86 == 6) {
    #		switch (boot_cpu_data.x86_model) {
    #		case INTEL_FAM6_SKYLAKE_MOBILE:
    #		case INTEL_FAM6_SKYLAKE_DESKTOP:
    #		case INTEL_FAM6_SKYLAKE_X:
    #		case INTEL_FAM6_KABYLAKE_MOBILE:
    #		case INTEL_FAM6_KABYLAKE_DESKTOP:
    #			return true;
    parse_cpu_details
    is_intel || return 1
    [ "$cpu_family" = 6 ] || return 1
    if [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_L" ] ||
        [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE" ] ||
        [ "$cpu_model" = "$INTEL_FAM6_SKYLAKE_X" ] ||
        [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE_L" ] ||
        [ "$cpu_model" = "$INTEL_FAM6_KABYLAKE" ]; then
        return 0
    fi
    return 1
}

# Check whether the CPU is vulnerable to empty RSB speculation
# Returns: 0 if vulnerable, 1 otherwise
is_vulnerable_to_empty_rsb() {
    if is_intel && [ -z "$cap_rsba" ]; then
        pr_warn "is_vulnerable_to_empty_rsb() called before ARCH CAPABILITIES MSR was read"
    fi
    if is_skylake_cpu || [ "$cap_rsba" = 1 ]; then
        return 0
    fi
    return 1
}

# Check whether the CPU is from the AMD Zen family (Ryzen, EPYC, ...)
# Returns: 0 if Zen, 1 otherwise
is_zen_cpu() {
    parse_cpu_details
    is_amd || return 1
    [ "$cpu_family" = 23 ] && return 0
    return 1
}

# Check whether the CPU is a Hygon Moksha (Dhyana) family processor
# Returns: 0 if Moksha, 1 otherwise
is_moksha_cpu() {
    parse_cpu_details
    is_hygon || return 1
    [ "$cpu_family" = 24 ] && return 0
    return 1
}

# Encode an AMD family/model/stepping range into a single integer (mimics Linux AMD_MODEL_RANGE macro)
# Args: $1=family $2=model_start $3=stepping_start $4=model_end $5=stepping_end
amd_model_range() {
    echo $((($1 << 24) | ($2 << 16) | ($3 << 12) | ($4 << 4) | ($5)))
}

# Check if the current AMD CPU falls within a given model/stepping range (mimics Linux amd_legacy_erratum)
# Args: $1=range (output of amd_model_range)
# Returns: 0 if CPU is in range, 1 otherwise
amd_legacy_erratum() {
    local range ms
    range="$1"
    ms=$((cpu_model << 4 | cpu_stepping))
    if [ "$cpu_family" = $((((range) >> 24) & 0xff)) ] &&
        [ $ms -ge $((((range) >> 12) & 0xfff)) ] &&
        [ $ms -le $(((range) & 0xfff)) ]; then
        return 0
    fi
    return 1
}

# Check whether the CPU has a microcode version that fixes Zenbleed
# Sets: g_zenbleed_fw, g_zenbleed_fw_required
# Returns: 0=fixed, 1=not fixed, 2=not applicable
has_zenbleed_fixed_firmware() {
    local tuples tuple model_low model_high fwver
    # return cached data
    [ -n "$g_zenbleed_fw" ] && return "$g_zenbleed_fw"
    # or compute it:
    g_zenbleed_fw=2 # unknown
    # only amd
    if ! is_amd; then
        g_zenbleed_fw=1
        return $g_zenbleed_fw
    fi
    # list of known fixed firmwares, from commit 522b1d69219d8f083173819fde04f994aa051a98
    tuples="
		0x30,0x3f,0x0830107a
		0x60,0x67,0x0860010b
		0x68,0x6f,0x08608105
		0x70,0x7f,0x08701032
		0xa0,0xaf,0x08a00008
	"
    for tuple in $tuples; do
        model_low=$(echo "$tuple" | cut -d, -f1)
        model_high=$(echo "$tuple" | cut -d, -f2)
        fwver=$(echo "$tuple" | cut -d, -f3)
        if [ $((cpu_model)) -ge $((model_low)) ] && [ $((cpu_model)) -le $((model_high)) ]; then
            if [ -n "$cpu_ucode" ] && [ $((cpu_ucode)) -ge $((fwver)) ]; then
                g_zenbleed_fw=0 # true
                break
            else
                g_zenbleed_fw=1 # false
                g_zenbleed_fw_required=$fwver
            fi
        fi
    done
    unset tuples
    return $g_zenbleed_fw
}
