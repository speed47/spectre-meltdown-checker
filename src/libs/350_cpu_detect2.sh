# vim: set ts=4 sw=4 sts=4 et:
# Detect and cache CPU vendor, family, model, stepping, microcode, and arch capabilities
# Sets: cpu_vendor, cpu_family, cpu_model, cpu_stepping, cpu_cpuid, cpu_ucode, cpu_friendly_name, g_max_core_id, and many cap_* globals
parse_cpu_details() {
    [ "${g_parse_cpu_details_done:-}" = 1 ] && return 0

    local number_of_cores arch part ret
    if command -v nproc >/dev/null; then
        number_of_cores=$(nproc)
    elif echo "$g_os" | grep -q BSD; then
        number_of_cores=$(sysctl -n hw.ncpu 2>/dev/null || echo 1)
    elif [ -e "$g_procfs/cpuinfo" ]; then
        number_of_cores=$(grep -c ^processor "$g_procfs/cpuinfo" 2>/dev/null || echo 1)
    else
        # if we don't know, default to 1 CPU
        number_of_cores=1
    fi
    g_max_core_id=$((number_of_cores - 1))

    cap_avx2=0
    cap_avx512=0
    if [ -e "$g_procfs/cpuinfo" ]; then
        if grep -qw avx2 "$g_procfs/cpuinfo" 2>/dev/null; then cap_avx2=1; fi
        if grep -qw avx512 "$g_procfs/cpuinfo" 2>/dev/null; then cap_avx512=1; fi
        cpu_vendor=$(grep '^vendor_id' "$g_procfs/cpuinfo" | awk '{print $3}' | head -n1)
        cpu_friendly_name=$(grep '^model name' "$g_procfs/cpuinfo" | cut -d: -f2- | head -n1 | sed -e 's/^ *//')
        # special case for ARM follows
        if grep -qi 'CPU implementer[[:space:]]*:[[:space:]]*0x41' "$g_procfs/cpuinfo"; then
            cpu_vendor='ARM'
            # some devices (phones or other) have several ARMs and as such different part numbers,
            # an example is "bigLITTLE", so we need to store the whole list, this is needed for is_cpu_affected
            cpu_part_list=$(awk '/CPU part/         {print $4}' "$g_procfs/cpuinfo")
            cpu_arch_list=$(awk '/CPU architecture/ {print $3}' "$g_procfs/cpuinfo")
            # take the first one to fill the friendly name, do NOT quote the vars below
            # shellcheck disable=SC2086
            arch=$(echo $cpu_arch_list | awk '{ print $1 }')
            # shellcheck disable=SC2086
            part=$(echo $cpu_part_list | awk '{ print $1 }')
            [ "$arch" = "AArch64" ] && arch=8
            cpu_friendly_name="ARM"
            [ -n "$arch" ] && cpu_friendly_name="$cpu_friendly_name v$arch"
            [ -n "$part" ] && cpu_friendly_name="$cpu_friendly_name model $part"

        elif grep -qi 'CPU implementer[[:space:]]*:[[:space:]]*0x43' "$g_procfs/cpuinfo"; then
            cpu_vendor='CAVIUM'
        elif grep -qi 'CPU implementer[[:space:]]*:[[:space:]]*0x70' "$g_procfs/cpuinfo"; then
            cpu_vendor='PHYTIUM'
        fi

        cpu_family=$(grep '^cpu family' "$g_procfs/cpuinfo" | awk '{print $4}' | grep -E '^[0-9]+$' | head -n1)
        cpu_model=$(grep '^model' "$g_procfs/cpuinfo" | awk '{print $3}' | grep -E '^[0-9]+$' | head -n1)
        cpu_stepping=$(grep '^stepping' "$g_procfs/cpuinfo" | awk '{print $3}' | grep -E '^[0-9]+$' | head -n1)
        cpu_ucode=$(grep '^microcode' "$g_procfs/cpuinfo" | awk '{print $3}' | head -n1)
    else
        cpu_vendor=$(dmesg 2>/dev/null | grep -i -m1 'Origin=' | awk '{print $2}' | cut -f2 -d= | cut -f2 -d\")
        cpu_family=$(dmesg 2>/dev/null | grep -i -m1 'Family=' | awk '{print $4}' | cut -f2 -d=)
        cpu_family=$((cpu_family))
        cpu_model=$(dmesg 2>/dev/null | grep -i -m1 'Model=' | awk '{print $5}' | cut -f2 -d=)
        cpu_model=$((cpu_model))
        cpu_stepping=$(dmesg 2>/dev/null | grep -i -m1 'Stepping=' | awk '{print $6}' | cut -f2 -d=)
        cpu_friendly_name=$(sysctl -n hw.model 2>/dev/null)
    fi

    # Intel processors have a 3bit Platform ID field in MSR(17H) that specifies the platform type for up to 8 types
    # see https://elixir.bootlin.com/linux/v6.0/source/arch/x86/kernel/cpu/microcode/intel.c#L694
    # Set it to 8 (impossible value as it is 3 bit long) by default
    cpu_platformid=8
    if [ "$cpu_vendor" = GenuineIntel ] && [ "$cpu_model" -ge 5 ]; then
        read_msr $MSR_IA32_PLATFORM_ID
        ret=$?
        if [ $ret = $READ_MSR_RET_OK ]; then
            # platform ID (bits 52:50) = bits 18:20 of the upper 32-bit word
            cpu_platformid=$((1 << ((ret_read_msr_value_hi >> 18) & 7)))
        fi
    fi

    if [ -n "${SMC_MOCK_CPU_FRIENDLY_NAME:-}" ]; then
        cpu_friendly_name="$SMC_MOCK_CPU_FRIENDLY_NAME"
        pr_debug "parse_cpu_details: MOCKING cpu friendly name to $cpu_friendly_name"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_FRIENDLY_NAME='$cpu_friendly_name'")
    fi
    if [ -n "${SMC_MOCK_CPU_VENDOR:-}" ]; then
        cpu_vendor="$SMC_MOCK_CPU_VENDOR"
        pr_debug "parse_cpu_details: MOCKING cpu vendor to $cpu_vendor"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_VENDOR='$cpu_vendor'")
    fi
    if [ -n "${SMC_MOCK_CPU_FAMILY:-}" ]; then
        cpu_family="$SMC_MOCK_CPU_FAMILY"
        pr_debug "parse_cpu_details: MOCKING cpu family to $cpu_family"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_FAMILY='$cpu_family'")
    fi
    if [ -n "${SMC_MOCK_CPU_MODEL:-}" ]; then
        cpu_model="$SMC_MOCK_CPU_MODEL"
        pr_debug "parse_cpu_details: MOCKING cpu model to $cpu_model"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_MODEL='$cpu_model'")
    fi
    if [ -n "${SMC_MOCK_CPU_STEPPING:-}" ]; then
        cpu_stepping="$SMC_MOCK_CPU_STEPPING"
        pr_debug "parse_cpu_details: MOCKING cpu stepping to $cpu_stepping"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_STEPPING='$cpu_stepping'")
    fi
    if [ -n "${SMC_MOCK_CPU_PLATFORMID:-}" ]; then
        cpu_platformid="$SMC_MOCK_CPU_PLATFORMID"
        pr_debug "parse_cpu_details: MOCKING cpu platformid name to $cpu_platformid"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_PLATFORMID='$cpu_platformid'")
    fi

    # get raw cpuid, it's always useful (referenced in the Intel doc for firmware updates for example)
    if [ "$g_mocked" != 1 ] && read_cpuid 0x1 0x0 $EAX 0 0xFFFFFFFF; then
        cpu_cpuid="$ret_read_cpuid_value"
    else
        # try to build it by ourselves
        pr_debug "parse_cpu_details: build the CPUID by ourselves"
        cpu_cpuid=$(fms2cpuid "$cpu_family" "$cpu_model" "$cpu_stepping")
    fi

    # under BSD, linprocfs often doesn't export ucode information, so fetch it ourselves the good old way
    if [ -z "$cpu_ucode" ] && [ "$g_os" != Linux ]; then
        load_cpuid
        if [ -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
            if [ "$cpu_vendor" = AuthenticAMD ]; then
                # AMD: read MSR_PATCHLEVEL (0xC0010058) directly
                cpu_ucode=$(cpucontrol -m 0xC0010058 ${BSD_CPUCTL_DEV_BASE}0 2>/dev/null | awk '{print $3}')
            elif [ "$cpu_vendor" = GenuineIntel ]; then
                # Intel: write 0 to IA32_BIOS_SIGN_ID, execute CPUID, then read back
                cpucontrol -m 0x8b=0 ${BSD_CPUCTL_DEV_BASE}0 2>/dev/null
                cpucontrol -i 1 ${BSD_CPUCTL_DEV_BASE}0 >/dev/null 2>&1
                cpu_ucode=$(cpucontrol -m 0x8b ${BSD_CPUCTL_DEV_BASE}0 2>/dev/null | awk '{print $3}')
            fi
            if [ -n "$cpu_ucode" ]; then
                # convert to decimal then back to hex
                cpu_ucode=$((cpu_ucode))
                cpu_ucode=$(printf "0x%x" "$cpu_ucode")
            fi
        fi
    fi

    # if we got no cpu_ucode (e.g. we're in a vm), leave it empty
    # so that we can detect this case and avoid false positives

    # on non-x86 systems (e.g. ARM), these fields may not exist in cpuinfo, fall back to 0
    : "${cpu_family:=0}"
    : "${cpu_model:=0}"
    : "${cpu_stepping:=0}"

    if [ -n "${SMC_MOCK_CPU_UCODE:-}" ]; then
        cpu_ucode="$SMC_MOCK_CPU_UCODE"
        pr_debug "parse_cpu_details: MOCKING cpu ucode to $cpu_ucode"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPU_UCODE='$cpu_ucode'")
    fi

    local ucode_str
    if [ -n "$cpu_ucode" ]; then
        echo "$cpu_ucode" | grep -q ^0x && cpu_ucode=$((cpu_ucode))
        ucode_str=$(printf "0x%x" "$cpu_ucode")
    else
        ucode_str="unknown"
    fi
    g_ucode_found=$(printf "family 0x%x model 0x%x stepping 0x%x ucode %s cpuid 0x%x pfid 0x%x" \
        "$cpu_family" "$cpu_model" "$cpu_stepping" "$ucode_str" "$cpu_cpuid" "$cpu_platformid")

    g_parse_cpu_details_done=1
}
# Check whether the CPU vendor is Hygon
# Returns: 0 if Hygon, 1 otherwise
