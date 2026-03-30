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
        read_msr 0x17
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
            # init MSR with NULLs
            cpucontrol -m 0x8b=0 ${BSD_CPUCTL_DEV_BASE}0
            # call CPUID
            cpucontrol -i 1 ${BSD_CPUCTL_DEV_BASE}0 >/dev/null
            # read MSR
            cpu_ucode=$(cpucontrol -m 0x8b ${BSD_CPUCTL_DEV_BASE}0 | awk '{print $3}')
            # convert to decimal
            cpu_ucode=$((cpu_ucode))
            # convert back to hex
            cpu_ucode=$(printf "0x%x" "$cpu_ucode")
        fi
    fi

    # if we got no cpu_ucode (e.g. we're in a vm), fall back to 0x0
    : "${cpu_ucode:=0x0}"

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

    echo "$cpu_ucode" | grep -q ^0x && cpu_ucode=$((cpu_ucode))
    g_ucode_found=$(printf "family 0x%x model 0x%x stepping 0x%x ucode 0x%x cpuid 0x%x pfid 0x%x" \
        "$cpu_family" "$cpu_model" "$cpu_stepping" "$cpu_ucode" "$cpu_cpuid" "$cpu_platformid")

    # also define those that we will need in other funcs
    # taken from https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/intel-family.h
    # curl -s 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/arch/x86/include/asm/intel-family.h' | awk '/#define INTEL_FAM6/ {print $2"=$(( "$3" )) # "$4,$5,$6,$7,$8,$9}' | sed -Ee 's/ +$//'
    # shellcheck disable=SC2034
    {
        readonly INTEL_FAM6_CORE_YONAH=$((0x0E))           #
        readonly INTEL_FAM6_CORE2_MEROM=$((0x0F))          #
        readonly INTEL_FAM6_CORE2_MEROM_L=$((0x16))        #
        readonly INTEL_FAM6_CORE2_PENRYN=$((0x17))         #
        readonly INTEL_FAM6_CORE2_DUNNINGTON=$((0x1D))     #
        readonly INTEL_FAM6_NEHALEM=$((0x1E))              #
        readonly INTEL_FAM6_NEHALEM_G=$((0x1F))            # /* Auburndale / Havendale */
        readonly INTEL_FAM6_NEHALEM_EP=$((0x1A))           #
        readonly INTEL_FAM6_NEHALEM_EX=$((0x2E))           #
        readonly INTEL_FAM6_WESTMERE=$((0x25))             #
        readonly INTEL_FAM6_WESTMERE_EP=$((0x2C))          #
        readonly INTEL_FAM6_WESTMERE_EX=$((0x2F))          #
        readonly INTEL_FAM6_SANDYBRIDGE=$((0x2A))          #
        readonly INTEL_FAM6_SANDYBRIDGE_X=$((0x2D))        #
        readonly INTEL_FAM6_IVYBRIDGE=$((0x3A))            #
        readonly INTEL_FAM6_IVYBRIDGE_X=$((0x3E))          #
        readonly INTEL_FAM6_HASWELL=$((0x3C))              #
        readonly INTEL_FAM6_HASWELL_X=$((0x3F))            #
        readonly INTEL_FAM6_HASWELL_L=$((0x45))            #
        readonly INTEL_FAM6_HASWELL_G=$((0x46))            #
        readonly INTEL_FAM6_BROADWELL=$((0x3D))            #
        readonly INTEL_FAM6_BROADWELL_G=$((0x47))          #
        readonly INTEL_FAM6_BROADWELL_X=$((0x4F))          #
        readonly INTEL_FAM6_BROADWELL_D=$((0x56))          #
        readonly INTEL_FAM6_SKYLAKE_L=$((0x4E))            # /* Sky Lake */
        readonly INTEL_FAM6_SKYLAKE=$((0x5E))              # /* Sky Lake */
        readonly INTEL_FAM6_SKYLAKE_X=$((0x55))            # /* Sky Lake */
        readonly INTEL_FAM6_KABYLAKE_L=$((0x8E))           # /* Sky Lake */
        readonly INTEL_FAM6_KABYLAKE=$((0x9E))             # /* Sky Lake */
        readonly INTEL_FAM6_COMETLAKE=$((0xA5))            # /* Sky Lake */
        readonly INTEL_FAM6_COMETLAKE_L=$((0xA6))          # /* Sky Lake */
        readonly INTEL_FAM6_CANNONLAKE_L=$((0x66))         # /* Palm Cove */
        readonly INTEL_FAM6_ICELAKE_X=$((0x6A))            # /* Sunny Cove */
        readonly INTEL_FAM6_ICELAKE_D=$((0x6C))            # /* Sunny Cove */
        readonly INTEL_FAM6_ICELAKE=$((0x7D))              # /* Sunny Cove */
        readonly INTEL_FAM6_ICELAKE_L=$((0x7E))            # /* Sunny Cove */
        readonly INTEL_FAM6_ICELAKE_NNPI=$((0x9D))         # /* Sunny Cove */
        readonly INTEL_FAM6_LAKEFIELD=$((0x8A))            # /* Sunny Cove / Tremont */
        readonly INTEL_FAM6_ROCKETLAKE=$((0xA7))           # /* Cypress Cove */
        readonly INTEL_FAM6_TIGERLAKE_L=$((0x8C))          # /* Willow Cove */
        readonly INTEL_FAM6_TIGERLAKE=$((0x8D))            # /* Willow Cove */
        readonly INTEL_FAM6_SAPPHIRERAPIDS_X=$((0x8F))     # /* Golden Cove */
        readonly INTEL_FAM6_ALDERLAKE=$((0x97))            # /* Golden Cove / Gracemont */
        readonly INTEL_FAM6_ALDERLAKE_L=$((0x9A))          # /* Golden Cove / Gracemont */
        readonly INTEL_FAM6_RAPTORLAKE=$((0xB7))           #
        readonly INTEL_FAM6_ATOM_BONNELL=$((0x1C))         # /* Diamondville, Pineview */
        readonly INTEL_FAM6_ATOM_BONNELL_MID=$((0x26))     # /* Silverthorne, Lincroft */
        readonly INTEL_FAM6_ATOM_SALTWELL=$((0x36))        # /* Cedarview */
        readonly INTEL_FAM6_ATOM_SALTWELL_MID=$((0x27))    # /* Penwell */
        readonly INTEL_FAM6_ATOM_SALTWELL_TABLET=$((0x35)) # /* Cloverview */
        readonly INTEL_FAM6_ATOM_SILVERMONT=$((0x37))      # /* Bay Trail, Valleyview */
        readonly INTEL_FAM6_ATOM_SILVERMONT_D=$((0x4D))    # /* Avaton, Rangely */
        readonly INTEL_FAM6_ATOM_SILVERMONT_MID=$((0x4A))  # /* Merriefield */
        readonly INTEL_FAM6_ATOM_AIRMONT=$((0x4C))         # /* Cherry Trail, Braswell */
        readonly INTEL_FAM6_ATOM_AIRMONT_MID=$((0x5A))     # /* Moorefield */
        readonly INTEL_FAM6_ATOM_AIRMONT_NP=$((0x75))      # /* Lightning Mountain */
        readonly INTEL_FAM6_ATOM_GOLDMONT=$((0x5C))        # /* Apollo Lake */
        readonly INTEL_FAM6_ATOM_GOLDMONT_D=$((0x5F))      # /* Denverton */
        readonly INTEL_FAM6_ATOM_GOLDMONT_PLUS=$((0x7A))   # /* Gemini Lake */
        readonly INTEL_FAM6_ATOM_TREMONT_D=$((0x86))       # /* Jacobsville */
        readonly INTEL_FAM6_ATOM_TREMONT=$((0x96))         # /* Elkhart Lake */
        readonly INTEL_FAM6_ATOM_TREMONT_L=$((0x9C))       # /* Jasper Lake */
        readonly INTEL_FAM6_XEON_PHI_KNL=$((0x57))         # /* Knights Landing */
        readonly INTEL_FAM6_XEON_PHI_KNM=$((0x85))         # /* Knights Mill */
    }
    g_parse_cpu_details_done=1
}
# Check whether the CPU vendor is Hygon
# Returns: 0 if Hygon, 1 otherwise
