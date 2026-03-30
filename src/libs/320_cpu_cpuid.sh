# vim: set ts=4 sw=4 sts=4 et:
# Load the CPUID kernel module if not already loaded (Linux only)
# Sets: g_insmod_cpuid
load_cpuid() {
    [ "${g_load_cpuid_once:-}" = 1 ] && return
    g_load_cpuid_once=1

    if [ "$g_os" = Linux ]; then
        if ! grep -qw cpuid "$g_procfs/modules" 2>/dev/null; then
            modprobe cpuid 2>/dev/null && g_insmod_cpuid=1
            pr_debug "attempted to load module cpuid, g_insmod_cpuid=$g_insmod_cpuid"
        else
            pr_debug "cpuid module already loaded"
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

# shellcheck disable=SC2034
readonly EAX=1
readonly EBX=2
readonly ECX=3
readonly EDX=4
readonly READ_CPUID_RET_OK=0
readonly READ_CPUID_RET_KO=1
readonly READ_CPUID_RET_ERR=2
# Read a CPUID register value across one or all cores
# Args: $1=leaf $2=subleaf $3=register(EAX|EBX|ECX|EDX) $4=shift $5=bit_width $6=expected_value
# Sets: ret_read_cpuid_value, ret_read_cpuid_msg
# Returns: READ_CPUID_RET_OK | READ_CPUID_RET_KO | READ_CPUID_RET_ERR
read_cpuid() {
    local ret core first_core_ret first_core_value
    if [ "$opt_cpu" != all ]; then
        # we only have one core to read, do it and return the result
        read_cpuid_one_core "$opt_cpu" "$@"
        return $?
    fi

    # otherwise we must read all cores
    for core in $(seq 0 "$g_max_core_id"); do
        read_cpuid_one_core "$core" "$@"
        ret=$?
        if [ "$core" = 0 ]; then
            # save the result of the first core, for comparison with the others
            first_core_ret=$ret
            first_core_value=$ret_read_cpuid_value
        else
            # compare first core with the other ones
            if [ "$first_core_ret" != "$ret" ] || [ "$first_core_value" != "$ret_read_cpuid_value" ]; then
                ret_read_cpuid_msg="result is not homogeneous between all cores, at least core 0 and $core differ!"
                return $READ_CPUID_RET_ERR
            fi
        fi
    done
    # if we're here, all cores agree, return the result
    return "$ret"
}

# Read a CPUID register value from a single CPU core
# Args: $1=core $2=leaf $3=subleaf $4=register(EAX|EBX|ECX|EDX) $5=shift $6=bit_width $7=expected_value
# Sets: ret_read_cpuid_value, ret_read_cpuid_msg
# Returns: READ_CPUID_RET_OK | READ_CPUID_RET_KO | READ_CPUID_RET_ERR
read_cpuid_one_core() {
    local core leaf subleaf register shift mask wanted position ddskip odskip cpuid mockvarname reg reg_shifted
    # on which core to send the CPUID instruction
    core="$1"
    # leaf is the value of the eax register when calling the cpuid instruction:
    leaf="$2"
    # subleaf is the value of the ecx register when calling the cpuid instruction:
    subleaf="$3"
    # eax=1 ebx=2 ecx=3 edx=4:
    register="$4"
    # number of bits to shift the register right to, 0-31:
    shift="$5"
    # mask to apply as an AND operand to the shifted register value
    mask="$6"
    # wanted value (optional), if present we return 0(true) if the obtained value is equal, 1 otherwise:
    wanted="${7:-}"
    # in any case, the read value is globally available in $ret_read_cpuid_value
    ret_read_cpuid_value=''
    ret_read_cpuid_msg='unknown error'

    if [ $# -lt 6 ]; then
        ret_read_cpuid_msg="read_cpuid: missing arguments, got only $#, expected at least 6: $*"
        return $READ_CPUID_RET_ERR
    fi
    if [ "$register" -gt 4 ]; then
        ret_read_cpuid_msg="read_cpuid: register must be 0-4, got $register"
        return $READ_CPUID_RET_ERR
    fi
    if [ "$shift" -gt 32 ]; then
        ret_read_cpuid_msg="read_cpuid: shift must be 0-31, got $shift"
        return $READ_CPUID_RET_ERR
    fi

    if [ ! -e $CPU_DEV_BASE/0/cpuid ] && [ ! -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
        # try to load the module ourselves (and remember it so we can rmmod it afterwards)
        load_cpuid
    fi

    if [ -e $CPU_DEV_BASE/0/cpuid ]; then
        # Linux
        if [ ! -r $CPU_DEV_BASE/0/cpuid ]; then
            ret_read_cpuid_msg="Couldn't load cpuid module"
            return $READ_CPUID_RET_ERR
        fi
        # on some kernel versions, $CPU_DEV_BASE/0/cpuid doesn't imply that the cpuid module is loaded, in that case dd returns an error,
        # we use that fact to load the module if dd returns an error
        if ! dd if=$CPU_DEV_BASE/0/cpuid bs=16 count=1 >/dev/null 2>&1; then
            load_cpuid
        fi
        # we need leaf to be converted to decimal for dd
        leaf=$((leaf))
        subleaf=$((subleaf))
        position=$((leaf + (subleaf << 32)))
        # to avoid using iflag=skip_bytes, which doesn't exist on old versions of dd, seek to the closer multiple-of-16
        ddskip=$((position / 16))
        odskip=$((position - ddskip * 16))
        # now read the value
        cpuid=$(dd if="$CPU_DEV_BASE/$core/cpuid" bs=16 skip=$ddskip count=$((odskip + 1)) 2>/dev/null | od -j $((odskip * 16)) -A n -t u4)
    elif [ -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
        # BSD
        if [ ! -r ${BSD_CPUCTL_DEV_BASE}0 ]; then
            ret_read_cpuid_msg="Couldn't read cpuid info from cpuctl"
            return $READ_CPUID_RET_ERR
        fi
        cpuid=$(cpucontrol -i "$leaf","$subleaf" "${BSD_CPUCTL_DEV_BASE}$core" 2>/dev/null | cut -d: -f2-)
        # cpuid level 0x4, level_type 0x2: 0x1c004143 0x01c0003f 0x000001ff 0x00000000
    else
        ret_read_cpuid_msg="Found no way to read cpuid info"
        return $READ_CPUID_RET_ERR
    fi

    pr_debug "cpuid: leaf$leaf subleaf$subleaf on cpu$core, eax-ebx-ecx-edx: $cpuid"
    mockvarname="SMC_MOCK_CPUID_${leaf}_${subleaf}"
    # shellcheck disable=SC1083
    if [ -n "$(eval echo \${"$mockvarname":-})" ]; then
        cpuid="$(eval echo \$"$mockvarname")"
        pr_debug "read_cpuid: MOCKING enabled for leaf $leaf subleaf $subleaf, will return $cpuid"
        g_mocked=1
    else
        g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_CPUID_${leaf}_${subleaf}='$cpuid'")
    fi
    if [ -z "$cpuid" ]; then
        ret_read_cpuid_msg="Failed to get cpuid data"
        return $READ_CPUID_RET_ERR
    fi

    # get the value of the register we want
    reg=$(echo "$cpuid" | awk '{print $'"$register"'}')
    # Linux returns it as decimal, BSD as hex, normalize to decimal
    reg=$((reg))
    # shellcheck disable=SC2046
    pr_debug "cpuid: wanted register ($register) has value $reg aka "$(printf "%08x" "$reg")
    reg_shifted=$((reg >> shift))
    # shellcheck disable=SC2046
    pr_debug "cpuid: shifted value by $shift is $reg_shifted aka "$(printf "%x" "$reg_shifted")
    ret_read_cpuid_value=$((reg_shifted & mask))
    # shellcheck disable=SC2046
    pr_debug "cpuid: after AND $mask, final value is $ret_read_cpuid_value aka "$(printf "%x" "$ret_read_cpuid_value")
    if [ -n "$wanted" ]; then
        pr_debug "cpuid: wanted $wanted and got $ret_read_cpuid_value"
        if [ "$ret_read_cpuid_value" = "$wanted" ]; then
            return $READ_CPUID_RET_OK
        else
            return $READ_CPUID_RET_KO
        fi
    fi

    return $READ_CPUID_RET_OK
}
