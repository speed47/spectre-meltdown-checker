# vim: set ts=4 sw=4 sts=4 et:
readonly WRITE_MSR_RET_OK=0
readonly WRITE_MSR_RET_KO=1
readonly WRITE_MSR_RET_ERR=2
readonly WRITE_MSR_RET_LOCKDOWN=3
# Write a value to an MSR register across one or all cores
# Args: $1=msr_address $2=value(optional) $3=cpu_index(optional, default 0)
# Sets: ret_write_msr_msg, ret_write_msr_ADDR_msg (where ADDR is the hex address, e.g. ret_write_msr_0x123_msg)
# Returns: WRITE_MSR_RET_OK | WRITE_MSR_RET_KO | WRITE_MSR_RET_ERR | WRITE_MSR_RET_LOCKDOWN
write_msr() {
    local ret core first_core_ret msr_dec msr
    msr_dec=$(($1))
    msr=$(printf "0x%x" "$msr_dec")
    if [ "$opt_cpu" != all ]; then
        # we only have one core to write to, do it and return the result
        write_msr_one_core "$opt_cpu" "$@"
        ret=$?
        # shellcheck disable=SC2163
        eval "ret_write_msr_${msr}_msg=\$ret_write_msr_msg"
        return $ret
    fi

    # otherwise we must write on all cores
    for core in $(seq 0 "$g_max_core_id"); do
        write_msr_one_core "$core" "$@"
        ret=$?
        # shellcheck disable=SC2163
        eval "ret_write_msr_${msr}_msg=\$ret_write_msr_msg"
        if [ "$core" = 0 ]; then
            # save the result of the first core, for comparison with the others
            first_core_ret=$ret
        else
            # compare first core with the other ones
            if [ "$first_core_ret" != "$ret" ]; then
                ret_write_msr_msg="result is not homogeneous between all cores, at least core 0 and $core differ!"
                # shellcheck disable=SC2163
                eval "ret_write_msr_${msr}_msg=\$ret_write_msr_msg"
                return $WRITE_MSR_RET_ERR
            fi
        fi
    done
    # if we're here, all cores agree, return the result
    return $ret
}

# Write a value to an MSR register on a single CPU core
# Args: $1=core $2=msr_address $3=value
# Sets: ret_write_msr_msg
# Returns: WRITE_MSR_RET_OK | WRITE_MSR_RET_KO | WRITE_MSR_RET_ERR | WRITE_MSR_RET_LOCKDOWN
write_msr_one_core() {
    local ret core msr msr_dec value value_dec mockvarname write_denied
    core="$1"
    msr_dec=$(($2))
    msr=$(printf "0x%x" "$msr_dec")
    value_dec=$((${3:-0}))
    value=$(printf "0x%x" "$value_dec")

    ret_write_msr_msg='unknown error'
    : "${g_msr_locked_down:=0}"

    mockvarname="SMC_MOCK_WRMSR_${msr}_RET"
    # shellcheck disable=SC2086,SC1083
    if [ -n "$(eval echo \${$mockvarname:-})" ]; then
        local mockret
        mockret="$(eval echo \$$mockvarname)"
        pr_debug "write_msr: MOCKING enabled for msr $msr func returns $mockret"
        g_mocked=1
        if [ "$mockret" = "$WRITE_MSR_RET_LOCKDOWN" ]; then
            g_msr_locked_down=1
            ret_write_msr_msg="kernel lockdown is enabled, MSR writes are restricted"
        elif [ "$mockret" = "$WRITE_MSR_RET_ERR" ]; then
            ret_write_msr_msg="could not write MSR"
        fi
        return "$mockret"
    fi

    # proactive lockdown detection via sysfs (vanilla 5.4+, CentOS 8+, Rocky 9+):
    # if the kernel lockdown is set to integrity or confidentiality, MSR writes will be denied,
    # so we can skip the write attempt entirely and avoid relying on dmesg parsing
    if [ -e "$SYSKERNEL_BASE/security/lockdown" ]; then
        if grep -qE '\[integrity\]|\[confidentiality\]' "$SYSKERNEL_BASE/security/lockdown" 2>/dev/null; then
            pr_debug "write_msr: kernel lockdown detected via $SYSKERNEL_BASE/security/lockdown"
            g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_WRMSR_${msr}_RET=$WRITE_MSR_RET_LOCKDOWN")
            g_msr_locked_down=1
            ret_write_msr_msg="your kernel is locked down, please reboot with lockdown=none in the kernel cmdline and retry"
            return $WRITE_MSR_RET_LOCKDOWN
        fi
    fi

    if [ ! -e $CPU_DEV_BASE/0/msr ] && [ ! -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
        # try to load the module ourselves (and remember it so we can rmmod it afterwards)
        load_msr
    fi
    if [ ! -e $CPU_DEV_BASE/0/msr ] && [ ! -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
        ret_write_msr_msg="msr kernel module is not available"
        return $WRITE_MSR_RET_ERR
    fi

    write_denied=0
    if [ "$g_os" != Linux ]; then
        cpucontrol -m "$msr=$value" "${BSD_CPUCTL_DEV_BASE}$core" >/dev/null 2>&1
        ret=$?
    else
        # for Linux
        if [ ! -w $CPU_DEV_BASE/"$core"/msr ]; then
            ret_write_msr_msg="No write permission on $CPU_DEV_BASE/$core/msr"
            return $WRITE_MSR_RET_ERR
        # if wrmsr is available, use it
        elif command -v wrmsr >/dev/null 2>&1 && [ "${SMC_NO_WRMSR:-}" != 1 ]; then
            pr_debug "write_msr: using wrmsr"
            wrmsr -p "$core" $msr_dec $value_dec 2>/dev/null
            ret=$?
            # ret=4: msr doesn't exist, ret=127: msr.allow_writes=off
            [ "$ret" = 127 ] && write_denied=1
        # or fallback to dd if it supports seek_bytes, we prefer it over perl because we can tell the difference between EPERM and EIO
        elif dd if=/dev/null of=/dev/null bs=8 count=1 seek="$msr_dec" oflag=seek_bytes 2>/dev/null && [ "${SMC_NO_DD:-}" != 1 ]; then
            pr_debug "write_msr: using dd"
            awk "BEGIN{printf \"%c\", $value_dec}" | dd of=$CPU_DEV_BASE/"$core"/msr bs=8 count=1 seek="$msr_dec" oflag=seek_bytes 2>/dev/null
            ret=$?
            # if it failed, inspect stderrto look for EPERM
            if [ "$ret" != 0 ]; then
                if awk "BEGIN{printf \"%c\", $value_dec}" | dd of=$CPU_DEV_BASE/"$core"/msr bs=8 count=1 seek="$msr_dec" oflag=seek_bytes 2>&1 | grep -qF 'Operation not permitted'; then
                    write_denied=1
                fi
            fi
        # or if we have perl, use it, any 5.x version will work
        elif command -v perl >/dev/null 2>&1 && [ "${SMC_NO_PERL:-}" != 1 ]; then
            pr_debug "write_msr: using perl"
            ret=1
            perl -e "open(M,'>','$CPU_DEV_BASE/$core/msr') and seek(M,$msr_dec,0) and exit(syswrite(M,pack(v4,$value_dec)))"
            [ $? -eq 8 ] && ret=0
        else
            pr_debug "write_msr: got no wrmsr, perl or recent enough dd!"
            g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_WRMSR_${msr}_RET=$WRITE_MSR_RET_ERR")
            ret_write_msr_msg="missing tool, install either msr-tools or perl"
            return $WRITE_MSR_RET_ERR
        fi
        if [ "$ret" != 0 ]; then
            # * Fedora (and probably Red Hat) have a "kernel lock down" feature that prevents us to write to MSRs
            # when this mode is enabled and EFI secure boot is enabled (see issue #303)
            # https://src.fedoraproject.org/rpms/kernel/blob/master/f/efi-lockdown.patch
            # when this happens, any write will fail and dmesg will have a msg printed "msr: Direct access to MSR"
            # * A version of this patch also made it to vanilla in 5.4+, in that case the message is: 'raw MSR access is restricted'
            # * we don't use dmesg_grep() because we don't care if dmesg is truncated here, as the message has just been printed
            # yet more recent versions of the msr module can be set to msr.allow_writes=off, in which case no dmesg message is printed,
            # but the write fails
            if [ "$write_denied" = 1 ]; then
                pr_debug "write_msr: writing to msr has been denied"
                g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_WRMSR_${msr}_RET=$WRITE_MSR_RET_LOCKDOWN")
                g_msr_locked_down=1
                ret_write_msr_msg="your kernel is configured to deny writes to MSRs from user space"
                return $WRITE_MSR_RET_LOCKDOWN
            elif dmesg 2>/dev/null | grep -qF "msr: Direct access to MSR"; then
                pr_debug "write_msr: locked down kernel detected (Red Hat / Fedora)"
                g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_WRMSR_${msr}_RET=$WRITE_MSR_RET_LOCKDOWN")
                g_msr_locked_down=1
                ret_write_msr_msg="your kernel is locked down (Fedora/Red Hat), please reboot without secure boot and retry"
                return $WRITE_MSR_RET_LOCKDOWN
            elif dmesg 2>/dev/null | grep -qF "raw MSR access is restricted"; then
                pr_debug "write_msr: locked down kernel detected (vanilla)"
                g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_WRMSR_${msr}_RET=$WRITE_MSR_RET_LOCKDOWN")
                g_msr_locked_down=1
                ret_write_msr_msg="your kernel is locked down, please reboot with lockdown=none in the kernel cmdline and retry"
                return $WRITE_MSR_RET_LOCKDOWN
            fi
            unset write_denied
        fi
    fi

    # normalize ret
    if [ "$ret" = 0 ]; then
        ret=$WRITE_MSR_RET_OK
    else
        ret=$WRITE_MSR_RET_KO
    fi
    pr_debug "write_msr: for cpu $core on msr $msr, value=$value, ret=$ret"
    g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_WRMSR_${msr}_RET=$ret")
    return $ret
}

readonly MSR_IA32_PLATFORM_ID=0x17
readonly MSR_IA32_SPEC_CTRL=0x48
readonly MSR_IA32_ARCH_CAPABILITIES=0x10a
readonly MSR_IA32_TSX_FORCE_ABORT=0x10f
readonly MSR_IA32_TSX_CTRL=0x122
readonly MSR_IA32_MCU_OPT_CTRL=0x123
readonly READ_MSR_RET_OK=0
readonly READ_MSR_RET_KO=1
readonly READ_MSR_RET_ERR=2
readonly READ_MSR_RET_LOCKDOWN=3
# Read an MSR register value across one or all cores
# Args: $1=msr_address $2=cpu_index(optional, default 0)
# Sets: ret_read_msr_value, ret_read_msr_value_hi, ret_read_msr_value_lo, ret_read_msr_msg,
#       ret_read_msr_ADDR_msg (where ADDR is the hex address, e.g. ret_read_msr_0x10a_msg)
# Returns: READ_MSR_RET_OK | READ_MSR_RET_KO | READ_MSR_RET_ERR | READ_MSR_RET_LOCKDOWN
read_msr() {
    local ret core first_core_ret first_core_value msr_dec msr
    msr_dec=$(($1))
    msr=$(printf "0x%x" "$msr_dec")
    if [ "$opt_cpu" != all ]; then
        # we only have one core to read, do it and return the result
        read_msr_one_core "$opt_cpu" "$@"
        ret=$?
        # shellcheck disable=SC2163
        eval "ret_read_msr_${msr}_msg=\$ret_read_msr_msg"
        return $ret
    fi

    # otherwise we must read all cores
    for core in $(seq 0 "$g_max_core_id"); do
        read_msr_one_core "$core" "$@"
        ret=$?
        # shellcheck disable=SC2163
        eval "ret_read_msr_${msr}_msg=\$ret_read_msr_msg"
        if [ "$core" = 0 ]; then
            # save the result of the first core, for comparison with the others
            first_core_ret=$ret
            first_core_value=$ret_read_msr_value
        else
            # compare first core with the other ones
            if [ "$first_core_ret" != "$ret" ] || [ "$first_core_value" != "$ret_read_msr_value" ]; then
                ret_read_msr_msg="result is not homogeneous between all cores, at least core 0 and $core differ!"
                # shellcheck disable=SC2163
                eval "ret_read_msr_${msr}_msg=\$ret_read_msr_msg"
                return $READ_MSR_RET_ERR
            fi
        fi
    done
    # if we're here, all cores agree, return the result
    return "$ret"
}

# Read an MSR register value from a single CPU core
# Args: $1=core $2=msr_address
# Sets: ret_read_msr_value, ret_read_msr_value_hi, ret_read_msr_value_lo, ret_read_msr_msg
# Returns: READ_MSR_RET_OK | READ_MSR_RET_KO | READ_MSR_RET_ERR | READ_MSR_RET_LOCKDOWN
read_msr_one_core() {
    local ret core msr msr_dec mockvarname msr_h msr_l mockval
    core="$1"
    msr_dec=$(($2))
    msr=$(printf "0x%x" "$msr_dec")

    ret_read_msr_value=''
    ret_read_msr_value_hi=''
    ret_read_msr_value_lo=''
    ret_read_msr_msg='unknown error'

    mockvarname="SMC_MOCK_RDMSR_${msr}"
    # shellcheck disable=SC2086,SC1083
    if [ -n "$(eval echo \${$mockvarname:-})" ]; then
        mockval="$(eval echo \$$mockvarname)"
        # accept both legacy decimal (small values) and new 16-char hex format
        if [ "${#mockval}" -eq 16 ]; then
            ret_read_msr_value="$mockval"
        else
            ret_read_msr_value=$(printf '%016x' "$mockval")
        fi
        ret_read_msr_value_hi=$((0x${ret_read_msr_value%????????}))
        ret_read_msr_value_lo=$((0x${ret_read_msr_value#????????}))
        pr_debug "read_msr: MOCKING enabled for msr $msr, returning $ret_read_msr_value"
        g_mocked=1
        return $READ_MSR_RET_OK
    fi

    mockvarname="SMC_MOCK_RDMSR_${msr}_RET"
    # shellcheck disable=SC2086,SC1083
    if [ -n "$(eval echo \${$mockvarname:-})" ] && [ "$(eval echo \$$mockvarname)" -ne 0 ]; then
        local mockret
        mockret="$(eval echo \$$mockvarname)"
        pr_debug "read_msr: MOCKING enabled for msr $msr func returns $mockret"
        g_mocked=1
        if [ "$mockret" = "$READ_MSR_RET_LOCKDOWN" ]; then
            ret_read_msr_msg="kernel lockdown is enabled, MSR reads are restricted"
        elif [ "$mockret" = "$READ_MSR_RET_ERR" ]; then
            ret_read_msr_msg="could not read MSR"
        fi
        return "$mockret"
    fi

    # proactive lockdown detection via sysfs (vanilla 5.4+, CentOS 8+, Rocky 9+):
    # if the kernel lockdown is set to integrity or confidentiality, MSR reads will be denied,
    # so we can skip the read attempt entirely and avoid relying on dmesg parsing
    if [ -e "$SYSKERNEL_BASE/security/lockdown" ]; then
        if grep -qE '\[integrity\]|\[confidentiality\]' "$SYSKERNEL_BASE/security/lockdown" 2>/dev/null; then
            pr_debug "read_msr: kernel lockdown detected via $SYSKERNEL_BASE/security/lockdown"
            g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_RDMSR_${msr}_RET=$READ_MSR_RET_LOCKDOWN")
            g_msr_locked_down=1
            ret_read_msr_msg="kernel lockdown is enabled, MSR reads are restricted"
            return $READ_MSR_RET_LOCKDOWN
        fi
    fi

    if [ ! -e $CPU_DEV_BASE/0/msr ] && [ ! -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
        # try to load the module ourselves (and remember it so we can rmmod it afterwards)
        load_msr
    fi
    if [ ! -e $CPU_DEV_BASE/0/msr ] && [ ! -e ${BSD_CPUCTL_DEV_BASE}0 ]; then
        ret_read_msr_msg="msr kernel module is not available"
        return $READ_MSR_RET_ERR
    fi

    if [ "$g_os" != Linux ]; then
        # for BSD
        msr=$(cpucontrol -m "$msr" "${BSD_CPUCTL_DEV_BASE}$core" 2>/dev/null)
        ret=$?
        if [ $ret -ne 0 ]; then
            g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_RDMSR_${msr}_RET=$READ_MSR_RET_KO")
            return $READ_MSR_RET_KO
        fi
        # MSR 0x10: 0x000003e1 0xb106dded
        msr_h=$(echo "$msr" | awk '{print $3}')
        msr_l=$(echo "$msr" | awk '{print $4}')
        ret_read_msr_value=$(printf '%08x%08x' "$((msr_h))" "$((msr_l))")
    else
        # for Linux
        if [ ! -r $CPU_DEV_BASE/"$core"/msr ]; then
            g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_RDMSR_${msr}_RET=$READ_MSR_RET_ERR")
            ret_read_msr_msg="No read permission for $CPU_DEV_BASE/$core/msr"
            return $READ_MSR_RET_ERR
        # if rdmsr is available, use it
        elif command -v rdmsr >/dev/null 2>&1 && [ "${SMC_NO_RDMSR:-}" != 1 ]; then
            pr_debug "read_msr: using rdmsr on $msr"
            ret_read_msr_value=$(rdmsr -r $msr_dec 2>/dev/null | od -A n -t x8)
        # or if we have perl, use it, any 5.x version will work
        elif command -v perl >/dev/null 2>&1 && [ "${SMC_NO_PERL:-}" != 1 ]; then
            pr_debug "read_msr: using perl on $msr"
            ret_read_msr_value=$(perl -e "open(M,'<','$CPU_DEV_BASE/$core/msr') and seek(M,$msr_dec,0) and read(M,\$_,8) and print" | od -A n -t x8)
        # fallback to dd if it supports skip_bytes
        elif dd if=/dev/null of=/dev/null bs=8 count=1 skip="$msr_dec" iflag=skip_bytes 2>/dev/null; then
            pr_debug "read_msr: using dd on $msr"
            ret_read_msr_value=$(dd if=$CPU_DEV_BASE/"$core"/msr bs=8 count=1 skip="$msr_dec" iflag=skip_bytes 2>/dev/null | od -A n -t x8)
        else
            pr_debug "read_msr: got no rdmsr, perl or recent enough dd!"
            g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_RDMSR_${msr}_RET=$READ_MSR_RET_ERR")
            ret_read_msr_msg='missing tool, install either msr-tools or perl'
            return $READ_MSR_RET_ERR
        fi
        if [ -z "$ret_read_msr_value" ]; then
            # MSR doesn't exist, don't check for $? because some versions of dd still return 0!
            g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_RDMSR_${msr}_RET=$READ_MSR_RET_KO")
            return $READ_MSR_RET_KO
        fi
        # remove sparse spaces od might give us
        ret_read_msr_value=$(printf '%s' "$ret_read_msr_value" | tr -d ' \t\n' | tr '[:upper:]' '[:lower:]')
    fi
    ret_read_msr_value_hi=$((0x${ret_read_msr_value%????????}))
    ret_read_msr_value_lo=$((0x${ret_read_msr_value#????????}))
    g_mockme=$(printf "%b\n%b" "$g_mockme" "SMC_MOCK_RDMSR_${msr}='$ret_read_msr_value'")
    pr_debug "read_msr: MSR=$msr value is $ret_read_msr_value"
    return $READ_MSR_RET_OK
}
