# vim: set ts=4 sw=4 sts=4 et:
# --- JSON helper functions ---

# Escape a string for use in a JSON value (handles backslashes, double quotes, newlines, tabs)
# Args: $1=string
# Prints: escaped string (without surrounding quotes)
_json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/\\t/g' | tr '\n' ' '
}

# Escape a string for use as a Prometheus label value (handles backslashes, double quotes, newlines)
# Args: $1=string
# Prints: escaped string (without surrounding quotes)
_prom_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n' ' '
}

# Convert a shell capability value to a JSON token
# Args: $1=value (1=true, 0=false, -1/empty=null, other string=quoted string)
# Prints: JSON token
_json_cap() {
    case "${1:-}" in
        1)    printf 'true' ;;
        0)    printf 'false' ;;
        -1|'') printf 'null' ;;
        *)    printf '"%s"' "$(_json_escape "$1")" ;;
    esac
}

# Emit a JSON string value or null
# Args: $1=string (empty=null)
# Prints: JSON token ("escaped string" or null)
_json_str() {
    if [ -n "${1:-}" ]; then
        printf '"%s"' "$(_json_escape "$1")"
    else
        printf 'null'
    fi
}

# Emit a JSON number value or null
# Args: $1=number (empty=null)
# Prints: JSON token
_json_num() {
    if [ -n "${1:-}" ]; then
        printf '%s' "$1"
    else
        printf 'null'
    fi
}

# Emit a JSON boolean value or null
# Args: $1=value (1/0/empty)
# Prints: JSON token
_json_bool() {
    case "${1:-}" in
        1) printf 'true' ;;
        0) printf 'false' ;;
        *) printf 'null' ;;
    esac
}

# --- JSON section builders (comprehensive format) ---

# Build the "meta" section of the comprehensive JSON output
# Sets: g_json_meta
# shellcheck disable=SC2034
_build_json_meta() {
    local timestamp mode
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "unknown")
    if [ "$opt_no_hw" = 1 ]; then
        mode="no-hw"
    elif [ "$opt_runtime" = 0 ]; then
        mode="no-runtime"
    else
        mode="live"
    fi
    local run_as_root
    if [ "$(id -u)" -eq 0 ]; then
        run_as_root='true'
    else
        run_as_root='false'
    fi
    g_json_meta=$(printf '{"script_version":%s,"format_version":1,"timestamp":%s,"os":%s,"mode":"%s","run_as_root":%s,"reduced_accuracy":%s,"paranoid":%s,"sysfs_only":%s,"no_hw":%s,"extra":%s}' \
        "$(_json_str "$VERSION")" \
        "$(_json_str "$timestamp")" \
        "$(_json_str "$g_os")" \
        "$mode" \
        "$run_as_root" \
        "$(_json_bool "${g_bad_accuracy:-0}")" \
        "$(_json_bool "$opt_paranoid")" \
        "$(_json_bool "$opt_sysfs_only")" \
        "$(_json_bool "$opt_no_hw")" \
        "$(_json_bool "$opt_extra")")
}

# Build the "system" section of the comprehensive JSON output
# Sets: g_json_system
# shellcheck disable=SC2034
_build_json_system() {
    local kernel_release kernel_version kernel_arch smt_val
    if [ "$opt_runtime" = 1 ]; then
        kernel_release=$(uname -r)
        kernel_version=$(uname -v)
        kernel_arch=$(uname -m)
    else
        kernel_release=''
        kernel_version=''
        kernel_arch=''
    fi
    # SMT detection
    is_cpu_smt_enabled
    smt_val=$?
    case $smt_val in
        0) smt_val='true' ;;
        1) smt_val='false' ;;
        *) smt_val='null' ;;
    esac
    g_json_system=$(printf '{"kernel_release":%s,"kernel_version":%s,"kernel_arch":%s,"kernel_image":%s,"kernel_config":%s,"kernel_version_string":%s,"kernel_cmdline":%s,"cpu_count":%s,"smt_enabled":%s,"hypervisor_host":%s,"hypervisor_host_reason":%s}' \
        "$(_json_str "$kernel_release")" \
        "$(_json_str "$kernel_version")" \
        "$(_json_str "$kernel_arch")" \
        "$(_json_str "${opt_kernel:-}")" \
        "$(_json_str "${opt_config:-}")" \
        "$(_json_str "${g_kernel_version:-}")" \
        "$(_json_str "${g_kernel_cmdline:-}")" \
        "$(_json_num "${g_max_core_id:+$((g_max_core_id + 1))}")" \
        "$smt_val" \
        "$(_json_bool "${g_has_vmm:-}")" \
        "$(_json_str "${g_has_vmm_reason:-}")")
}

# Build the "cpu" section of the comprehensive JSON output
# Sets: g_json_cpu
# shellcheck disable=SC2034
_build_json_cpu() {
    local cpuid_hex ucode_hex codename caps
    if [ -n "${cpu_cpuid:-}" ]; then
        cpuid_hex=$(printf '0x%08x' "$cpu_cpuid")
    else
        cpuid_hex=''
    fi
    if [ -n "${cpu_ucode:-}" ]; then
        ucode_hex=$(printf '0x%x' "$cpu_ucode")
    else
        ucode_hex=''
    fi
    codename=''
    if is_intel; then
        codename=$(get_intel_codename 2>/dev/null || true)
    fi
    # Build capabilities sub-object
    caps=$(printf '{"spec_ctrl":%s,"ibrs":%s,"ibpb":%s,"ibpb_ret":%s,"stibp":%s,"ssbd":%s,"l1d_flush":%s,"md_clear":%s,"arch_capabilities":%s,"rdcl_no":%s,"ibrs_all":%s,"rsba":%s,"l1dflush_no":%s,"ssb_no":%s,"mds_no":%s,"taa_no":%s,"pschange_msc_no":%s,"tsx_ctrl_msr":%s,"tsx_ctrl_rtm_disable":%s,"tsx_ctrl_cpuid_clear":%s,"gds_ctrl":%s,"gds_no":%s,"gds_mitg_dis":%s,"gds_mitg_lock":%s,"rfds_no":%s,"rfds_clear":%s,"its_no":%s,"sbdr_ssdp_no":%s,"fbsdp_no":%s,"psdp_no":%s,"fb_clear":%s,"rtm":%s,"tsx_force_abort":%s,"tsx_force_abort_rtm_disable":%s,"tsx_force_abort_cpuid_clear":%s,"sgx":%s,"srbds":%s,"srbds_on":%s,"amd_ssb_no":%s,"hygon_ssb_no":%s,"ipred":%s,"rrsba":%s,"bhi":%s,"tsa_sq_no":%s,"tsa_l1_no":%s,"verw_clear":%s,"autoibrs":%s,"sbpb":%s,"avx2":%s,"avx512":%s}' \
        "$(_json_cap "${cap_spec_ctrl:-}")" \
        "$(_json_cap "${cap_ibrs:-}")" \
        "$(_json_cap "${cap_ibpb:-}")" \
        "$(_json_cap "${cap_ibpb_ret:-}")" \
        "$(_json_cap "${cap_stibp:-}")" \
        "$(_json_cap "${cap_ssbd:-}")" \
        "$(_json_cap "${cap_l1df:-}")" \
        "$(_json_cap "${cap_md_clear:-}")" \
        "$(_json_cap "${cap_arch_capabilities:-}")" \
        "$(_json_cap "${cap_rdcl_no:-}")" \
        "$(_json_cap "${cap_ibrs_all:-}")" \
        "$(_json_cap "${cap_rsba:-}")" \
        "$(_json_cap "${cap_l1dflush_no:-}")" \
        "$(_json_cap "${cap_ssb_no:-}")" \
        "$(_json_cap "${cap_mds_no:-}")" \
        "$(_json_cap "${cap_taa_no:-}")" \
        "$(_json_cap "${cap_pschange_msc_no:-}")" \
        "$(_json_cap "${cap_tsx_ctrl_msr:-}")" \
        "$(_json_cap "${cap_tsx_ctrl_rtm_disable:-}")" \
        "$(_json_cap "${cap_tsx_ctrl_cpuid_clear:-}")" \
        "$(_json_cap "${cap_gds_ctrl:-}")" \
        "$(_json_cap "${cap_gds_no:-}")" \
        "$(_json_cap "${cap_gds_mitg_dis:-}")" \
        "$(_json_cap "${cap_gds_mitg_lock:-}")" \
        "$(_json_cap "${cap_rfds_no:-}")" \
        "$(_json_cap "${cap_rfds_clear:-}")" \
        "$(_json_cap "${cap_its_no:-}")" \
        "$(_json_cap "${cap_sbdr_ssdp_no:-}")" \
        "$(_json_cap "${cap_fbsdp_no:-}")" \
        "$(_json_cap "${cap_psdp_no:-}")" \
        "$(_json_cap "${cap_fb_clear:-}")" \
        "$(_json_cap "${cap_rtm:-}")" \
        "$(_json_cap "${cap_tsx_force_abort:-}")" \
        "$(_json_cap "${cap_tsx_force_abort_rtm_disable:-}")" \
        "$(_json_cap "${cap_tsx_force_abort_cpuid_clear:-}")" \
        "$(_json_cap "${cap_sgx:-}")" \
        "$(_json_cap "${cap_srbds:-}")" \
        "$(_json_cap "${cap_srbds_on:-}")" \
        "$(_json_cap "${cap_amd_ssb_no:-}")" \
        "$(_json_cap "${cap_hygon_ssb_no:-}")" \
        "$(_json_cap "${cap_ipred:-}")" \
        "$(_json_cap "${cap_rrsba:-}")" \
        "$(_json_cap "${cap_bhi:-}")" \
        "$(_json_cap "${cap_tsa_sq_no:-}")" \
        "$(_json_cap "${cap_tsa_l1_no:-}")" \
        "$(_json_cap "${cap_verw_clear:-}")" \
        "$(_json_cap "${cap_autoibrs:-}")" \
        "$(_json_cap "${cap_sbpb:-}")" \
        "$(_json_cap "${cap_avx2:-}")" \
        "$(_json_cap "${cap_avx512:-}")")

    g_json_cpu=$(printf '{"vendor":%s,"friendly_name":%s,"family":%s,"model":%s,"stepping":%s,"cpuid":%s,"platform_id":%s,"hybrid":%s,"codename":%s,"arm_part_list":%s,"arm_arch_list":%s,"capabilities":%s}' \
        "$(_json_str "${cpu_vendor:-}")" \
        "$(_json_str "${cpu_friendly_name:-}")" \
        "$(_json_num "${cpu_family:-}")" \
        "$(_json_num "${cpu_model:-}")" \
        "$(_json_num "${cpu_stepping:-}")" \
        "$(_json_str "$cpuid_hex")" \
        "$(_json_num "${cpu_platformid:-}")" \
        "$(_json_bool "${cpu_hybrid:-}")" \
        "$(_json_str "$codename")" \
        "$(_json_str "${cpu_part_list:-}")" \
        "$(_json_str "${cpu_arch_list:-}")" \
        "$caps")
}

# Build the "cpu_microcode" section of the comprehensive JSON output
# Sets: g_json_cpu_microcode
# shellcheck disable=SC2034
_build_json_cpu_microcode() {
    local ucode_uptodate ucode_hex latest_hex blacklisted
    if [ -n "${cpu_ucode:-}" ]; then
        ucode_hex=$(printf '0x%x' "$cpu_ucode")
    else
        ucode_hex=''
    fi
    is_latest_known_ucode
    case $? in
        0) ucode_uptodate='true' ;;
        1) ucode_uptodate='false' ;;
        *) ucode_uptodate='null' ;;
    esac
    if is_ucode_blacklisted; then
        blacklisted='true'
    else
        blacklisted='false'
    fi
    latest_hex="${ret_is_latest_known_ucode_version:-}"
    g_json_cpu_microcode=$(printf '{"installed_version":%s,"latest_version":%s,"microcode_up_to_date":%s,"is_blacklisted":%s,"message":%s,"db_source":%s,"db_info":%s}' \
        "$(_json_str "$ucode_hex")" \
        "$(_json_str "$latest_hex")" \
        "$ucode_uptodate" \
        "$blacklisted" \
        "$(_json_str "${ret_is_latest_known_ucode_latest:-}")" \
        "$(_json_str "${g_mcedb_source:-}")" \
        "$(_json_str "${g_mcedb_info:-}")")
}

# --- Format-specific batch emitters ---

# Emit a single CVE result as plain text
# Args: $1=cve $2=aka $3=status $4=description
# Callers: pvulnstatus
_emit_text() {
    _pr_echo 0 "$1: $3 ($4)"
}

# Append CVE ID to the space-separated short output buffer
# Args: $1=cve $2=aka $3=status $4=description
# Sets: g_short_output
# Callers: pvulnstatus
_emit_short() {
    g_short_output="${g_short_output}$1 "
}

# Append a CVE result as a terse JSON object to the batch output buffer
# Args: $1=cve $2=aka $3=status(UNK|VULN|OK) $4=description
# Sets: g_json_output
# Callers: pvulnstatus
_emit_json_terse() {
    local is_vuln esc_name esc_infos
    case "$3" in
        UNK) is_vuln="null" ;;
        VULN) is_vuln="true" ;;
        OK) is_vuln="false" ;;
        *)
            echo "$0: error: unknown status '$3' passed to _emit_json_terse()" >&2
            exit 255
            ;;
    esac
    esc_name=$(_json_escape "$2")
    esc_infos=$(_json_escape "$4")
    [ -z "$g_json_output" ] && g_json_output='['
    g_json_output="${g_json_output}{\"NAME\":\"$esc_name\",\"CVE\":\"$1\",\"VULNERABLE\":$is_vuln,\"INFOS\":\"$esc_infos\"},"
}

# Append a CVE result as a comprehensive JSON object to the batch output buffer
# Args: $1=cve $2=aka $3=status(UNK|VULN|OK) $4=description
# Sets: g_json_vulns
# Callers: pvulnstatus
_emit_json_full() {
    local is_vuln esc_name esc_infos aliases cpu_affected sysfs_status sysfs_msg
    case "$3" in
        UNK) is_vuln="null" ;;
        VULN) is_vuln="true" ;;
        OK) is_vuln="false" ;;
        *)
            echo "$0: error: unknown status '$3' passed to _emit_json_full()" >&2
            exit 255
            ;;
    esac
    esc_name=$(_json_escape "$2")
    esc_infos=$(_json_escape "$4")
    aliases=$(_cve_registry_field "$1" 4)

    # CPU affection status (cached, cheap)
    if is_cpu_affected "$1" 2>/dev/null; then
        cpu_affected='true'
    else
        cpu_affected='false'
    fi

    # sysfs status: use the value captured by this CVE's check function, then clear it
    # so it doesn't leak into the next CVE that might not call sys_interface_check
    sysfs_status="${g_json_cve_sysfs_status:-}"
    sysfs_msg="${g_json_cve_sysfs_msg:-}"

    : "${g_json_vulns:=}"
    g_json_vulns="${g_json_vulns}{\"cve\":\"$1\",\"name\":\"$esc_name\",\"aliases\":$(_json_str "$aliases"),\"cpu_affected\":$cpu_affected,\"status\":\"$3\",\"vulnerable\":$is_vuln,\"info\":\"$esc_infos\",\"sysfs_status\":$(_json_str "$sysfs_status"),\"sysfs_message\":$(_json_str "$sysfs_msg")},"
}

# Accumulate a CVE result into the NRPE output buffers
# Args: $1=cve $2=aka $3=status $4=description
# Sets: g_nrpe_total, g_nrpe_vuln_count, g_nrpe_unk_count, g_nrpe_vuln_ids, g_nrpe_vuln_details, g_nrpe_unk_details
# Callers: pvulnstatus
_emit_nrpe() {
    g_nrpe_total=$((g_nrpe_total + 1))
    case "$3" in
        VULN)
            g_nrpe_vuln_count=$((g_nrpe_vuln_count + 1))
            g_nrpe_vuln_ids="${g_nrpe_vuln_ids:+$g_nrpe_vuln_ids }$1"
            g_nrpe_vuln_details="${g_nrpe_vuln_details:+$g_nrpe_vuln_details\n}[CRITICAL] $1 ($2): $4"
            ;;
        UNK)
            g_nrpe_unk_count=$((g_nrpe_unk_count + 1))
            g_nrpe_unk_details="${g_nrpe_unk_details:+$g_nrpe_unk_details\n}[UNKNOWN]  $1 ($2): $4"
            ;;
    esac
}

# Append a CVE result as a Prometheus gauge to the batch output buffer
# Status is encoded numerically: 0=not_vulnerable, 1=vulnerable, 2=unknown
# Args: $1=cve $2=aka $3=status(UNK|VULN|OK) $4=description
# Sets: g_smc_vuln_output, g_smc_ok_count, g_smc_vuln_count, g_smc_unk_count
# Callers: pvulnstatus
_emit_prometheus() {
    local numeric_status cpu_affected full_name esc_name
    case "$3" in
        OK)   numeric_status=0 ; g_smc_ok_count=$((g_smc_ok_count + 1)) ;;
        VULN) numeric_status=1 ; g_smc_vuln_count=$((g_smc_vuln_count + 1)) ;;
        UNK)  numeric_status=2 ; g_smc_unk_count=$((g_smc_unk_count + 1)) ;;
        *)
            echo "$0: error: unknown status '$3' passed to _emit_prometheus()" >&2
            exit 255
            ;;
    esac
    if is_cpu_affected "$1" 2>/dev/null; then
        cpu_affected='true'
    else
        cpu_affected='false'
    fi
    # use the complete CVE name (field 4) rather than the short aka key (field 2)
    full_name=$(_cve_registry_field "$1" 4)
    esc_name=$(_prom_escape "$full_name")
    g_smc_vuln_output="${g_smc_vuln_output:+$g_smc_vuln_output\n}smc_vulnerability_status{cve=\"$1\",name=\"$esc_name\",cpu_affected=\"$cpu_affected\"} $numeric_status"
}

# Build the smc_system_info Prometheus metric line
# Sets: g_smc_system_info_line
# Callers: src/main.sh (after check_cpu / check_cpu_vulnerabilities)
# shellcheck disable=SC2034
_build_prometheus_system_info() {
    local kernel_release kernel_arch hypervisor_host sys_labels
    if [ "$opt_runtime" = 1 ]; then
        kernel_release=$(uname -r 2>/dev/null || true)
        kernel_arch=$(uname -m 2>/dev/null || true)
    else
        kernel_release=''
        kernel_arch=''
    fi
    case "${g_has_vmm:-}" in
        1) hypervisor_host='true' ;;
        0) hypervisor_host='false' ;;
        *) hypervisor_host='' ;;
    esac
    sys_labels=''
    [ -n "$kernel_release"  ] && sys_labels="${sys_labels:+$sys_labels,}kernel_release=\"$(_prom_escape "$kernel_release")\""
    [ -n "$kernel_arch"     ] && sys_labels="${sys_labels:+$sys_labels,}kernel_arch=\"$(_prom_escape "$kernel_arch")\""
    [ -n "$hypervisor_host" ] && sys_labels="${sys_labels:+$sys_labels,}hypervisor_host=\"$hypervisor_host\""
    [ -n "$sys_labels" ] && g_smc_system_info_line="smc_system_info{$sys_labels} 1"
}

# Build the smc_cpu_info Prometheus metric line
# Sets: g_smc_cpu_info_line
# Callers: src/main.sh (after check_cpu / check_cpu_vulnerabilities)
# shellcheck disable=SC2034
_build_prometheus_cpu_info() {
    local cpuid_hex ucode_hex ucode_latest_hex ucode_uptodate ucode_blacklisted codename smt_val cpu_labels
    if [ -n "${cpu_cpuid:-}" ]; then
        cpuid_hex=$(printf '0x%08x' "$cpu_cpuid")
    else
        cpuid_hex=''
    fi
    if [ -n "${cpu_ucode:-}" ]; then
        ucode_hex=$(printf '0x%x' "$cpu_ucode")
    else
        ucode_hex=''
    fi
    is_latest_known_ucode
    case $? in
        0) ucode_uptodate='true' ;;
        1) ucode_uptodate='false' ;;
        *) ucode_uptodate='' ;;
    esac
    ucode_latest_hex="${ret_is_latest_known_ucode_version:-}"
    if is_ucode_blacklisted; then
        ucode_blacklisted='true'
    else
        ucode_blacklisted='false'
    fi
    codename=''
    if is_intel; then
        codename=$(get_intel_codename 2>/dev/null || true)
    fi
    is_cpu_smt_enabled
    case $? in
        0) smt_val='true' ;;
        1) smt_val='false' ;;
        *) smt_val='' ;;
    esac
    cpu_labels=''
    [ -n "${cpu_vendor:-}"        ] && cpu_labels="${cpu_labels:+$cpu_labels,}vendor=\"$(_prom_escape "$cpu_vendor")\""
    [ -n "${cpu_friendly_name:-}" ] && cpu_labels="${cpu_labels:+$cpu_labels,}model=\"$(_prom_escape "$cpu_friendly_name")\""
    [ -n "${cpu_family:-}"        ] && cpu_labels="${cpu_labels:+$cpu_labels,}family=\"$cpu_family\""
    [ -n "${cpu_model:-}"         ] && cpu_labels="${cpu_labels:+$cpu_labels,}model_id=\"$cpu_model\""
    [ -n "${cpu_stepping:-}"      ] && cpu_labels="${cpu_labels:+$cpu_labels,}stepping=\"$cpu_stepping\""
    [ -n "$cpuid_hex"             ] && cpu_labels="${cpu_labels:+$cpu_labels,}cpuid=\"$cpuid_hex\""
    [ -n "$codename"              ] && cpu_labels="${cpu_labels:+$cpu_labels,}codename=\"$(_prom_escape "$codename")\""
    [ -n "$smt_val"               ] && cpu_labels="${cpu_labels:+$cpu_labels,}smt=\"$smt_val\""
    [ -n "$ucode_hex"             ] && cpu_labels="${cpu_labels:+$cpu_labels,}microcode=\"$ucode_hex\""
    [ -n "$ucode_latest_hex"      ] && cpu_labels="${cpu_labels:+$cpu_labels,}microcode_latest=\"$ucode_latest_hex\""
    [ -n "$ucode_uptodate"        ] && cpu_labels="${cpu_labels:+$cpu_labels,}microcode_up_to_date=\"$ucode_uptodate\""
    # always emit microcode_blacklisted when we have microcode info (it's a boolean, never omit)
    [ -n "$ucode_hex"             ] && cpu_labels="${cpu_labels:+$cpu_labels,}microcode_blacklisted=\"$ucode_blacklisted\""
    [ -n "$cpu_labels" ] && g_smc_cpu_info_line="smc_cpu_info{$cpu_labels} 1"
}

# Update global state used to determine the program exit code
# Args: $1=cve $2=status(UNK|VULN|OK)
# Sets: g_unknown, g_critical
# Callers: pvulnstatus
_record_result() {
    case "$2" in
        UNK) g_unknown="1" ;;
        VULN) g_critical="1" ;;
        OK) ;;
        *)
            echo "$0: error: unknown status '$2' passed to _record_result()" >&2
            exit 255
            ;;
    esac
}

# Print the final vulnerability status for a CVE and dispatch to batch emitters
# Args: $1=cve $2=status(UNK|OK|VULN) $3=description
# Sets: g_pvulnstatus_last_cve
pvulnstatus() {
    local aka vulnstatus
    g_pvulnstatus_last_cve="$1"
    if [ "$opt_batch" = 1 ]; then
        aka=$(_cve_registry_field "$1" 2)

        case "$opt_batch_format" in
            text) _emit_text "$1" "$aka" "$2" "$3" ;;
            short) _emit_short "$1" "$aka" "$2" "$3" ;;
            json) _emit_json_full "$1" "$aka" "$2" "$3" ;;
            json-terse) _emit_json_terse "$1" "$aka" "$2" "$3" ;;
            nrpe) _emit_nrpe "$1" "$aka" "$2" "$3" ;;
            prometheus) _emit_prometheus "$1" "$aka" "$2" "$3" ;;
            *)
                echo "$0: error: invalid batch format '$opt_batch_format' specified" >&2
                exit 255
                ;;
        esac
        # reset per-CVE sysfs globals so they don't leak into the next CVE
        g_json_cve_sysfs_status=''
        g_json_cve_sysfs_msg=''
    fi

    _record_result "$1" "$2"

    # display info if we're not in quiet/batch mode
    vulnstatus="$2"
    shift 2
    pr_info_nol "> \033[46m\033[30mSTATUS:\033[0m "
    : "${g_final_summary:=}"
    : "${g_final_summary_count:=0}"
    g_final_summary_count=$((g_final_summary_count + 1))
    # wrap to a new line every 4 entries for readability
    if [ "$g_final_summary_count" -gt 1 ] && [ $((g_final_summary_count % 4)) -eq 1 ]; then
        g_final_summary="$g_final_summary\n          "
    fi
    # pad entry to fixed width so columns align despite varying CVE ID lengths
    case "$vulnstatus" in
        UNK)
            pstatus yellow 'UNKNOWN' "$@"
            _summary_label=$(printf "%-17s" "$g_pvulnstatus_last_cve:??")
            g_final_summary="$g_final_summary \033[43m\033[30m$_summary_label\033[0m"
            ;;
        VULN)
            pstatus red 'VULNERABLE' "$@"
            _summary_label=$(printf "%-17s" "$g_pvulnstatus_last_cve:KO")
            g_final_summary="$g_final_summary \033[41m\033[30m$_summary_label\033[0m"
            ;;
        OK)
            pstatus green 'NOT VULNERABLE' "$@"
            _summary_label=$(printf "%-17s" "$g_pvulnstatus_last_cve:OK")
            g_final_summary="$g_final_summary \033[42m\033[30m$_summary_label\033[0m"
            ;;
        *)
            echo "$0: error: unknown status '$vulnstatus' passed to pvulnstatus()" >&2
            exit 255
            ;;
    esac
}
