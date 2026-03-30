# vim: set ts=4 sw=4 sts=4 et:
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

# Append a CVE result as a JSON object to the batch output buffer
# Args: $1=cve $2=aka $3=status(UNK|VULN|OK) $4=description
# Sets: g_json_output
# Callers: pvulnstatus
_emit_json() {
    local is_vuln esc_name esc_infos
    case "$3" in
        UNK) is_vuln="null" ;;
        VULN) is_vuln="true" ;;
        OK) is_vuln="false" ;;
        *)
            echo "$0: error: unknown status '$3' passed to _emit_json()" >&2
            exit 255
            ;;
    esac
    # escape backslashes and double quotes for valid JSON strings
    esc_name=$(printf '%s' "$2" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
    esc_infos=$(printf '%s' "$4" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
    [ -z "$g_json_output" ] && g_json_output='['
    g_json_output="${g_json_output}{\"NAME\":\"$esc_name\",\"CVE\":\"$1\",\"VULNERABLE\":$is_vuln,\"INFOS\":\"$esc_infos\"},"
}

# Append vulnerable CVE IDs to the NRPE output buffer
# Args: $1=cve $2=aka $3=status $4=description
# Sets: g_nrpe_vuln
# Callers: pvulnstatus
_emit_nrpe() {
    [ "$3" = VULN ] && g_nrpe_vuln="$g_nrpe_vuln $1"
}

# Append a CVE result as a Prometheus metric to the batch output buffer
# Args: $1=cve $2=aka $3=status $4=description
# Sets: g_prometheus_output
# Callers: pvulnstatus
_emit_prometheus() {
    local esc_info
    # escape backslashes and double quotes for Prometheus label values
    esc_info=$(printf '%s' "$4" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
    g_prometheus_output="${g_prometheus_output:+$g_prometheus_output\n}specex_vuln_status{name=\"$2\",cve=\"$1\",status=\"$3\",info=\"$esc_info\"} 1"
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
            json) _emit_json "$1" "$aka" "$2" "$3" ;;
            nrpe) _emit_nrpe "$1" "$aka" "$2" "$3" ;;
            prometheus) _emit_prometheus "$1" "$aka" "$2" "$3" ;;
            *)
                echo "$0: error: invalid batch format '$opt_batch_format' specified" >&2
                exit 255
                ;;
        esac
    fi

    _record_result "$1" "$2"

    # display info if we're not in quiet/batch mode
    vulnstatus="$2"
    shift 2
    pr_info_nol "> \033[46m\033[30mSTATUS:\033[0m "
    : "${g_final_summary:=}"
    case "$vulnstatus" in
        UNK)
            pstatus yellow 'UNKNOWN' "$@"
            g_final_summary="$g_final_summary \033[43m\033[30m$g_pvulnstatus_last_cve:??\033[0m"
            ;;
        VULN)
            pstatus red 'VULNERABLE' "$@"
            g_final_summary="$g_final_summary \033[41m\033[30m$g_pvulnstatus_last_cve:KO\033[0m"
            ;;
        OK)
            pstatus green 'NOT VULNERABLE' "$@"
            g_final_summary="$g_final_summary \033[42m\033[30m$g_pvulnstatus_last_cve:OK\033[0m"
            ;;
        *)
            echo "$0: error: unknown status '$vulnstatus' passed to pvulnstatus()" >&2
            exit 255
            ;;
    esac
}
