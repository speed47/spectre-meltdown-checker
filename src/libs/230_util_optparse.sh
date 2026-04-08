# vim: set ts=4 sw=4 sts=4 et:
# Validate a command-line option that expects a readable file path
# Args: $1=option_name $2=option_value (file path)
parse_opt_file() {
    local option_name option_value
    option_name="$1"
    option_value="$2"
    if [ -z "$option_value" ]; then
        show_header
        show_usage
        echo "$0: error: --$option_name expects one parameter (a file)" >&2
        exit 1
    elif [ ! -e "$option_value" ]; then
        show_header
        echo "$0: error: couldn't find file $option_value" >&2
        exit 1
    elif [ ! -f "$option_value" ]; then
        show_header
        echo "$0: error: $option_value is not a file" >&2
        exit 1
    elif [ ! -r "$option_value" ]; then
        show_header
        echo "$0: error: couldn't read $option_value (are you root?)" >&2
        exit 1
    fi
    echo "$option_value"
    exit 0
}

while [ -n "${1:-}" ]; do
    if [ "$1" = "--kernel" ]; then
        opt_kernel=$(parse_opt_file kernel "$2")
        ret=$?
        [ $ret -ne 0 ] && exit 255
        shift 2
    elif [ "$1" = "--config" ]; then
        opt_config=$(parse_opt_file config "$2")
        ret=$?
        [ $ret -ne 0 ] && exit 255
        shift 2
    elif [ "$1" = "--map" ]; then
        opt_map=$(parse_opt_file map "$2")
        ret=$?
        [ $ret -ne 0 ] && exit 255
        shift 2
    elif [ "$1" = "--arch-prefix" ]; then
        opt_arch_prefix="$2"
        shift 2
    elif [ "$1" = "--live" ]; then
        # deprecated, kept for backward compatibility (live is now the default)
        shift
    elif [ "$1" = "--no-color" ]; then
        opt_no_color=1
        shift
    elif [ "$1" = "--no-sysfs" ]; then
        opt_no_sysfs=1
        shift
    elif [ "$1" = "--sysfs-only" ]; then
        opt_sysfs_only=1
        shift
    elif [ "$1" = "--coreos" ]; then
        opt_coreos=1
        shift
    elif [ "$1" = "--coreos-within-toolbox" ]; then
        # don't use directly: used internally by --coreos
        opt_coreos=0
        shift
    elif [ "$1" = "--paranoid" ]; then
        opt_paranoid=1
        shift
    elif [ "$1" = "--extra" ]; then
        opt_extra=1
        shift
    elif [ "$1" = "--hw-only" ]; then
        opt_hw_only=1
        shift
    elif [ "$1" = "--no-runtime" ]; then
        opt_runtime=0
        shift
    elif [ "$1" = "--no-hw" ]; then
        opt_no_hw=1
        opt_runtime=0
        shift
    elif [ "$1" = "--allow-msr-write" ]; then
        opt_allow_msr_write=1
        shift
    elif [ "$1" = "--no-intel-db" ]; then
        opt_intel_db=0
        shift
    elif [ "$1" = "--cpu" ]; then
        opt_cpu=$2
        if [ "$opt_cpu" != all ]; then
            if echo "$opt_cpu" | grep -Eq '^[0-9]+'; then
                opt_cpu=$((opt_cpu))
            else
                echo "$0: error: --cpu should be an integer or 'all', got '$opt_cpu'" >&2
                exit 255
            fi
        fi
        shift 2
    elif [ "$1" = "--no-explain" ]; then
        # deprecated, kept for compatibility
        opt_explain=0
        shift
    elif [ "$1" = "--update-fwdb" ] || [ "$1" = "--update-mcedb" ]; then
        update_fwdb
        exit $?
    elif [ "$1" = "--update-builtin-fwdb" ] || [ "$1" = "--update-builtin-mcedb" ]; then
        update_fwdb builtin
        exit $?
    elif [ "$1" = "--dump-mock-data" ]; then
        opt_mock=1
        shift
    elif [ "$1" = "--explain" ]; then
        opt_explain=1
        shift
    elif [ "$1" = "--batch" ]; then
        opt_batch=1
        opt_verbose=0
        opt_no_color=1
        shift
        case "$1" in
            text | short | nrpe | json | json-terse | prometheus)
                opt_batch_format="$1"
                shift
                ;;
            --*) ;; # allow subsequent flags
            '') ;;  # allow nothing at all
            *)
                echo "$0: error: unknown batch format '$1'" >&2
                echo "$0: error: --batch expects a format from: text, short, nrpe, json, json-terse, prometheus" >&2
                exit 255
                ;;
        esac
    elif [ "$1" = "-v" ] || [ "$1" = "--verbose" ]; then
        opt_verbose=$((opt_verbose + 1))
        [ "$opt_verbose" -ge 2 ] && opt_mock=1
        shift
    elif [ "$1" = "--cve" ]; then
        if [ -z "$2" ]; then
            echo "$0: error: option --cve expects a parameter, supported CVEs are: $g_supported_cve_list" >&2
            exit 255
        fi
        selected_cve=$(echo "$g_supported_cve_list" | grep -iwo "$2")
        if [ -n "$selected_cve" ]; then
            opt_cve_list="$opt_cve_list $selected_cve"
            opt_cve_all=0
        else
            echo "$0: error: unsupported CVE specified ('$2'), supported CVEs are: $g_supported_cve_list" >&2
            exit 255
        fi
        shift 2
    elif [ "$1" = "--vmm" ]; then
        if [ -z "$2" ]; then
            echo "$0: error: option --vmm (auto, yes, no)" >&2
            exit 255
        fi
        case "$2" in
            auto) opt_vmm=-1 ;;
            yes) opt_vmm=1 ;;
            no) opt_vmm=0 ;;
            *)
                echo "$0: error: expected one of (auto, yes, no) to option --vmm instead of '$2'" >&2
                exit 255
                ;;
        esac
        shift 2
    elif [ "$1" = "--variant" ]; then
        if [ -z "$2" ]; then
            echo "$0: error: option --variant expects a parameter (see --variant help)" >&2
            exit 255
        fi
        case "$2" in
            help)
                echo "The following parameters are supported for --variant (can be used multiple times):"
                echo "1, 2, 3, 3a, 4, msbds, mfbds, mlpds, mdsum, l1tf, taa, mcepsc, srbds, mmio, sbdr, sbds, drpw, div0, zenbleed, downfall, retbleed, inception, reptar, rfds, tsa, tsa-sq, tsa-l1, its, vmscape, bpi, sls"
                exit 0
                ;;
            1)
                opt_cve_list="$opt_cve_list CVE-2017-5753"
                opt_cve_all=0
                ;;
            2)
                opt_cve_list="$opt_cve_list CVE-2017-5715"
                opt_cve_all=0
                ;;
            3)
                opt_cve_list="$opt_cve_list CVE-2017-5754"
                opt_cve_all=0
                ;;
            3a)
                opt_cve_list="$opt_cve_list CVE-2018-3640"
                opt_cve_all=0
                ;;
            4)
                opt_cve_list="$opt_cve_list CVE-2018-3639"
                opt_cve_all=0
                ;;
            msbds)
                opt_cve_list="$opt_cve_list CVE-2018-12126"
                opt_cve_all=0
                ;;
            mfbds)
                opt_cve_list="$opt_cve_list CVE-2018-12130"
                opt_cve_all=0
                ;;
            mlpds)
                opt_cve_list="$opt_cve_list CVE-2018-12127"
                opt_cve_all=0
                ;;
            mdsum)
                opt_cve_list="$opt_cve_list CVE-2019-11091"
                opt_cve_all=0
                ;;
            l1tf)
                opt_cve_list="$opt_cve_list CVE-2018-3615 CVE-2018-3620 CVE-2018-3646"
                opt_cve_all=0
                ;;
            taa)
                opt_cve_list="$opt_cve_list CVE-2019-11135"
                opt_cve_all=0
                ;;
            mcepsc)
                opt_cve_list="$opt_cve_list CVE-2018-12207"
                opt_cve_all=0
                ;;
            srbds)
                opt_cve_list="$opt_cve_list CVE-2020-0543"
                opt_cve_all=0
                ;;
            mmio)
                opt_cve_list="$opt_cve_list CVE-2022-21123 CVE-2022-21125 CVE-2022-21166"
                opt_cve_all=0
                ;;
            sbdr)
                opt_cve_list="$opt_cve_list CVE-2022-21123"
                opt_cve_all=0
                ;;
            sbds)
                opt_cve_list="$opt_cve_list CVE-2022-21125"
                opt_cve_all=0
                ;;
            drpw)
                opt_cve_list="$opt_cve_list CVE-2022-21166"
                opt_cve_all=0
                ;;
            div0)
                opt_cve_list="$opt_cve_list CVE-2023-20588"
                opt_cve_all=0
                ;;
            zenbleed)
                opt_cve_list="$opt_cve_list CVE-2023-20593"
                opt_cve_all=0
                ;;
            downfall)
                opt_cve_list="$opt_cve_list CVE-2022-40982"
                opt_cve_all=0
                ;;
            retbleed)
                opt_cve_list="$opt_cve_list CVE-2022-29900 CVE-2022-29901"
                opt_cve_all=0
                ;;
            inception)
                opt_cve_list="$opt_cve_list CVE-2023-20569"
                opt_cve_all=0
                ;;
            reptar)
                opt_cve_list="$opt_cve_list CVE-2023-23583"
                opt_cve_all=0
                ;;
            rfds)
                opt_cve_list="$opt_cve_list CVE-2023-28746"
                opt_cve_all=0
                ;;
            tsa)
                opt_cve_list="$opt_cve_list CVE-2024-36350 CVE-2024-36357"
                opt_cve_all=0
                ;;
            tsa-sq)
                opt_cve_list="$opt_cve_list CVE-2024-36350"
                opt_cve_all=0
                ;;
            tsa-l1)
                opt_cve_list="$opt_cve_list CVE-2024-36357"
                opt_cve_all=0
                ;;
            its)
                opt_cve_list="$opt_cve_list CVE-2024-28956"
                opt_cve_all=0
                ;;
            vmscape)
                opt_cve_list="$opt_cve_list CVE-2025-40300"
                opt_cve_all=0
                ;;
            bpi)
                opt_cve_list="$opt_cve_list CVE-2024-45332"
                opt_cve_all=0
                ;;
            sls)
                opt_cve_list="$opt_cve_list CVE-0000-0001"
                opt_cve_all=0
                ;;
            *)
                echo "$0: error: invalid parameter '$2' for --variant, see --variant help for a list" >&2
                exit 255
                ;;
        esac
        shift 2
    elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
        show_header
        show_usage
        exit 0
    elif [ "$1" = "--version" ]; then
        opt_no_color=1
        show_header
        exit 0
    elif [ "$1" = "--disclaimer" ]; then
        show_header
        show_disclaimer
        exit 0
    else
        show_header
        show_usage
        echo "$0: error: unknown option '$1'"
        exit 255
    fi
done

show_header

if [ "$opt_no_sysfs" = 1 ] && [ "$opt_sysfs_only" = 1 ]; then
    pr_warn "Incompatible options specified (--no-sysfs and --sysfs-only), aborting"
    exit 255
fi

if [ "$opt_no_hw" = 1 ] && [ "$opt_hw_only" = 1 ]; then
    pr_warn "Incompatible options specified (--no-hw and --hw-only), aborting"
    exit 255
fi

if [ "$opt_runtime" = 0 ] && [ "$opt_sysfs_only" = 1 ]; then
    pr_warn "Incompatible options specified (--no-runtime and --sysfs-only), aborting"
    exit 255
fi

if [ "$opt_runtime" = 0 ] && [ -z "$opt_kernel" ] && [ -z "$opt_config" ] && [ -z "$opt_map" ]; then
    pr_warn "Option --no-runtime requires at least one of --kernel, --config, or --map"
    exit 255
fi

