# vim: set ts=4 sw=4 sts=4 et:
# Print a colored status badge followed by an optional supplement
# Args: $1=color(red|green|yellow|blue) $2=message $3=supplement(optional)
pstatus() {
    local col
    if [ "$opt_no_color" = 1 ]; then
        pr_info_nol "$2"
    else
        case "$1" in
            red) col="\033[41m\033[30m" ;;
            green) col="\033[42m\033[30m" ;;
            yellow) col="\033[43m\033[30m" ;;
            blue) col="\033[44m\033[30m" ;;
            *) col="" ;;
        esac
        pr_info_nol "$col $2 \033[0m"
    fi
    [ -n "${3:-}" ] && pr_info_nol " ($3)"
    pr_info
    unset col
}
