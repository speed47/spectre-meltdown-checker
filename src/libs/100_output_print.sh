# vim: set ts=4 sw=4 sts=4 et:
# Low-level echo wrapper handling color stripping and printf/echo portability
# Args: $1=opt(-n for no newline, '' for normal) $2...=message
# Callers: _pr_echo, _pr_echo_nol
_pr_echo_raw() {
    local opt msg interpret_chars ctrlchar
    opt="$1"
    shift
    msg="$*"

    if [ "$opt_no_color" = 1 ]; then
        # strip ANSI color codes
        # some sed versions (i.e. toybox) can't seem to handle
        # \033 aka \x1B correctly, so do it for them.
        if [ "$g_echo_cmd_type" = printf ]; then
            interpret_chars=''
        else
            interpret_chars='-e'
        fi
        ctrlchar=$($g_echo_cmd $interpret_chars "\033")
        msg=$($g_echo_cmd $interpret_chars "$msg" | sed -E "s/$ctrlchar\[([0-9][0-9]?(;[0-9][0-9]?)?)?m//g")
    fi
    if [ "$g_echo_cmd_type" = printf ]; then
        if [ "$opt" = "-n" ]; then
            $g_echo_cmd "$msg"
        else
            $g_echo_cmd "$msg\n"
        fi
    else
        # shellcheck disable=SC2086
        $g_echo_cmd $opt -e "$msg"
    fi
}

# Print a message if the current verbosity level is high enough
# Args: $1=minimum_verbosity_level $2...=message
# Callers: pr_warn, pr_info, pr_verbose, pr_debug, _emit_text, toplevel batch output
_pr_echo() {
    if [ "$opt_verbose" -ge "$1" ]; then
        shift
        _pr_echo_raw '' "$*"
    fi
}

# Print a message without trailing newline if the current verbosity level is high enough
# Args: $1=minimum_verbosity_level $2...=message
# Callers: pr_info_nol, pr_verbose_nol
_pr_echo_nol() {
    if [ "$opt_verbose" -ge "$1" ]; then
        shift
        _pr_echo_raw -n "$*"
    fi
}

# Print a warning message in red to stderr (verbosity 0, always shown)
# Args: $1...=message
pr_warn() {
    _pr_echo 0 "\033[31m$*\033[0m" >&2
}

# Print an informational message (verbosity >= 1)
# Args: $1...=message
pr_info() {
    _pr_echo 1 "$*"
}

# Print an informational message without trailing newline (verbosity >= 1)
# Args: $1...=message
pr_info_nol() {
    _pr_echo_nol 1 "$*"
}

# Print a verbose message (verbosity >= 2)
# Args: $1...=message
pr_verbose() {
    _pr_echo 2 "$*"
}

# Print a verbose message without trailing newline (verbosity >= 2)
# Args: $1...=message
pr_verbose_nol() {
    _pr_echo_nol 2 "$*"
}

# Print a debug message in blue (verbosity >= 3)
# Args: $1...=message
pr_debug() {
    _pr_echo 3 "\033[34m(debug) $*\033[0m"
}

# Print a "How to fix" explanation when --explain is enabled
# Args: $1...=fix description
explain() {
    if [ "$opt_explain" = 1 ]; then
        pr_info ''
        pr_info "> \033[41m\033[30mHow to fix:\033[0m $*"
    fi
}

# Convert a CVE ID to its human-readable vulnerability name
# Args: $1=cve_id (e.g. "CVE-2017-5753")
cve2name() {
    _cve_registry_field "$1" 4
}

g_is_cpu_affected_cached=0
