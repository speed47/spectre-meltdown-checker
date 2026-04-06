# vim: set ts=4 sw=4 sts=4 et:
# The 3 below functions are taken from the extract-linux script, available here:
# https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux
# The functions have been modified for better integration to this script
# The original header of the file has been retained below

# ----------------------------------------------------------------------
# extract-vmlinux - Extract uncompressed vmlinux from a kernel image
#
# Inspired from extract-ikconfig
# (c) 2009,2010 Dick Streefland <dick@streefland.net>
#
# (c) 2011      Corentin Chary <corentin.chary@gmail.com>
#
# Licensed under the GNU General Public License, version 2 (GPLv2).
# ----------------------------------------------------------------------

g_kernel=''
g_kernel_err=''
# Validate whether a file looks like a valid uncompressed Linux kernel image
# Args: $1=file_path
# Sets: g_kernel, g_kernel_err
check_kernel() {
    local ret file mode readelf_warnings readelf_sections kernel_size
    file="$1"
    mode="${2:-normal}"
    # checking the return code of readelf -h is not enough, we could get
    # a damaged ELF file and validate it, check for stderr warnings too

    # the warning "readelf: Warning: [16]: Link field (0) should index a symtab section./" can appear on valid kernels, ignore it
    readelf_warnings=$("${opt_arch_prefix}readelf" -S "$file" 2>&1 >/dev/null | grep -v 'should index a symtab section' | tr "\n" "/")
    ret=$?
    readelf_sections=$("${opt_arch_prefix}readelf" -S "$file" 2>/dev/null | grep -c -e data -e text -e init)
    kernel_size=$(stat -c %s "$file" 2>/dev/null || stat -f %z "$file" 2>/dev/null || echo 10000)
    pr_debug "check_kernel: ret=$? size=$kernel_size sections=$readelf_sections warnings=$readelf_warnings"
    if [ "$mode" = desperate ]; then
        if "${opt_arch_prefix}strings" "$file" | grep -Eq '^Linux version '; then
            pr_debug "check_kernel (desperate): ... matched!"
            if [ "$readelf_sections" = 0 ] && grep -qF -e armv6 -e armv7 "$file"; then
                pr_debug "check_kernel (desperate): raw arm binary found, adjusting objdump options"
                g_objdump_options="-D -b binary -marm"
            else
                g_objdump_options="-d"
            fi
            return 0
        else
            pr_debug "check_kernel (desperate): ... invalid"
        fi
    else
        if [ $ret -eq 0 ] && [ -z "$readelf_warnings" ] && [ "$readelf_sections" -gt 0 ]; then
            if [ "$kernel_size" -ge 100000 ]; then
                pr_debug "check_kernel: ... file is valid"
                g_objdump_options="-d"
                return 0
            else
                pr_debug "check_kernel: ... file seems valid but is too small, ignoring"
            fi
        else
            pr_debug "check_kernel: ... file is invalid"
        fi
    fi
    return 1
}

# Attempt to find and decompress a kernel image using a given compression format
# Args: $1=magic_search $2=magic_match $3=format_name $4=decompress_cmd $5=decompress_args $6=input_file $7=output_file
try_decompress() {
    local pos ret
    # The obscure use of the "tr" filter is to work around older versions of
    # "grep" that report the byte offset of the line instead of the pattern.

    # Try to find the header ($1) and decompress from here
    pr_debug "try_decompress: looking for $3 magic in $6"
    for pos in $(tr "$1\n$2" "\n$2=" <"$6" | grep -abo "^$2"); do
        pr_debug "try_decompress: magic for $3 found at offset $pos"
        if ! command -v "$3" >/dev/null 2>&1; then
            if [ "$8" = 1 ]; then
                # pass1: if the tool is not installed, just bail out silently
                # and hope that the next decompression tool will be, and that
                # it'll happen to be the proper one for this kernel
                pr_debug "try_decompress: the '$3' tool is not installed (pass 1), try the next algo"
            else
                # pass2: if the tool is not installed, populate g_kernel_err this time
                g_kernel_err="missing '$3' tool, please install it, usually it's in the '$5' package"
                pr_debug "try_decompress: $g_kernel_err"
            fi
            return 1
        fi
        pos=${pos%%:*}
        # shellcheck disable=SC2086
        # wrap in subshell so that if $3 segfaults (e.g. old BusyBox unlzma on random data),
        # the "Segmentation fault" message printed by the shell goes to /dev/null
        (tail -c+$pos "$6" 2>/dev/null | $3 $4 >"$g_kerneltmp" 2>/dev/null) 2>/dev/null
        ret=$?
        if [ ! -s "$g_kerneltmp" ]; then
            # don't rely on $ret, sometimes it's != 0 but worked
            # (e.g. gunzip ret=2 just means there was trailing garbage)
            pr_debug "try_decompress: decompression with $3 failed (err=$ret)"
        elif check_kernel "$g_kerneltmp" "$7"; then
            g_kernel="$g_kerneltmp"
            pr_debug "try_decompress: decompressed with $3 successfully!"
            return 0
        elif [ "$3" != "cat" ]; then
            pr_debug "try_decompress: decompression with $3 worked but result is not a kernel, trying with an offset"
            [ -z "$g_kerneltmp2" ] && g_kerneltmp2=$(mktemp -t smc-kernel-XXXXXX)
            cat "$g_kerneltmp" >"$g_kerneltmp2"
            try_decompress '\177ELF' xxy 'cat' '' cat "$g_kerneltmp2" && return 0
        else
            pr_debug "try_decompress: decompression with $3 worked but result is not a kernel"
        fi
    done
    return 1
}

# Extract an uncompressed vmlinux from a possibly compressed kernel image
# Args: $1=kernel_image_path
# Sets: g_kerneltmp
extract_kernel() {
    local pass mode
    [ -n "${1:-}" ] || return 1
    # Prepare temp files:
    g_kerneltmp="$(mktemp -t smc-kernel-XXXXXX)"

    # Initial attempt for uncompressed images or objects:
    if check_kernel "$1"; then
        pr_debug "extract_kernel: found kernel is valid, no decompression needed"
        cat "$1" >"$g_kerneltmp"
        g_kernel=$g_kerneltmp
        return 0
    fi

    # That didn't work, so retry after decompression.
    for pass in 1 2; do
        for mode in normal desperate; do
            pr_debug "extract_kernel: pass $pass $mode mode"
            try_decompress '\037\213\010' xy gunzip '' gunzip "$1" "$mode" "$pass" && return 0
            try_decompress '\002\041\114\030' xyy 'lz4' '-d -l' liblz4-tool "$1" "$mode" "$pass" && return 0
            try_decompress '\3757zXZ\000' abcde unxz '' xz-utils "$1" "$mode" "$pass" && return 0
            try_decompress 'BZh' xy bunzip2 '' bzip2 "$1" "$mode" "$pass" && return 0
            try_decompress '\135\0\0\0' xxx unlzma '' xz-utils "$1" "$mode" "$pass" && return 0
            try_decompress '\211\114\132' xy 'lzop' '-d' lzop "$1" "$mode" "$pass" && return 0
            try_decompress '\177ELF' xxy 'cat' '' cat "$1" "$mode" "$pass" && return 0
            try_decompress '(\265/\375' xxy unzstd '' zstd "$1" "$mode" "$pass" && return 0
        done
    done
    # g_kernel_err might already have been populated by try_decompress() if we're missing one of the tools
    if [ -z "$g_kernel_err" ]; then
        g_kernel_err="kernel compression format is unknown or image is invalid"
    fi
    pr_verbose "Couldn't extract the kernel image ($g_kernel_err), accuracy might be reduced"
    return 1
}

# end of extract-vmlinux functions
