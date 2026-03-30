#!/bin/sh
# vim: set ts=4 sw=4 sts=4 et:
# Assemble spectre-meltdown-checker.sh from src/ fragments.
# Usage: ./build.sh [output_file]
#   default output: spectre-meltdown-checker.sh
set -e

SRCDIR="$(dirname "$0")/src"
OUTPUT="${1:-$(dirname "$0")/spectre-meltdown-checker.sh}"

SECTIONS="
libs/*.sh
vulns-helpers/*.sh
vulns/*.sh
main.sh
db/*.sh
"

first=1
for pattern in $SECTIONS; do
    # shellcheck disable=SC2086
    for file in "$SRCDIR"/$pattern; do
        [ -f "$file" ] || continue
        # source file marker
        relpath="${file#"$SRCDIR"/}"
        if [ "$first" = 1 ]; then
            # first file (001_core_header.sh): emit verbatim, keeps shebang
            cat "$file"
            first=0
        else
            # separator blank line + source marker between fragments
            echo ""
            echo "# >>>>>> $relpath <<<<<<"
            echo ""
            # strip accidental shebang on line 1
            {
                IFS= read -r line
                case "$line" in
                    '#!'*) ;; # skip shebang
                    *) printf '%s\n' "$line" ;;
                esac
                cat
            } <"$file"
        fi
    done
done >"$OUTPUT"

chmod +x "$OUTPUT"
echo "Assembled $OUTPUT ($(wc -l <"$OUTPUT") lines)"
