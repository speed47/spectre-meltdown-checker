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

# Patch VERSION= with semantic version: X.Y.Z
# X=YY, Y=number of CVE files in src/vulns/, Z=MMDDVAL
# VAL is a 3-digit (000-999) value derived from seconds since midnight UTC
cve_count=$(find "$SRCDIR/vulns" -maxdepth 1 -name '*.sh' -type f | wc -l | tr -d ' ')
epoch=$(date -u +%s)
secs_since_midnight=$((epoch % 86400))
val=$(printf '%03d' $((secs_since_midnight * 1000 / 86400)))
version="$(date -u +%y).${cve_count}.$(date -u +%m%d)${val}"
sed -i "s/^VERSION=.*/VERSION='${version}'/" "$OUTPUT"

echo "Assembled $OUTPUT ($(wc -l <"$OUTPUT") lines, version $version)"
