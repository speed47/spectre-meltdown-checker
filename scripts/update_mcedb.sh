#!/bin/sh
# vim: set ts=4 sw=4 sts=4 et:
# Regenerate src/db/200_mcedb.sh, the builtin microcode firmware database.
#
# This is a standalone port of the --update-builtin-fwdb logic from
# spectre-meltdown-checker.sh. It builds the database from three sources:
#   1. platomav's MCExtractor MCE.db (Intel + AMD microcode versions)
#   2. Intel's official Linux Processor Microcode Data Files (takes precedence)
#   3. linux-firmware's amd-ucode README (AMD patch levels)
#
# The header of src/db/200_mcedb.sh (everything before the "# %%% MCEDB" line)
# is preserved as-is; only the version line and the data lines are regenerated.
#
# Requires: sqlite3, unzip, md5sum, and wget or curl.
# Intel firmwares are listed with iucode-tool when available; otherwise a pure-shell
# parser (needing only `od`) is used, so the script also works on arm64 where
# iucode-tool has no package.
#
# Usage: scripts/update_mcedb.sh

set -eu

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
REPODIR="$(dirname "$SCRIPTDIR")"
OUTFILE="$REPODIR/src/db/200_mcedb.sh"

MCEDB_URL='https://github.com/platomav/MCExtractor/raw/master/MCE.db'
INTEL_URL='https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/archive/main.zip'
LINUXFW_URL='https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/amd-ucode/README'

# --- sanity checks ----------------------------------------------------------

[ -r "$OUTFILE" ] || { echo "ERROR: cannot read $OUTFILE" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "ERROR: please install the \`$1\` program" >&2; exit 1; }
}
need sqlite3
need unzip
need md5sum

# iucode-tool is preferred for listing Intel microcodes, but it has no arm64
# package, so we fall back to a pure-shell parser (parse_intel_shell) when it's
# absent. The shell parser needs `od`, which is part of coreutils everywhere.
if command -v iucode_tool >/dev/null 2>&1; then
    iucode_tool=iucode_tool
elif command -v iucode-tool >/dev/null 2>&1; then
    iucode_tool=iucode-tool
else
    iucode_tool=
    need od
fi

# download_file URL DEST
download_file() {
    if command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    elif command -v curl >/dev/null 2>&1; then
        curl -sL -o "$2" "$1"
    else
        echo "ERROR: please install either \`wget\` or \`curl\`" >&2
        exit 1
    fi
}

# fms2cpuid FAMILY MODEL STEPPING  -- replicates the helper from the main script
fms2cpuid() {
    family="$1"
    model="$2"
    stepping="$3"
    if [ "$((family))" -le 15 ]; then
        extfamily=0
        lowfamily=$((family))
    else
        lowfamily=15
        extfamily=$(((family) - 15))
    fi
    extmodel=$(((model & 0xF0) >> 4))
    lowmodel=$(((model & 0x0F) >> 0))
    echo $(((stepping & 0x0F) | (lowmodel << 4) | (lowfamily << 8) | (extmodel << 16) | (extfamily << 20)))
}

# Emit a normalized "CPUID PFMASK VERSION YYYYMMDD" line (all hex except date).
# Args: $1=sig $2=pf $3=rev (all hex, no 0x) $4=date as stored (0xMMDDYYYY hex)
emit_intel() {
    _mm=${4%????}; _yyyy=${4#????}     # date is MMDDYYYY -> reorder to YYYYMMDD
    printf '%08X %02X %08X %s\n' "$((0x$1))" "$((0x$2))" "$((0x$3))" "${_yyyy}${_mm}"
}

# Pure-shell equivalent of `iucode-tool -l`: walk every microcode in a directory
# and print one normalized line per (signature, processor-flags) pair, including
# those that exist only via a microcode's extended signature table.
# The Intel microcode header is 48 bytes of little-endian uint32 fields:
#   off 0 hdrver, 4 rev, 8 date, 12 sig, 24 pf, 28 datasize, 32 totalsize.
# An extended signature table (if totalsize > 48+datasize) sits at 48+datasize:
#   a 20-byte sub-header (count at off 0) then 12 bytes per entry (sig, pf, cksum).
parse_intel_shell() {
    for _f in "$1"/*; do
        [ -f "$_f" ] || continue
        _fsize=$(wc -c <"$_f")
        _base=0
        while [ "$_base" -lt "$_fsize" ] && [ $((_base + 48)) -le "$_fsize" ]; do
            # shellcheck disable=SC2046  # intentional word-splitting of the 12 header words
            set -- $(od -An -tx4 -j "$_base" -N48 "$_f" | tr '\n' ' ')
            [ "$1" = "00000001" ] || break        # not a microcode header, stop
            _rev=$2; _date=$3; _sig=$4; _pf=$7
            _datasize=$((0x$8));  [ "$_datasize" = 0 ] && _datasize=2000
            _totalsize=$((0x$9)); [ "$_totalsize" = 0 ] && _totalsize=2048
            emit_intel "$_sig" "$_pf" "$_rev" "$_date"
            # extended signature table, if any
            _extbase=$((_base + 48 + _datasize))
            if [ "$_totalsize" -gt $((48 + _datasize)) ]; then
                _count=$((0x$(od -An -tx4 -j "$_extbase" -N4 "$_f" | tr -d ' \n')))
                _i=0
                while [ "$_i" -lt "$_count" ]; do
                    _eoff=$((_extbase + 20 + _i * 12))
                    _esig=$(od -An -tx4 -j "$_eoff"        -N4 "$_f" | tr -d ' \n')
                    _epf=$( od -An -tx4 -j $((_eoff + 4))  -N4 "$_f" | tr -d ' \n')
                    emit_intel "$_esig" "$_epf" "$_rev" "$_date"
                    _i=$((_i + 1))
                done
            fi
            _base=$((_base + _totalsize))
        done
    done
}

# List Intel microcodes as normalized "CPUID PFMASK VERSION YYYYMMDD" lines,
# using iucode-tool when available, else the pure-shell parser.
intel_listing() {
    if [ -n "$iucode_tool" ]; then
        #  079/001: sig 0x000106c2, pf_mask 0x01, 2009-04-10, rev 0x0217, size 5120
        "$iucode_tool" -l "$1" | grep -wF sig | while read -r line; do
            _sig=$(echo "$line" | grep -Eio 'sig 0x[0-9a-f]+' | awk '{print $2}')
            _pf=$(echo "$line" | grep -Eio 'pf_mask 0x[0-9a-f]+' | awk '{print $2}')
            _rev=$(echo "$line" | grep -Eio 'rev 0x[0-9a-f]+' | awk '{print $2}')
            _date=$(echo "$line" | grep -Eo '(19|20)[0-9][0-9]-[01][0-9]-[0-3][0-9]' | tr -d '-')
            printf '%08X %02X %08X %s\n' "$((_sig))" "$((_pf))" "$((_rev))" "$_date"
        done
    else
        parse_intel_shell "$1"
    fi
}

# --- temp files -------------------------------------------------------------

MCEDB_TMP=$(mktemp -t smc-mcedb-XXXXXX)
INTEL_TMP=$(mktemp -d -t smc-intelfw-XXXXXX)
LINUXFW_TMP=$(mktemp -t smc-linuxfw-XXXXXX)
DATA_TMP=$(mktemp -t smc-mcedata-XXXXXX)
trap 'rm -rf "$MCEDB_TMP" "$INTEL_TMP" "$LINUXFW_TMP" "$DATA_TMP"' EXIT INT TERM

# --- 1. fetch MCExtractor's MCE.db ------------------------------------------

printf 'Fetching MCE.db from the MCExtractor project... '
download_file "$MCEDB_URL" "$MCEDB_TMP"
mcedb_revision=$(sqlite3 "$MCEDB_TMP" 'SELECT "revision" from "MCE"')
[ -n "$mcedb_revision" ] || { echo "ERROR: downloaded file seems invalid" >&2; exit 1; }

# add origin/pfmask columns; everything from MCE.db is tagged 'mce' with a wildcard pfmask
sqlite3 "$MCEDB_TMP" 'ALTER TABLE "Intel" ADD COLUMN "origin" TEXT'
sqlite3 "$MCEDB_TMP" 'ALTER TABLE "Intel" ADD COLUMN "pfmask" TEXT'
sqlite3 "$MCEDB_TMP" 'ALTER TABLE "AMD" ADD COLUMN "origin" TEXT'
sqlite3 "$MCEDB_TMP" 'ALTER TABLE "AMD" ADD COLUMN "pfmask" TEXT'
sqlite3 "$MCEDB_TMP" "UPDATE \"Intel\" SET \"origin\"='mce'"
sqlite3 "$MCEDB_TMP" "UPDATE \"Intel\" SET \"pfmask\"='FF'"
sqlite3 "$MCEDB_TMP" "UPDATE \"AMD\" SET \"origin\"='mce'"
sqlite3 "$MCEDB_TMP" "UPDATE \"AMD\" SET \"pfmask\"='FF'"
echo "OK (MCExtractor database revision $mcedb_revision)"

# --- 2. integrate Intel's official firmwares (these take precedence) --------

printf 'Fetching Intel firmwares... '
download_file "$INTEL_URL" "$INTEL_TMP/fw.zip"
(cd "$INTEL_TMP" && unzip -q fw.zip)
INTEL_UCODE_DIR="$INTEL_TMP/Intel-Linux-Processor-Microcode-Data-Files-main"
[ -d "$INTEL_UCODE_DIR/intel-ucode" ] || { echo "ERROR: expected the 'intel-ucode' folder in the downloaded zip file" >&2; exit 1; }
echo OK

if [ -n "$iucode_tool" ]; then
    printf 'Integrating Intel firmwares data to db (via %s)... ' "$iucode_tool"
else
    printf 'Integrating Intel firmwares data to db (via shell parser)... '
fi
intel_listing "$INTEL_UCODE_DIR/intel-ucode" | while read -r cpuid pfmask version date; do
    # ensure the official Intel DB always has precedence over mcedb, even if mcedb has seen a more recent fw
    sqlite3 "$MCEDB_TMP" "DELETE FROM \"Intel\" WHERE \"origin\" != 'intel' AND \"cpuid\" = '$cpuid';"
    sqlite3 "$MCEDB_TMP" "INSERT INTO \"Intel\" (\"origin\",\"cpuid\",\"pfmask\",\"version\",\"yyyymmdd\") VALUES ('intel','$cpuid','$pfmask','$version','$date');"
done

# the license file's mtime matches the upstream last commit date
intel_timestamp=$(stat -c %Y "$INTEL_UCODE_DIR/license" 2>/dev/null || stat -f %m "$INTEL_UCODE_DIR/license" 2>/dev/null || true)
if [ -n "$intel_timestamp" ]; then
    intel_latest_date=$(date -d @"$intel_timestamp" +%Y%m%d 2>/dev/null || date -r "$intel_timestamp" +%Y%m%d)
else
    echo "Falling back to the latest microcode date"
    intel_latest_date=$(sqlite3 "$MCEDB_TMP" "SELECT \"yyyymmdd\" FROM \"Intel\" WHERE \"origin\"='intel' ORDER BY \"yyyymmdd\" DESC LIMIT 1;")
fi
echo "DONE (version $intel_latest_date)"

# --- 3. integrate AMD patch levels from linux-firmware ----------------------

printf 'Fetching latest amd-ucode README from linux-firmware project... '
download_file "$LINUXFW_URL" "$LINUXFW_TMP"
echo OK

printf 'Parsing the README... '
nbfound=0
for line in $(grep -E 'Family=0x[0-9a-f]+ Model=0x[0-9a-f]+ Stepping=0x[0-9a-f]+: Patch=0x[0-9a-f]+' "$LINUXFW_TMP" | tr " " ","); do
    family=$(echo "$line" | grep -Eoi 'Family=0x[0-9a-f]+' | cut -d= -f2)
    model=$(echo "$line" | grep -Eoi 'Model=0x[0-9a-f]+' | cut -d= -f2)
    stepping=$(echo "$line" | grep -Eoi 'Stepping=0x[0-9a-f]+' | cut -d= -f2)
    version=$(echo "$line" | grep -Eoi 'Patch=0x[0-9a-f]+' | cut -d= -f2)
    version=$(printf "%08X" "$((version))")
    cpuid=$(fms2cpuid "$family" "$model" "$stepping")
    cpuid=$(printf "%08X" "$cpuid")
    sqlite3 "$MCEDB_TMP" "INSERT INTO \"AMD\" (\"origin\",\"cpuid\",\"pfmask\",\"version\",\"yyyymmdd\") VALUES ('linux-firmware','$cpuid','FF','$version','20000101')"
    nbfound=$((nbfound + 1))
done
echo "found $nbfound microcodes"

# --- 4. compute version string and dump the most recent fw per cpuid+pfmask -

dbversion="$mcedb_revision+i$intel_latest_date"
linuxfw_hash=$(md5sum "$LINUXFW_TMP" 2>/dev/null | cut -c1-4)
[ -n "$linuxfw_hash" ] && dbversion="$dbversion+$linuxfw_hash"

printf 'Building database... '
{
    echo "# %%% MCEDB v$dbversion"
    sqlite3 "$MCEDB_TMP" "SELECT '# I,0x'||\"t1\".\"cpuid\"||',0x'||\"t1\".\"pfmask\"||',0x'||MAX(\"t1\".\"version\")||','||\"t1\".\"yyyymmdd\" FROM \"Intel\" AS \"t1\" LEFT OUTER JOIN \"Intel\" AS \"t2\" ON \"t2\".\"cpuid\"=\"t1\".\"cpuid\" AND \"t2\".\"pfmask\"=\"t1\".\"pfmask\" AND \"t2\".\"yyyymmdd\" > \"t1\".\"yyyymmdd\" WHERE \"t2\".\"yyyymmdd\" IS NULL GROUP BY \"t1\".\"cpuid\",\"t1\".\"pfmask\" ORDER BY \"t1\".\"cpuid\",\"t1\".\"pfmask\" ASC;" | grep -v '^# .,0x00000000,'
    sqlite3 "$MCEDB_TMP" "SELECT '# A,0x'||\"t1\".\"cpuid\"||',0x'||\"t1\".\"pfmask\"||',0x'||MAX(\"t1\".\"version\")||','||\"t1\".\"yyyymmdd\" FROM \"AMD\"   AS \"t1\" LEFT OUTER JOIN \"AMD\"   AS \"t2\" ON \"t2\".\"cpuid\"=\"t1\".\"cpuid\" AND \"t2\".\"pfmask\"=\"t1\".\"pfmask\" AND \"t2\".\"yyyymmdd\" > \"t1\".\"yyyymmdd\" WHERE \"t2\".\"yyyymmdd\" IS NULL GROUP BY \"t1\".\"cpuid\",\"t1\".\"pfmask\" ORDER BY \"t1\".\"cpuid\",\"t1\".\"pfmask\" ASC;" | grep -v '^# .,0x00000000,'
} >"$DATA_TMP"
echo "DONE (version $dbversion)"

# --- 5. rewrite src/db/200_mcedb.sh, preserving its header ------------------

newfile=$(mktemp -t smc-builtin-XXXXXX)
trap 'rm -rf "$MCEDB_TMP" "$INTEL_TMP" "$LINUXFW_TMP" "$DATA_TMP" "$newfile"' EXIT INT TERM
# keep everything before the "# %%% MCEDB" line, then append the freshly built data
awk '/^# %%% MCEDB / { exit }; { print }' "$OUTFILE" >"$newfile"
cat "$DATA_TMP" >>"$newfile"
cat "$newfile" >"$OUTFILE"

echo "Updated $OUTFILE ($(wc -l <"$OUTFILE") lines, version $dbversion)"
