# vim: set ts=4 sw=4 sts=4 et:
# Print the tool name and version banner
show_header() {
    pr_info "Spectre and Meltdown mitigation detection tool v$VERSION"
    pr_info
}

# Convert Family-Model-Stepping triplet to a CPUID value (base-10 to stdout)
# Args: $1=family $2=model $3=stepping
fms2cpuid() {
    local family model stepping extfamily lowfamily extmodel lowmodel
    family="$1"
    model="$2"
    stepping="$3"

    if [ "$((family))" -le 15 ]; then
        extfamily=0
        lowfamily=$((family))
    else
        # when we have a family > 0xF, then lowfamily is stuck at 0xF
        # and extfamily is ADDED to it (as in "+"), to ensure old software
        # never sees a lowfamily < 0xF for newer families
        lowfamily=15
        extfamily=$(((family) - 15))
    fi
    extmodel=$(((model & 0xF0) >> 4))
    lowmodel=$(((model & 0x0F) >> 0))
    echo $(((stepping & 0x0F) | (lowmodel << 4) | (lowfamily << 8) | (extmodel << 16) | (extfamily << 20)))
}

# Download a file using wget, curl, or fetch (whichever is available)
# Args: $1=url $2=output_file
download_file() {
    local ret url file
    url="$1"
    file="$2"
    if command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$file"
        ret=$?
    elif command -v curl >/dev/null 2>&1; then
        curl -sL "$url" -o "$file"
        ret=$?
    elif command -v fetch >/dev/null 2>&1; then
        fetch -q "$url" -o "$file"
        ret=$?
    else
        echo ERROR "please install one of \`wget\`, \`curl\` of \`fetch\` programs"
        unset file url
        return 1
    fi
    unset file url
    if [ "$ret" != 0 ]; then
        echo ERROR "error $ret"
        return $ret
    fi
    echo DONE
}

[ -z "$HOME" ] && HOME="$(getent passwd "$(whoami)" | cut -d: -f6)"
g_mcedb_cache="$HOME/.mcedb"
# Download and update the local microcode firmware database cache
# Sets: g_mcedb_tmp (temp file, cleaned up on exit)
update_fwdb() {
    local previous_dbversion dbversion mcedb_revision iucode_tool nbfound linuxfw_hash mcedb_url intel_url linuxfw_url newfile line cpuid pfmask date version intel_timestamp intel_latest_date family model stepping sqlstm

    show_header

    set -e

    if [ -r "$g_mcedb_cache" ]; then
        previous_dbversion=$(awk '/^# %%% MCEDB / { print $4 }' "$g_mcedb_cache")
    fi

    # first, download the MCE.db from the excellent platomav's MCExtractor project
    g_mcedb_tmp="$(mktemp -t smc-mcedb-XXXXXX)"
    mcedb_url='https://github.com/platomav/MCExtractor/raw/master/MCE.db'
    pr_info_nol "Fetching MCE.db from the MCExtractor project... "
    download_file "$mcedb_url" "$g_mcedb_tmp" || return $?

    # second, get the Intel firmwares from GitHub
    g_intel_tmp="$(mktemp -d -t smc-intelfw-XXXXXX)"
    intel_url="https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/archive/main.zip"
    pr_info_nol "Fetching Intel firmwares... "
    ## https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files.git
    download_file "$intel_url" "$g_intel_tmp/fw.zip" || return $?

    # now extract MCEdb contents using sqlite
    pr_info_nol "Extracting MCEdb data... "
    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo ERROR "please install the \`sqlite3\` program"
        return 1
    fi
    mcedb_revision=$(sqlite3 "$g_mcedb_tmp" "SELECT \"revision\" from \"MCE\"")
    if [ -z "$mcedb_revision" ]; then
        echo ERROR "downloaded file seems invalid"
        return 1
    fi
    sqlite3 "$g_mcedb_tmp" "ALTER TABLE \"Intel\" ADD COLUMN \"origin\" TEXT"
    sqlite3 "$g_mcedb_tmp" "ALTER TABLE \"Intel\" ADD COLUMN \"pfmask\" TEXT"
    sqlite3 "$g_mcedb_tmp" "ALTER TABLE \"AMD\" ADD COLUMN \"origin\" TEXT"
    sqlite3 "$g_mcedb_tmp" "ALTER TABLE \"AMD\" ADD COLUMN \"pfmask\" TEXT"
    sqlite3 "$g_mcedb_tmp" "UPDATE \"Intel\" SET \"origin\"='mce'"
    sqlite3 "$g_mcedb_tmp" "UPDATE \"Intel\" SET \"pfmask\"='FF'"
    sqlite3 "$g_mcedb_tmp" "UPDATE \"AMD\" SET \"origin\"='mce'"
    sqlite3 "$g_mcedb_tmp" "UPDATE \"AMD\" SET \"pfmask\"='FF'"

    echo OK "MCExtractor database revision $mcedb_revision"

    # parse Intel firmwares to get their versions
    pr_info_nol "Integrating Intel firmwares data to db... "
    if ! command -v unzip >/dev/null 2>&1; then
        echo ERROR "please install the \`unzip\` program"
        return 1
    fi
    (cd "$g_intel_tmp" && unzip fw.zip >/dev/null)
    if ! [ -d "$g_intel_tmp/Intel-Linux-Processor-Microcode-Data-Files-main/intel-ucode" ]; then
        echo ERROR "expected the 'intel-ucode' folder in the downloaded zip file"
        return 1
    fi

    if ! command -v iucode_tool >/dev/null 2>&1; then
        if ! command -v iucode-tool >/dev/null 2>&1; then
            echo ERROR "please install the \`iucode-tool\` program"
            return 1
        else
            iucode_tool="iucode-tool"
        fi
    else
        iucode_tool="iucode_tool"
    fi
    #  079/001: sig 0x000106c2, pf_mask 0x01, 2009-04-10, rev 0x0217, size 5120
    #  078/004: sig 0x000106ca, pf_mask 0x10, 2009-08-25, rev 0x0107, size 5120
    $iucode_tool -l "$g_intel_tmp/Intel-Linux-Processor-Microcode-Data-Files-main/intel-ucode" | grep -wF sig | while read -r line; do
        cpuid=$(echo "$line" | grep -Eio 'sig 0x[0-9a-f]+' | awk '{print $2}')
        cpuid=$((cpuid))
        cpuid=$(printf "%08X" "$cpuid")
        pfmask=$(echo "$line" | grep -Eio 'pf_mask 0x[0-9a-f]+' | awk '{print $2}')
        pfmask=$((pfmask))
        pfmask=$(printf "%02X" $pfmask)
        date=$(echo "$line" | grep -Eo '(19|20)[0-9][0-9]-[01][0-9]-[0-3][0-9]' | tr -d '-')
        version=$(echo "$line" | grep -Eio 'rev 0x[0-9a-f]+' | awk '{print $2}')
        version=$((version))
        version=$(printf "%08X" "$version")
        # ensure the official Intel DB always has precedence over mcedb, even if mcedb has seen a more recent fw
        sqlite3 "$g_mcedb_tmp" "DELETE FROM \"Intel\" WHERE \"origin\" != 'intel' AND \"cpuid\" = '$cpuid';"
        # then insert our version
        sqlite3 "$g_mcedb_tmp" "INSERT INTO \"Intel\" (\"origin\",\"cpuid\",\"pfmask\",\"version\",\"yyyymmdd\") VALUES ('intel','$cpuid','$pfmask','$version','$date');"
    done
    intel_timestamp=$(stat -c %Y "$g_intel_tmp/Intel-Linux-Processor-Microcode-Data-Files-main/license" 2>/dev/null)
    if [ -n "$intel_timestamp" ]; then
        # use this date, it matches the last commit date
        intel_latest_date=$(date +%Y%m%d -d @"$intel_timestamp")
    else
        echo "Falling back to the latest microcode date"
        intel_latest_date=$(sqlite3 "$g_mcedb_tmp" "SELECT \"yyyymmdd\" FROM \"Intel\" WHERE \"origin\"='intel' ORDER BY \"yyyymmdd\" DESC LIMIT 1;")
    fi
    echo DONE "(version $intel_latest_date)"

    # now parse the most recent linux-firmware amd-ucode README file
    pr_info_nol "Fetching latest amd-ucode README from linux-firmware project... "
    linuxfw_url="https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/amd-ucode/README"
    g_linuxfw_tmp=$(mktemp -t smc-linuxfw-XXXXXX)
    download_file "$linuxfw_url" "$g_linuxfw_tmp" || return $?

    pr_info_nol "Parsing the README... "
    nbfound=0
    for line in $(grep -E 'Family=0x[0-9a-f]+ Model=0x[0-9a-f]+ Stepping=0x[0-9a-f]+: Patch=0x[0-9a-f]+' "$g_linuxfw_tmp" | tr " " ","); do
        pr_debug "Parsing line $line"
        family=$(echo "$line" | grep -Eoi 'Family=0x[0-9a-f]+' | cut -d= -f2)
        model=$(echo "$line" | grep -Eoi 'Model=0x[0-9a-f]+' | cut -d= -f2)
        stepping=$(echo "$line" | grep -Eoi 'Stepping=0x[0-9a-f]+' | cut -d= -f2)
        version=$(echo "$line" | grep -Eoi 'Patch=0x[0-9a-f]+' | cut -d= -f2)
        version=$(printf "%08X" "$((version))")
        cpuid=$(fms2cpuid "$family" "$model" "$stepping")
        cpuid=$(printf "%08X" "$cpuid")
        sqlstm="INSERT INTO \"AMD\" (\"origin\",\"cpuid\",\"pfmask\",\"version\",\"yyyymmdd\") VALUES ('linux-firmware','$cpuid','FF','$version','20000101')"
        pr_debug "family $family model $model stepping $stepping cpuid $cpuid"
        pr_debug "$sqlstm"
        sqlite3 "$g_mcedb_tmp" "$sqlstm"
        nbfound=$((nbfound + 1))
        unset family model stepping version cpuid date sqlstm
    done
    echo "found $nbfound microcodes"
    unset nbfound

    dbversion="$mcedb_revision+i$intel_latest_date"
    linuxfw_hash=$(md5sum "$g_linuxfw_tmp" 2>/dev/null | cut -c1-4)
    if [ -n "$linuxfw_hash" ]; then
        dbversion="$dbversion+$linuxfw_hash"
    fi

    if [ "$1" != builtin ] && [ -n "$previous_dbversion" ] && [ "$previous_dbversion" = "v$dbversion" ]; then
        echo "We already have this version locally, no update needed"
        return 0
    fi

    pr_info_nol "Building local database... "
    {
        echo "# Spectre & Meltdown Checker"
        echo "# %%% MCEDB v$dbversion"
        # we'll use the more recent fw for Intel and AMD
        sqlite3 "$g_mcedb_tmp" "SELECT '# I,0x'||\"t1\".\"cpuid\"||',0x'||\"t1\".\"pfmask\"||',0x'||MAX(\"t1\".\"version\")||','||\"t1\".\"yyyymmdd\" FROM \"Intel\" AS \"t1\" LEFT OUTER JOIN \"Intel\" AS \"t2\" ON \"t2\".\"cpuid\"=\"t1\".\"cpuid\" AND \"t2\".\"pfmask\"=\"t1\".\"pfmask\" AND \"t2\".\"yyyymmdd\" > \"t1\".\"yyyymmdd\" WHERE \"t2\".\"yyyymmdd\" IS NULL GROUP BY \"t1\".\"cpuid\",\"t1\".\"pfmask\" ORDER BY \"t1\".\"cpuid\",\"t1\".\"pfmask\" ASC;" | grep -v '^# .,0x00000000,'
        sqlite3 "$g_mcedb_tmp" "SELECT '# A,0x'||\"t1\".\"cpuid\"||',0x'||\"t1\".\"pfmask\"||',0x'||MAX(\"t1\".\"version\")||','||\"t1\".\"yyyymmdd\" FROM \"AMD\"   AS \"t1\" LEFT OUTER JOIN \"AMD\"   AS \"t2\" ON \"t2\".\"cpuid\"=\"t1\".\"cpuid\" AND \"t2\".\"pfmask\"=\"t1\".\"pfmask\" AND \"t2\".\"yyyymmdd\" > \"t1\".\"yyyymmdd\" WHERE \"t2\".\"yyyymmdd\" IS NULL GROUP BY \"t1\".\"cpuid\",\"t1\".\"pfmask\" ORDER BY \"t1\".\"cpuid\",\"t1\".\"pfmask\" ASC;" | grep -v '^# .,0x00000000,'
    } >"$g_mcedb_cache"
    echo DONE "(version $dbversion)"

    if [ "$1" = builtin ]; then
        newfile=$(mktemp -t smc-builtin-XXXXXX)
        awk '/^# %%% MCEDB / { exit }; { print }' "$0" >"$newfile"
        awk '{ if (NR>1) { print } }' "$g_mcedb_cache" >>"$newfile"
        cat "$newfile" >"$0"
        rm -f "$newfile"
    fi
}
