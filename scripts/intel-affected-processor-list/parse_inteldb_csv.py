#!/usr/bin/env python3
"""
Parse Intel's affected processor list CSV into the checker's INTELDB format.

Recovered from smc-new2/c/scripts/inteldb/parse_inteldb_csv.py. Uses explicit
hybrid identification when available, with codename inference for old CSVs.
"""

import argparse
import csv
import re
import sys
from collections import OrderedDict


# Only used for historical CSVs without the hybrid identification column.
HYBRID_CODENAMES = {'alder lake', 'raptor lake'}
NON_HYBRID_CODENAMES = {'catlow', 'arizona beach', 'alder lake n', 'twin lake'}

STATUS_MAP = {
    'not affected': 'N',
    'affected': 'Y',
    'mcu': 'M',
    'software': 'S',
    'hardware': 'H',
    'bios': 'B',
    'no planned mitigation': 'X',
    'mcu+software': 'MS',
    'mcu + software': 'MS',
    'hardware+software': 'HS',
    'hardware + software': 'HS',
    'hardware+mcu': 'HM',
    'hardware + mcu': 'HM',
}

STATUS_SEVERITY = {
    'N': 0, 'S': 1, 'M': 2, 'B': 2, 'H': 3,
    'MS': 3, 'MB': 3, 'HS': 4, 'HM': 4, 'MBS': 4, 'HMS': 5, 'X': 6, 'Y': 6,
}


def normalize_status(status_text):
    """Convert status text to db code."""
    s = status_text.strip().lower()
    s = s.replace('\xa0', ' ').strip()
    s = re.sub(r'(\d+)$', '', s).strip()
    s = re.sub(r'[_\s]+', ' ', s).strip()
    if not s:
        return None
    if s in STATUS_MAP:
        return STATUS_MAP[s]
    if 'not affected' in s:
        return 'N'
    if 'no planned' in s:
        return 'X'
    s = re.sub(r'\s*\+\s*', '+', s)
    parts = set()
    for part in s.split('+'):
        part = part.strip()
        if part in ('mcu', 'microcode'):
            parts.add('M')
        elif part in ('software', 'sw', 'soft'):
            parts.add('S')
        elif part in ('hardware', 'hw'):
            parts.add('H')
        elif part == 'bios':
            parts.add('B')
        elif part == 'mcu bios':
            parts.update(('M', 'B'))
        else:
            print(f"WARNING: unknown status part '{part}' in '{status_text}' -> treating as Y", file=sys.stderr)
            return 'Y'
    return ''.join(code for code in ('H', 'M', 'B', 'S') if code in parts) or 'Y'


def worst_case_status(s1, s2):
    sev1 = STATUS_SEVERITY.get(s1, 6)
    sev2 = STATUS_SEVERITY.get(s2, 6)
    return s1 if sev1 >= sev2 else s2


def expand_combined_cves(vulns):
    """Expand combined CVE keys into individual entries."""
    expanded = OrderedDict()
    for key, status in vulns.items():
        for cve in key.split('+'):
            expanded[cve] = status
    return expanded


def parse_cpuid_values(cpuid_cell):
    """Parse explicit CPUID lists, excluding parenthesized platform IDs."""
    text = re.sub(r'\([^)]*\)', '', cpuid_cell).strip()
    if not text:
        return []
    cpuids = []
    for part in re.split(r'[,\s]+', text):
        if part in ('', '-'):
            continue
        if not re.fullmatch(r'(?:0[xX])?[0-9a-fA-F]{5,8}', part):
            raise ValueError(f'Unsupported CPUID value {part!r} in {cpuid_cell!r}')
        cpuid = format_cpuid(part)
        if cpuid not in cpuids:
            cpuids.append(cpuid)
    return cpuids


def extract_cve_keys(header_row, first_cve_col=0):
    """Extract CVE keys by header text, including combined/duplicate columns."""
    cve_keys = []
    cve_count = {}
    for i in range(first_cve_col, len(header_row)):
        cve_matches = re.findall(r'CVE[- ](\d{4}[- ]\d+)', header_row[i])
        if not cve_matches:
            continue
        cve_ids = list(dict.fromkeys(m.replace(' ', '-') for m in cve_matches))
        key = '+'.join(cve_ids)
        cve_count[key] = cve_count.get(key, 0) + 1
        cve_keys.append((i, key))

    final_keys = []
    seen_count = {}
    for idx, key in cve_keys:
        if cve_count[key] > 1:
            seen_count[key] = seen_count.get(key, 0) + 1
            header_text = header_row[idx].lower()
            if 'ibpb' in header_text:
                suffix = 'IBPB'
            elif 'guest' in header_text or 'host' in header_text:
                suffix = 'GH'
            elif 'cbpf' in header_text:
                suffix = 'cBPF'
            elif 'zero' in header_text:
                suffix = 'zero'
            elif 'stale' in header_text:
                suffix = 'stale'
            elif 'rrsba' in header_text:
                suffix = 'RRSBA'
            elif 'rsbu' in header_text or 'rsba' in header_text:
                suffix = 'RSBU'
            else:
                suffix = f'v{seen_count[key]}'
            final_keys.append((idx, f'{key}_{suffix}'))
        else:
            final_keys.append((idx, key))
    return final_keys


def infer_hybrid(codename):
    """Infer hybrid status for old CSVs. Returns '0', '1', or None."""
    cn = codename.lower()
    for name in NON_HYBRID_CODENAMES:
        if name in cn:
            return '0'
    for name in HYBRID_CODENAMES:
        if name in cn:
            return '1'
    return None


def parse_hybrid(text):
    """Read Intel's explicit hybrid bit, accepting the optional core-type field.

    INTELDB describes processors at CPUID + hybrid-bit granularity. Core-type
    rows sharing that key are worst-case merged, like segment-specific rows.
    The core-type value is hexadecimal (20 = Atom, 40 = Core).
    """
    text = text.strip()
    if text.upper() in ('', 'NA', 'N/A'):
        return None
    match = re.fullmatch(
        r'CPUID\.0x7\.EDX\[15\]\s*=\s*([01])'
        r'(?:\s*-\s*CPUID\.0x1A\.EAX\[31:24\]\s*=\s*(?:0x)?(?:20|40))?',
        text, re.IGNORECASE,
    )
    if not match:
        raise ValueError(f'Unsupported CPUID Hybrid Identification: {text!r}')
    return match.group(1)


def merge_worst_case(vulns1, vulns2):
    merged = OrderedDict(vulns1)
    for cve, status in vulns2.items():
        merged[cve] = worst_case_status(merged[cve], status) if cve in merged else status
    return merged


def format_cpuid(cpuid_hex):
    return f'0x{int(cpuid_hex, 16):08X}'


def parse_csv(stream):
    """Return {(normalized CPUID, hybrid qualifier): vulnerability mapping}."""
    reader = csv.reader(stream)
    header = next(reader, [])
    header_lower = [h.lstrip('\ufeff').strip().lower() for h in header]
    if 'cpuid' not in header_lower:
        raise ValueError('Cannot find CPUID column')
    cpuid_col = header_lower.index('cpuid')
    codename_col = next((i for i, h in enumerate(header_lower)
                         if 'code name' in h or 'microarchitecture' in h), None)
    hybrid_col = (header_lower.index('cpuid hybrid identification')
                  if 'cpuid hybrid identification' in header_lower else None)
    cve_keys = extract_cve_keys(header)
    if not cve_keys:
        raise ValueError('Cannot find vulnerability columns')

    raw_entries = {}
    for row in reader:
        if not row or not any(cell.strip() for cell in row):
            continue
        if len(row) != len(header):
            raise ValueError(f'CSV line {reader.line_num}: expected {len(header)} columns, got {len(row)}')
        cpuids = parse_cpuid_values(row[cpuid_col])
        if not cpuids:
            continue
        if hybrid_col is not None:
            hybrid = parse_hybrid(row[hybrid_col])
        else:
            hybrid = infer_hybrid(row[codename_col]) if codename_col is not None else None
        vuln_data = OrderedDict()
        for col_idx, cve_key in cve_keys:
            status = normalize_status(row[col_idx])
            if status:
                vuln_data[cve_key] = status
        vuln_data = expand_combined_cves(vuln_data)
        for cpuid in cpuids:
            key = (cpuid, hybrid)
            raw_entries[key] = merge_worst_case(raw_entries.get(key, {}), vuln_data)

    cpuid_groups = {}
    for (cpuid, hybrid), vulns in raw_entries.items():
        cpuid_groups.setdefault(cpuid, {})[hybrid] = vulns

    final_entries = {}
    for cpuid, hybrid_map in cpuid_groups.items():
        # Historical inference only distinguished conflicting profiles. Keep
        # that behavior for old CSVs, but never discard explicit qualifiers.
        vuln_sets = {tuple(sorted(v.items())) for v in hybrid_map.values()}
        if hybrid_col is None and len(vuln_sets) == 1:
            final_entries[(cpuid, '')] = next(iter(hybrid_map.values()))
        else:
            for hybrid, vulns in hybrid_map.items():
                qualifier = f'H={hybrid}' if hybrid is not None else ''
                final_entries[(cpuid, qualifier)] = vulns
    if not final_entries:
        raise ValueError('No processor entries found')
    return final_entries


def format_db(entries, description='Parsed from Intel affected processor list CSV (GitHub)'):
    lines = [
        f'# {description}',
        '# Source: https://github.com/intel/Intel-affected-processor-list',
        '#',
        '# %%% INTELDB',
    ]
    for (cpuid, qualifier), vulns in sorted(entries.items()):
        fields = [cpuid] + ([qualifier] if qualifier else [])
        fields.extend(f'{cve}={status}' for cve, status in vulns.items())
        lines.append('# ' + ','.join(fields) + ',')
    lines.append('# %%% ENDOFINTELDB')
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv_file')
    parser.add_argument('output_file', nargs='?')
    args = parser.parse_args()
    try:
        with open(args.csv_file, encoding='utf-8-sig', newline='') as stream:
            entries = parse_csv(stream)
        output = format_db(entries)
        if args.output_file:
            with open(args.output_file, 'w', encoding='utf-8') as stream:
                stream.write(output)
        else:
            sys.stdout.write(output)
        print(f'Parsed {len(entries)} processor entries', file=sys.stderr)
    except (OSError, ValueError, csv.Error) as error:
        parser.exit(1, f'ERROR: {error}\n')


if __name__ == '__main__':
    main()
