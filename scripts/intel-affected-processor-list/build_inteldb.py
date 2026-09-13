#!/usr/bin/env python3
"""Build INTELDB from a local clone of Intel's affected processor list history."""

import argparse
import csv
import io
from pathlib import Path
import re
import subprocess
import sys

from parse_inteldb_csv import format_cpuid, format_db, parse_csv


CSV_PATH = 'Intel_affected_processor_list.csv'


def parse_db(stream):
    """Recover legacy entries, adapted from compare_inteldb_history.py."""
    entries = {}
    in_db = False
    for line in stream:
        if '%%% INTELDB' in line:
            in_db = True
            continue
        if not in_db:
            continue
        if '%%% ENDOFINTELDB' in line:
            break
        if not line.startswith('# 0x'):
            continue
        fields = line[2:].strip().rstrip(',').split(',')
        cpuid = format_cpuid(fields.pop(0))
        qualifier = ''
        if fields and re.fullmatch(r'H=[01]', fields[0]):
            qualifier = fields.pop(0)
        vulns = {}
        for field in fields:
            cves, status = field.split('=', 1)
            for cve in cves.split('+'):
                vulns[cve] = status
        entries[(cpuid, qualifier)] = vulns
    if not entries:
        raise ValueError('No entries found in baseline INTELDB')
    return entries


def merge_snapshot(merged, snapshot):
    """Newest snapshot wins per CPUID; retain CPUs absent from that snapshot.

    Replace all qualifiers for a present CPUID together. Otherwise historical
    unqualified entries survive when explicit H=0/H=1 entries are introduced,
    and runtime lookup can incorrectly fall back to obsolete data.
    """
    present = {cpuid for cpuid, _ in snapshot}
    for key in list(merged):
        if key[0] in present:
            del merged[key]
    merged.update(snapshot)


def git(repo, *args):
    return subprocess.run(
        ['git', '-C', repo, *args], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, encoding='utf-8-sig',
    ).stdout


def build_history(repo, ref='HEAD', baseline=None):
    # Resolve once so a concurrent fetch/checkout cannot change the input.
    revision = git(repo, 'rev-parse', '--verify', f'{ref}^{{commit}}').strip()
    if git(repo, 'rev-parse', '--is-shallow-repository').strip() == 'true':
        raise ValueError('Intel repository is shallow; use a full clone to retain historical CPUs')
    # Consume Git's ordering directly, never a glob sorted by commit hash.
    commits = git(repo, 'log', '--reverse', '--topo-order', '--format=%H',
                  revision, '--', CSV_PATH).splitlines()
    # Always parse the selected tip last, including when it is a merge commit
    # that was omitted by path-history simplification.
    commits = [commit for commit in commits if commit != revision] + [revision]
    merged = dict(baseline or {})
    for commit in commits:
        try:
            snapshot = parse_csv(io.StringIO(git(repo, 'show', f'{commit}:{CSV_PATH}')))
        except (ValueError, csv.Error) as error:
            raise ValueError(f'{commit}: {error}') from error
        merge_snapshot(merged, snapshot)
        print(f'{commit[:12]}: {len(snapshot)} entries; {len(merged)} retained', file=sys.stderr)
    return merged, revision


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repo', help='Full local clone of intel/Intel-affected-processor-list')
    parser.add_argument('output_file', nargs='?', help='Defaults to stdout')
    parser.add_argument('--ref', default='HEAD', help='Revision to build (default: HEAD)')
    parser.add_argument('--base-db', help='Existing INTELDB retaining legacy CPUs absent from CSV history')
    args = parser.parse_args()
    try:
        header = Path(__file__).resolve().with_name('header.txt').read_text(encoding='utf-8')
        baseline = None
        if args.base_db:
            with open(args.base_db, encoding='utf-8') as stream:
                baseline = parse_db(stream)
        entries, revision = build_history(args.repo, args.ref, baseline)
        output = format_db(entries, f'Merged Intel CSV history through {revision} (newest CPUID data wins)')
        output = header.rstrip('\n') + '\n' + output
        if args.output_file:
            with open(args.output_file, 'w', encoding='utf-8') as stream:
                stream.write(output)
        else:
            sys.stdout.write(output)
    except subprocess.CalledProcessError as error:
        parser.exit(1, f'ERROR: git: {error.stderr.strip()}\n')
    except (OSError, ValueError, csv.Error) as error:
        parser.exit(1, f'ERROR: {error}\n')


if __name__ == '__main__':
    main()
