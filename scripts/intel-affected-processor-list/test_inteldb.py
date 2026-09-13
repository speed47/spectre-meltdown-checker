"""Regression cases for processor identity and historical database updates."""

import csv
import io
import unittest
from unittest.mock import patch

from build_inteldb import build_history, merge_snapshot, parse_db
from parse_inteldb_csv import format_db, parse_csv, parse_cpuid_values


HYBRID = 'CPUID Hybrid Identification'
RFDS = 'Register File Data Sampling - CVE-2023-28746'
REPTAR = 'Reptar - CVE-2023-23583'


def csv_text(headers, rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)
    writer.writerow(headers)
    writer.writerows(rows)
    return stream.getvalue()


def parse(headers, rows):
    return parse_csv(io.StringIO(csv_text(headers, rows)))


class ParserTests(unittest.TestCase):
    def test_explicit_identity_overrides_codename(self):
        # Deliberately misleading names prove the explicit field wins.
        entries = parse(['Code Name(s)', HYBRID, RFDS, 'CPUID'], [
            ['Catlow', 'CPUID.0x7.EDX[15]=1', 'MCU+Software', '90675'],
            ['Alder Lake S', 'CPUID.0x7.EDX[15]=0 - CPUID.0x1A.EAX[31:24]=40',
             'Not Affected', '90675'],
        ])
        self.assertEqual(entries[('0x00090675', 'H=1')]['2023-28746'], 'MS')
        self.assertEqual(entries[('0x00090675', 'H=0')]['2023-28746'], 'N')
        self.assertNotIn(('0x00090675', ''), entries)

    def test_arizona_beach_and_alder_lake_u(self):
        entries = parse(['CPUID', HYBRID, REPTAR], [
            ['906A4', 'CPUID.0x7.EDX[15]=0', 'Not Affected'],
            ['906A4', 'CPUID.0x7.EDX[15]=1', 'MCU'],
        ])
        self.assertEqual(entries[('0x000906A4', 'H=0')]['2023-23583'], 'N')
        self.assertEqual(entries[('0x000906A4', 'H=1')]['2023-23583'], 'M')

    def test_single_and_identical_explicit_profiles_keep_qualifiers(self):
        entries = parse(['CPUID', HYBRID, RFDS], [
            ['90672', 'CPUID.0x7.EDX[15]=1', 'MCU+Software'],
            ['90675', 'CPUID.0x7.EDX[15]=1', 'Not Affected'],
            ['90675', 'CPUID.0x7.EDX[15]=0', 'Not Affected'],
        ])
        self.assertEqual(set(entries), {
            ('0x00090672', 'H=1'), ('0x00090675', 'H=0'), ('0x00090675', 'H=1'),
        })

    def test_na_does_not_infer_hybrid(self):
        for value in ('NA', 'N/A', ''):
            with self.subTest(value=value):
                entries = parse(['CPUID', 'Code Name(s)', HYBRID, RFDS], [
                    ['90675', 'Alder Lake S', value, 'Not Affected'],
                ])
                self.assertEqual(set(entries), {('0x00090675', '')})

    def test_legacy_inference(self):
        entries = parse(['CPUID', 'Code Name(s)', RFDS], [
            ['90675', 'Alder Lake S', 'MCU+Software'],
            ['90675', 'Catlow', 'Not Affected'],
            ['306F2', 'Haswell', 'Not Affected'],
        ])
        self.assertEqual(set(entries), {
            ('0x00090675', 'H=0'), ('0x00090675', 'H=1'), ('0x000306F2', ''),
        })

    def test_unknown_identity_and_truncated_rows_fail(self):
        with self.assertRaisesRegex(ValueError, 'Hybrid Identification'):
            parse(['CPUID', HYBRID, RFDS], [['90675', 'unknown', 'Not Affected']])
        with self.assertRaisesRegex(ValueError, 'expected 3 columns'):
            parse(['CPUID', HYBRID, RFDS], [['90675', 'NA']])

    def test_platform_masks_are_not_cpuids(self):
        self.assertEqual(parse_cpuid_values('806F5 - 806F8 (PID 0x87)'),
                         ['0x000806F5', '0x000806F8'])
        self.assertEqual(parse_cpuid_values('A06D1 (PID 0x00000095)'), ['0x000A06D1'])

    def test_combined_cves_and_duplicate_columns(self):
        entries = parse([
            'CPUID', 'L1TF - CVE-2018-3615 - CVE-2018-3620 - CVE-2018-3646',
            'ITS (IBPB) - CVE-2024-28956', 'ITS (Guest-Host) - CVE-2024-28956',
            'ITS cBPF - CVE-2024-28956',
        ], [['90675', 'Not Affected', 'MCU', 'Software', 'Not Affected']])
        self.assertEqual(entries[('0x00090675', '')], {
            '2018-3615': 'N', '2018-3620': 'N', '2018-3646': 'N',
            '2024-28956_IBPB': 'M', '2024-28956_GH': 'S', '2024-28956_cBPF': 'N',
        })

    def test_segment_and_core_type_rows_merge_conservatively(self):
        entries = parse(['CPUID', HYBRID, 'Segment', RFDS], [
            ['B06E0', 'CPUID.0x7.EDX[15]=0 - CPUID.0x1A.EAX[31:24]=20',
             'Embedded', 'MCU_BIOS+Software'],
            ['B06E0', 'CPUID.0x7.EDX[15]=0 - CPUID.0x1A.EAX[31:24]=40',
             'Mobile', 'Not Affected'],
        ])
        self.assertEqual(entries[('0x000B06E0', 'H=0')]['2023-28746'], 'MBS')
        self.assertEqual(parse_db(io.StringIO(format_db(entries))), entries)


class HistoryTests(unittest.TestCase):
    def test_new_snapshot_replaces_profiles_and_preserves_absent_cpus(self):
        merged = {
            ('0x00090675', ''): {'2023-28746': 'N'},
            ('0x000306F2', ''): {'2023-28746': 'N'},
        }
        snapshot = {
            ('0x00090675', 'H=1'): {'2023-28746': 'MS'},
            ('0x00090675', 'H=0'): {'2023-28746': 'N'},
        }
        merge_snapshot(merged, snapshot)
        self.assertNotIn(('0x00090675', ''), merged)
        self.assertIn(('0x000306F2', ''), merged)
        merge_snapshot(merged, {('0x00090675', ''): {'2023-28746': 'M'}})
        self.assertNotIn(('0x00090675', 'H=0'), merged)
        self.assertNotIn(('0x00090675', 'H=1'), merged)

    def test_build_uses_git_order_not_hash_order_and_tip_last(self):
        old = csv_text(['CPUID', RFDS], [['90675', 'Not Affected'], ['306F2', 'Not Affected']])
        new = csv_text(['CPUID', HYBRID, RFDS], [['90675', 'CPUID.0x7.EDX[15]=1', 'MCU']])
        tip = csv_text(['CPUID', HYBRID, RFDS], [['90675', 'CPUID.0x7.EDX[15]=1', 'MCU+Software']])
        with patch('build_inteldb.git', side_effect=[
            'tip\n', 'false\n', 'ffff\naaaa\n', old, new, tip,
        ]) as run_git:
            entries, revision = build_history('repo')
        self.assertEqual(revision, 'tip')
        self.assertEqual(entries[('0x00090675', 'H=1')]['2023-28746'], 'MS')
        self.assertNotIn(('0x00090675', ''), entries)
        self.assertIn(('0x000306F2', ''), entries)
        self.assertEqual([call.args[2] for call in run_git.call_args_list[3:]], [
            'ffff:Intel_affected_processor_list.csv',
            'aaaa:Intel_affected_processor_list.csv',
            'tip:Intel_affected_processor_list.csv',
        ])

    def test_shallow_clone_rejected(self):
        with patch('build_inteldb.git', side_effect=['tip\n', 'true\n']):
            with self.assertRaisesRegex(ValueError, 'shallow'):
                build_history('repo')


if __name__ == '__main__':
    unittest.main()
