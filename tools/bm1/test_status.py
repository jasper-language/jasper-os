"""Regression contract for actual accept.sh row aggregation, without booting."""
import pathlib
import subprocess
import unittest


class AggregationContract(unittest.TestCase):
    def test_status_column_and_explicit_timing_classification(self):
        source = (pathlib.Path(__file__).resolve().parents[2]/'scripts/accept.sh').read_text()
        start = source.index('row_nonblocking() {')
        end = source.index('\n}', start)+2
        function = source[start:end]
        cases = [
            ('SMP4/SCHED1/计时 TIME 计时·参考（QEMU 不阻塞）：overrun', 0),
            ('SMP4/T-2/计时 TIME 计时·参考（QEMU 不阻塞）：overrun', 0),
            ('SMP4/M2 PASS functional check passed', 0),
            ('SMP4/ISA N/A frozen architecture', 0),
            ('SMP4/M2 FAIL explanation contains PASS but must still block', 1),
            ('SMP4/M2 TIME 计时·参考 cannot reclassify a functional row', 1),
            ('SMP4/T-2/计时 TIME missing reference classification', 1),
            ('SMP4/M2 UNKNOWN missing result', 1),
            ('', 1),
        ]
        for row, expected in cases:
            with self.subTest(row=row):
                result = subprocess.run(['bash', '-c', function+'\nrow_nonblocking "$1"', 'row-test', row], check=False)
                self.assertEqual(result.returncode, expected)
