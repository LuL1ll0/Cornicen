"""The disk-backed Sequence must retain normal indexing semantics."""
import tempfile
import unittest
from cornicen.sources.cvelist import _Records


class RecordSequenceTests(unittest.TestCase):
    def test_positive_negative_slice_and_repeated_iteration(self):
        with tempfile.TemporaryDirectory(dir='.') as directory:
            records = _Records(directory)
            self.addCleanup(records.close)
            expected = [{'number': n} for n in range(3)]
            for record in expected:
                records.append(record)
            self.assertEqual(records[0], expected[0])
            self.assertEqual(records[1], expected[1])
            self.assertEqual(records[-1], expected[-1])
            self.assertEqual(records[-3], expected[0])
            self.assertEqual(records[1:], tuple(expected[1:]))
            for index in (3, -4):
                with self.subTest(index=index), self.assertRaises(IndexError):
                    records[index]
            self.assertEqual(list(records), expected)
            self.assertEqual(list(records), expected)
