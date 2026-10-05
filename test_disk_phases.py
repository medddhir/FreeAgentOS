"""Unprivileged allocation-phase diagnostics; mocked calls prove no enforcement."""
import errno
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_disk_allocation import metadata, MIB
from test_disk_diagnostics import sandbox
from test_resource_sandbox import allocate_disk_demand, disk_phase_record


class DiskPhaseTests(unittest.TestCase):
    def test_reservation_pair_precedes_coverage(self):
        events = []
        with patch.object(os, 'posix_fallocate', side_effect=lambda *args: events.append('reserve')), \
                patch.object(os, 'fstat', return_value=metadata()):
            allocate_disk_demand(99, lambda amount: events.append(('covered', amount)),
                                 lambda name, category: events.append((name, category)))
        self.assertEqual(events, [('reservation_before', 'NONE'), 'reserve',
                                 ('reservation_after', 'OK'), ('covered', 60 * MIB)])

    def test_fallback_pairs_and_error_categories_preserve_exceptions(self):
        for error, category in ((OSError(errno.ENOSPC, 'private'), 'ENOSPC'),
                                (OSError(errno.EIO, 'private'), 'UNEXPECTED'),
                                (RuntimeError('private'), 'INVALID'), (None, 'OK')):
            events = []
            with self.subTest(category=category), \
                    patch.object(os, 'posix_fallocate', side_effect=OSError(errno.ENOSPC, 'private')), \
                    patch.object(os, 'fstat', side_effect=[metadata(0, 0), metadata()]), \
                    patch.object(os, 'lseek'), \
                    patch.object(os, 'write', side_effect=error, return_value=MIB):
                callback = lambda name, value: events.append((name, value))
                if error:
                    with self.assertRaises(type(error)) as caught:
                        allocate_disk_demand(99, lambda _: None, callback)
                    self.assertIs(caught.exception, error)
                else:
                    allocate_disk_demand(99, lambda _: None, callback)
            self.assertEqual(events, [('reservation_before', 'NONE'),
                                     ('reservation_after', 'ENOSPC'),
                                     ('fallback_before', 'NONE'), ('fallback_after', category)])

    def test_reservation_errors_are_paired_without_fallback(self):
        for error, category in ((AttributeError('private'), 'UNSUPPORTED'),
                                (OSError(errno.EOPNOTSUPP, 'private'), 'UNSUPPORTED'),
                                (OSError(errno.EIO, 'private'), 'UNEXPECTED')):
            events = []
            with self.subTest(category=category), patch.object(os, 'posix_fallocate', side_effect=error):
                with self.assertRaises((OSError, RuntimeError)):
                    allocate_disk_demand(99, lambda _: self.fail('unexpected coverage'),
                                         lambda name, value: events.append((name, value)))
            self.assertEqual(events, [('reservation_before', 'NONE'), ('reservation_after', category)])

    def test_six_demands_worst_case_fits_existing_bounds_and_parser(self):
        records = []
        written = 0
        demand_id = 0
        def phase(name, category='NONE'):
            records.append(disk_phase_record(name, demand_id, written, category))
        phase('test_start')
        # Every reservation fails but every bounded fallback completes: maximal
        # five records per demand, plus start and terminal = 32 (not 40).
        for demand_id in range(1, 7):
            base = written
            def covered(offset):
                nonlocal written
                written = base + offset
                if offset == 60 * MIB:
                    phase('write')
            with patch.object(os, 'posix_fallocate', side_effect=OSError(errno.ENOSPC, 'private')), \
                    patch.object(os, 'fstat', side_effect=[metadata(0, 0), metadata()]), \
                    patch.object(os, 'lseek'), patch.object(os, 'write', return_value=MIB):
                allocate_disk_demand(99, covered, phase)
        phase('complete', 'OK')
        text = ''.join(json.dumps(record) + '\n' for record in records)
        self.assertEqual(len(records), 32)
        self.assertLessEqual(len(records), sandbox.DIAGNOSTIC_RECORDS)
        # Worst finite float representation and largest allowed progress integer
        # remain under 192 bytes/record; 32*192=6144 <8192.
        for record in records:
            largest = {**record, 'monotonic': -1.2345678901234567e-300,
                       'written_bytes': 360 * MIB}
            self.assertLessEqual(len(json.dumps(largest) + '\n'), 192)
        self.assertLessEqual(len(text.encode()), sandbox.DIAGNOSTIC_BYTES)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tmp').mkdir()
            path = root / 'tmp' / sandbox.DISK_DIAGNOSTIC_FILE
            path.write_text(text)
            parsed = sandbox._disk_progress(root)
            self.assertEqual(parsed['status'], 'CHILD_REPORTED')
            self.assertEqual(parsed['records'], records)
            for changed in ({'demand': 7}, {'category': 'private error'}, {'phase': 'foreign'}):
                path.write_text(json.dumps({**records[1], **changed}) + '\n')
                self.assertEqual(sandbox._disk_progress(root)['status'], 'MISSING_OR_INVALID')
            path.write_text(text + text)
            self.assertEqual(sandbox._disk_progress(root)['status'], 'MISSING_OR_INVALID')


if __name__ == '__main__':
    unittest.main()
