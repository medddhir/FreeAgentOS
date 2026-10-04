"""Fixed capacity-fixture algorithm tests; mocked allocation is not enforcement."""
import errno
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from test_resource_sandbox import allocate_disk_demand

MIB = 1024 * 1024
DEMAND = 60 * MIB


def metadata(size=DEMAND, allocated=DEMAND):
    return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=size, st_blocks=allocated // 512)


class DiskAllocationTests(unittest.TestCase):
    def test_complete_fallback_requires_final_backing_metadata(self):
        error = OSError(errno.ENOSPC, 'full')
        for final in (metadata(0, 0), metadata(DEMAND, 0),
                      metadata(DEMAND, DEMAND - 512), metadata(DEMAND + 1),
                      metadata(DEMAND, DEMAND + 512), metadata(-1, DEMAND),
                      metadata(DEMAND, -512),
                      SimpleNamespace(st_mode=stat.S_IFDIR | 0o700,
                                      st_size=DEMAND, st_blocks=DEMAND // 512)):
            with self.subTest(size=final.st_size, blocks=final.st_blocks), \
                    patch.object(os, 'posix_fallocate', side_effect=error), \
                    patch.object(os, 'fstat', side_effect=[metadata(0, 0), final]) as observe, \
                    patch.object(os, 'lseek'), patch.object(os, 'write', return_value=MIB) as write:
                with self.assertRaisesRegex(RuntimeError, 'DISK_ALLOCATION_NOT_BACKED'):
                    allocate_disk_demand(99, lambda _: None)
                self.assertEqual(write.call_count, 60)
                self.assertEqual(observe.call_count, 2)

    def test_fully_backed_fallback_reuses_retained_partial_allocation(self):
        observations = []
        with patch.object(os, 'posix_fallocate', side_effect=OSError(errno.ENOSPC, 'full')), \
                patch.object(os, 'fstat', side_effect=[metadata(DEMAND, 7 * MIB), metadata()]) as observe, \
                patch.object(os, 'lseek') as seek, \
                patch.object(os, 'write', return_value=MIB) as write:
            allocate_disk_demand(99, observations.append)
            seek.assert_called_once_with(99, 0, os.SEEK_SET)
            self.assertEqual(write.call_count, 60)
            self.assertEqual(sum(len(call.args[1]) for call in write.call_args_list), DEMAND)
            self.assertEqual(observations, [MIB * offset for offset in range(1, 61)])
            self.assertEqual(observe.call_args_list[0].args, (99,))
            self.assertEqual(observe.call_args_list[1].args, (99,))

    def test_short_writes_do_not_infer_completion_from_retained_allocation(self):
        observations = []
        with patch.object(os, 'posix_fallocate', side_effect=OSError(errno.ENOSPC, 'full')), \
                patch.object(os, 'fstat', return_value=metadata(DEMAND, 7 * MIB)) as observe, \
                patch.object(os, 'lseek'), \
                patch.object(os, 'write', side_effect=[MIB // 2] + [MIB] * 59) as write:
            with self.assertRaisesRegex(RuntimeError, 'DISK_FALLBACK_INCOMPLETE'):
                allocate_disk_demand(99, observations.append)
            self.assertEqual(write.call_count, 60)
            self.assertEqual(observations[0], MIB // 2)
            self.assertEqual(observations[-1], DEMAND - MIB // 2)
            self.assertTrue(all(value <= DEMAND for value in observations))
            observe.assert_called_once_with(99)  # Incomplete writes cannot prove completion.

    def test_final_metadata_read_error_propagates_after_bounded_writes(self):
        error = OSError(errno.EIO, 'final metadata unavailable')
        with patch.object(os, 'posix_fallocate', side_effect=OSError(errno.ENOSPC, 'full')), \
                patch.object(os, 'fstat', side_effect=[metadata(0, 0), error]), \
                patch.object(os, 'lseek'), patch.object(os, 'write', return_value=MIB) as write:
            with self.assertRaises(OSError) as caught:
                allocate_disk_demand(99, lambda _: None)
            self.assertIs(caught.exception, error)
            self.assertEqual(write.call_count, 60)

    def test_successful_reservations_cover_fixed_aggregate_demands(self):
        observations = []
        with patch.object(os, 'posix_fallocate') as reserve, \
                patch.object(os, 'fstat', return_value=metadata()), \
                patch.object(os, 'write') as write:
            for descriptor in range(4):
                allocate_disk_demand(descriptor, observations.append)
            self.assertEqual(observations, [DEMAND] * 4)
            self.assertEqual(sum(observations), 240 * MIB)
            self.assertEqual([call.args for call in reserve.call_args_list],
                             [(descriptor, 0, DEMAND) for descriptor in range(4)])
            write.assert_not_called()

    def test_enospc_partial_reservation_reuses_offsets_and_propagates_real_error(self):
        observations = []
        error = OSError(errno.ENOSPC, 'No space left on device')
        # Size is not a usable-prefix proof; simulate holes/partial reservation.
        with patch.object(os, 'posix_fallocate', side_effect=error), \
                patch.object(os, 'fstat', return_value=metadata(DEMAND, 7 * MIB)), \
                patch.object(os, 'lseek') as seek, \
                patch.object(os, 'write', side_effect=[MIB, MIB // 2, error]) as write:
            with self.assertRaises(OSError) as caught:
                allocate_disk_demand(99, observations.append)
            self.assertIs(caught.exception, error)
            seek.assert_called_once_with(99, 0, os.SEEK_SET)
            self.assertEqual(observations, [MIB, MIB + MIB // 2])
            self.assertTrue(all(len(call.args[1]) <= MIB for call in write.call_args_list))
            self.assertLessEqual(max(observations), DEMAND)
            # Never count the retained 7MiB a second time or infer its location.
            self.assertNotIn(7 * MIB, observations)

    def test_fallback_success_short_zero_and_allocation_anomalies_are_bounded(self):
        for amount, outcome in ((MIB, None), (1, 'DISK_FALLBACK_INCOMPLETE'),
                                (0, 'DISK_FALLBACK_WRITE_INVALID')):
            with self.subTest(amount=amount), \
                    patch.object(os, 'posix_fallocate', side_effect=OSError(errno.ENOSPC, 'full')), \
                    patch.object(os, 'fstat', side_effect=[metadata(0, 0), metadata()]), \
                    patch.object(os, 'lseek'), patch.object(os, 'write', return_value=amount) as write:
                observations = []
                if outcome:
                    with self.assertRaisesRegex(RuntimeError, outcome):
                        allocate_disk_demand(99, observations.append)
                else:
                    allocate_disk_demand(99, observations.append)
                    self.assertEqual(observations[-1], DEMAND)
                self.assertLessEqual(write.call_count, 60)
                self.assertTrue(all(0 < value <= DEMAND for value in observations))
        with patch.object(os, 'posix_fallocate'), patch.object(os, 'fstat', return_value=metadata(DEMAND, 0)):
            with self.assertRaisesRegex(RuntimeError, 'DISK_ALLOCATION_NOT_BACKED'):
                allocate_disk_demand(99, lambda _: None)
        with patch.object(os, 'posix_fallocate', side_effect=OSError(errno.ENOSPC, 'full')), \
                patch.object(os, 'fstat', return_value=metadata(DEMAND + 1)), patch.object(os, 'write') as write:
            with self.assertRaisesRegex(RuntimeError, 'DISK_PARTIAL_ALLOCATION_INVALID'):
                allocate_disk_demand(99, lambda _: None)
            write.assert_not_called()

    def test_unsupported_unexpected_and_fallback_errors_cannot_become_exhaustion(self):
        for error in (AttributeError('not provided'), OSError(errno.ENOSYS, 'unsupported'),
                      OSError(errno.EOPNOTSUPP, 'unsupported'), OSError(errno.EIO, 'unexpected')):
            with self.subTest(error=type(error).__name__), \
                    patch.object(os, 'posix_fallocate', side_effect=error), patch.object(os, 'write') as write:
                if isinstance(error, OSError) and error.errno == errno.EIO:
                    with self.assertRaises(OSError) as caught:
                        allocate_disk_demand(99, lambda _: None)
                    self.assertIs(caught.exception, error)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'DISK_ALLOCATION_UNSUPPORTED'):
                        allocate_disk_demand(99, lambda _: None)
                write.assert_not_called()
        error = OSError(errno.EIO, 'unexpected fallback error')
        with patch.object(os, 'posix_fallocate', side_effect=OSError(errno.ENOSPC, 'full')), \
                patch.object(os, 'fstat', return_value=metadata(0, 0)), patch.object(os, 'lseek'), \
                patch.object(os, 'write', side_effect=error):
            with self.assertRaises(OSError) as caught:
                allocate_disk_demand(99, lambda _: None)
            self.assertIs(caught.exception, error)
