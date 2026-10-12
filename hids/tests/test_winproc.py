"""One-call Windows process snapshot used by the process sensor."""
import os
import unittest

import psutil

from hids import process_monitor, winproc


class TestCpuSampler(unittest.TestCase):
    def test_first_reading_is_zero_then_share_of_one_core(self):
        sampler = winproc.CpuSampler()
        proc = winproc.ProcSnapshot(10, 1, "a.exe", 100.0, 5.0, 0)
        self.assertEqual(sampler.sample([proc], now=1000.0), {(10, 100.0): 0.0})
        later = proc._replace(cpu_time=6.0)
        self.assertAlmostEqual(sampler.sample([later], now=1002.0)[(10, 100.0)], 50.0)

    def test_reused_pid_starts_over(self):
        sampler = winproc.CpuSampler()
        sampler.sample([winproc.ProcSnapshot(10, 1, "a.exe", 100.0, 5.0, 0)], now=1000.0)
        reused = winproc.ProcSnapshot(10, 1, "b.exe", 200.0, 9.0, 0)
        self.assertEqual(sampler.sample([reused], now=1001.0), {(10, 200.0): 0.0})


@unittest.skipUnless(winproc.available(), "Windows only")
class TestSnapshot(unittest.TestCase):
    def test_own_process_matches_psutil(self):
        me = psutil.Process()
        own = [p for p in winproc.SnapshotReader().read() if p.pid == os.getpid()]
        self.assertEqual(len(own), 1)
        self.assertEqual(own[0].ppid, me.ppid())
        self.assertEqual(own[0].name.lower(), me.name().lower())
        self.assertAlmostEqual(own[0].create_time, me.create_time(), places=2)
        self.assertGreater(own[0].rss, 0)

    def test_scan_rows_have_the_psutil_shape(self):
        rows = process_monitor.scan()
        self.assertGreater(len(rows), 10)
        own = next(r for r in rows if r["pid"] == os.getpid())
        self.assertEqual(set(own), {"pid", "ppid", "name", "create_time", "cpu_percent", "memory_mb"})
        self.assertEqual(own["create_time"], round(psutil.Process().create_time(), 3))


if __name__ == "__main__":
    unittest.main()
