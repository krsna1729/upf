# SPDX-License-Identifier: BSD-3-Clause
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('txtrace', Path(__file__).with_name('trace-transactions.py'))
txtrace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(txtrace)


class TraceJoinTest(unittest.TestCase):
    def test_missing_switch_does_not_extend_reported_thread_state(self):
        switch_in = 'bessd 20/21 [006] 1.000000001: sched:sched_switch: prev_pid=0 prev_state=R next_pid=21'
        switch_out = 'bessd 20/21 [006] 1.000000004: sched:sched_switch: prev_pid=21 prev_state=S next_pid=0'
        lost_record = 'bessd 20/21 [006] 1.000000003: PERF_RECORD_LOST lost 2'
        meta = dict(upfd=10, bessd=20, group='markers')
        for lines, want in (
            ([switch_in, switch_out], [(1000000001, 1000000004, 'running', '')]),
            ([switch_in, lost_record, switch_out], []),
        ):
            _, switches, wakes, names, lost = txtrace.read_perf(lines, meta)
            states = txtrace.kernel_intervals(switches, wakes, names, lost)
            self.assertEqual(states.get(21, []), want)

    def test_final_sync_without_clock_measurement_ends_window(self):
        offset, drift, anchors, _, _, bounds = txtrace.read_go([
            'M=-1 P=-1 G=-1 Sync Time=100 N=1 Trace=110 Mono=127 Wall=ignored',
            'M=-1 P=-1 G=-1 Sync Time=200 N=2',
        ])
        self.assertEqual([bounds[0] + offset, bounds[-1] + offset], [117, 217])
        self.assertEqual((anchors, drift), (1, 0))

    def test_interleaved_frames_keep_each_batch_slot(self):
        a, b, c = ('%032x' % i for i in (1, 2, 3))
        go = [(11, 100, 1, 'send', f'{a} 1 0 {a}'), (12, 100, 1, 'send', f'{a} 1 1 {b}'),
              (13, 100, 2, 'send', f'{c} 1 0 {c}'), (26, 100, 2, 'reply', f'{c} 1 0 {c}'),
              (40, 101, 1, 'reply', f'{a} 1 0 {a}'), (41, 101, 1, 'reply', f'{a} 1 1 {b}')]

        def server(lead, tid, times, second=()):
            stages = ('frame_read', 'lock_request', 'lock_acquired', 'apply_enter',
                      'apply_leave', 'lock_release', 'write_enter')
            return [(t, tid, k, lead, 1, 0) for t, k in zip(times, stages)] + [
                (t, tid, k, lead, 1, 1) for t, k in zip(second, ('apply_enter', 'apply_leave'))]

        bess = server(a, 201, (21, 22, 24, 27, 29, 34, 35), (31, 33)) + server(c, 202, range(14, 21))
        rows, skipped, frames, _ = txtrace.join(go, bess, 0, 42)
        self.assertEqual([(r['request'], r['server_tid'], r['points']['apply_enter']) for r in rows],
                         [(a, 201, 27), (b, 201, 31), (c, 202, 17)])
        self.assertEqual(frames, 2)
        self.assertFalse(skipped)

        bess.append((23, 203, 'frame_read', a, 1, 2))  # same ID/attempt on a reopened stream
        rows, skipped, *_ = txtrace.join(go, bess, 0, 42)
        self.assertEqual([r['request'] for r in rows], [c])
        self.assertEqual(skipped['duplicate or incomplete server attempt'], 2)


if __name__ == '__main__':
    unittest.main()
