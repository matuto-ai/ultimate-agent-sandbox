"""Canonical Manager/Supervisor/SQLite with controlled resource reads, not host proof."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_manager_lifecycle as fixtures
from uas.docker_fixture import DockerFixtureBackend
from uas.host_capacity import (CapacityReport, HostCapacityScenario, DockerCapacityObserver,
    CYCLES, MAX_RECORD, MAX_RECORDS, MAX_REPORT, STATS_FORMAT, pair)
from uas.lifecycle import LifecycleError, BackendUnknown


class HostCapacityTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.ManagerLifecycleTests(); self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.original = self.case.backend
        self.backend = DockerFixtureBackend(timeout=1)
        for name in ('create', 'start', 'stop', 'admit', 'name'):
            setattr(self.backend, name, getattr(self.original, name))
        self.backend.inspect = self.inspect
        self.backend._run = Mock(side_effect=self.read)
        self.case.supervisor.backend = self.backend
        self.container = 'd' * 64
        self.report = self.case.root / 'capacity.jsonl'
        self.commands = []
        self.mutate_read = lambda: None
        self.clock = patch('uas.host_capacity.time.monotonic', return_value=1)
        self.clock.start(); self.addCleanup(self.clock.stop)

    def inspect(self, state, kind):
        row = self.original.inspect(state, kind)
        if row is not None and kind == 'container': row['id'] = self.container
        return row

    def read(self, argv):
        self.commands.append(argv)
        self.mutate_read()
        if argv == ['stats', '--no-stream', '--format', STATS_FORMAT, self.container]:
            return json.dumps({'cpu': '12.50%', 'memory': '1.5MiB / 64MiB', 'pids': '3', 'block_io': '1kB / 2kB'})
        self.assertEqual(argv, ['inspect', '--size', '--type', 'container', '--format', '{{json .SizeRw}}', self.container])
        return '2048'

    def scenario(self, **options):
        return HostCapacityScenario(self.case.supervisor, self.case.spec, self.case.ledger, self.report,
            session=self.case.session, deadline=10000, candidate_sha='a' * 40, workload_id='controlled-test', **options)

    def records(self):
        return [json.loads(line) for line in self.report.read_text().splitlines()]

    def test_all100_actual_canonical_cycles_and_reports_never_qualify_fixture(self):
        self.case.project.joinpath('human-data').write_text('preserve')
        scenario = self.scenario(); result = scenario.run()
        self.assertEqual(result['collection'], 'complete', result)
        self.assertEqual(result['cycles_completed'], 100)
        self.assertEqual(result['qualification'], 'unqualified'); self.assertIsNone(result['defaults'])
        self.assertIn('qualified-puglab-production-backend', result['missing'])
        self.assertEqual(self.original.calls.count('stop'), 100)
        self.assertEqual(self.original.calls.count('start'), 101)  # initial fixture start
        rows = self.records(); self.assertEqual(len(rows), 503)
        self.assertEqual(len([r for r in rows if r['kind'] == 'cycle']), CYCLES)
        self.assertEqual(rows[1]['sample']['memory_used_bytes'], 1572864)
        self.assertEqual(rows[-2]['sample']['process_count'], 3)
        self.assertEqual(self.case.project.joinpath('human-data').read_text(), 'preserve')
        self.assertFalse(any(c.startswith('remove') for c in self.original.calls))
        with self.assertRaisesRegex(LifecycleError, 'CAPACITY_ALREADY_STARTED'): scenario.run()

    def test_intent_is_durable_and_exact_before_each_owner_effect(self):
        original = self.case.supervisor.manager_action
        def execute(value, **kwargs):
            record = self.records()[-1]
            self.assertEqual(record['kind'], 'intent')
            self.assertEqual(record['request'], value)
            if value['action'] == 'start': self.case.connected = False
            return original(value, **kwargs)
        self.case.supervisor.manager_action = execute
        result = self.scenario().run()
        self.assertEqual(result['collection'], 'failed')
        self.assertEqual(result['reason'], 'CAPACITY_OWNER_DENIED')
        self.assertEqual(self.original.calls.count('stop'), 1)
        self.assertEqual(self.original.calls.count('start'), 1)
        self.assertEqual(self.case.supervisor._read()['phase'], 'stopped')

    def test_unknown_stop_keeps_pending_and_does_not_replay_or_cleanup(self):
        self.original.revoke_verified = False
        result = self.scenario().run()
        self.assertEqual(result['collection'], 'unknown')
        self.assertEqual(result['pending']['action'], 'stop')
        self.assertEqual(result['cycles_completed'], 0)
        self.assertEqual(len([r for r in self.records() if r['kind'] == 'intent']), 1)
        self.assertEqual(self.original.calls.count('start'), 1)
        self.assertFalse(any(c.startswith('remove') for c in self.original.calls))

    def test_replaced_instance_between_view_and_action_has_no_foreign_effect(self):
        original = self.case.supervisor.manager_action
        def race(value, **kwargs):
            state = self.case.supervisor._read(); state['instance_id'] = 'e' * 32
            self.case.supervisor._save(state)
            return original(value, **kwargs)
        self.case.supervisor.manager_action = race
        before = list(self.original.calls)
        result = self.scenario().run()
        self.assertEqual(result['reason'], 'CAPACITY_OWNER_DENIED')
        self.assertEqual(self.original.calls, before)

    def test_staged_spec_between_snapshot_and_view_is_not_adopted_by_start(self):
        original = self.case.supervisor.manager_view
        def changed(**kwargs):
            state = self.case.supervisor._read()
            if state['phase'] == 'stopped':
                state['pending_spec'] = deepcopy(state['spec'])
                state['pending_spec']['profile_digest'] = 'sha256:' + 'f' * 64
                self.case.supervisor._save(state)
            return original(**kwargs)
        self.case.supervisor.manager_view = changed
        result = self.scenario().run()
        self.assertEqual(result['reason'], 'CAPACITY_LIFECYCLE_CHANGED')
        self.assertEqual(self.original.calls.count('stop'), 1)
        self.assertEqual(self.original.calls.count('start'), 1)
        self.assertEqual(len([r for r in self.records() if r['kind'] == 'intent']), 1)
        self.assertEqual(self.case.supervisor._read()['phase'], 'stopped')

    def test_report_fsync_failure_prevents_lifecycle_effect(self):
        before = list(self.original.calls)
        with patch('uas.host_capacity.os.fsync', side_effect=OSError('unavailable')):
            with self.assertRaises(OSError): self.scenario().run()
        self.assertEqual(self.original.calls, before)
        self.assertTrue(self.report.exists())

    def test_file_fsync_failure_after_directory_durability_still_prevents_effect(self):
        original = os.fsync
        calls = []
        def fail_file(fd):
            calls.append(fd)
            if len(calls) > 1: raise OSError('unavailable')
            return original(fd)
        before = list(self.original.calls)
        with patch('uas.host_capacity.os.fsync', side_effect=fail_file): result = self.scenario().run()
        self.assertEqual(result['collection'], 'failed')
        self.assertEqual(self.original.calls, before)
        self.assertEqual(len(calls), 2)

    def test_stats_owner_change_and_invalid_metric_abort_before_stop(self):
        self.mutate_read = lambda: setattr(self, 'container', 'e' * 64)
        result = self.scenario().run()
        self.assertEqual(result['collection'], 'failed')
        self.assertEqual(self.original.calls.count('stop'), 0)

    def test_observer_failure_after_first_cycle_retains_previous_records(self):
        def fail_later():
            if self.original.calls.count('stop') == 1: raise BackendUnknown()
        self.mutate_read = fail_later
        result = self.scenario().run()
        self.assertEqual(result['cycles_completed'], 0)
        self.assertEqual(result['collection'], 'failed')
        self.assertEqual(self.original.calls.count('stop'), 1)
        self.assertEqual(len([r for r in self.records() if r['kind'] == 'effect-observed']), 2)

    def test_resource_identity_loss_after_confirmed_start_stops_next_cycle(self):
        original = self.backend.start
        def changed(state):
            original(state)
            self.container = 'f' * 64
        self.backend.start = changed
        result = self.scenario().run()
        self.assertEqual(result['reason'], 'CAPACITY_RETENTION_FAILED')
        self.assertEqual(self.original.calls.count('stop'), 1)
        self.assertEqual(self.original.calls.count('start'), 2)
        self.assertEqual(result['pending']['action'], 'start')

    def test_partial_report_intent_write_failure_does_not_start_effect(self):
        append = CapacityReport.append
        def failure(report, value):
            if value['kind'] == 'intent': raise OSError('report unavailable')
            return append(report, value)
        before = list(self.original.calls)
        with patch.object(CapacityReport, 'append', failure): result = self.scenario().run()
        self.assertEqual(self.original.calls, before)
        self.assertNotEqual(result['collection'], 'complete')

    def test_deadline_expiring_during_report_write_prevents_next_effect(self):
        append = CapacityReport.append
        now = [1]
        def expire(report, value):
            append(report, value)
            if value['kind'] == 'intent': now[0] = 10001
        before = list(self.original.calls)
        with patch('uas.host_capacity.time.monotonic', side_effect=lambda: now[0]), \
             patch.object(CapacityReport, 'append', expire):
            result = self.scenario().run()
        self.assertEqual(result['reason'], 'CAPACITY_DEADLINE')
        self.assertEqual(self.original.calls, before)
        self.assertEqual(len([r for r in self.records() if r['kind'] == 'intent']), 1)

    def test_existing_report_and_project_report_refuse_without_overwrite(self):
        self.report.write_text('human')
        before = list(self.original.calls)
        with self.assertRaises(FileExistsError): self.scenario().run()
        self.assertEqual(self.report.read_text(), 'human'); self.assertEqual(self.original.calls, before)
        with self.assertRaisesRegex(LifecycleError, 'CAPACITY_REPORT_IN_PROJECT'):
            CapacityReport(self.case.project / 'report', [str(self.case.project)])

    def test_report_bounds_identity_and_unsupported_owner_are_failclosed(self):
        report = CapacityReport(self.report, [])
        self.addCleanup(report.close)
        with self.assertRaisesRegex(LifecycleError, 'CAPACITY_REPORT_LIMIT'):
            report.append({'text': 'x' * MAX_RECORD})
        report.records = MAX_RECORDS
        with self.assertRaisesRegex(LifecycleError, 'CAPACITY_REPORT_LIMIT'): report.append({})
        report.records = 0; report.bytes = MAX_REPORT
        with self.assertRaisesRegex(LifecycleError, 'CAPACITY_REPORT_LIMIT'): report.append({})
        report.bytes = 0
        self.report.unlink(); self.report.write_text('replacement')
        with self.assertRaisesRegex(LifecycleError, 'CAPACITY_REPORT_CHANGED'): report.append({})
        self.case.supervisor.backend = self.original
        with self.assertRaisesRegex(LifecycleError, 'CAPACITY_OWNER_REQUIRED'): self.scenario()

    def test_deadline_never_starts_an_observation_without_its_timeout_budget(self):
        observer = DockerCapacityObserver(self.case.supervisor, deadline=1.5)
        with self.assertRaisesRegex(LifecycleError, 'CAPACITY_DEADLINE'): observer.call(['stats'])
        self.backend._run.assert_not_called()
        with self.assertRaises(LifecycleError): pair('secret text')
