"""Actual official Pi -> kernel-bound channel -> sanitized durable Forge reads.

Account-free controlled GitHub responses. This is same-UID fixture integration,
not live credentials, production Broker isolation, Run admission or human merge.
"""
from dataclasses import replace
import json
import hashlib
import os
import select
import sqlite3
import time
import threading
import unittest
from unittest.mock import patch

import test_pi_participant as harness
from uas.context import FixtureRun, FixtureRunTerminal
from uas.peer import Message, Readiness, WorkRequest
from uas.forge import ForgeBinding, ReadOnlyForgeBroker
from uas.github_read import GitHubProject, GitHubReadProvider, ProviderFailure, ProviderResponse
from uas.ledger import LedgerError, RoomLedger
from uas.lifecycle import Supervisor
from uas.participant import FixtureCredentials


@unittest.skipUnless(harness.INSTALL, 'Set UAS_PI_INSTALL for required actual Pi Forge integration')
class PiForgeTests(unittest.TestCase):
    recipe = harness.PiParticipantTests.recipe
    start = harness.PiParticipantTests.start
    tearDown = harness.PiParticipantTests.tearDown
    receive = harness.PiParticipantTests.receive
    idle = harness.PiParticipantTests.idle

    def setUp(self):
        harness.PiParticipantTests.setUp(self)
        self.seat = replace(self.seat, capabilities=('peer-traffic', 'forge-read'))
        self.calls, self.actors = [], []
        self.fail_provider = False
        self.provider = GitHubReadProvider(GitHubProject('owner/repo'), self.transport)
        self.broker = ReadOnlyForgeBroker(self.ledger,
            ForgeBinding('alpha', 'fixture', 'owner/repo'), self.select_provider)
        self.controller.bind_forge(self.broker)

    def issue(self, number, state='open'):
        base = 'https://api.github.com/repos/owner/repo'
        return {'id': 1000 + number, 'number': number, 'state': state,
                'repository_url': base, 'url': base + '/issues/' + str(number),
                'assignees': [{'id': 41, 'login': 'actor-p', 'email': 'not-persisted@example.invalid'}],
                'title': 'untrusted title do not persist', 'body': 'SECRET_RAW_RESPONSE_SENTINEL'}

    def transport(self, path):
        self.calls.append(path)
        if self.fail_provider:
            raise ProviderFailure('TIMEOUT')
        if path == 'repos/owner/repo/issues/66':
            value = self.issue(66)
        elif path == 'repos/owner/repo/issues/66/dependencies/blocked_by?per_page=100&page=1':
            value = [self.issue(58, 'closed')]
        else:
            raise AssertionError('unexpected provider route')
        return ProviderResponse(200, json.dumps(value).encode(), {})

    def select_provider(self, actor):
        self.actors.append(actor)
        return self.provider

    def invoke(self, operation='read-66', argv=None):
        self.native.rpc('prompt', message='/fixture-forge-tools ' + harness.encoded([
            {'id': operation, 'argv': argv if argv is not None else ['issue', 'view', '66']}]))
        self.native.rpc('prompt', message='Invoke the configured read-only GitHub tool.')
        result = self.receive()
        self.idle()
        return result

    def test_actual_pi_pr_and_submitted_review_observation_is_not_a_verdict(self):
        # Defined for ordinary CI only where the existing native opt-in is set.
        # The local restricted development gate does not execute this test.
        from test_github_pr import pull, review, response
        def transport(path):
            self.calls.append(path)
            return response([review(number=66, repository='owner/repo')]
                            if '/reviews?' in path else pull(number=66, repository='owner/repo'))
        self.provider = GitHubReadProvider(GitHubProject('owner/repo'), transport)
        self.start()
        first = self.invoke('pr-66', ['pr', 'view', '66'])
        self.assertTrue(first['ok'])
        result = first['receipt']
        self.assertEqual('OK', result['observation']['status'])
        self.assertEqual('not-evaluated', result['admission'])
        self.assertEqual('APPROVED', result['observation']['reviews'][0]['state'])
        self.assertNotIn('verdict', result['observation'])
        self.assertNotIn('runs', self.ledger.snapshot()['state'])
        self.assertEqual(result, self.invoke('pr-66', ['pr', 'view', '66'])['receipt'])
        self.assertEqual(3, len(self.calls))
        self.assertNotIn('SECRET', json.dumps(self.ledger.replay(0)))
        tool = [e for e in self.native.event_snapshot() if e.get('type') == 'tool_execution_end'][-1]
        self.assertFalse(tool['isError'])

    def test_actual_pi_read_observation_is_sanitized_durable_and_retry_stable(self):
        handle = self.start()
        first = self.invoke()
        self.assertTrue(first['ok'])
        result = first['receipt']
        self.assertEqual('not-evaluated', result['admission'])
        self.assertEqual('complete', result['observation']['completeness'])
        self.assertEqual('OK', result['observation']['status'])
        self.assertEqual([{'id': 1058, 'number': 58, 'state': 'closed'}], result['observation']['dependencies'])
        self.assertEqual([{'id': 41, 'login': 'actor-p'}], result['observation']['issue']['assignees'])
        self.assertEqual(['actor-p'], self.actors)
        self.assertEqual(2, len(self.calls))
        retry = self.invoke()
        self.assertEqual(result, retry['receipt'])
        self.assertEqual(2, len(self.calls))
        events = [event for event in self.ledger.replay(0) if event['kind'].startswith('forge-read-')]
        self.assertEqual(['forge-read-started', 'forge-read-observed'], [event['kind'] for event in events])
        self.assertTrue(all(event['origin'] == handle.badge.origin().canonical() for event in events))
        self.assertTrue(any(event.get('type') == 'tool_execution_start' and event.get('toolName') == 'gh'
                            for event in self.native.event_snapshot()))
        with RoomLedger(self.root / 'room.db', 'alpha') as reopened:
            self.assertEqual(self.ledger.snapshot(), reopened.snapshot())
            persisted = json.dumps(reopened.replay(0)) + json.dumps(reopened.snapshot())
        self.assertNotIn('SECRET_RAW_RESPONSE_SENTINEL', persisted)
        self.assertNotIn('not-persisted@example.invalid', persisted)
        self.assertNotIn('untrusted title', persisted)

    def test_actual_pi_unsupported_write_path_endpoint_and_cross_target_never_contact_provider(self):
        self.start()
        # Mutation routing now identifies edits as writes, even when their
        # arguments are incomplete. A read-only binding rejects the write;
        # it must not relabel that attempt as a successful read observation.
        denied_write = self.invoke('denied-write', ['issue', 'edit', '66'])
        self.assertFalse(denied_write['ok'])
        self.assertEqual('FORGE_WRITE_UNAVAILABLE', denied_write['error'])
        self.assertNotIn('receipt', denied_write)
        self.assertEqual([], self.calls)
        self.assertEqual([], self.actors)
        attempts = [
            ['api', 'repos/owner/repo/issues/66'],
            ['issue', 'view', '../66'], ['issue', 'view', '66', '--repo', 'other/repo'],
            ['issue', 'view', '66', '--hostname', 'attacker.invalid'],
            ['auth', 'token'], ['run', 'watch', '66'],
        ]
        for index, argv in enumerate(attempts):
            result = self.invoke('denied-' + str(index), argv)
            self.assertTrue(result['ok'])  # durable denial receipt, not successful read
            self.assertEqual('unknown', result['receipt']['observation']['completeness'])
            self.assertNotEqual('OK', result['receipt']['observation']['status'])
        self.assertEqual([], self.calls)
        self.assertEqual([], self.actors)
        persisted = json.dumps(self.ledger.snapshot()) + json.dumps(self.ledger.replay(0))
        self.assertNotIn('attacker.invalid', persisted)
        self.assertNotIn('../66', persisted)
        self.assertNotIn('other/repo', persisted)

    def test_actual_pi_read_deadline_does_not_inherit_short_peer_deadline(self):
        self.start()
        transport = self.transport
        def delayed(path):
            if '/dependencies/' not in path:
                time.sleep(2.2)
            return transport(path)
        self.provider = GitHubReadProvider(GitHubProject('owner/repo'), delayed)
        result = self.invoke('slow-read')
        self.assertTrue(result['ok'])
        self.assertEqual('complete', result['receipt']['observation']['completeness'])
        tool = [e for e in self.native.event_snapshot() if e.get('type') == 'tool_execution_end'][-1]
        self.assertFalse(tool['isError'])

    def test_actual_pi_timeout_remains_unknown_and_exact_retry_does_not_repeat_provider(self):
        self.start()
        self.fail_provider = True
        first = self.invoke('timeout')
        self.assertEqual('unknown', first['receipt']['observation']['completeness'])
        self.assertEqual('TIMEOUT', first['receipt']['observation']['status'])
        self.fail_provider = False
        self.assertEqual(first['receipt'], self.invoke('timeout')['receipt'])
        self.assertEqual(1, len(self.calls))

    def test_actual_pi_pagination_limit_is_incomplete_and_never_admission(self):
        self.start()
        def page_limited(path):
            self.calls.append(path)
            value = self.issue(66) if '/dependencies/' not in path else [self.issue(n) for n in range(100, 200)]
            return ProviderResponse(200, json.dumps(value).encode(), {})
        self.provider = GitHubReadProvider(GitHubProject('owner/repo'), page_limited, max_pages=1)
        result = self.invoke('page-limit')['receipt']
        self.assertEqual('incomplete', result['observation']['completeness'])
        self.assertEqual('PAGINATION_LIMIT', result['observation']['status'])
        self.assertEqual('not-evaluated', result['admission'])
        self.assertEqual(100, len(result['observation']['dependencies']))
        self.assertEqual(2, len(self.calls))

    def test_actual_pi_help_and_conflicting_operation_id_are_not_provider_retries(self):
        self.start()
        help_result = self.invoke('help', ['--help'])['receipt']
        self.assertEqual('HELP', help_result['observation']['status'])
        self.assertIn('gh issue view NUMBER', help_result['observation']['help'])
        self.assertEqual([], self.calls)
        self.assertTrue(self.invoke('exact')['ok'])
        conflict = self.invoke('exact', ['issue', 'view', '67'])
        self.assertFalse(conflict['ok'])
        self.assertEqual('ID_CONFLICT', conflict['error'])
        self.assertEqual(2, len(self.calls))

    def test_actual_pi_terminal_audit_failure_recovers_unknown_without_provider_replay(self):
        self.start()
        original = self.ledger._commit
        commits = []
        def fail_terminal():
            commits.append(True)
            if len(commits) == 2:
                raise sqlite3.OperationalError('account-free terminal audit failure')
            return original()
        with patch.object(self.ledger, '_commit', fail_terminal):
            failed = self.invoke('audit-failure')
        self.assertFalse(failed['ok'])
        self.assertEqual('AUDIT_UNAVAILABLE', failed['error'])
        self.assertEqual(2, len(self.calls))
        fenced = self.invoke('audit-failure')
        self.assertFalse(fenced['ok'])
        self.assertEqual('AUDIT_UNAVAILABLE', fenced['error'])
        # Trusted Broker reconstruction models recovery, not a client-driven
        # rebind. Fresh controller authority still guards the exact old request.
        rebuilt = ReadOnlyForgeBroker(self.ledger, self.broker.binding, self.select_provider)
        envelope = {'id': 'audit-failure', 'kind': 'forge-read', 'argv': ['issue', 'view', '66']}
        def retry():
            return rebuilt.submit(envelope, origin=self.handle.badge.origin(), authorize=lambda:
                self.controller._authority(self.handle, (self.handle.process.pid, os.getuid(), os.getgid())))
        recovered = retry()
        self.assertEqual('unknown', recovered['observation']['completeness'])
        self.assertEqual('INTERRUPTED_OBSERVATION', recovered['observation']['status'])
        self.assertEqual(2, len(self.calls))
        self.assertEqual(recovered, retry())

    def test_actual_pi_forged_identity_fields_rejected_before_provider_contact(self):
        self.start()
        packet = {'request_id': 'a' * 32, 'envelope': {
            'id': 'forged-identity', 'kind': 'forge-read', 'argv': ['issue', 'view', '66'],
            'actor_id': 'other-actor', 'room_id': 'sibling', 'project_id': 'other-project'}}
        self.native.rpc('prompt', message='/fixture-peer-probe ' + harness.encoded({
            'mode': 'raw', 'packet': harness.encoded(packet)}))
        result = self.receive()
        self.assertFalse(result['ok'])
        self.assertEqual('INVALID_FORGE_ENVELOPE', result['error'])
        self.assertEqual([], self.calls)
        self.assertEqual([], self.actors)
        self.assertNotIn('forge_observations', self.ledger.snapshot()['state'])
        persisted = json.dumps(self.ledger.replay(0))
        self.assertNotIn('other-actor', persisted)
        self.assertNotIn('other-project', persisted)

    def test_actual_pi_persisted_revocation_before_dispatch_prevents_provider_contact(self):
        self.start()
        self.native.rpc('prompt', message='/fixture-forge-tools ' + harness.encoded([
            {'id': 'revoked-read', 'argv': ['issue', 'view', '66']}]))
        self.native.rpc('prompt', message='Invoke the configured read-only GitHub tool.')
        self.assertTrue(select.select([self.handle.channel], [], [], 5)[0])
        # Commit the same authoritative fence used by revoke(), while retaining
        # the transport so this already queued record can receive its denial.
        with self.supervisor._locked():
            self.controller._fence(self.controller._read(), 'pi', 'revoked', 'explicit-revocation')
        self.assertEqual('revoked', self.controller.snapshot()['seats']['pi']['status'])
        result = self.receive()
        self.assertFalse(result['ok'])
        self.assertEqual('AUTHORITY_REVOKED', result['error'])
        self.assertEqual([], self.calls)
        self.assertEqual([], self.actors)
        self.assertNotIn('forge_observations', self.ledger.snapshot()['state'])
        denial = [event for event in self.ledger.replay(0) if event['kind'] == 'forge-record-denied']
        self.assertEqual({'code': 'AUTHORITY_REVOKED'}, denial[-1]['payload'])

    def test_same_room_wrong_project_bind_and_dispatch_cannot_select_authority(self):
        self.start()
        wrong = ReadOnlyForgeBroker(self.ledger, ForgeBinding('alpha', 'other-project', 'owner/repo'),
                                    self.select_provider)
        with self.assertRaises(LedgerError) as rejected:
            self.controller.bind_forge(wrong)
        self.assertEqual('PROJECT_MISMATCH', rejected.exception.code)
        original_binding = self.broker.binding
        self.broker.binding = replace(original_binding, project_id='other-project')
        try:
            rejected_dispatch = self.invoke('wrong-project-binding')
            self.assertFalse(rejected_dispatch['ok'])
            self.assertEqual('PROJECT_MISMATCH', rejected_dispatch['error'])
        finally:
            self.broker.binding = original_binding
        self.assertEqual([], self.calls)
        self.assertEqual([], self.actors)

    def test_current_project_manifest_drift_cannot_rebind_actual_pi_dispatch(self):
        self.start()
        # Current manifest drift cannot silently rebind the captured Project.
        with self.supervisor._locked():
            original_spec = self.supervisor._read()
            drifted = json.loads(json.dumps(original_spec))
            drifted['spec']['project_id'] = 'other-project'
            self.supervisor._save(drifted)
        try:
            rejected_drift = self.invoke('wrong-current-project')
            self.assertFalse(rejected_drift['ok'])
            self.assertEqual('PROJECT_MISMATCH', rejected_drift['error'])
        finally:
            with self.supervisor._locked():
                self.supervisor._save(original_spec)
        self.assertEqual([], self.calls)
        self.assertEqual([], self.actors)

    def test_actual_controller_replacement_recovers_eight_pending_without_contact_or_receipt_downgrade(self):
        self.start()
        old_handle = self.handle
        old_origin = old_handle.badge.origin()
        # A previously completed observation must not be downgraded by recovery.
        completed = self.invoke('committed-before-loss')['receipt']
        terminal_key = hashlib.sha256(b'alpha\0committed-before-loss').hexdigest()
        terminal_id = 'forge-terminal-' + terminal_key
        before_terminal = self.ledger.operation_receipt(terminal_id, old_origin, authorize=lambda: True)
        self.assertEqual(completed, before_terminal['result'])
        calls_before = list(self.calls)
        # Seven trusted starts plus one real Pi read interrupted at terminal
        # commit fill all pending slots. All bind actual process authority.
        with self.supervisor._locked():
            for index in range(7):
                self.broker.prepare({'id': 'interrupted-' + str(index), 'kind': 'forge-read',
                                     'argv': ['issue', 'view', '66']}, origin=old_origin,
                    authorize=lambda: self.controller._authority(old_handle,
                        (old_handle.process.pid, os.getuid(), os.getgid())))
        original_commit = self.ledger._commit
        commits = []
        def fail_terminal_commit():
            commits.append(True)
            if len(commits) == 2:
                raise sqlite3.OperationalError('controlled interrupted terminal commit')
            return original_commit()
        with patch.object(self.ledger, '_commit', fail_terminal_commit):
            interrupted = self.invoke('interrupted-7')
        self.assertFalse(interrupted['ok'])
        self.assertEqual('AUDIT_UNAVAILABLE', interrupted['error'])
        calls_before = list(self.calls)
        self.assertEqual(8, len(self.ledger.snapshot()['state']['forge_pending']))
        self.controller.close()
        self.assertIsNotNone(old_handle.process.poll())
        self.supervisor = Supervisor(self.root / 'control', 'alpha', self.backend,
                                     authorize=lambda *_: True, revoke=self.backend.revoke)
        self.controller = self.supervisor.participants(self.hub, FixtureCredentials())
        self.broker = ReadOnlyForgeBroker(self.ledger, ForgeBinding('alpha', 'fixture', 'owner/repo'),
                                         self.select_provider)
        self.controller.bind_forge(self.broker)
        self.assertEqual({}, self.ledger.snapshot()['state']['forge_pending'])
        self.assertEqual(calls_before, self.calls)
        abandoned = [event for event in self.ledger.replay(0) if event['kind'] == 'forge-read-abandoned']
        self.assertEqual(8, len(abandoned))
        self.assertTrue(all(event['origin'] == old_origin.canonical() for event in abandoned))
        self.assertTrue(all(event['payload']['observation'] == {
            'completeness': 'unknown', 'status': 'AUTHORITY_LOST',
            'controller_reason': 'CONTROLLER_REPLACED'} for event in abandoned))
        self.assertEqual(before_terminal,
                         self.ledger.operation_receipt(terminal_id, old_origin, authorize=lambda: True))
        self.start()
        self.assertNotEqual(old_handle.badge.incarnation_id, self.handle.badge.incarnation_id)
        self.assertTrue(self.invoke('new-incarnation-read')['ok'])
        calls_after_fresh_read = list(self.calls)
        conflicting = self.invoke('interrupted-0')
        self.assertFalse(conflicting['ok'])
        self.assertEqual('ID_CONFLICT', conflicting['error'])
        self.assertEqual(calls_after_fresh_read, self.calls)
        conflicting_terminal = self.invoke('committed-before-loss')
        self.assertFalse(conflicting_terminal['ok'])
        self.assertEqual('ID_CONFLICT', conflicting_terminal['error'])
        self.assertEqual(calls_after_fresh_read, self.calls)
        self.assertEqual(before_terminal,
                         self.ledger.operation_receipt(terminal_id, old_origin, authorize=lambda: True))

    def test_actual_pi_lost_terminal_commit_ack_survives_controller_replacement_unchanged(self):
        self.start()
        old_origin = self.handle.badge.origin()
        original_commit = self.ledger._commit
        commits = []
        def lose_terminal_ack():
            commits.append(True)
            original_commit()
            if len(commits) == 2:
                raise sqlite3.OperationalError('controlled lost terminal commit acknowledgement')
        with patch.object(self.ledger, '_commit', lose_terminal_ack):
            response = self.invoke('lost-commit-ack')
        self.assertFalse(response['ok'])
        self.assertEqual('AUDIT_UNAVAILABLE', response['error'])
        terminal_id = 'forge-terminal-' + hashlib.sha256(b'alpha\0lost-commit-ack').hexdigest()
        committed = self.ledger.operation_receipt(terminal_id, old_origin, authorize=lambda: True)
        self.assertEqual('complete', committed['result']['observation']['completeness'])
        self.assertEqual({}, self.ledger.snapshot()['state']['forge_pending'])
        calls_before = list(self.calls)
        old_handle = self.handle
        self.controller.close()
        self.assertIsNotNone(old_handle.process.poll())
        self.supervisor = Supervisor(self.root / 'control', 'alpha', self.backend,
                                     authorize=lambda *_: True, revoke=self.backend.revoke)
        self.controller = self.supervisor.participants(self.hub, FixtureCredentials())
        self.broker = ReadOnlyForgeBroker(self.ledger, ForgeBinding('alpha', 'fixture', 'owner/repo'),
                                         self.select_provider)
        self.controller.bind_forge(self.broker)
        self.assertEqual(calls_before, self.calls)
        self.assertEqual(committed, self.ledger.operation_receipt(terminal_id, old_origin, authorize=lambda: True))
        self.assertFalse(any(event['kind'] == 'forge-read-abandoned' for event in self.ledger.replay(0)))
        self.start()
        denied_retry = self.invoke('lost-commit-ack')
        self.assertFalse(denied_retry['ok'])
        self.assertEqual('ID_CONFLICT', denied_retry['error'])
        self.assertEqual(calls_before, self.calls)
        self.assertEqual(committed, self.ledger.operation_receipt(terminal_id, old_origin, authorize=lambda: True))

    def test_cross_room_broker_cannot_bind_to_actual_pi_controller(self):
        self.start()
        with RoomLedger(self.root / 'sibling.db', 'sibling') as other:
            broker = ReadOnlyForgeBroker(other, ForgeBinding('sibling', 'other-project', 'owner/other'),
                                         self.select_provider)
            with self.assertRaises(LedgerError) as rejected:
                self.controller.bind_forge(broker)
            self.assertEqual('ROOM_MISMATCH', rejected.exception.code)
        self.assertIs(self.broker, self.controller.forge_broker)
        self.assertEqual([], self.calls)
        self.assertEqual([], self.actors)

    def test_actual_pi_saturated_read_preserves_work_completion_and_native_reset(self):
        self.start()
        def command(identifier, action):
            return {'id': identifier, 'run_id': 'run-1', 'generation': 1, 'kind': 'command',
                    'payload': {'request_id': 'work', 'action': action, 'reason': None}}
        self.native.rpc('prompt', message='/fixture-tools ' + harness.encoded([command('accept', 'accept')]))
        self.hub.submit(self.sender, WorkRequest('work', 'run-1', 1, 'pi', 'Retain completion capacity.'))
        self.hub.observe(self.handle.connection, self.native.observe())
        self.assertEqual('CONFIRMED', self.hub.deliver(self.handle.connection)['outcome'])
        self.assertTrue(self.receive()['ok'])
        self.idle()
        saturated = []
        def full_transport(path):
            self.calls.append(path)
            if not saturated:
                self.assertEqual(1, len(self.ledger.snapshot()['state']['forge_pending']))
                for index in range(200):
                    try:
                        self.hub.submit(self.sender, Message('fill-' + str(index), 'run-1', 1,
                                                            'pi', 'x' * 16_384))
                    except LedgerError as error:
                        saturated.append(error.code)
                        break
                if not saturated:
                    raise AssertionError('queue did not saturate')
            if '/dependencies/' not in path:
                value = self.issue(66)
            else:
                page = int(path.rsplit('=', 1)[1])
                value = [self.issue(number) for number in range(100 + (page - 1) * 100, 100 + page * 100)]
            return ProviderResponse(200, json.dumps(value).encode(), {})
        self.provider = GitHubReadProvider(GitHubProject('owner/repo'), full_transport)
        result = self.invoke('large-observation')
        self.assertEqual(['QUEUE_CAPACITY_EXHAUSTED'], saturated)
        self.assertTrue(result['ok'])
        observation = result['receipt']['observation']
        self.assertEqual('incomplete', observation['completeness'])
        self.assertGreater(len(json.dumps(observation).encode()), 40_000)
        self.assertEqual({}, self.ledger.snapshot()['state']['forge_pending'])
        self.native.rpc('prompt', message='/fixture-tools ' + harness.encoded([command('complete', 'complete')]))
        self.native.rpc('prompt', message='Complete the accepted request.')
        self.assertTrue(self.receive()['ok'])
        self.idle()
        self.assertEqual('COMPLETED', self.hub._state()['traffic']['work']['status'])
        self.hub.contexts.close_run('close-run-1', 'run-1', FixtureRunTerminal.COMPLETED)
        self.hub.contexts.open_run('open-run-2', FixtureRun('run-2'))
        old = self.handle
        self.scope = {**self.scope, 'run_id': 'run-2', 'context_generation': 2}
        self.handle = self.controller.reset_pi('reset-after-saturation', self.seat, self.recipe(),
                         expected_context_generation=1, target_run=FixtureRun('run-2'))
        self.native = self.handle.connection.receiver
        self.assertIsNotNone(old.process.poll())
        self.assertEqual(2, self.hub.contexts.scope('pi')['context_generation'])
        self.assertIs(Readiness.SAFE, self.native.observe())

    def delayed_read_lifecycle_race(self, action):
        self.start()
        acquired = threading.Event()
        probe_threads = []
        lifecycle_results = []
        def transport(path):
            # Another lifecycle contender must acquire the actual file lock
            # while provider contact is still pending. It deliberately does not
            # touch the ledger's thread-owned SQLite connection.
            if not probe_threads:
                def probe():
                    with self.supervisor._locked():
                        acquired.set()
                worker = threading.Thread(target=probe)
                probe_threads.append(worker)
                worker.start()
                if not acquired.wait(.5):
                    raise ProviderFailure('TIMEOUT')
                worker.join(timeout=1)
                # Perform real revocation/Stop on the ledger-owning thread,
                # during the provider observation and before its result exists.
                if action == 'revoke':
                    self.controller.revoke('pi')
                    lifecycle_results.append(self.controller.snapshot()['seats']['pi']['status'])
                else:
                    lifecycle_results.append(self.supervisor.stop()['phase'])
            return self.transport(path)
        self.provider = GitHubReadProvider(GitHubProject('owner/repo'), transport)
        self.native.rpc('prompt', message='/fixture-forge-tools ' + harness.encoded([
            {'id': 'read-lifecycle-race', 'argv': ['issue', 'view', '66']}]))
        self.native.rpc('prompt', message='Invoke the configured read-only GitHub tool.')
        result = self.receive()
        for worker in probe_threads:
            worker.join(timeout=1)
            self.assertFalse(worker.is_alive(), 'lifecycle probe remained blocked')
        self.assertTrue(acquired.is_set(), 'provider contact held the lifecycle lock')
        self.assertEqual(['revoked' if action == 'revoke' else 'stopped'], lifecycle_results)
        self.assertIsNotNone(self.handle.process.poll())
        self.assertFalse(result['ok'])
        self.assertIn(result['error'], {'AUTHORITY_REVOKED', 'ROOM_NOT_RUNNING'})
        self.assertFalse(any(event['kind'] == 'forge-read-observed' for event in self.ledger.replay(0)),
                         'stale provider result published after authority revocation')
        self.assertEqual({}, self.ledger.snapshot()['state']['forge_pending'])
        abandoned = [event for event in self.ledger.replay(0) if event['kind'] == 'forge-read-abandoned']
        self.assertEqual(1, len(abandoned))
        self.assertEqual({'completeness': 'unknown', 'status': 'AUTHORITY_LOST',
                          'controller_reason': result['error']}, abandoned[0]['payload']['observation'])
        self.assertEqual(self.handle.badge.origin().canonical(), abandoned[0]['origin'])

    def test_actual_pi_delayed_provider_does_not_block_revoke_or_publish_stale_read(self):
        self.delayed_read_lifecycle_race('revoke')

    def test_actual_pi_delayed_provider_does_not_block_stop_or_publish_stale_read(self):
        self.delayed_read_lifecycle_race('stop')

    def test_actual_pi_wrong_process_fork_cannot_use_forge_authority(self):
        self.start()
        packet = {'request_id': 'a' * 32, 'envelope': {
            'id': 'forged-fork', 'kind': 'forge-read', 'argv': ['issue', 'view', '66']}}
        before = self.ledger.snapshot()
        self.native.rpc('prompt', message='/fixture-peer-probe ' + harness.encoded({
            'mode': 'fork', 'packet': harness.encoded(packet)}))
        result = self.receive()
        self.assertFalse(result['ok'])
        self.assertEqual('WRONG_PROCESS', result['error'])
        self.assertEqual([], self.calls)
        # No untrusted actor fields or provider observation enter the Room state.
        self.assertEqual(before['state'], self.ledger.snapshot()['state'])
        denial = self.ledger.replay(before['room_seq'])
        self.assertEqual(1, len(denial))
        self.assertEqual('forge-record-denied', denial[0]['kind'])
        self.assertEqual({'code': 'WRONG_PROCESS'}, denial[0]['payload'])
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if 'WRONG_PROCESS' in str(self.native.event_snapshot()):
                break
            time.sleep(.01)
        self.assertIn('WRONG_PROCESS', str(self.native.event_snapshot()))
