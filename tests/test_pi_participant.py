"""Actual official Pi tools through Supervisor-owned PID/pidfd/SEQPACKET.

Same-UID Linux fixture evidence, not production Workstation/credential isolation.
"""
import base64
from dataclasses import replace
import json
import os
from pathlib import Path
import select
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

from lifecycle_support import FileFixtureBackend
from uas.ledger import LedgerError, RoomLedger
from uas.lifecycle import FixtureSpec, Supervisor
from uas.participant import FixtureCredentials, FixtureSeat
from uas.peer import FixtureParticipant, FixturePeerHub, Readiness, WorkRequest
from uas.pi_fixture import FixturePiRecipe
from uas.pi_runtime import NativeUnavailable

ROOT = Path(__file__).resolve().parents[1]
INSTALL = os.environ.get('UAS_PI_INSTALL')


def encoded(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode()


@unittest.skipUnless(INSTALL, 'Set UAS_PI_INSTALL for mandatory actual Pi authority CI')
class PiParticipantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='uas-pi-authority-')
        self.root = Path(self.temp.name)
        self.project = self.root / 'project'
        self.project.mkdir()
        self.backend = FileFixtureBackend(self.root / 'resources')
        self.spec = FixtureSpec('alpha', 'fixture', (str(self.project),), *['sha256:' + c * 64 for c in 'abc'])
        self.supervisor = Supervisor(self.root / 'control', 'alpha', self.backend,
                                     authorize=lambda *_: True, revoke=self.backend.revoke)
        self.supervisor.start(self.spec)
        self.ledger = RoomLedger(self.root / 'room.db', 'alpha')
        self.hub = FixturePeerHub(self.ledger)
        self.hub.configure('configure', (FixtureParticipant('sender', 'actor-s'), FixtureParticipant('pi', 'actor-p')), 'run-1')
        self.sender = self.hub.connect('sender', 'sender', 'sender-inc', object())
        self.controller = self.supervisor.participants(self.hub, FixtureCredentials())
        self.seat = FixtureSeat('pi', 'actor-p', 'pi-account-free', ('peer-traffic',), runtime='pi-fixture')
        self.scope = {'room_id': 'alpha', 'participant_id': 'pi', 'run_id': 'run-1', 'generation': 1, 'context_generation': 1}
        self.handle = None

    def recipe(self, session=None):
        return FixturePiRecipe(INSTALL, self.root / 'native', scope=self.scope, session=session)

    def start(self, session=None):
        self.handle = self.controller.launch_pi(self.seat, self.recipe(session))
        self.native = self.handle.connection.receiver
        return self.handle

    def tearDown(self):
        try:
            if self.handle and os.environ.get('UAS_PI_EVIDENCE') and not self.native._closed:
                row = {'case': self.id(), **self.native.evidence(),
                       'authority': 'linux-same-uid-fixture-scm-credentials-and-held-pidfd',
                       'pid': self.handle.process.pid, 'badge': self.handle.badge.origin().canonical()}
                with open(os.environ['UAS_PI_EVIDENCE'], 'a') as output:
                    output.write(json.dumps(row, sort_keys=True) + '\n')
        finally:
            self.controller.close()
            self.ledger.close()
            self.temp.cleanup()

    def command(self, id, action):
        return {'id': id, 'run_id': 'run-1', 'generation': 1, 'kind': 'command',
                'payload': {'request_id': 'work', 'action': action, 'reason': None}}

    def message(self, id='message'):
        return {'id': id, 'run_id': 'run-1', 'generation': 1, 'kind': 'message',
                'payload': {'recipient': 'sender', 'text': 'Pi native peer output', 'parent_id': None}}

    def script(self, envelopes):
        self.native.rpc('prompt', message='/fixture-tools ' + encoded(envelopes))

    def receive(self):
        self.assertTrue(select.select([self.handle.channel], [], [], 5)[0], 'Pi did not send native peer tool record')
        return self.controller.receive(self.handle)

    def idle(self):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.native.observe() is Readiness.SAFE:
                return
            time.sleep(.01)
        self.fail('native Pi did not settle: ' + repr(self.native.event_snapshot()[-8:]))

    def deliver(self):
        self.hub.observe(self.handle.connection, self.native.observe())
        return self.hub.deliver(self.handle.connection)

    def test_first_work_native_tools_accept_complete_with_exact_supervisor_origin(self):
        handle = self.start()
        self.assertIs(handle.process, self.native.process)
        self.assertNotEqual(handle.badge.incarnation_id, self.native.initial_state['runtime_id'])
        self.assertEqual(handle.badge.incarnation_id, self.native.incarnation_id)
        self.assertTrue(self.controller._alive(handle))
        self.assertFalse(Path(self.native.initial_state['session_file']).exists())
        self.script([self.command('accept', 'accept'), self.command('complete', 'complete')])
        self.hub.submit(self.sender, WorkRequest('work', 'run-1', 1, 'pi', 'Do this account-free fixture work.'))
        self.assertEqual('CONFIRMED', self.deliver()['outcome'])
        self.assertEqual('DELIVERED', self.hub._state()['traffic']['work']['status'])
        self.assertTrue(self.receive()['ok'])
        self.assertEqual('ACCEPTED', self.hub._state()['traffic']['work']['status'])
        self.assertTrue(self.receive()['ok'])
        self.idle()
        self.assertEqual('COMPLETED', self.hub._state()['traffic']['work']['status'])
        events = [e for e in self.ledger.replay(0) if e['operation_id'] in ('accept', 'complete')]
        self.assertEqual(2, len(events))
        self.assertTrue(all(e['origin'] == handle.badge.origin().canonical() for e in events))
        native_events = self.native.event_snapshot()
        self.assertTrue(any(e.get('type') == 'tool_execution_start' and e.get('toolName') == 'uas_peer' for e in native_events))
        entries = self.native.rpc('get_entries')['data']['entries']
        self.assertEqual(1, sum(e.get('customType') == 'uas-peer-v1' for e in entries))

    def test_same_uid_node_fork_and_scm_rights_handoff_have_no_badge_authority(self):
        self.start()
        before = self.ledger.snapshot()
        for mode in ('fork', 'handoff'):
            packet = {'request_id': 'a' * 32, 'envelope': self.message(mode)}
            self.native.rpc('prompt', message='/fixture-peer-probe ' + encoded({'mode': mode, 'packet': encoded(packet)}))
            result = self.receive()
            self.assertFalse(result['ok'])
            self.assertEqual('WRONG_PROCESS', result['error'])
            self.assertEqual(before, self.ledger.snapshot())
            # Let the child consume its own denial before the Pi tool uses the
            # same descriptor. FD handoff can steal replies/DoS, never identity.
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                notifications = []
                for event in self.native.event_snapshot():
                    if event.get('type') == 'extension_ui_request' and event.get('method') == 'notify':
                        try:
                            item = json.loads(event['message'])
                            if item.get('fixture_probe') and item.get('mode') == mode:
                                notifications.append(item['data'])
                        except (KeyError, ValueError):
                            pass
                text = ''.join(notifications)
                if 'WRONG_PROCESS' in text:
                    break
                time.sleep(.01)
            self.assertIn('WRONG_PROCESS', text)
            sent = next(json.loads(line) for line in text.splitlines() if '"sent"' in line)
            self.assertNotEqual(self.handle.process.pid, sent['pid'])
        self.script([self.message('parent-still-valid')])
        self.native.rpc('prompt', message='Send the configured peer message.')
        self.assertTrue(self.receive()['ok'])
        self.idle()
        event = next(e for e in self.ledger.replay(0) if e['operation_id'] == 'parent-still-valid')
        self.assertEqual(self.handle.badge.origin().canonical(), event['origin'])

    def test_same_run_restore_retains_responsibility_new_badge_and_stale_rpc_denial(self):
        old = self.start()
        old_native = self.native
        self.script([self.command('accept', 'accept')])
        self.hub.submit(self.sender, WorkRequest('work', 'run-1', 1, 'pi', 'Retain this responsibility.'))
        self.deliver()
        self.assertTrue(self.receive()['ok'])
        self.idle()
        session = self.native.initial_state['session_file']
        self.controller.revoke('pi')
        self.assertIsNotNone(old.process.poll())
        with self.assertRaises(NativeUnavailable):
            old_native.rpc('get_state')
        new = self.start(session)
        self.assertNotEqual(old.badge.incarnation_id, new.badge.incarnation_id)
        self.assertEqual(old.badge.epoch + 2, new.badge.epoch)
        self.assertEqual('HELD', self.hub.deliver(old.connection)['outcome'])
        self.assertEqual('ACCEPTED', self.hub._state()['traffic']['work']['status'])
        self.assertEqual('CONFIRMED', self.deliver()['outcome'])
        self.script([self.command('complete-after-restore', 'complete')])
        self.native.rpc('prompt', message='Complete the retained responsibility.')
        self.assertTrue(self.receive()['ok'])
        self.idle()
        self.assertEqual('COMPLETED', self.hub._state()['traffic']['work']['status'])
        entries = self.native.rpc('get_entries')['data']['entries']
        self.assertEqual(1, sum(e.get('customType') == 'uas-peer-v1' for e in entries))

    def test_real_pi_malformed_and_oversized_records_never_reach_ledger(self):
        self.start()
        before = self.ledger.snapshot()
        for data in (b'{"request_id":"a","envelope":{}}', b'x' * 65536, b'x' * 65537):
            self.native.rpc('prompt', message='/fixture-peer-probe ' + encoded({
                'mode': 'raw', 'packet': base64.urlsafe_b64encode(data).decode()}))
            self.assertFalse(self.receive()['ok'])
            self.assertEqual(before, self.ledger.snapshot())
        # Raw probes intentionally don't consume replies. Do not reuse that
        # channel for a valid tool after an uncorrelated response.
        self.script([self.message()])
        self.native.rpc('prompt', message='Exercise stale uncorrelated reply fencing.')
        self.receive()
        self.idle()
        self.assertIn('uncorrelated', str(self.native.event_snapshot()))

    def test_real_pi_lost_reply_fences_channel_and_late_reply_cannot_match_new_tool(self):
        self.start()
        self.script([self.message('once'), self.message('must-not-send')])
        self.native.rpc('prompt', message='Use both configured tools.')
        self.assertTrue(select.select([self.handle.channel], [], [], 5)[0])
        # Hold the native request longer than the channel deadline, then commit
        # the original record. A late response cannot authorize another send.
        time.sleep(2.2)
        self.assertTrue(self.receive()['ok'])
        self.idle()
        self.assertIn('once', self.hub._state()['traffic'])
        self.assertNotIn('must-not-send', self.hub._state()['traffic'])
        self.assertFalse(select.select([self.handle.channel], [], [], .05)[0])
        self.assertIn('fenced', str(self.native.event_snapshot()))

    def test_recipe_rejects_arbitrary_runtime_arguments_and_wrong_scope(self):
        with self.assertRaises(LedgerError):
            self.controller.launch_pi(replace(self.seat, arguments=('arbitrary',)), self.recipe())
        recipe = self.recipe()
        recipe.scope['participant_id'] = 'sender'
        with self.assertRaises((LedgerError, NativeUnavailable)):
            self.controller.launch_pi(self.seat, recipe)
        self.assertFalse(self.controller.handles)

    def test_actual_native_ready_then_stop_or_revoke_before_publish_cannot_activate(self):
        # Ordered lifecycle race at the exact boundary: real Pi has answered its
        # handshake outside the lock; Stop/revoke wins before active publication.
        for operation in ('revoke', 'stop'):
            with self.subTest(operation=operation):
                original = FixturePiRecipe.attach
                observed = []
                def late(recipe, process, badge):
                    native = original(recipe, process, badge)
                    observed.append(native)
                    self.assertEqual('1.4.0', native.initial_state['api_baseline'])
                    self.assertEqual('starting', self.controller.snapshot()['seats']['pi']['status'])
                    if operation == 'revoke':
                        self.controller.revoke('pi')
                    else:
                        self.assertEqual('stopped', self.supervisor.stop()['phase'])
                    return native
                with patch.object(FixturePiRecipe, 'attach', late):
                    with self.assertRaises(LedgerError):
                        self.start()
                self.assertTrue(observed[0]._closed)
                self.assertIsNotNone(observed[0].process.poll())
                self.assertFalse(self.controller.handles)
                self.assertNotIn('pi', self.hub._state()['connections'])

    def test_actual_native_active_and_compensating_store_failure_reaps_only_owned_child(self):
        original_replace = os.replace
        original_attach = FixturePiRecipe.attach
        observed = []
        def attached(recipe, process, badge):
            native = original_attach(recipe, process, badge)
            observed.append(native)
            return native
        def fail_active(source, target):
            if Path(target) == self.controller.path:
                record = json.loads(Path(source).read_text())['seats'].get('pi')
                if record and record['reason'] in ('launched', 'launch-failed'):
                    raise OSError('actual Pi test: active/compensating store unavailable')
            return original_replace(source, target)
        with patch.object(FixturePiRecipe, 'attach', attached), patch('uas.participant.os.replace', side_effect=fail_active):
            with self.assertRaises(OSError):
                self.start()
        self.assertEqual(1, len(observed))
        self.assertTrue(observed[0]._closed)
        self.assertIsNotNone(observed[0].process.poll())
        self.assertTrue(self.controller.store_failed)
        self.assertFalse(self.controller.handles)
        self.assertTrue(self.controller.fenced)

    def test_actual_native_new_session_fences_peer_channel_without_claiming_reset(self):
        self.start()
        before = self.ledger.snapshot()
        self.native.rpc('new_session')
        self.assertIs(Readiness.LOST, self.native.observe())
        self.script([self.message('new-session-must-not-send')])
        self.native.rpc('prompt', message='Attempt after unsupported native reset.')
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if any(e.get('type') == 'agent_settled' for e in self.native.event_snapshot()):
                break
            time.sleep(.01)
        self.assertEqual(before, self.ledger.snapshot())
        # EOF is readiness, not a peer record. The old descriptor is closed.
        self.assertEqual(b'', self.handle.channel.recv(1))

    def test_actual_pi_max_reply_accepted_but_oversized_json_prefix_fences(self):
        self.start()
        for size in (65536, 65537):
            self.script([self.message('reply-size-' + str(size))])
            self.native.rpc('prompt', message='Exercise the real native peer reply boundary.')
            self.assertTrue(select.select([self.handle.channel], [], [], 5)[0])
            # Preserve the real committed receipt; change only transport padding.
            actual = self.handle.channel
            class PaddedReply:
                def recvmsg(inner, *args):
                    return actual.recvmsg(*args)
                def send(inner, data):
                    self.assertLess(len(data), size)
                    return actual.send(data + b' ' * (size - len(data)))
            self.handle.channel = PaddedReply()
            try:
                self.assertTrue(self.controller.receive(self.handle)['ok'])
            finally:
                self.handle.channel = actual
            self.idle()
            self.assertIn('reply-size-' + str(size), self.hub._state()['traffic'])
            if size == 65537:
                self.assertIn('oversized reply', str(self.native.event_snapshot()))
            else:
                result = [e for e in self.native.event_snapshot() if e.get('type') == 'tool_execution_end'][-1]
                self.assertFalse(result['isError'])
