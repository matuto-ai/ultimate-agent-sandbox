"""Two canonical owners, file-backed host facts and an inert provider.

No process is killed and no network, Docker or credentials are used. This is
failure-composition evidence, not native isolation or disposable-VM proof.
"""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from lifecycle_support import FileFixtureBackend
from test_github_mutations import MemoryGitHub
from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_mutations import ExternalMutationBroker
from uas.github_mutations import GitHubMutationProvider
from uas.github_read import GitHubProject
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition
from uas.lifecycle import FixtureSpec, LifecycleError, Supervisor
from uas.manager_stream import ManagerReadModel, RoomIdentity, RoomStream
from uas.manager_transport import ManagerSession

TIME = '2026-10-27T20:00:00+00:00'


class TwoRoomSurvivalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.backend = FileFixtureBackend(self.root / 'host-facts')
        self.audit = ForgeAudit(self.root / 'broker.sqlite3', 'deployment')
        self.addCleanup(self.audit.close)
        self.manager = ManagerReadModel(self.root / 'manager.sqlite3')
        self.addCleanup(self.manager.close)
        self.rooms = {}
        for name in ('alpha', 'beta'):
            project = self.root / ('project-' + name)
            project.mkdir()
            (project / 'human-work').write_text(name + ' retained edits')
            supervisor = Supervisor(self.root / 'control', name, self.backend,
                authorize=lambda *_: True, revoke=self.backend.revoke)
            spec = FixtureSpec(name, 'project-' + name, (str(project),),
                'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64, 'sha256:' + 'c' * 64)
            state = supervisor.start(spec)
            self.assertEqual('running', state['phase'])
            data = supervisor.directory / 'instances' / state['instance_id'] / 'data'
            ledger = RoomLedger(data / 'hub.sqlite3', name)
            self.addCleanup(ledger.close)
            identity = RoomIdentity('deployment', name, 'stream-' + name)
            stream = RoomStream(ledger, identity, supervisor=supervisor, audit=self.audit)
            session = ManagerSession(self.manager, identity)
            self.addCleanup(session.close)
            provider = MemoryGitHub()
            provider.repository = 'owner/' + name
            provider.base = 'repos/' + provider.repository
            provider.api = 'https://api.github.com/' + provider.base
            provider.web = 'https://github.com/' + provider.repository
            provider.__init__()
            adapter = GitHubMutationProvider(GitHubProject(provider.repository), provider)
            origin = Origin('actor-' + name, 'seat-' + name, 'inc-' + name, 'epoch', ('forge-write',))
            broker = ExternalMutationBroker(ForgeBinding(name, 'project-' + name, provider.repository),
                state['instance_id'], self.audit, {origin.actor_id: 41}, lambda _, p=adapter: p)
            self.rooms[name] = dict(supervisor=supervisor, spec=spec, ledger=ledger,
                identity=identity, stream=stream, session=session, provider=provider,
                origin=origin, broker=broker, project=project, state=supervisor._read())
            self.append(name)
            self.assertEqual('OK', self.mutate(name, 'initial')['mutation']['status'])
            self.sync(name)

    def append(self, name):
        room = self.rooms[name]
        number = room['ledger'].snapshot()['room_seq'] + 1
        room['ledger'].apply(Command('event-' + str(number), 'counter', 'counter', None, {}),
            room['origin'], authorize=lambda *_: True,
            decide=lambda state, _: Transition({'counter': number},
                (Event('counter.changed', {}),), {}))

    def mutate(self, name, operation, argv=None, **extra):
        room = self.rooms[name]
        return room['broker'].execute({'id': operation, 'kind': 'forge-write',
            'argv': argv or ['issue', 'edit', '1', '--title', operation], **extra},
            origin=room['origin'], authorize=lambda: room['supervisor']._read()['phase'] == 'running')

    def sync(self, name):
        room = self.rooms[name]
        transfer = room['stream'].capture(self.manager.cursor(room['identity']), captured_at=TIME)
        room['session'].handle({'kind': 'begin', 'transfer': transfer.begin()})
        cursor = transfer.after_seq
        while cursor is not None and cursor < transfer.cut:
            reply = room['session'].handle({'kind': 'events', 'page': transfer.page(cursor, limit=2)})
            cursor = reply['room_seq']
        room['session'].handle({'kind': 'finish', 'transfer_id': transfer.transfer_id})

    def beta_cut(self):
        room = self.rooms['beta']
        state = room['supervisor']._read()
        observation = self.audit.manager_observations('beta')[0].document()
        return deepcopy(dict(lifecycle=state, resources={kind: self.backend.inspect(state, kind)
            for kind in ('container', 'volume')}, ledger=room['ledger'].snapshot(),
            manager=self.manager.view(room['identity'], now=TIME),
            cursor=self.manager.cursor(room['identity']), audit_version=observation['observed_version'],
            audit_value=observation['value'], provider=vars(room['provider']),
            project={str(p.relative_to(room['project'])): p.read_bytes()
                     for p in room['project'].rglob('*') if p.is_file()}))

    def assert_beta_survives(self, before):
        self.assertEqual(before, self.beta_cut())
        beta = self.rooms['beta']
        self.assertEqual('running', beta['supervisor'].status()['phase'])
        self.assertTrue(self.backend.inspect(beta['supervisor']._read(), 'container')['running'])
        # A preserved frozen snapshot alone does not prove continued use: advance
        # the same ledger/session and execute through the existing Broker owner.
        self.append('beta')
        self.sync('beta')
        self.assertEqual(before['cursor'] + 1, self.manager.cursor(beta['identity']))
        self.assertEqual('OK', self.mutate('beta', 'after-alpha-failure')['mutation']['status'])

    def test_alpha_stop_resume_leaves_beta_owners_and_connection_unchanged(self):
        before = self.beta_cut()
        alpha = self.rooms['alpha']
        self.assertEqual('stopped', alpha['supervisor'].stop()['phase'])
        self.sync('alpha')
        self.assertEqual(before, self.beta_cut())
        self.assertEqual('running', alpha['supervisor'].start(alpha['spec'])['phase'])
        self.sync('alpha')
        self.assert_beta_survives(before)

    def test_alpha_observed_task_exit_does_not_revoke_beta(self):
        before = self.beta_cut()
        alpha = self.rooms['alpha']
        path = self.backend.path(alpha['state'], 'container')
        resource = json.loads(path.read_text())
        resource['running'] = False  # Controlled host observation, NOT an OS kill.
        path.write_text(json.dumps(resource))
        self.assertFalse(alpha['supervisor'].status()['observed']['container']['running'])
        self.sync('alpha')
        self.assert_beta_survives(before)

    def test_corrupt_alpha_manifest_fails_closed_without_touching_beta(self):
        before = self.beta_cut()
        alpha = self.rooms['alpha']
        (alpha['supervisor'].directory / 'lifecycle.json').write_text('{broken')
        calls = list(self.backend.calls)
        with self.assertRaises(LifecycleError):
            alpha['supervisor'].reconcile()
        self.assertEqual(calls, self.backend.calls)
        self.assert_beta_survives(before)

    def test_partial_destroy_recovery_and_full_destroy_leave_beta_unchanged(self):
        before = self.beta_cut()
        alpha = self.rooms['alpha']
        alpha['session'].close()
        alpha['ledger'].close()
        self.backend.fail_before.add('remove-volume')
        try:
            failed = alpha['supervisor'].destroy()
            self.assertEqual('destroy_failed', failed['phase'])
            self.assertEqual(['volume', 'control-state'], [x['kind'] for x in failed['leftovers']])
            self.assertEqual(before, self.beta_cut())
        finally:
            self.backend.fail_before.clear()
        reopened = Supervisor(self.root / 'control', 'alpha', self.backend,
            authorize=lambda *_: True, revoke=self.backend.revoke)
        self.assertEqual('destroyed', reopened.reconcile()['phase'])
        self.assertEqual(before, self.beta_cut())
        self.assertEqual('destroyed', reopened.destroy()['phase'])
        self.assertEqual('alpha retained edits', (alpha['project'] / 'human-work').read_text())
        self.assert_beta_survives(before)

    def test_alpha_full_destroy_and_recreation_preserve_beta_session(self):
        before = self.beta_cut()
        alpha = self.rooms['alpha']
        old = alpha['state']['instance_id']
        alpha['session'].close()
        alpha['ledger'].close()
        self.assertEqual('destroyed', alpha['supervisor'].destroy()['phase'])
        self.assertEqual(before, self.beta_cut())
        recreated = alpha['supervisor'].start(alpha['spec'])
        self.assertNotEqual(old, recreated['instance_id'])
        self.assert_beta_survives(before)

    def test_alpha_lost_stop_response_reconciles_without_beta_effect(self):
        before = self.beta_cut()
        self.backend.fail_after.add('stop')
        try:
            self.assertEqual('stopped', self.rooms['alpha']['supervisor'].stop()['phase'])
        finally:
            self.backend.fail_after.clear()
        self.assertEqual(1, self.backend.calls.count('stop'))
        self.sync('alpha')
        self.assert_beta_survives(before)

    def test_alpha_target_and_authority_substitution_never_contact_beta(self):
        before = self.beta_cut()
        alpha = self.rooms['alpha']
        calls = len(alpha['provider'].calls)
        denied = self.mutate('alpha', 'cross-project', ['issue', 'close', '1', '-R', 'owner/beta'])
        self.assertEqual('DENIED', denied['mutation']['status'])
        self.assertEqual(calls, len(alpha['provider'].calls))
        for field, value in (('room_id', 'beta'), ('actor_id', 'actor-beta'), ('repository', 'owner/beta')):
            with self.assertRaises(LedgerError):
                self.mutate('alpha', 'override-' + field, **{field: value})
        with self.assertRaises(LedgerError):
            alpha['broker'].execute({'id': 'stolen-origin', 'kind': 'forge-write',
                'argv': ['issue', 'close', '1']}, origin=self.rooms['beta']['origin'], authorize=lambda: True)
        self.assertEqual(calls, len(alpha['provider'].calls))
        self.assert_beta_survives(before)
