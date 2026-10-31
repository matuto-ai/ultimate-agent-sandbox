"""Pipe-only browser fixture for the actual private Manager/Hub/Library path.

The persistent service owns disposable canonical Git and SQLite. Scenario flags
are test-only fault/grant injection, never fields accepted by the production API.
No model is executed, no socket or remote resource is opened.
"""
from copy import deepcopy
import json
import sys

from uas import library
from uas.library_controls import canonical
from uas.manager_library_transport import LibraryServiceContact
from uas.manager_stream import ManagerReadModel, RoomIdentity, RoomStream
from uas.manager_transport import ManagerSession
import test_manager_library_transport as transport
import test_library_inspection as inspection
import test_library_scheduler as scheduling
import test_library_requeue as requeue
from test_library_attention import ServiceAttentionTests, Recorder

ITEM = 'T32_PRIVATE_ITEM'
CONTEXT = 'T32_PRIVATE_CONTEXT'
SIBLING = 'T32_PRIVATE_SIBLING'
CONCLUSION = 'T32_PRIVATE_CONCLUSION'
RATIONALE = 'T32_PRIVATE_RATIONALE'
REASON = 'T32_PRIVATE_REASON'
MARKERS = (ITEM, CONTEXT, SIBLING, CONCLUSION, RATIONALE, REASON)


class BrowserFixture:
    def __init__(self):
        self.fx = None
        self.reset()

    def close(self):
        if self.fx is not None:
            self.fx.doCleanups()
            self.fx = None

    def reset(self, mode='normal'):
        self.close()
        self.fx = transport.TransportTests('runTest')
        self.fx.setUp()
        fx = self.fx
        # Broader grants remain same-Project and are independently checked at
        # both production boundaries on every service call.
        fx.fx.principal = library.LocalHuman('human', 'actor', 'grant',
            lambda _, key, action: fx.fx.allowed and key == fx.source.scope.project_identity
                and action in ('library-inspect', 'library-drain', 'library-retry',
                    'library-defer', 'library-requeue', 'library-reject',
                    'library-adjudicate', 'library-resume'), lambda: fx.connected)
        fx.contact = LibraryServiceContact(fx.controls, lambda _: fx.fx.principal)
        fx.hub.contact = fx.contact
        self.notices = []
        self.serial = 0
        # Actual second Project, not merely a string inserted in the response.
        svc = fx.fx.fx.fx
        svc.scheduler = fx.fx.service.scheduler
        svc.runner = svc.fixture.runner()
        svc.replies = []
        svc.register = lambda runner: scheduling.SchedulerTests.register(svc, runner)
        _, self.beta_queue = scheduling.SchedulerTests.second(svc)
        beta_path = 'projects/github.com/acme/beta/pending/' + self.beta_queue + '.md'
        _, tree = fx.source.publisher.project_snapshot(
            library.participant_scope(__import__('library_support').ORIGIN,
                binding=__import__('library_support').binding('beta','acme/beta','2002')),
            fx.source.settings, current=lambda:None)
        fx.source.mutate({beta_path: tree.files[beta_path].replace(b'Beta data', SIBLING.encode())})
        if mode == 'inspection':
            helper = inspection.InspectionTests('runTest')
            helper.source = fx.source
            helper.q = fx.fx.q
            concept = helper.concept(body=CONTEXT)
            helper.replace_draft(ITEM + '\n[Context](/' + concept + ')\n'
                '<img src="https://never-fetch.test/t32" onerror="globalThis.t32Pwned=true">\n'
                '![remote](https://never-fetch.test/image)\n'
                '[Sibling](/projects/github.com/acme/beta/context/secret.md)')
        else:
            path = 'projects/' + fx.source.scope.project_path + '/pending/' + fx.fx.q + '.md'
            fx.source.mutate({path: fx.source.contents('pending/'+fx.fx.q+'.md').replace(
                'Selected draft data.', ITEM).encode()})
        self.parked_drain = None
        if mode in ('blocked', 'defer'):
            fx.fx.blocked(second=True)
        if mode == 'defer':
            attention = ServiceAttentionTests('runTest')
            attention.fx = svc
            attention.source = fx.source
            attention.observation()
            recorder = Recorder()
            attention.attention().sample(notify=recorder)
            self.notices = recorder.notices
        if mode == 'parked':
            helper = requeue.RequeueTests('runTest')
            helper.source, helper.service = fx.source, fx.fx.service
            _, _, self.parked_drain = helper.parked(bad=False)
        return self.state()

    def state(self):
        fx = self.fx
        return {'queue_id': fx.fx.q, 'beta_queue_id': self.beta_queue,
            'parked_drain': self.parked_drain, 'head': fx.source.head(),
            'commits': fx.source.count(), 'schedule': deepcopy(fx.fx.entry()['state'])}

    def invoke(self, packet, scenario='normal'):
        fx = self.fx
        fx.allowed = scenario != 'revoked-host'
        fx.fx.allowed = scenario not in ('revoked', 'settings-only')
        if scenario == 'stale':
            self.serial += 1
            fx.source.capture('stale-'+str(self.serial), body='Additional unrelated current data.')
        prior_state = deepcopy(fx.fx.entry()['state'])
        if scenario == 'busy':
            fx.fx.entry()['state']['state'] = 'ACTIVE'
        def contact(*a, **kw):
            if scenario == 'lost-before': raise OSError('private transport diagnostic')
            result = fx.contact(*a, **kw)
            if scenario == 'revoked-after': fx.fx.allowed = False
            if scenario == 'lost-after': raise OSError('private transport diagnostic')
            return result
        fx.hub.contact = contact
        try:
            return fx.host.handle(canonical(packet), fx.context)
        finally:
            fx.hub.contact = fx.contact
            if scenario == 'busy': fx.fx.entry()['state'] = prior_state

    def privacy(self):
        fx = self.fx
        identity = RoomIdentity('deployment-1', 'room', 'stream')
        cache = fx.source.base / 'manager-cache.db'
        model = ManagerReadModel(cache)
        try:
            session = ManagerSession(model, identity)
            transfer = RoomStream(fx.ledger, identity).capture(model.cursor(identity),
                captured_at='2026-10-31T00:00:00+00:00')
            session.handle({'kind':'begin', 'transfer':transfer.begin()})
            cursor = transfer.after_seq
            while cursor is not None and cursor < transfer.cut:
                page = transfer.page(cursor)
                cursor = session.handle({'kind':'events', 'page':page})['room_seq']
            session.handle({'kind':'finish', 'transfer_id':transfer.transfer_id})
            maintained = canonical(model.view(identity, now='2026-10-31T00:00:00+00:00'))
            maintained += canonical(model.events(identity))
            session.close()
        finally:
            model.close()
        maintained += canonical(fx.ledger.snapshot()) + canonical(fx.ledger.replay(0, limit=1000))
        maintained += canonical(self.notices) + canonical(fx.fx.fx.fx.fixture.audit)
        files = []
        for base in (fx.path, fx.source.records, cache, fx.fx.fx.fx.path):
            for path in base.parent.glob(base.name+'*'):
                if path.is_file():
                    maintained += path.read_bytes()
                    files.append(path.name)
        return {'marker_absent': {marker: marker.encode() not in maintained for marker in MARKERS},
            'surfaces': ['Manager snapshot/cache/events', 'Hub SQLite/WAL/replay',
                'Library records/audit', 'Gotify notice payloads'],
            'files': sorted(set(files)), 'provider_called': fx.fx.fx.fx.fixture.marker.exists()}

    def command(self, value):
        command = value.get('command', 'invoke')
        if command == 'reset': return self.reset(value.get('mode','normal'))
        if command == 'state': return self.state()
        if command == 'privacy': return self.privacy()
        if command == 'decision':
            return {'text': self.fx.source.contents('decisions/adjudication-'+self.fx.fx.q+'.md')}
        return self.invoke(value['packet'], value.get('scenario','normal'))


if __name__ == '__main__':
    fixture = BrowserFixture()
    try:
        for line in sys.stdin:
            value = json.loads(line)
            if value.get('command') == 'close': break
            result = fixture.command(value)
            print(json.dumps(result, ensure_ascii=False), flush=True)
    finally:
        fixture.close()
