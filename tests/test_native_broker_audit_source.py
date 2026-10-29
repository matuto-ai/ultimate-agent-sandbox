"""Finite controlled IPC + original SQLite audit checks; no native effects."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import select
import socket
import tempfile
import threading
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_read import ExternalReadBroker
from uas.forge_read_service import ReadBrokerClient
from uas.kernel_origin import HeldOrigin, OriginDenied
from uas.ledger import LedgerError, Origin, _json
from uas.manager_actions import HumanSession, OwnerFence
from uas.native_broker_audit import (KIND, NativeBrokerAudit, _holder_exited, _scope,
                                      serve_audit_fence)
import test_forge_mutation_audit as mutation


def held():
    value = object.__new__(HeldOrigin)
    value.pidfd = 900; value.identity = (1, 2); value.revoked = False
    return value


@contextmanager
def record(value):
    yield N(data=_json(value).encode())


class NativeBrokerAuditSourceTests(unittest.TestCase):
    def setUp(self):
        for p in (patch('uas.native_broker_audit._identity', return_value=(1, 2)),
                  patch('uas.native_broker_audit.alive', return_value=True)):
            p.start(); self.addCleanup(p.stop)
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.audit = ForgeAudit(Path(self.tmp.name) / 'original-broker.db', 'deployment')
        self.addCleanup(self.audit.close)
        self.broker = object.__new__(ExternalReadBroker)
        self.broker.audit = self.audit; self.broker.failed = False
        self.broker.binding = ForgeBinding('room', 'project', 'owner/repo')
        self.broker.room_instance = 'instance'
        self.human = Origin('human', 'human', 'human-context', 'human-version', ('human-control-run',))
        self.connected = self.authorized = True
        self.session = HumanSession('deployment', 'room', 'instance', 'manager', self.human,
            lambda *_: self.authorized, lambda: self.connected)
        self.packet = {'kind': KIND, 'request_id': 'a'*32, 'deployment_id': 'deployment',
            'room_id': 'room', 'room_instance': 'instance', 'repository': 'owner/repo',
            'operation_id': 'human-change', 'action': 'request-changes', 'request_digest': 'b'*64,
            'origin': self.human.canonical()}
        self.holder = held(); self.holder.require = Mock()
        self.channel = N(settimeout=Mock(), close=Mock())

    def unknown(self):
        self.audit.begin_mutation('ordinary', mutation.metadata(room_id='room', room_instance='instance'))
        self.audit.mutation_prepared('ordinary', 0, mutation.ISSUE)
        self.audit.finish_mutation('ordinary', mutation.result(status='UNKNOWN_OUTCOME', confirmed_fields=[],
            objects=[], failed_field='title', error_code='TIMEOUT'))

    def test_server_retains_original_sqlite_unknown_until_exact_release(self):
        self.unknown(); before = self.audit.get_mutation('ordinary'); sent = []
        digest = _scope(self.packet, self.broker)
        def send(channel, request_id, value):
            sent.append(deepcopy(value))
            self.assertEqual(self.audit._connection().in_transaction, value['kind'].endswith('_HELD'))
        def recv(channel):
            self.assertTrue(self.audit._connection().in_transaction)
            # A distinct connection cannot acquire a competing audit writer.
            import sqlite3
            other = sqlite3.connect(Path(self.tmp.name) / 'original-broker.db', timeout=0)
            try:
                with self.assertRaises(sqlite3.OperationalError): other.execute('BEGIN IMMEDIATE')
            finally: other.close()
            return record({'kind': KIND+'_RELEASE', 'request_id': self.packet['request_id'], 'scope_digest': digest})
        with patch('uas.native_broker_audit._holder_exited', return_value=False), \
                patch('uas.native_broker_audit.receive', side_effect=recv), \
                patch('uas.forge_read_service.send_result', side_effect=send):
            serve_audit_fence(self.channel, self.broker, self.holder, self.packet)
        self.assertTrue(sent[0]['state']['blocked']); self.assertEqual(sent[0]['state']['reason'], 'FORGE_RECONCILIATION_REQUIRED')
        self.assertEqual(len(sent), 2); self.assertEqual(self.audit.get_mutation('ordinary'), before)
        self.assertFalse(self.audit._connection().in_transaction)

    def test_foreign_origin_scope_action_or_extra_fields_fail_before_fence(self):
        for change in ({'deployment_id':'other'}, {'room_id':'other'}, {'room_instance':'other'},
                       {'repository':'other/repo'}, {'action':'start'}, {'extra':True},
                       {'origin':{**self.human.canonical(), 'capabilities':[]}}):
            with self.subTest(change=change), self.assertRaises(LedgerError):
                serve_audit_fence(self.channel, self.broker, self.holder, {**self.packet, **change})
            self.assertFalse(self.audit._connection().in_transaction)

    def test_timeout_does_not_release_live_holder(self):
        digest = _scope(self.packet, self.broker); count = 0
        def recv(channel):
            nonlocal count
            count += 1; self.assertTrue(self.audit._connection().in_transaction)
            if count == 1: raise socket.timeout()
            return record({'kind':KIND+'_RELEASE','request_id':self.packet['request_id'],'scope_digest':digest})
        with patch('uas.native_broker_audit._holder_exited', return_value=False), \
                patch('uas.native_broker_audit.receive', side_effect=recv), \
                patch('uas.forge_read_service.send_result'):
            serve_audit_fence(self.channel, self.broker, self.holder, self.packet)
        self.assertEqual(count, 2)

    def test_lost_acquire_eof_and_wrong_release_wait_exact_holder_death(self):
        for failure in ('send', 'eof', 'wrong-release'):
            dead = False; waits = []
            def wait(holder):
                nonlocal dead
                self.assertIs(holder, self.holder); self.assertTrue(self.audit._connection().in_transaction)
                waits.append(True); dead = True
            receive = Mock(side_effect=OriginDenied('EOF')) if failure == 'eof' else Mock(return_value=record({'kind':'foreign'}))
            send = Mock(side_effect=OSError('lost')) if failure == 'send' else Mock()
            self.broker.failed = False
            with patch('uas.native_broker_audit._holder_exited', side_effect=lambda _:dead), \
                    patch('uas.native_broker_audit._wait_holder_exit', side_effect=wait), \
                    patch('uas.native_broker_audit.receive', receive), \
                    patch('uas.forge_read_service.send_result', send), self.assertRaises(OriginDenied):
                serve_audit_fence(self.channel, self.broker, self.holder, self.packet)
            self.assertEqual(len(waits), 1); self.assertTrue(self.broker.failed)
            self.assertFalse(self.audit._connection().in_transaction)

    def test_exact_death_not_conservative_alive_false_retires_fence(self):
        poll = N(register=Mock(), poll=Mock())
        with patch('uas.native_broker_audit._identity', return_value=self.holder.identity), \
                patch('uas.native_broker_audit.select.poll', return_value=poll):
            for flags in (select.POLLIN, select.POLLIN|select.POLLHUP):
                poll.poll.return_value=[(900, flags)]; self.assertTrue(_holder_exited(self.holder))
            for flags in (select.POLLERR, select.POLLNVAL, select.POLLHUP, select.POLLIN|select.POLLERR):
                poll.poll.return_value=[(900, flags)]; self.assertFalse(_holder_exited(self.holder))
            poll.poll.return_value=[]; self.assertFalse(_holder_exited(self.holder))
        with patch('uas.native_broker_audit._identity', side_effect=OSError('unknown')):
            self.assertFalse(_holder_exited(self.holder))
        poll.poll.return_value=[(900, select.POLLIN)]
        with patch('uas.native_broker_audit._identity', side_effect=[self.holder.identity,(3,4)]), \
                patch('uas.native_broker_audit.select.poll', return_value=poll):
            self.assertFalse(_holder_exited(self.holder))

    def client(self):
        client = object.__new__(ReadBrokerClient)
        client.closed=False; client.manager_audit_enabled=True; client.worker=held()
        client.binding=self.broker.binding; client.room_instance='instance'; client.lock=threading.Lock()
        client.channel=N(close=Mock(), send=Mock(side_effect=lambda b:len(b)))
        owner=NativeBrokerAudit(client,self.session)
        value={'version':1,'operation_id':'human-change','action':'request-changes','deployment_id':'deployment',
            'room_id':'room','instance_id':'instance','run_id':'run','generation':1,'object_id':'submission',
            'observed_version':'c'*64,'payload':{'body':'human changes'}}
        return client, owner, owner.bind(value,self.session)

    def wire(self, client, *, lose=None):
        state={'version':'d'*64,'blocked':False,'partial':False,'reason':None}
        packets=[]; replies=[]
        def send(channel, request_id, packet, **kwargs):
            packets.append(deepcopy(packet)); digest=hashlib.sha256(_json(packet).encode()).hexdigest()
            replies.extend([{'kind':KIND+'_HELD','request_id':request_id,'scope_digest':digest,'state':state},
                            {'kind':KIND+'_RELEASED','request_id':request_id,'scope_digest':digest}])
        def recv(*args):
            if lose=='acquire' or lose=='release' and len(replies)==1:raise OSError('lost')
            return replies.pop(0)
        return send,recv,packets

    def test_client_pure_guard_requires_preparation_and_current_exact_context(self):
        client,owner,operation=self.client();send,recv,packets=self.wire(client)
        with self.assertRaisesRegex(LedgerError,'NOT_PREPARED'):
            with operation.manager_action_guard('room','owner/repo'):pass
        with patch('uas.native_broker_audit.alive',return_value=True), \
                patch('uas.forge_read_service.send_result',side_effect=send), \
                patch('uas.forge_read_service.receive_result',side_effect=recv):
            with operation.prepare_manager_guard():
                self.assertTrue(client.lock.locked())
                with operation.manager_action_guard('room','owner/repo') as current:
                    self.assertFalse(current['blocked'])
                with self.assertRaisesRegex(LedgerError,'PROVIDER_FENCED'):
                    client.prepare({}, self.human)
                with self.assertRaisesRegex(LedgerError,'PROVIDER_FENCED'):
                    client.perform({})
                with self.assertRaisesRegex(LedgerError,'PROVIDER_FENCED'):
                    client.denied('FORBIDDEN')
                with self.assertRaisesRegex(LedgerError,'BUSY'):
                    with operation.prepare_manager_guard():pass
                self.connected=False
                with self.assertRaisesRegex(LedgerError,'UNAVAILABLE'):
                    operation.manager_action_state('room','owner/repo')
        self.assertEqual(len(packets),1);self.assertFalse(client.lock.locked());self.assertIsNone(operation.held)

    def test_cached_fence_denies_dead_revoked_or_changed_worker_at_every_cut(self):
        for failure in ('dead', 'unknown', 'revoked', 'identity', 'pidfd', 'identity-race'):
            with self.subTest(failure=failure):
                client,owner,operation=self.client();send,recv,packets=self.wire(client)
                with patch('uas.forge_read_service.send_result',side_effect=send), \
                        patch('uas.forge_read_service.receive_result',side_effect=recv):
                    with operation.prepare_manager_guard():
                        alive = patch('uas.native_broker_audit.alive',return_value=failure!='dead')
                        identity = patch('uas.native_broker_audit._identity',return_value=(3,4) if failure=='identity' else (1,2))
                        with alive, identity as identity_call:
                            if failure=='unknown':identity_call.side_effect=OSError('unknown identity')
                            if failure=='revoked':client.worker.revoked=True
                            if failure=='pidfd':client.worker.pidfd=901
                            for consume in ('state','guard','authorization'):
                                if failure=='identity-race':identity_call.side_effect=[(1,2),(3,4)]
                                with self.assertRaisesRegex(LedgerError,'UNAVAILABLE'):
                                    if consume=='state':operation.manager_action_state('room','owner/repo')
                                    elif consume=='guard':
                                        with operation.manager_action_guard('room','owner/repo'):pass
                                    else:operation.require_current()
                self.assertEqual(len(packets),1);self.assertIsNone(operation.held)

    def test_denial_refuses_before_non_reentrant_lock_acquisition(self):
        client,owner,operation=self.client()
        client._manager_audit_active=operation
        client.lock=Mock()
        with self.assertRaisesRegex(LedgerError,'PROVIDER_FENCED'):client.denied('FORBIDDEN')
        client.lock.acquire.assert_not_called();client.channel.send.assert_not_called()

    def test_client_unknown_acquire_or_release_never_retries_or_reuses_owner(self):
        for loss in ('acquire','release'):
            client,owner,operation=self.client();send,recv,packets=self.wire(client,lose=loss)
            with patch('uas.native_broker_audit.alive',return_value=True), \
                    patch('uas.forge_read_service.send_result',side_effect=send), \
                    patch('uas.forge_read_service.receive_result',side_effect=recv):
                with self.assertRaises((OSError,LedgerError)):
                    with operation.prepare_manager_guard():pass
                with self.assertRaisesRegex(LedgerError,'UNAVAILABLE'):
                    with operation.prepare_manager_guard():pass
            self.assertEqual(len(packets),1);self.assertTrue(owner.failed);self.assertTrue(client.closed)
            self.assertFalse(client.lock.locked());client.channel.close.assert_called_once()

    def test_changed_operation_or_binding_is_rejected_without_exchange(self):
        for change in ('operation','binding'):
            client,owner,operation=self.client()
            if change=='operation':operation.value['operation_id']='changed'
            else:client.room_instance='changed'
            with self.assertRaisesRegex(LedgerError,'UNAVAILABLE'):
                with operation.prepare_manager_guard():pass
            client.channel.send.assert_not_called()


class NativeBrokerAuditOwnerTests(unittest.TestCase):
    def setUp(self):
        # Audited finite fixture setup uses actual Room/Review/Audit SQLite and
        # explicitly controlled native/provider boundaries. No discovery.
        from test_native_session_human_actions import NativeSessionHumanActionsTests
        self.f=NativeSessionHumanActionsTests(); self.f.setUp(); self.addCleanup(self.f.doCleanups)
        f=self.f;client=f.c.owner_client
        client.closed=False;client.manager_audit_enabled=True;client.worker=held()
        client.binding=f.c.admission.broker.binding;client.room_instance=f.session.instance_id
        client.lock=threading.Lock();client.channel=N(close=Mock())
        self.client=client;self.remote=NativeBrokerAudit(client,f.session)
        self.guard=None;self.replies=[];self.exchanges=[]
        def outside():
            self.assertFalse(f.c.ledger._connection().in_transaction)
            self.assertFalse(f.c.recruitment.provenance._history_fenced)
            active=f.review_host.identity.active
            self.assertTrue(active is None or active.capability is None)
        def send(channel,request_id,packet,**kwargs):
            outside();self.assertIsNone(self.guard)
            self.guard=f.audit.manager_action_guard(client.binding.room_id,client.binding.repository)
            state=self.guard.__enter__();digest=hashlib.sha256(_json(packet).encode()).hexdigest()
            self.exchanges.append(packet);self.replies.append({'kind':KIND+'_HELD','request_id':request_id,'scope_digest':digest,'state':state})
        def release(raw):
            outside();packet=json.loads(raw);self.assertIsNotNone(self.guard)
            self.guard.__exit__(None,None,None);self.guard=None
            self.replies.append({**packet,'kind':KIND+'_RELEASED'});return len(raw)
        client.channel.send=release
        for p in (patch('uas.native_broker_audit._identity',return_value=(1,2)),
                  patch('uas.native_broker_audit.alive',return_value=True),
                  patch('uas.forge_read_service.send_result',side_effect=send),
                  patch('uas.forge_read_service.receive_result',side_effect=lambda *_:self.replies.pop(0))):
            p.start();self.addCleanup(p.stop)
        for name in ('observe','comment','reconcile_comment'):
            original=getattr(f.broker,name)
            def provider(*args,_original=original,**kwargs):
                self.assertIsNone(self.guard);self.assertFalse(client.lock.locked())
                self.assertFalse(f.audit._connection().in_transaction)
                return _original(*args,**kwargs)
            setattr(f.broker,name,provider)
        self.addCleanup(self.cleanup_guard)

    def cleanup_guard(self):
        if self.guard is not None:self.guard.__exit__(None,None,None);self.guard=None

    def test_actual_canonical_human_change_consumes_original_remote_audit_fence(self):
        f=self.f;packet=f.packet()
        result=f.review_host.human_action(packet,session=f.session,audit=self.remote)
        self.assertEqual(result['status'],'confirmed');self.assertGreaterEqual(len(self.exchanges),2)
        self.assertEqual(f.comments()['human-change']['human_origin'],f.session.human.canonical())
        self.assertEqual([x[0] for x in f.provider_calls].count('comment'),1)
        self.assertIsNone(self.guard);self.assertFalse(self.client.lock.locked())

    def test_original_ordinary_mutation_unknown_blocks_without_provider_or_comment(self):
        f=self.f
        f.audit.begin_mutation('ordinary',mutation.metadata(room_id=f.c.room['id'],room_instance='instance',
                                                        repository=self.client.binding.repository))
        f.audit.mutation_prepared('ordinary',0,mutation.ISSUE)
        f.audit.finish_mutation('ordinary',mutation.result(status='UNKNOWN_OUTCOME',confirmed_fields=[],objects=[],failed_field='title',error_code='TIMEOUT'))
        packet=f.packet()
        with self.assertRaisesRegex(LedgerError,'FORGE_RECONCILIATION_REQUIRED'):
            f.review_host.human_action(packet,session=f.session,audit=self.remote)
        self.assertFalse(f.provider_calls);self.assertNotIn('human-change',f.comments())
        self.assertIsNone(self.guard)

    def test_stale_state_denies_before_any_provider_call(self):
        f=self.f;packet=f.packet();f.c.seed(lambda s:s['runs'][f.c.run_id].update(control_revision=44))
        with self.assertRaisesRegex(LedgerError,'STALE_ACTION'):
            f.review_host.human_action(packet,session=f.session,audit=self.remote)
        self.assertFalse(f.provider_calls);self.assertIsNone(self.guard)

    def test_broker_revocation_after_guard_before_consuming_hub_check_denies(self):
        f=self.f;packet=f.packet();before=[]
        original=OwnerFence.check
        def revoke_then_check(fence,*args,**kwargs):
            if fence._forge is not None:
                before.append(f.c.ledger.snapshot())
                self.client.worker.revoked=True
            return original(fence,*args,**kwargs)
        with patch.object(OwnerFence,'check',revoke_then_check), \
                self.assertRaisesRegex(LedgerError,'UNAVAILABLE'):
            f.review_host.human_action(packet,session=f.session,audit=self.remote)
        self.assertEqual(len(before),1);self.assertEqual(f.c.ledger.snapshot(),before[0])
        self.assertNotIn('human-change',f.comments())
        self.assertNotIn('comment',[name for name,_ in f.provider_calls]);self.assertIsNone(self.guard)

    def test_existing_native_driver_consumes_exact_remote_audit_inbox(self):
        from uas.native_session_driver import NativeHumanReviewInbox, NativeSessionDriver
        f=self.f
        inbox=NativeHumanReviewInbox(f.session,self.remote)
        driver=NativeSessionDriver(f.c.admission,f.c.recruitment,f.request,f.budget,human_actions=inbox)
        inbox.enqueue(f.packet());result=driver.run()
        self.assertEqual(f.comments()['human-change']['status'],'confirmed',result)
        self.assertEqual(inbox.snapshot()[0]['status'],'confirmed')
        self.assertEqual([x[0] for x in f.provider_calls].count('comment'),1)
        self.assertIsNone(self.guard)
