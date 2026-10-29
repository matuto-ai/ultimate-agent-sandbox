"""Local browser transport with controlled TLS; no socket, account or provider."""
import hashlib
import json
from pathlib import Path
import socket
import ssl
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

from uas import human_mtls as human
from uas import local_manager as local
from uas.ledger import Origin, LedgerError
from uas.manager_stream import ManagerReadModel, RoomIdentity
from uas.manager_ui import FieldNotesDocument, ProjectBinding


class TLS:
    def __init__(self, request=b''):
        self.context=SimpleNamespace(verify_mode=ssl.CERT_REQUIRED,minimum_version=ssl.TLSVersion.TLSv1_3)
        self.server_side=True;self.incoming=request;self.output=b'';self.timeouts=[]
    def fileno(self):return 5
    def version(self):return 'TLSv1.3'
    def getpeercert(self,*,binary_form):return b'test-client'
    def recv(self,count):data=self.incoming[:count];self.incoming=self.incoming[count:];return data
    def sendall(self,data):self.output+=data
    def settimeout(self,value):self.timeouts.append(value)


def wire(payload=None,*,method='POST',target=human.PATH,extra=''):
    if payload is None:payload={'version':1,'action':'observe','payload':{'kind':'document'}}
    body=json.dumps(payload).encode() if method=='POST' else b''
    return (f'{method} {target} HTTP/1.1\r\nHost: localhost:8765\r\n'
            f'Content-Type: application/json\r\nContent-Length: {len(body)}\r\n{extra}\r\n').encode()+body


class LocalManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.model=ManagerReadModel(Path(self.temp.name)/'manager.db');self.addCleanup(self.model.close)
        self.identity=RoomIdentity('deployment','room','stream')
        self.document=FieldNotesDocument(self.model,(ProjectBinding(self.identity,'project','owner/repo'),))
        self.grant=human.HumanActionGrant('deployment','room','instance','manager',
            Origin('operator','human','session','epoch',()),('observe','request-changes','reconcile-changes'))
        self.fingerprint=hashlib.sha256(b'test-client').hexdigest()
        self.bindings=human.HumanActionBindings({self.fingerprint:self.grant})
        self.resolver=Mock(return_value=self.document)
        self.host=local.LocalManager(self.bindings,self.resolver,authority='localhost:8765')
        patcher=patch.object(human.ssl,'SSLSocket',TLS);patcher.start();self.addCleanup(patcher.stop)

    def test_loader_contains_no_room_state_and_document_uses_existing_renderer(self):
        channel=TLS(wire(method='GET',target='/?page=project'))
        self.host.handle(channel)
        self.assertIn(b'200 OK',channel.output);self.resolver.assert_not_called()
        self.assertIn(b'no-store',channel.output);self.assertNotIn(b'owner/repo',channel.output)
        channel=TLS(wire());self.host.handle(channel)
        value=json.loads(channel.output.split(b'\r\n\r\n',1)[1])
        self.assertEqual(value['status'],'available');self.assertIn('owner/repo',value['html'])
        self.assertIn('manager-data',value['html'])
        session=self.resolver.call_args.args[0];self.assertFalse(session.allowed('observe'))

    def test_unregistered_and_revoked_certificates_never_disclose_document(self):
        self.bindings.revoke(self.fingerprint);channel=TLS(wire());self.host.handle(channel)
        self.assertIn(b'403 Forbidden',channel.output);self.resolver.assert_not_called()
        self.bindings.bind(self.fingerprint,self.grant)
        def revoke(session):self.bindings.revoke(self.fingerprint);return self.document
        self.host.document_for=revoke;channel=TLS(wire());self.host.handle(channel)
        self.assertIn(b'403 Forbidden',channel.output);self.assertNotIn(b'owner/repo',channel.output)

    def test_wrong_room_and_empty_grants_fail_closed(self):
        other=FieldNotesDocument(self.model,(ProjectBinding(RoomIdentity('deployment','other','stream'),'project','owner/repo'),))
        self.resolver.return_value=other;channel=TLS(wire());self.host.handle(channel)
        self.assertIn(b'403 Forbidden',channel.output)
        self.bindings.bind(self.fingerprint,human.HumanActionGrant('deployment','room','instance','manager',self.grant.human))
        self.resolver.reset_mock();channel=TLS(wire());self.host.handle(channel);self.resolver.assert_not_called()

    def test_routes_framing_origin_and_authority_cannot_supply_permission(self):
        bad=[wire(target='/other'),wire(method='GET',target='/secret'),wire(extra='Host: localhost:8765\r\n'),
             wire(extra='Origin: https://evil.invalid\r\n'),wire(extra='Transfer-Encoding: chunked\r\n'),
             wire(payload={'version':1,'action':'observe','payload':{'kind':'document','authorized':True}}),
             wire(payload={'version':1,'action':'start','payload':{}}),
             b'POST '+human.PATH.encode()+b' HTTP/1.1\r\nHost: localhost:8765\r\nContent-Type: application/json\r\nContent-Length: 999999\r\n\r\n']
        for request in bad:
            with self.subTest(request=request[:40]):
                channel=TLS(request);self.host.handle(channel);self.assertIn(b'403 Forbidden',channel.output)
        self.resolver.assert_not_called()

    def test_request_scope_and_legacy_receive_preserve_revocation_and_expiry(self):
        channel=TLS();conn=self.bindings.accept(channel)
        frame={'version':1,'action':'observe','payload':{}}
        with conn.request(frame) as (_,session):
            self.assertTrue(session.allowed('observe'));self.assertFalse(session.allowed('request-changes'))
        self.assertFalse(session.allowed('observe'))
        with patch.object(human,'receive_frame',return_value=frame):
            with conn.receive() as (_,fresh):self.assertTrue(fresh.allowed('observe'))
        self.assertFalse(fresh.allowed('observe'))
        with conn.request(frame):
            with patch.object(human,'receive_frame',side_effect=AssertionError('must not read nested frame')):
                with self.assertRaises(LedgerError):
                    with conn.receive():pass

    def test_no_action_owner_means_no_implicit_actions(self):
        channel=TLS(wire(payload={'version':1,'action':'observe','payload':{'kind':'lifecycle'}}))
        self.host.handle(channel);self.assertIn(b'403 Forbidden',channel.output)
        self.resolver.assert_not_called()

    def test_server_borrows_listener_restores_timeout_and_requires_tls(self):
        class Context:
            verify_mode=ssl.CERT_REQUIRED;minimum_version=ssl.TLSVersion.TLSv1_3
        listener=Mock();listener.getsockname.return_value=('127.0.0.1',8765);listener.gettimeout.return_value=2
        with patch.object(local.ssl,'SSLContext',Context):
            self.host.serve(listener,Context(),lambda:True)
            listener.accept.assert_not_called();listener.close.assert_not_called()
            self.assertEqual(listener.settimeout.call_args.args,(2,))
            listener.getsockname.return_value=('0.0.0.0',8765)
            with self.assertRaises(LedgerError):self.host.serve(listener,Context(),lambda:True)

    def test_authority_is_explicit_loopback_with_port(self):
        for value in ('evil.invalid:8765','localhost','127.0.0.1:0','[::1]:65536','localhost:1/path'):
            with self.assertRaises(LedgerError):local.LocalManager(self.bindings,self.resolver,authority=value)

    def test_existing_action_host_receives_only_live_bound_session(self):
        import test_manager_actions as fixture
        from uas.manager_action_host import FieldNotesActionHost
        scenario=fixture.ManagerActionsTests();scenario.setUp();self.addCleanup(scenario.doCleanups)
        seen=[]
        def authenticate(context):seen.append(context);return context
        action=FieldNotesActionHost(scenario.actions,authenticate)
        self.host.action_host_for=lambda session:action
        channel=TLS(wire(payload={'version':1,'action':'observe','payload':{'kind':'run','run_id':'run'}}))
        self.host.handle(channel)
        result=json.loads(channel.output.split(b'\r\n\r\n',1)[1])
        self.assertEqual(result['status'],'available');self.assertEqual(result['scope']['room_id'],'room')
        self.assertTrue(seen);self.assertFalse(seen[0].allowed('observe'))
        channel=TLS(wire(payload={'version':1,'action':'request-changes','payload':{
            'kind':'execute','request':{'action':'reconcile-changes'}}}))
        before=len(seen);self.host.handle(channel)
        self.assertIn(b'403 Forbidden',channel.output);self.assertEqual(len(seen),before)

    def test_owner_failure_is_sanitized_and_does_not_retry(self):
        self.host.document_for=Mock(side_effect=RuntimeError('private path or secret'))
        channel=TLS(wire());self.host.handle(channel)
        self.assertIn(b'503 Service Unavailable',channel.output)
        self.assertNotIn(b'private path',channel.output);self.host.document_for.assert_called_once()

    def test_server_failed_handshake_closes_raw_and_keeps_borrowed_listener(self):
        raw=Mock();raw.__enter__=Mock(return_value=raw);raw.__exit__=Mock(return_value=False)
        class Context:
            verify_mode=ssl.CERT_REQUIRED;minimum_version=ssl.TLSVersion.TLSv1_3
            def wrap_socket(self,*args,**kwargs):raise OSError('handshake failed')
        listener=Mock();listener.getsockname.return_value=('127.0.0.1',8765)
        listener.gettimeout.return_value=None;listener.accept.return_value=(raw,('127.0.0.1',123))
        stop=Mock(side_effect=[False,True])
        with patch.object(local.ssl,'SSLContext',Context):self.host.serve(listener,Context(),stop)
        raw.__exit__.assert_called_once();listener.close.assert_not_called()
        self.assertEqual(listener.settimeout.call_args.args,(None,))


class ManagerSelectionTests(unittest.TestCase):
    def value(self):
        return {'version':1,'purpose':'local-manager-v1','deployment_id':'deployment','room_id':'room',
            'instance_id':'instance','configuration_sha256':'a'*64,'authority':'localhost:8765',
            'manager_id':'manager','client_certificate_sha256':'b'*64,
            'human_origin':Origin('operator','human','session','epoch',()).canonical(),
            'actions':['observe'],'tls':{'trust_file':'/secure/ca.pem','certificate_file':'/secure/server.pem',
                                       'private_key_file':'/secure/key.pem'}}
    def parse(self,value):
        return local.ManagerSelection.parse(value,deployment_id='deployment',room_id='room',
                                            instance_id='instance',configuration_sha256='a'*64)
    def test_selection_no_tls_read_and_factory(self):
        with patch.object(local,'_held_tls',side_effect=AssertionError('setup must not open credentials')):
            selection=self.parse(self.value())
            manager=selection.manager(lambda _:None)
            self.assertEqual(manager.authority,'localhost:8765')
            value=self.value();value['actions'].append('open-run')
            self.assertEqual(selection.grant.actions,('observe',))
        ref={'path':'/secure/manager.json','sha256':'c'*64}
        with patch.object(local,'read_manifest',return_value=self.value()) as read:
            result=local.ManagerSelection.read(ref,deployment_id='deployment',room_id='room',
                instance_id='instance',configuration_sha256='a'*64)
            read.assert_called_once_with(ref['path'],ref['sha256'])
            self.assertEqual(result,selection)
    def test_exact_scope_fields_actions_and_paths(self):
        for key,bad in [('instance_id','other'),('configuration_sha256','d'*64),('version',True),
                        ('purpose','other'),('authority','remote:8765'),('authority','localhost:0'),
                        ('client_certificate_sha256','bad'),('actions',[]),('actions',['observe','start']),
                        ('actions',['observe','observe']),('actions',['observe','open-run']),
                        ('actions',['observe','request-changes'])]:
            value=self.value();value[key]=bad
            with self.subTest(key=key,bad=bad),self.assertRaises((LedgerError,ValueError,TypeError)):
                self.parse(value)
        for mutate in (lambda v:v.update(extra=True),lambda v:v['tls'].update(private_key_file='/secure/../key'),
                       lambda v:v['human_origin'].update(extra=True)):
            value=self.value();mutate(value)
            with self.assertRaises((LedgerError,ValueError,TypeError)):self.parse(value)
    def test_runtime_held_context_identity_rechecked(self):
        selection=self.parse(self.value())
        info=SimpleNamespace(st_dev=1,st_ino=2,st_size=3,st_mtime_ns=4,st_ctime_ns=5,
                             st_mode=0o100600,st_uid=0,st_gid=0,st_nlink=1)
        identity=local._tls_identity(info)
        with patch.object(local,'_held_tls',side_effect=[(3,identity),(4,identity),(5,identity)]) as held, \
             patch.object(local.os,'fstat',return_value=info),patch.object(local,'server_tls_context') as context:
            self.assertIs(selection.tls_context(),context.return_value)
            self.assertEqual(held.call_count,3)
            self.assertEqual(context.call_args.kwargs,{'certificate_file':'/proc/self/fd/3',
                'private_key_file':'/proc/self/fd/4','trust_file':'/proc/self/fd/5'})
            self.assertEqual([c.kwargs['private'] for c in held.call_args_list],[False,True,False])
        with patch.object(local,'_held_tls',return_value=(3,identity)), \
             patch.object(local.os,'fstat',return_value=SimpleNamespace(**{**vars(info),'st_size':99})), \
             patch.object(local,'server_tls_context'):
            with self.assertRaisesRegex(LedgerError,'REFERENCE_CHANGED'):selection.tls_context()
    def test_held_tls_rejects_permissions_owner_type_and_closes(self):
        from contextlib import ExitStack
        info=SimpleNamespace(st_dev=1,st_ino=2,st_size=3,st_mtime_ns=4,st_ctime_ns=5,
                             st_mode=0o100600,st_uid=0,st_gid=0,st_nlink=1)
        directory=SimpleNamespace(st_uid=0,st_mode=0o40700)
        cases=({'st_mode':0o100644},{'st_mode':0o20600},{'st_nlink':2},
               {'st_size':0},{'st_size':1048577},{'st_uid':987654})
        for change in cases:
            with self.subTest(change=change),patch.object(local.os,'open',side_effect=[10,11,12]), \
                 patch.object(local.os,'close') as close,patch.object(local.os,'getuid',return_value=1000), \
                 patch.object(local.os,'fstat',side_effect=[directory,SimpleNamespace(**{**vars(info),**change})]):
                with self.assertRaises(LedgerError),ExitStack() as stack:
                    local._held_tls('/secure/key',private=True,stack=stack)
                self.assertEqual([c.args[0] for c in close.call_args_list],[10,11,12])
        with patch.object(local.os,'open',side_effect=[10,11,OSError('symlink denied')]), \
             patch.object(local.os,'close') as close,patch.object(local.os,'fstat',return_value=directory):
            with self.assertRaises(OSError),ExitStack() as stack:
                local._held_tls('/secure/key',private=True,stack=stack)
            self.assertEqual([c.args[0] for c in close.call_args_list],[10,11])
        with patch.object(local.os,'open',side_effect=[10,11,12]) as opened, \
             patch.object(local.os,'close'),patch.object(local.os,'fstat',side_effect=[directory,info]):
            with ExitStack() as stack:
                fd,identity=local._held_tls('/secure/key',private=True,stack=stack)
                self.assertEqual(fd,12);self.assertEqual(identity,local._tls_identity(info))
            self.assertTrue(opened.call_args.args[1]&local.os.O_NOFOLLOW)
