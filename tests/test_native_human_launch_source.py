"""Protected launch input source checks; no socket/TLS/native or permission effects."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

from uas.ledger import LedgerError, _json
from uas.native_image_package import canonical
from uas.native_qualification import QualificationPlan
from uas.native_human_launch import (GRANTS_DIRECTORY, NativeHumanLaunch, _identity, _parse,
    host_bindings, open_grant, raw_stream_identity, read_held_grant, reference)
import test_native_qualification as qualification_fixture


class NativeHumanLaunchSourceTests(unittest.TestCase):
    def setUp(self):
        fixture=qualification_fixture.NativeQualificationTests();fixture.setUp();self.plan=fixture.plan()
        self.value={'version':1,'purpose':'one-original-native-qualification',
            'deployment_id':self.plan.config['deployment']['id'],'room_id':self.plan.room['id'],
            'configuration_sha256':self.plan.config_digest,'installation_nonce':self.plan.installation['nonce'],
            'manager_id':'manager','client_certificate_sha256':'c'*64,
            'human_origin':{'actor_id':'human','participant_id':'human','incarnation_id':'authenticated-context',
                'authority_version':'operator-v1','capabilities':['human-control-run','human-open-run']},
            'actions':['open-run','authorize-run-request','observe','request-changes','reconcile-changes'],
            'tls':{'trust_file':'/installed/trust.pem','certificate_file':'/installed/server.pem',
                   'private_key_file':'/installed/private.pem'}}
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)

    def selected(self, value=None):
        raw=_json(self.value if value is None else value).encode()
        selection=deepcopy(self.plan.installation)
        selection['human_host_manifest']={'path':str(GRANTS_DIRECTORY/(selection['nonce']+'.json')),
                                         'sha256':hashlib.sha256(raw).hexdigest()}
        self.plan=QualificationPlan(self.plan.config_text,selection,installation_digest=self.plan.installation_digest)
        return raw

    def held(self, raw):
        filename=Path(self.tmp.name)/'operator-input.json';filename.write_bytes(raw)
        fd=os.open(filename,os.O_RDONLY);self.addCleanup(os.close,fd)
        original=os.fstat
        def controlled(fd):
            info=original(fd)
            return N(**{name:getattr(info,name) for name in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns',
                'st_gid','st_nlink')},st_uid=0,st_mode=stat.S_IFREG|0o600)
        return fd,controlled

    def test_finite_new_module_loader_preserves_ids_without_fixture_reexports(self):
        # Loading is not executing. Keep this exact inventory finite: all new
        # B2 test modules plus the original fixture module they may reference.
        # The global partition verifier remains unchanged and still rejects
        # duplicate IDs; never repair this by excluding or deduplicating tests.
        import importlib
        modules=('test_native_qualification','test_native_human_launch_source',
                 'test_native_human_host_source','test_native_human_tls')
        identifiers=[]
        for name in modules:
            pending=[unittest.defaultTestLoader.loadTestsFromModule(importlib.import_module(name))]
            current=[]
            while pending:
                item=pending.pop()
                if isinstance(item,unittest.TestSuite):pending.extend(item)
                else:
                    self.assertEqual(type(item).__module__,name,'fixture TestCase reexported from '+name)
                    current.append(item.id())
            self.assertTrue(current,name)
            identifiers.extend(current)
        self.assertEqual(len(identifiers),len(set(identifiers)))

    def test_default_absent_and_exact_existing_fixed_reference_only(self):
        self.assertIsNone(reference(self.plan));self.selected()
        self.assertEqual(reference(self.plan),self.plan.installation['human_host_manifest'])
        for bad in ('/tmp/grant.json',str(GRANTS_DIRECTORY/'different.json')):
            self.plan.installation['human_host_manifest']['path']=bad
            self.plan._declarations=canonical({'configuration':self.plan.config,'installation':self.plan.installation})
            with self.assertRaisesRegex(LedgerError,'REFERENCE_INVALID'):reference(self.plan)

    def test_explicit_grant_scopes_not_nonce_or_json_correlation_authority(self):
        raw=self.selected();self.assertEqual(_parse(raw,self.plan),self.value)
        for change in ({'actions':[]},{'actions':['open-run','authorize-run-request','start']},
                {'purpose':'all-room-instances'},{'room_id':'foreign'},{'installation_nonce':'f'*32},
                {'authorized':True},{'human_origin':{**self.value['human_origin'],'capabilities':['human-open-run']}},
                {'actions':['open-run','authorize-run-request','request-changes']},
                {'tls':{**self.value['tls'],'private_key_file':'/bad/../key'}}):
            with self.subTest(change=change),self.assertRaises((LedgerError,ValueError)):
                _parse(_json({**self.value,**change}).encode(),self.plan)
        with self.assertRaisesRegex(LedgerError,'GRANT_INVALID'):
            _parse(b'{"version":1,"version":1}',self.plan)

    def test_held_file_provenance_hash_identity_and_parse_are_rechecked(self):
        raw=self.selected();fd,controlled=self.held(raw)
        with patch('uas.native_human_launch.os.fstat',side_effect=controlled):
            value,identity=read_held_grant(fd,self.plan)
            self.assertEqual(value,self.value)
            self.assertEqual(read_held_grant(fd,self.plan,identity=identity),(value,identity))
            with self.assertRaisesRegex(LedgerError,'CHANGED'):
                read_held_grant(fd,self.plan,identity=(99,)*9)
        for change in ({'st_uid':1000},{'st_nlink':2},{'st_mode':stat.S_IFREG|0o622}):
            node=controlled(fd);node.__dict__.update(change)
            with patch('uas.native_human_launch.os.fstat',return_value=node),self.assertRaisesRegex(LedgerError,'PROTECTED'):
                read_held_grant(fd,self.plan)
        node=controlled(fd);changed=deepcopy(node);changed.st_ctime_ns+=1
        with patch('uas.native_human_launch.os.fstat',side_effect=[node,node,changed]),self.assertRaisesRegex(LedgerError,'CHANGED'):
            read_held_grant(fd,self.plan)
        with patch('uas.native_human_launch.os.fstat',side_effect=controlled), \
                patch('uas.native_human_launch.os.pread',return_value=raw+b' '),self.assertRaisesRegex(LedgerError,'CHANGED'):
            read_held_grant(fd,self.plan)

    def test_root_opener_never_creates_or_changes_permissions_and_rejects_unprotected_parent(self):
        self.selected();node=N(st_uid=1000,st_mode=stat.S_IFDIR|0o700)
        with patch('uas.native_human_launch.os.getuid',return_value=0), \
                patch('uas.native_human_launch.os.open',side_effect=[40,41]) as opened, \
                patch('uas.native_human_launch.os.close') as closed, \
                patch('uas.native_human_launch.os.fstat',return_value=node),self.assertRaisesRegex(LedgerError,'DIRECTORY'):
            open_grant(self.plan)
        self.assertTrue(all(not call.args[1]&os.O_CREAT for call in opened.call_args_list))
        self.assertEqual([c.args[0] for c in closed.call_args_list],[40,41])

    def test_exact_raw_connected_stream_only_not_tls_listener_or_other_object(self):
        class Raw:
            family=2
            def fileno(self):return 44
            def getsockopt(self,level,option):return 1 if option==3 else 0
            def getpeername(self):return ('127.0.0.1',1234)
            def getsockname(self):return ('127.0.0.1',2345)
        channel=Raw();node=N(st_dev=1,st_ino=2,st_mode=stat.S_IFSOCK|0o600)
        with patch('uas.native_human_launch.socket.socket',Raw), \
                patch('uas.native_human_launch.os.fstat',return_value=node):
            identity=raw_stream_identity(channel);self.assertEqual(identity[:3],(44,1,2))
            with self.assertRaisesRegex(LedgerError,'RAW_STREAM'):raw_stream_identity(N())
            channel.getsockopt=lambda *_:1
            with self.assertRaisesRegex(LedgerError,'RAW_STREAM'):raw_stream_identity(channel)
            channel.getsockopt=lambda level,option:1 if option==3 else 0
            channel.getpeername=Mock(side_effect=OSError('unconnected'))
            with self.assertRaisesRegex(LedgerError,'RAW_STREAM'):raw_stream_identity(channel)

    def test_one_original_transfer_no_retry_after_uncertain_start(self):
        self.selected();channel=N(fileno=lambda:44,close=Mock());identity=(44,1,2,('127.0.0.1',1),('127.0.0.1',2))
        resources={'room_id':self.plan.room['id'],'instance':'a'*32}
        with patch('uas.native_human_launch.raw_stream_identity',return_value=identity), \
                patch('uas.native_human_launch.open_grant',return_value=(45,self.value,(1,)*9)), \
                patch('uas.native_human_launch.read_held_grant'),patch('uas.native_human_launch.time.monotonic',return_value=10), \
                patch('uas.native_human_launch.os.close') as close:
            owner=NativeHumanLaunch(self.plan,channel);result=owner.transfer(resources,deadline=50)
            self.assertNotIn('human_origin',str(result));self.assertNotIn('actions',result)
            with self.assertRaisesRegex(LedgerError,'CUSTODY'):owner.transfer(resources,deadline=50)
            owner.close();owner.close();channel.close.assert_called_once();close.assert_called_once_with(45)

    def test_host_mints_exact_instance_from_original_protected_grant_not_wire_principal(self):
        raw=self.selected();fd,controlled=self.held(raw)
        resources={'room_id':self.plan.room['id'],'instance':'a'*32}
        with patch('uas.native_human_launch.os.fstat',side_effect=controlled):
            _,identity=read_held_grant(fd,self.plan)
            selection={'grant_fd':fd,'grant_identity':list(identity),'raw_fd':44,'raw_identity':[44,1,2,[],[]],
                       'instance':resources['instance'],'deadline':50}
            with patch('uas.native_human_launch.time.monotonic',return_value=10):
                bindings,tls=host_bindings(self.plan,resources,selection)
                grant=bindings._bindings[self.value['client_certificate_sha256']][0]
                self.assertEqual(grant.instance_id,resources['instance']);self.assertEqual(grant.human.canonical(),self.value['human_origin'])
                self.assertEqual(tuple(self.value['actions']),grant.actions)
                self.assertEqual(tls,self.value['tls'])
                for invalid in ({'instance':'b'*32},{'human_origin':self.value['human_origin']},{'deadline':float('inf')}):
                    with self.assertRaisesRegex(LedgerError,'CUSTODY'):
                        host_bindings(self.plan,resources,{**selection,**invalid})
