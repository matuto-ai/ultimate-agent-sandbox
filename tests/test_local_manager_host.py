"""Real SQLite projection composition, mocked network/TLS/process boundaries."""
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from uas import local_manager_host as host
from uas.ledger import RoomLedger, Origin, Command, Event, Transition, LedgerError
from uas.lifecycle import Supervisor, LifecycleError
from uas.manager_stream import ManagerReadModel, RoomIdentity
from uas.manager_ui import ProjectBinding
from uas.manager_actions import HumanSession
from uas.local_installation import Installation


class LocalManagerHostTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.ledger=RoomLedger(self.root/'room.db','room');self.addCleanup(self.ledger.close)
        self.model=ManagerReadModel(self.root/'manager.db');self.addCleanup(self.model.close)
        self.supervisor=Supervisor(self.root,'room',None,authorize=lambda *_:False,revoke=lambda *_:False)
        self.state={'instance_id':'instance','phase':'running'}
        for name,value in [('_locked',Mock(side_effect=lambda:nullcontext())),('_read',Mock(side_effect=lambda:self.state)),
                           ('manager_observations',Mock(side_effect=LifecycleError('NO_CONTROLLED_EXPORT')))]:
            p=patch.object(self.supervisor,name,value);p.start();self.addCleanup(p.stop)
        self.identity=RoomIdentity('deployment','room','instance')
        self.human=HumanSession('deployment','room','instance','manager',Origin('operator','human','session','epoch',()),
                                 lambda *_:True,lambda:True)
    def projection(self):
        p=host.LocalProjection(self.ledger,self.model,self.supervisor,self.identity,
                              ProjectBinding(self.identity,'project','owner/repo'))
        self.addCleanup(p.close);return p
    def append(self):
        self.ledger.apply(Command('op','counter','counter',None,{}),self.human.human,authorize=lambda *_:True,
            decide=lambda *_:Transition({'counter':1},(Event('counter.changed',{}),),{}))
    def test_real_snapshot_and_incremental_replay(self):
        projection=self.projection();doc=projection.refresh(self.human)
        self.assertEqual(self.model.cursor(self.identity),0)
        self.append();self.assertIs(projection.refresh(self.human),doc)
        self.assertEqual(self.model.cursor(self.identity),1)
        self.assertIn('manager-data',doc.render())
        self.assertEqual(len(self.model.events(self.identity)['events']),1)
    def test_scope_revocation_instance_change_and_replay_bound(self):
        p=self.projection();p.refresh(self.human)
        wrong=HumanSession('deployment','room','other','manager',self.human.human,lambda *_:True,lambda:True)
        with self.assertRaisesRegex(LedgerError,'SESSION_SCOPE'):p.refresh(wrong)
        with patch.object(type(self.human),'allowed',return_value=False):
            with self.assertRaisesRegex(LedgerError,'REVOKED'):p.refresh(self.human)
        self.state={'instance_id':'other','phase':'running'}
        with self.assertRaisesRegex(LedgerError,'INSTANCE_CHANGED'):p.refresh(self.human)
        self.state={'instance_id':'instance','phase':'running'};self.append()
        with patch.object(host,'MAX_REPLAY_EVENTS',0):
            with self.assertRaisesRegex(LedgerError,'REPLAY_LIMIT'):p.refresh(self.human)
        self.assertEqual(self.model.cursor(self.identity),0)
    def test_real_reader_does_not_initialize_missing_store(self):
        missing=self.root/'missing.db'
        with self.assertRaises(LedgerError):RoomLedger.open_reader(missing,'room')
        self.assertFalse(missing.exists())
    def test_composition_binds_exact_loopback_serves_closes_owned_resources(self):
        installation=Installation(self.root)
        config={'deployment':{'id':'deployment'},'rooms':[{'id':'room','project':{'id':'project','repository':'owner/repo'}}]}
        value={'manager':{'path':'/selected/manager.json','sha256':'a'*64}}
        selection=Mock(authority='localhost:8765');manager=selection.manager.return_value
        def serve(listener,context,stopped):
            resolver=selection.manager.call_args.args[0]
            self.assertIn('manager-data',resolver(self.human).render())
            self.assertTrue(stopped())
        manager.serve.side_effect=serve
        with patch.object(installation,'open',return_value=(value,config,{})), \
             patch.object(host.ManagerSelection,'read',return_value=selection) as read, \
             patch.object(host.socket,'socket') as socket:
            host.serve_local_manager(installation,self.supervisor,ledger_path=self.root/'room.db',stopped=lambda:True)
            socket.return_value.bind.assert_called_once_with(('127.0.0.1',8765))
            socket.return_value.close.assert_called_once()
            self.assertEqual(read.call_args.kwargs['instance_id'],'instance')
            manager.serve.assert_called_once()
    def test_bind_collision_no_retry_and_no_reader(self):
        installation=Installation(self.root)
        config={'deployment':{'id':'deployment'},'rooms':[{'id':'room'}]}
        with patch.object(installation,'open',return_value=({'manager':{}},config,{})), \
             patch.object(host.ManagerSelection,'read',return_value=Mock(authority='localhost:8765')), \
             patch.object(host.socket,'socket') as socket,patch.object(RoomLedger,'open_reader') as reader:
            socket.return_value.bind.side_effect=OSError('in use')
            with self.assertRaises(OSError):host.serve_local_manager(installation,self.supervisor,ledger_path='unused',stopped=lambda:True)
            socket.return_value.bind.assert_called_once();socket.return_value.close.assert_called_once()
            reader.assert_not_called()
    def test_instance_change_during_capture_does_not_publish(self):
        projection=self.projection();projection.refresh(self.human);self.append()
        original=projection.stream.capture
        def capture(*args,**kwargs):
            transfer=original(*args,**kwargs)
            self.state={'instance_id':'replacement','phase':'running'}
            return transfer
        with patch.object(projection.stream,'capture',side_effect=capture):
            with self.assertRaisesRegex(LedgerError,'INSTANCE_CHANGED'):projection.refresh(self.human)
        self.assertEqual(self.model.cursor(self.identity),0)
    def test_installation_change_rejected_by_document_owner(self):
        installation=Installation(self.root)
        config={'deployment':{'id':'deployment'},'rooms':[{'id':'room','project':{'id':'project','repository':'owner/repo'}}]}
        value={'manager':{'path':'/selected/manager.json','sha256':'a'*64}}
        selection=Mock(authority='localhost:8765')
        def serve(*_):
            resolver=selection.manager.call_args.args[0]
            with self.assertRaisesRegex(LedgerError,'INSTALLATION_CHANGED'):resolver(self.human)
        selection.manager.return_value.serve.side_effect=serve
        with patch.object(installation,'open',side_effect=[(value,config,{}),({'manager':None},config,{})]), \
             patch.object(host.ManagerSelection,'read',return_value=selection),patch.object(host.socket,'socket'):
            host.serve_local_manager(installation,self.supervisor,ledger_path=self.root/'room.db',stopped=lambda:True)
    def test_ready_and_tls_document_end_to_end_shutdown_closes_resources(self):
        import json
        from uas import human_mtls
        from uas.local_manager import ManagerSelection
        from test_local_manager import TLS, wire
        import hashlib
        installation=Installation(self.root)
        config={'deployment':{'id':'deployment'},'rooms':[{'id':'room','project':{'id':'project','repository':'owner/repo'}}]}
        value={'manager':{'path':'/selected/manager.json','sha256':'a'*64}}
        grant=human_mtls.HumanActionGrant('deployment','room','instance','manager',self.human.human,('observe',))
        selection=ManagerSelection('localhost:8765',hashlib.sha256(b'test-client').hexdigest(),grant,(), 'a'*64)
        order=[];closed=[]
        reader=RoomLedger.open_reader;model=ManagerReadModel
        def track_reader(*args):
            result=reader(*args);close=result.close
            result.close=lambda:(closed.append('ledger'),close())
            return result
        def track_model(*args):
            result=model(*args);close=result.close
            result.close=lambda:(closed.append('model'),close())
            return result
        def ready(receipt):
            order.append('ready');self.assertEqual(receipt['mode'],'observe-only')
            self.assertEqual(receipt['instance_id'],'instance')
        def serve(manager,*_):
            order.append('serve')
            channel=TLS(wire());manager.handle(channel)
            self.assertIn(b'200 OK',channel.output)
            payload=json.loads(channel.output.split(b'\r\n\r\n',1)[1])
            self.assertIn('manager-data',payload['html'])
            self.state={'instance_id':'replacement','phase':'running'}
            rejected=TLS(wire());manager.handle(rejected)
            self.assertIn(b'403',rejected.output);self.assertNotIn(b'manager-data',rejected.output)
        with patch.object(installation,'open',return_value=(value,config,{})), \
             patch.object(host.ManagerSelection,'read',return_value=selection), \
             patch.object(host.ManagerSelection,'tls_context',return_value=object()), \
             patch.object(host.socket,'socket') as socket, \
             patch.object(host.RoomLedger,'open_reader',side_effect=track_reader), \
             patch.object(host,'ManagerReadModel',side_effect=track_model), \
             patch.object(human_mtls.ssl,'SSLSocket',TLS), \
             patch('uas.local_manager.LocalManager.serve',serve):
            host.serve_local_manager(installation,self.supervisor,ledger_path=self.root/'room.db',
                                     stopped=lambda:True,on_ready=ready)
            socket.return_value.close.assert_called_once()
        self.assertEqual(order,['ready','serve']);self.assertEqual(closed,['model','ledger'])
