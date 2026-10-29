"""Controlled local owner composition; no socket/process/Engine operations."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from uas.local_installation import Installation,LocalInstallationError
from uas.local_host import LocalController,peer_owner


class LocalHostTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.project=self.root/'project.json'
        self.project.write_bytes((Path(__file__).parent/'fixtures/two-rooms.json').read_bytes())
        self.value={'version':1,'project':self.ref(self.project),'native':None,'manager':None}
        self.installation=Installation(self.root/'install')

    def ref(self,p):return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    def setup(self):self.installation.setup(json.dumps(self.value).encode())
    def packet(self,action='status',room='alpha'):return json.dumps({'action':action,'room_id':room}).encode()

    def test_no_accounts_inspection_never_constructs_runtime(self):
        self.setup();factory=Mock();services=Mock()
        owner=LocalController(self.installation,factory,services=services)
        room=next(iter(owner.rooms))
        for action in ('start','status','stop'):
            value=owner.handle(self.packet(action,room))
            self.assertEqual(value['state'],'not-configured');self.assertEqual(value['runtime'],'not-started')
        factory.assert_not_called();self.assertEqual(services.mock_calls,[])

    def test_disconnect_after_effect_does_not_end_host(self):
        import os, stat
        from types import SimpleNamespace
        from uas.local_host import serve
        self.setup()
        controller=Mock();controller.handle.return_value={'infrastructure':{'phase':'running'}}
        channel=Mock();channel.__enter__=Mock(return_value=channel);channel.__exit__=Mock(return_value=False)
        channel.recv.return_value=self.packet('start')
        channel.sendall.side_effect=BrokenPipeError('caller left after start')
        listener=Mock();listener.accept.return_value=(channel,None)
        stop=Mock(side_effect=[False,False,True])
        node=SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFSOCK|0o600,st_uid=os.geteuid())
        with patch.object(self.installation,'_safe_root'),patch('uas.local_host.socket.socket',return_value=listener),patch('uas.local_host.peer_owner'),patch('pathlib.Path.lstat',return_value=node),patch('pathlib.Path.unlink'):
            serve(self.installation,controller,stopped=stop)
        self.assertEqual(controller.handle.call_count,2)
        self.assertEqual(listener.accept.call_count,2)
        listener.close.assert_called_once()


    def configured(self):
        from test_local_installation import native_selection
        native=self.root/'native.json';native.write_text(json.dumps(native_selection(json.loads(self.project.read_text()))))
        self.value['native']=self.ref(native);self.setup()
        backend=Mock();backend.start.return_value={'infrastructure':{'phase':'running'}}
        backend.status.return_value={'infrastructure':{'phase':'running'}}
        backend.stop.return_value={'infrastructure':{'phase':'stopped'}}
        backend.resources.return_value=('supervisor','backend',{'instance_id':'actual-instance'})
        factory=Mock(return_value=backend);services=Mock();services.ensure.return_value={'hub':'ready'}
        return LocalController(self.installation,factory,services=services),backend,services

    def test_lifecycle_consumes_existing_owner_and_service_confirmation(self):
        owner,native,services=self.configured();room=next(iter(owner.rooms))
        value=owner.handle(self.packet('start',room));self.assertEqual(value['services'],{'hub':'ready'})
        services.ensure.assert_called_once_with(room,'supervisor','backend',{'instance_id':'actual-instance'})
        self.assertEqual(owner.handle(self.packet('stop',room))['infrastructure']['phase'],'stopped')
        native.stop.assert_called_once_with(room)
        owner.handle(self.packet('status',room));services.status.assert_called_once_with(room)

    def test_unknown_service_start_is_not_retried_or_reported_success(self):
        owner,native,services=self.configured();services.ensure.side_effect=OSError('unknown')
        with self.assertRaises(OSError):owner.handle(self.packet('start',next(iter(owner.rooms))))
        self.assertEqual(native.start.call_count,1);self.assertEqual(services.ensure.call_count,1)
        native.stop.assert_not_called()

    def test_refused_actions_cannot_supply_paths_commands_or_other_room(self):
        owner,native,services=self.configured()
        for packet in (b'{"action":"destroy","room_id":"alpha"}',b'{"action":"start","room_id":"foreign"}',
                       b'{"action":"start","room_id":"alpha","command":"shell"}'):
            with self.assertRaises(LocalInstallationError):owner.handle(packet)
        native.start.assert_not_called();services.ensure.assert_not_called()

    def test_revocation_requires_exact_true_from_owned_services(self):
        owner,_,services=self.configured()
        for value in (False,None,1,'true'):
            services.revoke.return_value=value;self.assertFalse(owner.revoke('instance','workstation'))
        services.revoke.return_value=True;self.assertTrue(owner.revoke('instance','workstation'))
        with patch('uas.local_host.os.geteuid',return_value=1000):
            self.assertFalse(owner.authorize('start',next(iter(owner.rooms)),None))
