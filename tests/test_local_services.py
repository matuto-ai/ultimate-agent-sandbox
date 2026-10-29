"""Controlled root-side lifecycle doubles; never spawn or touch Docker."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import stat
import unittest
from unittest.mock import Mock,patch
from uas import local_services as services
from uas.lifecycle import LifecycleError

class LocalServicesTests(unittest.TestCase):
    def owner(self):
        with patch.object(services.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFREG)):
            return services.LocalServices(8)
    def backend(self):
        backend=Mock();backend.profile.room={'id':'alpha','seats':[]}
        backend.admit.return_value={'State':{'Running':True,'Pid':90}}
        backend.ensure_hub.return_value={'Id':'owned','State':{'Running':False}}
        backend.listeners=[Mock(),Mock()];backend.listeners[0].fileno.return_value=9;backend.listeners[1].fileno.return_value=10
        backend.layout.return_value={'control':Path('/owned/control')}
        return backend
    def test_mapping_exact_bootstrap_format(self):
        data={'uid_map':'         0     100000      65536\n','gid_map':'         0     100000      65536\n','overflow_uid':65534,'overflow_gid':65534}
        def read(path):return data[path.name] if path.name in {'uid_map','gid_map'} else '65534'
        with patch.object(services.Path,'read_text',read):
            self.assertEqual(services.mapping_digest(90),hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest())
    def test_ready_requires_receipt_and_inherits_lock(self):
        owner=self.owner();backend=self.backend();process=Mock();process.poll.return_value=None
        with patch.object(services.os,'geteuid',return_value=0),patch.object(services,'mapping_digest',return_value='a'*64),patch.object(services.os,'stat',return_value=SimpleNamespace(st_gid=55)),patch.object(services.subprocess,'Popen',return_value=process) as spawn,patch.object(services,'read_ready',return_value={'status':'ready'}) as ready,patch.object(services,'send_startup'):
            result=owner.ensure('alpha',Mock(),backend,{'instance_id':'instance'})
            self.assertEqual(result['hub'],'ready');ready.assert_called_once()
            self.assertEqual(spawn.call_args.kwargs['pass_fds'],(9,10,8))
            self.assertEqual(spawn.call_args.kwargs['user'],165533)
            owner.ensure('alpha',Mock(),backend,{'instance_id':'instance'});spawn.assert_called_once()
    def test_uncertain_start_never_retries(self):
        owner=self.owner();backend=self.backend()
        with patch.object(services.os,'geteuid',return_value=0),patch.object(services,'mapping_digest',return_value='a'*64),patch.object(services.os,'stat',return_value=SimpleNamespace(st_gid=55)),patch.object(services.subprocess,'Popen',side_effect=TimeoutError) as spawn:
            with self.assertRaises(TimeoutError):owner.ensure('alpha',Mock(),backend,{'instance_id':'instance'})
            self.assertEqual(owner.ensure('alpha',Mock(),backend,{'instance_id':'instance'})['hub'],'unknown');spawn.assert_called_once()
    def test_participant_stop_preserves_known_idle_hub(self):
        owner=self.owner();process=Mock();process.poll.return_value=None
        owner._rooms['alpha']={'instance':'instance','state':'ready','process':process}
        self.assertIs(owner.revoke('instance','participants'),True);process.stdin.close.assert_not_called()
        self.assertIs(owner.revoke('unowned','participants'),False)
        process.poll.return_value=1;self.assertIs(owner.revoke('instance','participants'),False)
    def test_shutdown_confirms_stopped_container(self):
        owner=self.owner();process=Mock();backend=self.backend()
        backend._hub.side_effect=[{'Id':'owned','State':{'Running':True}},{'Id':'owned','State':{'Running':False}}]
        owner._rooms['alpha']={'instance':'instance','state':'ready','process':process,'backend':backend,'resource_state':{},'hub_id':'owned'}
        self.assertIs(owner.close(),True);process.stdin.close.assert_called_once();process.wait.assert_called_once_with(timeout=10)
        backend._run.assert_called_once_with(['stop','--time','5','owned'])
    def test_shutdown_unknown_is_not_fenced(self):
        owner=self.owner();process=Mock();process.wait.side_effect=TimeoutError
        owner._rooms['alpha']={'instance':'instance','state':'ready','process':process}
        self.assertIs(owner.close(),False)
    def test_ready_receipt_rejects_wrong_instance(self):
        process=Mock();process.poll.return_value=None
        raw=json.dumps({'version':1,'status':'ready','room_id':'alpha','room_instance':'other','controller':'x'}).encode()+b'\n'
        with patch.object(services.select,'select',return_value=([process.stdout],[],[])),patch.object(services.os,'read',side_effect=[bytes([c]) for c in raw]):
            with self.assertRaisesRegex(LifecycleError,'READY_SCOPE'):services.read_ready(process,'alpha','instance')
    def test_write_deadline_has_no_blocking_retry(self):
        process=Mock();process.stdin.fileno.return_value=9
        with patch.object(services.os,'set_blocking') as mode,patch.object(services.time,'monotonic',side_effect=[0,11]):
            with self.assertRaisesRegex(LifecycleError,'WRITE_UNKNOWN'):services.send_startup(process,b'{}\n')
        mode.assert_called_once_with(9,False)
    def test_shutdown_refuses_replacement_or_invalid_hub(self):
        for replacement in (True,False):
            owner=self.owner();process=Mock();backend=self.backend()
            backend._hub.return_value={'Id':'replacement' if replacement else 'owned','State':{'Running':True}}
            if not replacement:backend.validate_hub.side_effect=LifecycleError('wrong owner')
            owner._rooms['alpha']={'instance':'instance','state':'ready','process':process,'backend':backend,'resource_state':{},'hub_id':'owned'}
            self.assertIs(owner.close(),False);backend._run.assert_not_called()
    def test_receipt_timeout_retains_handle_for_cleanup_not_retry(self):
        owner=self.owner();backend=self.backend();process=Mock();process.poll.return_value=None
        backend._hub.return_value={'Id':'owned','State':{'Running':False}}
        with patch.object(services.os,'geteuid',return_value=0),patch.object(services,'mapping_digest',return_value='a'*64),patch.object(services.os,'stat',return_value=SimpleNamespace(st_gid=55)),patch.object(services.subprocess,'Popen',return_value=process) as spawn,patch.object(services,'read_ready',side_effect=TimeoutError),patch.object(services,'send_startup'):
            with self.assertRaises(TimeoutError):owner.ensure('alpha',Mock(),backend,{'instance_id':'instance'})
            self.assertEqual(owner.status('alpha')['hub'],'unknown')
            self.assertIs(owner.close(),True);process.stdin.close.assert_called_once()
            self.assertEqual(owner.ensure('alpha',Mock(),backend,{'instance_id':'instance'})['hub'],'stopped');spawn.assert_called_once()
