"""One setup action composes planned Engine and canonical metadata handoff."""
from contextlib import ExitStack
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uas import local_setup as setup
from uas.local_host_profile import HostProfileError,canonical,digest
from uas.local_prepare import assemble
from tests import test_local_prepare as fixtures
from tests.test_local_host_plan import profile,observation
from tests.test_local_engine_prepare import observation as engine_observation


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.LocalPrepareTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        f=self.f;self.profile=profile('owned');self.profile['installation_id']='b'*32
        self.profile['engine'].update(data_root='/var/lib/uas-owned',exec_root='/run/uas-owned',socket='/run/uas-owned.sock')
        f.settings.update(version=2,host_profile=self.profile);f.write(f.settings_file,f.settings)
        self.old=observation();self.old.update(engine=None,subuid=[],subgid=[])
        self.old['storage'].update(path=str(f.root),identity=[f.root.stat().st_dev,f.root.stat().st_ino])
        self.receipt=f.root/'host-receipts';self.bootstrap=f.root/'engine-receipts'
        self.current=None;self.order=[]
    def proposal(self):
        fake=SimpleNamespace(inspect_exclusive=lambda _:engine_observation())
        with patch.dict(sys.modules,{'uas.local_engine_observe':fake}),patch.object(setup,'inspect',return_value=self.old):
            return setup.proposal(self.f.project_file,self.f.settings_file,self.f.ws,self.f.hub,self.f.revision,
                host_receipt_root=str(self.receipt),engine_receipt_root=str(self.bootstrap),account_uid=981,account_gid=982)
    def prepared_engine(self,value):
        self.order.append('engine');self.bootstrap.mkdir(exist_ok=True)
        p=value['artifacts']['admission_profile'];current=deepcopy(self.old)
        current['engine']=observation()['engine'];current['engine']['docker_root']=p['engine']['data_root']+'/100000.100000'
        current['subuid']=current['subgid']=[{'user':p['mapping']['user'],'offset':100000,'size':65536}]
        current['allocated_ids']=sorted(set(current['allocated_ids'])|{981,982});self.current=current
        return {'profile':p,'plan_id':value['plan_id']}
    def rooms(self,value):
        self.order.append('rooms');self.receipt.mkdir(exist_ok=True)
        self.assertEqual(value['host_plan']['profile']['mode'],'reuse')
        self.assertFalse(value['host_plan']['blockers'])
        return {'native':assemble(value['config'],value['settings'],value['workstation'],value['hub'])}
    def stack(self):
        stack=ExitStack();real=os.fstat
        def rootstat(fd):
            fields=list(real(fd));fields[4]=fields[5]=0;return os.stat_result(fields)
        stack.enter_context(patch.object(setup.os,'geteuid',return_value=0))
        stack.enter_context(patch.object(setup.os,'fstat',side_effect=rootstat))
        stack.enter_context(patch.object(setup.engine,'canonical_node',return_value=None))
        stack.enter_context(patch.object(setup.engine,'apply',side_effect=self.prepared_engine))
        stack.enter_context(patch.object(setup,'inspect',side_effect=lambda *a,**k:self.current))
        stack.enter_context(patch.object(setup,'apply_rooms',side_effect=self.rooms))
        return stack
    def test_one_action_reaches_real_canonical_handoff_no_manual_profile_file(self):
        value=self.proposal()
        with self.stack():result=setup.apply(value,self.f.output)
        self.assertEqual(self.order,['engine','rooms']);self.assertEqual(result['status'],'local-host-prepared')
        native=json.loads((self.f.output/'native.json').read_bytes())
        self.assertEqual(native['host_profile'],value['engine']['artifacts']['admission_profile'])
        self.assertEqual(json.loads(self.f.settings_file.read_bytes())['host_profile']['mode'],'owned')
        self.assertTrue((self.bootstrap/'setup-room-request.json').is_file())
    def test_rehashed_selection_cannot_escape_actual_input_files(self):
        value=self.proposal();value['rooms']['settings']['rooms']['alpha']['quota_project_id']+=1
        value['plan_id']=digest({k:v for k,v in value.items() if k!='plan_id'})
        with self.stack(),self.assertRaisesRegex(HostProfileError,'SELECTION_CHANGED'):setup.apply(value,self.f.output)
        self.assertEqual(self.order,[])
    def test_unexpected_host_change_after_engine_stops_before_room_effects(self):
        value=self.proposal();original=self.prepared_engine
        def changed(p):
            result=original(p);self.current['networks'].append('192.168.50.0/24');return result
        with self.stack(),patch.object(setup.engine,'apply',side_effect=changed),self.assertRaisesRegex(HostProfileError,'HOST_CHANGED'):
            setup.apply(value,self.f.output)
        self.assertEqual(self.order,['engine'])
    def test_unknown_room_apply_reuses_exact_persisted_request(self):
        value=self.proposal();original=self.rooms
        def interrupted(p):
            self.order.append('rooms-unknown');raise OSError('unknown')
        with self.stack():
            with patch.object(setup,'apply_rooms',side_effect=interrupted),self.assertRaises(OSError):setup.apply(value,self.f.output)
            result=setup.apply(value,self.f.output)
        self.assertEqual(self.order,['engine','rooms-unknown','engine','rooms'])
        self.assertEqual(result['status'],'local-host-prepared')
