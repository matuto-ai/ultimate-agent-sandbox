"""Pure Gate resource declarations: no native, permission, quota or socket effects."""
from copy import deepcopy
from contextlib import contextmanager
from types import SimpleNamespace as N
import hashlib
import struct
import unittest
from unittest.mock import patch, Mock
from uas import native_gate_resources as gate
from uas import native_qualification_backend as backend
from uas.artifact_protocol import ArtifactError,RESERVATION_BYTES


def scope():
    return {'version':1,'evaluation_id':'evaluation','room_id':'room','room_instance':'1'*32,
        'project_id':'project','repository':'owner/repo','run_id':'run','generation':1,'participant_id':'actor',
        'policy_id':'policy','policy_version':1,'policy_digest':'2'*64,'gate_id':'gate','config_digest':'3'*64}


def elf():
    raw=bytearray(120);raw[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<H',raw,18,62);struct.pack_into('<Q',raw,32,64)
    struct.pack_into('<HH',raw,54,56,1);struct.pack_into('<II',raw,64,1,5)
    return bytes(raw)


class GateResourcesTests(unittest.TestCase):
    def setUp(self):
        self.plan=N(room={'id':'room','image':'image','state_root':'/mnt/uas-native/'+'a'*32+'/state/room'},
            config={'deployment':{'images':[{'id':'image','reference':'registry/image@sha256:'+'b'*64}]}},
            installation={'gate_manifest':{'path':'/public/manifest','sha256':'c'*64},'git_manifest':{}})
        self.manifest={'version':1,'profile':'artifacts-v1-source','image_id':'sha256:'+'d'*64,
            'image_reference':self.plan.config['deployment']['images'][0]['reference'],
            'helpers':dict.fromkeys(gate.HELPERS,'e'*64),'host_materializer':dict.fromkeys(gate.HOST_TOOLS,'f'*64)}
        self.state={'room_id':'room','instance_id':'1'*32}

    def test_selection_exact_artifacts_not_command_diff_or_flag(self):
        with patch.object(gate,'read_manifest',return_value=self.manifest):
            self.assertEqual(gate.selection(self.plan),self.manifest)
        for key,value in [('version',True),('profile','command-v1-source'),('helpers',{}),('qualified',True)]:
            bad={**self.manifest,key:value}
            with self.subTest(key=key),patch.object(gate,'read_manifest',return_value=bad),self.assertRaises(ArtifactError):
                gate.selection(self.plan)
        del self.plan.installation['git_manifest']
        with patch.object(gate,'read_manifest',return_value=self.manifest),self.assertRaises(ArtifactError):gate.selection(self.plan)

    def test_mounts_charged_scratch_not_runtime_or_run(self):
        mounts=gate.gate_mounts(self.plan,self.state)
        self.assertEqual([(m.destination,m.read_only) for m in mounts],[('/uas/gate-targets',True),('/uas/gate',True)])
        self.assertTrue(mounts[0].source.startswith('/mnt/uas-native/'))
        self.assertNotIn('/runtime',mounts[0].source)
        self.assertTrue(mounts[1].source.startswith('/run/uas-native/'))

    def test_profile_immutable_and_digest_bound(self):
        p=gate.NativeGateMountProfile.from_plan(self.plan,self.state,self.manifest,'c'*64,container_id='4'*64,mapping_digest='5'*64)
        with self.assertRaises(ArtifactError):p.mounts=()
        copied=p.document();copied['mounts'][0]['source']='/untrusted'
        self.assertNotEqual(copied,p.document())
        self.assertEqual(len(p.mount_tuples()),2)
        with self.assertRaises(ArtifactError):gate.NativeGateMountProfile().document()
        with self.assertRaises(ArtifactError):gate.NativeGateMountProfile.from_plan(self.plan,self.state,self.manifest,'0'*64,container_id='4'*64,mapping_digest='5'*64)

    def test_static_elf_disallows_interp_dynamic_and_wx(self):
        gate.static_elf(elf())
        for kind,flags in [(3,4),(2,4),(1,7)]:
            raw=bytearray(elf());struct.pack_into('<II',raw,64,kind,flags)
            with self.subTest(kind=kind,flags=flags),self.assertRaises(ArtifactError):gate.static_elf(bytes(raw))
        for raw in (b'',elf()[:70],b'not elf'*20):
            with self.assertRaises(ArtifactError):gate.static_elf(raw)

    def test_quota_actual_used_and_strict_fixed_project(self):
        self.assertEqual(backend.parse_gate_quota('#301 2048 0 4096 00 [------]\n',4096*1024),
            {'used_bytes':2048*1024,'hard_bytes':4096*1024})
        for raw in ('#302 0 0 4096 00 [------]', '#301 -1 0 4096 00 [------]',
                    '#301 0 0 4096 00 [------]\n#301 0 0 4096 00 [------]',
                    '#301 0 0 4097 00 [------]','#301 4097 0 4096 00 [------]',
                    '#301 0 0 4096'):
            with self.subTest(raw=raw),self.assertRaises(backend.LifecycleError):backend.parse_gate_quota(raw,4096*1024)
        with self.assertRaises(backend.LifecycleError):backend.parse_gate_quota('',True)

    def test_existing_reservations_include_quarantine_no_double_current(self):
        s=scope();rows={'evaluation':{'scope':s,'result':None,'reservation':{'scratch_bytes':RESERVATION_BYTES},
            'source':{'head_sha':'6'*40},'checkout_digest':'7'*64},
            'quarantine':{'result':{'error':'unknown'},'reservation':{'scratch_bytes':RESERVATION_BYTES}},
            'cleaned':{'reservation':{'scratch_bytes':0}}}
        value=gate.reservation_snapshot({'gate_evaluations':rows},s)
        self.assertEqual(sum(x['scratch_bytes'] for x in value['outstanding']),2*RESERVATION_BYTES)
        for field,value in [('result',{}),('reservation',{'scratch_bytes':True}),('scope',{**s,'generation':2})]:
            bad=deepcopy(rows);bad['evaluation'][field]=value
            with self.subTest(field=field),self.assertRaises(ArtifactError):gate.reservation_snapshot({'gate_evaluations':bad},s)

    def test_capacity_rechecks_identity_after_unlocked_root_observation(self):
        owner=gate.NativeGateResources();s=scope();owner.instance=s['room_instance'];owner.room_id='room'
        row={'scope':s,'result':None,'reservation':{'scratch_bytes':RESERVATION_BYTES},'source':{},'checkout_digest':'7'*64}
        state={'gate_evaluations':{'evaluation':row}}; held=[]
        @contextmanager
        def commit():
            held.append(True)
            try:yield
            finally:held.pop()
        owner.review_host=N(identity=N(active=N(commit=commit),ledger=N(snapshot=lambda:{'state':state})))
        owner._directory_identities={'scratch_root':(1,2)}
        owner.plan=N(room={'resources':{'disk_bytes':3*RESERVATION_BYTES}})
        response={**gate.reservation_snapshot(state,s),'instance':owner.instance,'scratch_identity':[1,2],
            'used_bytes':RESERVATION_BYTES,'hard_bytes':3*RESERVATION_BYTES}
        def observe(evaluation):
            self.assertFalse(held);self.assertEqual(evaluation,'evaluation');return deepcopy(response)
        owner.quota_client=N(observe_gate_quota=observe)
        self.assertTrue(owner.reserve_capacity(s,RESERVATION_BYTES))
        response['used_bytes']=3*RESERVATION_BYTES
        with self.assertRaises(ArtifactError):owner.reserve_capacity(s,RESERVATION_BYTES)
        response['used_bytes']=0
        def race(evaluation):
            self.assertFalse(held);state['gate_evaluations']['evaluation']['checkout_digest']='9'*64;return response
        owner.quota_client=N(observe_gate_quota=race)
        with self.assertRaises(ArtifactError):owner.reserve_capacity(s,RESERVATION_BYTES)

    def test_actual_image_readback_required_for_helpers(self):
        item={'kind':'file','uid':0,'mode':0o555,'sha256':'e'*64,'prefix':elf()}
        reader=Mock();reader.single.return_value=item
        # Stop before host file reads: this focused test only exercises image checks.
        with patch.object(gate,'_ImageReader',return_value=reader),patch('uas.artifact_target._trusted_executable',side_effect=ArtifactError('HOST_STOP')):
            with self.assertRaisesRegex(ArtifactError,'HOST_STOP'):gate.verify_payload(object(),'4'*64,self.manifest,99)
        self.assertEqual(reader.single.call_count,2)
        for change in ({'uid':65532},{'kind':'link'},{'sha256':'0'*64},{'prefix':b'not static'}):
            reader.single.return_value={**item,**change}
            with patch.object(gate,'_ImageReader',return_value=reader),self.assertRaises(ArtifactError):
                gate.verify_payload(object(),'4'*64,self.manifest,99)

    def test_quota_observer_pins_owned_scratch_and_all_commands_deadline(self):
        from pathlib import Path
        import stat
        selected=gate.paths(self.plan,self.state)
        record={'version':1,'instance':self.state['instance_id'],'profile_digest':'9'*64,
            'paths':{key:{'path':str(selected[key]),'identity':[1,index+2]}
                for index,key in enumerate(('scratch_root','journal_root','launch_journal_root'))}}
        raw=gate.canonical(record)
        owner=backend.NativeQualificationBackend.__new__(backend.NativeQualificationBackend)
        owner.profile=N(nonce='a'*32,gate_manifest=self.manifest,gate_plan=self.plan,digest='9'*64,
            limits={'disk_bytes':4096*1024},owners={'supervisor':165533})
        owner._binding=Mock()
        def metadata(path,**kwargs):
            for index,key in enumerate(('scratch_root','journal_root','launch_journal_root')):
                if path==selected[key]:
                    return N(st_mode=stat.S_IFDIR|(0o711 if key=='scratch_root' else 0o700),st_uid=165533,
                        st_gid=165533,st_dev=1,st_ino=index+2)
            return N(st_dev=1)
        calls=[]
        def command(*args,deadline=None,**kwargs):
            calls.append((args,deadline));self.assertEqual(deadline,99)
            if args[0]=='getenforce':return 'Enforcing\n'
            if args[0]=='stat':return 'xfs\n'
            if 'state -p' in args:return 'Accounting: ON\nEnforcement: ON\n'
            return '#301 2048 0 4096 00 [------]\n'
        with patch.object(backend,'guard') as guard,patch.object(backend,'command',side_effect=command),\
            patch.object(backend.time,'monotonic',return_value=1),patch.object(backend,'project_attributes',return_value=(301,True)),\
            patch.object(Path,'stat',metadata),patch.object(Path,'resolve',lambda path:path),\
            patch.object(Path,'read_text',return_value='1'),patch.object(backend.os,'open',return_value=9),\
            patch.object(backend.os,'read',return_value=raw),patch.object(backend.os,'close'),\
            patch.object(backend.os,'fstat',return_value=N(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_size=len(raw))):
            self.assertEqual(owner.observe_gate_quota(self.state,deadline=99),
                {'used_bytes':2048*1024,'hard_bytes':4096*1024,'scratch_identity':[1,2]})
            guard.assert_called_once_with('a'*32,require_selinux=False)
            self.assertEqual(len(calls),4)
            record['paths']['scratch_root']['identity']=[1,900];raw=gate.canonical(record)
            with patch.object(backend.os,'read',return_value=raw),self.assertRaises(backend.LifecycleError):
                owner.observe_gate_quota(self.state,deadline=99)

    def test_deadline_refuses_before_os_and_bounds_command_timeout(self):
        owner=backend.NativeQualificationBackend.__new__(backend.NativeQualificationBackend)
        with patch.object(backend.time,'monotonic',return_value=100),patch.object(backend,'guard') as guard:
            with self.assertRaises(backend.LifecycleError):owner.observe_gate_quota(self.state,deadline=99)
            guard.assert_not_called()
        result=N(returncode=0,stderr='',stdout='Enforcing\n')
        with patch.object(backend.time,'monotonic',return_value=98.5),patch.object(backend.subprocess,'run',return_value=result) as run:
            backend.command('getenforce',deadline=99)
            self.assertEqual(run.call_args.kwargs['timeout'],0.5)

    def test_fresh_admission_pid_directory_identity_mode_group_drift(self):
        from pathlib import Path
        import stat
        owner=gate.NativeGateResources();owner._closed=False;owner.deadline=100
        owner.workstation=N(host_profile=None);owner.room_id='room';owner.instance='1'*32;owner.container_id='4'*64
        @contextmanager
        def locked():yield
        owner.supervisor=N(_locked=locked,_read=lambda:{'instance_id':owner.instance})
        owner.git_resources=Mock();owner.git_resources._container_pid=123
        owner.git_resources.profile.mount_tuples.return_value=()
        owner.plan=N(room={'project':{'roots':{}},'state_root':'/owned','resources':{'cpu':2}})
        owner._host_owners=gate.host_owners(owner.plan)
        owner.data={'peer_path':'/run/uas-native/'+owner.instance+'/peer/pi.sock'}
        owner.profile=N(image_id='sha256:'+'4'*64,image_reference='selected',mount_tuples=lambda:())
        value={'State':{'Running':True,'Pid':123}};owner.engine=N(inspect_container=lambda _:deepcopy(value))
        owner.endpoint=Mock();owner.endpoint.path=Path('/fixed/gate.sock')
        owner.listener=Mock();owner.listener.getsockname.return_value='/fixed/gate.sock';owner.listener.getsockopt.return_value=1
        owner._listener_identity=(8,9)
        owner.scratch_root=Path('/scratch');owner.journal_root=Path('/journal');owner.launch_journal_root=Path('/launch')
        owner._directory_identities={key:(1,index) for index,key in enumerate(('scratch_root','journal_root','launch_journal_root'))}
        change={}
        def metadata(path,**kwargs):
            for key,identity in owner._directory_identities.items():
                if getattr(owner,key)==path:
                    fields={'st_dev':identity[0],'st_ino':identity[1],'st_uid':165533,'st_gid':165533,
                        'st_mode':stat.S_IFDIR|(0o711 if key=='scratch_root' else 0o700)}
                    if key=='scratch_root':fields.update(change)
                    return N(**fields)
            raise AssertionError('unexpected path')
        with patch.object(gate.time,'monotonic',return_value=1),patch.object(backend,'validate_native_container',return_value=True),\
            patch.object(gate.os,'fstat',return_value=N(st_dev=8,st_ino=9)),patch.object(Path,'stat',metadata):
            self.assertTrue(owner.require(owner.workstation))
            value['State']['Pid']=124
            with self.assertRaises(ArtifactError):owner.require(owner.workstation)
            value['State']['Pid']=123
            for fields in ({'st_ino':900},{'st_uid':165532},{'st_gid':165530},{'st_mode':stat.S_IFDIR|0o777}):
                change.clear();change.update(fields)
                with self.subTest(fields=fields),self.assertRaises(ArtifactError):owner.require(owner.workstation)
