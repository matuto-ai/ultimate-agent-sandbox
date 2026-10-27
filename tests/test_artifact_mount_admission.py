"""Full inspect-shape to real fixture admission; all Engine/kernel effects mocked.

Legacy --tmpfs configuration and actual /tmp runtime facts remain separate.
These are source regressions, not captured inspect data or native qualification.
"""
from copy import deepcopy
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

VM=Path(__file__).parent/'vm';sys.path.insert(0,str(VM))
try:
    import artifact_supervisor as supervisor
    import artifact_diagnostics as diagnostics
    import guest_artifacts as guest
finally:sys.path.remove(str(VM))


def fixture(room='alpha'):
    template=json.loads((VM.parent/'fixtures/two-rooms.json').read_text())
    plan=guest.fixture_layout('a'*32,template);config=deepcopy(plan['rooms'][room])
    config.update(nonce='a'*32,helper_sha256={'artifact-bootstrap':'b'*64},level='s0:c301,c302')
    if room=='beta':config['foreign_scratch']=plan['rooms']['alpha']['scratch']
    flags={'readonly':False,'nosuid':True,'nodev':True,'noexec':True}
    runtime={'version':1,'mount_id':30,'parent_mount_id':20,'device_major':0,'device_minor':45,
        'filesystem':'tmpfs','mount_flags':flags,'statvfs_flags':dict(flags),'size_bytes':8<<20,
        'allocation_unit':4096,'uid':65532,'gid':65532,'mode':0o700,'device':45,'inode':1}
    mapping={'uid_map':'0 100000 65536\n','gid_map':'0 100000 65536\n','overflow_uid':65534,'overflow_gid':65534}
    workstation=supervisor.GateWorkstation(room,config['room_instance'],'1'*64,'2'*64,'3'*64,'4'*64,
        '5'*64,hashlib.sha256(json.dumps(mapping,sort_keys=True).encode()).hexdigest(),'hub-'+room)
    binds=supervisor.expected_bind_mounts(config)
    info={'Image':'sha256:'+workstation.image_digest,'State':{'Running':True},
        'ProcessLabel':'system_u:system_r:container_t:'+config['level'],
        'Config':{'Labels':{'uas.artifact-owner':config['nonce']},'User':'65532:65532','Entrypoint':['/opt/uas/bin/tini']},
        'HostConfig':{'ReadonlyRootfs':True,'CapDrop':['ALL'],'Privileged':False,'NetworkMode':'none',
            'PidMode':'','UsernsMode':'','IpcMode':'private','SecurityOpt':['no-new-privileges=true','label=level:'+config['level']],
            'Memory':256<<20,'MemorySwap':256<<20,'PidsLimit':64,'NanoCpus':500000000,
            'Tmpfs':{'/tmp':supervisor.TMPFS_OPTIONS}},
        'Mounts':[{'Type':'bind','Source':source,'Destination':destination,'RW':writable,'Mode':'rw' if writable else 'ro',
            'Propagation':'rprivate','Name':'','Driver':''} for destination,(source,writable) in binds.items()]}
    facts={'uid':65532,'gid':65532,'kernel_status':{'CapEff':'0000000000000000','CapBnd':'0000000000000000','NoNewPrivs':'1','Seccomp':'2'},
        **mapping,'helper_sha256':config['helper_sha256'],'outer_socket_creation':True,
        'private_paths':{'/run/docker.sock':2,'/uas/hub/room.db':2,'/uas/control/hub.sock':2},
        'label':info['ProcessLabel'],'tmp_mount':runtime}
    engine=Mock();engine._request.return_value=info
    admission=supervisor.NativeAdmission(engine,config);admission.target_lease=SimpleNamespace(path=Path('/owned/target'))
    return admission,workstation,info,facts


class MountAdmissionTests(unittest.TestCase):
    def run_admission(self,admission,workstation,facts):
        with patch.object(supervisor,'command',return_value=facts) as command, \
                patch.object(supervisor.os,'walk',return_value=[('/owned/target',[],['README.md'])]), \
                patch.object(supervisor.os,'getxattr',return_value=('system_u:object_r:container_file_t:'+admission.config['level']).encode()):
            result=admission.require(workstation)
        command.assert_called_once();admission.engine._request.assert_called_once_with('GET','/containers/'+workstation.container_id+'/json')
        self.assertEqual(admission.engine.method_calls,[call._request('GET','/containers/'+workstation.container_id+'/json')])
        return result

    def test_actual_inspect_shape_separates_bind_mounts_and_legacy_tmpfs_config(self):
        for room in ('alpha','beta'):
            with self.subTest(room=room):
                admission,workstation,info,facts=fixture(room)
                self.assertNotIn('/tmp',[item['Destination'] for item in info['Mounts']])
                self.assertEqual(set(info['HostConfig']['Tmpfs']),{'/tmp'})
                self.assertTrue(self.run_admission(admission,workstation,facts))
                self.assertEqual(admission.observations[0]['tmp_mount'],facts['tmp_mount'])

    def test_fixture_create_requests_the_exact_profile_without_executing_engine(self):
        admission,_,_,_=fixture()
        with patch.object(guest,'run',return_value='fixed\n') as run:
            guest.create('image','name',admission.config,admission.config['nonce'])
        args=run.call_args.args
        self.assertEqual(args[args.index('--tmpfs')+1],'/tmp:'+supervisor.TMPFS_OPTIONS)
        binds=[args[index+1] for index,item in enumerate(args) if item=='--mount']
        self.assertEqual(len(binds),3)
        for destination,(source,writable) in supervisor.expected_bind_mounts(admission.config).items():
            self.assertIn('type=bind,src='+source+',dst='+destination+('' if writable else ',readonly'),binds)

    def test_missing_extra_duplicate_wrong_type_source_rw_propagation_fail_before_probe(self):
        mutations=[lambda d:d['Mounts'].pop(),lambda d:d['Mounts'].append(dict(d['Mounts'][0])),
            lambda d:d['Mounts'].__setitem__(1,dict(d['Mounts'][0])),
            lambda d:d['Mounts'][0].update(Type='volume'),lambda d:d['Mounts'][0].update(Source='/wrong'),
            lambda d:d['Mounts'][0].update(RW=True),lambda d:d['Mounts'][2].update(RW=False),
            lambda d:d['Mounts'][0].update(RW=0),lambda d:d['Mounts'][0].update(Propagation='rshared'),
            lambda d:d['Mounts'][0].update(Destination='/run/docker.sock'),lambda d:d.update(Mounts={}),
            lambda d:d['Mounts'].append({'Type':'tmpfs','Destination':'/tmp','Source':'','RW':True})]
        for index,mutate in enumerate(mutations):
            admission,workstation,info,_=fixture();mutate(info)
            with self.subTest(index=index),patch.object(supervisor,'command') as command,redirect_stdout(io.StringIO()):
                with self.assertRaises(RuntimeError):admission.require(workstation)
                command.assert_not_called();self.assertFalse(admission.observations)

    def test_tmpfs_configuration_is_singleton_exact_bounded_and_not_runtime_proof(self):
        bad=[None,{}, {'/tmp':supervisor.TMPFS_OPTIONS,'/extra':supervisor.TMPFS_OPTIONS},
            {'/tmp':supervisor.TMPFS_OPTIONS+',rw'}, {'/tmp':supervisor.TMPFS_OPTIONS.replace('noexec','exec')},
            {'/tmp':supervisor.TMPFS_OPTIONS.replace('8m','16m')}, {'/tmp':supervisor.TMPFS_OPTIONS.replace('65532','0')},
            {'/tmp':supervisor.TMPFS_OPTIONS.replace('0700','0777')}, {'/tmp':True}, {'/run':supervisor.TMPFS_OPTIONS}]
        for value in bad:
            admission,workstation,info,_=fixture();info['HostConfig']['Tmpfs']=value
            with self.subTest(value=value),patch.object(supervisor,'command') as command,redirect_stdout(io.StringIO()):
                with self.assertRaises(RuntimeError):admission.require(workstation)
                command.assert_not_called()
        admission,workstation,info,facts=fixture();info['HostConfig']['Tmpfs']['/tmp']=','.join(reversed(supervisor.TMPFS_OPTIONS.split(',')))
        self.assertTrue(self.run_admission(admission,workstation,facts))
        admission,workstation,_,facts=fixture();facts.pop('tmp_mount')
        with patch.object(supervisor,'command',return_value=facts),redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):admission.require(workstation)
        self.assertEqual(admission.observations,[])

    def test_runtime_flags_capacity_identity_and_owner_are_independently_required(self):
        mutations=[lambda d:d.update(filesystem='ext4'),lambda d:d.update(size_bytes=16<<20),
            lambda d:d.update(uid=0),lambda d:d.update(gid=0),lambda d:d.update(mode=0o777),
            lambda d:d.update(device_minor=99),lambda d:d.update(version=True),lambda d:d.update(inode=0),
            lambda d:d.update(allocation_unit=8192),lambda d:d.update(size_bytes=True)]
        for field in ('mount_flags','statvfs_flags'):
            for flag in ('readonly','nosuid','nodev','noexec'):
                mutations.append(lambda d,field=field,flag=flag:d[field].update({flag:not d[field][flag]}))
        for index,mutate in enumerate(mutations):
            admission,workstation,_,facts=fixture();mutate(facts['tmp_mount'])
            with self.subTest(index=index),patch.object(supervisor,'command',return_value=facts),redirect_stdout(io.StringIO()):
                with self.assertRaises(RuntimeError):admission.require(workstation)
                self.assertFalse(admission.observations)


class MountDiagnosticTests(unittest.TestCase):
    def document(self,runtime=False):
        admission,_,info,facts=fixture()
        return diagnostics.mount_failure('runtime-tmpfs' if runtime else 'inspect-mounts',info,
            supervisor.expected_bind_mounts(admission.config),supervisor.TMPFS_OPTIONS,facts['tmp_mount'] if runtime else None)

    def wire(self,value):return diagnostics.MOUNT_PREFIX+json.dumps(value,separators=(',',':')).encode()+b'\n'

    def test_failure_retains_known_destinations_types_readonly_security_not_secrets(self):
        admission,workstation,info,_=fixture();info['Mounts'][0].update(Destination='/secret-token',Source='/private-source')
        info['HostConfig']['Tmpfs']['/secret-tmp']='password=private';info['Config']['Env']=['SECRET=private']
        output=io.StringIO()
        with redirect_stdout(output),patch.object(supervisor,'command'):
            with self.assertRaises(RuntimeError):admission.require(workstation)
        value=diagnostics.mount_observation(output.getvalue().encode());self.assertEqual(value['parse_status'],'parsed')
        record=value['records'][0];self.assertEqual(record['mounts']['entries'][0]['path'],'other')
        self.assertEqual(record['mounts']['entries'][0]['path_digest'],hashlib.sha256(b'/secret-token').hexdigest())
        self.assertTrue(record['security']['readonly_rootfs']);self.assertEqual(record['mounts']['entries'][0]['type'],'bind')
        for secret in ('secret-token','private-source','password=private','SECRET=private'):
            self.assertNotIn(secret,output.getvalue())

    def test_broken_diagnostic_output_does_not_replace_mount_refusal(self):
        admission,workstation,info,_=fixture();info['Mounts'].pop()
        with patch('builtins.print',side_effect=OSError(32,'diagnostic unavailable')), \
                patch.object(supervisor,'command') as command:
            with self.assertRaisesRegex(RuntimeError,'mount set cardinality'):admission.require(workstation)
            command.assert_not_called()

    def test_middle_stream_record_survives_sampling_without_becoming_success(self):
        value=self.document(True);raw=b'x'*1000+b'\n'+self.wire(value)+b'y'*1000
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'out';err=Path(directory)/'err';out.write_bytes(raw);err.write_bytes(b'failure')
            with self.assertRaises(diagnostics.FixtureCommandFailure) as caught:
                diagnostics.require_file_result('supervisor-alpha',1,out,err,output_limit=1<<20)
        observed=caught.exception.document['stdout']['mount_observation']
        self.assertEqual(observed['records'],[value]);self.assertNotIn(b'UAS_ARTIFACT_MOUNTS',raw[:384]+raw[-384:])
        self.assertEqual(caught.exception.document['returncode'],1)

    def test_duplicate_unknown_malformed_fields_and_flood_are_bounded(self):
        good=self.document();bad=deepcopy(good);bad['private']='secret'
        bad2=deepcopy(good);bad2['mounts']['entries'][0]['readonly']=1
        bad3=deepcopy(good);bad3['security']['readonly_rootfs']='private'
        for value in (bad,bad2,bad3,{'version':True}):
            observed=diagnostics.mount_observation(self.wire(value));self.assertEqual(observed['rejected_records'],1)
            self.assertEqual(observed['records'],[])
        duplicate=diagnostics.MOUNT_PREFIX+b'{"version":1,"version":1}\n'
        self.assertEqual(diagnostics.mount_observation(duplicate)['rejected_records'],1)
        flood=self.wire(good)*100
        value=diagnostics.mount_observation(flood);self.assertEqual(len(value['records']),1);self.assertEqual(value['unretained_records'],99)
        self.assertEqual(diagnostics.mount_observation(b'x'*(1<<20|1))['parse_status'],'unavailable')

    def test_maximum_combined_diagnostics_stay_within_existing_record_bound(self):
        admission,_,info,facts=fixture();info['Mounts']=[{'Destination':'/unknown/'+str(i),'Source':'private','Type':'other','RW':False,'Propagation':'other'} for i in range(8)]
        info['HostConfig']['Tmpfs']={'/unknown/'+str(i):'private' for i in range(4)}
        value=diagnostics.mount_failure('runtime-tmpfs',info,{},supervisor.TMPFS_OPTIONS,facts['tmp_mount'])
        self.assertTrue(diagnostics._valid_mount_record(value));self.assertLessEqual(len(self.wire(value)),4096+len(diagnostics.MOUNT_PREFIX)+1)
        supervisor_record=diagnostics.SUPERVISOR_PREFIX+json.dumps(diagnostics.supervisor_failure('source-resolve',supervisor.ArtifactError('ARTIFACT_PATH_TRAVERSAL_UNAVAILABLE'),supervisor.ArtifactError),separators=(',',':')).encode()+b'\n'
        raw=b'\x00'*1000+b'\n'+self.wire(value)+supervisor_record*8+b'\x00'*1000
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)/'out';err=Path(directory)/'err';out.write_bytes(raw);err.write_bytes(b'\x00'*3000)
            with self.assertRaises(diagnostics.FixtureCommandFailure) as caught:
                diagnostics.require_file_result('supervisor-alpha',1,out,err,output_limit=1<<20)
            self.assertLess(len(str(caught.exception).encode()),diagnostics.MAX_DIAGNOSTIC_BYTES)


if __name__=='__main__':unittest.main()
