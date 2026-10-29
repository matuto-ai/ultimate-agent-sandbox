"""End-to-end source composition with controlled host effects, real temp inodes."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from uas import local_room_prepare as prepare
from uas.local_host_profile import digest, HostProfileError
from uas.local_native import LOCAL_HUB_COMMAND
from tests import test_local_room_resources as fixtures
from tests.test_local_host_plan import profile, observation
from uas.local_host_plan import plan


class RoomPreparationTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.RoomResourceTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f=self.fixture
        f.storage.chmod(0o711)
        self.config=json.loads((Path(__file__).parent/'fixtures/two-rooms.json').read_text().replace('/srv',str(f.storage)))
        self.endpoints=f.root/'endpoints';self.endpoints.mkdir()
        o=observation();o['storage']['path']=str(f.root)
        info=f.root.stat();o['storage']['identity']=[info.st_dev,info.st_ino]
        self.host=plan(profile(),o,storage_root=str(f.storage),endpoints_root=str(self.endpoints),receipt_root=str(f.receipts))
        self.settings={'version':1,'installation_id':'a'*32,'storage_root':str(f.storage),
            'endpoints_root':str(self.endpoints),'engine_version':'29.8.2','mapping':{'offset':100000,'size':65536},
            'rooms':{r['id']:{'quota_project_id':1200+i,'mcs_level':f's0:c{200+i*2},c{201+i*2}',
                           'subnet':f'10.91.{i+1}.0/24','gateway':f'10.91.{i+1}.1'}
                     for i,r in enumerate(self.config['rooms'])}}
        self.ws={'image_id':'sha256:'+'a'*64,'image_reference':'sha256:'+'a'*64}
        self.hub={**self.ws,'entrypoint':LOCAL_HUB_COMMAND[:]}
        self.value=prepare.request(self.host,self.config,self.settings,self.ws,self.hub)
        def native_command(*args):
            if args[0]=='stat':
                return 'xfs' if args[1]=='-f' else f.labels[args[-1]]
            if args[0]=='xfs_quota':
                command=args[args.index('-c')+1]
                if command=='state -p':return 'Accounting: ON\nEnforcement: ON'
                if command.startswith('project -c '):
                    parts=command.split();path=parts[3];project=parts[4]
                    return f'Checking project {project} (path {path})...\nProcessed 1 (/dev/null and cmdline) paths for project {project} with recursion depth infinite (-1).'
                return f.command(['/usr/sbin/xfs_quota','-c',command,args[-1]])
            raise AssertionError(args)
        for target,replacement in [
            ('uas.local_room_prepare.apply_host',lambda _:None),
            ('uas.local_room_prepare.observed_engine_allocations',lambda _:{'levels':set(),'networks':set()}),
            ('uas.local_room_prepare.inspect',self.inspect),
            ('uas.local_room_prepare.canonical_node',lambda p:f.fake_stat(p)),
            ('uas.local_host_apply.canonical_node',lambda p:f.fake_stat(p)),
            ('uas.local_native.LocalNativeProfile.guard',lambda *a,**k:None),
            ('uas.native_qualification_backend.command',native_command),
            ('uas.native_qualification_backend.project_attributes',lambda p:f.attributes.get(str(p),(0,False)))]:
            stub=patch(target,replacement);stub.start();self.addCleanup(stub.stop)

    def inspect(self, profile, *, storage_parent, proposed_paths):
        # Mirror the real observer boundary; an empty list was previously hidden
        # by a permissive mock and rejected on every real apply.
        self.assertEqual(storage_parent,self.host['storage_parent'])
        self.assertEqual(proposed_paths,[self.host[k] for k in ('storage_root','endpoints_root','receipt_root')])
        self.assertGreaterEqual(len(proposed_paths),1)
        return {'networks':[]}

    def test_two_rooms_through_real_receipts_and_canonical_storage_readback(self):
        result=prepare.apply(self.value)
        self.assertEqual(result['status'],'room-storage-prepared')
        self.assertEqual(set(result['native']['rooms']),{'alpha','beta'})
        for room in result['native']['rooms'].values():
            for record in room['paths'].values():
                self.assertEqual(prepare.directory_identity(record['path']),record['identity'])
                self.assertEqual(self.fixture.attributes[record['path']][0],room['quota_project_id'])
        effects=len(self.fixture.calls)
        second=prepare.apply(self.value)
        self.assertEqual(result,second)
        self.assertEqual(self.fixture.effect_count('limit'),2)
        self.assertEqual(self.fixture.effect_count('project'),10)
        self.assertEqual(self.fixture.effect_count('chcon'),10)
        self.assertGreater(len(self.fixture.calls),effects)

    def test_real_inspector_contract_composes_before_room_preparation(self):
        from uas import local_host_observe
        f=self.fixture
        def command(args):
            if args[0]=='/usr/bin/stat':return 'xfs'
            if args[0]=='/usr/sbin/xfs_quota':return 'Project quota state on fixture\nAccounting: ON\nEnforcement: ON'
            if args[0]=='/usr/sbin/ip':return '[]'
            if args[0]=='/usr/sbin/getenforce':return 'Enforcing'
            raise AssertionError(args)
        real_exists=__import__('os').path.lexists
        with patch.object(prepare,'inspect',local_host_observe.inspect), \
             patch.object(local_host_observe,'command',command), \
             patch.object(local_host_observe,'canonical_node',lambda p,**kw:f.fake_stat(p)), \
             patch.object(local_host_observe,'read_text',return_value=''), \
             patch.object(local_host_observe.os.path,'lexists',side_effect=lambda p:False if str(p)=='/run/docker.sock' else real_exists(p)):
            result=prepare.apply(self.value)
        self.assertEqual(result['status'],'room-storage-prepared')

    def test_actual_probe_plan_host_owner_room_owner_and_native_contracts(self):
        from types import SimpleNamespace
        from uas import local_host_observe, local_host_apply
        f=self.fixture
        # Only this test's empty scaffolding is removed so the REAL host owner
        # must create its roots and receipts rather than a mocked apply function.
        f.receipt.close()
        for entry in f.receipts.iterdir():entry.unlink()
        f.receipts.rmdir();f.storage.rmdir();self.endpoints.rmdir()
        def node(path,**kwargs):
            if str(path)=='/run/docker.sock':return SimpleNamespace(st_uid=0,st_mode=0o140600,st_dev=1,st_ino=22)
            return f.fake_stat(path)
        def command(args):
            if args[0]=='/usr/bin/stat':return 'xfs'
            if args[0]=='/usr/sbin/xfs_quota':return 'Project quota state on fixture\nAccounting: ON\nEnforcement: ON'
            if args[0]=='/usr/sbin/ip':return '[]'
            if args[0]=='/usr/sbin/getenforce':return 'Enforcing'
            if args[0]=='/usr/bin/docker':
                return {'{{.Server.Version}}':'29.8.2','{{.DockerRootDir}}':'/var/lib/docker/100000.100000',
                        '{{json .SecurityOptions}}':'["name=seccomp,profile=builtin","name=selinux","name=userns"]'}[args[-1]]
            raise AssertionError(args)
        real_exists=__import__('os').path.lexists
        with patch.object(prepare,'inspect',local_host_observe.inspect), \
             patch.object(prepare,'apply_host',local_host_apply.apply), \
             patch.object(local_host_observe,'command',command), \
             patch.object(local_host_observe,'canonical_node',node), \
             patch.object(local_host_observe,'read_text',side_effect=lambda p:'uas-remap:100000:65536\n' if p in ('/etc/subuid','/etc/subgid') else ''), \
             patch.object(local_host_observe.os.path,'lexists',side_effect=lambda p:True if str(p)=='/run/docker.sock' else real_exists(p)):
            paths=[str(f.storage),str(self.endpoints),str(f.receipts)]
            observed=local_host_observe.inspect(profile(),storage_parent=str(f.root),proposed_paths=paths)
            host=plan(profile(),observed,storage_root=paths[0],endpoints_root=paths[1],receipt_root=paths[2])
            value=prepare.request(host,self.config,self.settings,self.ws,self.hub)
            result=prepare.apply(value)
            self.assertEqual(prepare.apply(value),result)
        self.assertEqual(result['status'],'room-storage-prepared')
        self.assertTrue((f.receipts/'observations.json').is_file())
        self.assertTrue((f.receipts/'rooms'/'plan.json').is_file())

    def test_request_tamper_stops_before_host_apply(self):
        self.value['ancestors'].append('/foreign')
        with patch.object(prepare,'apply_host') as owner:
            with self.assertRaisesRegex(HostProfileError,'REQUEST_CHANGED'):prepare.apply(self.value)
            owner.assert_not_called()

    def test_network_collision_precedes_room_effects(self):
        with patch.object(prepare,'inspect',return_value={'networks':['10.91.1.0/24']}):
            with self.assertRaisesRegex(HostProfileError,'NETWORK_COLLISION'):prepare.apply(self.value)
        self.assertEqual(self.fixture.effect_count('limit'),0)

    def test_existing_container_mcs_precedes_room_effects(self):
        with patch.object(prepare,'observed_engine_allocations',return_value={'levels':{'s0:c200,c201'},'networks':set()}):
            with self.assertRaisesRegex(HostProfileError,'MCS_COLLISION'):prepare.apply(self.value)
        self.assertEqual(self.fixture.effect_count('limit'),0)

    def test_incomplete_engine_observation_prevents_even_host_directory_apply(self):
        with patch.object(prepare,'observed_engine_allocations',side_effect=HostProfileError('ROOM_ENGINE_OBSERVATION_BOUND')), \
             patch.object(prepare,'apply_host') as host:
            with self.assertRaisesRegex(HostProfileError,'OBSERVATION_BOUND'):prepare.apply(self.value)
            host.assert_not_called()
        self.assertEqual(self.fixture.effect_count('limit'),0)

    def test_unknown_label_effect_resumes_same_plan_without_duplication(self):
        self.fixture.failure='chcon'
        with self.assertRaises(OSError):prepare.apply(self.value)
        prepare.apply(self.value)
        self.assertEqual(self.fixture.effect_count('limit'),2)
        self.assertEqual(self.fixture.effect_count('project'),10)
        self.assertEqual(self.fixture.effect_count('chcon'),10)


class EngineProjectionTests(unittest.TestCase):
    def test_reads_only_id_label_and_subnet_projections(self):
        identity='a'*64;calls=[]
        def command(args, **kwargs):
            calls.append(args)
            if 'ps' in args or 'ls' in args:return identity
            if 'container' in args:return json.dumps({'id':identity,'value':['system_u:system_r:container_t:s0:c1,c2','system_u:object_r:container_file_t:s0:c1,c2']})
            return json.dumps({'id':identity,'value':[{'Subnet':'10.10.0.0/24','Gateway':'10.10.0.1'}]})
        with patch.object(prepare,'run_fixed',command):
            result=prepare.observed_engine_allocations(profile())
        self.assertEqual(result,{'levels':{'s0:c1,c2'},'networks':{'10.10.0.0/24'}})
        self.assertTrue(all('--host' in call and '--format' in call for call in calls))
        self.assertFalse(any('{{json .}}' in call for call in calls))
        self.assertEqual(len(calls),4)

    def test_malformed_or_duplicate_inventory_fails(self):
        for value in ('foreign','a'*64+'\n'+'a'*64):
            with patch.object(prepare,'run_fixed',return_value=value):
                with self.assertRaisesRegex(HostProfileError,'ENGINE_INVENTORY'):
                    prepare.observed_engine_allocations(profile())

    def test_one_deadline_and_total_output_budget_for_all_projections(self):
        identity='a'*64;budgets=[]
        def command(args,**kwargs):
            budgets.append(kwargs)
            if 'ps' in args or 'ls' in args:return identity
            return json.dumps({'id':identity,'value':['',''] if 'container' in args else []})
        with patch.object(prepare,'run_fixed',command),patch.object(prepare.time,'monotonic',return_value=100):
            prepare.observed_engine_allocations(profile())
        self.assertEqual({b['deadline'] for b in budgets},{110})
        self.assertEqual(len(budgets),4)
        self.assertTrue(all(budgets[i+1]['limit']<budgets[i]['limit'] for i in range(3)))

    def test_deadline_reached_never_returns_partial_inventory(self):
        with patch.object(prepare,'run_fixed',return_value=''), \
             patch.object(prepare.time,'monotonic',side_effect=[100,100,111]):
            with self.assertRaisesRegex(HostProfileError,'OBSERVATION_BOUND'):
                prepare.observed_engine_allocations(profile())


class FileHandoffTests(unittest.TestCase):
    def setUp(self):
        from tests import test_local_prepare
        self.fixture=test_local_prepare.LocalPrepareTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f=self.fixture
        p=profile();p['installation_id']='b'*32
        o=observation();o['storage']['path']=str(f.root)
        info=f.root.stat();o['storage']['identity']=[info.st_dev,info.st_ino]
        self.host=plan(p,o,storage_root=str(f.data),endpoints_root=str(f.root/'endpoints'),receipt_root=str(f.root/'receipts'))
        self.host_path=f.root/'host-plan.json';f.write(self.host_path,self.host)
        self.envelope=f.root/'request.json'
    def request(self):
        f=self.fixture
        return prepare.file_request(self.host_path,f.project_file,f.settings_file,f.ws,f.hub,f.revision)
    def test_verified_file_request_roundtrips_canonical_handoff(self):
        f=self.fixture;value=self.request();f.write(self.envelope,value)
        real_fstat=__import__('os').fstat
        def rootstat(fd):
            fields=list(real_fstat(fd));fields[4]=0;return __import__('os').stat_result(fields)
        native=prepare.assemble(value['request']['config'],f.settings,value['request']['workstation'],value['request']['hub'])
        with patch.object(prepare,'apply',return_value={'request_id':value['request']['request_id'],'native':native}), \
             patch('uas.local_room_prepare.os.geteuid',return_value=0), \
             patch('uas.local_prepare.os.fstat',side_effect=rootstat):
            result=prepare.apply_file(self.envelope,f.output)
        self.assertEqual(result['status'],'local-host-prepared')
        self.assertTrue((f.output/'native-reference.json').is_file())
        self.assertTrue((f.output/'installation-selection.json').is_file())
        self.assertEqual(json.loads((f.output/'native.json').read_text())['installation_id'],'b'*32)
    def test_changed_input_rejected_before_effect(self):
        f=self.fixture;value=self.request();f.write(self.envelope,value)
        f.project_file.write_text(f.project_file.read_text()+'\n')
        # Recomputed proposal changes even when normalized Project is equivalent.
        self.assertNotEqual(self.request()['envelope_id'],value['envelope_id'])

    def test_input_changed_during_apply_never_emits_handoff(self):
        f=self.fixture;value=self.request();f.write(self.envelope,value)
        real_fstat=__import__('os').fstat
        def rootstat(fd):
            fields=list(real_fstat(fd));fields[4]=0;return __import__('os').stat_result(fields)
        def mutate(_):
            settings=json.loads(f.settings_file.read_text());settings['rooms']['alpha']['quota_project_id']=777
            f.write(f.settings_file,settings)
            return {'request_id':value['request']['request_id']}
        with patch.object(prepare,'apply',side_effect=mutate), \
             patch('uas.local_room_prepare.os.geteuid',return_value=0), \
             patch('uas.local_prepare.os.fstat',side_effect=rootstat):
            with self.assertRaisesRegex(HostProfileError,'INPUT_CHANGED_DURING_APPLY'):
                prepare.apply_file(self.envelope,f.output)
        self.assertFalse(f.output.exists())

    def test_postwrite_native_mismatch_is_preserved_not_success(self):
        from uas import local_prepare
        f=self.fixture;value=self.request();f.write(self.envelope,value)
        native=prepare.assemble(value['request']['config'],f.settings,value['request']['workstation'],value['request']['hub'])
        real_fstat=__import__('os').fstat;real_prepare=local_prepare.prepare
        def rootstat(fd):
            fields=list(real_fstat(fd));fields[4]=0;return __import__('os').stat_result(fields)
        def mutate(*args):
            result=real_prepare(*args)
            data=json.loads((f.output/'native.json').read_text());data['installation_id']='e'*32
            f.write(f.output/'native.json',data)
            return result
        with patch.object(prepare,'apply',return_value={'request_id':value['request']['request_id'],'native':native}), \
             patch('uas.local_room_prepare.os.geteuid',return_value=0), \
             patch('uas.local_prepare.os.fstat',side_effect=rootstat), \
             patch('uas.local_prepare.prepare',side_effect=mutate):
            with self.assertRaisesRegex(HostProfileError,'HANDOFF_CHANGED'):
                prepare.apply_file(self.envelope,f.output)
        self.assertEqual(json.loads((f.output/'native.json').read_text())['installation_id'],'e'*32)

    def test_documented_cli_plan_then_apply_routes(self):
        from contextlib import redirect_stdout
        from io import StringIO
        f=self.fixture;proposal=f.root/'proposal'
        with redirect_stdout(StringIO()):
            self.assertEqual(prepare.main(['plan','--host-plan',str(self.host_path),'--project',str(f.project_file),
                '--settings',str(f.settings_file),'--workstation-output',str(f.ws),'--hub-output',str(f.hub),
                '--revision',f.revision,'--output',str(proposal)]),0)
        value=json.loads((proposal/'request.json').read_text())
        native=prepare.assemble(value['request']['config'],f.settings,value['request']['workstation'],value['request']['hub'])
        real_fstat=__import__('os').fstat
        def rootstat(fd):
            fields=list(real_fstat(fd));fields[4]=0;return __import__('os').stat_result(fields)
        with patch.object(prepare,'apply',return_value={'request_id':value['request']['request_id'],'native':native}), \
             patch('uas.local_room_prepare.os.geteuid',return_value=0), \
             patch('uas.local_prepare.os.fstat',side_effect=rootstat),redirect_stdout(StringIO()) as printed:
            self.assertEqual(prepare.main(['apply','--plan',str(proposal/'request.json'),'--output',str(f.output)]),0)
        self.assertEqual(json.loads(printed.getvalue())['status'],'local-host-prepared')

    def test_input_changed_inside_producer_preserves_output_and_rejects_success(self):
        from uas import local_prepare
        f=self.fixture;value=self.request();f.write(self.envelope,value)
        native=prepare.assemble(value['request']['config'],f.settings,value['request']['workstation'],value['request']['hub'])
        real_fstat=__import__('os').fstat;real_prepare=local_prepare.prepare
        def rootstat(fd):
            fields=list(real_fstat(fd));fields[4]=0;return __import__('os').stat_result(fields)
        def mutate(*args):
            settings=json.loads(f.settings_file.read_text());settings['rooms']['alpha']['quota_project_id']=777
            f.write(f.settings_file,settings)
            return real_prepare(*args)
        with patch.object(prepare,'apply',return_value={'request_id':value['request']['request_id'],'native':native}), \
             patch('uas.local_room_prepare.os.geteuid',return_value=0), \
             patch('uas.local_prepare.os.fstat',side_effect=rootstat), \
             patch('uas.local_prepare.prepare',side_effect=mutate):
            with self.assertRaisesRegex(HostProfileError,'INPUT_CHANGED_DURING_HANDOFF'):
                prepare.apply_file(self.envelope,f.output)
        self.assertEqual(json.loads((f.output/'native.json').read_text())['rooms']['alpha']['quota_project_id'],777)
