"""Real full-config admission plus mocked layout effects; never native setup."""
from contextlib import ExitStack
from copy import deepcopy
import ast
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

from uas.artifact_protocol import RESERVATION_BYTES
from uas.checkouts import CheckoutAllocator
from uas.config import ConfigError, load
from uas.lifecycle import Supervisor

VM=Path(__file__).parent/'vm'
REPO=VM.parent.parent
sys.path.insert(0,str(VM))
try:
    SPEC=importlib.util.spec_from_file_location('artifact_layout_guest',VM/'guest_artifacts.py')
    guest=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(guest)
finally:sys.path.remove(str(VM))

NONCE='0123456789abcdef0123456789abcdef'


def template():return json.loads((REPO/'tests/fixtures/two-rooms.json').read_text())
def plan():return guest.fixture_layout(NONCE,template())
def admitted(document):return load(io.StringIO(json.dumps(document)))


class CompleteLayoutConfigTests(unittest.TestCase):
    def test_exact_generated_full_two_room_document_passes_real_loader(self):
        value=plan();configuration=value['configuration'];normalized=admitted(configuration)
        self.assertEqual(configuration['deployment']['state_root'],
            '/var/lib/uas-artifacts-'+NONCE+'/lifecycle')
        self.assertEqual({room['id'] for room in normalized['rooms']},{'alpha','beta'})
        self.assertIn('capability_enforcement',normalized)
        self.assertNotIn('capability_enforcement',configuration)
        for room in normalized['rooms']:
            paths=value['rooms'][room['id']]
            self.assertEqual(room['state_root'],str(Path(value['state_root'])/room['id']))
            self.assertEqual(room['project']['repository'],'example/'+room['id'])
            self.assertEqual(room['project']['roots'],{key:paths[key] for key in ('repo','checkouts','reference','workspace')})
            self.assertEqual(room['resolved']['boundary'],'declared-not-verified')
            self.assertEqual({seat['resolved']['activation'] for seat in room['seats']},{'not-evaluated'})
            self.assertEqual({seat['resolved']['credential_status'] for seat in room['seats']},{'unavailable'})
            self.assertEqual(room['resources'],{'cpu':.5,'memory_bytes':256<<20,'disk_bytes':256<<20,
                'pids':64,'log_bytes':10<<20})
            self.assertLessEqual(room['resources']['log_bytes'],room['resources']['disk_bytes'])
            self.assertLessEqual(RESERVATION_BYTES*2,room['resources']['disk_bytes'])
    def test_exact_generated_config_agrees_with_real_supervisor_and_allocator_constructors(self):
        value=plan()
        with patch.object(CheckoutAllocator,'_git',side_effect=AssertionError('Git execution forbidden')) as git, \
                patch.object(Supervisor,'_locked',side_effect=AssertionError('lifecycle effects forbidden')) as locked, \
                patch.object(Path,'mkdir',side_effect=AssertionError('directory creation forbidden')):
            for room in ('alpha','beta'):
                supervisor=Supervisor(value['state_root'],room,None,authorize=lambda *_:False,revoke=lambda *_:False)
                allocator=CheckoutAllocator(supervisor,io.StringIO(json.dumps(value['configuration'])))
                self.assertEqual(allocator.room['state_root'],str(supervisor.directory))
                self.assertEqual(allocator.repo,Path(value['rooms'][room]['repo']))
                self.assertEqual(allocator.root,Path(value['rooms'][room]['checkouts']))
            git.assert_not_called();locked.assert_not_called()
    def test_planning_is_deterministic_and_does_not_mutate_shared_template(self):
        source=template();before=deepcopy(source)
        first=guest.fixture_layout(NONCE,source);second=guest.fixture_layout(NONCE,source)
        self.assertEqual(first,second);self.assertEqual(source,before)
        other=guest.fixture_layout('f'*32,source)
        self.assertNotEqual(other['scratch_root'],first['scratch_root'])
        self.assertNotEqual(other['rooms']['alpha']['room_instance'],first['rooms']['alpha']['room_instance'])
        self.assertEqual(first['rooms']['alpha']['room_root'],other['rooms']['alpha']['room_root'])
    def test_invalid_nonce_or_room_template_fails_without_caller_chosen_roots(self):
        for nonce in ('',NONCE.upper(),'../escape','f'*33,None):
            with self.subTest(nonce=nonce),self.assertRaises(AssertionError):guest.fixture_layout(nonce,template())
        source=template();source['rooms'][1]['id']='gamma'
        with self.assertRaises(AssertionError):guest.fixture_layout(NONCE,source)
    def test_real_loader_rejects_original_reserved_run_path(self):
        value=plan()['configuration'];value['deployment']['state_root']='/run/uas-artifacts-'+NONCE+'/lifecycle'
        for room in value['rooms']:room['state_root']=value['deployment']['state_root']+'/'+room['id']
        with self.assertRaises(ConfigError) as failure:admitted(value)
        self.assertEqual(failure.exception.field,'$.deployment.state_root')
        self.assertEqual(failure.exception.reason,'reserved host path')
    def test_real_loader_rejects_project_control_room_and_crossroom_overlap(self):
        mutations=[lambda c:c['rooms'][1]['project']['roots'].update(repo=c['rooms'][0]['project']['roots']['repo']),
            lambda c:c['rooms'][0]['project']['roots'].update(repo=c['deployment']['state_root']+'/repo'),
            lambda c:c['rooms'][1].update(state_root=c['rooms'][0]['state_root']),
            lambda c:c['rooms'][0]['project']['roots'].update(checkouts=c['rooms'][0]['project']['roots']['repo']+'/slots')]
        for mutate in mutations:
            value=plan()['configuration'];mutate(value)
            with self.subTest(value=value['rooms'][0]['state_root']),self.assertRaises(ConfigError):admitted(value)
    def test_real_loader_exercises_nonpath_schema_and_reference_constraints(self):
        mutations=[lambda c:c['deployment'].update(unknown_field=True),
            lambda c:c['rooms'][1]['project'].update(repository='example/alpha'),
            lambda c:c['rooms'][0]['seats'][0].update(profile='missing-profile'),
            lambda c:c['rooms'][0]['network'].update(block_host=False),
            lambda c:c['rooms'][0]['resources'].update(log_bytes=(256<<20)+1),
            lambda c:c['rooms'][0]['boundary'].update(non_root=False)]
        for mutate in mutations:
            value=plan()['configuration'];mutate(value)
            with self.subTest(mutate=mutate),self.assertRaises(ConfigError):admitted(value)


class RuntimeLayoutUseTests(unittest.TestCase):
    def test_guest_startup_imports_only_stdlib_and_preinstalled_boundary(self):
        module=ast.parse((VM/'guest_artifacts.py').read_text())
        imports=[]
        class StartupImports(ast.NodeVisitor):
            def visit_FunctionDef(self,node):pass
            def visit_AsyncFunctionDef(self,node):pass
            def visit_Import(self,node):imports.extend(alias.name.split('.')[0] for alias in node.names)
            def visit_ImportFrom(self,node):imports.append((node.module or '').split('.')[0])
        StartupImports().visit(module)
        self.assertLessEqual(set(imports),sys.stdlib_module_names|{'guest_boundary'})
        storage=next(node for node in module.body if isinstance(node,ast.FunctionDef) and node.name=='storage')
        self.assertTrue(any(isinstance(node,ast.ImportFrom) and node.module=='uas.config' for node in storage.body))
        scenario=next(node for node in module.body if isinstance(node,ast.FunctionDef) and node.name=='scenario')
        self.assertEqual(ast.unparse(scenario.body[0]),"sys.path[:0] = [str(ROOT), str(ROOT / 'tests/vm')]")
    def test_full_config_rejection_precedes_every_storage_effect(self):
        value=plan();value['configuration']['deployment']['state_root']='/run/rejected'
        with patch.object(guest,'ROOT',REPO),patch.object(guest,'fixture_layout',return_value=value), \
                patch.object(guest,'run',side_effect=AssertionError('no external command')) as run, \
                patch.object(Path,'mkdir',side_effect=AssertionError('no directory effects')) as mkdir, \
                patch.object(guest.os,'chown',side_effect=AssertionError('no ownership effects')) as chown:
            with self.assertRaises(ConfigError):guest.storage(NONCE,{})
            run.assert_not_called();mkdir.assert_not_called();chown.assert_not_called()
    def test_storage_consumes_plan_paths_and_exact_raw_validated_configuration(self):
        value=plan();ownership={}
        with ExitStack() as stack:
            stack.enter_context(patch.object(guest,'ROOT',REPO))
            stack.enter_context(patch.object(Path,'resolve',autospec=True,side_effect=lambda path:path))
            stack.enter_context(patch.object(Path,'is_block_device',return_value=True))
            run=stack.enter_context(patch.object(guest,'run',side_effect=lambda *args,**kwargs:str(2*1024**3) if args[0]=='blockdev' else ''))
            mkdir=stack.enter_context(patch.object(Path,'mkdir',autospec=True))
            chmod=stack.enter_context(patch.object(Path,'chmod',autospec=True))
            chown=stack.enter_context(patch.object(guest.os,'chown'))
            stack.enter_context(patch.object(Path,'write_bytes',autospec=True))
            write=stack.enter_context(patch.object(Path,'write_text',autospec=True))
            actual=guest.storage(NONCE,ownership)
        self.assertEqual(actual,value['rooms'])
        self.assertEqual(ownership['scratch'],Path(value['scratch_root']))
        write.assert_called_once_with(Path(value['configuration_path']),json.dumps(value['configuration']))
        self.assertEqual(admitted(json.loads(write.call_args.args[1])),admitted(value['configuration']))
        self.assertIn(unittest.mock.call(Path(value['scratch_root']),mode=0o711),mkdir.call_args_list)
        self.assertIn(unittest.mock.call(Path(value['state_root']),mode=0o700),mkdir.call_args_list)
        self.assertIn(unittest.mock.call(Path(value['state_root']),165533,165533),chown.call_args_list)
        for room in ('alpha','beta'):
            path=Path(value['rooms'][room]['journal'])
            self.assertIn(unittest.mock.call(path,mode=0o700),mkdir.call_args_list)
            self.assertIn(unittest.mock.call(path,165533,165533),chown.call_args_list)
            self.assertIn(unittest.mock.call('xfs_quota','-x','-c',
                'limit -p bhard=262144k ihard=8192 '+str(value['rooms'][room]['project']),str(guest.STORAGE)),run.call_args_list)
            self.assertIn(unittest.mock.call('xfs_quota','-x','-c',
                'limit -p bhard=65536k ihard=2048 '+str(value['rooms'][room]['project']+1),str(guest.STORAGE)),run.call_args_list)
    def test_no_lifecycle_configuration_or_private_journal_mounted_into_workstation_or_hub(self):
        value=plan()
        for room,paths in value['rooms'].items():
            for hub in (False,True):
                with patch.object(guest,'run',return_value='fixed-container-id') as run:
                    guest.create('sha256:'+'a'*64,'fixed-name',paths,NONCE,hub=hub)
                args=run.call_args.args
                mounts=[args[i+1] for i,arg in enumerate(args[:-1]) if arg=='--mount']
                sources=[Path(part.split('=',1)[1]) for mount in mounts for part in mount.split(',') if part.startswith('src=')]
                for secret in (Path(value['state_root']),Path(value['configuration_path']),Path(paths['journal'])):
                    self.assertFalse(any(source==secret or source in secret.parents for source in sources))
                self.assertNotIn(value['scratch_root'],map(str,sources))
                if not hub:
                    self.assertIn(paths['scratch'],map(str,sources))
                    self.assertIn('--memory',args);self.assertEqual(args[args.index('--memory')+1],'256m')
                    self.assertEqual(args[args.index('--cpus')+1],'0.5')
                    self.assertEqual(args[args.index('--pids-limit')+1],'64')
                else:
                    self.assertEqual(args[args.index('--memory')+1],'128m')
                    self.assertEqual(args[args.index('--cpus')+1],'0.25')
                    self.assertEqual(args[args.index('--pids-limit')+1],'32')
    def test_private_path_socket_lengths_and_capacity_cleanup_invariants(self):
        value=plan()
        for room,paths in value['rooms'].items():
            self.assertEqual(Path(paths['journal']),Path(paths['room_root'])/'.supervisor')
            self.assertNotIn(Path(value['state_root']),Path(paths['scratch']).parents)
            for key,name in (('gate','gate.sock'),('control','hub.sock')):
                self.assertLess(len(str(Path(paths[key])/name).encode()),108)
        supervisor=(VM/'artifact_supervisor.py').read_text()
        self.assertIn("allocated((room_root,supervisor.directory,Path(config['gate']),Path(config['control'])))",supervisor)
        self.assertIn('used+reserved+size>256<<20',supervisor)
        self.assertIn('MAX_LOG=1<<20',supervisor)
        self.assertIn('ROOM_DISK_BYTES = 256 << 20',(VM/'artifact_hub.py').read_text())
        self.assertEqual(RESERVATION_BYTES,32<<20)
        source=(VM/'guest_artifacts.py').read_text()
        self.assertIn("cleanup('owned-scratch',lambda:shutil.rmtree(ownership['scratch']))",source)
        storage=source[source.index('def storage('):source.index('def create(')]
        self.assertLess(storage.index('load(io.StringIO(configuration))'),storage.index("run('mkfs.xfs'"))
        self.assertLess(storage.index('load(io.StringIO(configuration))'),storage.index('os.chown('))


if __name__=='__main__':unittest.main()
