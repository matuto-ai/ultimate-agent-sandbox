"""Read-only Git selection and controlled root custody, no native effects."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import json
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

from uas.native_qualification import (QualificationError, execute, git_broker_selection,
                                       check_git_credentials)
import test_native_qualification as plan_fixture
import test_native_qualification_execute as execute_fixture


class NativeGitQualificationTests(unittest.TestCase):
    def selection(self):
        f=plan_fixture.NativeQualificationTests();f.setUp()
        for name in ('git','git_broker'):
            f.selection[name+'_manifest']={'path':'/installation/'+name+'.json','sha256':'f'*64}
        plan=f.plan()
        value={'version':1,'ssh_executable':'/usr/bin/ssh','ssh_sha256':'a'*64,
            'credentials':[{'actor_id':seat['actor'],'key_path':'/private/'+seat['actor']+'/key',
                            'known_hosts_path':'/private/'+seat['actor']+'/hosts'} for seat in plan.seats.values()]}
        return f,plan,value

    def test_refs_both_or_neither_preserve_legacy(self):
        f=plan_fixture.NativeQualificationTests();f.setUp();legacy=f.plan()
        self.assertNotIn('git_manifest',legacy.installation)
        for name in ('git','git_broker'):
            f.selection[name+'_manifest']={'path':'/installation/'+name+'.json','sha256':'a'*64}
            with self.assertRaisesRegex(QualificationError,'INVALID_NATIVE_SELECTION'):f.plan()
            del f.selection[name+'_manifest']
        f,plan,_=self.selection();self.assertIn('git_manifest',plan.installation)
        f.selection['git_manifest']['sha256']='bad'
        with self.assertRaisesRegex(QualificationError,'INVALID_INSTALLATION_REFERENCE'):f.plan()

    def test_public_selection_exact_actors_paths_and_no_credential_reads(self):
        _,plan,value=self.selection()
        with patch('uas.native_qualification.read_manifest',return_value=value) as reader, \
             patch.object(Path,'read_bytes',side_effect=AssertionError('credential read')), \
             patch.object(Path,'read_text',side_effect=AssertionError('credential read')):
            self.assertEqual(git_broker_selection(plan),value)
        reader.assert_called_once_with('/installation/git_broker.json','f'*64)
        invalid=[]
        other=deepcopy(value);other['credentials'][0]['actor_id']='unknown';invalid.append(other)
        duplicate=deepcopy(value);duplicate['credentials'][1]=deepcopy(duplicate['credentials'][0]);invalid.append(duplicate)
        extra=deepcopy(value);extra['credentials'][0]['token']='secret';invalid.append(extra)
        relative=deepcopy(value);relative['credentials'][0]['key_path']='relative/key';invalid.append(relative)
        traversal=deepcopy(value);traversal['credentials'][0]['known_hosts_path']='/private/../hosts';invalid.append(traversal)
        mounted=deepcopy(value);mounted['credentials'][0]['key_path']=next(iter(plan.room['project']['roots'].values()))+'/key';invalid.append(mounted)
        for current in invalid:
            with self.subTest(current=current),patch('uas.native_qualification.read_manifest',return_value=current):
                with self.assertRaises((QualificationError,ValueError)):git_broker_selection(plan)

    def test_metadata_private_regular_owned_single_link_and_no_content_read(self):
        _,plan,value=self.selection()
        paths={row[k] for row in value['credentials'] for k in ('key_path','known_hosts_path')}
        baseline=dict(st_mode=stat.S_IFREG|0o600,st_uid=165534,st_nlink=1,st_size=64)
        current=dict(baseline);resolve=lambda path,**kw:path
        def info(path):
            self.assertIn(str(path),paths);return N(**current)
        with patch.object(Path,'resolve',resolve),patch.object(Path,'lstat',info), \
             patch.object(Path,'open',side_effect=AssertionError('credential content read')):
            check_git_credentials(plan,value)
            for changes in ({'st_mode':stat.S_IFREG|0o644},{'st_mode':stat.S_IFREG|0o200},
                            {'st_mode':stat.S_IFLNK|0o600},{'st_uid':0},{'st_nlink':2},
                            {'st_size':0},{'st_size':1048577}):
                current.clear();current.update(baseline);current.update(changes)
                with self.subTest(changes=changes),self.assertRaisesRegex(QualificationError,'GIT_CREDENTIAL_UNAVAILABLE'):
                    check_git_credentials(plan,value)
        with patch.object(Path,'resolve',lambda path,**kw:Path('/redirect') if str(path) in paths else path), \
             patch.object(Path,'lstat',lambda path:N(**baseline)):
            with self.assertRaisesRegex(QualificationError,'GIT_CREDENTIAL_UNAVAILABLE'):check_git_credentials(plan,value)

    def test_fixed_public_projection_excludes_credentials_without_reading(self):
        _,plan,value=self.selection()
        value['credentials'][0]['key_path']='/run/uas-native/instance/git/private-key'
        with patch.object(Path,'resolve',lambda path,**kw:path), \
             patch.object(Path,'lstat',lambda path:N(st_mode=stat.S_IFREG|0o600,st_uid=165534,st_nlink=1,st_size=64)), \
             patch.object(Path,'open',side_effect=AssertionError('credential read')):
            with self.assertRaisesRegex(QualificationError,'GIT_CREDENTIAL_UNAVAILABLE'):
                check_git_credentials(plan,value)

    def wrapped(self,root,*,git_timeout=False,child_timeout=False):
        helper=execute_fixture.NativeQualificationExecuteTests();self.addCleanup(helper.doCleanups)
        plan,events,broker,child=helper.fixture(root,child_timeout=child_timeout)
        plan.installation.update(git_manifest={},git_broker_manifest={})
        import uas.native_qualification_backend as backend
        original_provision=backend.provision
        @contextmanager
        def provision(selected):
            with original_provision(selected) as resources:
                resources.expect_git_broker=lambda:events.append('expect-git')
                resources.hold_git_broker=lambda p:events.append(('hold-git',p))
                yield resources
        class Channel:
            def __init__(self,n):self.n=n
            def fileno(self):return self.n
            def close(self):events.append(('close-channel',self.n))
        git=N(returncode=None,terminated=False,stdin=N(role='git'))
        def wait(timeout):
            events.append(('wait','git'))
            if git_timeout:raise subprocess.TimeoutExpired('fixed-git',timeout)
            git.returncode=0;return 0
        git.wait=wait;git.poll=lambda:git.returncode
        git.terminate=Mock();git.kill=Mock()
        spawns=[];startup=[]
        def popen(argv,**kwargs):
            role={'uas.forge_read_service':'broker','uas.git_service':'git','uas.native_session':'child'}[argv[2]]
            events.append(('spawn',role));spawns.append((role,argv,kwargs))
            return {'broker':broker,'git':git,'child':child}[role]
        original_lstat=Path.lstat
        git_private=root/'git-broker';git_private.mkdir()
        def lstat(path):
            if path==git_private:return N(st_mode=stat.S_IFDIR|0o700,st_uid=165534)
            return original_lstat(path)
        def write(stream,raw,deadline):
            events.append('bounded-'+stream.role+'-startup');startup.append((stream.role,json.loads(raw)))
        stack=ExitStack();self.addCleanup(stack.close)
        stack.enter_context(patch('uas.native_qualification_backend.provision',provision))
        stack.enter_context(patch('uas.native_qualification.git_broker_selection',return_value={
            'version':1,'ssh_executable':'/usr/bin/ssh','ssh_sha256':'e'*64,
            'credentials':[{'actor_id':'dev','key_path':'/private/dev-key','known_hosts_path':'/private/dev-hosts'}]}))
        stack.enter_context(patch('uas.native_qualification.check_git_credentials'))
        # Preserve the original fixture's exact allocation channel identities.
        original_pairs=__import__('socket').socketpair
        calls=[0]
        def pairs(*args):
            calls[0]+=1
            return (Channel(45),Channel(46)) if calls[0]==3 else original_pairs(*args)
        stack.enter_context(patch('socket.socketpair',side_effect=pairs))
        stack.enter_context(patch('subprocess.Popen',side_effect=popen))
        stack.enter_context(patch.object(Path,'lstat',lstat))
        stack.enter_context(patch('uas.native_qualification.write_startup',side_effect=write))
        return plan,events,broker,git,child,spawns,startup

    def test_fixed_git_service_separate_fd_intent_custody_before_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            plan,events,broker,git,child,spawns,startup=self.wrapped(Path(directory))
            result=execute(plan)
            self.assertEqual(result['resources']['status'],'stopped-evidence-retained')
            self.assertLess(events.index('expect-git'),events.index(('spawn','git')))
            self.assertLess(events.index(('hold-git',git)),events.index('bounded-git-startup'))
            self.assertLess(events.index('bounded-git-startup'),events.index('expect-child'))
            rows={role:(argv,kw) for role,argv,kw in spawns}
            argv,kw=rows['git'];self.assertEqual(argv[1:],['-m','uas.git_service','46'])
            self.assertEqual((kw['user'],kw['group'],kw['extra_groups'],kw['pass_fds']),(165534,165534,[],(46,)))
            self.assertEqual(rows['child'][0][-3:],['41','44','45'])
            self.assertEqual(rows['child'][1]['pass_fds'],(31,32,41,44,45))
            self.assertEqual(rows['broker'][1]['pass_fds'],(42,))
            for _,_,kw in spawns:
                self.assertNotIn('shell',kw);self.assertEqual(kw['cwd'],'/')
            configuration=dict(startup)['git']
            self.assertEqual(configuration['binding']['repository'],'owner/repo')
            self.assertTrue(configuration['audit_path'].endswith('/git-broker/audit.db'))
            self.assertNotIn('never read',json.dumps(configuration))
            self.assertEqual(events[-1],'cleanup-owner')
            git.kill.assert_not_called();git.terminate.assert_not_called()

    def test_uncertain_git_broker_keeps_cleanup_pending_and_never_kills_or_resends(self):
        with tempfile.TemporaryDirectory() as directory:
            plan,events,broker,git,child,spawns,startup=self.wrapped(Path(directory),git_timeout=True)
            with self.assertRaisesRegex(QualificationError,'GIT_BROKER_CLEANUP_PENDING'):execute(plan)
            self.assertEqual(events.count(('spawn','git')),1)
            self.assertEqual(events.count('bounded-git-startup'),1)
            git.kill.assert_not_called();git.terminate.assert_not_called();self.assertFalse(broker.terminated)
            self.assertEqual(events[-1],'cleanup-owner')

    def test_child_timeout_only_terminates_owned_host_not_either_broker(self):
        with tempfile.TemporaryDirectory() as directory:
            plan,events,broker,git,child,spawns,startup=self.wrapped(Path(directory),child_timeout=True)
            with self.assertRaises(subprocess.TimeoutExpired):execute(plan)
            self.assertTrue(child.terminated);self.assertFalse(broker.terminated)
            git.terminate.assert_not_called();git.kill.assert_not_called()
            self.assertEqual(events.count(('spawn','git')),1);self.assertEqual(events[-1],'cleanup-owner')
