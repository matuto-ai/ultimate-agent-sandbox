"""Pure synchronization/identity contracts for the hosted-only map wrapper."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import stat
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fixture_mapped_namespace',ROOT/'tests/linux/mapped_namespace.py')
wrapper=importlib.util.module_from_spec(spec);spec.loader.exec_module(wrapper)


class MappedNamespaceTests(unittest.TestCase):
    def argv(self):
        return ['/usr/bin/python3',str(ROOT/'tests/linux/diff_smoke.py'),'--namespace-helper','fixed']

    def test_only_fixed_staged_fixture_entrypoints(self):
        self.assertEqual(wrapper.fixed_argv(self.argv()),self.argv())
        for argv in (['sh','-c','true'],['/usr/bin/python3','/tmp/diff_smoke.py','--namespace-helper'],
                     ['/usr/bin/python3',str(ROOT/'tests/linux/diff_smoke.py'),'--run']):
            with self.assertRaises(RuntimeError):wrapper.fixed_argv(argv)

    def test_staged_wrapper_requires_exact_immutable_source(self):
        with tempfile.TemporaryDirectory() as directory:
            staged=Path(directory)/'mapped_namespace.py'
            source=(ROOT/'tests/linux/mapped_namespace.py').read_bytes()
            staged.write_bytes(source)
            argv=['/usr/bin/python3',str(Path(directory)/'diff_smoke.py'),'--namespace-helper','fixed']
            original=Path.lstat
            def info(path):
                if path==staged:return SimpleNamespace(st_mode=stat.S_IFREG|0o444,st_uid=0,st_size=len(source))
                return original(path)
            with patch.object(Path,'lstat',info):
                self.assertEqual(wrapper.fixed_argv(argv,staged=True),argv)
                staged.write_bytes(b'wrong wrapper')
                with self.assertRaises(RuntimeError):wrapper.fixed_argv(argv,staged=True)

    def test_exact_maps_are_written_once_and_read_back_before_release(self):
        values={'uid_map':'','gid_map':'','setgroups':'allow\n'};writes=[]
        class FakePath:
            def __init__(self,name=''):self.name=name
            def __truediv__(self,name):return FakePath(name)
            def read_text(self):return values[self.name]
            def write_text(self,value):writes.append((self.name,value));values[self.name]=value;return len(value)
        with patch.object(wrapper,'Path',FakePath):wrapper.install_maps(123)
        self.assertEqual(writes,[('uid_map',wrapper.MAP),('gid_map',wrapper.MAP)])
        with patch.object(wrapper,'Path',FakePath):
            with self.assertRaises(RuntimeError):wrapper.install_maps(123)
        self.assertEqual(len(writes),2)

    def launch(self,fail=False):
        events=[];child=Mock(pid=123);child.poll.return_value=None
        child.kill.side_effect=lambda:events.append('kill')
        child.wait.side_effect=lambda **kw:events.append('reap')
        def maps(pid):
            events.append('maps')
            if fail:raise RuntimeError('map denied')
        def write(fd,data):events.append('release');return 1
        with patch.object(wrapper,'fixed_argv',return_value=self.argv()),patch.object(wrapper.os,'geteuid',return_value=0),patch.dict(wrapper.os.environ,{'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux'}), \
             patch.object(wrapper.os,'pipe',side_effect=[(10,11),(12,13)]),patch.object(wrapper.os,'close') as close, \
             patch.object(wrapper.subprocess,'Popen',return_value=child) as popen, \
             patch.object(wrapper.select,'select',return_value=([10],[],[])),patch.object(wrapper.os,'read',return_value=wrapper.READY), \
             patch.object(wrapper.os,'write',side_effect=write),patch.object(wrapper,'install_maps',side_effect=maps):
            if fail:
                with self.assertRaises(RuntimeError):wrapper.mapped_popen(self.argv(),stdin=-1)
            else:self.assertIs(wrapper.mapped_popen(self.argv(),stdin=-1),child)
        self.assertEqual(popen.call_args.kwargs['pass_fds'],(11,12))
        self.assertEqual(sorted(x.args[0] for x in close.call_args_list),[10,11,12,13])
        return events

    def test_child_released_only_after_exact_map_success(self):
        self.assertEqual(self.launch(),['maps','release'])

    def test_map_failure_kills_reaps_without_release(self):
        self.assertEqual(self.launch(True),['maps','kill','reap'])

    def test_source_retains_maps_mount_and_identity_guards(self):
        source=(ROOT/'tests/linux/mapped_namespace.py').read_text()
        self.assertIn('os.unshare(os.CLONE_NEWUSER)',source)
        self.assertIn('os.unshare(os.CLONE_NEWNS)',source)
        self.assertLess(source.index('os.unshare(os.CLONE_NEWUSER)'),source.index('os.setgroups([])'))
        self.assertNotIn('/etc/subuid',source);self.assertNotIn('/etc/subgid',source)
        for name in wrapper.FIXTURES:
            text=(ROOT/'tests/linux'/name).read_text()
            self.assertIn('mapped_popen([',text)
            self.assertNotIn('--map-users=',text);self.assertNotIn('--map-groups=',text)
            self.assertIn("['0','100000','65536']",text)
            self.assertIn('os.setgid(65530);os.setuid(65530)',text)
        self.assertIn("'tests/linux/mapped_namespace.py'",(ROOT/'tests/linux/diff_smoke.py').read_text())
