"""Pure mountinfo parsing/mocked descriptors only. Never read local /proc/tmp."""
from contextlib import ExitStack
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

VM=Path(__file__).parent/'vm'
SPEC=importlib.util.spec_from_file_location('artifact_tmp_runtime',VM/'artifact_room_probe.py')
probe=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(probe)


def mountinfo(*,options='rw,nosuid,nodev,noexec',filesystem='tmpfs',device='0:77',
              point='/tmp',root='/',mount_id=33,parent=22,super_options='rw,size=8192k,uid=65532,gid=65532,inode64'):
    return (f'{mount_id} {parent} {device} {root} {point} {options} - {filesystem} tmpfs {super_options}\n').encode()


def node(**changes):
    return SimpleNamespace(**{'st_mode':stat.S_IFDIR|0o700,'st_uid':65532,'st_gid':65532,
        'st_dev':os.makedev(0,77),'st_ino':19,**changes})


def filesystem(**changes):
    return SimpleNamespace(**{'f_frsize':4096,'f_blocks':2048,
        'f_flag':os.ST_NOSUID|os.ST_NODEV|os.ST_NOEXEC,**changes})


class MountInfoParsingTests(unittest.TestCase):
    def test_actual_fixed_flags_and_device_not_option_size_or_uid_claims(self):
        raw=mountinfo(super_options='rw,size=999999k,uid=0,gid=0,private=do-not-log')
        value=probe.parse_tmp_mountinfo(raw)
        self.assertEqual(value,{'mount_id':33,'parent_mount_id':22,'device_major':0,'device_minor':77,
            'filesystem':'tmpfs','mount_flags':{'readonly':False,'nosuid':True,'nodev':True,'noexec':True}})
        self.assertNotIn('do-not-log',json.dumps(value));self.assertNotIn('size',value)

    def test_other_filesystems_and_missing_flags_are_observed_not_assumed(self):
        value=probe.parse_tmp_mountinfo(mountinfo(options='ro',filesystem='unknown-secret-name'))
        self.assertEqual(value['filesystem'],'other')
        self.assertEqual(value['mount_flags'],{'readonly':True,'nosuid':False,'nodev':False,'noexec':False})
        self.assertNotIn('unknown-secret-name',json.dumps(value))

    def test_unrelated_mounts_and_unknown_optional_fields_do_not_leak(self):
        other=mountinfo(point='/private\\040mount',mount_id=44)
        raw=mountinfo().replace(b' - ',b' shared:7 future-tag:private - ')+other
        self.assertEqual(probe.parse_tmp_mountinfo(raw),probe.parse_tmp_mountinfo(mountinfo()))

    def test_absent_duplicate_stacked_and_noncanonical_tmp_are_refused(self):
        variants=[mountinfo(point='/other'),mountinfo()+mountinfo(mount_id=44,parent=33),
            mountinfo()+mountinfo(),mountinfo(root='/subdirectory')]
        variants.extend(mountinfo(point=path) for path in ('/tmp/','//tmp','/tmp/.','/other/../tmp','tmp','/\\164mp'))
        for raw in variants:
            with self.subTest(raw=raw),self.assertRaises(RuntimeError):probe.parse_tmp_mountinfo(raw)

    def test_input_size_line_count_and_truncated_or_control_data_are_bounded(self):
        variants=[b'',mountinfo().decode(),b'x'*(probe.MOUNTINFO_BYTES+1),mountinfo().rstrip(b'\n'),
            mountinfo()+b'\x00',mountinfo().replace(b'/tmp',b'/tmp\t')]
        variants.append(b''.join(mountinfo(point='/other',mount_id=i+1) for i in range(probe.MOUNTINFO_LINES+1)))
        for raw in variants:
            with self.subTest(kind=type(raw)),self.assertRaises(RuntimeError):probe.parse_tmp_mountinfo(raw)

    def test_id_device_and_conflicting_mount_flags_are_not_ambiguously_parsed(self):
        variants=[mountinfo(mount_id=0),mountinfo(mount_id=2**64),mountinfo(device='-1:77'),
            mountinfo(device='0:077'),mountinfo(device='0:4294967296'),mountinfo(device='0:0:77'),
            mountinfo(options='rw,ro'),mountinfo(options='rw,rw'),mountinfo(options='nosuid,nodev,noexec'),
            mountinfo(options='rw,noexec,exec'),mountinfo(options='rw,nosuid,suid'),
            mountinfo(options='rw,nodev,dev'),mountinfo(options='rw,,nosuid'),
            mountinfo().replace(b' - ',b'  - '),mountinfo().replace(b' - ',b' -- ')]
        for raw in variants:
            with self.subTest(raw=raw),self.assertRaises(RuntimeError):probe.parse_tmp_mountinfo(raw)


class TmpMountDescriptorTests(unittest.TestCase):
    def observe(self,*,documents=None,nodes=None,filesystems=None,named=None,open_error=None,
                close_error=None,stat_error=None,filesystem_error=None):
        documents=[mountinfo(),mountinfo()] if documents is None else documents
        nodes=[node(),node()] if nodes is None else nodes
        filesystems=[filesystem(),filesystem()] if filesystems is None else filesystems
        events=[];streams=[]
        class BoundedStream(io.BytesIO):
            def read(self,size=-1):
                self_outer.assertEqual(size,probe.MOUNTINFO_BYTES+1)
                events.append('mountinfo-read');return super().read(size)
        self_outer=self
        def source(path,mode):
            self.assertEqual((path,mode),('/proc/self/mountinfo','rb'))
            stream=BoundedStream(documents[len(streams)]);streams.append(stream);return stream
        def open_directory(path,flags):
            events.append('directory-open');self.assertEqual(path,'/tmp')
            self.assertEqual(flags,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.assertFalse(flags&os.O_PATH)
            if open_error:raise open_error
            return 71
        def close_directory(fd):
            events.append('directory-close');self.assertEqual(fd,71)
            if close_error:raise close_error
        with ExitStack() as stack:
            stack.enter_context(patch('builtins.open',side_effect=source))
            opened=stack.enter_context(patch.object(probe.os,'open',side_effect=open_directory))
            closed=stack.enter_context(patch.object(probe.os,'close',side_effect=close_directory))
            fstat=stack.enter_context(patch.object(probe.os,'fstat',side_effect=nodes))
            fstatvfs=stack.enter_context(patch.object(probe.os,'fstatvfs',side_effect=filesystem_error or filesystems))
            pathstat=stack.enter_context(patch.object(probe.os,'stat',side_effect=stat_error,
                return_value=named or node()))
            try:return probe.tmp_mount_observation()
            finally:
                self.assertTrue(all(stream.closed for stream in streams))
                self.assertEqual(events[0],'mountinfo-read')
                if opened.called and not open_error:closed.assert_called_once_with(71)
                else:closed.assert_not_called()
                if pathstat.called:pathstat.assert_called_once_with('/tmp',follow_symlinks=False)
                for call in fstat.call_args_list+fstatvfs.call_args_list:self.assertEqual(call.args,(71,))

    def test_exact_schema_comes_from_held_directory_and_actual_statvfs(self):
        value=self.observe(documents=[mountinfo(super_options='rw,size=1,uid=0,gid=0')]*2)
        self.assertEqual(value,{'version':1,'mount_id':33,'parent_mount_id':22,'device_major':0,'device_minor':77,
            'filesystem':'tmpfs','mount_flags':{'readonly':False,'nosuid':True,'nodev':True,'noexec':True},
            'statvfs_flags':{'readonly':False,'nosuid':True,'nodev':True,'noexec':True},
            'size_bytes':8<<20,'allocation_unit':4096,'uid':65532,'gid':65532,'mode':0o700,
            'device':os.makedev(0,77),'inode':19})
        self.assertLess(len(json.dumps(value).encode()),1024)

    def test_observed_wrong_permissions_flags_or_capacity_not_relabelled_as_expected(self):
        nodes=[node(st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o1777)]*2
        filesystems=[filesystem(f_blocks=4096,f_flag=os.ST_RDONLY)]*2
        value=self.observe(nodes=nodes,named=nodes[0],filesystems=filesystems)
        self.assertEqual((value['uid'],value['gid'],value['mode'],value['size_bytes']),(0,0,0o1777,16<<20))
        self.assertEqual(value['statvfs_flags'],{'readonly':True,'nosuid':False,'nodev':False,'noexec':False})

    def test_device_mismatch_and_non_directory_fail_closed_with_held_fd_closed(self):
        for nodes in ([node(st_dev=os.makedev(0,78))], [node(st_mode=stat.S_IFREG|0o700)]):
            with self.subTest(nodes=nodes),self.assertRaises(RuntimeError):self.observe(nodes=nodes)

    def test_replaced_named_directory_or_changed_held_identity_is_refused(self):
        for field in ('st_dev','st_ino','st_uid','st_gid','st_mode'):
            other=node();setattr(other,field,getattr(other,field)+1)
            with self.subTest(field=field,named=True),self.assertRaises(RuntimeError):self.observe(named=other)
            with self.subTest(field=field,named=False),self.assertRaises(RuntimeError):self.observe(nodes=[node(),other])

    def test_mount_stack_identity_or_flags_or_filesystem_capacity_change_refused(self):
        for after in (mountinfo(mount_id=34),mountinfo(parent=21),mountinfo(options='ro'),
                mountinfo(filesystem='other'),mountinfo(device='0:78'),mountinfo()+mountinfo(mount_id=34)):
            with self.subTest(after=after),self.assertRaises(RuntimeError):self.observe(documents=[mountinfo(),after])
        for after in (filesystem(f_blocks=2049),filesystem(f_frsize=2048),filesystem(f_flag=0)):
            with self.subTest(after=after),self.assertRaises(RuntimeError):self.observe(filesystems=[filesystem(),after])

    def test_open_statvfs_pathstat_and_close_failures_do_not_yield_facts(self):
        for kwargs in ({'open_error':OSError(13,'fixed')},{'filesystem_error':OSError(5,'fixed')},
                {'stat_error':OSError(2,'fixed')},{'close_error':OSError(5,'fixed')}):
            with self.subTest(kwargs=kwargs),self.assertRaises(OSError):self.observe(**kwargs)

    def test_unavailable_statvfs_flag_definitions_and_invalid_numbers_fail_closed(self):
        values=[filesystem(),filesystem()]
        with patch.object(probe.os,'ST_NOEXEC',None),self.assertRaises(RuntimeError):self.observe(filesystems=values)
        for change in ({'f_blocks':True},{'f_blocks':-1},{'f_blocks':2**64-1},
                {'f_frsize':0},{'f_frsize':True},{'f_frsize':(1<<20)+1},{'f_flag':'private'}):
            with self.subTest(change=change),self.assertRaises(RuntimeError):self.observe(filesystems=[filesystem(**change)])

    def test_invalid_initial_mountinfo_never_opens_directory(self):
        with self.assertRaises(RuntimeError):self.observe(documents=[b'not mountinfo'])

    def test_facts_uses_runtime_observation_without_reading_local_proc_or_network(self):
        sentinel={'version':1,'test_only':'runtime observation'}
        text={'/proc/self/attr/current':'fixed-label','/proc/self/uid_map':'fixed-map',
            '/proc/self/gid_map':'fixed-map','/proc/sys/kernel/overflowuid':'65534',
            '/proc/sys/kernel/overflowgid':'65534'}
        with ExitStack() as stack:
            observed=stack.enter_context(patch.object(probe,'tmp_mount_observation',return_value=sentinel))
            stack.enter_context(patch.object(probe,'process_status',return_value={}))
            stack.enter_context(patch.object(probe.os,'getuid',return_value=65532))
            stack.enter_context(patch.object(probe.os,'getgid',return_value=65532))
            stack.enter_context(patch.object(probe.os,'getgroups',return_value=[65532]))
            stack.enter_context(patch.object(Path,'read_text',autospec=True,side_effect=lambda p:text[str(p)]))
            stack.enter_context(patch.object(probe.os,'readlink',return_value='fixed-namespace'))
            stack.enter_context(patch.object(probe.os,'stat',side_effect=OSError(2,'fixed missing')))
            stream=stack.enter_context(patch('builtins.open',side_effect=lambda *a:io.BytesIO(b'fixed-binary')))
            channel=stack.enter_context(patch.object(probe.socket,'socket',return_value=MagicMock()))
            value=probe.facts()
        self.assertIs(value['tmp_mount'],sentinel);observed.assert_called_once_with()
        self.assertEqual(stream.call_count,len(probe.BINARIES));channel.assert_called_once_with(probe.socket.AF_INET,probe.socket.SOCK_STREAM)


if __name__=='__main__':unittest.main()
