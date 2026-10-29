"""Fixed diff native source/ELF checks; no helper execution or kernel admission.

Build checks run only where the test runner permits a compiler. Pure source
cases can be selected under pre-import process/socket/kernel deny guards.
"""
from pathlib import Path
import ast
import hashlib
import importlib.util
import os
import stat
from types import SimpleNamespace
from unittest.mock import patch
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'runtime/workstation'


def source_filter():
    """Interpret the finite BPF source macros, not arbitrary C or native code."""
    source=(NATIVE/'diff_evaluator.c').read_text()
    table=source.split('static const struct sock_filter dg_filter[]={',1)[1].split('};',1)[0]
    table=re.sub(r'/\*.*?\*/','',table,flags=re.S)
    constants={'BPF_LD|BPF_W|BPF_ABS':0x20,'BPF_JMP|BPF_JEQ|BPF_K':0x15,
        'BPF_JMP|BPF_JGE|BPF_K':0x35,'AUDIT_ARCH_X86_64':0xc000003e,
        'SYS_exit':60,'SYS_exit_group':231,'SYS_read':0,'SYS_write':1,
        'SYS_openat2':437,'SYS_fstat':5,'SYS_getdents64':217,'SYS_close':3,
        'AG_MAX_FDS':64,'offsetof(struct seccomp_data,arch)':4}
    def value(text):
        text=text.strip()
        if text in constants:return constants[text]
        if re.fullmatch(r'[0-9]+',text):return int(text)
        raise AssertionError('Unrecognized fixed filter expression: '+text)
    code=[]
    # Hosted ELF comparison verifies these explicit macro expansions.
    while table.strip(' \n\t,'):
        table=table.lstrip(' \n\t,')
        macro=re.match(r'(LOAD_NR|DENY|ALLOW)\b',table)
        if macro:
            code.append({'LOAD_NR':(0x20,0,0,0),'DENY':(0x06,0,0,0x80000000),
                         'ALLOW':(0x06,0,0,0x7fff0000)}[macro[1]])
            table=table[macro.end():];continue
        macro=re.match(r'(BPF_STMT|BPF_JUMP|LOAD_ARG|ARG_FD|ARG_RANGE)\(',table)
        if not macro:raise AssertionError('Unexpected BPF token: '+table[:80])
        start=macro.end();depth=1;end=start
        while depth:
            if table[end]=='(':depth+=1
            if table[end]==')':depth-=1
            end+=1
        arguments=table[start:end-1]
        parts=[];level=0;begin=0
        for i,char in enumerate(arguments):
            if char=='(':level+=1
            if char==')':level-=1
            if char==',' and not level:parts.append(arguments[begin:i]);begin=i+1
        parts.append(arguments[begin:]);args=[value(item) for item in parts]
        kind=macro[1]
        if kind=='BPF_STMT':code.append((args[0],0,0,args[1]))
        elif kind=='BPF_JUMP':code.append((args[0],args[2],args[3],args[1]))
        elif kind=='LOAD_ARG':code.append((0x20,0,0,16+8*args[0]))
        elif kind=='ARG_FD':code.extend([(0x15,0,4,args[0]),(0x20,0,0,16),
            (0x15,1,0,args[1]),(0x06,0,0,0x80000000),(0x06,0,0,0x7fff0000)])
        elif kind=='ARG_RANGE':code.extend([(0x15,0,5,args[0]),(0x20,0,0,16),
            (0x35,0,2,args[1]),(0x35,1,0,64),(0x06,0,0,0x7fff0000),(0x06,0,0,0x80000000)])
        table=table[end:]
    return code


def bpf_result(code,number,fd,arch=0xc000003e):
    words={0:number,4:arch,16:fd};pc=0;accumulator=0
    for _ in range(len(code)+1):
        op,yes,no,constant=code[pc]
        if op==0x20:accumulator=words[constant]
        elif op==0x15:pc+=yes if accumulator==constant else no
        elif op==0x35:pc+=yes if accumulator>=constant else no
        elif op==0x06:return constant
        else:raise AssertionError('Unexpected BPF operation')
        pc+=1
    raise AssertionError('BPF did not terminate')


class DiffNativeSourceTests(unittest.TestCase):
    def setUp(self):
        self.bootstrap=(NATIVE/'diff_bootstrap.c').read_text()
        self.evaluator=(NATIVE/'diff_evaluator.c').read_text()

    def test_bootstrap_opens_two_immutable_roots_and_execs_fixed_empty_environment(self):
        for fragment in ('n!=68||memcmp(release,"DGR1",4)', 'if(!strcmp(target[0],target[1]))fail()',
            'dup2(trees[0],4)!=4||dup2(trees[1],5)!=5','close_range(6,~0U,0)',
            '#define AG_EVALUATOR "/opt/uas/bin/diff-evaluator"',
            'char *arguments[]={AG_EVALUATOR,NULL};char *environment[]={NULL};',
            'filesystem.f_flag&ST_RDONLY','clearenv()||argc!=1','alarm(AG_WALL_SECONDS)'):
            self.assertIn(fragment,self.bootstrap)
        self.assertNotIn('getenv(',self.bootstrap);self.assertNotIn('recvmsg(',self.bootstrap)

    def test_landlock_and_seccomp_precede_every_target_or_request_observation(self):
        main=self.evaluator.split('int main(',1)[1]
        self.assertLess(main.index('setup();filter();'),main.index('packet(request,'))
        self.assertLess(main.index('setup();filter();'),main.index('inspect(side,'))
        for fragment in ('if(abi<3)fail()', 'for(int target=4;target<=5;target++)',
            'LANDLOCK_ACCESS_FS_REFER|LANDLOCK_ACCESS_FS_TRUNCATE',
            'RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV',
            'limit_valid(RLIMIT_NPROC,1)', 'filesystem.f_flag&ST_RDONLY'):
            self.assertIn(fragment,self.evaluator)

    def test_actual_source_filter_has_only_exact_diff_descriptor_authority(self):
        code=source_filter();allow=0x7fff0000;deny=0x80000000
        permitted={0:{3,*range(6,64)},1:{3},437:{4,5},5:set(range(4,64)),
                   217:set(range(6,64)),3:set(range(6,64))}
        for number in range(512):
            for fd in (0,1,2,3,4,5,6,63,64,0xffffffff):
                expected=allow if number in (60,231) or fd in permitted.get(number,()) else deny
                self.assertEqual(bpf_result(code,number,fd),expected,(number,fd))
        for number in permitted:
            self.assertEqual(bpf_result(code,number|0x40000000,3),deny)
            self.assertEqual(bpf_result(code,number,3,0x40000003),deny)

    def test_data_traversal_is_bounded_remeasured_and_symlink_safe(self):
        for fragment in ('handle=opened(side,path,O_PATH)', 'before.st_nlink==1',
            'expanded[side]+(size_t)before.st_size>AG_MAX_TARGET_BYTES',
            '++entries[side]>AG_MAX_ENTRIES', 'depth>AG_MAX_DEPTH',
            'changed>=AG_MAX_ITEMS', 'output_bytes>AG_MAX_OUTPUT_BYTES',
            'hash256(blob,length,fact->digest)', 'a->mode!=b->mode||a->size!=b->size',
            'unchanged(&original,&after)', 'unchanged(&roots[side],&current)',
            'memcmp(acknowledgment,"DGA1",4)'):
            self.assertIn(fragment,self.evaluator)
        self.assertNotRegex(self.evaluator,r'\b(fork|execve|system|popen|socket|connect)\s*\(')
        self.assertNotIn('"passed"',self.evaluator);self.assertNotIn('"verdict"',self.evaluator)

    def test_artifacts_sources_remain_single_target_specific(self):
        source=(NATIVE/'artifact_evaluator.c').read_text()
        self.assertNotIn('DGQ1',source);self.assertNotIn('diff',source.lower())
        self.assertIn('ARG_FD(SYS_read,AG_CHANNEL_FD)',source)
        bootstrap=(NATIVE/'artifact_bootstrap.c').read_text()
        self.assertIn('n!=36||memcmp(release,"AGR1",4)',bootstrap)
        self.assertNotIn('DGR1',bootstrap)


class DiffSmokeSourceTests(unittest.TestCase):
    def setUp(self):
        self.source=(ROOT/'tests/linux/diff_smoke.py').read_text()
        self.tree=ast.parse(self.source)

    def test_native_entry_requires_explicit_owned_hosted_run(self):
        for fragment in ("sys.argv[1:]==['--run']", "os.geteuid()==0", "os.environ.get('GITHUB_ACTIONS')=='true'",
                         "os.environ.get('RUNNER_OS')=='Linux'", "DEADLINE_SECONDS=30"):
            self.assertIn(fragment,self.source)
        self.assertIn("if __name__=='__main__':main()",self.source)
        # No top-level native function is invoked merely by test discovery.
        calls=[node.value for node in self.tree.body if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call)]
        self.assertEqual(calls,[])

    def test_mapping_and_real_pair_materialization_are_not_profile_monkeypatches(self):
        for fragment in ('HOST_SUPERVISOR=165533','HOST_HELPER=165530',
            "mapped_popen([","['0','100000','65536']",
            'DiffSourceResolver(ArtifactSourceResolver(supervisor,allocator))',
            'targets.prepare(scope,source)', 'lease.mark_launch_possible()',
            'origin=HeldOrigin(record)', 'offer.acknowledge_final(final);offer.confirm_exit()',
            "'remount,bind,ro,nodev,nosuid,noexec'", 'lease.postverify()==pair'):
            self.assertIn(fragment,self.source)
        self.assertNotIn('patch(',self.source)
        self.assertNotIn('HELPER_HOST_GID=',self.source)

    def test_decisive_case_evidence_is_emitted_before_assertion_and_summary_after_cleanup(self):
        for name in ('positive','wrong-root','mutated-after-exit','cleanup-identity-loss','symlink-before-launch','missing-ack'):
            self.assertIn("'"+name+"'",self.source)
        self.assertLess(self.source.index('reports.append(result);emit(result)'),self.source.index("expect(result['supervisor_exit']==0"))
        self.assertLess(self.source.index('shutil.rmtree(root)'),self.source.index('emit(summary)'))
        for reduction in ('omitted-claim','extra-claim','forbidden-path'):
            self.assertIn("'"+reduction+"'",self.source)
        self.assertIn('DiffGateHub._checks(variant,facts,None)',self.source)
        self.assertIn("'native_qualification':False",self.source)
        self.assertIn("'cleanup_claimed':False",self.source)
        self.assertLess(self.source.index("expect(complete and safe,'fixture cleanup unconfirmed')"),self.source.index("summary['fixture_cleanup']=True"))


class DiffStagingTests(unittest.TestCase):
    """Ordinary-file copies only; mocked root guard is NOT UID qualification."""
    def setUp(self):
        spec=importlib.util.spec_from_file_location('diff_staging_fixture',ROOT/'tests/linux/diff_smoke.py')
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        self.directory=tempfile.TemporaryDirectory(prefix='uas-stage-pure-')
        self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)
        self.source=self.root/'input';self.source.mkdir()
        (self.source/'pkg').mkdir();(self.source/'pkg/main.py').write_bytes(b'VALUE = 1\n')
        self.output=self.root/'output';self.output.mkdir()
        def writable():
            for directory,dirs,files in os.walk(self.output):
                Path(directory).chmod(0o755)
                for name in files:(Path(directory)/name).chmod(0o644)
        self.addCleanup(writable)
        root_patch=patch.object(self.module,'ROOT',self.source)
        root_patch.start();self.addCleanup(root_patch.stop)
        sources_patch=patch.object(self.module,'SOURCES',('pkg/main.py',))
        sources_patch.start();self.addCleanup(sources_patch.stop)
        # Ownership is supplied by the real root-only hosted caller. This test
        # only exercises bounded ordinary byte-copy/NOFOLLOW/mode semantics.
        owner_patch=patch.object(self.module.os,'geteuid',return_value=0)
        owner_patch.start();self.addCleanup(owner_patch.stop)

    def test_exact_readonly_staged_bytes_hashes_and_explicit_extra_paths(self):
        (self.source/'extra.py').write_bytes(b'EXTRA = 2\n')
        destination,hashes=self.module.stage_sources(self.output,extra_paths=('extra.py','pkg/main.py'))
        self.assertEqual(set(hashes),{'pkg/main.py','extra.py'})
        for relative,digest in hashes.items():
            self.assertEqual((destination/relative).read_bytes(),(self.source/relative).read_bytes())
            self.assertEqual(hashlib.sha256((destination/relative).read_bytes()).hexdigest(),digest)
            self.assertEqual(stat.S_IMODE((destination/relative).stat().st_mode),0o444)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode),0o555)
        self.assertEqual(stat.S_IMODE((destination/'pkg').stat().st_mode),0o555)
        self.assertEqual(stat.S_IMODE(self.source.stat().st_mode),0o755)
        with self.assertRaises(FileExistsError):self.module.stage_sources(self.output)

    def test_nonroot_staging_and_oversized_closure_are_refused_before_destination(self):
        with patch.object(self.module.os,'geteuid',return_value=1):
            with self.assertRaisesRegex(AssertionError,'root-owned'):self.module.stage_sources(self.output)
        self.assertFalse((self.output/'source').exists())
        with self.assertRaisesRegex(AssertionError,'file count'):
            self.module.stage_sources(self.output,extra_paths=tuple('file-'+str(i) for i in range(self.module.MAX_SOURCE_FILES)))
        self.assertFalse((self.output/'source').exists())

    def test_symlink_leaf_ancestor_and_source_root_are_rejected(self):
        original=self.source/'pkg/main.py';real=self.source/'real.py';original.rename(real)
        original.symlink_to(real)
        with self.assertRaises(OSError):self.module.stage_sources(self.output)
        original.unlink();real.rename(original)
        import shutil
        shutil.rmtree(self.output/'source')
        (self.source/'alias').symlink_to(self.source/'pkg',target_is_directory=True)
        with patch.object(self.module,'SOURCES',('alias/main.py',)):
            with self.assertRaises(OSError):self.module.stage_sources(self.output)
        shutil.rmtree(self.output/'source')
        alias=self.root/'source-alias';alias.symlink_to(self.source,target_is_directory=True)
        with patch.object(self.module,'ROOT',alias):
            with self.assertRaises(OSError):self.module.stage_sources(self.output)

    def test_hardlink_oversize_and_path_escape_never_copy_source(self):
        os.link(self.source/'pkg/main.py',self.source/'alias.py')
        with self.assertRaises(AssertionError):self.module.stage_sources(self.output)
        (self.source/'alias.py').unlink()
        import shutil
        shutil.rmtree(self.output/'source')
        with patch.object(self.module,'MAX_SOURCE_BYTES',2):
            with self.assertRaises(AssertionError):self.module.stage_sources(self.output)
        shutil.rmtree(self.output/'source')
        with patch.object(self.module,'SOURCES',('../outside.py',)):
            with self.assertRaises(AssertionError):self.module.stage_sources(self.output)
        self.assertFalse((self.output/'outside.py').exists())

    def test_changed_named_inode_is_rejected_before_copy(self):
        real_stat=self.module.os.stat
        def changed(path,*args,**kwargs):
            node=real_stat(path,*args,**kwargs)
            if path=='main.py' and 'dir_fd' in kwargs:
                return SimpleNamespace(**{name:getattr(node,name)+(1 if name=='st_ino' else 0) for name in
                    ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')})
            return node
        with patch.object(self.module.os,'stat',side_effect=changed):
            with self.assertRaisesRegex(AssertionError,'source changed'):self.module.stage_sources(self.output)
        self.assertFalse((self.output/'source/pkg/main.py').exists())

    def test_fixed_diff_sources_close_transitive_python_imports_without_discovery(self):
        text=(ROOT/'tests/linux/diff_smoke.py').read_text();tree=ast.parse(text)
        declared=next(ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign)
            and any(isinstance(name,ast.Name) and name.id=='SOURCES' for name in node.targets))
        paths=set(declared);self.assertIn('uas/__init__.py',paths)
        self.assertLessEqual(len(paths),self.module.MAX_SOURCE_FILES)
        for relative in sorted(path for path in paths if path.startswith('uas/') and path.endswith('.py')):
            module=relative[:-3].replace('/','.')
            for node in ast.walk(ast.parse((ROOT/relative).read_text())):
                names=[]
                if isinstance(node,ast.ImportFrom):
                    prefix=module.split('.')[:-node.level] if node.level else []
                    name='.'.join(prefix+([node.module] if node.module else [])) if node.level else node.module or ''
                    if name=='uas':names=['uas.'+alias.name for alias in node.names]
                    elif name.startswith('uas.'):names=[name]
                elif isinstance(node,ast.Import):names=[alias.name for alias in node.names if alias.name.startswith('uas.')]
                for name in names:self.assertIn(name.replace('.','/')+'.py',paths,(relative,name))
        self.assertIn("payload,source_hashes=stage_sources(root)",text)
        self.assertIn("script=payload/'tests/linux/diff_smoke.py'",text)
        self.assertEqual(text.count('str(script)'),2)
        self.assertEqual(text.count('cwd=payload'),2)
        self.assertNotIn('str(Path(__file__).resolve())',text)
        self.assertIn('build(root,source_root=payload)',text)
        self.assertIn("'source_sha256':source_hashes,'staged_sources_verified':True",text)


class DiffNativeBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler=shutil.which('gcc')
        if compiler is None:raise unittest.SkipTest('fixed diff source build needs gcc; native qualification remains pending')
        cls.directory=tempfile.TemporaryDirectory(prefix='uas-diff-build-')
        cls.addClassCleanup(cls.directory.cleanup);cls.images={}
        for name in ('diff_bootstrap','diff_evaluator'):
            output=Path(cls.directory.name)/name
            subprocess.run([compiler,'-std=c11','-Wall','-Wextra','-Werror','-O2',
                '-fstack-protector-strong','-static','-Wl,-z,noexecstack','-Wl,-z,relro',
                '-Wl,-z,now',str(NATIVE/(name+'.c')),'-o',str(output)],
                check=True,timeout=20,capture_output=True)
            cls.images[name]=output.read_bytes()

    def test_fixed_images_are_static_and_compiled_filter_matches_source(self):
        # Import contains no effects; these helpers parse ELF bytes only.
        from test_artifact_native_source import elf_data,elf_symbol
        for image in self.images.values():
            programs,_=elf_data(image)
            self.assertNotIn(3,[p[0] for p in programs]);self.assertNotIn(2,[p[0] for p in programs])
            self.assertFalse(any(p[1]&3==3 for p in programs))
        code=list(struct.iter_unpack('<HBBI',elf_symbol(self.images['diff_evaluator'],'dg_filter')))
        self.assertEqual(code,source_filter())
