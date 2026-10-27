"""Fixed diff native source/ELF checks; no helper execution or kernel admission.

Build checks run only where the test runner permits a compiler. Pure source
cases can be selected under pre-import process/socket/kernel deny guards.
"""
from pathlib import Path
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
