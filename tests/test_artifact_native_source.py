"""Build and inspect data only: NEVER execute either helper or install a filter.

No native opt-in, listener, namespace, UID change, Landlock or seccomp operation
is used here. These source tests do not qualify the installed Workstation.
"""
import ast
import pathlib
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'runtime' / 'workstation'


def elf_data(blob):
    if blob[:6] != b'\x7fELF\x02\x01':
        raise AssertionError('little-endian ELF64 required')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', blob)
    if header[2] != 62:
        raise AssertionError('x86-64 required')
    programs = [struct.unpack_from('<IIQQQQQQ', blob, header[5]+i*header[9])
                for i in range(header[10])]
    sections = [struct.unpack_from('<IIQQQQIIQQ', blob, header[6]+i*header[11])
                for i in range(header[12])]
    return programs, sections


def elf_symbol(blob, name):
    _, sections = elf_data(blob)
    for table in sections:
        if table[1] != 2:  # SHT_SYMTAB
            continue
        strings = sections[table[6]]
        text = blob[strings[4]:strings[4]+strings[5]]
        for offset in range(table[4], table[4]+table[5], table[9]):
            item = struct.unpack_from('<IBBHQQ', blob, offset)
            if text[item[0]:].split(b'\0', 1)[0] == name.encode():
                section = sections[item[3]]
                start = section[4] + item[4] - section[3]
                return blob[start:start+item[5]]
    raise AssertionError('compiled policy symbol absent')


def bpf_result(code, syscall, fd=0, arch=0xc000003e):
    # Pure interpreter for the exact classic BPF instructions used in ag_filter.
    data = struct.pack('<iIQQQQQQQ', syscall, arch, 0, fd, 0, 0, 0, 0, 0)
    accumulator = 0
    pc = 0
    for _ in range(len(code)+1):
        op, yes, no, constant = code[pc]
        if op == 0x20:  # LD W ABS
            accumulator, = struct.unpack_from('<I', data, constant)
        elif op == 0x15:  # JMP JEQ K
            pc += yes if accumulator == constant else no
        elif op == 0x35:  # JMP JGE K
            pc += yes if accumulator >= constant else no
        elif op == 0x06:  # RET K
            return constant
        else:
            raise AssertionError('unexpected policy instruction')
        pc += 1
    raise AssertionError('nonterminating policy')


class ArtifactNativeBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('gcc')
        if compiler is None:
            raise unittest.SkipTest('source build requires gcc; native proof remains mandatory')
        cls.directory = tempfile.TemporaryDirectory(prefix='uas-artifact-source-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.images = {}
        for name in ('artifact_bootstrap', 'artifact_evaluator'):
            target = pathlib.Path(cls.directory.name) / name
            # Compilation only. Do not add an invocation of target here.
            subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-O2', '-fstack-protector-strong', '-static', '-Wl,-z,noexecstack',
                '-Wl,-z,relro', '-Wl,-z,now', str(SOURCE / (name+'.c')),
                '-o', str(target)], check=True, timeout=20, capture_output=True)
            cls.images[name] = target.read_bytes()

    def test_both_images_are_static_without_interpreter_or_writable_executable_segment(self):
        for image in self.images.values():
            programs, _ = elf_data(image)
            self.assertNotIn(3, [entry[0] for entry in programs])  # PT_INTERP
            self.assertNotIn(2, [entry[0] for entry in programs])  # PT_DYNAMIC
            self.assertFalse(any(entry[1] & 3 == 3 for entry in programs))

    def test_actual_compiled_bpf_allows_only_exact_fixed_fd_operations(self):
        raw = elf_symbol(self.images['artifact_evaluator'], 'ag_filter')
        self.assertEqual(len(raw) % 8, 0)
        code = list(struct.iter_unpack('<HBBI', raw))
        allow, deny = 0x7fff0000, 0x80000000
        permitted = {0: {3}, 1: {3}, 437: {4}, 5: set(range(4, 64)),
                     217: set(range(5, 64)), 3: set(range(5, 64))}
        for syscall in range(512):
            for fd in (0, 1, 2, 3, 4, 5, 63, 64, 0xffffffff):
                expected = allow if syscall in (60, 231) or fd in permitted.get(syscall, ()) else deny
                self.assertEqual(bpf_result(code, syscall, fd), expected, (syscall, fd))
        for syscall in permitted:
            self.assertEqual(bpf_result(code, syscall | 0x40000000, 3), deny)  # x32
            self.assertEqual(bpf_result(code, syscall, 3, 0x40000003), deny)  # i386
            self.assertEqual(bpf_result(code, syscall, 3, 0), deny)

    def test_native_payload_is_never_executed_by_this_suite(self):
        # The only subprocess command used by setUpClass is the compiler.
        source = pathlib.Path(__file__).read_text()
        calls = [node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                 and node.func.value.id == 'subprocess']
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].func.attr, 'run')
        self.assertIsInstance(calls[0].args[0], ast.List)
        self.assertEqual(calls[0].args[0].elts[0].id, 'compiler')


class ArtifactNativeSourceTests(unittest.TestCase):
    def setUp(self):
        self.bootstrap = (SOURCE/'artifact_bootstrap.c').read_text()
        self.evaluator = (SOURCE/'artifact_evaluator.c').read_text()
        self.header = (SOURCE/'artifact_protocol.h').read_text()

    def test_bootstrap_uses_fixed_empty_environment_and_fixed_private_paths(self):
        self.assertIn('clearenv()||argc!=1', self.bootstrap)
        self.assertIn('char *arguments[]={AG_EVALUATOR,NULL};char *environment[]={NULL};', self.bootstrap)
        self.assertIn('execve(AG_EVALUATOR,arguments,environment)', self.bootstrap)
        self.assertIn('#define AG_ENDPOINT "/uas/gate/gate.sock"', self.header)
        self.assertIn('#define AG_TARGETS "uas/gate-targets"', self.header)
        self.assertIn('open_beneath(parent,"tree"', self.bootstrap)
        self.assertNotIn('getenv(', self.bootstrap)
        self.assertNotIn('recvmsg(', self.bootstrap)
        self.assertNotIn('system(', self.bootstrap)
        self.assertNotIn('execvp(', self.bootstrap)

    def test_timer_is_armed_once_before_rendezvous_preserved_across_exec_not_rearmed(self):
        self.assertEqual(re.findall(r'\balarm\(([^)]*)\)', self.bootstrap), ['2', 'AG_WALL_SECONDS'])
        self.assertLess(self.bootstrap.index('alarm(AG_WALL_SECONDS)'), self.bootstrap.index('socket(AF_UNIX'))
        self.assertIn('sigaction(SIGALRM,&action,NULL)', self.bootstrap)
        self.assertIn('getitimer(ITIMER_REAL,&timer)', self.evaluator)
        self.assertNotRegex(self.evaluator, r'\balarm\(\d')
        self.assertNotIn('timer_create(', self.evaluator)
        self.assertNotIn('SYS_rt_sig', self.evaluator)

    def test_confinement_precedes_request_and_uses_mandatory_failclosed_controls(self):
        main = self.evaluator[self.evaluator.index('int main('):]
        self.assertLess(main.index('setup();filter();'), main.index('packet(header,'))
        for right in ('EXECUTE', 'WRITE_FILE', 'READ_FILE', 'READ_DIR', 'REMOVE_DIR',
                      'REMOVE_FILE', 'MAKE_CHAR', 'MAKE_DIR', 'MAKE_REG', 'MAKE_SOCK',
                      'MAKE_FIFO', 'MAKE_BLOCK', 'MAKE_SYM', 'REFER', 'TRUNCATE'):
            self.assertIn('LANDLOCK_ACCESS_FS_'+right, self.evaluator)
        self.assertIn('if(abi<3)fail()', self.evaluator)
        self.assertIn('RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV', self.evaluator)
        self.assertIn('fstatvfs(AG_TARGET_FD,&filesystem)', self.evaluator)
        self.assertIn('filesystem.f_flag&ST_RDONLY', self.evaluator)
        self.assertIn('.flags=O_PATH|O_CLOEXEC|O_NOFOLLOW', self.evaluator)
        self.assertIn('directory_how.flags=O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW', self.evaluator)

    def test_wire_is_bounded_raw_facts_not_verdicts_or_file_contents(self):
        for magic in ('AGQ1', 'AGP1', 'AGS1', 'AGI1', 'AGF1', 'AGA1'):
            self.assertIn('"'+magic+'"', self.evaluator)
        for constant, value in [('AG_HEADER_BYTES', '104U'), ('AG_ITEM_BYTES', '60U'),
                                ('AG_MAX_ITEMS', '128U'), ('AG_MAX_PATH_BYTES', '4095U'),
                                ('AG_MAX_PATH_SCALARS', '1024U')]:
            self.assertIn('#define '+constant+' '+value, self.header)
        self.assertIn('path_digest(input+12', self.evaluator)
        self.assertIn('memcmp(acknowledgment+4,header+4,32)', self.evaluator)
        self.assertNotIn('SYS_read,fd', self.evaluator)
        self.assertNotIn('printf(', self.evaluator)
        self.assertIn('cp>=0x7f&&cp<0xa0', self.evaluator)
        self.assertIn('git_component(p+start,component)', self.evaluator)


if __name__ == '__main__':
    unittest.main()
