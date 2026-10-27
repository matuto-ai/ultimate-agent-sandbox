"""Static source and hosted build checks; never execute the command payload.

Building is intentionally separate from native qualification. Source-only local
verification selects CommandNativeSourceTests explicitly; it does not discover
or run CommandNativeBuildTests.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'runtime' / 'workstation'


class CommandNativeSourceTests(unittest.TestCase):
    def setUp(self):
        self.source = (SOURCE / 'command_evaluator.c').read_text()

    def test_profile_is_distinct_and_has_no_shell_or_network_launcher(self):
        bootstrap = (SOURCE / 'command_bootstrap.c').read_text()
        self.assertIn('"/opt/uas/bin/command-evaluator"', bootstrap)
        self.assertNotIn('system(', self.source)
        self.assertNotIn('popen(', self.source)
        self.assertNotIn('execvp(', self.source)
        for syscall in ('socket', 'connect', 'sendmsg', 'recvmsg', 'ptrace', 'process_vm_writev', 'setuid', 'setgid'):
            self.assertNotIn('CG_ALLOW(SYS_' + syscall + ')', self.source)

    def test_group_identity_remains_pinned_until_one_signal_then_whole_tree_reap(self):
        observer = self.source[self.source.index('if(setpgid(guard,guard)'):]
        self.assertLess(observer.index('WNOWAIT'), observer.index('kill(-guard,SIGKILL)'))
        self.assertLess(observer.index('kill(-guard,SIGKILL)'), observer.index('waitpid(-1,&observed,WNOHANG)'))
        self.assertIn('if(!killed&&', observer)
        self.assertIn('if(errno==ECHILD) {reaped=1;break;}', observer)
        self.assertEqual(observer.count('kill(-guard,SIGKILL)'), 1)

    def test_independent_guard_lifetime_and_private_fd_closure_precede_project_exec(self):
        self.assertIn('PR_SET_PDEATHSIG,SIGUSR1', self.source)
        self.assertIn('sigaction(SIGALRM,&action,NULL)', self.source)
        self.assertIn('alarm(seconds+1)', self.source)
        self.assertIn('syscall(SYS_kill,0,SIGKILL)', self.source)
        child = self.source[self.source.index('if(child==0)'):]
        self.assertLess(child.index('close_range(3,4,0)'), child.index('SYS_execveat'))
        self.assertLess(child.index('child_filter()'), child.index('SYS_execveat'))

    def test_child_limits_cannot_be_raised_or_escape_group_and_runtime_execute_is_not_recursive(self):
        child = self.source[self.source.index('static void child_filter'):self.source.index('static void parent_filter')]
        for syscall in ('setsid', 'setpgid', 'kill', 'tkill', 'tgkill', 'prctl', 'setrlimit'):
            self.assertNotIn('CG_ALLOW(SYS_' + syscall + ')', child)
        self.assertNotIn('CG_ALLOW(SYS_prlimit64)', child)
        self.assertIn('CLONE_CHILD_CLEARTID', child)
        self.assertNotIn('|CLONE_PARENT|', child)
        self.assertIn('read_rule(ruleset,libraries,LANDLOCK_ACCESS_FS_READ_FILE|LANDLOCK_ACCESS_FS_READ_DIR)', self.source)
        self.assertIn('read_rule(ruleset,dependencies[i],LANDLOCK_ACCESS_FS_EXECUTE|LANDLOCK_ACCESS_FS_READ_FILE)', self.source)


class CommandNativeBuildTests(unittest.TestCase):
    def test_static_payloads_compile_without_execution(self):
        compiler = shutil.which('gcc')
        if compiler is None:
            self.skipTest('hosted source build requires gcc; this is not native qualification')
        with tempfile.TemporaryDirectory(prefix='uas-command-source-') as directory:
            for name in ('command_bootstrap', 'command_evaluator'):
                target = Path(directory) / name
                result = subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-O2', '-fstack-protector-strong', '-static', '-Wl,-z,noexecstack',
                    '-Wl,-z,relro', '-Wl,-z,now', str(SOURCE / (name + '.c')), '-o', str(target)],
                    capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', errors='replace')[-8192:])
                image = target.read_bytes()
                self.assertEqual(image[:6], b'\x7fELF\x02\x01')
                # The test only reads compiled bytes: no target invocation.


if __name__ == '__main__':
    unittest.main()
