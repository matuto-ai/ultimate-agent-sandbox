"""Fully mocked listener setup; no socketpair/listen/fork/SELinux/native calls."""
from contextlib import ExitStack
import array
import errno
import importlib.util
import json
from pathlib import Path
import socket
import stat
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

VM=Path(__file__).parent/'vm'
sys.path.insert(0,str(VM))
try:
    SPEC=importlib.util.spec_from_file_location('artifact_listener_guest',VM/'guest_artifacts.py')
    guest=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(guest)
finally:sys.path.remove(str(VM))

CHILD=9876
PATH=Path('/run/uas-artifacts-1234567890abcdef1234567890abcdef/alpha-gate/gate.sock')


def record(*fds,credentials=(CHILD,165533,165533),flags=socket.MSG_CMSG_CLOEXEC,raw=b'LISTENER'):
    ancillary=[]
    if credentials is not None:ancillary.append((socket.SOL_SOCKET,socket.SCM_CREDENTIALS,struct.pack('3i',*credentials)))
    if fds:ancillary.append((socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds).tobytes()))
    return raw,ancillary,flags,None


def listener():
    result=Mock();result.family=socket.AF_UNIX
    result.getsockopt.side_effect=lambda level,kind: {socket.SO_TYPE:socket.SOCK_SEQPACKET,socket.SO_ACCEPTCONN:1}[kind]
    result.getsockname.return_value=str(PATH)
    return result


class ReceiveSetupTests(unittest.TestCase):
    def invoke(self,message,*,inheritable=False,result=None):
        channel=Mock();channel.recvmsg.return_value=message;diagnostic={}
        result=result or listener()
        stack=ExitStack();self.addCleanup(stack.close)
        factory=stack.enter_context(patch.object(guest.socket,'socket',return_value=result))
        stack.enter_context(patch.object(guest.os,'get_inheritable',return_value=inheritable))
        close=stack.enter_context(patch.object(guest.os,'close'))
        return lambda:guest.receive_setup_listener(channel,CHILD,diagnostic),result,close,diagnostic,factory,channel
    def test_echoed_cloexec_and_zero_flags_accept_only_one_noninheritable_listener(self):
        for flags in (socket.MSG_CMSG_CLOEXEC,0):
            call,result,close,diagnostic,_,channel=self.invoke(record(41,flags=flags))
            self.assertIs(call(),result);close.assert_not_called();result.close.assert_not_called()
            self.assertEqual(diagnostic['transfer']['flags'],flags)
            self.assertEqual(diagnostic['transfer']['raw_bytes'],8)
            self.assertEqual(channel.recvmsg.call_args.args[2],socket.MSG_CMSG_CLOEXEC)
    def test_truncation_unknown_flags_bad_payload_or_wrong_credentials_close_all_fds(self):
        cases=[record(41,flags=socket.MSG_CTRUNC|socket.MSG_CMSG_CLOEXEC),record(41,flags=socket.MSG_TRUNC),
            record(41,flags=socket.MSG_OOB),record(41,raw=b'bad'),record(41,credentials=(CHILD,0,0)),
            record(41,credentials=(CHILD+1,165533,165533)),record(41,credentials=None),record(41,42)]
        for message in cases:
            with self.subTest(message=message[:1]):
                call,_,close,_,factory,_=self.invoke(message)
                with self.assertRaises(AssertionError):call()
                self.assertIn(unittest.mock.call(41),close.call_args_list)
                if message==cases[-1]:self.assertIn(unittest.mock.call(42),close.call_args_list)
                factory.assert_not_called()
    def test_malformed_rights_tail_is_rejected_after_complete_fds_are_owned(self):
        raw,ancillary,flags,address=record(41)
        ancillary[-1]=(socket.SOL_SOCKET,socket.SCM_RIGHTS,ancillary[-1][2]+b'x')
        call,_,close,_,_,_=self.invoke((raw,ancillary,flags,address))
        with self.assertRaises(AssertionError):call()
        close.assert_called_once_with(41)
    def test_unexpected_pidfd_is_closed_not_treated_as_credentials_or_listener(self):
        raw,ancillary,flags,address=record(41)
        ancillary.append((socket.SOL_SOCKET,getattr(socket,'SCM_PIDFD',4),array.array('i',[42]).tobytes()))
        call,_,close,_,_,_=self.invoke((raw,ancillary,flags,address))
        with self.assertRaises(AssertionError):call()
        self.assertCountEqual(close.call_args_list,[unittest.mock.call(41),unittest.mock.call(42)])
    def test_duplicate_or_malformed_credentials_are_rejected_with_fd_cleanup(self):
        for extra in ((socket.SOL_SOCKET,socket.SCM_CREDENTIALS,b'x'),
                      (socket.SOL_SOCKET,socket.SCM_CREDENTIALS,struct.pack('3i',CHILD,165533,165533))):
            raw,ancillary,flags,address=record(41);ancillary.append(extra)
            call,_,close,_,_,_=self.invoke((raw,ancillary,flags,address))
            with self.assertRaises(AssertionError):call()
            close.assert_called_once_with(41)
    def test_inheritable_or_nonlistening_or_wrong_family_never_qualifies(self):
        call,_,close,_,_,_=self.invoke(record(41),inheritable=True)
        with self.assertRaises(AssertionError):call()
        close.assert_called_once_with(41)
        for family,kind,accept in ((socket.AF_INET,socket.SOCK_SEQPACKET,1),
                                   (socket.AF_UNIX,socket.SOCK_STREAM,1),(socket.AF_UNIX,socket.SOCK_SEQPACKET,0)):
            result=listener();result.family=family
            result.getsockopt.side_effect=lambda level,option:{socket.SO_TYPE:kind,socket.SO_ACCEPTCONN:accept}[option]
            call,_,close,_,_,_=self.invoke(record(41),result=result)
            with self.assertRaises(AssertionError):call()
            result.close.assert_called_once();close.assert_not_called()
    def test_socket_constructor_failure_closes_still_owned_fd(self):
        call,_,close,_,factory,_=self.invoke(record(41));factory.side_effect=OSError(errno.ENOTSOCK,'fixed failure')
        with self.assertRaises(OSError):call()
        close.assert_called_once_with(41)
    def test_installed_close_failure_records_uncertainty_and_attempts_every_descriptor(self):
        call,_,close,diagnostic,_,_=self.invoke(record(41,42))
        close.side_effect=[OSError(errno.EIO,'fixed failure'),None]
        with self.assertRaises(AssertionError):call()
        self.assertEqual(close.call_count,2)
        self.assertEqual(diagnostic['cleanup_errors'],[{'phase':'installed-descriptor-close',
            'count':1,'errnos':[errno.EIO],'errno_types_truncated':False}])
    def test_interrupted_installed_close_still_attempts_all_fds_and_preserves_rejection(self):
        for failure in (KeyboardInterrupt(),SystemExit(123)):
            call,_,close,diagnostic,_,_=self.invoke(record(41,42))
            close.side_effect=[failure,None]
            with self.subTest(failure=type(failure).__name__),self.assertRaisesRegex(AssertionError,'one exact Supervisor'):
                call()
            self.assertEqual(close.call_count,2)
            self.assertCountEqual(close.call_args_list,[unittest.mock.call(41),unittest.mock.call(42)])
            self.assertEqual(diagnostic['cleanup_errors'],[{'phase':'installed-descriptor-close',
                'count':1,'errnos':[None],'errno_types_truncated':False}])
    def test_wrapped_socket_close_failure_preserved_without_replacing_original_rejection(self):
        result=listener();result.family=socket.AF_INET;result.close.side_effect=OSError(errno.EIO,'close failure')
        call,_,close,diagnostic,_,_=self.invoke(record(41),result=result)
        with self.assertRaisesRegex(AssertionError,'expected listening'):call()
        close.assert_not_called()
        self.assertEqual(diagnostic['cleanup_errors'],[{'phase':'received-listener-close','errno':errno.EIO}])
    def test_maximum_rights_close_failures_remain_one_bounded_typed_record(self):
        call,_,close,diagnostic,_,_=self.invoke(record(*range(1000,1253)))
        close.side_effect=[OSError(number,'ignored raw failure text') for number in range(1,254)]
        with self.assertRaises(AssertionError):call()
        self.assertEqual(close.call_count,253)
        self.assertEqual(diagnostic['cleanup_errors'],[{'phase':'installed-descriptor-close','count':253,
            'errnos':list(range(1,9)),'errno_types_truncated':True}])
        text=str(guest.ListenerSetupFailure(diagnostic))
        self.assertLess(len(text.encode()),8192);self.assertNotIn('1000',text)
        self.assertNotIn('raw failure text',text)
    def test_child_failure_diagnostics_fixed_phase_errno_and_no_fd_acceptance(self):
        packet=guest.SETUP_FAILURE.pack(b'LSF1',guest.SETUP_CHILD_PHASES.index('drop-uid')+1,errno.EPERM)
        call,_,close,diagnostic,factory,_=self.invoke(record(credentials=(CHILD,0,165533),raw=packet))
        with self.assertRaisesRegex(RuntimeError,'child reported'):call()
        self.assertEqual(diagnostic['child_failure'],{'phase':'drop-uid','errno':errno.EPERM})
        factory.assert_not_called();close.assert_not_called()
        call,_,close,_,_,_=self.invoke(record(41,raw=packet))
        with self.assertRaises(AssertionError):call()
        close.assert_called_once_with(41)


class ExactChildWaitTests(unittest.TestCase):
    def test_wait_is_nonblocking_exact_child_and_reports_terminal_outcome(self):
        with patch.object(guest.os,'waitpid',return_value=(CHILD,125<<8)) as wait:
            self.assertEqual(guest.setup_child_outcome(CHILD,99),{'outcome':'exit','exit_code':125})
        wait.assert_called_once_with(CHILD,guest.os.WNOHANG)
    def test_wait_timeout_or_eintr_storm_is_bounded_not_guessed_success(self):
        for outcome in ((0,0),InterruptedError()):
            with patch.object(guest.os,'waitpid',side_effect=outcome if isinstance(outcome,Exception) else None,
                              return_value=outcome if not isinstance(outcome,Exception) else None), \
                    patch.object(guest.time,'monotonic',return_value=10):
                self.assertEqual(guest.setup_child_outcome(CHILD,9),{'outcome':'unconfirmed'})
    def test_no_child_is_not_adopted_or_signaled_by_wait_helper(self):
        with patch.object(guest.os,'waitpid',side_effect=ChildProcessError(errno.ECHILD,'unknown')):
            self.assertEqual(guest.setup_child_outcome(CHILD,99),{'outcome':'wait-error','errno':errno.ECHILD})


class ListenerLifecycleTests(unittest.TestCase):
    def fixture(self):
        stack=ExitStack();self.addCleanup(stack.close)
        left=Mock();right=Mock();left.getsockopt.return_value=1
        result=listener();library=Mock();library.setsockcreatecon.side_effect=[0,0]
        stack.enter_context(patch.object(guest.ctypes,'CDLL',return_value=library))
        stack.enter_context(patch.object(guest.ctypes,'get_errno',return_value=errno.EPERM))
        stack.enter_context(patch.object(guest.os,'geteuid',return_value=0))
        getsignal=stack.enter_context(patch.object(guest.signal,'getsignal',return_value=guest.signal.SIG_DFL))
        setsignal=stack.enter_context(patch.object(guest.signal,'signal',return_value=guest.signal.SIG_DFL))
        stack.enter_context(patch.object(guest.socket,'socketpair',return_value=(left,right)))
        fork=stack.enter_context(patch.object(guest.os,'fork',return_value=CHILD))
        kill=stack.enter_context(patch.object(guest.os,'kill'))
        stack.enter_context(patch.object(guest.Path,'lstat',return_value=SimpleNamespace(
            st_mode=stat.S_IFSOCK|0o620,st_uid=165533,st_gid=165530)))
        receive=stack.enter_context(patch.object(guest,'receive_setup_listener',return_value=result))
        outcome=stack.enter_context(patch.object(guest,'setup_child_outcome',return_value={'outcome':'exit','exit_code':0}))
        run=stack.enter_context(patch.object(guest,'run'))
        stack.enter_context(patch.object(guest.time,'monotonic',return_value=10))
        return SimpleNamespace(left=left,right=right,result=result,library=library,fork=fork,
                               kill=kill,receive=receive,outcome=outcome,run=run,
                               getsignal=getsignal,setsignal=setsignal)
    def test_ignored_custom_or_unknown_sigchld_refused_before_reset_socket_or_fork(self):
        for handler in (guest.signal.SIG_IGN,lambda *_:None,None):
            f=self.fixture();f.getsignal.return_value=handler
            with self.subTest(handler=handler),self.assertRaises(guest.ListenerSetupFailure) as failure:
                guest.labeled_listener(PATH,165530,guest.LEVELS['alpha'])
            self.assertEqual(failure.exception.document['phase'],'child-reaping-policy')
            f.setsignal.assert_not_called();f.fork.assert_not_called()
            f.library.setsockcreatecon.assert_not_called()
    def test_sigchld_reset_error_or_disposition_change_prevents_fork(self):
        for value in (OSError(errno.EPERM,'reset denied'),guest.signal.SIG_IGN):
            f=self.fixture()
            if isinstance(value,Exception):f.setsignal.side_effect=value
            else:f.setsignal.return_value=value
            with self.subTest(value=value),self.assertRaises(guest.ListenerSetupFailure):
                guest.labeled_listener(PATH,165530,guest.LEVELS['alpha'])
            f.fork.assert_not_called();f.library.setsockcreatecon.assert_not_called()
    def test_fixed_linux_cpython_required_without_reaping_fallback(self):
        f=self.fixture()
        with patch.object(guest.sys,'platform','unsupported'),self.assertRaises(guest.ListenerSetupFailure):
            guest.labeled_listener(PATH,165530,guest.LEVELS['alpha'])
        f.getsignal.assert_not_called();f.setsignal.assert_not_called();f.fork.assert_not_called()
    def test_missing_sigchld_support_fails_before_fork_without_fallback(self):
        f=self.fixture()
        with patch.object(guest,'signal',SimpleNamespace(SIG_DFL=0)),self.assertRaises(guest.ListenerSetupFailure):
            guest.labeled_listener(PATH,165530,guest.LEVELS['alpha'])
        f.fork.assert_not_called();f.library.setsockcreatecon.assert_not_called()
    def test_success_is_one_exact_listener_after_child_exit_and_label_reset(self):
        f=self.fixture()
        self.assertIs(guest.labeled_listener(PATH,165530,guest.LEVELS['alpha']),f.result)
        f.left.setsockopt.assert_called_once_with(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        f.fork.assert_called_once();f.result.close.assert_not_called();f.kill.assert_not_called()
        f.getsignal.assert_called_once_with(guest.signal.SIGCHLD)
        f.setsignal.assert_called_once_with(guest.signal.SIGCHLD,guest.signal.SIG_DFL)
        f.left.close.assert_called_once();f.right.close.assert_called_once()
        self.assertEqual(f.library.setsockcreatecon.call_args_list[-1].args,(None,))
        f.run.assert_called_once_with('chcon','-t','container_file_t','-l',guest.LEVELS['alpha'],str(PATH),timeout=5)
    def test_reset_failure_closes_listener_channels_and_preserves_error(self):
        f=self.fixture();f.library.setsockcreatecon.side_effect=[0,-1]
        with self.assertRaises(guest.ListenerSetupFailure) as failure:
            guest.labeled_listener(PATH,165530,guest.LEVELS['alpha'])
        f.result.close.assert_called_once();f.left.close.assert_called_once();f.right.close.assert_called_once()
        self.assertIn({'phase':'socket-label-reset','errno':errno.EPERM},failure.exception.document['cleanup_errors'])
    def test_chcon_failure_closes_owned_listener_and_still_resets(self):
        f=self.fixture();f.run.side_effect=OSError(errno.EACCES,'denied')
        with self.assertRaises(guest.ListenerSetupFailure) as failure:
            guest.labeled_listener(PATH,165530,guest.LEVELS['alpha'])
        f.result.close.assert_called_once();self.assertEqual(failure.exception.document['phase'],'path-label')
        self.assertEqual(f.library.setsockcreatecon.call_args_list[-1].args,(None,))
    def test_socket_name_or_path_ownership_mismatch_is_not_accepted(self):
        f=self.fixture();f.result.getsockname.return_value='/wrong'
        with self.assertRaises(guest.ListenerSetupFailure):guest.labeled_listener(PATH,165530,guest.LEVELS['alpha'])
        f.result.close.assert_called_once();f.run.assert_not_called()
    def test_receive_failure_still_reaps_exact_child_and_resets_and_closes(self):
        f=self.fixture();f.receive.side_effect=TimeoutError('timed out')
        with self.assertRaises(guest.ListenerSetupFailure) as failure:
            guest.labeled_listener(PATH,165530,guest.LEVELS['alpha'])
        f.outcome.assert_called_once_with(CHILD,22);f.kill.assert_not_called()
        f.left.close.assert_called_once();f.right.close.assert_called_once()
        self.assertEqual(failure.exception.document['child'],{'outcome':'exit','exit_code':0})
        self.assertEqual(failure.exception.document['phase'],'receive')
    def test_unknown_child_wait_never_signals_an_unowned_pid(self):
        f=self.fixture();f.receive.side_effect=RuntimeError('bad packet')
        f.outcome.return_value={'outcome':'wait-error','errno':errno.ECHILD}
        with self.assertRaises(guest.ListenerSetupFailure) as failure:
            guest.labeled_listener(PATH,165530,guest.LEVELS['alpha'])
        f.kill.assert_not_called();self.assertIn({'phase':'child-exit-unconfirmed'},failure.exception.document['cleanup_errors'])
    def test_still_unreaped_actual_child_timeout_kills_only_it_and_bounds_reap(self):
        f=self.fixture();f.outcome.side_effect=[{'outcome':'unconfirmed'},{'outcome':'unconfirmed'},
                                               {'outcome':'signal','signal':9}]
        with self.assertRaises(guest.ListenerSetupFailure) as failure:
            guest.labeled_listener(PATH,165530,guest.LEVELS['alpha'])
        f.kill.assert_called_once_with(CHILD,guest.signal.SIGKILL)
        self.assertEqual(f.outcome.call_args_list[-1].args,(CHILD,11))
        self.assertEqual(failure.exception.document['child'],{'outcome':'signal','signal':9})
        f.result.close.assert_called_once()
    def test_channel_close_failure_does_not_skip_listener_close_or_child_cleanup(self):
        f=self.fixture();f.left.close.side_effect=OSError(errno.EIO,'close failed')
        with self.assertRaises(guest.ListenerSetupFailure) as failure:
            guest.labeled_listener(PATH,165530,guest.LEVELS['alpha'])
        f.result.close.assert_called_once()
        self.assertIn({'phase':'setup-channel-close','errno':errno.EIO},failure.exception.document['cleanup_errors'])
    def test_fork_failure_closes_both_channels_without_pid_guessing(self):
        f=self.fixture();f.fork.side_effect=OSError(errno.EAGAIN,'fork denied')
        with self.assertRaises(guest.ListenerSetupFailure):guest.labeled_listener(PATH,165530,guest.LEVELS['alpha'])
        f.left.close.assert_called_once();f.right.close.assert_called_once();f.kill.assert_not_called()
        f.outcome.assert_not_called()
    def test_failed_initial_label_setup_still_resets_without_socket_or_child(self):
        f=self.fixture();f.library.setsockcreatecon.side_effect=[-1,0]
        with self.assertRaises(guest.ListenerSetupFailure):guest.labeled_listener(PATH,165530,guest.LEVELS['alpha'])
        f.fork.assert_not_called();f.outcome.assert_not_called()
        self.assertEqual(f.library.setsockcreatecon.call_args_list[-1].args,(None,))


class ScenarioListenerOwnershipTests(unittest.TestCase):
    def scenario_failure(self,cleanup_errors,*,first_close_error=None):
        """Run actual scenario control flow; every external/native effect mocked."""
        original=guest.ListenerSetupFailure({'version':1,'phase':'receive',
            'cleanup_errors':cleanup_errors,'child':{'outcome':'unconfirmed' if cleanup_errors else 'exit'}})
        unchanged=json.loads(json.dumps(original.document));checks={}
        first=Mock();first.close.side_effect=first_close_error
        rootfs=MagicMock();rootfs.name='fixture-rootfs';rootfs.exists.return_value=False
        rootfs.is_symlink.return_value=False;rootfs.iterdir.return_value=[]
        rootfs.with_name.return_value.exists.return_value=False
        archive=MagicMock();archive.exists.return_value=False;archive.is_symlink.return_value=False
        rooms={room:{'gate':'/unused/'+room+'-gate','control':'/unused/'+room+'-control',
            'level':guest.LEVELS[room],'scratch':'/unused/'+room+'-scratch'} for room in ('alpha','beta')}
        def quota(room):return {'room':room},{'observed':True}
        def capture(phase,*args,**kwargs):
            room=phase.removeprefix('quota-')
            return SimpleNamespace(returncode=0,stdout=json.dumps({'quota_facts':{'room':room},
                'project_hard_quota_enforced':True,'observed_errno':errno.ENOSPC}).encode(),stderr=b'')
        with ExitStack() as stack:
            stack.enter_context(patch.object(sys,'path',[str(VM),*sys.path]))
            import native_rootfs,guest_workstation,artifact_diagnostics
            stack.enter_context(patch.object(native_rootfs,'build_rootfs',return_value={'rootfs_manifest_sha256':'a'*64}))
            stack.enter_context(patch.object(guest_workstation,'import_image',return_value='sha256:'+'b'*64))
            stack.enter_context(patch.object(guest_workstation,'engine_profile',return_value={}))
            stack.enter_context(patch.object(guest.boundary,'start_engine'))
            stack.enter_context(patch.object(guest,'run'))
            stack.enter_context(patch.object(guest,'ROOTFS',rootfs))
            stack.enter_context(patch.object(guest,'ARCHIVE',archive))
            stack.enter_context(patch.object(guest.Path,'read_bytes',return_value=b'fixed-fixture-hash-input'))
            stack.enter_context(patch.object(guest.tarfile,'open'))
            stack.enter_context(patch.object(guest,'storage',return_value=rooms))
            stack.enter_context(patch.object(guest,'quota_facts',side_effect=quota))
            stack.enter_context(patch.object(artifact_diagnostics,'captured',side_effect=capture))
            setup=stack.enter_context(patch.object(guest,'labeled_listener',side_effect=[first,original]))
            create=stack.enter_context(patch.object(guest,'create',side_effect=AssertionError('no container effects')))
            stack.enter_context(patch.object(guest.subprocess,'Popen',side_effect=AssertionError('no process effects')))
            emit=stack.enter_context(patch.object(guest,'emit'))
            stack.enter_context(patch('builtins.print'))
            with self.assertRaises(guest.ListenerSetupFailure) as caught:
                guest.scenario('f'*32,{'native_runtime':{'helper_sha256':{}}},checks)
            self.assertIs(caught.exception,original)
            self.assertEqual(original.document,unchanged)
            self.assertEqual(setup.call_count,2);create.assert_not_called()
            self.assertEqual(emit.call_args.args,('guest_cleanup',checks['guest_cleanup']))
        first.close.assert_called_once_with()
        return checks['guest_cleanup']
    def test_second_listener_clean_failure_closes_first_and_preserves_original_failure(self):
        cleanup=self.scenario_failure([])
        self.assertEqual(cleanup['status'],'passed');self.assertEqual(cleanup['errors'],[])
    def test_setup_uncertainty_remains_failed_guest_cleanup_even_if_teardown_succeeds(self):
        details=[{'phase':'child-exit-unconfirmed'}, {'phase':'socket-label-reset','errno':errno.EPERM},
                 {'phase':'listener-close','errno':errno.EIO}]
        for detail in details:
            with self.subTest(detail=detail):
                cleanup=self.scenario_failure([detail])
                self.assertEqual(cleanup['status'],'failed')
                self.assertEqual(cleanup['errors'],[{'resource':'listener-setup',
                    'error':'ListenerSetupFailure','detail':detail}])
    def test_first_listener_close_failure_also_fails_cleanup_without_replacing_setup_exception(self):
        cleanup=self.scenario_failure([],first_close_error=OSError(errno.EIO,'fixed close failure'))
        self.assertEqual(cleanup['status'],'failed')
        self.assertEqual(cleanup['errors'],[{'resource':'listener','error':'OSError'}])


class ListenerSourceTests(unittest.TestCase):
    def test_credentials_enabled_before_fork_and_uid_dropped_before_socket_listen(self):
        source=(VM/'guest_artifacts.py').read_text()
        function=source[source.index('def labeled_listener('):source.index('def storage(')]
        self.assertLess(function.index('require_setup_reaping()'),function.index('ctypes.CDLL('))
        self.assertLess(function.index('require_setup_reaping()'),function.index('socket.socketpair('))
        self.assertLess(function.index('socket.SO_PASSCRED,1'),function.index('child=os.fork()'))
        child=source[source.index('def setup_listener_child('):source.index('def labeled_listener(')]
        self.assertIn('if child==0:setup_listener_child(left,right,path,group)',function)
        self.assertLess(child.index('os.setuid(165533)'),child.index('with socket.socket('))
        self.assertLess(child.index('os.setuid(165533)'),child.index('listener.listen(4)'))
        self.assertIn('os.waitpid(child,os.WNOHANG)',source)
        self.assertNotIn('os.waitpid(child,0)',function)
    def test_quota_checkpoint_follows_independent_echo_and_postcheck_before_listener(self):
        source=(VM/'guest_artifacts.py').read_text()
        scenario=source[source.index('def scenario('):]
        self.assertLess(scenario.index('after_facts,after=quota_facts(room)'),scenario.index('UAS_ARTIFACT_QUOTA_RESULT:'))
        self.assertLess(scenario.index("quota_exhaustion[room]['project_hard_quota_enforced'] is True"),
                        scenario.index('UAS_ARTIFACT_QUOTA_RESULT:'))
        self.assertLess(scenario.index('UAS_ARTIFACT_QUOTA_RESULT:'),scenario.index('listener=labeled_listener('))
        self.assertIn("output_limit=8192",scenario)
        self.assertIn('if len(quota_checkpoint.encode())>16384:',scenario)
    def test_diagnostics_are_bounded_typed_without_raw_payload_or_untrusted_error_text(self):
        value={'version':1,'phase':'receive','transfer':{'raw_bytes':8,'flags':socket.MSG_CMSG_CLOEXEC,
            'ancillary_count':2,'ancillary':[{'level':1,'type':1,'bytes':4}]},'child':{'outcome':'exit','exit_code':125}}
        error=guest.ListenerSetupFailure(value)
        self.assertLess(len(str(error).encode()),8192)
        self.assertEqual(error.document,value)
        self.assertNotIn('LISTENER',str(error))


if __name__=='__main__':unittest.main()
