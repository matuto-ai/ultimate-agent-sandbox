"""Pure fixed-policy diagnostics tests: never load SELinux or run a child."""
import ctypes
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

VM = Path(__file__).parent / 'vm'
sys.path.insert(0, str(VM))
try:
    import room_policy_diagnostics as diagnostic
finally:
    sys.path.pop(0)


class PolicyDiagnosticTests(unittest.TestCase):
    def library(self, *, allowed=4, decided=4, flags=0, code=0, seqno=9):
        def compute(_source, _target, _class, _request, output):
            value = output._obj
            value.allowed, value.decided = allowed, decided
            value.auditallow, value.auditdeny = 0, 4
            value.seqno, value.flags = seqno, flags
            return code
        return SimpleNamespace(is_selinux_enabled=Mock(return_value=1),
            security_getenforce=Mock(return_value=1), security_policyvers=Mock(return_value=33),
            string_to_security_class=Mock(return_value=7), string_to_av_perm=Mock(return_value=4),
            security_compute_av_flags_raw=Mock(side_effect=compute))

    def capture(self, output='installed-nevras\n', *, code=0, timeout=False):
        return {'returncode': code, 'timeout': timeout, 'cleanup_errors': [],
                'stdout': {'output': output, 'bytes': len(output), 'truncated': False},
                'stderr': {'output': '', 'bytes': 0, 'truncated': False}}

    def test_libselinux_abi_has_six_fixed_width_fields_and_raw_flags_entrypoint(self):
        lib = self.library()
        with patch.object(diagnostic.ctypes, 'CDLL', return_value=lib) as load:
            self.assertIs(lib, diagnostic.load_library())
        load.assert_called_once_with('libselinux.so.1', use_errno=True)
        self.assertEqual(24, ctypes.sizeof(diagnostic.AVDecision))
        self.assertEqual(['allowed','decided','auditallow','auditdeny','seqno','flags'],
                         [key for key, _ in diagnostic.AVDecision._fields_])
        self.assertEqual(ctypes.c_ushort, lib.string_to_security_class.restype)
        self.assertEqual(ctypes.c_uint32, lib.string_to_av_perm.restype)
        self.assertEqual((ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ushort, ctypes.c_uint32,
                          ctypes.POINTER(diagnostic.AVDecision)), lib.security_compute_av_flags_raw.argtypes)

    def test_exact_four_context_pairs_and_masks_are_recorded_without_launch_decision(self):
        lib = self.library(flags=1)
        rows = diagnostic.fixed_decisions(lib)
        self.assertEqual(4, len(rows))
        self.assertEqual([pair[1:3] for pair in diagnostic.PAIRS],
                         [(row['source_context'], row['target_context']) for row in rows])
        self.assertTrue(all(row['requested_allowed'] and row['requested_fully_decided'] for row in rows))
        self.assertTrue(all(row['permissive'] and row['flags'] == 1 and row['seqno'] == 9 for row in rows))
        self.assertEqual([('unix_stream_socket','connectto')]*2 + [('sock_file','write')]*2,
                         [(row['class'],row['permission']) for row in rows])
        self.assertEqual(4, lib.security_compute_av_flags_raw.call_count)

    def test_return_zero_does_not_mean_allowed_and_incomplete_mask_is_unknown(self):
        self.assertTrue(all(row['requested_allowed'] is False
                            for row in diagnostic.fixed_decisions(self.library(allowed=0))))
        self.assertTrue(all(row['requested_allowed'] is None and not row['requested_fully_decided']
                            for row in diagnostic.fixed_decisions(self.library(decided=0))))

    def test_unavailable_class_permission_or_av_is_diagnostic_not_a_fake_deny(self):
        for missing in ('class', 'permission', 'compute'):
            lib = self.library(code=-1 if missing == 'compute' else 0)
            if missing == 'class': lib.string_to_security_class.return_value = 0
            if missing == 'permission': lib.string_to_av_perm.return_value = 0
            with self.subTest(missing=missing), patch.object(diagnostic.ctypes, 'get_errno', return_value=22):
                rows = diagnostic.fixed_decisions(lib)
            self.assertTrue(all(row['status'] == 'unavailable' and 'requested_allowed' not in row for row in rows))
            if missing != 'compute': lib.security_compute_av_flags_raw.assert_not_called()

    def test_loaded_policy_is_hashed_with_a_hard_byte_bound(self):
        with patch.object(Path, 'open', return_value=io.BytesIO(b'abc')):
            value = diagnostic.policy_digest()
        self.assertEqual(3, value['bytes'])
        self.assertEqual('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', value['sha256'])
        for data in (b'', b'12345'):
            with self.subTest(data=data), patch.object(diagnostic, 'POLICY_LIMIT', 4), \
                    patch.object(Path, 'open', return_value=io.BytesIO(data)):
                with self.assertRaises(ValueError): diagnostic.policy_digest()

    def test_installed_versions_use_only_fixed_readonly_rpm_query_and_capture_bounds(self):
        capture = Mock(return_value=self.capture())
        result = diagnostic.installed_packages(capture)
        capture.assert_called_once_with(diagnostic.RPM_ARGUMENTS, timeout=3, limit=2048)
        self.assertEqual('observed', result['status'])
        self.assertEqual(('-q','--queryformat'), diagnostic.RPM_ARGUMENTS[1:3])
        for code, timeout in ((1,False),(-9,True)):
            self.assertEqual('unavailable', diagnostic.installed_packages(
                Mock(return_value=self.capture(code=code,timeout=timeout)))['status'])

    def test_installed_metadata_does_not_override_capture_failure_or_truncated_stderr(self):
        for failure in ('capture_unavailable', 'stderr_truncated'):
            result = self.capture()
            if failure == 'capture_unavailable': result['status'] = 'unavailable'
            else: result['stderr']['truncated'] = True
            with self.subTest(failure=failure):
                observed = diagnostic.installed_packages(Mock(return_value=result))
            self.assertEqual('unavailable', observed['status'])

    def test_consistent_observations_are_diagnostic_and_policy_drift_is_visible(self):
        digest = {'status':'observed','sha256':'a'*64,'bytes':3}
        with patch.object(diagnostic,'policy_digest',return_value=digest):
            result = diagnostic.collect(lib=self.library(), capture=Mock(return_value=self.capture()))
        self.assertIs(result['admission_decision'], False)
        self.assertTrue(result['diagnostic_only'] and result['snapshot_consistent'])
        with patch.object(diagnostic,'policy_digest',side_effect=[digest,{**digest,'sha256':'b'*64}]):
            result = diagnostic.collect(lib=self.library(), capture=Mock(return_value=self.capture()))
        self.assertIs(result['snapshot_consistent'], False)
        with patch.object(diagnostic,'policy_digest',side_effect=OSError(13,'denied')):
            result = diagnostic.collect(lib=self.library(), capture=Mock(return_value=self.capture()))
        self.assertIsNone(result['snapshot_consistent'])
        self.assertEqual(4,len(result['decisions']))

    def test_library_unavailable_preserves_installed_metadata(self):
        with patch.object(diagnostic,'load_library',side_effect=OSError(2,'missing')):
            result = diagnostic.collect(capture=Mock(return_value=self.capture()))
        self.assertEqual('observed',result['installed_packages']['status'])
        self.assertEqual('unavailable',result['library']['status'])
        self.assertIsNone(result['snapshot_consistent'])

    def test_fixed_capture_wrappers_never_accept_a_name_or_extra_arguments(self):
        with patch.object(diagnostic,'_capture',return_value=self.capture('{"connected":false,"error":"EACCES"}')) as capture:
            result = diagnostic.capture_endpoint_probe('a'*64)
        self.assertEqual({'connected':False,'error':'EACCES'},result['decoded'])
        capture.assert_called_once_with(('/usr/bin/docker','exec','a'*64,'/usr/bin/python3','-I',
                                        '/opt/uas/uas/room_probe.py','endpoint'),timeout=8,limit=4096)
        for invalid in ('alpha','a'*63,'A'*64,'a'*64+';true',None):
            with self.subTest(invalid=invalid), patch.object(diagnostic,'_capture') as capture:
                with self.assertRaises(ValueError): diagnostic.capture_endpoint_probe(invalid)
                capture.assert_not_called()
        with patch.object(diagnostic,'_capture',return_value=self.capture('{}')) as capture:
            diagnostic.capture_policy_diagnostic()
        self.assertEqual(10,capture.call_args.kwargs['timeout'])
        self.assertEqual(8192,capture.call_args.kwargs['limit'])

    def test_json_evidence_bound_also_covers_control_and_unicode_expansion(self):
        for data in (b'\x00'*100, ('😀'*100).encode(), b'x'*100):
            result = diagnostic._output(data, len(data), 32)
            self.assertLessEqual(len(json.dumps(result['output'],ensure_ascii=True)),32)
            self.assertTrue(result['truncated'])
        result = self.capture('{}');result['stdout']['truncated'] = True
        self.assertIsNone(diagnostic._decode(result)['decoded'])

    def test_failed_or_timed_out_capture_keeps_status_separate_from_decoded_evidence(self):
        for code,timeout,errors in ((1,False,[]),(-9,True,[]),(0,False,['OSError'])):
            result=self.capture('{"connected":false,"error":"EACCES"}',code=code,timeout=timeout)
            result['cleanup_errors']=errors
            with self.subTest(code=code,timeout=timeout,errors=errors), \
                    patch.object(diagnostic,'_capture',return_value=result):
                observed=diagnostic.capture_endpoint_probe('a'*64)
            self.assertEqual({'connected':False,'error':'EACCES'},observed['decoded'])
            self.assertEqual(code,observed['returncode']);self.assertEqual(timeout,observed['timeout'])
            self.assertEqual(errors,observed['cleanup_errors'])

    def test_capture_drains_without_retaining_unbounded_bytes(self):
        stdout,stderr = Mock(),Mock()
        stdout.fileno.return_value=11;stderr.fileno.return_value=12
        process=Mock(stdout=stdout,stderr=stderr,pid=123,wait=Mock(return_value=0))
        selector=Mock(); keys={}
        def register(stream,_events,name): keys[name]=SimpleNamespace(fileobj=stream,data=name)
        selector.register.side_effect=register
        selector.get_map.side_effect=lambda:dict(keys)
        selector.select.side_effect=lambda _timeout:[(key,1) for key in list(keys.values())]
        selector.unregister.side_effect=lambda stream:keys.pop('stdout' if stream is stdout else 'stderr')
        outputs={11:iter((b'x'*100,b'')),12:iter((b'err',b''))}
        with patch.object(diagnostic.subprocess,'Popen',return_value=process) as popen, \
                patch.object(diagnostic.selectors,'DefaultSelector',return_value=selector), \
                patch.object(diagnostic.os,'set_blocking'), \
                patch.object(diagnostic.os,'read',side_effect=lambda fd,_size:next(outputs[fd])), \
                patch.object(diagnostic.os,'killpg') as kill, \
                patch.object(diagnostic.time,'monotonic',return_value=0):
            result=diagnostic._capture(('fixed',),timeout=3,limit=16)
        self.assertEqual(100,result['stdout']['bytes']);self.assertTrue(result['stdout']['truncated'])
        self.assertEqual('err',result['stderr']['output']);self.assertEqual(0,result['returncode'])
        self.assertFalse(result['timeout']);kill.assert_not_called()
        self.assertTrue(popen.call_args.kwargs['start_new_session'])

    def test_timeout_kills_owned_group_before_reap_and_preserves_partial_capture(self):
        events=[]
        process=Mock(pid=321,wait=Mock(side_effect=lambda **_:events.append('wait') or -9))
        selector=Mock();selector.get_map.return_value={1:1}
        with patch.object(diagnostic.subprocess,'Popen',return_value=process), \
                patch.object(diagnostic.selectors,'DefaultSelector',return_value=selector), \
                patch.object(diagnostic.os,'set_blocking'), \
                patch.object(diagnostic.os,'killpg',side_effect=lambda *_:events.append('kill')), \
                patch.object(diagnostic.time,'monotonic',side_effect=[0,4]):
            result=diagnostic._capture(('fixed',),timeout=3,limit=16)
        self.assertEqual(['kill','wait'],events)
        self.assertTrue(result['timeout']);self.assertEqual(-9,result['returncode'])
        self.assertEqual([],result['cleanup_errors'])

    def test_capture_setup_and_cleanup_failure_are_retained_not_raised(self):
        process=Mock(pid=321,wait=Mock(return_value=-9))
        selector=Mock();selector.register.side_effect=ValueError('setup failed')
        with patch.object(diagnostic.subprocess,'Popen',return_value=process), \
                patch.object(diagnostic.selectors,'DefaultSelector',return_value=selector), \
                patch.object(diagnostic.os,'set_blocking'), \
                patch.object(diagnostic.os,'killpg',side_effect=PermissionError(13,'denied')):
            result=diagnostic._capture(('fixed',),timeout=3,limit=16)
        self.assertEqual('unavailable',result['status'])
        self.assertEqual('ValueError',result['error_type'])
        self.assertEqual(['PermissionError'],result['cleanup_errors'])
        process.wait.assert_called_once_with(timeout=5)


if __name__ == '__main__':
    unittest.main()
