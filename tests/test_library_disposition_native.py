"""Authenticated host-local rejection transport; CI cannot skip socket proof."""
import errno
import os
import socket
import threading
import time
import unittest

import test_library_disposition as fixture
import test_library_disposition_recovery as recovery
from uas import library
from uas.library_controls import request, serve


class NativeDispositionTests(unittest.TestCase):
    def setUp(self):
        probe=None
        try:
            probe=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);probe.bind('')
        except OSError as error:
            if error.errno==errno.EPERM and os.environ.get('GITHUB_ACTIONS')!='true':
                self.skipTest('environment denies Unix socket bind')
            raise
        finally:
            if probe is not None:probe.close()
        self.fx=fixture.DispositionTests('test_pending_reject_one_commit_history_and_exact_retry')
        self.fx.setUp();self.addCleanup(self.fx.doCleanups)
        self.stop=threading.Event();self.errors=[];root=self.fx.fx.root
        def run():
            try:serve(root,self.fx.controls,authenticate=lambda uid:self.fx.principal,stopped=self.stop.is_set)
            except BaseException as e:self.errors.append(e)
        self.thread=threading.Thread(target=run);self.thread.start();self.addCleanup(self.close)
        deadline=time.monotonic()+2
        while not (root/'library-operator.sock').exists() and time.monotonic()<deadline:time.sleep(.005)
        self.assertTrue((root/'library-operator.sock').exists())
        def send(value):
            response=request(root,value)
            if response['outcome']!='observed':raise library.LibraryError(response['error'])
            return response['result']
        self.fx.send=send
    def close(self):
        self.stop.set();self.thread.join(3);self.assertFalse(self.thread.is_alive());self.assertFalse(self.errors)
    def test_complete_pending_reject_and_exact_retry(self):
        self.fx.test_pending_reject_one_commit_history_and_exact_retry()
    def test_current_authority_conflict_and_config_replay(self):
        self.fx.test_conflicting_id_current_revocation_and_historical_config_replay()
    def test_stale_and_wire_forgery(self):
        recovery.RecoveryTests.test_wire_scope_and_cross_project_forgery_refused(self.fx)
        self.fx.test_stale_inspection_and_configuration_no_write()
    def test_active_busy_and_blocked_disposal(self):
        self.fx.test_active_and_direct_attempt_lock_busy()
        self.fx.entry()['state']['state']='BLOCKED'
        result=self.fx.send(self.fx.value());self.assertEqual(result['outcome'],'COMMITTED')
        self.assertEqual(self.fx.entry()['state']['state'],'DISPOSED')
