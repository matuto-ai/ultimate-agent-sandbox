"""Authenticated host-local deterministic repair transport; CI cannot skip socket proof."""
import errno
import os
import socket
import threading
import time
import unittest

import test_library_repair as fixture
from uas import library
from uas.library_controls import request, serve


class NativeRepairTests(unittest.TestCase):
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
        self.fx=fixture.RepairTests('test_missing_generated_entry_repairs_only_indexes_and_exact_replay')
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
    def test_repair_and_exact_retry(self):
        self.fx.test_missing_generated_entry_repairs_only_indexes_and_exact_replay()
    def test_root_and_authored_preservation(self):
        self.fx.test_root_service_links_rebuilt_without_rewriting_authored_root()
    def test_damaged_history_no_resurrection(self):
        self.fx.test_truncated_structurally_valid_history_cannot_resurrect_pending()
    def test_authority_revocation_and_wire_forgery(self):
        self.fx.test_current_authority_and_untrusted_wire()
