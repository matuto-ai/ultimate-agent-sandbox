"""Actual private Unix transport for archive/restore; hosted CI must not skip."""
import errno
import os
import socket
import threading
import time
import unittest
from uas.library_controls import request, serve
from test_library_archive_integration import ArchiveFixture


class NativeArchiveTests(ArchiveFixture, unittest.TestCase):
    def setUp(self):
        probe = None
        try:
            probe=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);probe.bind('')
        except OSError as error:
            if error.errno==errno.EPERM and os.environ.get('GITHUB_ACTIONS')!='true':
                self.skipTest('environment denies Unix socket bind')
            raise
        finally:
            if probe is not None: probe.close()
        self.setup_archive()
        self.stop=threading.Event();self.errors=[]
        def run():
            try:serve(self.fx.root,self.fx.controls,authenticate=lambda uid:self.fx.principal,stopped=self.stop.is_set)
            except BaseException as error:self.errors.append(error)
        self.thread=threading.Thread(target=run);self.thread.start();self.addCleanup(self.close)
        deadline=time.monotonic()+2
        while not (self.fx.root/'library-operator.sock').exists() and time.monotonic()<deadline:time.sleep(.005)
        self.assertTrue((self.fx.root/'library-operator.sock').exists(),self.errors)
        self.fx.send=lambda value:request(self.fx.root,value)
    def close(self):
        self.stop.set();self.thread.join(3)
        self.assertFalse(self.thread.is_alive());self.assertFalse(self.errors)
    def test_archive_restore_and_duplicate_no_model_contact(self):self.roundtrip()
    def test_current_authority_before_action_and_receipt(self):self.authority()
    def test_failed_final_model_is_not_repeated(self):self.failed_final()
