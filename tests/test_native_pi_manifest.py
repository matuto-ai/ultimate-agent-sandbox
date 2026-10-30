"""Descriptor-only doubles: never create/open a FIFO or native process."""
import hashlib
import json
import os
import stat
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
from uas.native_pi_recipe import read_manifest, NativeRecipeError


class NativeManifestTests(unittest.TestCase):
    def test_stable_nofollow_private_regular_file_is_hashed(self):
        data=json.dumps({'version':1}).encode();digest=hashlib.sha256(data).hexdigest()
        directory=NS(st_uid=os.getuid(),st_mode=stat.S_IFDIR|0o700)
        regular=NS(st_uid=os.getuid(),st_mode=stat.S_IFREG|0o600,st_nlink=1,
            st_size=len(data),st_dev=1,st_ino=2,st_mtime_ns=3,st_ctime_ns=4)
        with patch('os.open',side_effect=[10,11,12]) as opened,patch('os.close') as closed,\
             patch('os.fstat',side_effect=[directory,regular,regular]),patch('os.read',side_effect=[data,b'']):
            self.assertEqual(read_manifest('/private/native.json',digest),{'version':1})
            self.assertTrue(opened.call_args_list[-1].args[1]&os.O_NOFOLLOW)
            self.assertTrue(opened.call_args_list[-1].args[1]&os.O_NONBLOCK)
            self.assertEqual([c.args[0] for c in closed.call_args_list],[10,12,11])
    def test_fifo_and_shared_file_rejected_without_read(self):
        directory=NS(st_uid=os.getuid(),st_mode=stat.S_IFDIR|0o700)
        for mode in (stat.S_IFIFO|0o600,stat.S_IFREG|0o644):
            value=NS(st_uid=os.getuid(),st_mode=mode,st_nlink=1,st_size=8)
            with patch('os.open',side_effect=[10,11,12]) as opened,patch('os.close'),\
                 patch('os.fstat',side_effect=[directory,value]),patch('os.read') as read:
                with self.assertRaisesRegex(NativeRecipeError,'private regular'):
                    read_manifest('/private/native.json','a'*64)
                read.assert_not_called()
                self.assertTrue(opened.call_args_list[-1].args[1]&os.O_NONBLOCK)
    def test_changed_descriptor_rejected(self):
        data=b'{}';directory=NS(st_uid=os.getuid(),st_mode=stat.S_IFDIR|0o700)
        before=dict(st_uid=os.getuid(),st_mode=stat.S_IFREG|0o600,st_nlink=1,
            st_size=2,st_dev=1,st_ino=2,st_mtime_ns=3,st_ctime_ns=4)
        with patch('os.open',side_effect=[10,11,12]),patch('os.close'),\
             patch('os.fstat',side_effect=[directory,NS(**before),NS(**(before|{'st_ctime_ns':5}))]),\
             patch('os.read',side_effect=[data,b'']):
            with self.assertRaisesRegex(NativeRecipeError,'changed during read'):
                read_manifest('/private/native.json',hashlib.sha256(data).hexdigest())
