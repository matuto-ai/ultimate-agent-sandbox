"""Canonical replacement metadata policy, with no actual chmod/chown effects."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from lifecycle_support import FileFixtureBackend
from uas.lifecycle import Supervisor, FixtureSpec, LifecycleError


class LocalStateProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.project=self.root/'project';self.project.mkdir()
        self.backend=FileFixtureBackend(self.root/'backend')
        self.spec=FixtureSpec('room','project',(str(self.project),),'sha256:'+'a'*64,'sha256:'+'b'*64,'sha256:'+'c'*64)
    def owner(self,**extra):
        return Supervisor(self.root/'control','room',self.backend,authorize=lambda *_:True,revoke=self.backend.revoke,**extra)
    def test_fixed_reader_policy_rejects_any_other_gid_and_nonroot(self):
        for gid in (True,0,165532,165534,'165533'):
            with self.subTest(gid=gid),patch('uas.lifecycle.os.geteuid',return_value=0),self.assertRaises(LifecycleError):
                self.owner(state_reader_gid=gid)
        with patch('uas.lifecycle.os.geteuid',return_value=1000),self.assertRaises(LifecycleError):
            self.owner(state_reader_gid=165533)
    def test_default_save_never_changes_permissions_or_group(self):
        with patch('uas.lifecycle.os.fchown') as chown,patch('uas.lifecycle.os.fchmod') as chmod:
            owner=self.owner();owner.start(self.spec);owner.stop();owner.start(self.spec)
        chown.assert_not_called();chmod.assert_not_called()
    def test_stop_start_every_replacement_projects_same_readonly_group_before_publish(self):
        events=[];metadata={};observed=[];original_replace=os.replace
        def chown(fd,uid,gid):
            info=os.fstat(fd);metadata[(info.st_dev,info.st_ino)]={'uid':uid,'gid':gid};events.append(('chown',fd))
        def chmod(fd,mode):
            info=os.fstat(fd);metadata[(info.st_dev,info.st_ino)]['mode']=mode;events.append(('chmod',fd))
        def replace(source,target):
            if Path(target).name=='lifecycle.json':
                info=Path(source).stat();self.assertEqual(metadata[(info.st_dev,info.st_ino)],{'uid':0,'gid':165533,'mode':0o640})
                self.assertEqual([event[0] for event in events[-2:]],['chown','chmod'])
                original_replace(source,target)
                # Read actual replaced bytes through a fresh descriptor, as a
                # retained read-only owner does; access metadata is mocked.
                with open(target) as stream:observed.append(json.load(stream))
            else:original_replace(source,target)
        with patch('uas.lifecycle.os.geteuid',return_value=0),patch('uas.lifecycle.os.fchown',side_effect=chown),\
             patch('uas.lifecycle.os.fchmod',side_effect=chmod),patch('uas.lifecycle.os.replace',side_effect=replace):
            owner=self.owner(state_reader_gid=165533);first=owner.start(self.spec)
            owner.stop();owner.start(self.spec)
        self.assertGreater(len(observed),3)
        self.assertEqual({value['instance_id'] for value in observed},{first['instance_id']})
        self.assertIn('stopped',{value['phase'] for value in observed});self.assertEqual(observed[-1]['phase'],'running')
    def test_metadata_failure_cannot_replace_previous_manifest(self):
        owner=self.owner();owner.start(self.spec);before=owner._manifest.read_bytes()
        with patch('uas.lifecycle.os.geteuid',return_value=0):owner=self.owner(state_reader_gid=165533)
        with patch('uas.lifecycle.os.geteuid',return_value=0),patch('uas.lifecycle.os.fchown',side_effect=OSError('denied')),\
             patch('uas.lifecycle.os.fchmod') as chmod,patch('uas.lifecycle.os.replace') as replace:
            with self.assertRaises(OSError):owner.stop()
        chmod.assert_not_called();replace.assert_not_called();self.assertEqual(owner._manifest.read_bytes(),before)
    def test_lost_root_authority_fails_before_new_state_write(self):
        with patch('uas.lifecycle.os.geteuid',return_value=0):owner=self.owner(state_reader_gid=165533)
        with patch('uas.lifecycle.os.geteuid',return_value=1000),patch('uas.lifecycle.os.open') as opened:
            with self.assertRaises(LifecycleError):owner._save({})
        opened.assert_not_called()
