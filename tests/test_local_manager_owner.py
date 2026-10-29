import unittest
from unittest.mock import Mock, patch
from pathlib import Path
from uas.local_manager_owner import ManagerOwner

class ImmediateThread:
    def __init__(self, *, target, **kw): self.target=target
    def start(self): self.target()
    def join(self, **kw): pass
    def is_alive(self): return False

class ManagerOwnerTests(unittest.TestCase):
    def owner(self, manager):
        installation=Mock();installation.open.return_value=({}, {}, {'manager':manager})
        return ManagerOwner(installation)

    def test_missing_selection_never_spawns(self):
        owner=self.owner(None)
        with patch('uas.local_manager_owner.threading.Thread') as thread:
            self.assertEqual(owner.ensure('room',None,None,None),{'status':'not-configured'})
            thread.assert_not_called()

    def test_unknown_failure_not_retried_and_exact_ledger_path(self):
        owner=self.owner({'room_id':'room'});backend=Mock();backend.layout.return_value={'hub':Path('/owned/hub')}
        with patch('uas.local_manager_owner.threading.Thread',ImmediateThread),patch('uas.local_manager_owner.serve_local_manager',side_effect=OSError('private')) as serve:
            result=owner.ensure('room','owner',backend,{'instance_id':'i'})
            self.assertEqual(result,{'status':'unknown','error':'LOCAL_MANAGER_FAILED'})
            self.assertEqual(serve.call_args.kwargs['ledger_path'],Path('/owned/hub/room.db'))
            owner.ensure('room','owner',backend,{'instance_id':'i'})
            self.assertEqual(serve.call_count,1)
            owner.close();self.assertTrue(owner.stopped.is_set())

    def test_different_room_never_reuses_grant(self):
        owner=self.owner({'room_id':'alpha'})
        self.assertEqual(owner.ensure('beta',None,None,None),{'status':'not-selected-for-room'})
        self.assertIsNone(owner.thread)

if __name__=='__main__':unittest.main()
