"""Re-admission refreshes only observed selected Engine socket inode."""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
from tests.test_local_host_apply import FakeReceipt
from tests.test_local_host_plan import selected,observation
from uas.local_host_apply import apply
from uas.local_host_profile import HostProfileError,digest

class HostReadmissionTests(unittest.TestCase):
    def test_only_ephemeral_engine_identity_refresh_allowed(self):
        original=observation();original['storage']['filesystem']='btrfs'
        proposed=selected(o=original,allocation_bytes=1024**3)
        evidence={'identity':[0,22],'observed_sha256':'b'*64}
        for change,route,allowed in [({'socket_identity':[99,88]},None,True),({'docker_root':'/foreign'},None,False),({},'10.91.1.0/24',True),({},'10.92.1.0/24',False)]:
            current=deepcopy(original);current['engine'].update(change)
            if route:current['networks'].append(route)
            FakeReceipt.states={i:{'state':'confirmed','evidence':evidence} for i in range(2)}
            FakeReceipt.documents={'observations.json':original,'xfs-identity-policy.json':{'version':3,'plan_id':proposed['plan_id'],'uuid':str(uuid.UUID(hex=proposed['plan_id'][:32]))}}
            request={'host_plan':proposed,'settings':{'rooms':{'alpha':{'subnet':'10.91.1.0/24'}}}}
            FakeReceipt.documents['room-request.json']={**request,'request_id':digest(request)}
            with patch('uas.local_host_apply.os.geteuid',return_value=0),patch('uas.local_host_apply.canonical_node',return_value=SimpleNamespace(st_dev=original['storage']['identity'][0])),patch('uas.local_host_apply.os.path.lexists',return_value=True),patch('uas.local_host_apply.owned_directory',return_value=evidence),patch('uas.local_host_apply.PreparationReceipt',FakeReceipt),patch('uas.local_host_apply.inspect',return_value=current),patch('uas.local_host_apply.fcntl.flock'),patch('uas.local_xfs_storage.prepare') as image,patch('uas.local_boot_endpoints.prepare_endpoints') as endpoints:
                if allowed:
                    apply(proposed,readmission=True);image.assert_called_once();endpoints.assert_called_once()
                else:
                    with self.assertRaisesRegex(HostProfileError,'HOST_DRIFT'):apply(proposed,readmission=True)
                    image.assert_not_called();endpoints.assert_not_called()
