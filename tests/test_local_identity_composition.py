"""Selected UID range reaches real channel owners; host IO is doubled."""
from contextlib import ExitStack
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch
from uas import native_session as session, local_services as services
from uas.local_native import LocalNativeProfile
from uas.local_host_profile import plan_owners, HostProfileError
from uas.native_qualification import QualificationError
from tests.test_local_native_engine import selections


def selected():
    config,doc=selections()
    doc['host_profile']['mapping']['offset']=500000
    doc['mapping']['offset']=500000
    return LocalNativeProfile(config,doc,'room','/srv/uas/control').host_profile


class IdentityCompositionTests(unittest.TestCase):
    def test_mapping_digest_checks_both_kernel_maps_against_selected_range(self):
        profile=selected()
        values={'uid_map':'0 500000 65536\n','gid_map':'0 500000 65536\n'}
        with patch.object(services.Path,'read_text',lambda path:values.get(path.name,'65534')):
            self.assertEqual(len(services.mapping_digest(90,host_profile=profile)),64)
            values['gid_map']='0 100000 65536\n'
            with self.assertRaises(Exception):services.mapping_digest(90,host_profile=profile)

    def test_hub_peer_requires_selected_uid_and_gid_before_release(self):
        profile=selected();metadata={'challenge':'ab'*32,'room_id':'room','room_instance':'instance'}
        resources={'control_path':'/owned/control','hub_id':'owned'}
        for credentials,accepted in [((12,565531,565531),True),((12,165531,165531),False),((12,565531,165531),False)]:
            record=Mock();record.data=b'HUB1'+bytes.fromhex('ab'*32);record.credentials=credentials
            receiver=Mock();receiver.__enter__=Mock(return_value=record);receiver.__exit__=Mock(return_value=False)
            listener=Mock();listener.accept.return_value=(Mock(),None)
            with ExitStack() as stack,patch.object(session,'EndpointLease') as lease,patch.object(session,'enable'),patch.object(session,'receive',return_value=receiver),patch.object(session,'HeldOrigin',side_effect=RuntimeError('accepted-peer')) as held:
                if accepted:
                    with self.assertRaisesRegex(RuntimeError,'accepted-peer'):
                        session.start_hub_channel(Mock(),resources,metadata,listener,stack,Mock(),host_profile=profile)
                else:
                    with self.assertRaisesRegex(QualificationError,'IDENTITY_MISMATCH'):
                        session.start_hub_channel(Mock(),resources,metadata,listener,stack,Mock(),host_profile=profile)
                    held.assert_not_called()
                lease.assert_called_once_with('/owned/control',owner=565533,group=565531)

    def test_mapping_shaped_unvalidated_plan_never_selects_identity(self):
        with self.assertRaisesRegex(HostProfileError,'LOCAL_PLAN_REQUIRED'):
            plan_owners(N(native_profile=N(host_profile=selected())))


class MappingRangeTests(unittest.TestCase):
    def test_full_range_fits_canonical_signed_identity_contract(self):
        from uas.local_host_profile import LocalHostProfile
        from tests.test_local_host_plan import profile
        value=profile();value['mapping']['offset']=2**31-65536
        self.assertLess(max(LocalHostProfile.parse(value).owners.values()),2**31)
        value['mapping']['offset']+=1
        with self.assertRaisesRegex(HostProfileError,'HOST_MAPPING'):LocalHostProfile.parse(value)
        value['mapping']['offset']=2**31
        with self.assertRaisesRegex(HostProfileError,'HOST_MAPPING'):LocalHostProfile.parse(value)
