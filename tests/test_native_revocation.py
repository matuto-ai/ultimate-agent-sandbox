"""Controlled Room-ledger revocation and inert poll tests; no native effects."""
import select
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch
import test_native_helper_owner as fixture
from uas import workstation_control as control
from uas import workstation_admission as admission
from uas.peer import Readiness
from uas.ledger import RoomLedger, LedgerError
from uas.kernel_origin import OriginDenied

class RevocationTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.CombinedSeamTests('test_actual_helper_dispatch_review_ledger_replay_and_revocation')
        self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.hub=self.f.hub;self.hub.db=N(execute=Mock())
        self.channel=N(close=Mock());self.hub.bind_control(self.channel)
    def state(self):return self.f.hub and self.f.f.state()['peer_traffic']['connections']['builder-seat']
    def test_root_loss_publishes_existing_attachment_lost(self):
        old=self.state().copy();self.hub.revoke('a'*32)
        new=self.state();self.assertEqual(new['readiness'],'lost')
        self.assertEqual(new['attachment_id'],old['attachment_id'])
        self.assertFalse(self.hub._active);self.assertFalse(self.hub._helpers)
        self.hub.revoke('a'*32) # no duplicate Room event
    def test_helper_loss_cascades_root_attachment(self):
        self.hub.revoke_helper('f'*32)
        self.assertEqual(self.state()['readiness'],'lost');self.assertFalse(self.hub._active)
    def test_control_loss_publishes_lost_and_closes_host_channel(self):
        self.hub.control_lost();self.assertEqual(self.state()['readiness'],'lost')
        self.assertTrue(self.hub._fenced);self.channel.close.assert_called_once()
    def test_replaced_attachment_is_not_marked_lost(self):
        peer=self.f.f.peer
        replacement=peer.connect('replacement','builder-seat',self.f.binding.incarnation,object())
        self.hub.revoke('a'*32)
        self.assertEqual(self.state()['attachment_id'],replacement.attachment_id)
        self.assertNotEqual(self.state()['readiness'],'lost')
    def test_room_write_failure_fences_and_never_acknowledges_retry(self):
        with patch('uas.workstation_peer.FixturePeerHub.observe',side_effect=RuntimeError('controlled-store-failure')):
            with self.assertRaisesRegex(RuntimeError,'controlled-store'):self.hub.revoke('a'*32)
        self.assertTrue(self.hub._fenced);self.channel.close.assert_called_once()
        self.assertNotEqual(self.state()['readiness'],'lost')
        self.hub.db.execute.assert_not_called()
        with self.assertRaises(OriginDenied):self.hub.revoke('a'*32)
    def test_partial_attach_recheck_failure_publishes_lost(self):
        # Remove only the test's transport mapping, then exercise real connect.
        self.f.dispatcher._connections.clear()
        with patch.object(self.hub,'recheck',side_effect=OriginDenied('late revocation')):
            with self.assertRaises(OriginDenied):self.f.dispatcher.attach_current('a'*32,context_generation=1)
        self.assertEqual(self.state()['readiness'],'lost')

    def test_control_binding_cannot_change_or_reopen_after_fence(self):
        self.hub.bind_control(self.channel)
        with self.assertRaises(OriginDenied):self.hub.bind_control(N(close=Mock()))
        self.hub.control_lost()
        with self.assertRaises(OriginDenied):self.hub.bind_control(self.channel)
    def test_control_close_error_still_marks_attachments_lost(self):
        self.channel.close.side_effect=OSError('close failed')
        with self.assertRaises(OSError):self.hub.control_lost()
        self.assertEqual(self.state()['readiness'],'lost');self.assertFalse(self.hub._active)
    def test_helper_close_error_still_closes_root(self):
        root=self.hub._active['a'*32][0]
        original=root.close;root.close=Mock(side_effect=original)
        self.f.offer.close=Mock(side_effect=OSError('helper close failed'))
        with self.assertRaises(OSError):self.hub.revoke('a'*32)
        root.close.assert_called_once();self.assertTrue(self.hub._fenced)
        with self.assertRaises(OriginDenied):self.hub.revoke('a'*32)

    def test_original_room_connection_closed_before_revocation_is_supported(self):
        path,identity=self.f.dispatcher._revocation_store
        self.f.f.ledger.close()
        self.hub.revoke('a'*32)
        with RoomLedger.open_reader(path,'room') as reader:
            self.assertEqual(reader.snapshot()['state']['peer_traffic']['connections']['builder-seat']['readiness'],'lost')
    def test_missing_or_replaced_room_store_never_creates_or_revokes_successfully(self):
        path,identity=self.f.dispatcher._revocation_store
        self.f.f.ledger.close()
        moved=path.with_suffix('.saved');path.rename(moved)
        try:
            with self.assertRaises(LedgerError):self.hub.revoke('a'*32)
            self.assertFalse(path.exists());self.assertTrue(self.hub._fenced)
        finally:moved.rename(path)
    def test_replacement_attachment_during_observe_is_not_marked_lost(self):
        from uas.peer import FixturePeerHub
        original=FixturePeerHub.observe
        def raced(hub,connection,readiness):
            if readiness is Readiness.LOST:
                self.f.f.peer.connect('replacement-during-observe','builder-seat',self.f.binding.incarnation,object())
            return original(hub,connection,readiness)
        with patch.object(FixturePeerHub,'observe',raced):self.hub.revoke('a'*32)
        self.assertEqual(self.state()['attachment_id'],'replacement-during-observe')
        self.assertNotEqual(self.state()['readiness'],'lost')

    def test_borrowed_receive_reply_wrappers_never_replace_owned_control(self):
        packet={'kind':'POLL_DELIVERY','operation_id':'a'*32,'exchange_id':'e'*32,'controller':self.hub.controller}
        for _ in range(2):
            borrowed=N(send=lambda data:len(data))  # deliberately no close method
            with patch.object(admission,'_receive_offer',return_value=packet):
                self.assertEqual(self.hub.serve_once(borrowed,on_delivery=lambda *a,**k:{'status':'HELD'}),{'status':'HELD'})
        self.assertIs(self.hub._control,self.channel);self.channel.close.assert_not_called()
    def test_malformed_borrowed_input_does_not_claim_control_ownership(self):
        self.hub._control=None
        borrowed=object()
        with patch.object(admission,'_receive_offer',side_effect=OriginDenied('malformed')):
            with self.assertRaisesRegex(OriginDenied,'malformed'):self.hub.admit(borrowed)
        self.assertIsNone(self.hub._control);self.channel.close.assert_not_called()
        self.assertEqual(self.state()['readiness'],'lost')
    def test_replaced_store_same_room_id_is_rejected(self):
        path,identity=self.f.dispatcher._revocation_store
        self.f.f.ledger.close();saved=path.with_suffix('.saved');path.rename(saved)
        try:
            replacement=RoomLedger(path,'room');replacement.close()
            with self.assertRaisesRegex(LedgerError,'STORE_REPLACED'):
                RoomLedger.open_writer(path,'room',identity=identity)
        finally:
            path.unlink();saved.rename(path)

class ControlCurrentTests(unittest.TestCase):
    def make(self):
        client=object.__new__(control.SupervisorAdmission)
        client._fenced=False;client.control=object()
        client.hub_origin=N(revoked=False,pidfd=10)
        client.launch=N(origin=N(revoked=False,pidfd=11),state='active',endpoint=N(require=Mock()))
        return client
    def test_hup_with_queued_reply_is_still_lost(self):
        for events in (select.POLLHUP,select.POLLIN|select.POLLHUP,select.POLLERR,select.POLLNVAL,getattr(select,'POLLRDHUP',select.POLLHUP)):
            client=self.make();poll=N(register=Mock(),poll=Mock(return_value=[(5,events)]))
            with patch.object(control.select,'poll',return_value=poll),patch.object(control,'alive',return_value=True):
                with self.assertRaises(OriginDenied):client._current()
            self.assertTrue(client._fenced);poll.poll.assert_called_once_with(0)
    def test_live_empty_or_queued_reply_is_not_consumed(self):
        for events in ([],[(5,select.POLLIN)]):
            client=self.make();poll=N(register=Mock(),poll=Mock(return_value=events))
            with patch.object(control.select,'poll',return_value=poll),patch.object(control,'alive',return_value=True):client._current()
            self.assertFalse(client._fenced);client.launch.endpoint.require.assert_called_once()
    def test_invalid_or_closed_descriptor_is_fenced(self):
        client=self.make();poll=N(register=Mock(side_effect=ValueError('closed')))
        with patch.object(control.select,'poll',return_value=poll):
            with self.assertRaises(OriginDenied):client._current()
        self.assertTrue(client._fenced)
