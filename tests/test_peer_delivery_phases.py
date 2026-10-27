"""Pure existing-ledger delivery phases; no native runtime or transport launch."""
from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import patch

import test_peer
from uas.ledger import Command, Event, Origin, Transition
from uas.peer import DeliveryOffer, Readiness


class PeerDeliveryPhaseTests(unittest.TestCase):
    setUp = test_peer.PeerTests.setUp
    tearDown = test_peer.PeerTests.tearDown
    connect = test_peer.PeerTests.connect
    request = test_peer.PeerTests.request
    state = test_peer.PeerTests.state
    assert_code = test_peer.PeerTests.assert_code

    def prepared(self, **kwargs):
        self.request()
        self.hub.observe(self.b, Readiness.SAFE)
        return self.hub.prepare_delivery(self.b, **kwargs)

    def test_prepare_is_bounded_immutable_and_never_contacts_receiver(self):
        with patch.object(self.b.receiver, 'accept', side_effect=AssertionError('external contact')) as accept:
            offer = self.prepared()
        accept.assert_not_called()
        self.assertIs(type(offer), DeliveryOffer)
        self.assertLessEqual(len(offer.envelope_json.encode()),65536)
        with self.assertRaises(FrozenInstanceError):offer.observation_id='changed'
        envelope = offer.envelope; envelope['text']='changed'
        self.assertNotEqual(offer.envelope['text'],'changed')
        self.assertEqual(self.state()['offers']['request-1']['bob']['outcome'],'UNCONFIRMED')
        self.assertIsNone(self.state()['traffic']['request-1']['response_started_at'])
        self.assertEqual(self.b.receiver.inbox(),[])

    def test_authority_spans_each_transaction_not_external_acceptance(self):
        held=False; checks=[]
        def authorized():
            self.assertTrue(held)
            checks.append(self.ledger._db.in_transaction)
            return True
        self.request();self.hub.observe(self.b,Readiness.SAFE)
        held=True
        offer=self.hub.prepare_delivery(self.b,authorize=authorized)
        self.assertIn(True,checks)
        held=False
        self.assertFalse(self.ledger._db.in_transaction)
        receipt=self.b.receiver.accept(offer.envelope)
        checks.clear();held=True
        self.hub.confirm_delivery(self.b,offer,receipt,authorize=authorized)
        self.assertIn(True,checks)
        held=False
        self.assertEqual(self.state()['traffic']['request-1']['status'],'DELIVERED')

    def test_lost_native_receipt_reuses_existing_offer_and_receiver_receipt(self):
        offer=self.prepared()
        native_receipt=self.b.receiver.accept(offer.envelope)  # return lost before confirmation
        sequence=self.ledger.snapshot()['room_seq']
        retried=self.hub.prepare_delivery(self.b)
        self.assertEqual(offer,retried)
        self.assertEqual(self.ledger.snapshot()['room_seq'],sequence)
        self.assertEqual(self.b.receiver.accept(retried.envelope),native_receipt)
        result=self.hub.confirm_delivery(self.b,retried,native_receipt)
        sequence=self.ledger.snapshot()['room_seq']
        self.assertEqual(self.hub.confirm_delivery(self.b,retried,native_receipt),result)
        self.assertEqual(self.ledger.snapshot()['room_seq'],sequence)
        self.assertEqual(len(self.b.receiver.inbox()),1)
        self.assertIsNone(self.hub.prepare_delivery(self.b))

    def test_mismatched_or_absent_receipt_never_confirms(self):
        offer=self.prepared(); receipt=self.b.receiver.accept(offer.envelope)
        sequence=self.ledger.snapshot()['room_seq']
        for invalid in (None,{}, {**receipt,'digest':'wrong'}, {**receipt,'context_generation':True}):
            self.assert_code('UNCONFIRMED_DELIVERY',lambda:self.hub.confirm_delivery(self.b,offer,invalid))
        self.assertEqual(self.ledger.snapshot()['room_seq'],sequence)
        self.assertIsNone(self.state()['traffic']['request-1']['response_started_at'])

    def test_fresh_safe_observation_still_fences_older_offer_context(self):
        offer=self.prepared(); receipt=self.b.receiver.accept(offer.envelope)
        self.hub.observe(self.b,Readiness.SAFE)
        self.assert_code('FORBIDDEN',lambda:self.hub.confirm_delivery(self.b,offer,receipt))
        self.assertEqual(self.state()['offers']['request-1']['bob']['outcome'],'UNCONFIRMED')
        refreshed=self.hub.prepare_delivery(self.b)
        self.assertEqual(refreshed.envelope,offer.envelope)
        self.assertNotEqual(refreshed.observation_id,offer.observation_id)
        self.hub.confirm_delivery(self.b,refreshed,receipt)
        self.assertEqual(len(self.b.receiver.inbox()),1)

    def test_late_authority_revoke_preserves_unknown_native_effect(self):
        offer=self.prepared(authorize=lambda:True)
        receipt=self.b.receiver.accept(offer.envelope)
        self.assert_code('FORBIDDEN',lambda:self.hub.confirm_delivery(self.b,offer,receipt,authorize=lambda:False))
        self.assertEqual(len(self.b.receiver.inbox()),1)
        self.assertEqual(self.state()['traffic']['request-1']['status'],'QUEUED')
        self.assertIsNone(self.state()['traffic']['request-1']['response_started_at'])

    def test_revoked_authority_prevents_offer_transaction_and_exact_retry(self):
        self.request();self.hub.observe(self.b,Readiness.SAFE)
        self.assert_code('FORBIDDEN',lambda:self.hub.prepare_delivery(self.b,authorize=lambda:False))
        self.assertEqual(self.state()['offers'],{})
        offer=self.hub.prepare_delivery(self.b,authorize=lambda:True)
        sequence=self.ledger.snapshot()['room_seq']
        self.assert_code('FORBIDDEN',lambda:self.hub.prepare_delivery(self.b,authorize=lambda:False))
        self.assertEqual(self.ledger.snapshot()['room_seq'],sequence)
        self.assertEqual(offer.envelope['id'],'request-1')

    def test_connection_replacement_cannot_confirm_old_offer(self):
        offer=self.prepared();receipt=self.b.receiver.accept(offer.envelope)
        replacement=self.connect('bob',incarnation=2)
        self.hub.observe(replacement,Readiness.SAFE)
        self.assert_code('FORBIDDEN',lambda:self.hub.confirm_delivery(self.b,offer,receipt))
        self.assert_code('DELIVERY_FENCED',lambda:self.hub.confirm_delivery(replacement,offer,receipt))
        self.assertEqual(self.state()['offers']['request-1']['bob']['outcome'],'UNCONFIRMED')

    def test_cancel_between_phases_uses_existing_confirmation_fence(self):
        offer=self.prepared();receipt=self.b.receiver.accept(offer.envelope)
        self.hub.cancel('cancel','request-1','cancel after native acceptance')
        self.assert_code('DELIVERY_FENCED',lambda:self.hub.confirm_delivery(self.b,offer,receipt))
        self.assertEqual(self.state()['traffic']['request-1']['status'],'CANCELLED')
        self.assertIsNone(self.state()['traffic']['request-1']['response_started_at'])

    def test_canonical_pause_between_phases_preserves_offer_until_resume(self):
        offer=self.prepared();receipt=self.b.receiver.accept(offer.envelope)
        control=Origin('fixture','fixture','control','fixture',('fixture-control',))
        def state_change(operation,status):
            def decide(state,_):
                state.setdefault('runs',{})['run-1']={'status':status,'generation':1}
                return Transition(state,(Event('fixture.run-state',{'status':status}),),{'status':status})
            self.ledger.apply(Command(operation,'fixture.run-state','run-1',1,{'status':status}),
                              control,authorize=lambda *_:True,decide=decide)
        state_change('fixture-pause','PAUSED')
        self.assert_code('FORBIDDEN',lambda:self.hub.confirm_delivery(self.b,offer,receipt))
        self.assertIsNone(self.hub.prepare_delivery(self.b))
        self.assertEqual(self.state()['offers']['request-1']['bob']['outcome'],'UNCONFIRMED')
        self.assertEqual(self.state()['traffic']['request-1']['status'],'QUEUED')
        self.assertIsNone(self.state()['traffic']['request-1']['response_started_at'])
        state_change('fixture-resume','ACTIVE')
        self.assertEqual(self.hub.prepare_delivery(self.b).envelope,offer.envelope)
        self.hub.confirm_delivery(self.b,offer,receipt)
        self.assertEqual(self.state()['traffic']['request-1']['status'],'DELIVERED')
        self.assertEqual(len(self.b.receiver.inbox()),1)

    def test_held_and_selected_traffic_do_not_manufacture_offers(self):
        self.request()
        self.assertIsNone(self.hub.prepare_delivery(self.b))
        self.hub.observe(self.b,Readiness.SAFE)
        self.assertIsNone(self.hub.prepare_delivery(self.b,traffic_id='missing'))
        self.assertEqual(self.state()['offers'],{})
        self.assertEqual(self.hub.prepare_delivery(self.b,traffic_id='request-1').envelope['id'],'request-1')


if __name__=='__main__':unittest.main()
