"""Real held child origins, synthetic native receipts: not native qualification."""
import unittest
import json
from unittest.mock import patch
import test_workstation_peer as fixture
from uas.kernel_origin import OriginDenied, enable, receive
from uas.ledger import LedgerError
from uas.peer import digest, MAX_TEXT_BYTES
from uas.workstation_admission import _canonical, DELIVERY_REPLY_LIMIT


class DispatcherDeliveryTests(unittest.TestCase):
    setUpClass = classmethod(fixture.AdmittedPeerTests.setUpClass.__func__)
    setUp = fixture.AdmittedPeerTests.setUp
    packet = fixture.AdmittedPeerTests.packet
    exchange = fixture.AdmittedPeerTests.exchange

    def offered(self):
        self.assertTrue(self.exchange(0, self.packet())['ok'])
        result = self.dispatcher.delivery(self.operations[1], 'POLL_DELIVERY')
        self.assertEqual(result['status'], 'OFFER')
        e = result['envelope']
        receipt = {k:e[k] for k in ('delivery_id','participant_id','incarnation_id','context_generation')}
        receipt['digest'] = digest(e)
        return result, receipt

    def test_offer_and_confirm_retries_preserve_exact_existing_receipt(self):
        result, receipt = self.offered()
        before = self.ledger.snapshot()['room_seq']
        self.assertEqual(self.dispatcher.delivery(self.operations[1], 'POLL_DELIVERY'), result)
        self.assertEqual(self.ledger.snapshot()['room_seq'], before)
        confirmed = self.dispatcher.delivery(self.operations[1], 'CONFIRM_DELIVERY', receipt)
        self.assertEqual(confirmed['status'], 'CONFIRMED')
        self.assertEqual(confirmed['receipt']['result'], receipt)
        before = self.ledger.snapshot()['room_seq']
        self.assertEqual(self.dispatcher.delivery(self.operations[1], 'CONFIRM_DELIVERY', receipt), confirmed)
        self.assertEqual(self.ledger.snapshot()['room_seq'], before)
        self.assertEqual(self.dispatcher.delivery(self.operations[1], 'POLL_DELIVERY'), {'status':'HELD'})

    def test_receipt_from_other_seat_or_forged_digest_has_no_confirmation(self):
        _, receipt = self.offered()
        before = self.ledger.snapshot()
        for invalid in ({**receipt,'participant_id':'alice'}, {**receipt,'digest':'0'*64}):
            with self.assertRaises(LedgerError):
                self.dispatcher.delivery(self.operations[1], 'CONFIRM_DELIVERY', invalid)
        with self.assertRaises(LedgerError):
            self.dispatcher.delivery(self.operations[0], 'CONFIRM_DELIVERY', receipt)
        self.assertEqual(self.ledger.snapshot(), before)

    def test_late_revocation_never_confirms_native_effect(self):
        _, receipt = self.offered()
        self.admissions.revoke(self.operations[1])
        before = self.ledger.snapshot()
        with self.assertRaises(OriginDenied):
            self.dispatcher.delivery(self.operations[1], 'CONFIRM_DELIVERY', receipt)
        self.assertEqual(self.ledger.snapshot(), before)

    def test_pure_transaction_recheck_rolls_back_confirmation(self):
        _, receipt = self.offered()
        before = self.ledger.snapshot()
        real = self.admissions.recheck
        def check(*args):
            self.assertTrue(self.admissions._lock._is_owned())
            return False if self.ledger._db.in_transaction else real(*args)
        with patch.object(self.admissions,'recheck',side_effect=check):
            with self.assertRaises(LedgerError):
                self.dispatcher.delivery(self.operations[1], 'CONFIRM_DELIVERY', receipt)
        self.assertEqual(self.ledger.snapshot(), before)

    def test_cached_poll_rechecks_run_scope_before_native_effect(self):
        self.offered()
        with patch.object(self.hub,'_scope_permits',return_value=False):
            self.assertEqual(self.dispatcher.delivery(self.operations[1], 'POLL_DELIVERY'), {'status':'HELD'})

    def test_maximum_text_crosses_real_authenticated_control_and_later_work_progresses(self):
        enable(self.sender)
        sequence = 0
        def control(kind, receipt=None):
            nonlocal sequence
            sequence += 1
            command={'version':1,'kind':kind,'operation_id':self.operations[1],
                     'controller':self.admissions.controller,'exchange_id':format(sequence,'032x')}
            if receipt is not None:command['receipt']=receipt
            self.sender.send(_canonical(command))
            self.admissions.serve_once(self.control,on_delivery=self.dispatcher.delivery)
            with receive(self.sender) as record:
                self.supervisor.require(record)  # This fixture's actual Hub task.
                self.assertLessEqual(len(record.data),DELIVERY_REPLY_LIMIT)
                reply=json.loads(record.data)
                self.assertEqual(reply['exchange_id'],command['exchange_id'])
                return reply['result']
        for index,text in enumerate(('a'*MAX_TEXT_BYTES,'é'*(MAX_TEXT_BYTES//2),
                                     '😀'*(MAX_TEXT_BYTES//4),'later-small-message')):
            packet=self.packet(identity='sized-'+str(index))
            packet['envelope']['payload']['text']=text
            self.assertTrue(self.exchange(0,packet)['ok'])
            offered=control('POLL_DELIVERY')['envelope']
            self.assertEqual(offered['text'],text)
            self.assertEqual(offered['id'],'sized-'+str(index))
            receipt={k:offered[k] for k in ('delivery_id','participant_id','incarnation_id','context_generation')}
            receipt['digest']=digest(offered)
            self.assertEqual(control('CONFIRM_DELIVERY',receipt)['receipt']['result'],receipt)
        self.assertEqual(control('POLL_DELIVERY'),{'status':'HELD'})

    def test_oversize_text_denied_before_admission_and_later_message_delivers(self):
        for text in ('a'*(MAX_TEXT_BYTES+1),'é'*(MAX_TEXT_BYTES//2+1),'😀'*(MAX_TEXT_BYTES//4+1)):
            packet=self.packet(identity='oversize')
            packet['envelope']['payload']['text']=text
            self.assertEqual(self.exchange(0,packet)['error'],'INVALID_PAYLOAD')
        self.assertEqual(self.hub._state()['traffic'],{})
        offered,receipt=self.offered()
        self.assertEqual(offered['envelope']['id'],'message-1')
        self.assertEqual(self.dispatcher.delivery(self.operations[1],'CONFIRM_DELIVERY',receipt)['status'],'CONFIRMED')
