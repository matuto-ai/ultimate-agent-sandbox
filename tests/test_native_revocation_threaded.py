"""Hosted thread-affinity regression; intentionally excluded from local guards."""
import threading
import unittest
import test_native_revocation as fixture

class NativeThreadedRevocationTests(unittest.TestCase):
    def test_other_thread_publishes_lost_through_same_store_without_reusing_connection(self):
        f=fixture.RevocationTests('test_root_loss_publishes_existing_attachment_lost')
        f.setUp();self.addCleanup(f.doCleanups)
        f.hub._lock=threading.RLock()
        errors=[];before=f.f.f.ledger.snapshot()['room_seq']
        def revoke():
            try:f.hub.revoke('a'*32)
            except BaseException as error:errors.append(error)
        worker=threading.Thread(target=revoke)
        worker.start();worker.join(6)
        self.assertFalse(worker.is_alive(),'bounded same-store revocation did not finish')
        self.assertEqual(errors,[])
        events=f.f.f.ledger.replay(before)
        self.assertEqual([event['kind'] for event in events],['peer.observed'])
        self.assertEqual(events[0]['payload']['readiness'],'lost')
        self.assertEqual(f.state()['readiness'],'lost')
