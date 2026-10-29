"""Bounded real AF_UNIX packets and pipe control; no Engine/provider/process.

Run separately from the no-socket guard. Threads simulate only a root service's
packet/control order; canonical root lifecycle has its own controlled tests.
"""
import io,json,os,socket,threading,time,unittest
from unittest.mock import Mock,patch
from uas.local_successor_checkout import LocalNativeCheckoutClient
import test_local_native_run_session as host_fixture
import test_native_checkout_successor as slot_fixture

class LocalCheckoutTransportTests(unittest.TestCase):
    def test_exact_parent_pause_resume_is_serviced_while_waiting_for_checkout_reply(self):
        support=host_fixture.LocalNativeRunSessionTests();f,host=support.make();self.addCleanup(support.doCleanups)
        del host.current
        client_side,root_side=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.addCleanup(client_side.close);self.addCleanup(root_side.close)
        parent_r,parent_w=os.pipe();idle_r,idle_w=os.pipe()
        for fd in (parent_r,parent_w,idle_r,idle_w):self.addCleanup(os.close,fd)
        host.parent_fd=parent_r;host.origin.pidfd=idle_r;host.control=client_side
        host._busy=True;host._cleanup_confirmed=False
        graph=Mock();graph.transition_retirement=object();host._graph=graph
        paused=threading.Event();resumed=threading.Event();errors=[];order=[]
        output=io.BytesIO();stdout=Mock();stdout.buffer=output
        def current():
            host.current()
            if host._pause_receipt:paused.set()
            elif paused.is_set() and not host._paused:resumed.set()
        request,_,_,_,slot=slot_fixture.fixture()
        def root():
            try:
                root_side.settimeout(2)
                packet=json.loads(root_side.recv(4096));self.assertEqual(packet['kind'],'REUSE_PRIMARY')
                order.append('request');os.write(parent_w,b'P')
                self.assertTrue(paused.wait(1),'child did not service P');order.append('paused')
                os.write(parent_w,b'R');self.assertTrue(resumed.wait(1),'child did not service R')
                order.append('resumed')
                root_side.send(json.dumps({**packet,'status':'OK','slot':slot}).encode())
            except BaseException as error:errors.append(error)
        worker=threading.Thread(target=root,daemon=True)
        refreshed=[]
        client=LocalNativeCheckoutClient(client_side,deadline=time.monotonic()+2,current=current,
            after_reuse=lambda:refreshed.append(not host._paused))
        with patch('uas.local_native_run_session.alive',return_value=True), \
                patch('uas.local_native_run_session.sys.stdout',stdout):
            worker.start()
            result=client.reuse_primary(request['run_id'],request['operation_id'])
            worker.join(2)
        self.assertFalse(worker.is_alive());self.assertEqual(errors,[])
        self.assertEqual(result,slot);self.assertEqual(order,['request','paused','resumed'])
        self.assertEqual(refreshed,[True]);graph.require_retired.assert_called_once()
        graph.close.assert_not_called()
        self.assertIn(b'participants-revoked',output.getvalue());self.assertIn(b'runtime-resumed',output.getvalue())

if __name__=='__main__':unittest.main()
