"""Inert lock-order/dispatch double checks; no kernel/runtime qualification."""
from contextlib import contextmanager
from types import SimpleNamespace as N
from unittest.mock import patch
import unittest
from uas.workstation_peer import AdmittedPeerDispatcher
from uas.ledger import Origin, LedgerError

class PeerForgeTests(unittest.TestCase):
    def make(self,helper=False):
        stack=[]; events=[]
        @contextmanager
        def locked():
            assert 'admission' not in stack, stack
            stack.append('supervisor')
            try: yield
            finally: stack.pop()
        binding=N(operation_id='root',seat=N(room_id='room',room_instance='instance'))
        @contextmanager
        def authorize(operation,record):
            assert stack and stack[0]=='supervisor' and all(x=='admission' for x in stack[1:]),stack
            events.append(('authorize',operation));stack.append('admission')
            try: yield binding
            finally: stack.pop()
        def recheck(operation,record):
            assert stack[-1]=='admission';events.append(('recheck',operation));return True
        service=N(supervisor=N(_locked=locked,_read=lambda:{'phase':'running','instance_id':'instance','spec':{'project_id':'project'}}),
            closed=False,room_instance='instance',binding=N(room_id='room',project_id='project'))
        def prepare(envelope,origin,*,authorize):
            self.assertEqual(stack,['supervisor','admission']);service.guard=authorize;return {'packet':1}
        def perform(packet):
            self.assertEqual(stack,[])
            with locked(): self.assertTrue(service.guard())
            self.assertEqual(stack,[]);return {'result':'ok'}
        service.prepare=prepare;service.perform=perform
        obj=object.__new__(AdmittedPeerDispatcher);obj.read_service=service
        obj.admissions=N(authorize=authorize,recheck=recheck,authorize_descendant=authorize,recheck_descendant=recheck)
        obj.hub=N(ledger=object(),_current=lambda conn:True);obj._connections={'root':object()}
        obj._origin=lambda value:Origin('actor','participant','incarnation','authority',('forge-read',))
        def reserve(*args):
            self.assertEqual(stack,['supervisor','admission'])
            before=len(events)
            with patch.object(obj,'_forge_room_current',side_effect=AssertionError('transaction filesystem read')):
                self.assertTrue(args[-1]())
            self.assertEqual(len(events),before+1)
            self.assertEqual(events[-1][0],'recheck')
        return obj,stack,events,reserve
    def test_direct_guard_reenters_and_perform_unlocked(self):
        obj,stack,events,reserve=self.make()
        with patch('uas.forge_read_service.reserve_forge_operation',side_effect=reserve):
            self.assertEqual(obj._forge('root',object(),{'kind':'forge-read'}),{'result':'ok'})
        self.assertEqual(stack,[]);self.assertTrue(all(value=='root' for _,value in events))
    def test_helper_guard_uses_helper_while_connection_uses_root(self):
        obj,stack,events,reserve=self.make()
        with patch('uas.forge_read_service.reserve_forge_operation',side_effect=reserve):
            obj._forge(None,object(),{'kind':'forge-read'},helper='helper')
        self.assertEqual(stack,[]);self.assertTrue(all(value=='helper' for _,value in events))
    def test_room_change_blocks_before_reserve(self):
        obj,stack,events,reserve=self.make();obj.read_service.room_instance='other'
        with patch('uas.forge_read_service.reserve_forge_operation',side_effect=AssertionError('must not reserve')):
            with self.assertRaises(LedgerError):obj._forge('root',object(),{'kind':'forge-read'})
        self.assertEqual(events,[])

class PeerReplyTests(unittest.TestCase):
    def test_large_forge_uses_canonical_chunks(self):
        from uas.forge_read_service import receive_result
        import base64, hashlib, json
        sent=[]
        channel=N(send=lambda raw:sent.append(raw) or len(raw))
        result={'request_id':'a'*32,'ok':True,'receipt':{'value':'x'*180000}}
        self.assertEqual(AdmittedPeerDispatcher._reply(channel,result,forge=True),result)
        self.assertTrue(all(len(x)<=65536 for x in sent))
        frames=[json.loads(x) for x in sent]
        self.assertEqual([x['index'] for x in frames],list(range(len(frames))))
        raw=b''.join(base64.b64decode(x['data']) for x in frames)
        self.assertTrue(all(x['sha256']==hashlib.sha256(raw).hexdigest() for x in frames))
        self.assertEqual(json.loads(raw),result)
    def test_oversize_reply_becomes_bounded_error(self):
        for size,forge in ((70000,False),(1048577,True)):
            sent=[];channel=N(send=lambda raw:sent.append(raw) or len(raw))
            result=AdmittedPeerDispatcher._reply(channel,{'request_id':'a'*32,'ok':True,'receipt':'x'*size},forge=forge)
            self.assertEqual(result['error'],'OUTPUT_LIMIT');self.assertEqual(len(sent),1)
    def test_fragment_and_oversize_request_rejected_before_dispatch(self):
        import json
        for packet in (json.dumps({'request_id':'a'*32,'index':0,'count':2,'sha256':'b'*64,'data':'eA=='}).encode(),
                       json.dumps({'request_id':'a'*32,'envelope':{'kind':'forge-write','body':'x'*65536}}).encode()):
            with self.assertRaises(LedgerError):AdmittedPeerDispatcher._decode(packet)
