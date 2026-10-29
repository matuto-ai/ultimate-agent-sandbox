"""Actual Hub attachment hook over canonical ledger; no event-loop/native I/O."""
import unittest
from dataclasses import replace
from types import MappingProxyType
from unittest.mock import patch
from uas.workstation_hub import AdmittedHubLoop
from uas.kernel_origin import OriginDenied
from uas.ledger import LedgerError
from uas.context import FixtureRun
import test_native_helper_owner as fixture

class NativeHubContextTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.CombinedSeamTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.dispatcher._connections.clear()
        offer,binding=self.f.hub._active['a'*32]
        self.f.hub._active['a'*32]=(offer,replace(binding,incarnation='fresh-native-incarnation'))
        self.loop=object.__new__(AdmittedHubLoop)
        self.loop.admissions=self.f.hub;self.loop.dispatcher=self.f.dispatcher
        self.loop.context_generations=MappingProxyType({'builder-seat':1})
        self.loop.canonical_context_generations=True
    def generation(self,value,status='READY'):
        def change(state):
            state['fixture_context']['participants']['builder-seat'].update(context_generation=value,status=status)
        self.f.f.seed(change)
    def successor(self,complete=True):
        self.f.f.seed(lambda state:state['fixture_context']['runs']['run'].update(status='CLOSED'))
        contexts=self.f.f.peer.contexts
        contexts.open_run('next-context',FixtureRun('successor'))
        contexts.request_reset('reset-context','builder-seat',1,FixtureRun('successor'))
        if complete:contexts.succeed_reset('reset-context',1,authorize=lambda:True)
    def test_real_attach_uses_canonical_successor_not_startup_generation(self):
        self.successor();self.loop._attach('a'*32)
        self.assertEqual(2,self.f.f.state()['peer_traffic']['connections']['builder-seat']['context_generation'])
    def test_default_fixed_generation_still_rejects_changed_context(self):
        self.generation(2);self.loop.canonical_context_generations=False
        with self.assertRaises((LedgerError,OriginDenied)):self.loop._attach('a'*32)
    def test_resetting_or_missing_context_never_falls_back_to_one(self):
        self.successor(complete=False)
        with self.assertRaisesRegex(OriginDenied,'canonical ready'):self.loop._attach('a'*32)
    def test_context_change_after_lookup_rejected_by_actual_connect(self):
        self.generation(2);connect=self.f.f.peer.connect
        def changed(*args,**kwargs):
            self.generation(3);return connect(*args,**kwargs)
        with patch.object(self.f.f.peer,'connect',side_effect=changed):
            with self.assertRaises((LedgerError,OriginDenied)):self.loop._attach('a'*32)
        self.assertNotEqual(2,self.f.f.state()['peer_traffic']['connections']['builder-seat']['context_generation'])

    def test_pi_binding_also_attaches_succeeded_generation_two(self):
        offer,binding=self.f.hub._active['a'*32]
        self.f.hub._active['a'*32]=(offer,replace(binding,native_payload_digest=None))
        self.successor();self.loop._attach('a'*32)
        self.assertEqual(2,self.f.f.state()['peer_traffic']['connections']['builder-seat']['context_generation'])
