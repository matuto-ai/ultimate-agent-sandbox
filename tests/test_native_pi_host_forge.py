"""Pure exact-type Pi direct-host contracts. No native/process/socket execution."""
from contextlib import nullcontext
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch
from uas.native_host_forge import NativePiHostForge
from uas.native_pi_recipe import NativePiRecipe
from uas.workstation_exec import ExecLaunch
from uas.workstation_control import SupervisorAdmission
from uas.workstation_admission import AdmissionSeat, _canonical
from uas.workstation_peer import AdmittedPeerDispatcher
from uas.forge import ForgeBinding
from uas.forge_read_service import ReadBrokerClient
from uas.lifecycle import Supervisor
from uas.kernel_origin import OriginDenied, ReceiverIdentity
from uas.ledger import LedgerError


class Channel:
    def __init__(self):self.sent=[];self.closed=False
    def settimeout(self,value):self.timeout=value
    def send(self,value):self.sent.append(value);return len(value)
    def close(self):self.closed=True
    def recv(self,*args):raise BlockingIOError()


class NativePiForgeTests(unittest.TestCase):
    def typed(self):
        # Actual exact classes, inert fields; constructor checks must not accept
        # duck-typed authority. Kernel liveness is explicitly controlled below.
        launch=object.__new__(ExecLaunch)
        launch.native_recipe=object.__new__(NativePiRecipe)
        launch.state='active';launch.origin=N(revoked=False,pidfd=22,require=Mock())
        launch.endpoint=N(require=Mock());launch.forge_channel=Channel();launch.incarnation='i'*32
        launch.admission={'state':'admitted','controller':'c'*32,'operation_id':'a'*32,'epoch':4,'readiness_digest':'d'*64}
        admission=object.__new__(SupervisorAdmission)
        admission.launch=launch;admission._fenced=False;admission.controller='c'*32
        admission.hub_origin=N(revoked=False,pidfd=23,require=Mock())
        admission.control=Channel();admission._io=nullcontext();admission.forge_service=None
        admission.seat=AdmissionSeat('room','instance','pi','builder','profile',('peer-traffic','forge-read','forge-write'),ReceiverIdentity(1000,1000,'hub','f'*64))
        supervisor=object.__new__(Supervisor);supervisor.room_id='room'
        supervisor._locked=lambda:nullcontext()
        supervisor._read=lambda:{'phase':'running','instance_id':'instance','spec':{'project_id':'project'}}
        client=object.__new__(ReadBrokerClient);client.supervisor=supervisor;client.binding=ForgeBinding('room','project','owner/repo')
        client.room_instance='instance';client.closed=False
        return admission,client

    def test_exact_typed_constructor_and_origin_match_canonical_pi(self):
        admission,client=self.typed()
        with patch('uas.workstation_control.alive',return_value=True):
            service=admission.attach_forge_service(client)
            self.assertIsInstance(service,NativePiHostForge)
            dispatcher=object.__new__(AdmittedPeerDispatcher);dispatcher.admissions=N(controller='c'*32)
            self.assertEqual(service.origin,dispatcher._origin(service.binding))
            self.assertIsNone(service.binding.native_payload_digest)
            self.assertEqual(service._reservation(),{'kind':'RESERVE_PI_FORGE'})
            with self.assertRaises(OriginDenied):admission.attach_forge_service(client)

    def test_fixture_or_unacknowledged_root_cannot_gain_direct_service(self):
        for invalid in ('fixture','unknown','controller','wrong-room'):
            admission,client=self.typed()
            if invalid=='fixture':admission.launch.native_recipe=None
            elif invalid=='unknown':admission.launch.admission['state']='unknown'
            elif invalid=='controller':admission.launch.admission['controller']='f'*32
            else:client.room_instance='other'
            with patch('uas.workstation_control.alive',return_value=True):
                with self.assertRaises(OriginDenied):NativePiHostForge(admission,client)
        with self.assertRaises(OriginDenied):NativePiHostForge(N(),N())

    def test_root_replacement_epoch_and_record_checked_after_reserve(self):
        for change in ('epoch','root','sender'):
            admission,client=self.typed()
            with patch('uas.workstation_control.alive',return_value=True):
                service=NativePiHostForge(admission,client)
                if change=='epoch':admission.launch.admission['epoch']=5
                elif change=='root':admission.launch.origin.revoked=True
                else:admission.launch.origin.require.side_effect=OriginDenied('wrong sender')
                with self.assertRaises(OriginDenied):service._current(object())

    def test_preactivation_queue_eof_and_missing_channel_fail(self):
        admission,_=self.typed();admission._empty_native_forge()
        for data in (b'queued',b''):
            admission.launch.forge_channel=N(recv=lambda *args:data)
            with self.assertRaises(OriginDenied):admission._empty_native_forge()
        admission.launch.forge_channel=None
        with self.assertRaises(OriginDenied):admission._empty_native_forge()

    def test_second_connection_matches_existing_root_and_initializes_only(self):
        from uas import workstation_exec as module
        for hello in (b'wrong',b'UAS-PI-FORGE-1\n'):
            admission,_=self.typed();launch=admission.launch;launch.state='released';launch.forge_channel=None
            launch._remaining=lambda:2
            channel=Channel();listener=N(settimeout=Mock(),accept=lambda:(channel,None))
            record=N(data=hello)
            with patch.object(module,'enable'),patch.object(module,'receive',return_value=nullcontext(record)):
                if hello==b'wrong':
                    with self.assertRaises(OriginDenied):launch._receive_native_forge(listener)
                    self.assertTrue(channel.closed);self.assertIsNone(launch.forge_channel)
                else:
                    launch._receive_native_forge(listener)
                    self.assertIs(launch.forge_channel,channel);self.assertEqual(channel.sent,[b'UAS-FORGE-RELEASE-1\n'])
                    self.assertEqual(launch.state,'released')
                launch.origin.require.assert_called_once_with(record)

    def test_native_entry_fails_closed_before_auth_or_sdk_import(self):
        root=Path(__file__).resolve().parents[1]
        text=(root/'runtime/pi/native-entry.mjs').read_text()
        self.assertLess(text.index("process.env.UAS_PI_FORGE_FD !== '4'"),text.index("readProviderAuth(authPath"))
        self.assertIn('fstatSync(4).isSocket()',text)
        self.assertIn('PI_CODING_AGENT_DIR=agentDir',text)
        bootstrap=(root/'runtime/workstation/pi-native-connector.c').read_text()
        self.assertIn('"UAS_PI_NATIVE=1"',bootstrap);self.assertIn('close_range(5',bootstrap)
        self.assertIn('argc == 8',bootstrap);self.assertIn('native-entry.mjs',bootstrap)

    def test_only_gh_selects_direct_forge_transport(self):
        root=Path(__file__).resolve().parents[1]
        text=(root/'runtime/pi/extension.mjs').read_text()
        run=text[text.index("name: 'uas_run'"):text.index("name: 'gh'")]
        self.assertIn('await channel.request',run)
        self.assertNotIn('forgeChannel.request',run)
        self.assertEqual(text.count('await forgeChannel.request'),1)

    def test_review_tool_uses_canonical_hub_schema_and_no_forge_authority(self):
        root=Path(__file__).resolve().parents[1]
        text=(root/'runtime/pi/extension.mjs').read_text()
        section=text[text.index("name: 'uas_review'"):text.index("name: 'gh'")]
        self.assertIn("['submit-for-review','review-result']",section)
        self.assertIn("['id','run_id','generation','kind','payload']",section)
        self.assertIn('await channel.request(envelope, { signal, timeoutMs: 45000 })',section)
        self.assertNotIn('forgeChannel',section)
        self.assertIn('isError: !reply.ok',section)
        self.assertNotIn('actor_id:',section)

    def test_native_only_start_hook_preserves_fixture_connector(self):
        root=Path(__file__).resolve().parents[1]
        native=(root/'uas/workstation_exec.py').read_text()
        self.assertIn("if self.native_recipe is not None:\n                self._receive_native_forge(listener)",native)
        self.assertIn('self.native_recipe.require_provider_auth()',native)
        fixture=(root/'runtime/workstation/pi-connector.c')
        if fixture.exists():self.assertNotIn('UAS-PI-FORGE',fixture.read_text())

class NativePiReserveTests(unittest.TestCase):
    def test_real_room_namespace_and_direct_authorization(self):
        import test_native_helper_owner as owner_fixture
        fixture=owner_fixture.CombinedSeamTests('test_actual_helper_dispatch_review_ledger_replay_and_revocation')
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        admission=fixture.hub;offer,binding=admission._active['a'*32]
        binding=replace(binding,seat=replace(binding.seat,capabilities=('peer-traffic','forge-read')),native_payload_digest=None)
        admission._active['a'*32]=(offer,binding)
        dispatcher=fixture.dispatcher;dispatcher.attach_host_forge_binding(ForgeBinding('room','project','owner/repo'))
        envelope={'id':'pi-forge','kind':'forge-read','argv':['pr','view','1']};digest=hashlib.sha256(_canonical(envelope)).hexdigest()
        result=dispatcher.reserve_host_forge('a'*32,None,envelope,digest)
        snap=dispatcher.hub.ledger.snapshot()
        self.assertEqual(result,{'status':'RESERVED','digest':digest})
        self.assertEqual(dispatcher.reserve_host_forge('a'*32,None,envelope,digest),result)
        self.assertEqual(dispatcher.hub.ledger.snapshot(),snap)
        offer.origin.revoke()
        with self.assertRaises(OriginDenied):dispatcher.reserve_host_forge('a'*32,None,envelope,digest)

class PiReservationWireTests(unittest.TestCase):
    def test_private_packet_exact_fields_bounds_and_no_identity_claim(self):
        from uas import workstation_admission as module
        import array,struct
        envelope={'id':'stable','kind':'forge-write','argv':['pr','comment','1'],'body':'x'*9000}
        packet={'version':1,'kind':'RESERVE_PI_FORGE','operation_id':'a'*32,
                'controller':'c'*32,'exchange_id':'e'*32,'envelope':envelope,
                'digest':hashlib.sha256(_canonical(envelope)).hexdigest()}
        def parse(value):
            wire=_canonical(value)
            ancillary=[(module.socket.SOL_SOCKET,module.socket.SCM_CREDENTIALS,struct.pack('3i',123,1000,1000)),
                       (module.socket.SOL_SOCKET,module.SCM_PIDFD,array.array('i',[888]).tobytes())]
            control=N(recvmsg=lambda *args:(wire,ancillary,0,None))
            origin=N(require=Mock())
            with patch.object(module.os,'get_inheritable',return_value=False),patch.object(module.os,'close'):
                result=module._receive_offer(control,origin,{},commands=True)
            origin.require.assert_called_once()
            return result
        self.assertEqual(parse(packet),packet)
        for extra in ({'helper_operation':'f'*32},{'origin':{'actor_id':'forged'}},{'digest':'0'*64}):
            with self.assertRaises(OriginDenied):parse({**packet,**extra})
        with self.assertRaises(OriginDenied):parse({**packet,'kind':'STATUS'})
