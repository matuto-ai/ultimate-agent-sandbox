"""Real graph/owner constructors with inert socket, Engine and endpoint seams.

Canonical admission/recruitment fixtures are explicitly controlled native I/O;
these checks do not claim host installation, provider or process qualification.
"""
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace as N
import tempfile
import unittest
from unittest.mock import Mock, patch

from uas import local_native_graph as subject
from uas.local_native_run_session import LocalNativeRunSession
from uas.manager_actions import HumanSession
from uas.native_run_admission import NativeRunAdmission, NativeRunLauncher, NativeHumanRunRequest
from uas.native_qualification import QualificationError
from uas.ledger import LedgerError
import test_local_runtime_plan as plan_fixture
import test_native_run_admission as admission_fixture
import test_native_reviewer_recruitment_adversarial as recruitment_fixture


class Channel:
    family = subject.socket.AF_UNIX
    def __init__(self, *, fileno): self.fd=fileno; self.closed=False
    def getsockopt(self, *args): return subject.socket.SOCK_SEQPACKET
    def close(self): self.closed=True


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)

    def prepared(self, *, mapped=False):
        fixture=plan_fixture.LocalRuntimePlanTests();fixture.setUp();plan=fixture.plan()
        f=admission_fixture.fixture(self)
        host=object.__new__(LocalNativeRunSession)
        host.plan=plan;host.supervisor=f.supervisor
        host.supervisor.directory=Path(plan.room['state_root'])
        host.operation_current=Mock();host.current=Mock();host.checkout_fd=77
        root=tempfile.TemporaryDirectory();self.addCleanup(root.cleanup)
        host.resources={'instance':f.session.instance_id,'peer_fd':76,'peer_path':'/run/uas/exact/pi.sock',
            'hub_ledger_path':str(Path(root.name)/'hub.db'),'supervisor_directory':root.name,
            'mapping_digest':'a'*64,'workstation_id':'c'*64}
        profile=next(p for p in plan.room['profiles'] if p['id']==plan.seats['pi']['profile'])
        metadata={'seats':[{'participant_id':plan.seats['pi']['participant'],
                           'capabilities':tuple(sorted(set(profile['capabilities'])|{'peer-traffic'}))}]}
        host.hub_channel=lambda:(object(),object(),{'controller':'controller'},metadata)
        client=f.owner.broker.client
        host.clients=lambda:(client,None)
        ids={'supervisor':165533,'runtime':165532,'hub':165531,'broker':165534}
        endpoint='/run/docker.sock'
        if mapped:
            ids={key:value+100000 for key,value in ids.items()};endpoint='/run/selected/docker.sock'
            plan.native_profile.host_profile=N(owners=ids,socket=endpoint)
        provenance=subject.GitProvenance(Path(root.name)/'git-history.db',plan.room['id'],plan.room['project']['id'])
        patch.object(subject,'GitProvenance',return_value=provenance).start()
        patch.object(subject.os,'getuid',return_value=ids['supervisor']).start()
        patch.object(subject.os,'getgid',return_value=ids['supervisor']).start()
        patch.object(subject.os,'dup',side_effect=lambda fd:fd+100).start()
        patch.object(subject.socket,'socket',Channel).start()
        patch.object(subject,'enable').start()
        patch.object(subject.EndpointLease,'_observe',return_value=(1,2,3,4)).start()
        graph=subject.LocalNativeGraph(host);self.addCleanup(graph.close)
        return graph,ids,endpoint

    def test_exact_owner_required_before_any_native_setup(self):
        with patch.object(subject.LocalNativeGraph,'_prepare') as prepare:
            with self.assertRaisesRegex(LedgerError,'LOCAL_RUN_HOST_REQUIRED'):
                subject.LocalNativeGraph(N(operation_current=Mock()))
        prepare.assert_not_called()

    def test_real_constructor_wiring_and_selected_engine_mapping(self):
        graph,ids,endpoint=self.prepared(mapped=True)
        self.assertIs(type(graph.launcher),NativeRunLauncher)
        self.assertIs(type(graph.owner),NativeRunAdmission)
        self.assertEqual(graph.engine.socket_path,endpoint)
        self.assertEqual((graph.launcher.exec_seat.host_uid,graph.launcher.exec_seat.host_gid),
                         (ids['runtime'],ids['runtime']))
        self.assertEqual((graph.launcher.endpoint.owner,graph.launcher.endpoint.group),
                         (ids['supervisor'],ids['runtime']))
        self.assertIs(graph.owner.checkout_client,graph.checkout)
        self.assertIs(graph.owner.supervisor,graph.host.supervisor)
        self.assertIsNone(graph.owner._session)
        self.assertFalse(any(type(value) is HumanSession for value in vars(graph).values()))
        graph.close();self.assertTrue(graph.peer.closed);self.assertTrue(graph.checkout.closed)

    def test_unselected_v1_endpoint_constructor_and_bounded_refresh(self):
        graph,_,endpoint=self.prepared()
        self.assertEqual(graph.engine.socket_path,endpoint)
        budget=graph.budget;old=budget.deadline
        graph._new_budget()
        self.assertIs(graph.budget,budget)
        self.assertGreaterEqual(budget.deadline,old)
        self.assertEqual(graph.checkout.deadline,budget.deadline)
        graph.host.operation_current.assert_called()

    def test_constructor_failure_closes_already_held_channels(self):
        # Fail after peer acquisition but before the new Hub ledger can be held.
        captured=[]
        original=Channel.__init__
        def capture(channel,**kw):original(channel,**kw);captured.append(channel)
        with patch.object(Channel,'__init__',capture),patch.object(subject,'RoomLedger',side_effect=LedgerError('LEDGER_FAIL')):
            with self.assertRaisesRegex(LedgerError,'LEDGER_FAIL'):self.prepared()
        self.assertEqual(len(captured),1)
        self.assertTrue(captured[0].closed)

    def test_close_always_closes_stack_when_admission_revocation_fails(self):
        graph=object.__new__(subject.LocalNativeGraph);graph.closed=False
        graph.stack=ExitStack();closed=Mock();graph.stack.callback(closed)
        revoke=Mock(side_effect=RuntimeError('revocation unknown'))
        graph.admissions=[N(revoke=revoke)]
        with self.assertRaisesRegex(QualificationError,'ADMISSION_REVOCATION_UNKNOWN'):graph.close()
        self.assertTrue(graph.closed);closed.assert_called_once();revoke.assert_called_once()
        with self.assertRaisesRegex(LedgerError,'CLEANUP_UNKNOWN'):graph.close()
        closed.assert_called_once();revoke.assert_called_once()

    def test_open_canonical_admission_and_recruitment_clear_human_scope(self):
        c=recruitment_fixture.RecruitmentAdversarialTests();c.setUp();self.addCleanup(c.doCleanups)
        # Fixture has canonically admitted the exact request with controlled
        # checkout/Broker/native boundaries. Reusing that request is idempotent.
        graph=object.__new__(subject.LocalNativeGraph)
        graph.closed=False;graph.activity=None;graph.recruitment=None
        graph.git_operations=graph.gate_operations=graph.gate_resources=None
        graph.git_resources=graph.gate_profile=None;graph.stack=ExitStack()
        graph.owner=c.admission;graph.launcher=c.launcher
        graph.host=N(plan=N(room=c.room),resources=c.launcher.resources)
        graph.provenance=c.recruitment.provenance;graph.source=c.recruitment.resolver
        graph.budget=object();graph._new_budget=Mock()
        activity=N(status=lambda:{'status':'ACTIVE','run_id':c.run_id,'generation':1})
        with patch.object(subject,'NativeReviewerRecruitment',return_value=c.recruitment),\
                patch.object(subject,'LocalRunActivity',return_value=activity) as factory:
            result=graph.open(NativeHumanRunRequest('open',1,c.participant,c.session),object())
        self.assertEqual(result['run_id'],c.run_id)
        self.assertIsNone(c.admission._session);self.assertIsNone(c.recruitment._session)
        self.assertEqual(len(c.starts),1)
        self.assertIs(graph.recruitment,c.recruitment)
        self.assertIs(factory.call_args.args[0],c.admission)
        self.assertFalse(any(type(value) is HumanSession for value in vars(graph).values()))

    def test_recruit_failure_keeps_exact_owner_and_clears_human_scope(self):
        c=recruitment_fixture.RecruitmentAdversarialTests();c.setUp();self.addCleanup(c.doCleanups)
        graph=object.__new__(subject.LocalNativeGraph);graph.closed=False;graph.activity=None
        graph.recruitment=None;graph.owner=c.admission;graph.launcher=c.launcher
        graph.provenance=c.recruitment.provenance;graph.source=c.recruitment.resolver
        graph.git_operations=None;graph.host=N(plan=N(room=c.room),resources=c.launcher.resources)
        graph._new_budget=Mock()
        c.recruitment._launch=Mock(side_effect=TimeoutError('native outcome unknown'))
        with patch.object(subject,'NativeReviewerRecruitment',return_value=c.recruitment):
            with self.assertRaises(TimeoutError):
                graph.open(NativeHumanRunRequest('open',1,c.participant,c.session),object())
        self.assertIs(graph.recruitment,c.recruitment)
        self.assertIsNone(c.admission._session);self.assertIsNone(c.recruitment._session)
        c.recruitment._launch.assert_called_once()

if __name__=='__main__':unittest.main()
