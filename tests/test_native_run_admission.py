"""Actual Room admission reducers with inert typed native/checkout boundaries."""
from contextlib import ExitStack
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_native_qualification as configuration_fixture
from uas.checkouts import CheckoutAllocator
from uas.forge import ForgeBinding
from uas.forge_read_service import ReadBrokerClient
from uas.ledger import RoomLedger, Origin, LedgerError
from uas.lifecycle import Supervisor
from uas.manager_actions import HumanSession
from uas.native_admission_broker import NativeAdmissionBroker
from uas.native_checkout_handoff import NativeCheckoutClient
from uas.native_run_admission import NativeRunAdmission, NativeRunLauncher, NativeHumanRunRequest
from uas.peer import FixturePeerHub, FixtureParticipant


def fixture(test):
    tmp = tempfile.TemporaryDirectory();test.addCleanup(tmp.cleanup);root=Path(tmp.name)
    config = configuration_fixture.NativeQualificationTests();config.setUp()
    config.config['deployment']['state_root']=str(root/'state')
    for room in config.config['rooms']: room['state_root']=str(root/'state'/room['id'])
    config.config['deployment']['actors'][0]['github_user_id']=7
    plan=config.plan();room=plan.room;seat=plan.seats['pi'];instance='a'*32
    supervisor=Supervisor(root/'state',room['id'],object(),authorize=lambda *_:False,revoke=lambda *_:False)
    supervisor._read=lambda:{'phase':'running','desired':'running','instance_id':instance,'spec':{'project_id':room['project']['id']}}
    ledger=RoomLedger(root/'room.db',room['id']);test.addCleanup(ledger.close)
    hub=FixturePeerHub(ledger);hub.configure('configure',tuple(FixtureParticipant(s['participant'],s['actor']) for s in room['seats']),'qualification-scope')
    client=object.__new__(ReadBrokerClient);client.supervisor=supervisor;client.binding=ForgeBinding(room['id'],room['project']['id'],room['project']['repository']);client.room_instance=instance
    broker=NativeAdmissionBroker(ledger,client.binding,client)
    launcher=object.__new__(NativeRunLauncher);launcher.plan=plan;launcher.resources={'instance':instance}
    launcher.supervisor=supervisor;launcher.hub=hub;launcher.forge_broker=broker;launcher.started={}
    checkout=object.__new__(NativeCheckoutClient);checkout.allocate=Mock();checkout.observe=Mock()
    allocator=CheckoutAllocator(supervisor,StringIO(plan.config_text))
    owner=NativeRunAdmission(launcher,allocator,checkout)
    human=Origin('human','human','human-session','human-auth',('human-open-run',))
    session=HumanSession(plan.config['deployment']['id'],room['id'],instance,'manager',human,
                         lambda *_:True,lambda:True)
    return SimpleNamespace(owner=owner,launcher=launcher,checkout=checkout,ledger=ledger,session=session,
                           plan=plan,participant=seat['participant'],supervisor=supervisor)


class NativeRunAdmissionTests(unittest.TestCase):
    def test_reservation_is_existing_canonical_prepare_without_native_effect(self):
        f=fixture(self)
        with f.owner.human_scope(f.session):
            run,command=f.owner._prepare('open-one',1,f.participant,f.session.human)
        state=f.ledger.snapshot()['state'];row=state['run_admissions'][run]
        self.assertEqual(row['status'],'PREPARING');self.assertFalse(row['authorization_consumed'])
        self.assertEqual(state['fixture_context']['participants'][f.participant]['reserved_run'],{'run_id':run,'generation':1})
        self.assertNotIn(run,state['runs']);f.checkout.allocate.assert_not_called()
        self.assertFalse(f.launcher.started)

    def test_arbitrary_human_origin_cannot_reserve_without_session(self):
        f=fixture(self)
        with self.assertRaisesRegex(LedgerError,'FORBIDDEN'):
            f.owner._prepare('open',1,f.participant,f.session.human)
        self.assertNotIn('run_admissions',f.ledger.snapshot()['state'])

    def test_json_request_cannot_become_human_session(self):
        with self.assertRaisesRegex(LedgerError,'MANAGER_AUTHENTICATION_REQUIRED'):
            NativeHumanRunRequest('open',1,'builder',{'authorized':True})

    def test_all_unadapted_fixture_entrypoints_deny(self):
        f=fixture(self)
        names=('open','pause','resume','manager_action','manager_eligibility','migrate_policy','force_stop',
               'terminal_stop','withdraw','appoint_coordinator','reconcile_coordinator','nominate_coordinator',
               'issue_request','propose','approve_proposal','revoke_request','open_requested','submit')
        for name in names:
            with self.subTest(name=name),self.assertRaisesRegex(LedgerError,'NATIVE_RUN_CONTROL_UNAVAILABLE'):
                getattr(f.owner,name)()
        f.checkout.allocate.assert_not_called()

    def test_wrong_thread_cannot_enter_human_scope(self):
        f=fixture(self)
        with patch('uas.native_run_admission.threading.get_ident',return_value=f.owner._owner_thread+1):
            with self.assertRaisesRegex(LedgerError,'OWNER_THREAD'):
                with f.owner.human_scope(f.session):pass
        self.assertIsNone(f.owner._session)

    def test_shared_fixture_seam_keeps_runtime_refusal(self):
        from uas.run_admission import RunAdmission
        self.assertFalse(RunAdmission._runtime_binding({'runtime':'pi'},SimpleNamespace(runtime='pi-native')))
        self.assertTrue(RunAdmission._runtime_binding({'runtime':'pi'},SimpleNamespace(runtime='pi-fixture')))

    def test_actual_launcher_constructor_rejects_added_capability_or_wrong_endpoint(self):
        from dataclasses import replace
        from uas.docker_exec_api import DockerExecAPI
        from uas.kernel_origin import ReceiverIdentity
        from uas.native_session import SessionBudget
        from uas.workstation_exec import ExecSeat,EndpointLease
        from uas.workstation_admission import AdmissionSeat
        f=fixture(self);selected=f.plan.seats['pi'];room=f.plan.room
        profile=next(p for p in room['profiles'] if p['id']==selected['profile'])
        endpoint=object.__new__(EndpointLease);endpoint.path=Path('/run/uas-native/exact/peer/pi.sock')
        resources={'instance':f.session.instance_id,'peer_path':str(endpoint.path)}
        seat=ExecSeat(room['id'],f.session.instance_id,f.participant,selected['actor'],'seat-a','c'*64,165532,165532)
        admitted=AdmissionSeat(room['id'],f.session.instance_id,f.participant,selected['actor'],selected['profile'],
            tuple(sorted(set(profile['capabilities'])|{'peer-traffic'})),ReceiverIdentity(65532,65532,'hub','a'*64))
        values=dict(engine=object.__new__(DockerExecAPI),endpoint=endpoint,listener=object(),control=object(),
            hub_origin=object(),controller='a'*32,control_lock=object(),exec_seat=seat,admission_seat=admitted,
            mounts=(),stack=ExitStack(),admissions=[],budget=SessionBudget(60))
        owner=NativeRunLauncher(f.plan,resources,f.supervisor,f.ledger,f.owner.broker,**values)
        self.assertIs(owner.supervisor,f.supervisor)
        for bad in (replace(admitted,capabilities=admitted.capabilities+('can-open-requested-run',)),
                    replace(admitted,room_instance='other')):
            with self.assertRaisesRegex(LedgerError,'ADMISSION_BINDING_MISMATCH'):
                NativeRunLauncher(f.plan,resources,f.supervisor,f.ledger,f.owner.broker,**{**values,'admission_seat':bad})
        endpoint.path=Path('/run/uas-native/other/peer/pi.sock')
        with self.assertRaisesRegex(LedgerError,'ADMISSION_BINDING_MISMATCH'):
            NativeRunLauncher(f.plan,resources,f.supervisor,f.ledger,f.owner.broker,**values)

    def test_fixed_native_startup_checks_checkout_before_sdk_or_auth_load(self):
        root=Path(__file__).parents[1]
        entry=(root/'runtime/pi/native-entry.mjs').read_text()
        self.assertLess(entry.index('process.cwd() !== cwd'),entry.index('readProviderAuth(authPath'))
        self.assertLess(entry.index('process.cwd() !== cwd'),entry.index('await import('))
        bootstrap=(root/'runtime/workstation/pi-native-connector.c').read_text()
        self.assertIn('if (chdir(argv[2])) fail();',bootstrap)
        self.assertLess(bootstrap.index('if (chdir(argv[2])) fail();'),bootstrap.index('execve('))

    def test_actual_host_rejects_serialized_request_before_startup_effects(self):
        from uas.native_session import run
        f=fixture(self)
        with patch('os.getuid',return_value=165533),patch('os.getgid',return_value=165533), \
                patch('uas.native_session.probe') as probe,patch('os.umask') as umask:
            with self.assertRaisesRegex(ValueError,'AUTHENTICATED_NATIVE_RUN_REQUEST_REQUIRED'):
                run(f.plan,{'room_id':f.plan.room['id'],'instance':f.session.instance_id},3,4,
                    human_request={'session':{'authorized':True}})
        probe.assert_not_called();umask.assert_not_called()

    def test_fixed_child_main_forwards_both_fds_but_never_deserializes_human_authority(self):
        from io import BytesIO
        from uas.native_session import main
        f=fixture(self)
        startup={'configuration':f.plan.config_text,'installation':f.plan.installation,
                 'installation_digest':f.plan.installation_digest,'resources':{'room_id':f.plan.room['id']}}
        with patch('sys.argv',['native_session','3','4']),patch('sys.stdin',SimpleNamespace(buffer=BytesIO(json.dumps(startup).encode()))), \
                patch('sys.stdout',new_callable=StringIO),patch('uas.native_session.run',return_value={}) as run:
            main()
        self.assertEqual(run.call_args.args[2:],(3,4));self.assertEqual(run.call_args.kwargs,{})
        startup['human_request']={'authorized':True}
        with patch('sys.argv',['native_session','3','4']),patch('sys.stdin',SimpleNamespace(buffer=BytesIO(json.dumps(startup).encode()))), \
                patch('uas.native_session.run') as run:
            with self.assertRaisesRegex(ValueError,'INVALID_TRUSTED_STARTUP'):main()
        run.assert_not_called()

    def test_exact_launch_denial_after_preflight_prevents_engine_create(self):
        from uas.workstation_exec import ExecLaunch,ExecSeat,ExecUnavailable
        allowed=[True];engine=SimpleNamespace(create=Mock(),start=Mock())
        seat=ExecSeat('room','instance','builder','actor','seat-a','c'*64,165532,165532)
        owner=ExecLaunch(engine,seat,SimpleNamespace(require=Mock()),'/private/launch.json')
        owner._save=Mock()
        with patch('uas.workstation_exec.probe',side_effect=lambda:allowed.__setitem__(0,False)), \
                patch('uas.workstation_exec.enable'):
            with self.assertRaisesRegex(ExecUnavailable,'authorization revoked'):
                owner.launch(object(),authorize=lambda:allowed[0])
        engine.create.assert_not_called();engine.start.assert_not_called();owner._save.assert_not_called()

    def test_exact_launch_denial_after_create_never_starts_or_retries(self):
        from uas.workstation_exec import ExecLaunch,ExecSeat,ExecUnavailable
        allowed=[True]
        def create(*args):allowed[0]=False;return 'd'*64
        engine=SimpleNamespace(create=Mock(side_effect=create),start=Mock())
        seat=ExecSeat('room','instance','builder','actor','seat-a','c'*64,165532,165532)
        owner=ExecLaunch(engine,seat,SimpleNamespace(require=Mock()),'/private/launch.json')
        owner._save=Mock()
        with patch('uas.workstation_exec.probe'),patch('uas.workstation_exec.enable'):
            with self.assertRaisesRegex(ExecUnavailable,'authorization revoked'):
                owner.launch(object(),authorize=lambda:allowed[0])
            allowed[0]=True
            with self.assertRaisesRegex(ExecUnavailable,'one-shot'):
                owner.launch(object(),authorize=lambda:allowed[0])
        engine.create.assert_called_once();engine.start.assert_not_called()
        self.assertEqual(owner.state,'uncertain');self.assertEqual(owner.exec_id,'d'*64)
