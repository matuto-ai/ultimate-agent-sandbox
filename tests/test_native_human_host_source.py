"""Consumed native hosting checks with all TLS/thread/process boundaries controlled."""
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

from uas import human_mtls as auth
from uas import native_human_control as control_module
from uas import native_human_entry as entry
from uas.ledger import LedgerError
from uas.native_broker_audit import NativeBrokerAudit
from uas.native_human_control import NativeHumanControl
from uas.native_human_launch import NativeHumanLaunch, validate_result
from uas.native_qualification import execute, QualificationPlan, QualificationError
from uas.native_session_driver import NativeHumanReviewInbox, NativeSessionDriver
from uas.run_admission import RunAdmission
from test_native_human_control_source import TLS


def control_for(test, session, operation='open', issue=1, deadline=120):
    channel=TLS();fingerprint=hashlib.sha256(channel.certificate).hexdigest()
    grant=auth.HumanActionGrant(session.deployment_id,session.room_id,session.instance_id,session.manager_id,
                                session.human,tuple(sorted(auth.ACTIONS)))
    bindings=auth.HumanActionBindings({fingerprint:grant})
    with patch.object(auth.ssl,'SSLSocket',TLS):
        control=NativeHumanControl(bindings,channel,instance_id=session.instance_id,deadline=deadline,clock=lambda:0.)
    worker=N(ident=threading.get_ident()+1,start=Mock(),join=Mock(),is_alive=lambda:False)
    with patch.object(control_module.threading,'Thread',return_value=worker):control.start()
    control._worker_thread=worker.ident
    def frame(value):
        with patch.object(control_module.threading,'get_ident',return_value=worker.ident):
            return control._accept(value)
    frame({'version':1,'action':'open-run','payload':{'operation_id':operation,'issue_number':issue}})
    control.first_request();test.addCleanup(control.close)
    return control,frame


class NativeHumanConsumedSourceTests(unittest.TestCase):
    def setUp(self):
        from test_native_broker_audit_source import NativeBrokerAuditOwnerTests
        self.fixture=NativeBrokerAuditOwnerTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture.f;self.f=f
        self.control,self.frame=control_for(self,f.session,f.request.operation_id,f.request.issue_number,f.budget.deadline)
        f.session=self.control.session;f.request=replace(f.request,session=f.session)
        self.remote=NativeBrokerAudit(self.fixture.client,f.session)
        self.inbox=NativeHumanReviewInbox(f.session,self.remote)
        self.driver=NativeSessionDriver(f.c.admission,f.c.recruitment,f.request,f.budget,
                                        human_actions=self.inbox,human_control=self.control)

    def test_verified_control_view_then_unchanged_envelope_reaches_actual_hub_and_original_audit(self):
        self.frame({'version':1,'action':'observe','payload':{}})
        self.driver._human_transport()
        view=self.control._current_view
        self.assertEqual(view['submission_id'],'submission');self.assertFalse(view['forge_uncertain'])
        packet=self.f.packet();packet.update(object_id=view['submission_id'],observed_version=view['observed_version'])
        saved=deepcopy(packet)
        reply=self.frame({'version':1,'action':'request-changes','payload':packet})
        self.assertEqual(reply['receipt'],'queued');self.assertNotIn('human-change',self.f.comments())
        result=self.driver.run()
        self.assertEqual(packet,saved)
        row=self.f.comments()['human-change'];self.assertEqual(row['status'],'confirmed',result)
        self.assertEqual(row['human_origin'],self.control.session.human.canonical())
        self.assertIs(self.inbox.audit.client,self.f.c.owner_client)
        self.assertIs(self.inbox.session,self.driver.request.session)
        self.assertEqual(self.inbox.snapshot()[0]['status'],'confirmed')
        self.assertEqual([name for name,_ in self.f.provider_calls].count('comment'),1)
        self.assertTrue(any(packet['action']=='observe' for packet in self.fixture.exchanges))

    def test_terminal_disconnect_after_queue_denies_canonical_consumption(self):
        self.frame({'version':1,'action':'request-changes','payload':self.f.packet()})
        before=self.f.c.ledger.snapshot();self.control.close()
        result=self.driver.run()
        self.assertEqual(self.f.c.ledger.snapshot(),before)
        self.assertFalse(self.f.provider_calls);self.assertFalse(self.f.comments())
        self.assertNotEqual(result['outcome'],'completed')

    def test_scope_or_broker_substitution_never_becomes_a_control_owner(self):
        other=NativeHumanReviewInbox(self.control.session,self.f.audit)
        with self.assertRaisesRegex(LedgerError,'EXACT_NATIVE_HUMAN_CONTROL'):
            NativeSessionDriver(self.f.c.admission,self.f.c.recruitment,self.f.request,self.f.budget,
                                human_actions=other,human_control=self.control)
        with self.assertRaisesRegex(LedgerError,'EXACT_NATIVE_HUMAN_CONTROL'):
            NativeSessionDriver(self.f.c.admission,self.f.c.recruitment,self.f.request,self.f.budget,
                                human_actions=self.inbox,human_control=N(session=self.control.session))


class NativeHumanRunCompositionSourceTests(unittest.TestCase):
    def test_actual_run_constructs_remote_audit_and_inbox_from_its_original_broker(self):
        from test_native_gate_session_composition import NativeGateSessionCompositionTests
        from uas import native_session
        from uas.kernel_origin import HeldOrigin
        fixture=NativeGateSessionCompositionTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        control,frame=control_for(self,fixture.request.session,fixture.request.operation_id,
                                  fixture.request.issue_number,deadline=10**9)
        fixture.request=replace(fixture.request,session=control.session)
        original_run=native_session.run;original_audit=NativeBrokerAudit.__init__
        def audit(owner,client,session):
            worker=object.__new__(HeldOrigin);worker.pidfd=900;worker.identity=(1,2);worker.revoked=False
            client.manager_audit_enabled=True;client.worker=worker
            original_audit(owner,client,session)
        def run(*args,**kwargs):return original_run(*args,**kwargs,human_control=control)
        with patch.object(native_session,'run',side_effect=run),patch.object(NativeBrokerAudit,'__init__',audit):
            result=fixture.execute()
        driver=fixture.captured['driver']
        self.assertIs(driver.human_control,control)
        self.assertIs(driver.human_actions.session,control.session)
        self.assertIs(type(driver.human_actions.audit),NativeBrokerAudit)
        self.assertIs(driver.human_actions.audit.client,driver.owner.broker.client)
        self.assertEqual(result['status'],'NATIVE_RUN_SESSION_FINISHED')
        self.assertTrue(result['human_host_attached'])
        self.assertNotIn('AUTHENTICATED_MANAGER_DISPATCH_UNAVAILABLE',result['lifecycle_blockers'])
        self.assertIn('FULL_NATIVE_RUN_COMPLETION_UNQUALIFIED',result['lifecycle_blockers'])


class NativeHumanRootSourceTests(unittest.TestCase):
    def fixture(self, *, lost=False):
        from test_native_qualification_execute import NativeQualificationExecuteTests
        fixture=NativeQualificationExecuteTests();self.addCleanup(fixture.doCleanups)
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        plan,events,broker,child=fixture.fixture(Path(tmp.name),child_timeout=lost)
        plan.installation['human_host_manifest']={'path':'/existing/grant.json','sha256':'f'*64}
        plan.seats={'pi':{'participant':'participant'}}
        channel=N(fileno=lambda:91,close=lambda:events.append('close-human-parent'))
        identity=(91,1,2,('127.0.0.1',1),('127.0.0.1',2))
        stack=ExitStack();self.addCleanup(stack.close)
        stack.enter_context(patch('uas.native_human_launch.reference',return_value=plan.installation['human_host_manifest']))
        stack.enter_context(patch('uas.native_human_launch.raw_stream_identity',return_value=identity))
        stack.enter_context(patch('uas.native_human_launch.open_grant',return_value=(92,{},(1,)*9)))
        stack.enter_context(patch('uas.native_human_launch.read_held_grant'))
        import os,subprocess
        real_close=os.close
        stack.enter_context(patch('uas.native_human_launch.os.close',side_effect=lambda fd:
            events.append('close-grant-parent') if fd==92 else real_close(fd)))
        old_spawn=subprocess.Popen.side_effect
        def spawn(argv,**kwargs):
            if argv[2]=='uas.native_human_entry':
                self.assertEqual(kwargs['pass_fds'][-2:],(91,92))
                self.assertNotIn('close-human-parent',events)
                kwargs['pass_fds']=kwargs['pass_fds'][:-2]
                events.append('fixed-human-entry')
            return old_spawn(argv,**kwargs)
        stack.enter_context(patch('subprocess.Popen',side_effect=spawn))
        from uas import native_checkout_handoff
        old_collect=native_checkout_handoff.collect_child.side_effect
        def collect(*args,**kwargs):
            prior=json.loads(old_collect(*args,**kwargs))
            return json.dumps(self.result(plan,prior['instance'])).encode()
        stack.enter_context(patch.object(native_checkout_handoff,'collect_child',side_effect=collect))
        from uas import native_qualification_backend
        provision=native_qualification_backend.provision
        from contextlib import contextmanager
        @contextmanager
        def owned(selected):
            with provision(selected) as resources:
                resources.data['room_id']=plan.room['id']
                yield resources
        stack.enter_context(patch.object(native_qualification_backend,'provision',owned))
        from uas import native_qualification
        old_write=native_qualification.write_startup.side_effect
        def write(stream,raw,deadline):
            if stream.role=='child':
                value=json.loads(raw)
                self.assertNotIn('human_origin',str(value['human_host']))
                self.assertEqual(value['human_host']['raw_fd'],91)
                self.assertIn('close-human-parent',events)
            return old_write(stream,raw,deadline)
        stack.enter_context(patch.object(native_qualification,'write_startup',side_effect=write))
        return plan,events,broker,child,channel

    def result(self,plan,instance):
        run=RunAdmission.run_id('human-open')
        return {'version':1,'status':'NATIVE_RUN_SESSION_FINISHED','room_id':plan.room['id'],'instance':instance,
            'run_id':run,'product_run_created':True,'reviewer_attached':True,'human_review_actions_attached':True,
            'human_host_attached':True,'configuration_sha256':plan.config_digest,
            'installation_sha256':plan.installation_digest,'human_host_manifest_sha256':'f'*64,
            'human_request':{'operation_id':'human-open','issue_number':78,'participant_id':'participant'},
            'session':{'current_run':run,'authority_restored_from_journal':False,'successor_started':False,
                       'runs':[],'outcome':'inconclusive'},
            'lifecycle_blockers':['FULL_NATIVE_RUN_COMPLETION_UNQUALIFIED'],'production_launcher':'disabled'}

    def test_fixed_launcher_adopts_child_before_closing_raw_and_grant_parent_copies(self):
        plan,events,broker,child,channel=self.fixture()
        result=execute(plan,human_channel=channel)
        self.assertEqual(result['status'],'NATIVE_RUN_SESSION_FINISHED')
        self.assertEqual(events.count('fixed-human-entry'),1)
        self.assertLess(events.index(('hold-child',child)),events.index('close-human-parent'))
        self.assertLess(events.index('close-human-parent'),events.index('collect-child'))
        self.assertEqual(events.count('close-human-parent'),1)
        self.assertEqual(events.count('close-grant-parent'),1)

    def test_unknown_child_result_never_launches_a_pair_fallback_or_second_human_host(self):
        import subprocess
        plan,events,broker,child,channel=self.fixture(lost=True)
        with self.assertRaises(subprocess.TimeoutExpired):execute(plan,human_channel=channel)
        self.assertEqual(events.count(('spawn','child')),1)
        self.assertEqual(events.count('fixed-human-entry'),1)
        self.assertTrue(child.terminated);self.assertFalse(broker.terminated)

    def test_root_refuses_pair_mode_or_wrong_instance_policy_request_and_completion_claim(self):
        plan,events,broker,child,channel=self.fixture()
        resources={'instance':'c'*32};value=self.result(plan,resources['instance'])
        validate_result(plan,resources,value)
        for change in ({'status':'NATIVE_PAIR_ATTACHED'},{'instance':'d'*32},
                {'human_host_manifest_sha256':'0'*64},{'run_id':'forged'},
                {'human_host_attached':False},{'lifecycle_blockers':[]},{'human_origin':{}},
                {'human_request':{**value['human_request'],'participant_id':'other'}}):
            with self.subTest(change=change),self.assertRaises(LedgerError):
                validate_result(plan,resources,{**value,**change})


class NativeHumanEntrySourceTests(unittest.TestCase):
    def setup_entry(self):
        from test_native_human_launch_source import NativeHumanLaunchSourceTests
        fixture=NativeHumanLaunchSourceTests();fixture.setUp();self.addCleanup(fixture.doCleanups);fixture.selected()
        plan=fixture.plan;resources={'room_id':plan.room['id'],'instance':'a'*32}
        value=fixture.value;origin=value['human_origin']
        from uas.ledger import Origin
        human=Origin(**{**origin,'capabilities':tuple(origin['capabilities'])})
        channel=TLS();fingerprint=hashlib.sha256(channel.certificate).hexdigest()
        grant=auth.HumanActionGrant(plan.config['deployment']['id'],plan.room['id'],resources['instance'],
                                    'manager',human,tuple(value['actions']))
        bindings=auth.HumanActionBindings({fingerprint:grant})
        selection={'grant_fd':92,'grant_identity':[1]*9,'raw_fd':91,
            'raw_identity':[91,1,2,['127.0.0.1',1],['127.0.0.1',2]],'instance':resources['instance'],'deadline':120.}
        events=[];raw=N(close=lambda:events.append('raw-close'),settimeout=lambda value:events.append(('timeout',value)))
        def wrap(channel,*,server_side):
            self.assertIs(channel,raw);self.assertTrue(server_side);events.append('TLS-in-final-host');return secure
        secure=channel;context=N(wrap_socket=wrap)
        original=entry.NativeHumanControl
        class ScriptedThread:
            def __init__(self,*,target,name,daemon):self.control=target.__self__;self.ident=threading.get_ident()+1
            def start(self):
                control=self.control;control._worker_thread=self.ident
                with patch.object(control_module.threading,'get_ident',return_value=self.ident):
                    control._accept({'version':1,'action':'open-run','payload':{'operation_id':'human-open','issue_number':78}})
            def join(self,*,timeout):self.control._close_transport()
            def is_alive(self):return False
        stack=ExitStack();self.addCleanup(stack.close)
        for target,replacement in (
            ('uas.native_human_entry.os.getuid',lambda:165533),('uas.native_human_entry.os.getgid',lambda:165533),
            ('uas.native_qualification_backend.readonly_supervisor',lambda *_:events.append('original-room-observed')),
            ('uas.native_human_entry.host_bindings',lambda *_:(events.append('protected-grant') or bindings,value['tls'])),
            ('uas.native_human_entry.socket.socket',lambda **_:(events.append('raw-in-final-host') or raw)),
            ('uas.native_human_entry.raw_stream_identity',lambda _:tuple(selection['raw_identity'])),
            ('uas.native_human_entry._context',lambda _:context),
            ('uas.native_human_entry.time.monotonic',lambda:0.),
            ('uas.native_human_entry.os.close',lambda fd:events.append(('close-fd',fd))),
            ('uas.human_mtls.ssl.SSLSocket',TLS),('uas.native_human_control.threading.Thread',ScriptedThread)):
            stack.enter_context(patch(target,replacement))
        # NativeHumanControl's default clock was captured at module definition;
        # inject only deterministic time, retaining the real typed constructor.
        stack.enter_context(patch.object(entry,'NativeHumanControl',side_effect=lambda *a,**kw:original(*a,**kw,clock=lambda:0.)))
        return plan,resources,selection,events,secure

    def test_tls_is_negotiated_after_original_room_observation_and_exact_session_reaches_run(self):
        plan,resources,selection,events,secure=self.setup_entry();captured=[]
        def run(*args,**kwargs):
            events.append('run-owner');request=kwargs['human_request'];control=kwargs['human_control']
            self.assertIs(request.session,control.session);self.assertTrue(request.session.allowed('open-run'))
            self.assertEqual((request.operation_id,request.issue_number,request.participant_id),
                             ('human-open',78,plan.seats['pi']['participant']))
            self.assertEqual(control._deadline,selection['deadline']);captured.append(control)
            return {'status':'NATIVE_RUN_SESSION_FINISHED'}
        with patch('uas.native_session.run',side_effect=run) as invoke:
            result=entry.host(plan,resources,41,44,selection=selection)
        self.assertLess(events.index('original-room-observed'),events.index('protected-grant'))
        self.assertLess(events.index('protected-grant'),events.index('TLS-in-final-host'))
        self.assertLess(events.index('TLS-in-final-host'),events.index('run-owner'))
        self.assertEqual(invoke.call_count,1);self.assertEqual(secure.closes,1)
        self.assertFalse(captured[0].session.allowed('open-run'))
        self.assertNotIn('human_origin',result);self.assertEqual(result['human_request']['issue_number'],78)

    def test_replaced_room_refuses_before_grant_tls_or_run(self):
        plan,resources,selection,events,secure=self.setup_entry()
        with patch('uas.native_qualification_backend.readonly_supervisor',side_effect=QualificationError('OBSERVER_BINDING')), \
                patch('uas.native_session.run') as run,self.assertRaisesRegex(QualificationError,'OBSERVER_BINDING'):
            entry.host(plan,resources,41,44,selection=selection)
        self.assertNotIn('protected-grant',events);self.assertNotIn('TLS-in-final-host',events);run.assert_not_called()

    def test_unavailable_existing_tls_reference_has_no_permission_or_pair_fallback(self):
        plan,resources,selection,events,secure=self.setup_entry()
        with patch.object(entry,'_context',side_effect=PermissionError('unreadable existing reference')), \
                patch('uas.native_session.run') as run,self.assertRaises(PermissionError):
            entry.host(plan,resources,41,44,selection=selection)
        run.assert_not_called();self.assertNotIn('TLS-in-final-host',events)
        self.assertIn(('close-fd',92),events);self.assertIn('raw-close',events)

    def test_uncertain_native_result_has_one_invocation_and_terminal_session(self):
        plan,resources,selection,events,secure=self.setup_entry();captured=[]
        def unknown(*args,**kwargs):captured.append(kwargs['human_control']);raise TimeoutError('original intent remains')
        with patch('uas.native_session.run',side_effect=unknown) as run,self.assertRaises(TimeoutError):
            entry.host(plan,resources,41,44,selection=selection)
        self.assertEqual(run.call_count,1);self.assertFalse(captured[0].session.allowed('open-run'))
        self.assertEqual(secure.closes,1)

    def test_cli_requires_explicit_execution_before_touching_inherited_stream(self):
        from io import StringIO
        from uas.__main__ import main
        from test_native_qualification import NativeQualificationTests
        fixture=NativeQualificationTests();fixture.setUp();plan=fixture.plan()
        with patch('uas.native_qualification.QualificationPlan.read',return_value=plan), \
                patch('sys.stdin',StringIO('{}')),patch('sys.stderr',StringIO()), \
                patch('socket.socket') as channel,patch('uas.native_qualification.execute') as run:
            code=main(['qualify-native','-','--installation','/selected','--installation-sha256','a'*64,
                       '--human-stream-fd','91'])
        self.assertEqual(code,3);channel.assert_not_called();run.assert_not_called()


class NativeHumanHostedSelectionSourceTests(unittest.TestCase):
    def test_exact_two_hosted_modules_share_existing_timeout_and_environment_gate(self):
        import ast
        root=Path(__file__).resolve().parents[1]
        workflow=(root/'.github/workflows/validate.yml').read_text()
        job=workflow.split('\n  manager-mtls:\n',1)[1].split('\n  manager-field-notes:',1)[0]
        self.assertIn('timeout-minutes: 1',job)
        self.assertIn('UAS_MANAGER_TLS_TEST: "1"',job)
        self.assertEqual(job.count('timeout --signal=TERM --kill-after=2s 40s'),1)
        self.assertIn('PYTHONPATH=tests timeout --signal=TERM --kill-after=2s 40s python3 -m unittest test_manager_tls test_native_human_tls -v',job)
        fixture=ast.parse((root/'tests/test_native_human_tls.py').read_text())
        classes=[node for node in fixture.body if isinstance(node,ast.ClassDef)]
        self.assertEqual(len(classes),1)
        self.assertEqual(ast.unparse(classes[0].bases[0]),'unittest.TestCase')
        self.assertEqual(len([node for node in classes[0].body if isinstance(node,ast.FunctionDef) and node.name.startswith('test_')]),3)
        # Source inspection only. Never import or enable hosted TLS here.


class NativeHumanAuditObservationSourceTests(unittest.TestCase):
    def test_original_broker_accepts_only_bounded_explicit_observe_scope_without_provider(self):
        from test_native_broker_audit_source import NativeBrokerAuditSourceTests, record
        from uas.native_broker_audit import KIND, _scope, serve_audit_fence
        fixture=NativeBrokerAuditSourceTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.unknown()
        origin={**fixture.packet['origin'],'capabilities':['human-open-run']}
        packet={**fixture.packet,'action':'observe','origin':origin}
        digest=_scope(packet,fixture.broker);sent=[]
        with patch('uas.native_broker_audit._holder_exited',return_value=False), \
                patch('uas.native_broker_audit.receive',return_value=record({'kind':KIND+'_RELEASE',
                    'request_id':packet['request_id'],'scope_digest':digest})), \
                patch('uas.forge_read_service.send_result',side_effect=lambda channel,identifier,value:sent.append(value)):
            serve_audit_fence(fixture.channel,fixture.broker,fixture.holder,packet)
        self.assertTrue(sent[0]['state']['blocked'])
        self.assertEqual(set(sent[0]['state']),{'version','blocked','partial','reason'})
        self.assertFalse(fixture.audit._connection().in_transaction)
        with self.assertRaises(LedgerError):
            _scope({**packet,'origin':{**origin,'capabilities':[]}},fixture.broker)
        with self.assertRaises(LedgerError):_scope({**packet,'provider':'github'},fixture.broker)
