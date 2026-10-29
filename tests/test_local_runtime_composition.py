"""Execute actual session composition and canonical reservation with inert effects."""
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock,patch
import threading
import unittest
from uas import native_session as native
from uas.local_native_run_session import LocalNativeRunSession
from uas.local_runtime_plan import LocalRuntimePlan
from uas.native_run_admission import NativeRunAdmission,NativeHumanRunRequest
from uas.workstation_control import SupervisorAdmission
from uas.docker_exec_api import DockerExecAPI
from uas.workstation_exec import EndpointLease
from test_native_run_admission import fixture

class LocalRuntimeCompositionTests(unittest.TestCase):
    def test_actual_session_constructs_native_admission_same_ledger_session_and_retained_clients(self):
        self.composed()

    def test_actual_session_failure_revokes_admission_before_return(self):
        self.composed(fail=True)

    def composed(self, fail=False):
        f=fixture(self);source=f.plan
        plan=object.__new__(LocalRuntimePlan)
        for key in ('config','room','seats','config_text','config_digest','installation_digest'):
            setattr(plan,key,getattr(source,key))
        plan.installation={k:v for k,v in source.installation.items() if k not in {'git_manifest','gate_manifest'}}
        plan.operation_timeout_seconds=60;plan.require_unchanged=Mock()
        owner=object.__new__(LocalNativeRunSession);owner.plan=plan;owner.supervisor=f.supervisor
        owner._thread=threading.get_ident();owner.current=Mock();owner.operation_current=Mock()
        owner.clients=Mock(return_value=(f.launcher.forge_broker.client,None))
        resources={'room_id':plan.room['id'],'instance':f.session.instance_id,
            'supervisor_directory':str(f.supervisor.root.parent),'hub_ledger_path':str(f.ledger.writer_binding()[0]),
            'peer_path':'/run/local/peer/pi.sock','peer_fd':31,'mapping_digest':'a'*64,'workstation_id':'c'*64}
        profiles={p['id']:p for p in plan.room['profiles']}
        metadata={'seats':[{'participant_id':s['participant'],'capabilities':sorted(set(profiles[s['profile']]['capabilities'])|{'peer-traffic'})}
                           for s in plan.room['seats']]}
        owner.hub_channel=Mock(return_value=(object(),object(),{'controller':'a'*32},metadata))
        endpoint=object.__new__(EndpointLease);endpoint.path=Path(resources['peer_path'])
        engine=object.__new__(DockerExecAPI)
        channel=Mock();events=[];captured=[]
        def admission(this,op,issue,participant,*,session,attempt_id=None):
            captured.append(this);self.assertIs(this.ledger,f.ledger);self.assertIs(session,f.session)
            with this.human_scope(session):run,_=this._prepare(op,issue,participant,session.human)
            self.assertEqual(this.ledger.snapshot()['state']['run_admissions'][run]['status'],'PREPARING')
            held=object.__new__(SupervisorAdmission);held.revoke=Mock(side_effect=lambda:events.append('revoked'))
            this.launcher.started[participant]=held;this.launcher.admissions.append(held)
            events.append('canonical-reservation');return {'run_id':run,'generation':1}
        recruitment=Mock();driver=Mock()
        def drive():
            events.append('driver')
            if fail:raise OSError('injected native boundary failure')
            return {'current_run':'run-one','outcome':'attention','last_observed_run':{'generation':1}}
        driver.run.side_effect=drive
        with ExitStack() as stack:
            for target,value in [
                ('uas.native_session.os.getuid',lambda:165533),('uas.native_session.os.getgid',lambda:165533),
                ('uas.native_session.os.umask',Mock()),('uas.native_session.probe',Mock()),
                ('uas.native_session.enable',Mock()),('uas.native_session.os.dup',lambda fd:fd+100),
                ('uas.native_session.socket.socket',lambda **kw:channel),
                ('uas.native_session.DockerExecAPI',lambda *_:engine),
                ('uas.native_session.EndpointLease',lambda *a,**kw:endpoint),
                ('uas.native_session.RoomLedger',lambda *a:f.ledger),
                ('uas.native_session.GitProvenance',lambda *a:Mock()),
                ('uas.native_run_admission.NativeRunAdmission.open_human',admission),
                ('uas.native_checkout_handoff.NativeCheckoutClient.__init__',lambda *a,**kw:None),
                ('uas.native_checkout_handoff.NativeCheckoutClient.close',lambda *_:None),
                ('uas.native_reviewer_recruitment.NativeReviewerRecruitment',lambda *a,**kw:recruitment),
                ('uas.native_pi_restore.NativePiSameRunRestore',lambda *a,**kw:Mock()),
                ('uas.native_session_driver.NativeSessionDriver',lambda *a,**kw:driver)]:
                stack.enter_context(patch(target,value))
            bootstrap=stack.enter_context(patch('uas.native_session._hub'))
            def execute():return native.run(plan,resources,32,33,human_request=NativeHumanRunRequest('open-one',1,f.participant,f.session),local_host=owner)
            if fail:
                with self.assertRaises(OSError):execute()
                result=None
            else:result=execute()
        self.assertEqual(events,['canonical-reservation','driver','revoked'])
        if not fail:self.assertEqual(result['status'],'NATIVE_RUN_SESSION_FINISHED')
        self.assertIs(type(captured[0]),NativeRunAdmission)
        bootstrap.assert_not_called();owner.clients.assert_called_once();recruitment.recruit.assert_called_once()
        f.launcher.forge_broker.client.closed=False

if __name__=='__main__':unittest.main()
