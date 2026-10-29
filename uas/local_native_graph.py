"""Retained native composition for an explicitly admitted local Run.

All effects remain with existing owners. This graph owns their lifetime, not a
second workflow state machine. HumanSession is used only by an open/control call.
"""
from contextlib import ExitStack, closing
from io import StringIO
from pathlib import Path
import hashlib
import os
import socket
import threading

from .ledger import LedgerError, RoomLedger
from .native_session import SessionBudget, admission_cleanup, _gate_listener
from .kernel_origin import ReceiverIdentity, enable
from .docker_exec_api import DockerExecAPI
from .workstation_exec import EndpointLease, ExecSeat
from .workstation_admission import AdmissionSeat
from .forge import ForgeBinding
from .git_provenance import GitProvenance
from .checkouts import CheckoutAllocator
from .artifact_target import ArtifactSourceResolver
from .native_pi_recipe import NativeMount
from .local_successor_checkout import LocalNativeCheckoutClient
from .native_admission_broker import NativeAdmissionBroker
from .native_run_admission import NativeRunLauncher, NativeRunAdmission
from .native_reviewer_recruitment import NativeReviewerRecruitment
from .gate_evaluation import GateRoomBinding
from .local_run_activity import LocalRunActivity


class LocalNativeGraph:
    def __init__(self, host):
        from .local_native_run_session import LocalNativeRunSession
        if type(host) is not LocalNativeRunSession:raise LedgerError('LOCAL_RUN_HOST_REQUIRED')
        host.operation_current()
        self.host=host;self.stack=ExitStack();self.admissions=[];self.closed=False
        self.activity=None;self.recruitment=None;self.git_operations=None;self.transition_retirement=None
        self.suspended=False;self.stop_observations=None;self._stop_unknown=False
        self.gate_operations=None;self.gate_resources=None
        try:self._prepare()
        except BaseException:
            self.close();raise

    def _prepare(self):
        host=self.host;plan=host.plan;data=host.resources;room=plan.room
        # The profile is validated by LocalNativeProfile; qualification defaults
        # are only retained for the existing v1 profile pending #202 integration.
        profile=getattr(plan.native_profile,'host_profile',None)
        ids=({'supervisor':165533,'runtime':165532,'hub':165531,'broker':165534}
             if profile is None else profile.owners)
        if (os.getuid(),os.getgid())!=(ids['supervisor'],ids['supervisor']):
            raise LedgerError('LOCAL_NATIVE_OWNER_IDENTITY')
        self.engine=DockerExecAPI('/run/docker.sock' if profile is None else profile.socket)
        self.budget=SessionBudget(plan.operation_timeout_seconds,current=host.operation_current)
        stack=self.stack;self.peer=stack.enter_context(closing(socket.socket(fileno=os.dup(data['peer_fd']))))
        enable(self.peer)
        self.control,self.origin,self.ready,metadata=host.hub_channel()
        self.broker,self.git_broker=host.clients()
        self.ledger=RoomLedger(data['hub_ledger_path'],room['id']);stack.callback(self.ledger.close)
        self.provenance=GitProvenance(Path(data['supervisor_directory'])/'git-history.db',room['id'],room['project']['id'])
        stack.callback(self.provenance.close)
        self.allocator=CheckoutAllocator(host.supervisor,StringIO(plan.config_text))
        self.source=ArtifactSourceResolver(host.supervisor,self.allocator)
        self.git_resources=None
        if self.git_broker is not None:
            from .native_git_resources import NativeGitResources
            self.git_resources=NativeGitResources.from_session(plan,data,self.engine,
                supervisor=host.supervisor,deadline=self.budget.deadline)
            stack.callback(self.git_resources.close)
        mounts=tuple(NativeMount(room['project']['roots'][key],room['project']['roots'][key],key=='reference')
                     for key in ('repo','workspace','reference','checkouts'))+(
            NativeMount(room['state_root']+'/runtime',room['state_root']+'/runtime',False),
            NativeMount(str(Path(data['peer_path']).parent),str(Path(data['peer_path']).parent),True))
        self.gate_profile=None;self.gate_listener=None
        if self.git_resources is not None:
            mounts+=self.git_resources.profile.mounts
            self.gate_profile=getattr(self.git_resources,'gate_profile',None)
        if self.gate_profile is not None:
            mounts+=self.gate_profile.mounts
            self.gate_listener=_gate_listener(data,local_plan=plan)
            filename=Path(data['gate_endpoint_path']);info=filename.lstat()
            def remove_owned():
                try:current=filename.lstat()
                except FileNotFoundError:return
                if (current.st_dev,current.st_ino)==(info.st_dev,info.st_ino):filename.unlink()
            stack.callback(remove_owned);stack.callback(self.gate_listener.close)
        receiver=ReceiverIdentity(65532,65532,'hub-'+data['instance'],data['mapping_digest'])
        selected=plan.seats['pi']
        declared=next(s for s in metadata['seats'] if s['participant_id']==selected['participant'])
        seat=ExecSeat(room['id'],data['instance'],selected['participant'],selected['actor'],'seat-a',
                      data['workstation_id'],ids['runtime'],ids['runtime'])
        admitted=AdmissionSeat(room['id'],data['instance'],selected['participant'],selected['actor'],
                                selected['profile'],tuple(declared['capabilities']),receiver)
        self.checkout=LocalNativeCheckoutClient(socket.socket(fileno=os.dup(host.checkout_fd)),
            deadline=self.budget.deadline,current=host.current,after_reuse=self.refresh_after_reuse)
        stack.callback(self.checkout.close)
        binding=ForgeBinding(room['id'],room['project']['id'],room['project']['repository'])
        admission_broker=NativeAdmissionBroker(self.ledger,binding,self.broker)
        self.launcher=NativeRunLauncher(plan,data,host.supervisor,self.ledger,admission_broker,
            engine=self.engine,endpoint=EndpointLease(data['peer_path'],owner=ids['supervisor'],group=ids['runtime']),
            listener=self.peer,control=self.control,hub_origin=self.origin,controller=self.ready['controller'],
            control_lock=threading.Lock(),exec_seat=seat,admission_seat=admitted,mounts=mounts,stack=stack,
            admissions=self.admissions,budget=self.budget,git_resources=self.git_resources,gate_profile=self.gate_profile)
        self.owner=NativeRunAdmission(self.launcher,self.allocator,self.checkout)

    def _new_budget(self):
        self.host.operation_current()
        self.budget.__init__(self.host.plan.operation_timeout_seconds,current=self.host.operation_current)
        self.checkout.deadline=self.budget.deadline
        if self.gate_resources is not None:self.gate_resources.deadline=self.budget.deadline

    def preflight(self):
        if self.closed:raise LedgerError("LOCAL_NATIVE_GRAPH_CLOSED")
        if self.activity is not None:
            row=self.activity._row()
            if self.activity.blocked is not None:raise LedgerError("LOCAL_RUN_RECONCILIATION_REQUIRED")
            if row["status"]!="CLOSED":
                raise LedgerError("LOCAL_PREVIOUS_RUN_NOT_COMPLETED")
            if row.get("outcome")!="completed":
                from .native_completed_retirement import retirement_for, require_retired
                proof=retirement_for(self.owner,row.get("native_stop"))
                if row.get("outcome")!="stopped" or proof is None:
                    raise LedgerError("LOCAL_PREVIOUS_RUN_NOT_COMPLETED")
                require_retired(proof)

    def open(self, request, grant):
        self.preflight()
        self._new_budget()
        self.transition_retirement=None
        previous=self.recruitment
        if self.activity is not None:
            row=self.activity._row()
            if self.activity.blocked is not None:raise LedgerError('LOCAL_RUN_RECONCILIATION_REQUIRED')
            if self.git_operations is not None:self._successor_git_ready()
            if row.get('outcome')=='completed':
                operation='local-retire-'+hashlib.sha256((request.operation_id+':'+row['run_id']).encode()).hexdigest()
                self.owner.retire_for_successor(request,grant,row['run_id'],row['generation'],
                                                row['control_revision'],reviewer=previous,
                                                observations=getattr(self,'stop_observations',None))
                self.transition_retirement=self.owner._completed_retirements[operation]
            else:
                from .native_completed_retirement import retirement_for
                self.transition_retirement=retirement_for(self.owner,row.get('native_stop'))
            self.require_retired()
            self._forget_retired(self.transition_retirement)
            self._close_run_effects()
        activated=self.owner.open_human(request.operation_id,request.issue_number,request.participant_id,
                                       session=request.session,attempt_id=request.attempt_id)
        pi=self.launcher.started.get(request.participant_id)
        from .workstation_control import SupervisorAdmission
        if type(pi) is not SupervisorAdmission:raise LedgerError('LOCAL_NATIVE_OWNER_UNAVAILABLE')
        room=self.host.plan.room
        recruitment=NativeReviewerRecruitment(self.owner,pi,self.provenance,self.source,
            GateRoomBinding(room['id'],self.host.resources['instance'],room['project']['id'],
                            room['project']['repository'],room['resources']['disk_bytes']))
        self.recruitment=recruitment  # Retain unknown recruitment, never repeat blindly.
        recruitment.recruit('reviewer-'+hashlib.sha256(request.operation_id.encode()).hexdigest(),
            activated['run_id'],activated['generation'],session=request.session,reset_from=previous)
        if self.git_resources is not None:
            from .native_git_operations import NativeGitOperations
            self.git_operations=NativeGitOperations(self.owner,recruitment,self.git_resources,self.git_broker)
            self.stack.callback(self.git_operations.close)
        if self.gate_profile is not None:
            from .native_gate_resources import NativeGateResources
            from .native_gate_operations import NativeGateOperations
            from .native_gate_workflow import NativeGateWorkflow
            self.gate_resources=NativeGateResources.from_session(self.host.plan,self.host.resources,self.engine,
                supervisor=self.host.supervisor,listener=self.gate_listener,git_resources=self.git_resources,
                review_host=recruitment.root.review_host,quota_client=self.checkout,gate_profile=self.gate_profile,
                deadline=self.budget.deadline)
            self.stack.callback(self.gate_resources.close)
            self.gate_operations=NativeGateOperations(recruitment.root.review_host,self.gate_resources)
            self.stack.callback(self.gate_operations.close)
            NativeGateWorkflow(recruitment.root.review_host,self.gate_operations.control)
        activity=LocalRunActivity(self.owner,recruitment,request,self.budget,grant=grant,host=self.host,
            git_operations=self.git_operations,gate_resources=self.gate_resources)
        self.activity=activity
        self.transition_retirement=None
        self.suspended=False;self.stop_observations=None
        return activity.status()

    def _forget_retired(self, retirement):
        known=[]
        from .workstation_control import SupervisorAdmission
        for owner in retirement.owners.values():
            known.append(owner if type(owner) is SupervisorAdmission else owner.native_admission)
        self.admissions[:]=[item for item in self.admissions if all(item is not old for old in known)]

    def prepare_stop(self):
        """Root P revokes effects while retaining exact completed-Run exit proof."""
        if self.closed:return self.close()
        if self._stop_unknown:raise LedgerError('LOCAL_NATIVE_CLEANUP_UNKNOWN')
        if self.suspended:
            from .native_completed_retirement import retirement_for, require_retired
            row=self.activity._row()
            proof=retirement_for(self.owner,row.get('native_stop'))
            if row.get('outcome')=='stopped' and proof is not None:
                return require_retired(proof)
            return self.stop_observations.require_exited()
        row=None if self.activity is None else self.activity._row()
        if row is None or (row['status'] not in {'ACTIVE','PAUSED'} and
                           (row['status']!='CLOSED' or row.get('outcome')!='completed')):
            return self.close()
        from .local_native_stop import LocalNativeStopObservations
        self._stop_unknown=True
        observations=LocalNativeStopObservations(self)
        self.stop_observations=observations
        self.stack.callback(observations.close)
        observations.retire(timeout=min(30,self.host.plan.operation_timeout_seconds))
        observations.require_exited()
        self._forget_retired(observations.held)
        self._close_run_effects()
        self.suspended=True;self._stop_unknown=False
        return True

    def _successor_git_ready(self):
        # This local graph implements new PID-pinned resources after root reuse;
        # qualification GitOperations intentionally keeps its finite refusal.
        from .native_git_operations import NativeGitOperations
        if (type(self.git_operations) is not NativeGitOperations
                or self.git_operations.owner is not self.owner
                or self.git_operations.resources is not self.git_resources
                or self.git_operations.closed or self.checkout.closed):
            raise LedgerError('LOCAL_SUCCESSOR_GIT_OWNER_REQUIRED')
        self.host.plan.require_unchanged()
        self.git_resources.profile.require_checkout('primary',self.git_resources.profile.repo)

    def _close_run_effects(self):
        # Revoke old per-Run writers before root-owned Workstation Stop. Keep
        # exact retirement objects for context reset, never reuse old PID pins.
        for value in (self.gate_operations,self.git_operations,self.gate_resources,self.git_resources):
            if value is not None:value.close()
        self.gate_operations=self.git_operations=self.gate_resources=self.git_resources=None

    def refresh_after_reuse(self):
        self.host.operation_current()
        self.require_retired()
        if self.git_broker is None:return
        from .native_git_resources import NativeGitResources
        previous=self.launcher.git_resources
        resources=NativeGitResources.from_session(self.host.plan,self.host.resources,self.engine,
            supervisor=self.host.supervisor,deadline=self.budget.deadline,resume_local_listener=True)
        self.stack.callback(resources.close)
        # New process identity, same approved fixed resource/mount selection.
        if (resources.profile.document()!=previous.profile.document()
                or ((None if resources.gate_profile is None else resources.gate_profile.document())
                    != (None if previous.gate_profile is None else previous.gate_profile.document()))):
            raise LedgerError('LOCAL_SUCCESSOR_RESOURCE_SELECTION_CHANGED')
        self.git_resources=resources
        self.gate_profile=resources.gate_profile
        self.launcher.git_resources=resources
        self.launcher.gate_profile=resources.gate_profile

    def require_retired(self):
        from .native_completed_retirement import retirement_supported, require_retired
        held=self.transition_retirement
        if (self.closed or not retirement_supported(held)
                or held.owner is not self.owner or held.reviewer is not self.recruitment):
            raise LedgerError('LOCAL_NATIVE_RETIREMENT_REQUIRED')
        return require_retired(held)

    def step(self):
        if self.closed:raise LedgerError('LOCAL_NATIVE_GRAPH_CLOSED')
        if getattr(self,'suspended',False):return self.activity.status()
        return None if self.activity is None else self.activity.step()

    def close(self):
        if self.closed:
            if getattr(self,'_cleanup_unknown',False):
                raise LedgerError('LOCAL_NATIVE_CLEANUP_UNKNOWN')
            return
        # Mark unknown before the first effect. A second call can report the
        # original failure but cannot retry revocation or manufacture success.
        self.closed=True;self._cleanup_unknown=True
        if getattr(self,'_stop_unknown',False):
            self.stack.close()
            raise LedgerError('LOCAL_NATIVE_CLEANUP_UNKNOWN')
        try:
            with admission_cleanup(self.admissions):
                pass
        finally:
            self.stack.close()
        self._cleanup_unknown=False
