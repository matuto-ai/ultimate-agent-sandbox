"""Separate SDK host and native Claude authority for trusted Supervisor use.

The Engine-bound host owns cleanup only. A separately received SCM_PIDFD native
child is proved an immediate child in the Supervisor's pinned procfs and kept
as a distinct held object. No PID, SDK diagnostic, manifest, or callback creates
Participant authority. The existing host one-shot journal owns recovery state.
"""
from copy import deepcopy
import hashlib
import hmac
import json
import secrets
import socket
import threading
import time
import uuid
from _thread import LockType

from .git_process import GitChildAuthority, GitSeat, ProcView, _Task
from .kernel_origin import HeldOrigin, OriginDenied, Record, alive, enable, receive
from .ledger import Origin
from .native_claude_recipe import NativeClaudeRecipe
from .workstation_admission import AdmissionSeat, OPERATION
from .workstation_control import SupervisorAdmission
from .workstation_exec import ExecLaunch, ExecUnavailable, EndpointLease, RELEASE


def _authorized(authorize):
    # Additional denial only; never replaces kernel/native admission authority.
    if authorize is not None and (not callable(authorize) or authorize() is not True):
        raise OriginDenied('native reviewer authorization revoked')


class NativeClaudeHostLaunch(ExecLaunch):
    """Exact Engine task is the SDK host, NEVER the Participant native child."""
    def __init__(self, engine, recipe, endpoint, journal, *, timeout=10):
        if (type(recipe) is not NativeClaudeRecipe or type(endpoint) is not EndpointLease
                or str(endpoint.path) != recipe.endpoint or recipe.resume):
            raise OriginDenied('fresh typed Claude host recipe and exact endpoint required')
        self.recipe = recipe
        self._native_child = None
        super().__init__(engine, recipe.seat, endpoint, journal, timeout=timeout)

    def _create_spec(self):
        return self.recipe.host_spec(manifest_in_image='/opt/uas/claude-manifest.json')

    def _journal_document(self):
        # Reuse the canonical writer: incarnation checks, fsync and atomic
        # replacement remain in ExecLaunch._save.
        document = super()._journal_document()
        document['native_host_recipe'] = self.recipe.identity
        document['native_child'] = None if self._native_child is None else self._native_child.document()
        return document

    def launch(self, listener, *, authorize=None):
        _authorized(authorize)
        self.recipe.require_provider_auth()
        self.recipe.validate_container(self.engine)
        return super().launch(listener, authorize=authorize)

    def current(self):
        if (self.state != 'released' or type(self.origin) is not HeldOrigin
                or self.origin.revoked or not alive(self.origin.pidfd)):
            raise OriginDenied('SDK host unavailable')
        self.endpoint.require()
        return True

    def inspect_current(self):
        """Bounded Engine cross-check outside a lineage/ledger transaction."""
        self.current()
        value = self.engine.inspect(self.exec_id)
        if (type(value) is not dict or value.get('ID') != self.exec_id
                or value.get('ContainerID') != self.seat.container_id
                or value.get('Running') is not True or type(value.get('Pid')) is not int
                or value['Pid'] != self.origin.credentials[0]):
            raise OriginDenied('SDK host Engine identity changed')
        self.recipe.validate_container(self.engine)
        self.current()
        return True

    def activate(self, native_ready):
        raise OriginDenied('SDK host cannot become a Participant')

    def attach_native(self, **kwargs):
        raise OriginDenied('Claude child requires separate native root')


class NativeClaudeRoot:
    """One fresh native child, with host cleanup and native identity separated.

    launch() consumes the second challenge and kernel child record. current()
    may establish liveness while released for SDK initialization; only a typed
    receiver's actual fresh proof permits active admission. No journal is ever
    read to reconstruct a live root. Failure remains one-shot and fenced.
    """
    def __init__(self, host_launch, admission_seat):
        if (type(host_launch) is not NativeClaudeHostLaunch or type(admission_seat) is not AdmissionSeat
                or host_launch._native_child is not None
                or any(getattr(host_launch.seat,key) != getattr(admission_seat,key)
                       for key in ('room_id','room_instance','participant_id','actor_id'))):
            raise OriginDenied('exact unused Claude host/seat required')
        host_launch.current()
        self.host_launch, self.recipe = host_launch, host_launch.recipe
        self.seat, self.admission_seat = host_launch.seat, admission_seat
        self.host_origin, self.endpoint = host_launch.origin, host_launch.endpoint
        self.incarnation = uuid.uuid4().hex
        self.state = 'new'
        self.origin = self.channel = self.native_receiver = None
        self.native_namespace_pid = None
        self.native_namespace = self.native_pid_depth = None
        self._lineage = self._authority = None
        self._native_readiness_json = None
        self.admission = None
        self.cleanup_incomplete = False
        self.helper_lease = self.native_admission = self.forge_service = None
        self._initialize_started = False
        host_launch._native_child = self

    @property
    def scope(self):
        return self.recipe.scope

    @property
    def native_readiness(self):
        return None if self._native_readiness_json is None else json.loads(self._native_readiness_json)

    def document(self):
        return {'version':1,'state':self.state,'incarnation':self.incarnation,
            'scope':dict(self.scope),'host_identity':list(self.host_origin.identity),
            'native_identity':None if self.origin is None else list(self.origin.identity),
            'native_namespace_pid':self.native_namespace_pid,
            'native_readiness':self.native_readiness,'admission':deepcopy(self.admission),
            'cleanup_incomplete':self.cleanup_incomplete}

    def _save(self):
        self.host_launch._save()

    def _host_current(self):
        return self.host_launch.current()

    def _bind_child(self, record, challenge):
        """Consume actual kernel evidence, never an SDK-reported numeric PID."""
        if (type(record) is not Record or type(challenge) is not bytes or len(challenge)!=32
                or record.data[:4] != b'UAS1' or len(record.data)!=36
                or not hmac.compare_digest(record.data[4:],challenge)
                or record.credentials[1:] != (self.seat.host_uid,self.seat.host_gid)):
            raise OriginDenied('unmatched native Claude bootstrap')
        self._host_current()
        view = ProcView()
        task = None
        try:
            task = _Task(view,self.host_origin.credentials[0],expected=self.host_origin.identity)
            bootstrap_origin = Origin(self.seat.actor_id,self.seat.participant_id,
                self.host_launch.incarnation,'native-host-bootstrap',())
            seat = GitSeat(bootstrap_origin,self.host_origin,self._host_current,
                           task.namespace,len(task.status['NSpid']))
            self._authority = GitChildAuthority((seat,))
            self._lineage = self._authority.bind(record)
            if (len(self._lineage.tasks)!=2
                    or self._lineage.tasks[-1].identity!=self.host_origin.identity
                    or self._lineage.tasks[0].identity==self.host_origin.identity):
                raise OriginDenied('native Claude must be immediate SDK child')
            self._lineage.current()
            native_task = self._lineage.tasks[0]
            self.native_namespace_pid = native_task.status['NSpid'][-1]
            self.native_namespace = native_task.namespace
            self.native_pid_depth = len(native_task.status['NSpid'])
            self.origin = HeldOrigin(record)
        finally:
            if task is not None:task.close()
            view.close()

    def launch(self, listener, *, timeout=10, authorize=None):
        if (self.state!='new' or type(timeout) not in (int,float) or not 0<timeout<=10
                or type(listener) is not socket.socket or listener.family!=socket.AF_UNIX
                or listener.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)!=socket.SOCK_SEQPACKET
                or listener.getsockname()!=str(self.endpoint.path)):
            raise OriginDenied('one bounded native child rendezvous required')
        self.host_launch.inspect_current()
        self.endpoint.require()
        _authorized(authorize)
        self.state='creating';self._save() # before any possible child release/contact
        deadline=time.monotonic()+timeout
        def remaining():
            value=deadline-time.monotonic()
            if value<=0:raise OriginDenied('native child rendezvous expired')
            return value
        challenge=secrets.token_bytes(32)
        try:
            _authorized(authorize)
            self.host_launch.transport.write(challenge,timeout=remaining())
            enable(listener);listener.settimeout(remaining())
            self.channel,_=listener.accept();enable(self.channel);self.channel.settimeout(remaining())
            with receive(self.channel) as record:self._bind_child(record,challenge)
            challenge=None
            self.state='bound';self._save()
            self.current();self.channel.settimeout(remaining())
            _authorized(authorize)
            if self.channel.send(RELEASE)!=len(RELEASE):raise OriginDenied('incomplete native child release')
            self.state='released';self._save()
            return self
        except BaseException:
            challenge=None
            self._fail()
            raise

    def _receive_helper(self, listener, timeout, *, authorize=None):
        from .native_helper import NativeDescendantLease
        self.current();self.endpoint.require()
        deadline=time.monotonic()+timeout
        listener.settimeout(timeout)
        channel,_=listener.accept()
        try:
            enable(channel)
            remaining=deadline-time.monotonic()
            if remaining<=0:raise OriginDenied('helper initialization expired')
            channel.settimeout(remaining)
            with receive(channel) as record:
                lease=NativeDescendantLease(self,channel,record)
            self.helper_lease=lease
            remaining=deadline-time.monotonic()
            if remaining<=0:raise OriginDenied('helper initialization expired')
            channel.settimeout(remaining)
            _authorized(authorize)
            lease.release()
            return lease
        except BaseException:
            channel.close()
            raise

    def _receive_forge_helper(self, listener, timeout, *, authorize=None):
        self.current(); self.endpoint.require()
        listener.settimeout(timeout)
        forge_channel, _ = listener.accept()
        try:
            enable(forge_channel); forge_channel.settimeout(timeout)
            with receive(forge_channel) as record:
                _authorized(authorize)
                self.helper_lease.bind_forge(forge_channel, record)
        except BaseException:
            forge_channel.close()
            raise

    def initialize_helper(self, listener, *, journal, control, hub_origin,
                          controller, control_lock, operation_id, epoch,
                          timeout=8, control_timeout=2, forge_client=None, review_startup=None, authorize=None):
        """Concrete fresh SDK/native/helper startup, without a worker thread.

        The fixed host starts SDK initialization after the second challenge;
        its MCP helper connects before host-ready. Releasing that helper permits
        initialize/list only. Actual tool calls remain gated until both typed
        admissions acknowledge. Each stage is bounded; unknown transfer outcomes
        retain the same owners for status-only reconciliation, never re-send.
        The caller separately owns the already running Hub control service.
        """
        if (self._initialize_started or self.state!='new'
                or type(timeout) not in (int,float) or not 0<timeout<=10
                or type(control_timeout) not in (int,float) or not 0<control_timeout<=5
                or type(operation_id) is not str or not OPERATION.fullmatch(operation_id)
                or type(epoch) is not int or not 1<=epoch<2**53):
            raise OriginDenied('one bounded fresh helper initialization required')
        if review_startup is not None:
            from .native_review_host import NativeReviewStartup
            if type(review_startup) is not NativeReviewStartup or forge_client is None:
                raise OriginDenied('explicit native review startup and Broker required')
        _authorized(authorize)
        self._initialize_started=True
        deadline=time.monotonic()+timeout
        def remaining():
            value=deadline-time.monotonic()
            if value<=0:raise TimeoutError('native helper initialization deadline exceeded')
            return value
        transfer_attempted=False
        try:
            if authorize is None:
                self.launch(listener,timeout=remaining())
                self._receive_helper(listener,remaining())
                self._receive_forge_helper(listener,remaining())
            else:
                self.launch(listener,timeout=remaining(),authorize=authorize)
                self._receive_helper(listener,remaining(),authorize=authorize)
                self._receive_forge_helper(listener,remaining(),authorize=authorize)
            _authorized(authorize)
            self.attach_native(journal=journal,timeout=remaining())
            _authorized(authorize)
            self.native_admission=NativeClaudeSupervisorAdmission(self,self.admission_seat,
                control,hub_origin=hub_origin,controller=controller,
                control_lock=control_lock,timeout=min(control_timeout,remaining()))
            transfer_attempted=True
            _authorized(authorize)
            self.native_admission.admit(operation_id,epoch)
            self.native_admission.control.settimeout(min(control_timeout,remaining()))
            _authorized(authorize)
            self.helper_lease.admit(self.native_admission)
            _authorized(authorize)
            if forge_client is not None:
                from .native_host_forge import NativeHostForge
                self.forge_service = NativeHostForge(self.helper_lease, forge_client)
            if review_startup is not None:
                self.review_host = review_startup.attach(self.forge_service)
            _authorized(authorize)
            remaining()
            return self
        except BaseException:
            if not transfer_attempted:self._fail()
            # A possibly stored ADMIT is reconciled through native_admission.status
            # or helper_lease.status, not replaced by a fresh initialization.
            raise

    def receive_forge_once(self):
        if self.forge_service is None:
            raise OriginDenied('trusted Forge service unavailable')
        return self.forge_service.receive_once()

    def current(self):
        if (self.state not in ('bound','released','active') or type(self.origin) is not HeldOrigin
                or self.origin.revoked or not alive(self.origin.pidfd) or self._lineage is None):
            raise OriginDenied('native Claude root unavailable')
        self._host_current()
        self.endpoint.require()
        self._lineage.current()
        if self.origin.identity != self._lineage.tasks[0].identity:
            raise OriginDenied('native Claude root replaced')
        return True

    def attach_native(self, *, journal, timeout=8):
        from .native_claude_runtime import NativeClaudeReceiver
        if (self.state!='released' or self.native_receiver is not None
                or type(timeout) not in (int,float) or not 0<timeout<=10):
            raise OriginDenied('native Claude attachment is one-shot after release')
        deadline=time.monotonic()+timeout
        def remaining():
            value=deadline-time.monotonic()
            if value<=0:raise TimeoutError('native Claude readiness deadline exceeded')
            return value
        try:
            self.host_launch.inspect_current();self.current()
            receiver=NativeClaudeReceiver(self,journal=journal,timeout=remaining())
            self.native_receiver=receiver
            receiver.timeout=remaining()
            proof=receiver.prove_fresh_context(self)
            remaining()
            receiver.timeout=timeout
            expected={'runtime':'Claude','runtime_version':'2.1.310','sdk_version':'0.3.310',
                'native_pid':self.native_namespace_pid,'session_id':self.recipe.session_id,
                'scope':self.scope,'source':'fresh-home-explicit-session-native-idle-no-input','readiness':'safe'}
            if (type(proof) is not dict or proof!=expected or type(receiver) is not NativeClaudeReceiver
                    or receiver.scope!=self.scope or receiver.incarnation_id!=self.incarnation):
                raise OriginDenied('native Claude fresh proof does not match held child')
            self.current()
            metadata={'version':1,'runtime':'Claude','runtime_version':'2.1.310',
                'profile_digest':self.recipe.manifest_digest,'scope':dict(self.scope),
                'incarnation':self.incarnation,'exec_id':self.host_launch.exec_id,
                'container_id':self.seat.container_id,'origin_identity':list(self.origin.identity),
                'host_origin_identity':list(self.host_origin.identity),'native':deepcopy(proof)}
            wire=json.dumps(metadata,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
            if len(wire)>8192:raise OriginDenied('bounded native Claude readiness required')
            metadata['digest']=hashlib.sha256(wire).hexdigest()
            self._native_readiness_json=json.dumps(metadata,sort_keys=True)
            self.state='active';self._save();self.current()
            return receiver
        except BaseException:
            self._fail()
            raise

    def _fail(self):
        self.state='uncertain';self._native_readiness_json=None
        if self.origin is not None:self.origin.revoke()
        try:self._save()
        except BaseException:pass # existing intent blocks blind replacement
        try:self.close_resources()
        except BaseException:
            # Preserve the decisive launch/proof failure. The exact host launch
            # remains owned for explicit Engine cleanup/reconciliation.
            self.cleanup_incomplete=True
            try:self._save()
            except BaseException:pass

    def revoke(self):
        if self.origin is not None:self.origin.revoke()
        self.state='revoked';self._save()

    def close_resources(self):
        """Close observations/channels, NOT terminate either live process.

        host_launch deliberately stays owned; stopping its exact Engine task and
        container is the caller's canonical cleanup/reconciliation obligation.
        """
        error=None
        for name in ('helper_lease','native_receiver','channel','_lineage','_authority','origin'):
            resource=getattr(self,name);setattr(self,name,None)
            if resource is not None:
                try:resource.close()
                except BaseException as failure:error=error or failure
        if error is not None:raise error

    def close(self):
        try:self.revoke()
        finally:self.close_resources()


class NativeClaudeSupervisorAdmission(SupervisorAdmission):
    """Same bounded control protocol; only exact native-child root can enter."""
    def __init__(self, launch, seat, control, *, hub_origin, controller, control_lock, timeout=2):
        if (type(launch) is not NativeClaudeRoot or type(seat) is not AdmissionSeat
                or launch.admission_seat!=seat or launch.state!='active'
                or type(hub_origin) is not HeldOrigin or hub_origin.revoked or not alive(hub_origin.pidfd)
                or type(controller) is not str or not OPERATION.fullmatch(controller)
                or type(control_lock) is not LockType or type(timeout) not in (int,float) or not 0<timeout<=5):
            raise OriginDenied('exact active native Claude root and Hub controller required')
        launch.current()
        self.launch,self.seat,self.control=launch,seat,control
        self.hub_origin,self.controller=hub_origin,controller
        self._authority=threading.RLock();self._io=control_lock;self._fenced=False
        self._delivery_lock=threading.Lock();self._delivery_pending=None
        enable(control);control.settimeout(timeout)

    def _current(self):
        super()._current()
        self.launch.current()
