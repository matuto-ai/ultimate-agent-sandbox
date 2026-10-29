"""Persistent local owner; requests admit work, never lend human authority.

Native custody survives a successful admission response. Every new human command
uses its own live request; only a narrow revocation lease follows an admitted Run.
"""
from contextlib import ExitStack
from copy import deepcopy
import os
import select
import socket
import threading
import sys
import json

from .ledger import LedgerError
from .kernel_origin import alive
from .local_runtime_plan import LocalRuntimePlan
from .local_native import readonly_local_supervisor
from .native_run_admission import NativeHumanRunRequest


class LocalNativeRunSession:
    def __init__(self, plan, resources, *, control, origin, ready, metadata,
                 broker_fd, checkout_fd, git_fd=None, parent_fd=0):
        if type(plan) is not LocalRuntimePlan: raise LedgerError('LOCAL_RUNTIME_PLAN_REQUIRED')
        self.plan=plan;self.resources=deepcopy(resources)
        self.control,self.origin,self.ready,self.metadata=control,origin,deepcopy(ready),deepcopy(metadata)
        self.broker_fd,self.checkout_fd,self.git_fd=broker_fd,checkout_fd,git_fd
        self.parent_fd=parent_fd;self._thread=threading.get_ident();self._busy=False
        self._paused=False;self._pause_receipt=False;self._cleanup_confirmed=True
        self._broker_attempted=False;self._broker=None;self._git_broker=None
        self._transition_paused=False
        self.participant_id=plan.seats['pi']['participant'];self._attempts={};self._graph=None
        self.supervisor=readonly_local_supervisor(plan,resources)
        self.current()

    def _require_owner(self):
        if threading.get_ident()!=self._thread: raise LedgerError('LOCAL_RUN_OWNER_THREAD')

    def current(self):
        self._require_owner();self.plan.require_unchanged()
        if self.origin.revoked or not alive(self.origin.pidfd): raise LedgerError('LOCAL_HUB_OWNER_LOST')
        readable,_,failed=select.select([self.parent_fd,self.origin.pidfd],[],[self.control],0)
        if failed or self.origin.pidfd in readable: raise LedgerError('LOCAL_PARENT_OR_HUB_LOST')
        if self.parent_fd in readable:
            command=os.read(self.parent_fd,1)
            if command==b'P':
                self._paused=True
                if self._graph is not None:
                    self._cleanup_confirmed=False
                    if self._busy and self._graph.transition_retirement is not None:
                        # The root checkout owner is waiting for proof before
                        # canonical Stop. Exact exited owners remain retained
                        # for context reset; no participant effect is serviced.
                        self._graph.require_retired()
                        self._transition_paused=True
                    else:self._graph.prepare_stop()
                    self._cleanup_confirmed=True
            elif command==b'R' and self._pause_receipt and self._cleanup_confirmed:
                self._paused=False;self._pause_receipt=False;self._transition_paused=False
                receipt={'version':1,'status':'runtime-resumed','room_id':self.plan.room['id'],
                         'room_instance':self.resources['instance']}
                sys.stdout.buffer.write(json.dumps(receipt,sort_keys=True).encode()+b'\n');sys.stdout.buffer.flush()
            else: raise LedgerError('LOCAL_PARENT_OR_HUB_LOST')
        if (self._paused and (not self._busy or self._transition_paused)
                and self._cleanup_confirmed and not self._pause_receipt):
            receipt={'version':1,'status':'participants-revoked','room_id':self.plan.room['id'],
                     'room_instance':self.resources['instance']}
            sys.stdout.buffer.write(json.dumps(receipt,sort_keys=True).encode()+b'\n');sys.stdout.buffer.flush()
            self._pause_receipt=True
        if (self.ready.get('room_id')!=self.plan.room['id']
                or self.ready.get('room_instance')!=self.resources['instance']):
            raise LedgerError('LOCAL_HUB_SCOPE')

    def operation_current(self):
        self.current()
        if self._paused:raise LedgerError('LOCAL_RUNTIME_PAUSED')

    def hub_channel(self):
        self.current()
        return self.control,self.origin,deepcopy(self.ready),deepcopy(self.metadata)

    def clients(self):
        """One HELLO per retained authenticated broker stream, never per Run."""
        self.current()
        if self._broker_attempted:
            if self._broker is None:raise LedgerError('LOCAL_BROKER_OUTCOME_UNKNOWN')
            return self._broker,self._git_broker
        self._broker_attempted=True
        from .forge import ForgeBinding
        from .forge_read_service import ReadBrokerClient
        from .git_service import GitBrokerClient
        binding=ForgeBinding(self.plan.room['id'],self.plan.room['project']['id'],
                             self.plan.room['project']['repository'])
        channel=socket.socket(fileno=os.dup(self.broker_fd))
        try:
            broker=ReadBrokerClient(channel,self.supervisor,binding,self.resources['instance'],
                                    worker_uid=165534,worker_gid=165534)
        except BaseException:channel.close();raise
        git=None
        try:
            if self.git_fd is not None:
                git_channel=socket.socket(fileno=os.dup(self.git_fd))
                try:git=GitBrokerClient(git_channel,binding,self.resources['instance'],broker_uid=165534,broker_gid=165534)
                except BaseException:git_channel.close();raise
        except BaseException:broker.close();raise
        self._broker,self._git_broker=broker,git
        return broker,git

    def close(self):
        self._require_owner()
        if self._graph is not None:
            self._cleanup_confirmed=False
            self._graph.close()
            self._cleanup_confirmed=True
        for client in (self._git_broker,self._broker):
            if client is not None:client.close()
        self._broker=self._git_broker=None

    def step(self):
        self.current()
        if self._paused or self._graph is None or self._graph.closed:return
        result=self._graph.step()
        if result is not None and result.get('status')=='attention':
            # Lost grant, changed scope or uncertain I/O cannot leave native
            # effects being serviced while only the UI reports a failure.
            self._cleanup_confirmed=False
            self._graph.close()
            self._cleanup_confirmed=True

    def open_human(self, operation_id, issue_number, *, session, grant=None, attempt_id=None,
                   next_operation_id=None, next_issue_number=None):
        from .human_mtls import AdmittedRunGrant
        self.operation_current()
        request=NativeHumanRunRequest(operation_id,issue_number,self.participant_id,session,attempt_id)
        if not session.allowed('open-run') or not session.allowed('authorize-run-request'):
            raise LedgerError('FORBIDDEN')
        if next_operation_id is not None or next_issue_number is not None:
            raise LedgerError('LOCAL_EXPLICIT_SEPARATE_RUN_REQUIRED')
        if (type(grant) is not AdmittedRunGrant or grant.operation_id!=operation_id
                or grant.issue_number!=issue_number or grant.human!=session.human
                or grant.deployment_id!=session.deployment_id or grant.room_id!=session.room_id
                or grant.instance_id!=session.instance_id or grant.manager_id!=session.manager_id):
            raise LedgerError('LOCAL_ADMISSION_GRANT_REQUIRED')
        grant.require_current()
        identity=(issue_number,attempt_id,session.human,session.manager_id)
        prior=self._attempts.get(operation_id)
        if prior is not None:
            if prior['identity']!=identity:raise LedgerError('ID_CONFLICT')
            if prior['result'] is None:raise LedgerError('LOCAL_RUN_OUTCOME_UNKNOWN')
            return deepcopy(prior['result'])
        if self._busy:raise LedgerError('LOCAL_RUN_OPERATION_BUSY')
        if not self._cleanup_confirmed:raise LedgerError('LOCAL_RUNTIME_CLEANUP_UNKNOWN')
        if self._graph is not None:
            self._graph.preflight()
            if (self._graph.activity is not None
                    and 'human-control-run' not in session.human.capabilities):
                raise LedgerError('LOCAL_SUCCESSOR_RETIREMENT_AUTHORITY_REQUIRED')
        row={'identity':identity,'result':None};self._attempts[operation_id]=row;self._busy=True
        self._cleanup_confirmed=False
        try:
            from .local_native_graph import LocalNativeGraph
            if self._graph is None:self._graph=LocalNativeGraph(self)
            result=self._graph.open(request,grant)
            if result.get('status')!='ACTIVE':raise LedgerError('LOCAL_ADMISSION_RESULT_INVALID')
            grant.require_current()
            if not session.allowed('open-run'):raise LedgerError('FORBIDDEN')
            receipt={key:result[key] for key in ('status','run_id','generation')}
            row['result']=receipt
            self._cleanup_confirmed=True
            return deepcopy(receipt)
        except BaseException:
            if self._graph is not None:
                try:
                    self._graph.close()
                    self._cleanup_confirmed=True
                except Exception:pass
            raise
        finally:self._busy=False
