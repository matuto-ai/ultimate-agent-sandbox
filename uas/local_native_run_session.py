"""Persistent Hub owner hosting explicit bounded authenticated native Run work.

The human request remains in its original TLS frame scope for the entire native
operation. No HumanSession is copied to a worker or retained after HTTP return.
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
from .local_host_profile import plan_owners
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
        self.participant_id=plan.seats['pi']['participant'];self._attempts={}
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
            if command==b'P': self._paused=True
            elif command==b'R' and self._pause_receipt and self._cleanup_confirmed:
                self._paused=False;self._pause_receipt=False
                receipt={'version':1,'status':'runtime-resumed','room_id':self.plan.room['id'],
                         'room_instance':self.resources['instance']}
                sys.stdout.buffer.write(json.dumps(receipt,sort_keys=True).encode()+b'\n');sys.stdout.buffer.flush()
            else: raise LedgerError('LOCAL_PARENT_OR_HUB_LOST')
        if self._paused and not self._busy and self._cleanup_confirmed and not self._pause_receipt:
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
                                    worker_uid=plan_owners(self.plan)['broker'],worker_gid=plan_owners(self.plan)['broker'])
        except BaseException:channel.close();raise
        git=None
        try:
            if self.git_fd is not None:
                git_channel=socket.socket(fileno=os.dup(self.git_fd))
                try:git=GitBrokerClient(git_channel,binding,self.resources['instance'],broker_uid=plan_owners(self.plan)['broker'],broker_gid=plan_owners(self.plan)['broker'])
                except BaseException:git_channel.close();raise
        except BaseException:broker.close();raise
        self._broker,self._git_broker=broker,git
        return broker,git

    def close(self):
        self._require_owner()
        for client in (self._git_broker,self._broker):
            if client is not None:client.close()
        self._broker=self._git_broker=None

    def open_human(self, operation_id, issue_number, *, session, attempt_id=None, next_operation_id=None, next_issue_number=None):
        self.operation_current()
        request=NativeHumanRunRequest(operation_id,issue_number,self.participant_id,session,attempt_id)
        if not session.allowed('open-run'): raise LedgerError('FORBIDDEN')
        if (next_operation_id is None)!=(next_issue_number is None):raise LedgerError('INVALID_NATIVE_SUCCESSOR')
        successor=None if next_operation_id is None else NativeHumanRunRequest(
            next_operation_id,next_issue_number,self.participant_id,session)
        if successor is not None and (successor.operation_id==operation_id or successor.issue_number==issue_number):
            raise LedgerError('INVALID_NATIVE_SUCCESSOR')
        identity=(issue_number,attempt_id,session.human,next_operation_id,next_issue_number)
        prior=self._attempts.get(operation_id)
        if prior is not None:
            if prior['identity']!=identity:raise LedgerError('ID_CONFLICT')
            if prior['result'] is None:raise LedgerError('LOCAL_RUN_OUTCOME_UNKNOWN')
            return deepcopy(prior['result'])
        if self._busy:raise LedgerError('LOCAL_RUN_OPERATION_BUSY')
        if not self._cleanup_confirmed:raise LedgerError('LOCAL_RUNTIME_CLEANUP_UNKNOWN')
        if self._attempts:raise LedgerError('LOCAL_RUN_NEW_EPOCH_UNSUPPORTED')
        row={'identity':identity,'result':None};self._attempts[operation_id]=row;self._busy=True
        self._cleanup_confirmed=False
        try:
            from .native_session import run
            result=run(self.plan,dict(self.resources),self.broker_fd,self.checkout_fd,self.git_fd,
                       human_request=request,next_request=successor,local_host=self)
            self._cleanup_confirmed=True
            observed=result['session'].get('last_observed_run') or {}
            outcome=result['session']['outcome']
            if outcome not in {'completed','attention','unknown','inconclusive'}:
                raise LedgerError('LOCAL_RUN_RESULT_INVALID')
            receipt={'status':'finished','run_id':result['run_id'],
                     'generation':observed.get('generation',1),'outcome':outcome}
            row['result']=receipt
            return deepcopy(receipt)
        finally:
            self._busy=False
