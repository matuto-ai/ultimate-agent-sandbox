"""Retained completed-Run exit observations across an operator Room Stop.

The root P channel authorizes revocation, not a human Run mutation. This object
keeps exact live-owner captures; it cannot reconstruct authority from a ledger.
Only a later fresh human command may adopt it into completed retirement.
"""
from copy import deepcopy
import time

from .ledger import LedgerError
from .native_completed_retirement import NativeCompletedRetirement
from .native_pi_retirement import NativePiRetirement
from .native_claude_retirement import NativeClaudeRetirement
from .workstation_control import SupervisorAdmission


class LocalNativeStopObservations:
    def __init__(self, graph):
        from .local_native_graph import LocalNativeGraph
        from .local_runtime_plan import LocalRuntimePlan
        if (type(graph) is not LocalNativeGraph or graph.closed
                or type(graph.host.plan) is not LocalRuntimePlan
                or graph.owner.launcher is not graph.launcher
                or graph.launcher.plan is not graph.host.plan
                or graph.recruitment is None):
            raise LedgerError('LOCAL_STOP_OWNER_REQUIRED')
        self.graph=graph;self.owner=graph.owner;self.reviewer=graph.recruitment
        self.run_id=self.reviewer.pi.launch.native_recipe.scope['run_id']
        self.held=NativeCompletedRetirement(self.owner,self.reviewer,'local-stop-observation',self.run_id)
        self.started=False;self.unknown=False;self.complete=False;self.adopted=None;self.closed=False
        with self.owner.supervisor._locked() as capability:
            self.owner._room()
            state=self.owner.ledger.snapshot()['state'];row=state.get('runs',{}).get(self.run_id)
            if (not row or row.get('status')!='CLOSED' or row.get('outcome')!='completed'
                    or row.get('control_pending') is not None):
                raise LedgerError('LOCAL_STOP_COMPLETED_RUN_REQUIRED')
            self.generation=row['generation'];self.revision=row.get('control_revision',0)
            self.digest=self.owner._completion_digest(row)
            self.targets=deepcopy(self.held._targets(state))
            self.held.targets=deepcopy(self.targets)
            self._unchanged()
            # Capture ALL pidfds while every original admission is still live.
            # No retirement or graph close may occur between these captures.
            for target in self.targets:
                participant=target['participant_id'];held=self.held.owners[participant]
                cls=NativePiRetirement if type(held) is SupervisorAdmission else NativeClaudeRetirement
                retirement=cls(held,lifecycle=capability)
                self.held.retirements[participant]=retirement
                graph.stack.callback(retirement.close)
            self._unchanged()

    def _unchanged(self):
        if (self.closed or self.graph.closed or self.graph.owner is not self.owner
                or self.graph.recruitment is not self.reviewer):
            raise LedgerError('LOCAL_STOP_OWNER_CHANGED')
        self.graph.host.plan.require_unchanged()
        state=self.owner.ledger.snapshot()['state'];row=state.get('runs',{}).get(self.run_id)
        if (not row or row.get('status')!='CLOSED' or row.get('outcome')!='completed'
                or row.get('generation')!=self.generation
                or self.owner._completion_digest(row)!=self.digest
                or self.held._targets(state)!=self.targets):
            raise LedgerError('LOCAL_STOP_SCOPE_CHANGED')
        self.held._validate_owners()
        return row

    def retire(self, timeout=10):
        # Unknown effects are sticky. This is not an automatic retry engine.
        if self.unknown:raise LedgerError('LOCAL_STOP_CLEANUP_UNKNOWN')
        if self.complete:return self.require_exited()
        if self.started:raise LedgerError('LOCAL_STOP_CLEANUP_UNKNOWN')
        if type(timeout) not in (int,float) or not 0<timeout<=30:
            raise ValueError('local retirement timeout must be within thirty seconds')
        self.started=True;self.unknown=True
        deadline=time.monotonic()+timeout
        for target in self.targets:
            self._unchanged()
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('local Stop retirement deadline')
            self.held.retirements[target['participant_id']].retire(timeout=remaining)
        self._unchanged()
        for target in self.targets:
            participant=target['participant_id']
            self.held.retirements[participant].require_exited(self.held.owners[participant])
        self.complete=True;self.unknown=False
        return True

    def require_exited(self):
        if self.unknown or not self.complete:raise LedgerError('LOCAL_STOP_CLEANUP_UNKNOWN')
        self._unchanged()
        for target in self.targets:
            participant=target['participant_id']
            self.held.retirements[participant].require_exited(self.held.owners[participant])
        return True

    def adopt_completed(self, owner, reviewer, operation, run):
        return NativeCompletedRetirement.from_local_stop(self,owner,reviewer,operation,run)

    def close(self):
        if self.closed:return
        self.closed=True
        for retirement in self.held.retirements.values():retirement.close()
