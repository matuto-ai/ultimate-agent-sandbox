"""Typed same-Run Pi graph replacement; existing effect owners are never rebuilt."""
from .kernel_origin import OriginDenied
from .ledger import LedgerError
from .native_host_forge import NativePiHostForge
from .native_review_host import NativeReviewHost
from .native_run_admission import NativeRunAdmission
from .native_reviewer_recruitment import NativeReviewerRecruitment
from .workstation_control import SupervisorAdmission


class NativePiRebind:
    """Prepared on the host owner thread; validation precedes every assignment.

    Gate controls/offers/launches, Git coordinator/unknown operations, listeners,
    review receipts and provenance stay with their original objects. Old lineage
    bindings keep their revoked old process, not the replacement process.
    """
    def __init__(self, owner, recruitment, old, git=None):
        if (type(owner) is not NativeRunAdmission or type(recruitment) is not NativeReviewerRecruitment
                or recruitment.owner is not owner or type(old) is not SupervisorAdmission
                or recruitment.pi is not old or type(old.forge_service) is not NativePiHostForge
                or type(recruitment.root.review_host) is not NativeReviewHost):
            raise LedgerError('NATIVE_RESTORE_GRAPH_REQUIRED')
        self.owner, self.recruitment, self.old, self.git = owner, recruitment, old, git
        self.host = recruitment.root.review_host
        self.identity = self.host.identity
        self.ingresses = self.identity.ingresses
        self.workflow = self.host.gate_workflow
        self.applied = False
        if git is not None:
            from .native_git_operations import NativeGitOperations
            if type(git) is not NativeGitOperations or git.owner is not owner or git.reviewer is not recruitment:
                raise LedgerError('NATIVE_RESTORE_GIT_OWNER_REQUIRED')
        self.require()

    def require(self):
        self.owner._require_owner()
        if (self.applied or self.recruitment.pi is not self.old
                or self.owner.launcher.started.get(self.old.seat.participant_id) is not self.old
                or self.recruitment.root.review_host is not self.host
                or self.host.identity is not self.identity or self.identity.active is not None
                or self.identity.ingresses is not self.ingresses
                or self.ingresses != (self.old.forge_service, self.recruitment.root.forge_service)
                or self.host.sources.identity is not self.identity
                or self.host.gates.identity is not self.identity
                or self.host.reviews.identity is not self.identity
                or self.host.gate_workflow is not self.workflow):
            raise LedgerError('NATIVE_RESTORE_GRAPH_CHANGED')
        if self.workflow is not None:
            from .native_gate_workflow import NativeGateWorkflow
            if (type(self.workflow) is not NativeGateWorkflow or self.workflow.host is not self.host
                    or self.workflow.active is not None):
                raise LedgerError('NATIVE_RESTORE_GATE_IN_FLIGHT')
        if self.git is not None:
            self.git.require_pi_restore(self.old)
        return True

    def apply(self, new, capability, sample):
        """No I/O or callbacks after final validation and before publication."""
        capability.require(self.owner.supervisor)
        self.require()
        if (type(new) is not SupervisorAdmission or type(new.forge_service) is not NativePiHostForge
                or new is self.old or new.seat != self.old.seat
                or new.forge_service.client is not self.old.forge_service.client
                or getattr(new.forge_service, 'review_host', None) is not None
                or new.launch.native_recipe.scope != self.old.launch.native_recipe.scope
                or new.launch.native_recipe.checkout != self.old.launch.native_recipe.checkout):
            raise LedgerError('NATIVE_RESTORE_GRAPH_NEW_OWNER')
        new.forge_service._current()
        scope = new.launch.native_recipe.scope
        self.identity.seat_current(new.forge_service, self.owner.ledger.snapshot()['state'],
                                   scope['run_id'], scope['generation'])
        # Preparing the exact new Git seat may observe /proc; no owner changes yet.
        git_seat = None if self.git is None else self.git.prepare_pi_restore(self.old, new)
        self.require()
        new.forge_service._current()
        from .peer import Readiness
        if new.launch.native_receiver.validate_admission_observation(sample, consume=True) is not Readiness.SAFE:
            raise LedgerError('NATIVE_RESTORE_SAFE_SAMPLE_REQUIRED')
        # Plain typed references only. No second host/Gate/Git service construction.
        if self.git is not None:
            self.git.publish_pi_restore(new, git_seat)
        new.forge_service.review_host = self.host
        self.identity.ingresses = (new.forge_service, self.ingresses[1])
        self.recruitment.pi = new
        self.owner.launcher.started[new.seat.participant_id] = new
        self.applied = True
