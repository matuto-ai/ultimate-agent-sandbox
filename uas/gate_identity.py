"""Known positive contribution history under the accepted trusted-peer model.

This is not filesystem surveillance or a declaration of innocence. Unreported
raw edits cannot be inferred; failures reading known history are not empty sets.
"""
from copy import deepcopy
from contextlib import contextmanager
import hashlib
import re

from .ledger import Command, Event, LedgerError, Origin, Transition, _json, _token

_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_SHA = re.compile(r'[0-9a-f]{40}\Z')


def _digest(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


class ContributionOwner:
    """Append-only positive reports on the canonical Room application ledger.

    Source Actor is derived from authenticated Origin, never from payload. An
    adopted patch refers to a previously authenticated exact patch report. Both
    source and adopter remain contributors; reset/session changes cannot erase
    either. Only positive records are supported, not a clean/withdraw operation.
    """
    def __init__(self, ledger, binding):
        if ledger.room_id != binding.room_id:
            raise LedgerError('ROOM_MISMATCH')
        self.ledger, self.binding = ledger, binding

    def submit(self, envelope, *, origin, authorize):
        if (type(envelope) is not dict or set(envelope) != {'id', 'kind', 'run_id', 'generation', 'payload'}
                or envelope['kind'] != 'contribution'):
            raise LedgerError('INVALID_CONTRIBUTION')
        payload = envelope['payload']
        if (type(payload) is not dict or set(payload) != {'kind', 'digest', 'source_report'}
                or payload['kind'] not in ('direct-edit', 'patch', 'adopted-patch')
                or type(payload['digest']) is not str or not _DIGEST.fullmatch(payload['digest'])):
            raise LedgerError('INVALID_CONTRIBUTION')
        if payload['kind'] == 'adopted-patch': _token(payload['source_report'])
        elif payload['source_report'] is not None: raise LedgerError('INVALID_CONTRIBUTION')
        if type(envelope['generation']) is not int or envelope['generation'] < 1:
            raise LedgerError('INVALID_CONTRIBUTION')
        command = Command(_token(envelope['id']), 'contribution.record', _token(envelope['run_id']),
                          envelope['generation'], deepcopy(payload))
        def permitted(actor, _):
            return (type(actor) is Origin and actor.participant_id is not None
                    and 'peer-traffic' in actor.capabilities and authorize() is True)
        def decide(state, cmd):
            run = state.get('runs', {}).get(cmd.target)
            if (run is None or run['generation'] != cmd.generation or run['status'] != 'ACTIVE'
                    or run['project_id'] != self.binding.project_id or run['repository'] != self.binding.repository):
                raise LedgerError('CONTRIBUTION_SCOPE_MISMATCH')
            reports = state.setdefault('contribution_reports', {})
            if len(reports) >= 10000: raise LedgerError('CONTRIBUTION_CAPACITY')
            actors = {origin.actor_id}
            if cmd.payload['kind'] == 'adopted-patch':
                source = reports.get(cmd.payload['source_report'])
                if (source is None or source['kind'] != 'patch' or source['digest'] != cmd.payload['digest']
                        or source['run_id'] != cmd.target or source['generation'] > cmd.generation):
                    raise LedgerError('CONTRIBUTION_SOURCE_UNKNOWN')
                actors.update(source['contributors'])
            row = {'run_id': cmd.target, 'generation': cmd.generation, **cmd.payload,
                   'contributors': sorted(actors), 'reported_by': origin.actor_id,
                   'authority_epoch': origin.authority_version}
            reports[cmd.id] = row
            return Transition(state, (Event('contribution.recorded', {'report_id': cmd.id, **row}),),
                              {'report_id': cmd.id})
        return self.ledger.apply(command, origin, authorize=permitted, decide=decide)

    def known(self, run):
        snapshot = self.ledger.snapshot()['state']
        current = snapshot.get('runs', {}).get(run['run_id'])
        if (current is None or current['generation'] != run['generation']
                or current['project_id'] != self.binding.project_id or current['repository'] != self.binding.repository):
            raise LedgerError('CONTRIBUTION_SCOPE_MISMATCH')
        records = snapshot.get('contribution_reports', {})
        if type(records) is not dict: raise LedgerError('CONTRIBUTION_UNAVAILABLE')
        selected = {key: row for key, row in records.items()
                    if row['run_id'] == run['run_id'] and row['generation'] <= run['generation']}
        actors = sorted({actor for row in selected.values() if row['kind'] != 'patch'
                         for actor in row['contributors']})
        if len(actors) > 128: raise LedgerError('CONTRIBUTION_CAPACITY')
        return {'contributors': actors, 'history_status': 'read', 'version': _digest(selected)}


class AdmittedGateIdentity:
    """Actual admission + canonical ledger + controlled Git read adapter.

    The hosting Hub retains its admission authority fence through consuming Gate
    transactions. No Actor, capability, clean flag or Git contributor list is
    accepted from a Participant packet. Human authority remains a separate
    authenticated host integration, not an invented Participant fallback.
    """
    def __init__(self, dispatcher, contributions, provenance):
        from .workstation_peer import AdmittedPeerDispatcher
        from .git_provenance import GitProvenance
        if (type(dispatcher) is not AdmittedPeerDispatcher or type(contributions) is not ContributionOwner
                or type(provenance) is not GitProvenance
                or dispatcher.hub.ledger is not contributions.ledger
                or provenance.room_id != contributions.binding.room_id
                or provenance.project_id != contributions.binding.project_id):
            raise LedgerError('GATE_IDENTITY_UNAVAILABLE')
        self.dispatcher, self.contributions, self.provenance = dispatcher, contributions, provenance

    @contextmanager
    def operation_fence(self, admission_operation):
        """Host holds this across operation_gates() and consuming ledger.apply()."""
        with self.dispatcher.admissions.authorize(admission_operation, None):
            with self.provenance.history_fence():
                yield

    def require_operation_fence(self):
        if (not getattr(self.dispatcher.admissions._authorization, 'depth', 0)
                or not getattr(self.provenance, '_history_fenced', False)):
            raise LedgerError('GATE_IDENTITY_FENCE_REQUIRED')

    def __call__(self, run, actor_id, head_sha):
        return self.read_identity(run, actor_id, head_sha, None)

    def read_identity(self, run, actor_id, head_sha, authority_version):
        _token(actor_id)
        if head_sha is not None and (type(head_sha) is not str or not _SHA.fullmatch(head_sha)):
            raise LedgerError('GATE_IDENTITY_UNVERIFIABLE')
        authority = self.dispatcher.actor_authority(actor_id, authority_version)
        positive = self.contributions.known(run)
        git = self.provenance.known_contribution_snapshot(
            {'run_id': run['run_id'], 'generation': run['generation']}, run['repository'], head_sha)
        actors = sorted(set(positive['contributors']) | set(git['contributors']))
        if len(actors) > 128: raise LedgerError('CONTRIBUTION_CAPACITY')
        return {**authority, 'contributors': actors, 'history_status': 'read',
                'contribution_version': _digest({'positive': positive['version'], 'git': git['version']})}
