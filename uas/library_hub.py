"""Authenticated Hub metadata owner; transient captures never enter RoomLedger.

A trusted service client supplies contact; the Hub has no canonical clone,
credentials, settings, model or fallback content store. Network/process transport
provisioning belongs to the Supervisor, not this route.
"""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import re

from . import library
from .library_enqueue import CaptureResult
from .ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition, _json

_RESULT_ORIGIN = Origin('library-hub', 'library-hub', 'library-hub', 'library-result-v1',
                        ('library-result',))
_REASON = re.compile(r'[A-Z][A-Z0-9_]{0,95}\Z')
_SHA = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def _uncertain(request_id, reason='LIBRARY_UNAVAILABLE'):
    return asdict(CaptureResult('NOT_DURABLE', request_id, reason, True))


def safe_result(value, request_id):
    """Project service replies are still checked before intermediary retention."""
    if type(value) is not CaptureResult:
        raise ValueError('invalid result')
    result = asdict(value)
    if value.request_id != request_id or type(value.retryable) is not bool or type(value.visible) is not bool:
        raise ValueError('invalid correlation')
    if value.outcome not in ('DURABLY_QUEUED', 'REJECTED', 'NOT_DURABLE'):
        raise ValueError('invalid outcome')
    if value.outcome == 'DURABLY_QUEUED':
        if (value.reason is not None or value.retryable or type(value.queue_id) is not str
                or not _DIGEST.fullmatch(value.queue_id)
                or value.path != 'pending/' + value.queue_id + '.md'
                or type(value.published_sha) is not str or not _SHA.fullmatch(value.published_sha)
                or (value.projection_sha is not None and (type(value.projection_sha) is not str
                    or not _SHA.fullmatch(value.projection_sha)))
                or (value.visible and value.projection_sha is None)):
            raise ValueError('invalid publication')
    elif (type(value.reason) is not str or not _REASON.fullmatch(value.reason)
          or value.retryable != (value.outcome == 'NOT_DURABLE')
          or (value.queue_id is not None and (type(value.queue_id) is not str or not _DIGEST.fullmatch(value.queue_id)))
          or any(getattr(value, name) is not None for name in
                 ('path', 'published_sha', 'projection_sha')) or value.visible):
        raise ValueError('invalid refusal')
    return result


class LibraryHub:
    def __init__(self, ledger, *, room_id, project, source_identity, contact,
                 clock=lambda: datetime.now(timezone.utc).isoformat()):
        if type(ledger) is not RoomLedger or ledger.room_id != room_id or not callable(contact):
            raise LedgerError('INVALID_LIBRARY_BINDING')
        self.ledger, self.room_id = ledger, room_id
        self.binding = library.project_binding(project, source_identity=source_identity)
        self.contact, self.clock = contact, clock

    def prepare(self, envelope, origin, *, authorize, run_id=None):
        """Called under current admission fence; only pure metadata in apply."""
        if authorize() is not True:
            raise LedgerError('FORBIDDEN')
        try:
            scope = library.participant_scope(origin, binding=self.binding)
            if (type(envelope) is not dict or set(envelope) != {'id', 'kind', 'request_id', 'capture'}
                    or envelope['kind'] != 'library.enqueue' or type(envelope['capture']) is not dict):
                raise LedgerError('INVALID_LIBRARY_ENVELOPE')
            if set(envelope['capture']) - {'type', 'title', 'body', 'sources', 'hints'}:
                raise LedgerError('INVALID_LIBRARY_ENVELOPE')
            library._token(envelope['id'], 'operation_id')
            library._token(envelope['request_id'], 'request_id')
            # Reject claimed authority before contacting an external service.
            library._reject_reserved(envelope['capture'], 'capture', extra=library.CAPTURE_IDENTITY_KEYS)
            digest = hashlib.sha256(_json(envelope).encode()).hexdigest()
        except library.LibraryError as error:
            raise LedgerError(error.code) from None
        request = json.loads(_json(envelope))  # Own the transient bytes against caller mutation.
        metadata = {'request_id': request['request_id'], 'request_sha256': digest,
                    'project_identity': scope.project_identity,
                    'service_operation_id': 'hub-enqueue-' + hashlib.sha256(_json(
                        [self.room_id, scope.project_identity, request['id']]).encode()).hexdigest()}
        command = Command(request['id'], 'library.enqueue', scope.project_id, None, metadata)
        at = self.clock()
        library._timestamp(at, 'at')
        if run_id is not None:
            library._token(run_id, 'run_id')
        def decide(state, _):
            result = {'at': at, 'run_id': run_id, **metadata}
            return Transition(state, (Event('library.enqueue.reserved', result),), result)
        reserved = self.ledger.apply(command, origin, authorize=lambda *_: authorize(), decide=decide)
        key = 'library-result-' + hashlib.sha256(_json([self.room_id, request['id']]).encode()).hexdigest()
        previous = self.ledger.operation_receipt(key, _RESULT_ORIGIN, authorize=authorize)
        return request, scope, reserved['result'], key, previous

    def perform(self, prepared, *, current):
        """No ledger transaction or admission lock across external service I/O."""
        request, scope, metadata, _, previous = prepared
        if current() is not True:
            raise LedgerError('FORBIDDEN')
        if previous is not None:
            return previous['result']
        try:
            result = self.contact(scope=scope, current=current, operation_id=metadata['service_operation_id'],
                                  request_id=request['request_id'], value=request['capture'],
                                  at=metadata['at'], run_id=metadata['run_id'])
            return safe_result(result, request['request_id'])
        except Exception:
            # Never retain exception text, request bodies, remote diagnostics or
            # infer rejection/absence from contact failure after publication.
            return _uncertain(request['request_id'])

    def finish(self, prepared, result, *, authorize):
        """Current origin has been rechecked before safe outcome disclosure."""
        request, scope, metadata, key, previous = prepared
        if authorize() is not True:
            raise LedgerError('FORBIDDEN')
        if previous is not None:
            return previous['result']
        payload = {'command_id': request['id'], 'request_sha256': metadata['request_sha256'],
                   'result': result}
        try:
            receipt = self.ledger.apply(Command(key, 'library.enqueue.result', scope.project_id, None, payload),
                _RESULT_ORIGIN, authorize=lambda *_: authorize(),
                decide=lambda state, _: Transition(state, (Event('library.enqueue.result', payload),), result))
            return receipt['result']
        except LedgerError as error:
            if error.code not in ('STORAGE_ERROR', 'CLOSED'):
                raise
            return _uncertain(request['request_id'], 'HUB_RECEIPT_UNAVAILABLE')
