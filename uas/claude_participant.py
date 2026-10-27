"""Claude-specific adapter to the existing Supervisor and context ledger.

No outbound native tool channel is claimed: the selected invocation surface is
Hub -> SDK -> Claude with native replay ACKs. Native PID/pidfd, not the SDK host
PID, selects the immutable Participant authority. No new workflow store exists.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import sqlite3
import uuid

from .claude_fixture import FixtureClaudeRecipe
from .claude_runtime import ClaudeUnavailable
from .ledger import LedgerError
from .lifecycle import _canonical, _unique_object
from .participant import Badge, FixtureSeat, ProcessHandle, MAX_EPOCH, MAX_SEATS
from .peer import Readiness


def _definition(seat, recipe):
    if type(seat) is not FixtureSeat or type(recipe) is not FixtureClaudeRecipe:
        raise LedgerError('INVALID_SEAT')
    definition = seat.document()
    if seat.runtime != 'claude-fixture' or seat.arguments:
        raise LedgerError('FIXTURE_ONLY')
    return definition


def _checkpoint_path(controller, participant):
    return controller.path.with_name('claude-context-' + hashlib.sha256(participant.encode()).hexdigest() + '.json')


def _checkpoint(controller, participant, recipe, native, reset_id):
    value = {'version': 1, 'room_instance': controller.instance, 'participant': participant,
             'scope': recipe.scope, 'directory': str(recipe.directory),
             'context_directory': str(recipe.context_directory), 'native': native, 'reset_id': reset_id}
    encoded = _canonical(value)
    if len(encoded.encode()) > 8192:
        raise LedgerError('NATIVE_CHECKPOINT_CAPACITY')
    path = _checkpoint_path(controller, participant)
    temporary = path.with_name('.claude-context-' + uuid.uuid4().hex)
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        controller.supervisor._sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _retired_stopped(controller):
    # Never adopt or kill a persisted PID; a live/reused identity blocks reset.
    for pid in controller._read()['retired_pids']:
        try:
            descriptor = os.pidfd_open(pid, 0)
        except ProcessLookupError:
            continue
        try:
            if not select.select([descriptor], [], [], 0)[0]:
                raise LedgerError('RETIRED_PROCESSES_UNVERIFIED')
        finally:
            os.close(descriptor)


def _authorized(controller, handle):
    with controller.supervisor._locked():
        return controller._authority(handle, (handle.native_pid, os.getuid(), os.getgid()))


def launch(controller, seat, recipe, *, resetting=None, restoring=None):
    definition = _definition(seat, recipe)
    if controller.store_failed:
        raise LedgerError('AUTHORITY_STORE_UNAVAILABLE')
    handle = receiver = None
    incarnation = None
    try:
        with controller.supervisor._locked():
            state = controller._room()
            controller.supervisor._allowed('participant-start', state)
            document = controller._read()
            previous = document['seats'].get(seat.participant_id)
            if previous and previous.get('cleanup_pending', False) and seat.participant_id not in controller.handles:
                raise LedgerError('NATIVE_STOP_UNVERIFIED')
            if previous and previous['seat'] != definition:
                raise LedgerError('SEAT_BINDING_CONFLICT')
            if previous and previous['status'] == 'closed':
                raise LedgerError('PARTICIPANT_CLOSED')
            if previous and previous['epoch'] == MAX_EPOCH:
                raise LedgerError('AUTHORITY_EPOCH_EXHAUSTED')
            if not previous and len(document['seats']) >= MAX_SEATS:
                raise LedgerError('AUTHORITY_CAPACITY')
            old = controller.handles.get(seat.participant_id)
            if previous and previous['status'] == 'active' and old and controller._alive(old):
                raise LedgerError('ALREADY_RUNNING')
            peer = controller.hub._state()['definition']['participants'].get(seat.participant_id)
            expected = (controller.hub.contexts.pending_scope(resetting['id']) if resetting
                        else controller.hub.contexts.scope(seat.participant_id))
            if not peer or peer['actor_id'] != seat.actor_id or recipe.scope != expected:
                raise LedgerError('PEER_BINDING_CONFLICT')
            if resetting is None and not controller.hub.contexts.permits(seat.participant_id,
                    expected['context_generation'], expected['run_id'], expected['generation']):
                raise LedgerError('CONTEXT_UNAVAILABLE')
            # Once a context has a checkpoint it can only be explicitly resumed.
            # A fresh launch is never an implicit same-Run session replacement.
            if (resetting is None and restoring is None
                    and (expected['context_generation'] > 1
                         or _checkpoint_path(controller, seat.participant_id).exists())):
                raise LedgerError('NATIVE_CONTEXT_RESTORE_REQUIRED')
            if old is not None:
                controller._dispose(old)
                controller.handles.pop(seat.participant_id, None)
            _retired_stopped(controller)
            incarnation = 'process-' + uuid.uuid4().hex
            epoch = previous['epoch'] + 1 if previous else 1
            record = {'seat': definition, 'epoch': epoch, 'incarnation_id': incarnation,
                      'status': 'starting', 'reason': 'explicit-start', 'pid': None,
                      'host_pid': None, 'cleanup_pending': True}
            document['seats'][seat.participant_id] = record
            if controller.credentials.missing(definition):
                record.update(status='disabled', reason='missing-credential', cleanup_pending=False)
            controller._save(document)
            if record['status'] == 'disabled':
                raise LedgerError('MISSING_ACTOR_CREDENTIAL')
            badge = Badge(controller.supervisor.room_id, controller.instance, controller.controller_id,
                seat.actor_id, seat.participant_id, seat.profile_id, seat.capabilities, incarnation, epoch)

            # Spawn only under the lifecycle lock, but never wait for native
            # initialization here. Stop owns this host immediately, including
            # a child that is still initializing or has not reported its PID.
            receiver = recipe.start(incarnation, resume=restoring is not None,
                context_directory=restoring['context_directory'] if restoring else None, defer_ready=True)
            descriptor = os.dup(receiver.host_pidfd)
            handle = ProcessHandle(badge, receiver.process, None, descriptor,
                                   None, recipe.context_directory, 'claude', receiver, None, descriptor)
            controller.handles[seat.participant_id] = handle
            record.update(pid=receiver.process.pid, host_pid=receiver.process.pid)
            # pending host is cleanup ownership, NOT native authority
            controller._save(document)

        receiver.wait_ready()  # Native waits never hold the lifecycle lock.
        with controller.supervisor._locked():
            controller._pending_pi_authority(handle, definition)
            if receiver.incarnation_id != incarnation or receiver.scope != expected:
                raise LedgerError('INVALID_NATIVE_RECEIVER')
            receiver._kernel()  # actual parent/start binding; host PID is not native authority
            descriptor = os.dup(receiver.native_pidfd)
            # Keep the independently held host descriptor for cleanup retries.
            handle.pidfd, handle.native_pid = descriptor, receiver.native_pid
            document = controller._read()
            document['seats'][seat.participant_id].update(pid=receiver.native_pid, cleanup_pending=False)
            controller._save(document)
        if restoring:
            if receiver.session_id != restoring['native']['session_id']:
                raise LedgerError('NATIVE_SESSION_MISMATCH')
            # A raw safe probe does not clear journal uncertainty. Hub's first
            # observe remains held if any retained intent lacks a receipt.
            receiver.wait_safe()
            native = restoring['native']
        else:
            receiver.wait_safe()
            native = receiver.prove_fresh_context(
                preceding_session=resetting['preceding_session'] if resetting else None)
        with controller.supervisor._locked():
            controller.supervisor._allowed('participant-start', controller._room())
            controller._pending_pi_authority(handle, definition)  # shared pending-badge guard
            if not restoring:
                _checkpoint(controller, seat.participant_id, recipe, native,
                            resetting['id'] if resetting else None)
            if resetting:
                controller.hub.contexts.succeed_reset(resetting['id'], resetting['expected_generation'],
                    authorize=lambda: controller._pending_pi_authority(handle, definition))
            receiver.authorize = lambda: _authorized(controller, handle)
            handle.connection = controller.hub.connect('attach-' + uuid.uuid4().hex,
                seat.participant_id, incarnation, receiver, context_generation=expected['context_generation'])
            document = controller._read()
            document['seats'][seat.participant_id].update(status='active', reason='launched')
            controller._save(document)
        return handle
    except BaseException:
        if incarnation is not None:
            controller.fenced.add(incarnation)
            try:
                with controller.supervisor._locked():
                    document = controller._read()
                    current = document['seats'].get(seat.participant_id)
                    if current and current['incarnation_id'] == incarnation and current['status'] in {'starting', 'active'}:
                        controller._fence(document, seat.participant_id, 'revoked', 'launch-failed')
            except (LedgerError, OSError):
                pass
        try:
            if handle is not None:
                with controller.supervisor._locked():
                    controller._dispose(handle)
            elif receiver is not None:
                receiver.close()
        finally:
            if (handle is not None and handle.cleanup_verified
                    and controller.handles.get(seat.participant_id) is handle):
                controller.handles.pop(seat.participant_id, None)
        raise


def restore(controller, seat, recipe):
    _definition(seat, recipe)
    with controller.supervisor._locked():
        controller.supervisor._allowed('participant-restore', controller._room())
        scope = controller.hub.contexts.scope(seat.participant_id)
        path = _checkpoint_path(controller, seat.participant_id)
        try:
            if path.is_symlink() or path.stat().st_size > 8192:
                raise ValueError()
            saved = json.loads(path.read_text(), object_pairs_hook=_unique_object)
            if (set(saved) != {'version', 'room_instance', 'participant', 'scope', 'directory',
                              'context_directory', 'native', 'reset_id'}
                    or type(saved['version']) is not int or saved['version'] != 1
                    or saved['room_instance'] != controller.instance or saved['participant'] != seat.participant_id
                    or saved['scope'] != scope or recipe.scope != scope or saved['directory'] != str(recipe.directory)
                    or type(saved['native']) is not dict or set(saved['native']) != {'session_id', 'source'}
                    or saved['native']['source'] != 'fresh-home-explicit-session-native-idle-no-input'
                    or str(uuid.UUID(saved['native']['session_id'])) != saved['native']['session_id']):
                raise ValueError()
            if saved['reset_id'] is not None and controller.hub.contexts.reset_status(saved['reset_id'])['status'] != 'SUCCEEDED':
                raise ValueError()
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise LedgerError('NATIVE_CONTEXT_RESTORE_UNVERIFIED') from error
    return launch(controller, seat, recipe, restoring=saved)


def reset(controller, operation_id, seat, recipe, *, expected_context_generation, target_run):
    definition = _definition(seat, recipe)
    with controller.supervisor._locked():
        controller.supervisor._allowed('participant-reset', controller._room())
        previous = controller._read()['seats'].get(seat.participant_id)
        if previous and previous['seat'] != definition:
            raise LedgerError('SEAT_BINDING_CONFLICT')
        controller.hub.contexts.request_reset(operation_id, seat.participant_id, expected_context_generation, target_run)
        status = controller.hub.contexts.reset_status(operation_id)
        if status['status'] == 'SUCCEEDED':
            current = controller.handles.get(seat.participant_id)
            if (current and current.connection is not None and controller.hub._current(current.connection)
                    and current.connection.context_generation == expected_context_generation + 1):
                controller._authority(current, (current.native_pid, os.getuid(), os.getgid()))
                return current
            raise LedgerError('RESET_SUCCEEDED_RESTORE_REQUIRED')
    try:
        if recipe.scope != controller.hub.contexts.pending_scope(operation_id):
            raise LedgerError('PEER_BINDING_CONFLICT')
        with controller.supervisor._locked():
            old = controller.handles.get(seat.participant_id)
            preceding = old.managed_receiver.session_id if old and old.managed_receiver else None
            if old:
                controller._fence(controller._read(), seat.participant_id, 'revoked', 'context-reset')
                controller._dispose(old)
                if controller._alive(old) or old.process.returncode is None:
                    raise LedgerError('NATIVE_STOP_UNVERIFIED')
            _retired_stopped(controller)
        return launch(controller, seat, recipe, resetting={'id': operation_id,
            'expected_generation': expected_context_generation, 'preceding_session': preceding})
    except BaseException:
        try:
            if controller.hub.contexts.reset_status(operation_id)['status'] != 'SUCCEEDED':
                controller.hub.contexts.fail_reset(operation_id, expected_context_generation, 'NATIVE_RESET_FAILED')
        except (LedgerError, OSError, sqlite3.Error):
            pass
        raise
