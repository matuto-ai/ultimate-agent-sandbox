"""T21 lease-first service lifecycle and bounded metadata report replay.

The Supervisor supplies current Project compositions and a trusted Hub transport.
No Participant, model client or canonical target provisioning API. Trusted human
controls compose the canonical disposition owner separately.
"""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import multiprocessing
import os
import signal
import threading
import time

from . import library, library_deadline
from .library_git import LibraryGit
from .library_records import LibraryRecords
from .library_scheduler import Scheduler


def fail(code):
    raise library.LibraryError(code, 'service')


def _contact(pipe, transport, report, lease, seconds):
    # No clone access and no inherited singleton ownership in report workers.
    os.setsid()
    signal.signal(signal.SIGALRM, lambda *_: os.killpg(os.getpid(), signal.SIGKILL))
    signal.setitimer(signal.ITIMER_REAL, seconds)
    if lease is not None: os.close(lease)  # never LOCK_UN a duplicated open description
    try:
        pipe.send(transport(report) is True)
    except BaseException:
        pass
    finally:
        pipe.close()


def bounded_report(transport, report, seconds, lease):
    """Bound a trusted transport, including descendants, independently of drains."""
    if seconds <= 0: return False
    context = multiprocessing.get_context('fork')
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_contact, args=(sender, transport, report, lease, seconds))
    process.start(); sender.close()
    acknowledged = False
    try:
        if receiver.poll(seconds):
            try: acknowledged = receiver.recv() is True
            except EOFError: pass
    finally:
        # Even a successful transport must not leak helpers retaining resources.
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        except PermissionError: pass
        if process.is_alive(): process.kill()
        process.join(1); receiver.close(); process.close()
    return acknowledged


@dataclass(frozen=True)
class Project:
    """Trusted inventory binding survives revocation of live Participant authority."""
    scope: library.LibraryScope
    runner: object
    context: object


class Service:
    """One serialized service loop, externally stoppable during a bounded turn.

    projects(publisher) yields Project descriptors from trusted service inventory.
    transport(project-scoped report) returns True only after the Hub commits it.
    No network/Room participants are needed for startup or eligible draining.
    """
    def __init__(self, publisher, projects, *, transport, room_for, now=lambda:datetime.now(timezone.utc),
                 report_seconds=.2, flush_seconds=.5, max_reports=32):
        if not isinstance(publisher, LibraryGit) or not callable(projects) or not callable(transport) or not callable(room_for):
            fail('SERVICE_DEPENDENCY_REQUIRED')
        if (type(max_reports) is not int or not 1<=max_reports<=256
                or not 0<report_seconds<=5 or not 0<flush_seconds<=10): fail('SERVICE_BOUND_INVALID')
        self.publisher, self.projects, self.transport, self.now = publisher, projects, transport, now
        self.room_for = room_for
        self.report_seconds, self.flush_seconds, self.max_reports = report_seconds, flush_seconds, max_reports
        self.scheduler = None
        self._stop = threading.Event(); self._idle = threading.Event(); self._idle.set()
        self._turn = threading.Lock(); self._closed = False
        self._keys = []; self._report_cursor = 0; self._cursors = {}

    def startup(self):
        if self.scheduler is not None: fail('SERVICE_ALREADY_STARTED')
        self.publisher.startup()  # authoritative identities before discarding local cache
        try:
            self.scheduler = Scheduler(self.publisher, now=self.now)
            for project in self.projects(self.publisher):
                if type(project) is not Project: fail('SERVICE_PROJECT_REQUIRED')
                key = self.scheduler.register(project.runner, context=project.context, recovery=True, binding_scope=project.scope)
                self._keys.append(key)
                self.scheduler.recover(key)
            self.flush()
            return self
        except BaseException:
            if self.scheduler is not None: self.scheduler.close()
            self.publisher.close(); self.scheduler = None
            raise

    def _ack_operation(self, record, report):
        values = dict(record['scope']); values['project_path'] = record['project_path']
        values['capabilities'] = tuple(values['capabilities'])
        scope = library.LibraryScope(seal=library._SCOPE_SEAL, **values)
        identity = 'report-' + library._digest([scope.project_identity,report['drain_id'],report['sequence']])
        return library._operation('drain-report-ack',scope,{'settings_id':record['settings_id'],'limits':{'payload_bytes':4096}},
            identity,identity,{'report_sha256':library._digest(report)},record['at'],drain_id=report['drain_id'])

    def flush(self):
        try:
            with library_deadline.bounded(self.flush_seconds):
                return self._flush()
        except library.LibraryError as error:
            if error.code == 'ATTEMPT_TIMEOUT': return 0  # uncertain ACK is replayed
            raise

    def _flush(self):
        """At most one bounded sweep; a dead Hub cannot starve another Project."""
        if self.scheduler is None or self._closed: fail('SERVICE_NOT_STARTED')
        deadline = time.monotonic() + self.flush_seconds
        sent = 0; attempted = 0
        if not self._keys: return 0
        keys = self._keys[self._report_cursor:] + self._keys[:self._report_cursor]
        self._report_cursor = (self._report_cursor + 1) % len(self._keys)
        with LibraryRecords(self.publisher.records_path,self.publisher.deployment_id) as records:
            for key in keys:
                for record in records.iter_schedules(key, after_sequence=self._cursors.get(key,0)):
                    if attempted >= self.max_reports or time.monotonic() >= deadline: return sent
                    transition = record['manifest'].get('transition')
                    if transition is None:
                        self._cursors[key] = record['manifest']['sequence']
                        continue
                    report = {'project_identity':key,'room_id':self.room_for(self.scheduler._entries[key]['scope']),
                              **library.drain_transition(transition)}
                    operation = self._ack_operation(record,report)
                    prior = records.record(operation.operation_id,project_identity=key)
                    if prior is not None and prior['receipt'] is not None:
                        self._cursors[key] = record['manifest']['sequence']
                        continue
                    attempted += 1
                    # Sender intent isn't a delivered report; lost ACK is safely resent.
                    records.begin(operation)
                    accepted = bounded_report(self.transport,report,
                        min(self.report_seconds,deadline-time.monotonic()),self.publisher._lease)
                    if not accepted: break
                    records.finish(operation,library.receipt(operation,'ACKNOWLEDGED',at=operation.at,
                        acknowledgement=library._digest(report),reason='HUB_RECORDED'))
                    self._cursors[key] = record['manifest']['sequence']
                    sent += 1
        return sent

    def tick(self):
        if self.scheduler is None or self._closed: fail('SERVICE_NOT_STARTED')
        if self._stop.is_set(): return None
        if not self._turn.acquire(blocking=False): fail('SERVICE_BUSY')
        self._idle.clear()
        try:
            if self._stop.is_set(): return None
            result = self.scheduler.tick()
            self.flush()
            return result
        finally:
            self._idle.set(); self._turn.release()

    def run(self, *, poll_seconds=.1):
        if not 0<poll_seconds<=5: fail('SERVICE_BOUND_INVALID')
        try:
            while not self._stop.is_set():
                self.tick()
                self._stop.wait(poll_seconds)
        finally:
            self.shutdown()

    def request_stop(self):
        self._stop.set()

    def shutdown(self):
        self.request_stop()
        if self._closed: return
        if self.scheduler is None: return
        maximum = max((e['settings']['limits']['attempt_seconds'] for e in self.scheduler._entries.values()),default=1)
        if not self._idle.wait(maximum + self.flush_seconds + 1):
            # Supervisor may terminate the process; never release lease under live work.
            fail('SERVICE_SHUTDOWN_TIMEOUT')
        with self._turn:
            try: self.flush()
            finally:
                self.scheduler.close(); self.publisher.close(); self._closed=True
