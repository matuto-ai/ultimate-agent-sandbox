"""One-shot Claude retirement; only exact held host/native/helper exit facts.

Transport shutdown is a request, never proof. No signal, PID lookup, adoption,
worker join, descendant enumeration or worktree-quiescence claim is made here.
"""
import math
import os
import select
import socket
import threading
import time

from .claude_native_admission import NativeClaudeRoot, NativeClaudeHostLaunch, NativeClaudeSupervisorAdmission
from .docker_exec_api import EngineStream
from .kernel_origin import HeldOrigin, OriginDenied, _identity
from .lifecycle import _HeldLifecycleScope
from .native_helper import NativeDescendantLease


class NativeClaudeRetirement:
    def __init__(self, root, *, lifecycle):
        if (type(root) is not NativeClaudeRoot or type(root.host_launch) is not NativeClaudeHostLaunch
                or type(root.native_admission) is not NativeClaudeSupervisorAdmission
                or root.native_admission.launch is not root
                or type(root.helper_lease) is not NativeDescendantLease
                or root.helper_lease.root is not root or root.helper_lease._admission is not root.native_admission
                or root.helper_lease.state != 'admitted' or root.state != 'active'
                or type(lifecycle) is not _HeldLifecycleScope or root.forge_service is None
                or type(root.host_launch.transport) is not EngineStream):
            raise OriginDenied('exact active Claude owners required')
        self.supervisor=root.forge_service.client.supervisor
        lifecycle.require(self.supervisor)
        root.current();root.helper_lease.current();root.native_admission._current()
        if (root.host_origin is not root.host_launch.origin
                or any(type(origin) is not HeldOrigin or origin.revoked
                       for origin in (root.host_origin,root.origin,root.helper_lease.origin))):
            raise OriginDenied('exact live held Claude identities required')
        self.root=root;self.helper=root.helper_lease;self.admission=root.native_admission
        self.transport=root.host_launch.transport;self.channel=self.transport.channel
        self.thread=threading.get_ident();self.fds={};self.identities={};self.exits=set()
        self.started=False;self.revoked=False;self.shutdown_requested=False;self.closed=False;self.invalid=False
        self.state='captured'
        try:
            for name,origin in (('host',root.host_origin),('native',root.origin),('helper',self.helper.origin)):
                fd=os.dup(origin.pidfd);self.fds[name]=fd
                os.set_inheritable(fd,False)
                identity=_identity(fd)
                if identity!=origin.identity:raise OriginDenied('changed held Claude identity')
                self.identities[name]=identity
            if len(set(self.identities.values()))!=3:raise OriginDenied('distinct Claude tasks required')
            root.current();self.helper.current();lifecycle.require(self.supervisor)
        except BaseException:
            self.close()
            raise

    def _owner(self):
        if self.closed or self.thread!=threading.get_ident():
            raise OriginDenied('retirement observation owner unavailable')

    def _outside_lifecycle(self):
        self._owner()
        if any(owner[:2]==(os.getpid(),threading.get_ident())
               for owner in self.supervisor._lifecycle_scopes.values()):
            raise OriginDenied('retirement waits require released lifecycle lock')

    @staticmethod
    def _deadline(timeout):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<=timeout<=30:
            raise ValueError('retirement timeout must be within thirty seconds')
        return time.monotonic()+timeout

    def retire(self, timeout=5):
        self._outside_lifecycle()
        deadline=self._deadline(timeout)
        if timeout==0 and not self.started:raise ValueError('positive initial retirement timeout required')
        if self.started:return self._observe(deadline)
        self.started=True;self.state='retiring'
        try:
            # A helper receipt must precede root revocation: successful helper
            # removal clears its private controller ownership before local close.
            helper=self.helper.revoke(deadline=deadline)
            if type(helper) is not dict or helper.get('state') not in ('absent','revoked'):
                raise OriginDenied('helper revocation unconfirmed')
            root=self.admission.revoke(deadline=deadline)
            if (type(root) is not dict or root.get('installed') is not False
                    or root.get('state') not in ('absent','revoked')):
                raise OriginDenied('root revocation unconfirmed')
            self.revoked=True
            if time.monotonic()>=deadline:raise TimeoutError('retirement deadline before shutdown')
            if self.root.host_launch.transport is not self.transport or self.transport.channel is not self.channel:
                raise OriginDenied('owned Claude transport changed')
            self.shutdown_requested=True  # Even an uncertain shutdown is never resent.
            self.channel.shutdown(socket.SHUT_RDWR)
            return self._observe(deadline)
        except BaseException:
            self.state='unknown'
            raise

    def _observe(self, deadline):
        self._owner()
        if self.invalid:raise OriginDenied('retirement observation invalid')
        try:
            for name,fd in self.fds.items():
                if _identity(fd)!=self.identities[name]:raise OriginDenied('retained pidfd identity changed')
            poll=select.poll()
            pending={fd:name for name,fd in self.fds.items() if name not in self.exits}
            for fd in pending:poll.register(fd,select.POLLIN)
            while pending:
                left=max(0,deadline-time.monotonic())
                events=poll.poll(int(left*1000))
                for fd,flags in events:
                    if (fd not in pending or flags & (select.POLLERR|select.POLLNVAL)
                            or not flags & select.POLLIN):
                        raise OriginDenied('retained pidfd observation unknown')
                    name=pending.pop(fd)
                    if _identity(fd)!=self.identities[name]:raise OriginDenied('retained pidfd identity changed')
                    self.exits.add(name);poll.unregister(fd)
                if not events or time.monotonic()>=deadline:break
            if self.revoked and len(self.exits)==3:self.state='exited'
            elif not self.revoked and self.started:self.state='unknown'
            elif self.started:self.state='pending'
            return {'state':self.state,'exited':sorted(self.exits),'canonical_revoked':self.revoked,
                    'shutdown_requested':self.shutdown_requested}
        except BaseException:
            self.invalid=True;self.state='unknown'
            raise

    def observe(self, timeout=0):
        self._outside_lifecycle()
        return self._observe(self._deadline(timeout))

    def require_exited(self, root=None):
        self._owner()
        if root is not None and root is not self.root:raise OriginDenied('different retirement root')
        result=self._observe(time.monotonic())  # Nonblocking; valid inside consuming lifecycle fence.
        if result['state']!='exited':raise OriginDenied('exact Claude retirement unverified')
        return True

    def close(self):
        if self.closed:return
        self.closed=True
        error=None
        for name,fd in list(self.fds.items()):
            self.fds.pop(name,None)
            try:os.close(fd)
            except BaseException as failure:error=error or failure
        if error is not None:raise error
