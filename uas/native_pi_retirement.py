"""One-shot Pi retirement; only exact held native task exit facts (not checkout or descendant quiescence).

Transport shutdown is a request, never proof. No signal, PID lookup, adoption,
worker join, descendant enumeration or worktree-quiescence claim is made here.
"""
import math
import os
import select
import socket
import threading
import time

from .workstation_control import SupervisorAdmission
from .workstation_exec import ExecLaunch
from .native_pi_recipe import NativePiRecipe
from .native_host_forge import NativePiHostForge
from .docker_exec_api import EngineStream
from .kernel_origin import HeldOrigin, OriginDenied, _identity
from .lifecycle import _HeldLifecycleScope


class NativePiRetirement:
    def __init__(self, admission, *, lifecycle):
        if (type(admission) is not SupervisorAdmission or type(admission.launch) is not ExecLaunch
                or type(admission.launch.native_recipe) is not NativePiRecipe
                or type(admission.forge_service) is not NativePiHostForge
                or admission.forge_service.admission is not admission
                or admission.forge_service.helper is not admission.launch
                or type(lifecycle) is not _HeldLifecycleScope
                or type(admission.launch.transport) is not EngineStream):
            raise OriginDenied('exact active Pi owners required')
        self.ingress=admission.forge_service
        self.supervisor=self.ingress.client.supervisor
        lifecycle.require(self.supervisor)
        self.ingress._current();admission._current()
        root=admission.launch
        if type(root.origin) is not HeldOrigin or root.origin.revoked:
            raise OriginDenied('exact live held Pi identity required')
        self.root=root;self.admission=admission
        self.transport=root.transport;self.channel=self.transport.channel
        self.thread=threading.get_ident();self.fds={};self.identities={};self.exits=set()
        self.started=False;self.revoked=False;self.shutdown_requested=False;self.closed=False;self.invalid=False
        self.state='captured'
        try:
            fd=os.dup(root.origin.pidfd);self.fds['native']=fd
            os.set_inheritable(fd,False)
            identity=_identity(fd)
            if identity!=root.origin.identity:raise OriginDenied('changed held Pi identity')
            self.identities['native']=identity
            self.ingress._current();admission._current();lifecycle.require(self.supervisor)
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
        if (self.admission.launch is not self.root or self.admission.forge_service is not self.ingress
                or self.ingress.admission is not self.admission or self.ingress.helper is not self.root
                or self.root.origin is None or self.root.origin.identity != self.identities['native']):
            raise OriginDenied('captured Pi ownership changed')
        self.started=True;self.state='retiring'
        try:
            root=self.admission.revoke(deadline=deadline)
            if (type(root) is not dict or root.get('installed') is not False
                    or root.get('state') not in ('absent','revoked')):
                raise OriginDenied('root revocation unconfirmed')
            self.revoked=True
            if time.monotonic()>=deadline:raise TimeoutError('retirement deadline before shutdown')
            if self.root.transport is not self.transport or self.transport.channel is not self.channel:
                raise OriginDenied('owned Pi transport changed')
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
            if self.revoked and len(self.exits)==1:self.state='exited'
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

    def require_exited(self, admission=None):
        self._owner()
        if admission is not None and admission is not self.admission:raise OriginDenied('different retirement root')
        result=self._observe(time.monotonic())  # Nonblocking; valid inside consuming lifecycle fence.
        if result['state']!='exited':raise OriginDenied('exact Pi retirement unverified')
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
