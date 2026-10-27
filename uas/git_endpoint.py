"""Pin a fixed Unix endpoint's actual connection peer, never a numeric PID.

The Supervisor owns/protects endpoint placement. SO_PEERPIDFD supplements the
connection challenge; every reply still carries fresh SCM_PIDFD credentials.
This requires Linux SO_PEERPIDFD (6.5+) and pidfs identities (6.9+), plus the
existing mandatory SO_PASSPIDFD support. There is no UID/PID fallback.
"""
import os
import socket
import struct

from .kernel_origin import HeldOrigin, OriginDenied, _identity, alive

SO_PEERPIDFD = 77


class EndpointPeer:
    def __init__(self, channel):
        self.fd = -1
        try:
            raw = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            if type(raw) is not bytes or len(raw) != 12:
                raise OriginDenied('invalid Git endpoint peer credentials')
            self.credentials = struct.unpack('3i', raw)
            if any(value < 0 for value in self.credentials):
                raise OriginDenied('invalid Git endpoint peer mapping')
            self.fd = channel.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD)
            if type(self.fd) is not int or self.fd < 0:
                self.fd = -1
                raise OriginDenied('Git endpoint peer pidfd unavailable')
            os.set_inheritable(self.fd, False)
            self.identity = _identity(self.fd)
            if not alive(self.fd): raise OriginDenied('Git endpoint peer exited')
        except BaseException:
            self.close()
            raise

    def require(self, record):
        if (self.fd < 0 or not alive(self.fd) or record.credentials != self.credentials
                or not alive(record.pidfd) or _identity(record.pidfd) != self.identity):
            raise OriginDenied('Git endpoint reply is not the connected peer')

    def hold(self, record):
        self.require(record)
        return HeldOrigin(record)

    def close(self):
        if self.fd >= 0:
            fd, self.fd = self.fd, -1
            os.close(fd)
