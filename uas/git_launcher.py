"""Untrusted public Git client: typed RPC only, never a credential/exec shim."""
import os
import socket
import uuid

from .git_endpoint import EndpointPeer
from .git_policy import parse_git
from .git_protocol import decode, send, receive_blob
from .kernel_origin import OriginDenied, enable, receive

ENDPOINT = '/uas/git/request.sock'


def main(argv, *, invoked_as):
    # Client validation is convenience only. Supervisor parses independently.
    parse_git(invoked_as, argv)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        enable(channel); channel.settimeout(45)
        channel.connect(ENDPOINT)
        peer = EndpointPeer(channel)
        try:
            send(channel, {'kind': 'git', 'id': uuid.uuid4().hex, 'invoked_as': invoked_as,
                           'argv': argv, 'cwd': os.getcwd()})
            def reply():
                with receive(channel) as record:
                    peer.require(record)
                    return decode(record.data)
            first = reply()
            if first.get('kind') == 'refused':
                if set(first) != {'kind', 'error', 'record'} or type(first['error']) is not str:
                    raise OriginDenied('invalid Git refusal')
                os.write(2, ('Controlled Git: ' + first['error'] + '\n').encode())
                return 128
            values = [first]
            def blobs(): return values.pop() if values else reply()
            stdout = receive_blob('stdout', blobs)
            stderr = receive_blob('stderr', reply)
            terminal = reply()
            if (set(terminal) != {'kind', 'code', 'status', 'receipt'} or terminal['kind'] != 'exit'
                    or type(terminal['code']) is not int or not 0 <= terminal['code'] <= 255
                    or type(terminal['status']) is not str):
                raise OriginDenied('invalid Git terminal')
            # Native Git's output is user data, never parsed as attribution.
            for fd, raw in ((1, stdout), (2, stderr)):
                offset = 0
                while offset < len(raw):
                    count = os.write(fd, raw[offset:])
                    if count <= 0: raise OriginDenied('Git output unavailable')
                    offset += count
            return terminal['code']
        finally:
            peer.close()
