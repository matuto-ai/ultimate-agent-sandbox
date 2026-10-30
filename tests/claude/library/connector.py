"""Owned fixture socket handoff; no production bootstrap/lineage claim."""
import fcntl
import os
from pathlib import Path
import socket
import sys

endpoint, node, root, profile = sys.argv[1:]
if profile != 'library-capture-v1':
    raise SystemExit(125)
peer = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
peer.connect(endpoint)
peer.send(b'CLAUDE-LIBRARY-FIXTURE')
# Preserve a separate inert Forge channel, as the production server expects it;
# the Library-only profile must never use or expose it.
forge, unused = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
a = fcntl.fcntl(peer.fileno(), fcntl.F_DUPFD_CLOEXEC, 10)
b = fcntl.fcntl(forge.fileno(), fcntl.F_DUPFD_CLOEXEC, 10)
os.dup2(a, 3); os.dup2(b, 4)
for fd in (3, 4):
    os.set_inheritable(fd, True); os.set_blocking(fd, False)
os.closerange(5, 1024)
os.execve(node, [node, str(Path(root)/'runtime/claude/mcp-server.mjs'), profile],
          {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
