"""Attack fixture: transfer Pi's duplicate FD via SCM_RIGHTS, then exec Node.

Only test code; not a launcher or attribution proxy. The recipient's PID differs
from Pi even though UID and authority-channel file description are identical.
"""
import array
import os
from pathlib import Path
import socket
import subprocess
import sys

if sys.argv[1] == 'receive':
    channel = socket.socket(fileno=int(sys.argv[2]))
    _, ancillary, _, _ = channel.recvmsg(1, socket.CMSG_SPACE(4))
    rights = array.array('i')
    rights.frombytes(ancillary[0][2])
    fd = rights[0]
    os.set_inheritable(fd, True)
    channel.close()
    os.execv(sys.argv[3], [sys.argv[3], str(Path(__file__).with_name('channel-probe.mjs')), str(fd), sys.argv[4]])
else:
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    process = subprocess.Popen([sys.executable, '-I', __file__, 'receive', str(child.fileno()),
                                sys.argv[3], sys.argv[4]], pass_fds=(child.fileno(),))
    child.close()
    parent.sendmsg([b'f'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [int(sys.argv[2])]))])
    parent.close()
    raise SystemExit(process.wait(timeout=5))
