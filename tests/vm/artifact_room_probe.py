#!/usr/bin/env python3
"""Fixed disposable-VM observations/attacks, never production helper authority."""
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time
from uas.workstation_probe import process_status

BINARIES = ('artifact-bootstrap','artifact-evaluator','artifact-test-bootstrap','artifact-confinement-probe')


def facts():
    value={'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),
        'kernel_status':process_status(),'label':Path('/proc/self/attr/current').read_text().rstrip('\0\n'),
        'uid_map':Path('/proc/self/uid_map').read_text(),'gid_map':Path('/proc/self/gid_map').read_text(),
        'overflow_uid':int(Path('/proc/sys/kernel/overflowuid').read_text()),
        'overflow_gid':int(Path('/proc/sys/kernel/overflowgid').read_text()),
        'pid_namespace':os.readlink('/proc/self/ns/pid'),'mount_namespace':os.readlink('/proc/self/ns/mnt'),
        'helper_sha256':{},'private_paths':{}}
    for name in BINARIES:
        with open('/opt/uas/bin/'+name,'rb') as stream:value['helper_sha256'][name]=hashlib.file_digest(stream,'sha256').hexdigest()
    for name in ('/run/docker.sock','/uas/hub/room.db','/uas/control/hub.sock','/uas/sibling/secret'):
        try:os.stat(name);value['private_paths'][name]='visible'
        except OSError as error:value['private_paths'][name]=error.errno
    # No guest NIC does not prohibit socket creation. This is the discriminating
    # outer baseline for the actual helper-filter AF_INET SIGSYS attack below.
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM):value['outer_socket_creation']=True
    return value


def wrong_process():
    if (os.getuid(),os.getgid())!=(65530,65530):raise RuntimeError('dedicated test identity required')
    challenge=sys.stdin.buffer.read(32)
    if len(challenge)!=32:raise RuntimeError('challenge required')
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as channel:
        channel.connect('/uas/gate/gate.sock');channel.send(b'AGH1'+challenge)
        if channel.recv(32)!=b'AG-WRONG-PROCESS-1':raise RuntimeError('fixed test release required')
        child=os.fork()  # TEST-ONLY duplicate-FD attacker, never evaluator source.
        if child==0:
            channel.send(b'AG-CHILD-FORGED-FACT');time.sleep(2);os._exit(0)
        _,status=os.waitpid(child,0)
        if status:raise RuntimeError('fixed child failed')


def main():
    if len(sys.argv)!=2:raise RuntimeError('fixed probe mode required')
    mode=sys.argv[1]
    if mode=='idle' and os.getuid()==65532:time.sleep(600)
    elif mode=='facts' and os.getuid()==65532:print(json.dumps(facts(),sort_keys=True),flush=True)
    elif mode=='cross-room' and os.getuid()==65532:
        try:
            with open('/uas/foreign/cross-room-sentinel','rb') as stream:stream.read(1)
            value={'denied':False}
        except OSError as error:value={'denied':error.errno in (errno.EACCES,errno.EPERM),'errno':error.errno}
        print(json.dumps(value,sort_keys=True),flush=True)
    elif mode=='wrong-process':wrong_process()
    else:raise RuntimeError('unsupported fixed probe')


if __name__=='__main__':main()
