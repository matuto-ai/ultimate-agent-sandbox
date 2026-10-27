#!/usr/bin/env python3
"""Fixed nonroot disposable-VM project-quota exhaustion, no helper authority."""
import errno
import json
import os
from pathlib import Path
import signal
import stat
import sys


def main():
    if len(sys.argv)!=2 or sys.argv[1] not in ('alpha','beta') or (os.getuid(),os.getgid())!=(165533,165533):
        raise RuntimeError('fixed disposable mapped quota probe required')
    marker=Path('/run/uas-vm-fixture')
    if not marker.is_file() or marker.stat().st_uid!=0:raise RuntimeError('disposable boot marker required')
    signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(15)
    parent=Path('/mnt/uas-artifacts')/sys.argv[1]
    directory=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    descriptor=-1;identity=None;denied=None
    try:
        if os.fstat(directory).st_uid!=165533:raise RuntimeError('owned quota root required')
        descriptor=os.open('.quota-exhaustion-probe',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
        node=os.fstat(descriptor);identity=(node.st_dev,node.st_ino)
        try:os.posix_fallocate(descriptor,0,(256<<20)+4096)
        except OSError as error:denied=error.errno
        if denied!=errno.EDQUOT:raise RuntimeError('configured project hard quota did not deny excess allocation')
        print(json.dumps({'room':sys.argv[1],'uid':os.getuid(),'requested_bytes':(256<<20)+4096,
            'configured_limit':256<<20,'errno':denied,'project_hard_quota_enforced':True}),flush=True)
    finally:
        if descriptor>=0:os.close(descriptor)
        if identity is not None:
            current=os.stat('.quota-exhaustion-probe',dir_fd=directory,follow_symlinks=False)
            if (current.st_dev,current.st_ino)!=identity or not stat.S_ISREG(current.st_mode):
                raise RuntimeError('quota probe ownership changed; retained')
            os.unlink('.quota-exhaustion-probe',dir_fd=directory);os.fsync(directory)
        os.close(directory)


if __name__=='__main__':main()
