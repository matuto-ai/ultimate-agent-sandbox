"""Fixed disposable native-profile observations; no arbitrary paths or commands."""
import json
import os
from pathlib import Path
import socket
import sys
import time


def process_status():
    raw=Path('/proc/self/status').read_text()
    if len(raw)>8192:raise RuntimeError('oversized actual process status')
    fields=dict(line.split(':',1) for line in raw.splitlines() if ':' in line)
    return {key:fields[key].strip() for key in ('CapEff','CapBnd','NoNewPrivs','Seccomp')}


def main():
    if len(sys.argv)!=2 or os.getuid() not in (65531,65532):
        raise RuntimeError('fixed confined qualification probe required')
    mode=sys.argv[1]
    if mode=='idle':
        time.sleep(180)
        return
    if mode=='observe':
        value={'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),
            'parent':os.getppid(),'kernel_status':process_status(),'label':Path('/proc/self/attr/current').read_text().rstrip('\0\n'),
            'uid_map':Path('/proc/self/uid_map').read_text(),
            'gid_map':Path('/proc/self/gid_map').read_text(),
            'overflow_uid':int(Path('/proc/sys/kernel/overflowuid').read_text()),
            'overflow_gid':int(Path('/proc/sys/kernel/overflowgid').read_text()),
            'pid_namespace':os.readlink('/proc/self/ns/pid'),
            'mount_namespace':os.readlink('/proc/self/ns/mnt'),
            'engine_mounted':Path('/run/docker.sock').exists() or Path('/var/run/docker.sock').exists()}
    elif mode=='peer':
        channel=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        try:
            channel.settimeout(2);channel.connect('/uas/peer/pi.sock')
            channel.send(b'UAS-NATIVE-PREFLIGHT')
            value={'connected':True}
        except OSError as error:
            value={'connected':False,'errno':error.errno}
        finally:channel.close()
    elif mode=='private':
        value={}
        for name,path in [('ledger','/uas/hub/room.db'),('control','/uas/control/hub.sock')]:
            try:
                os.stat(path)
                value[name]='visible'
            except OSError as error:value[name]=error.errno
        try:
            os.unlink('/uas/peer/pi.sock');value['unlink']='SUCCEEDED'
        except OSError as error:value['unlink']=error.errno
    else:
        raise RuntimeError('unknown fixed probe')
    print(json.dumps(value,sort_keys=True),flush=True)


if __name__=='__main__':main()
