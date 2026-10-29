"""Root-side persistent Hub process ownership, no runtime/actor launcher.

Retain exact Popen handles and an inherited host-lock descriptor. Unknown starts
are recorded before launching and are never repeated by ensure. No PID scanning,
account setup, daemon policy changes or inferred old-owner revocation.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import sys
import time

from .lifecycle import LifecycleError
from .workstation_admission import _canonical, _unique


def require(ok,code):
    if not ok:raise LifecycleError(code)


def mapping_digest(pid):
    require(type(pid) is int and pid>0,'LOCAL_HUB_WORKSTATION_PID')
    value={name:Path('/proc/'+str(pid)+'/'+name).read_text() for name in ('uid_map','gid_map')}
    require(all(value[k].split()==['0','100000','65536'] for k in value),'LOCAL_HUB_MAPPING')
    for name,filename in (('overflow_uid','overflowuid'),('overflow_gid','overflowgid')):
        value[name]=int(Path('/proc/sys/kernel/'+filename).read_text())
    require(value['overflow_uid']==65534 and value['overflow_gid']==65534,'LOCAL_HUB_OVERFLOW')
    return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()


def send_startup(process,raw):
    """Bound the private pipe write too; a child that stalls cannot hang host."""
    fd=process.stdin.fileno();os.set_blocking(fd,False)
    deadline=time.monotonic()+10;offset=0
    while offset<len(raw):
        left=deadline-time.monotonic();require(left>0,'LOCAL_HUB_START_WRITE_UNKNOWN')
        _,writable,_=select.select([],[fd],[],left)
        require(bool(writable),'LOCAL_HUB_START_WRITE_UNKNOWN')
        try:written=os.write(fd,raw[offset:])
        except BlockingIOError:continue
        require(written>0,'LOCAL_HUB_START_WRITE_UNKNOWN');offset+=written


def read_ready(process,room,instance,*,seconds=35):
    deadline=time.monotonic()+seconds;raw=bytearray()
    while len(raw)<=4096:
        require(process.poll() is None,'LOCAL_HUB_START_EXITED')
        left=deadline-time.monotonic();require(left>0,'LOCAL_HUB_START_UNCONFIRMED')
        readable,_,_=select.select([process.stdout],[],[],left)
        require(bool(readable),'LOCAL_HUB_START_UNCONFIRMED')
        byte=os.read(process.stdout.fileno(),1)
        require(bool(byte),'LOCAL_HUB_START_EOF')
        if byte==b'\n':break
        raw.extend(byte)
    require(len(raw)<=4096,'LOCAL_HUB_READY_SIZE')
    value=json.loads(raw,object_pairs_hook=_unique)
    require(type(value) is dict and set(value)=={'version','status','room_id','room_instance','controller'}
            and type(value['version']) is int and value['version']==1 and value['status']=='ready'
            and value['room_id']==room and value['room_instance']==instance
            and type(value['controller']) is str and 0<len(value['controller'])<=256,
            'LOCAL_HUB_READY_SCOPE')
    return value


class LocalServices:
    def __init__(self,host_lock_fd):
        require(type(host_lock_fd) is int and host_lock_fd>=3,'LOCAL_HOST_LOCK_REQUIRED')
        require(stat.S_ISREG(os.fstat(host_lock_fd).st_mode),'LOCAL_HOST_LOCK_REQUIRED')
        self._lock_fd=host_lock_fd;self._rooms={}

    def ensure(self,room,owner,backend,state):
        require(os.geteuid()==0,'LOCAL_SERVICE_ROOT_REQUIRED')
        require(room==backend.profile.room['id'] and type(state.get('instance_id')) is str,'LOCAL_SERVICE_SCOPE')
        if room in self._rooms:
            require(self._rooms[room]['instance']==state['instance_id'],'LOCAL_SERVICE_INSTANCE_CHANGED')
            return self.status(room)
        # Persist uncertainty in this owner before the first external start.
        row={'instance':state['instance_id'],'state':'unknown','process':None,'backend':backend,'resource_state':state};self._rooms[room]=row
        workstation=backend.admit(state)
        require(workstation['State']['Running'] is True,'LOCAL_WORKSTATION_NOT_RUNNING')
        hub=backend.ensure_hub(state)
        row['hub_id']=hub['Id']
        require(hub['State']['Running'] is False,'LOCAL_HUB_PREVIOUS_OWNER_UNCONFIRMED')
        require(len(backend.listeners)>=2,'LOCAL_HUB_LISTENERS_UNAVAILABLE')
        layout=backend.layout(state);fds=[backend.listeners[i].fileno() for i in (0,1)]
        resources={'hub_id':hub['Id'],'instance':state['instance_id'],
                   'control_path':str(layout['control']/'hub.sock'),
                   'mapping_digest':mapping_digest(workstation['State']['Pid']),
                   'peer_fd':fds[0],'control_fd':fds[1]}
        document={'version':1,'room':backend.profile.room,'resources':resources}
        raw=_canonical(document)+b'\n';require(len(raw)<=65536,'LOCAL_HUB_STARTUP_SIZE')
        docker_group=os.stat('/run/docker.sock').st_gid
        process=subprocess.Popen([sys.executable,'-m','uas.local_hub_host'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            user=165533,group=165533,extra_groups=[165531,docker_group],
            pass_fds=tuple(fds+[self._lock_fd]),cwd='/',
            env={'PATH':'/usr/bin:/bin','PYTHONPATH':str(Path(__file__).resolve().parents[1]),
                 'PYTHONDONTWRITEBYTECODE':'1'})
        row['process']=process
        # Parent retains writer only. Child inherits read end and host lock.
        send_startup(process,raw)
        row['ready']=read_ready(process,room,state['instance_id']);row['state']='ready'
        return self.status(room)

    @property
    def rooms(self):
        """Rooms with a confirmed startup, for orderly Workstation Stop first."""
        return tuple(room for room,row in self._rooms.items() if 'ready' in row)

    def status(self,room):
        row=self._rooms.get(room)
        if row is None:return {'hub':'not-owned','runtime':'not-started'}
        process=row['process']
        if row['state']=='ready' and (process is None or process.poll() is not None):row['state']='unknown'
        return {'hub':row['state'],'runtime':'not-started','instance':row['instance']}

    def revoke(self,instance,scope):
        # This exact child has no participant launch/admission path. Normal
        # Workstation Stop retains its live idle Hub; unknown ownership fails.
        rows=[row for row in self._rooms.values() if row['instance']==instance]
        if not rows or scope not in {'participants','all'}:return False
        if scope=='participants':
            return all(row['state']=='ready' and row['process'] is not None
                       and row['process'].poll() is None for row in rows)
        for row in rows:
            process=row['process']
            if process is None:return False
            row['state']='unknown'
            try:
                process.stdin.close()  # EOF fences the actual held control.
                process.wait(timeout=10)
                backend,state=row['backend'],row['resource_state']
                observed=backend._hub(state)
                if observed is None or observed['Id']!=row.get('hub_id'):return False
                backend.validate_hub(state,observed)
                if observed['State']['Running']:
                    if row.get('stop_attempted'):return False
                    row['stop_attempted']=True
                    try:backend._run(['stop','--time','5',observed['Id']])
                    except Exception:pass  # Reconcile one uncertain stop, never repeat.
                observed=backend._hub(state)
                if observed is None or observed['Id']!=row.get('hub_id'):return False
                backend.validate_hub(state,observed)
                if observed['State']['Running']:return False
            except Exception:return False
            process.stdout.close()
            row['state']='stopped'
        return True

    def close(self):
        results=[self.revoke(row['instance'],'all') for row in list(self._rooms.values())]
        return all(results)
