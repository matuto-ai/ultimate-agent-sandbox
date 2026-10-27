#!/usr/bin/env python3
"""Fixed disposable-VM observations/attacks, never production helper authority."""
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time
from uas.workstation_probe import process_status

BINARIES = ('artifact-bootstrap','artifact-evaluator','artifact-test-bootstrap','artifact-confinement-probe')
MOUNTINFO_BYTES=128<<10
MOUNTINFO_LINES=1024


def _mount_require(condition,code):
    if not condition:raise RuntimeError(code)


def _mount_path(raw):
    # Kernel mountinfo escaping, not arbitrary Python/URL escape decoding.
    escapes={b'040':b' ',b'011':b'\t',b'012':b'\n',b'134':b'\\'}
    result=bytearray();index=0
    while index<len(raw):
        if raw[index:index+1]==b'\\':
            value=escapes.get(raw[index+1:index+4])
            _mount_require(value is not None,'TMP_MOUNT_INVALID_ESCAPE')
            result.extend(value);index+=4
        else:result.append(raw[index]);index+=1
    return bytes(result)


def parse_tmp_mountinfo(raw):
    """Pure bounded selection; no paths, sources or raw options are returned.

    mountinfo separates per-mount flags from per-superblock options. This
    reports only the actual /tmp mount's fixed typed fields; capacity/ownership
    come independently from its held directory descriptor, not option strings.
    """
    _mount_require(type(raw) is bytes and 0<len(raw)<=MOUNTINFO_BYTES,'TMP_MOUNTINFO_BOUND')
    lines=raw.splitlines()
    _mount_require(raw.endswith(b'\n') and 0<len(lines)<=MOUNTINFO_LINES,'TMP_MOUNTINFO_LINES')
    _mount_require(not any(c<32 and c!=10 for c in raw),'TMP_MOUNTINFO_CONTROL')
    matches=[];ids=set()
    for line in lines:
        sides=line.split(b' - ')
        _mount_require(len(sides)==2,'TMP_MOUNTINFO_SHAPE')
        left,right=sides[0].split(b' '),sides[1].split(b' ')
        _mount_require(len(left)>=6 and len(right)==3 and all(left+right),'TMP_MOUNTINFO_SHAPE')
        _mount_require(all(re.fullmatch(rb'[1-9][0-9]{0,19}',n) for n in left[:2]),'TMP_MOUNTINFO_ID')
        mount_id,parent_id=map(int,left[:2])
        _mount_require(max(mount_id,parent_id)<2**64 and mount_id not in ids,'TMP_MOUNTINFO_ID')
        ids.add(mount_id)
        point=_mount_path(left[4])
        # Reject equivalent spellings instead of overlooking an alias/stack.
        equivalent=os.path.normpath(b'/'+point.lstrip(b'/'))==b'/tmp'
        if not equivalent:continue
        _mount_require(left[4]==b'/tmp' and left[3]==b'/','TMP_MOUNT_NONCANONICAL')
        _mount_require(re.fullmatch(rb'(0|[1-9][0-9]{0,9}):(0|[1-9][0-9]{0,9})',left[2]) is not None,
            'TMP_MOUNT_DEVICE')
        major,minor=map(int,left[2].split(b':'))
        _mount_require(max(major,minor)<2**32,'TMP_MOUNT_DEVICE')
        options=left[5].split(b',')
        _mount_require(len(options)<=64 and all(options) and len(set(options))==len(options),
            'TMP_MOUNT_OPTIONS')
        options=set(options)
        _mount_require(len(options&{b'ro',b'rw'})==1 and not any(
            a in options and b in options for a,b in ((b'dev',b'nodev'),(b'exec',b'noexec'),(b'suid',b'nosuid'))),
            'TMP_MOUNT_OPTIONS')
        matches.append({'mount_id':mount_id,'parent_mount_id':parent_id,
            'device_major':major,'device_minor':minor,'filesystem':'tmpfs' if right[0]==b'tmpfs' else 'other',
            'mount_flags':{'readonly':b'ro' in options,'nosuid':b'nosuid' in options,
                'nodev':b'nodev' in options,'noexec':b'noexec' in options}})
    _mount_require(len(matches)==1,'TMP_MOUNT_NOT_UNIQUE')
    return matches[0]


def _read_tmp_mountinfo():
    with open('/proc/self/mountinfo','rb') as stream:raw=stream.read(MOUNTINFO_BYTES+1)
    return parse_tmp_mountinfo(raw)


def _tmp_statvfs(value):
    _mount_require(type(value.f_frsize) is int and 0<value.f_frsize<=1<<20
        and type(value.f_blocks) is int and 0<=value.f_blocks<2**64
        and type(value.f_flag) is int and 0<=value.f_flag<2**64,'TMP_MOUNT_STATVFS_SHAPE')
    flags={}
    for name,constant in (('readonly','ST_RDONLY'),('nosuid','ST_NOSUID'),('nodev','ST_NODEV'),('noexec','ST_NOEXEC')):
        bit=getattr(os,constant,None)
        _mount_require(type(bit) is int and bit>0,'TMP_MOUNT_FLAGS_UNSUPPORTED')
        flags[name]=bool(value.f_flag&bit)
    size=value.f_blocks*value.f_frsize
    _mount_require(size<2**64,'TMP_MOUNT_STATVFS_SHAPE')
    return {'size_bytes':size,'allocation_unit':value.f_frsize,'statvfs_flags':flags}


def tmp_mount_observation():
    """Actual fixed-path observation only; parent independently admits profile.

    A missing/ambiguous/changed observation or close failure cannot produce a
    successful facts report. No probe writes, mounts or permission changes.
    """
    mount=_read_tmp_mountinfo();descriptor=None
    try:
        descriptor=os.open('/tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        before=os.fstat(descriptor);filesystem=_tmp_statvfs(os.fstatvfs(descriptor))
        _mount_require(stat.S_ISDIR(before.st_mode),'TMP_MOUNT_NOT_DIRECTORY')
        _mount_require((os.major(before.st_dev),os.minor(before.st_dev))==
            (mount['device_major'],mount['device_minor']),'TMP_MOUNT_DEVICE_CHANGED')
        after=os.fstat(descriptor);named=os.stat('/tmp',follow_symlinks=False)
        identity=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid)
        _mount_require(identity(before)==identity(after)==identity(named),'TMP_MOUNT_IDENTITY_CHANGED')
        _mount_require(_tmp_statvfs(os.fstatvfs(descriptor))==filesystem and _read_tmp_mountinfo()==mount,
            'TMP_MOUNT_CHANGED')
        return {'version':1,**mount,**filesystem,'uid':before.st_uid,'gid':before.st_gid,
            'mode':stat.S_IMODE(before.st_mode),'device':before.st_dev,'inode':before.st_ino}
    finally:
        if descriptor is not None:os.close(descriptor)


def facts():
    value={'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),
        'tmp_mount':tmp_mount_observation(),
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
