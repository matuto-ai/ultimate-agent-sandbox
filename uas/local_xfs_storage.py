"""Bounded installation-owned XFS image. Only explicit root apply calls this.

Unknown formatting is observed, never retried. No foreign image, block device,
partition, fstab entry or existing mount is modified.
"""
import os
from pathlib import Path
import re
import stat
import uuid

from .local_host_profile import canonical, digest, require
from .local_host_observe import canonical_node
from .local_host_process import run_fixed

IMAGE = 'storage.xfs'


def image_identity(fd, size, device):
    info=os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==0
            and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1
            and info.st_dev==device and info.st_size in (0,size), 'XFS_IMAGE_IDENTITY')
    return [info.st_dev,info.st_ino]


def filesystem_uuid(fd):
    header=os.pread(fd,48,0)
    if header[:4] != b'XFSB':return None
    require(len(header)==48,'XFS_HEADER_TRUNCATED')
    return str(uuid.UUID(bytes=header[32:48]))


def mounted(path, image):
    """Exact current namespace mount and kernel loop backing identity."""
    rows=[]
    with open('/proc/self/mountinfo',encoding='ascii') as stream:
        raw=stream.read(1024*1024+1)
    require(len(raw)<=1024*1024,'XFS_MOUNTINFO_BOUND')
    for line in raw.splitlines():
        fields=line.split();require('-' in fields,'XFS_MOUNTINFO')
        split=fields.index('-')
        if fields[4] != str(path):continue
        require(len(fields)>=split+4,'XFS_MOUNTINFO')
        rows.append((fields,split))
    require(len(rows)<=1,'XFS_STACKED_MOUNT')
    if not rows:return None
    fields,split=rows[0]
    require(fields[split+1]=='xfs' and fields[3]=='/' and
            re.fullmatch(r'/dev/loop[0-9]+',fields[split+2]) is not None
            and 'rw' in fields[5].split(',') and
            {'nodev','nosuid'} <= set(fields[5].split(',')) and
            ('prjquota' in fields[split+3].split(',') or 'pquota' in fields[split+3].split(',')),
            'XFS_FOREIGN_MOUNT')
    require(re.fullmatch(r'[0-9]+:[0-9]+',fields[2]) is not None,'XFS_LOOP_DEVICE')
    backing=Path('/sys/dev/block')/fields[2]/'loop/backing_file'
    raw=backing.read_text().strip()
    require(raw==str(image) and '\\' not in raw,'XFS_FOREIGN_BACKING')
    info=image.lstat();root=canonical_node(path)
    require(stat.S_ISREG(info.st_mode),'XFS_FOREIGN_BACKING')
    require(root.st_uid==0 and root.st_gid==0 and not root.st_mode&0o022,'XFS_ROOT_OWNERSHIP')
    report=run_fixed(['/usr/sbin/xfs_quota','-x','-c','state -p',str(path)])
    require(report.count('Project quota state on ')==1 and report.count('Accounting: ON')==1
            and report.count('Enforcement: ON')==1,'XFS_QUOTA_REQUIRED')
    return {'identity':[root.st_dev,root.st_ino], 'image_identity':[info.st_dev,info.st_ino]}


def _step(receipt, name, action, observe):
    """One issuance only; existing intent enters observation/reconciliation."""
    intent=name+'.intent.json';confirmed=name+'.confirmed.json'
    expected={'plan_id':receipt.plan['plan_id'],'step':name}
    prior=receipt._read(intent)
    require(prior is None or prior==expected,'XFS_STEP_SCOPE')
    if prior is None:
        require(receipt._read(confirmed) is None,'XFS_ORPHAN')
        if receipt._append(intent,expected):action()
    value=observe()
    previous=receipt._read(confirmed)
    if previous is not None:require(value==previous,'XFS_CONFIRMED_DRIFT')
    else:receipt._append(confirmed,value)
    return value


def prepare(receipt,index, *, make_directory, stable=False):
    operation=receipt.plan['operations'][index]
    require(operation['kind']=='prepare-owned-xfs-file' and operation['format_existing_device'] is False,
            'XFS_OPERATION')
    size=operation['bytes'];require(type(size) is int and 512*1024**2<=size<=1024**4
            and size%(1024**2)==0,'XFS_ALLOCATION_BOUND')
    require(os.geteuid()==0,'XFS_ROOT_REQUIRED')
    receipt._guard();root_info=os.fstat(receipt.fd)
    device=receipt.plan['storage_identity'][0]
    require(root_info.st_dev==device,'XFS_BACKING_FILESYSTEM')
    target=Path(operation['path']);image=receipt.root/IMAGE
    expected_uuid=str(uuid.UUID(hex=receipt.plan['plan_id'][:32]))
    state=receipt.state(index)
    if stable:
        policy={'version':3,'plan_id':receipt.plan['plan_id'],'uuid':expected_uuid}
        prior_policy=receipt._read('xfs-identity-policy.json')
        require(prior_policy==policy or (prior_policy is None and state['state']=='not-started'),
                'XFS_STABLE_POLICY_REQUIRED')
        receipt._append('xfs-identity-policy.json',policy)
    else:require(receipt._read('xfs-identity-policy.json') is None,'XFS_POLICY_DOWNGRADE')
    mount_step='xfs-mount-'+boot_id() if stable else 'xfs-mount'
    if state['state']=='not-started':receipt.intent(index)
    # A missing image ownership record after creation is deliberately unknown.
    # Never adopt/reformat an existing inode merely because its name matches.
    def create_image():
        space=os.fstatvfs(receipt.fd)
        require(space.f_bavail*space.f_frsize>=size,'XFS_ALLOCATION_SPACE')
        fd=os.open(IMAGE,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=receipt.fd)
        try:
            identity=image_identity(fd,size,device)
            os.fsync(fd);os.fsync(receipt.fd)
            receipt._append('xfs-image-owner.json',{'identity':identity,'bytes':size})
        finally:os.close(fd)
    def owned_image():
        owner=receipt._read('xfs-image-owner.json')
        require(type(owner) is dict and set(owner)=={'identity','bytes'} and owner['bytes']==size,
                'XFS_IMAGE_OWNERSHIP_UNKNOWN')
        fd=os.open(IMAGE,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=receipt.fd)
        try:require(image_identity(fd,size,device)==owner['identity'],'XFS_IMAGE_CHANGED')
        except BaseException:os.close(fd);raise
        return fd,owner
    def observe_image():
        fd,owner=owned_image();os.close(fd);return owner
    _step(receipt,'xfs-create',create_image,observe_image)
    fd,owner=owned_image()
    try:
        def allocate():
            space=os.fstatvfs(receipt.fd)
            require(space.f_bavail*space.f_frsize>=size,'XFS_ALLOCATION_SPACE')
            os.posix_fallocate(fd,0,size);os.fsync(fd)
        def allocated():
            info=os.fstat(fd)
            require(info.st_size==size and info.st_blocks*512>=size,'XFS_ALLOCATION_UNKNOWN')
            return owner
        _step(receipt,'xfs-allocate',allocate,allocated)
        def format_image():
            require(filesystem_uuid(fd) is None,'XFS_PREEXISTING_FILESYSTEM')
            require(image.lstat().st_ino==owner['identity'][1],'XFS_IMAGE_CHANGED')
            # No -f: even this owned inode is never forcibly reformatted.
            run_fixed(['/usr/sbin/mkfs.xfs','-K','-m','uuid='+expected_uuid,str(image)])
            os.fsync(fd)
        def formatted():
            require(filesystem_uuid(fd)==expected_uuid,'XFS_FORMAT_UNKNOWN')
            return {'image_identity':owner['identity'],'uuid':expected_uuid}
        _step(receipt,'xfs-format',format_image,formatted)
        current=mounted(target,image)
        directory_record=receipt._read('xfs-mountpoint.json')
        if current is None:
            if directory_record is None:
                def create_target():
                    evidence=make_directory(target,plan_id=receipt.plan['plan_id'],operation='xfs-mountpoint',
                        owner_uid=0,mode=0o711,create=True,expected_parent_identity=receipt.plan['storage_identity'])
                    receipt._append('xfs-mountpoint.json',evidence)
                def target_created():
                    evidence=receipt._read('xfs-mountpoint.json');require(evidence is not None,'XFS_MOUNTPOINT_UNKNOWN')
                    require(make_directory(target,plan_id=receipt.plan['plan_id'],operation='xfs-mountpoint',
                        owner_uid=0,mode=0o711,create=False,expected_parent_identity=receipt.plan['storage_identity'])==evidence,
                        'XFS_MOUNTPOINT_CHANGED')
                    return evidence
                _step(receipt,'xfs-mountpoint',create_target,target_created)
            else:
                require(make_directory(target,plan_id=receipt.plan['plan_id'],operation='xfs-mountpoint',
                    owner_uid=0,mode=0o711,create=False,expected_parent_identity=receipt.plan['storage_identity'])==directory_record,
                    'XFS_MOUNTPOINT_CHANGED')
        # Existing mount can only reconcile a previously persisted issuance.
        # The same observer runs for new, uncertain and confirmed paths.
        if current is not None:
            require(receipt._read(mount_step+'.intent.json') ==
                    {'plan_id':receipt.plan['plan_id'],'step':mount_step},'XFS_MOUNT_OWNERSHIP_UNKNOWN')
        def mount():
            require(current is None,'XFS_FOREIGN_MOUNT')
            run_fixed(['/usr/bin/mount','-t','xfs','-o','loop,prjquota,nodev,nosuid',str(image),str(target)])
        def observed_mount():
            value=mounted(target,image);require(value is not None,'XFS_MOUNT_UNKNOWN');return value
        current=_step(receipt,mount_step,mount,observed_mount)
        require(current['image_identity']==owner['identity'],'XFS_MOUNT_IMAGE_CHANGED')
        require(directory_record is not None or receipt._read('xfs-mountpoint.json') is not None,'XFS_MOUNTPOINT_UNKNOWN')
        evidence={'identity':([0,current['identity'][1]] if stable else current['identity']),'observed_sha256':digest({'uuid':expected_uuid,'image':owner})}
        if state['state']=='confirmed':require(evidence==state['evidence'],'XFS_CONFIRMED_DRIFT')
        else:receipt.confirm(index,evidence)
        return evidence
    finally:os.close(fd)


def boot_id():
    value=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(str(uuid.UUID(value))==value,'XFS_BOOT_ID')
    return value


def selection(receipt):
    owner=receipt._read('xfs-image-owner.json')
    policy=receipt._read('xfs-identity-policy.json')
    require(type(policy) is dict and policy=={'version':3,'plan_id':receipt.plan['plan_id'],
            'uuid':str(uuid.UUID(hex=receipt.plan['plan_id'][:32]))},'XFS_STABLE_POLICY_REQUIRED')
    require(type(owner) is dict and set(owner)=={'identity','bytes'},'XFS_IMAGE_OWNERSHIP_UNKNOWN')
    return {'receipt_root':str(receipt.root),'plan_id':receipt.plan['plan_id'],
            'image_identity':owner['identity'],'uuid':policy['uuid']}


def verify_owned_mount(value, storage_root):
    """Read-only proof; selection is never authority without private receipts."""
    import json
    from .local_host_profile import absolute_path
    from .local_host_receipt import PreparationReceipt
    require(type(value) is dict and set(value)=={'receipt_root','plan_id','image_identity','uuid'},'XFS_SELECTION')
    storage_root=absolute_path(str(storage_root))
    root=Path(absolute_path(value['receipt_root']));canonical_node(root)
    fd=os.open(root/'plan.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600
                and info.st_nlink==1 and 0<info.st_size<=65536,'XFS_PLAN_OWNER')
        raw=os.read(fd,65537);plan=json.loads(raw)
        require(canonical(plan)==raw and plan.get('plan_id')==value['plan_id']
                and plan['storage_root']==storage_root,'XFS_PLAN_SCOPE')
    finally:os.close(fd)
    with PreparationReceipt(root,plan,owner_uid=0) as receipt:
        require(selection(receipt)==value,'XFS_SELECTION_CHANGED')
        owner=receipt._read('xfs-image-owner.json')
        image=root/IMAGE
        fd=os.open(image,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            require(image_identity(fd,owner['bytes'],value['image_identity'][0])==value['image_identity']
                    and filesystem_uuid(fd)==value['uuid'],'XFS_IMAGE_CHANGED')
        finally:os.close(fd)
        step='xfs-mount-'+boot_id()
        require(receipt._read(step+'.intent.json')=={'plan_id':value['plan_id'],'step':step},'XFS_MOUNT_OWNERSHIP_UNKNOWN')
        current=mounted(Path(storage_root),image)
        require(current is not None and current==receipt._read(step+'.confirmed.json')
                and current['image_identity']==value['image_identity'],'XFS_MOUNT_CHANGED')
        return current
