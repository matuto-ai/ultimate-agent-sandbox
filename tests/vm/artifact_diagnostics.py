"""Bounded diagnostics for fixed account-free VM fixture commands only.

No argv/environment/configuration or arbitrary file content is logged. These
helpers add no production executor and do not establish successful confinement.
Capture/output/timeout acceptance limits stay with their fixed source callers.
"""
import json
import os
import stat
import subprocess

PHASES=frozenset(('quota-alpha','quota-beta','supervisor-alpha','supervisor-beta',
    'outer-facts','source-init','source-add','source-commit','source-pack',
    'quota-state-user','quota-state-group','quota-state-project','quota-hard-limits'))
SAMPLE_BYTES=768
MAX_DIAGNOSTIC_BYTES=16384
QUOTA_PHASES=frozenset(('fixed-identity','boot-marker','parent-quota-facts','open-mount',
    'open-room','project-prerequisites','exclusive-create','file-project-membership',
    'positive-allocation','over-limit-allocation','post-denial-proof','owned-cleanup','complete'))
QUOTA_CODES=frozenset(('CLEANUP_FILE_IDENTITY_CHANGED','CLEANUP_NAME_RECREATED',
    'CLEANUP_ROOM_IDENTITY_CHANGED','CLEANUP_UNLINK_UNCONFIRMED','DISPOSABLE_BOOT_MARKER_REQUIRED',
    'DUPLICATE_PARENT_FACT','FILE_PROJECT_ASSIGNMENT_MISMATCH','FIXED_DISPOSABLE_IDENTITY_REQUIRED',
    'GLOBAL_ROOT_QUOTA_CLAMPED','INSUFFICIENT_GLOBAL_SPACE','INVALID_PARENT_FACT_JSON',
    'PARENT_FACT_BOUND','PARENT_FACT_FIELDS','PARENT_QUOTA_FACT_MISMATCH','POSITIVE_ALLOCATION_UNPROVEN',
    'PROJECT_OVERLIMIT_NOT_DENIED','QUOTA_DEVICE_MISMATCH','QUOTA_IDENTITY_CHANGED','REPORT_BOUND',
    'ROOM_NAME_IDENTITY_CHANGED','ROOM_PROJECT_ASSIGNMENT_MISMATCH','UNOWNED_PROBE_FILE',
    'UNOWNED_ROOM_ROOT','UNSUPPORTED_ALLOCATION_UNIT','UNSUPPORTED_IOCTL_ABI','UNTRUSTED_GLOBAL_ROOT'))


def quota_observation(phase,data):
    """Retain typed failure facts even when they fall between sampled excerpts.

    This is diagnostic parsing only: it cannot accept a quota proof or convert
    a subprocess failure into success. No arbitrary child string is extracted.
    """
    if phase not in ('quota-alpha','quota-beta'):return None
    if data is None:return {'parse_status':'unavailable','reason':'absent'}
    if type(data) is not bytes:return {'parse_status':'unavailable','reason':'stream-type'}
    if len(data)>8192:return {'parse_status':'unavailable','reason':'oversized'}
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('duplicate diagnostic field')
            value[key]=item
        return value
    try:value=json.loads(data.decode('utf-8'),object_pairs_hook=unique)
    except (ValueError,UnicodeError,RecursionError):return {'parse_status':'unavailable','reason':'invalid-json'}
    if (type(value) is not dict or not {'version','status','phase','owned_cleanup'}<=set(value)
            or type(value.get('version')) is not int or value['version']!=1):
        return {'parse_status':'unavailable','reason':'shape'}
    result={'parse_status':'parsed'};rejected=[]
    for field in ('status','phase','failed_before_cleanup','error_code','errno','observed_errno','owned_cleanup'):
        if field not in value:continue
        item=value[field]
        if field in ('phase','failed_before_cleanup'):valid=type(item) is str and item in QUOTA_PHASES
        elif field=='status':valid=type(item) is str and item in ('passed','failed')
        elif field=='error_code':valid=item is None or (type(item) is str and item in QUOTA_CODES)
        elif field=='owned_cleanup':valid=type(item) is bool
        else:valid=item is None or (type(item) is int and 1<=item<=4095)
        if valid:result[field]=item
        else:rejected.append(field)
    if rejected:result.update(parse_status='partial',rejected_fields=rejected)
    return result


def stream_facts(data):
    if data is None:data=b''
    if type(data) is str:data=data.encode('utf-8',errors='replace')
    if type(data) is not bytes:raise TypeError('fixture diagnostic stream type')
    if len(data)<=SAMPLE_BYTES:head,tail=data,b''
    else:head,tail=data[:SAMPLE_BYTES//2],data[-SAMPLE_BYTES//2:]
    return {'bytes':len(data),'retained_bytes':len(head)+len(tail),
        'truncated':len(data)>SAMPLE_BYTES,'head':head.decode('utf-8',errors='replace'),
        'tail':tail.decode('utf-8',errors='replace')}


def file_facts(path):
    """Only head/tail of a fixed fixture-owned output file, never a whole dump."""
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        node=os.fstat(descriptor)
        if not stat.S_ISREG(node.st_mode) or node.st_nlink!=1:raise ValueError('ordinary fixture output required')
        if node.st_size<=SAMPLE_BYTES:return stream_facts(os.read(descriptor,SAMPLE_BYTES))
        head=os.read(descriptor,SAMPLE_BYTES//2)
        os.lseek(descriptor,max(0,node.st_size-SAMPLE_BYTES//2),os.SEEK_SET)
        tail=os.read(descriptor,SAMPLE_BYTES//2)
        return {'bytes':node.st_size,'retained_bytes':len(head)+len(tail),'truncated':True,
            'head':head.decode('utf-8',errors='replace'),'tail':tail.decode('utf-8',errors='replace')}
    finally:os.close(descriptor)


class FixtureCommandFailure(RuntimeError):
    def __init__(self,phase,outcome,*,returncode=None,errno=None,stdout=None,stderr=None,quota=None):
        if phase not in PHASES or outcome not in ('exit','output','timeout','launch','schema'):
            raise ValueError('unsupported fixed fixture diagnostic phase')
        if returncode is not None and type(returncode) is not int:raise TypeError('returncode type')
        if errno is not None and type(errno) is not int:raise TypeError('errno type')
        self.document={'version':1,'phase':phase,'outcome':outcome,'returncode':returncode,
            'errno':errno,'stdout':stdout or stream_facts(b''),'stderr':stderr or stream_facts(b'')}
        if quota is not None:self.document['quota_observation']=quota
        raw=json.dumps(self.document,sort_keys=True,ensure_ascii=True,separators=(',',':'))
        if len(raw.encode())>MAX_DIAGNOSTIC_BYTES:raise ValueError('fixture diagnostic bound')
        super().__init__('artifact fixture subprocess failure: '+raw)


def captured(phase,arguments,*,output_limit,inclusive=False,**kwargs):
    """Same fixed caller subprocess settings; never logs arguments/environment."""
    if phase not in PHASES or type(output_limit) is not int or not 0<output_limit<=1<<20:
        raise ValueError('fixed fixture capture profile required')
    if type(inclusive) is not bool:raise TypeError('capture comparison type')
    try:result=subprocess.run(arguments,**kwargs)
    except subprocess.TimeoutExpired as error:
        raise FixtureCommandFailure(phase,'timeout',stdout=stream_facts(error.output),
            stderr=stream_facts(error.stderr),quota=quota_observation(phase,error.output)) from None
    except OSError as error:
        raise FixtureCommandFailure(phase,'launch',errno=error.errno) from None
    size=len(result.stdout)+len(result.stderr)
    oversized=size>output_limit if inclusive else size>=output_limit
    if oversized or result.returncode!=0:
        raise FixtureCommandFailure(phase,'output' if oversized else 'exit',returncode=result.returncode,
            stdout=stream_facts(result.stdout),stderr=stream_facts(result.stderr),
            quota=quota_observation(phase,result.stdout))
    return result


def require_file_result(phase,returncode,stdout_path,stderr_path,*,output_limit):
    stdout,stderr=file_facts(stdout_path),file_facts(stderr_path)
    oversized=max(stdout['bytes'],stderr['bytes'])>output_limit
    if oversized or returncode!=0:
        raise FixtureCommandFailure(phase,'output' if oversized else 'exit',returncode=returncode,
            stdout=stdout,stderr=stderr)


def decoded_json(phase,result):
    try:return json.loads(result.stdout)
    except (ValueError,UnicodeError,RecursionError):
        raise FixtureCommandFailure(phase,'schema',returncode=result.returncode,
            stdout=stream_facts(result.stdout),stderr=stream_facts(result.stderr)) from None
