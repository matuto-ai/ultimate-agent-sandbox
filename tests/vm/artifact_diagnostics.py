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


# Fixture diagnostic vocabulary only; never a protocol verdict or admission.
SUPERVISOR_PREFIX=b'UAS_ARTIFACT_FAILURE:'
SUPERVISOR_PHASES=frozenset(('supervisor-main','source-setup','source-resolve','target-setup',
    'control-resolve','control-current','control-prepare','control-start','control-finish',
    'control-abort','control-reconcile','control-unsupported','confinement-probes'))
SUPERVISOR_CODES=frozenset((
    'ARTIFACT_ALLOCATION_LIMIT',
    'ARTIFACT_ALTERNATE_UNSUPPORTED',
    'ARTIFACT_CAPACITY_ADMISSION_REQUIRED',
    'ARTIFACT_CLEANUP_LIMIT',
    'ARTIFACT_CLEANUP_UNSAFE_NODE',
    'ARTIFACT_COPY_FAILED',
    'ARTIFACT_CORRELATION_MISMATCH',
    'ARTIFACT_DIRECTORY_LIMIT',
    'ARTIFACT_EXIT_UNCONFIRMED',
    'ARTIFACT_EXPANSION_LIMIT',
    'ARTIFACT_GIT_CLEANUP_UNCONFIRMED',
    'ARTIFACT_GIT_EXIT_ERROR',
    'ARTIFACT_GIT_UNTRUSTED',
    'ARTIFACT_HEAD_BINDING_CHANGED',
    'ARTIFACT_HELPER_GROUP_UNAVAILABLE',
    'ARTIFACT_JOURNAL_OWNERSHIP',
    'ARTIFACT_JOURNAL_RECONCILIATION_REQUIRED',
    'ARTIFACT_LAUNCH_REPLAY',
    'ARTIFACT_MATERIALIZATION_MISMATCH',
    'ARTIFACT_MATERIALIZATION_TIMEOUT',
    'ARTIFACT_METADATA_LIMIT',
    'ARTIFACT_NO_LIVE_LAUNCH',
    'ARTIFACT_OBJECT_HASH_MISMATCH',
    'ARTIFACT_OBJECT_LIMIT',
    'ARTIFACT_OBJECT_LIMIT_OR_TYPE',
    'ARTIFACT_OBJECT_OUTPUT_LIMIT',
    'ARTIFACT_OBJECT_SIZE_LIMIT',
    'ARTIFACT_OBJECT_UNAVAILABLE',
    'ARTIFACT_PATH_TRAVERSAL_UNAVAILABLE',
    'ARTIFACT_PREPARATION_REPLAY',
    'ARTIFACT_PROMISOR_UNSUPPORTED',
    'ARTIFACT_REF_MISSING',
    'ARTIFACT_REQUEST_LIMIT',
    'ARTIFACT_RESOURCE_JOURNAL_LIMIT',
    'ARTIFACT_RESOURCE_RECORD_LIMIT',
    'ARTIFACT_ROOM_CAPACITY_UNAVAILABLE',
    'ARTIFACT_ROOM_UNAVAILABLE',
    'ARTIFACT_SCOPE_SOURCE_MISMATCH',
    'ARTIFACT_SCRATCH_CAPACITY_UNAVAILABLE',
    'ARTIFACT_SCRATCH_OWNERSHIP',
    'ARTIFACT_SCRATCH_REPLACED',
    'ARTIFACT_SLOT_IDENTITY_CHANGED',
    'ARTIFACT_SLOT_NOT_OWNED',
    'ARTIFACT_SOURCE_BINDING_CHANGED',
    'ARTIFACT_SOURCE_CHANGED',
    'ARTIFACT_SOURCE_UNVERIFIABLE',
    'ARTIFACT_SUPERVISOR_MISMATCH',
    'ARTIFACT_TARGET_CHANGED',
    'ARTIFACT_TARGET_NOT_OWNED',
    'ARTIFACT_TARGET_NOT_PREPARED',
    'ARTIFACT_TARGET_OWNERSHIP_LOST',
    'ARTIFACT_TREE_LIMIT',
    'DUPLICATE_ARTIFACT_PATH',
    'INCOMPLETE_ARTIFACT_PACK',
    'INVALID_ARTIFACT_ADMIN',
    'INVALID_ARTIFACT_COMMIT',
    'INVALID_ARTIFACT_OBJECT_FRAMING',
    'INVALID_ARTIFACT_OBJECT_HEADER',
    'INVALID_ARTIFACT_OBJECT_REQUEST',
    'INVALID_ARTIFACT_OWNERSHIP',
    'INVALID_ARTIFACT_PATH',
    'INVALID_ARTIFACT_PATHS',
    'INVALID_ARTIFACT_RECORD',
    'INVALID_ARTIFACT_REF',
    'INVALID_ARTIFACT_SCOPE',
    'INVALID_ARTIFACT_SOURCE',
    'INVALID_ARTIFACT_TARGET',
    'NONCANONICAL_ARTIFACT_TREE',
    'UNSAFE_ARTIFACT_METADATA',
    'UNSAFE_ARTIFACT_PATH',
    'UNSAFE_ARTIFACT_TREE_ENTRY',
    'UNSUPPORTED_ARTIFACT_OBJECT_LAYOUT',
    'UNSUPPORTED_ARTIFACT_PACK_LAYOUT',
    'UNSUPPORTED_ARTIFACT_TREE_ENTRY',
    'GATE_PATH_TRAVERSAL_UNAVAILABLE',
    'ARTIFACT_OTHER_ERROR','OS_ERROR','UNCLASSIFIED_ERROR'))
MAX_SUPERVISOR_RECORDS=8
MAX_SUPERVISOR_RECORD_BYTES=512
MAX_SUPERVISOR_STREAM_BYTES=1<<20
MAX_EXCEPTION_CHAIN=8


def supervisor_failure(phase,error,artifact_error_type):
    """Typed actual exception observations, never message or traceback parsing.

    Follow explicit cause, otherwise context, including suppressed context.
    Nearest actual OSError errno is reported with its depth; a bounded/cyclic
    chain is explicit and never represented as a fully inspected chain.
    """
    if phase not in SUPERVISOR_PHASES:raise ValueError('fixed Supervisor failure phase required')
    if not isinstance(error,BaseException):raise TypeError('exception required')
    code='UNCLASSIFIED_ERROR';number=depth=None;seen=set();node=error;status='complete'
    for index in range(MAX_EXCEPTION_CHAIN):
        if id(node) in seen:status='cycle';break
        seen.add(id(node))
        if code=='UNCLASSIFIED_ERROR' and isinstance(node,artifact_error_type):
            value=node.code
            code=value if type(value) is str and value in SUPERVISOR_CODES else 'ARTIFACT_OTHER_ERROR'
        if isinstance(node,OSError):
            if code=='UNCLASSIFIED_ERROR':code='OS_ERROR'
            if number is None and type(node.errno) is int and 1<=node.errno<=4095:number,depth=node.errno,index
        node=node.__cause__ if node.__cause__ is not None else node.__context__
        if node is None:break
    else:status='cycle' if id(node) in seen else 'bounded'
    return {'version':1,'phase':phase,'code':code,'errno':number,'errno_depth':depth,'chain_status':status}


def supervisor_observation(data):
    """Strict records from the complete bounded stream, before excerpts.

    These are diagnostics only; malformed/absent/overbound input never changes
    subprocess acceptance or establishes a resolver, quota or helper result.
    """
    if type(data) is not bytes:return {'parse_status':'unavailable','reason':'stream-type'}
    if len(data)>MAX_SUPERVISOR_STREAM_BYTES:return {'parse_status':'unavailable','reason':'oversized'}
    records=[];rejected=0;matched=0;unretained=0
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('duplicate diagnostic field')
            value[key]=item
        return value
    for line in data.splitlines():
        if not line.startswith(SUPERVISOR_PREFIX):continue
        matched+=1
        if len(records)>=MAX_SUPERVISOR_RECORDS:unretained+=1;continue
        raw=line[len(SUPERVISOR_PREFIX):]
        if len(raw)>MAX_SUPERVISOR_RECORD_BYTES:rejected+=1;continue
        try:value=json.loads(raw.decode('ascii'),object_pairs_hook=unique)
        except (ValueError,UnicodeError,RecursionError):rejected+=1;continue
        if (type(value) is not dict or set(value)!={'version','phase','code','errno','errno_depth','chain_status'}
                or type(value['version']) is not int or value['version']!=1
                or type(value['phase']) is not str or value['phase'] not in SUPERVISOR_PHASES
                or type(value['code']) is not str or value['code'] not in SUPERVISOR_CODES
                or type(value['chain_status']) is not str or value['chain_status'] not in ('complete','cycle','bounded')
                or not ((value['errno'] is None and value['errno_depth'] is None)
                    or (type(value['errno']) is int and 1<=value['errno']<=4095
                        and type(value['errno_depth']) is int and 0<=value['errno_depth']<MAX_EXCEPTION_CHAIN))):
            rejected+=1;continue
        records.append(value)
    if not matched:return {'parse_status':'unavailable','reason':'absent'}
    return {'parse_status':'partial' if rejected or unretained else 'parsed','records':records,
        'matched_records':matched,'rejected_records':rejected,'unretained_records':unretained}


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


def file_facts(path,*,supervisor=False):
    """Bounded excerpts and optional typed records, never a whole-file dump."""
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        node=os.fstat(descriptor)
        if not stat.S_ISREG(node.st_mode) or node.st_nlink!=1:raise ValueError('ordinary fixture output required')
        if supervisor and node.st_size<=MAX_SUPERVISOR_STREAM_BYTES:
            # Child is exited in require_file_result. Still bound reads if the
            # file unexpectedly grows; no arbitrary text enters observations.
            chunks=[];remaining=MAX_SUPERVISOR_STREAM_BYTES+1
            while remaining:
                chunk=os.read(descriptor,min(65536,remaining))
                if not chunk:break
                chunks.append(chunk);remaining-=len(chunk)
            data=b''.join(chunks)
            observation=supervisor_observation(data)  # Before head/tail sampling.
            value=stream_facts(data);value['supervisor_observation']=observation
            return value
        if node.st_size<=SAMPLE_BYTES:return stream_facts(os.read(descriptor,SAMPLE_BYTES))
        head=os.read(descriptor,SAMPLE_BYTES//2)
        os.lseek(descriptor,max(0,node.st_size-SAMPLE_BYTES//2),os.SEEK_SET)
        tail=os.read(descriptor,SAMPLE_BYTES//2)
        value={'bytes':node.st_size,'retained_bytes':len(head)+len(tail),'truncated':True,
            'head':head.decode('utf-8',errors='replace'),'tail':tail.decode('utf-8',errors='replace')}
        if supervisor:value['supervisor_observation']={'parse_status':'unavailable','reason':'oversized'}
        return value
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
    stdout=file_facts(stdout_path,supervisor=phase in ('supervisor-alpha','supervisor-beta'))
    stderr=file_facts(stderr_path)
    oversized=max(stdout['bytes'],stderr['bytes'])>output_limit
    if oversized or returncode!=0:
        raise FixtureCommandFailure(phase,'output' if oversized else 'exit',returncode=returncode,
            stdout=stdout,stderr=stderr)


def decoded_json(phase,result):
    try:return json.loads(result.stdout)
    except (ValueError,UnicodeError,RecursionError):
        raise FixtureCommandFailure(phase,'schema',returncode=result.returncode,
            stdout=stream_facts(result.stdout),stderr=stream_facts(result.stderr)) from None
