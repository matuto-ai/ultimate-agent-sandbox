"""Pure bounded content-free Library observation wire contract."""
from copy import deepcopy
from datetime import datetime
import re

def identifier(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}', value): fail()

def digest(value,length=None):
    if type(value) is not str or len(value) not in ((length,) if length else (40,64)) or not re.fullmatch('[0-9a-f]+',value): fail()

COUNTS = ('active_depth','parked_depth','oldest_age_seconds','adjudication_wait_seconds',
          'published_drafts','completed_outcomes','duplicate_merges','human_corrections',
          'human_decisions','provider_version','attempt','retry_count','replay_lag',
          'capture_failures','source_failures','model_failures','validation_failures',
          'transport_failures','audit_failures','recovery_failures')
TIMES = ('window_start','window_end','next_retry_at','projected_at','provider_observed_at')
HASHES = ('canonical_sha','projected_sha','provider_profile_sha256')
ENUMS = {'coverage':{'complete','partial'},'queue_status':{'known','unknown','unavailable'},
         'drain_state':{'unknown','IDLE','READY','ACTIVE','BACKOFF','BLOCKED','DISPOSED'},
         'projection_state':{'unknown','current','stale','unavailable'},
         'provider_state':{'unknown','available','unavailable'},
         'provider_mode':{'unknown','local','hosted'},
         'effectiveness':{'unmeasured','observed'},'feedback':{'unmeasured','observed'}}
FIELDS = ('project_identity',*COUNTS,*TIMES,*HASHES,*ENUMS,'drain_id')


class ObservationError(ValueError):
    code = 'INVALID_LIBRARY_OBSERVATION'

def fail(): raise ObservationError('INVALID_LIBRARY_OBSERVATION')
def moment(value):
    if type(value) is not str or len(value)>40: fail()
    try: result=datetime.fromisoformat(value)
    except ValueError: fail()
    if result.tzinfo is None: fail()
    return result


def validate_row(row):
    if type(row) is not dict or set(row)!=set(FIELDS): fail()
    identifier(row['project_identity'])
    for key in COUNTS:
        if row[key] is not None and (type(row[key]) is not int or not 0<=row[key]<2**53): fail()
    for key in TIMES:
        if row[key] is not None: moment(row[key])
    if moment(row['window_start'])>moment(row['window_end']): fail()
    for key in HASHES:
        if row[key] is not None:
            digest(row[key], 64 if key.endswith('sha256') else None)
    for key,values in ENUMS.items():
        if type(row[key]) is not str or row[key] not in values: fail()
    if row['drain_id'] is not None: identifier(row['drain_id'])
    for label,numerator,denominator in (('effectiveness','duplicate_merges','completed_outcomes'),
                                       ('feedback','human_corrections','human_decisions')):
        if row[label]=='unmeasured':
            if row[numerator] is not None or row[denominator] is not None: fail()
        elif (row[numerator] is None or row[denominator] is None
              or row[denominator]==0 or row[numerator]>row[denominator]): fail()
    if row['provider_state']=='unknown' and any(row[x] is not None for x in ('provider_profile_sha256','provider_observed_at','provider_version')): fail()
    if row['provider_state']=='unknown' and row['provider_mode']!='unknown': fail()
    if row['provider_state']!='unknown' and (any(row[k] is None for k in ('provider_profile_sha256','provider_observed_at','provider_version')) or row['provider_mode']=='unknown'): fail()
    if row['queue_status']!='known' and any(row[k] is not None for k in ('active_depth','parked_depth','oldest_age_seconds','adjudication_wait_seconds')): fail()
    return deepcopy(row)


def observation(value):
    if type(value) is not dict or set(value)!={'sequence','observed_at','row'}: fail()
    if type(value['sequence']) is not int or not 1<=value['sequence']<2**53: fail()
    moment(value['observed_at']); validate_row(value['row'])
    if value['row']['window_end']!=value['observed_at']: fail()
    return deepcopy(value)

