"""Append-only endpoint generations for explicitly selected owned-XFS v3 hosts.

The caller holds its installation receipt lock. No existing directory is adopted:
reconciliation uses its exact root-owned marker plus durable generation evidence.
"""
import os
from pathlib import Path
import re
import uuid

from .local_host_profile import absolute_path, digest, require
from .local_host_receipt import PreparationReceipt
from .local_xfs_storage import boot_id

MAX_RECEIPT_FILES = 4096
MAX_GENERATIONS = 128


def _history(receipt, index, operation):
    receipt._guard()
    names=[]
    with os.scandir(receipt.fd) as entries:
        for entry in entries:
            require(len(names)<MAX_RECEIPT_FILES,'ENDPOINT_RECEIPT_BOUND')
            names.append(entry.name)
    prefix=f'endpoints-{index}-'
    generations={}
    for name in names:
        if not name.startswith(prefix):continue
        if name==prefix+'initial.json':continue
        match=re.fullmatch(re.escape(prefix)+r'boot-([0-9a-f-]{36})\.(intent|confirmed)\.json',name)
        require(match is not None,'ENDPOINT_GENERATION_NAME')
        generation,kind=match.groups()
        require(str(uuid.UUID(generation))==generation,'ENDPOINT_GENERATION_NAME')
        generations.setdefault(generation,{})[kind]=receipt._read(name)
    require(len(generations)<=MAX_GENERATIONS,'ENDPOINT_GENERATION_BOUND')
    for generation,records in generations.items():
        expected={'plan_id':receipt.plan['plan_id'],'step':prefix+'boot-'+generation,
                  'operation':digest(operation)}
        require(records.get('intent')==expected,'ENDPOINT_GENERATION_SCOPE')
        if 'confirmed' in records:PreparationReceipt._evidence(records['confirmed'])
    return generations


def prepare_endpoints(receipt,index,make_directory):
    """Observe or issue one endpoint directory creation in this boot only."""
    require(type(index) is int and 0<=index<len(receipt.plan['operations']),'ENDPOINT_OPERATION')
    operation=receipt.plan['operations'][index]
    require(type(operation) is dict and set(operation)=={'kind','path'}
            and operation['kind']=='prepare-owned-endpoints','ENDPOINT_OPERATION')
    target=Path(absolute_path(operation['path']))
    require(os.geteuid()==0,'ENDPOINT_ROOT_REQUIRED')
    plan_id=receipt.plan['plan_id']
    require(receipt._read('xfs-identity-policy.json')=={'version':3,'plan_id':plan_id,
        'uuid':str(uuid.UUID(hex=plan_id[:32]))},'ENDPOINT_STABLE_POLICY_REQUIRED')
    boot=boot_id();prefix=f'endpoints-{index}-';initial_name=prefix+'initial.json'
    state=receipt.state(index);initial=receipt._read(initial_name)
    if initial is None:
        require(state['state']=='not-started','ENDPOINT_LEGACY_OPERATION')
        initial={'plan_id':plan_id,'boot_id':boot,'operation':digest(operation)}
        receipt._append(initial_name,initial)
    require(type(initial) is dict and set(initial)=={'plan_id','boot_id','operation'}
            and initial['plan_id']==plan_id and initial['operation']==digest(operation)
            and type(initial['boot_id']) is str
            and str(uuid.UUID(initial['boot_id']))==initial['boot_id'],'ENDPOINT_INITIAL_SCOPE')
    history=_history(receipt,index,operation)
    first=history.get(initial['boot_id'],{})
    if state['state']=='confirmed':
        require(first.get('confirmed')==state['evidence'],'ENDPOINT_BASELINE_DRIFT')
    if state['state']=='not-started':receipt.intent(index)
    step=prefix+'boot-'+boot
    intent={'plan_id':plan_id,'step':step,'operation':digest(operation)}
    prior=history.get(boot)
    created=None
    if prior is None:
        require(len(history)<MAX_GENERATIONS,'ENDPOINT_GENERATION_BOUND')
        try:target.lstat()
        except FileNotFoundError:
            # Initial issuance, or a new boot after a completed earlier generation.
            # A same-boot intent always takes the observation-only branch below.
            require((boot==initial['boot_id'] and not history) or
                    (boot!=initial['boot_id'] and 'confirmed' in first),
                    'ENDPOINT_RECREATE_NOT_PROVEN')
            if receipt._append(step+'.intent.json',intent):
                created=make_directory(target,plan_id=plan_id,operation=operation['kind'],
                                       owner_uid=0,mode=0o711,create=True)
        else:
            observed=make_directory(target,plan_id=plan_id,operation=operation['kind'],
                                    owner_uid=0,mode=0o711,create=False)
            require(any(row.get('confirmed')==observed for row in history.values()),
                    'ENDPOINT_FOREIGN_DIRECTORY')
            receipt._append(step+'.intent.json',intent)
    observed=make_directory(target,plan_id=plan_id,operation=operation['kind'],
                            owner_uid=0,mode=0o711,create=False)
    PreparationReceipt._evidence(observed)
    require(created is None or observed==created,'ENDPOINT_CREATION_DRIFT')
    if prior is not None and 'confirmed' in prior:
        require(observed==prior['confirmed'],'ENDPOINT_CONFIRMED_DRIFT')
    receipt._append(step+'.confirmed.json',observed)
    baseline=observed if boot==initial['boot_id'] else first.get('confirmed')
    require(baseline is not None,'ENDPOINT_BASELINE_UNKNOWN')
    if state['state']=='confirmed':require(baseline==state['evidence'],'ENDPOINT_BASELINE_DRIFT')
    else:receipt.confirm(index,baseline)
    return observed
