"""Explicit pure protocol and mocked ownership tests. No native/Git/child effects."""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import struct
import threading
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas.artifact_protocol import ArtifactError, RESERVATION_BYTES, canonical
from uas.diff_protocol import (PROFILE_ID, artifact_source, source_binding, validate_diff_source,
    validate_diff_target, diff_correlation, diff_request, diff_observation, diff_final_ack)
from uas.diff_target import DiffSourceResolver, DiffTargets, DIFF_RESERVATION_BYTES


def scope():
    return {'version': 1, 'evaluation_id': 'evaluation-a', 'room_id': 'room-a',
        'room_instance': 'instance-a', 'project_id': 'project-a', 'repository': 'owner/repo',
        'run_id': 'run-a', 'generation': 1, 'participant_id': 'alice',
        'policy_id': 'policy-a', 'policy_version': 1, 'policy_digest': 'd' * 64,
        'gate_id': 'changed-files', 'config_digest': 'e' * 64}


def source():
    owned = {'room_instance': 'instance-a', 'project_id': 'project-a',
        'repository': 'owner/repo', 'run_id': 'run-a', 'participant_id': 'alice',
        'slot_id': 'primary', 'branch': 'refs/heads/main', 'head_sha': 'b' * 40,
        'source_digest': 'c' * 64}
    subject = {'repository': 'owner/repo', 'pull_number': 7, 'pull_id': 77,
               'base_sha': 'a' * 40, 'head_sha': 'b' * 40, 'base_ref': 'main'}
    return {**owned, 'profile': PROFILE_ID, 'subject': subject,
            'binding_digest': source_binding(owned, subject)}


def target():
    src = source()
    def node(side):
        return {'target_id': ('1' if side == 'base' else '2') * 32,
            'head_sha': src['subject'][side + '_sha'], 'tree_sha': '3' * 40,
            'manifest_sha256': '4' * 64, 'source_digest': src['source_digest'],
            'device': 9, 'inode': 20 if side == 'base' else 21,
            'entries': 1, 'expanded_bytes': 4}
    return {'version': 1, 'profile': PROFILE_ID, 'source_digest': src['binding_digest'],
            'subject': src['subject'], 'base': node('base'), 'head': node('head')}


def config():
    return {'allowed_paths': [], 'forbidden_paths': [], 'require_nonempty': True}


class DiffProtocolTests(unittest.TestCase):
    def test_source_contains_authoritative_base_not_checkout_head_substitution(self):
        current = validate_diff_source(source(), require_head=True)
        self.assertNotEqual(current['subject']['base_sha'], current['head_sha'])
        self.assertEqual(set(artifact_source(current)), set(current) - {'profile', 'subject', 'binding_digest'})
        with self.assertRaises(ArtifactError): validate_diff_source(artifact_source(current))

    def test_source_subject_and_ownership_are_both_digest_bound(self):
        for mutate in (lambda x: x['subject'].update(base_sha='f'*40),
                       lambda x: x.update(source_digest='0'*64),
                       lambda x: x.update(profile='artifacts-v1-source'),
                       lambda x: x.update(extra=True),
                       lambda x: x['subject'].update(base_sha='not-a-commit')):
            value = source(); mutate(value)
            with self.assertRaises(ArtifactError): validate_diff_source(value)

    def test_moved_checkout_head_is_observable_but_cannot_prepare_old_subject(self):
        value = source(); value['head_sha'] = 'f'*40
        value['binding_digest'] = source_binding(artifact_source(value), value['subject'])
        self.assertEqual(validate_diff_source(value), value)
        with self.assertRaises(ArtifactError): validate_diff_source(value, require_head=True)

    def test_pair_requires_two_distinct_measured_exact_revision_leases(self):
        self.assertEqual(validate_diff_target(target()), target())
        for mutate in (lambda x: x['base'].update(head_sha='b'*40),
                       lambda x: x['base'].update(target_id=x['head']['target_id']),
                       lambda x: x['base'].update(inode=x['head']['inode']),
                       lambda x: x['base'].update(source_digest='0'*64),
                       lambda x: x.update(version=True),
                       lambda x: x.update(target_id='3'*32)):
            value = target(); mutate(value)
            with self.assertRaises(ArtifactError): validate_diff_target(value)

    def test_request_binds_both_measured_roots_scope_subject_and_config(self):
        request = diff_request(scope(), target(), config())
        self.assertEqual(len(request), 68)
        self.assertEqual(struct.unpack('!QQQQ', request[36:]), (9,20,9,21))
        correlation = diff_correlation(scope(), target(), config())
        self.assertEqual(request[4:36].hex(), correlation)
        for s,t,c in (({**scope(), 'generation': 2},target(),config()),
                      (scope(),{**target(), 'source_digest': '0'*64},config()),
                      (scope(),target(),{**config(), 'require_nonempty': False})):
            self.assertNotEqual(diff_correlation(s,t,c), correlation)
        self.assertEqual(diff_final_ack(correlation), b'DGA1'+bytes.fromhex(correlation))

    def test_raw_records_report_paths_not_pass_or_claim_verdict(self):
        digest = 'd'*64
        self.assertEqual(diff_observation(b'DGS1'+bytes.fromhex(digest),digest),
                         {'kind':'header','correlation':digest})
        raw = 'dir/á.txt'.encode()
        value = diff_observation(b'DGP1'+struct.pack('!II',0,len(raw))+raw,digest)
        self.assertEqual(value, {'kind':'path','index':0,'path':'dir/á.txt'})
        self.assertEqual(diff_observation(b'DGF1'+bytes.fromhex(digest)+struct.pack('!I',1),digest),
                         {'kind':'final','correlation':digest,'count':1})
        self.assertNotIn('ok',value); self.assertNotIn('verdict',value)

    def test_empty_actual_diff_is_complete_fact_not_implicit_pass(self):
        digest='d'*64
        self.assertEqual(diff_observation(b'DGF1'+bytes.fromhex(digest)+b'\0'*4,digest)['count'],0)

    def test_malformed_unbounded_escaped_and_uncorrelated_records_fail(self):
        digest='d'*64
        packets=[b'',b'DGS1'+bytes.fromhex('e'*64),b'DGF1'+bytes.fromhex(digest)+struct.pack('!I',129),
                 b'DGP1'+struct.pack('!II',128,1)+b'a',b'DGP1'+struct.pack('!II',0,2)+b'a',
                 b'DGP1'+struct.pack('!II',0,4)+b'../a',b'DGP1'+struct.pack('!II',0,1)+b'\xff',
                 b'DGP1'+struct.pack('!II',0,1)+b'\0',b'DGV1passed']
        for packet in packets:
            with self.subTest(packet=packet),self.assertRaises(ArtifactError): diff_observation(packet,digest)


class FakeOwnedResolver:
    def __init__(self):
        self.repo=Path('/owned-repository'); self.value=artifact_source(source())
    def resolve(self,*args): return deepcopy(self.value)
    def current(self,old):
        if any(old[k]!=self.value[k] for k in old if k!='head_sha'):
            raise ArtifactError('ARTIFACT_SOURCE_BINDING_CHANGED')
        return deepcopy(self.value)
    def recheck(self,old):
        if self.current(old)!=old: raise ArtifactError('ARTIFACT_SOURCE_CHANGED')
        return deepcopy(old)


class DiffResolverTests(unittest.TestCase):
    def test_exact_subject_resolution_and_independent_current_head(self):
        owned=FakeOwnedResolver(); resolver=DiffSourceResolver(owned)
        result=resolver.resolve('run-a','alice','instance-a',source()['subject'])
        self.assertEqual(result,source())
        owned.value['head_sha']='f'*40
        current=resolver.current(result)
        self.assertEqual(current['subject'],result['subject'])
        self.assertEqual(current['head_sha'],'f'*40)
        self.assertNotEqual(current['binding_digest'],result['binding_digest'])
        with self.assertRaises(ArtifactError): resolver.recheck(result)

    def test_wrong_subject_head_and_changed_ownership_fail_closed(self):
        owned=FakeOwnedResolver(); resolver=DiffSourceResolver(owned)
        with self.assertRaises(ArtifactError): resolver.resolve('run-a','alice','instance-a',{'opaque':object()})
        subject={**source()['subject'],'head_sha':'f'*40}
        with self.assertRaises(ArtifactError): resolver.resolve('run-a','alice','instance-a',subject)
        owned.value['slot_id']='other'
        with self.assertRaises(ArtifactError): resolver.current(source())


class FakeTrees:
    def __init__(self,root,journal,resolver,*,reserve_capacity):
        self.root,self.journal_root=Path(root),Path(journal)
        self.root_identity=self.journal_identity=[1,2]
        self.reserve_capacity=reserve_capacity
        self.owned={}; self._lock=threading.RLock(); self.calls=[]; self.fail_side=None
    def _journal(self,evaluation): return self.journal_root/(evaluation+'.json')
    def _prepare(self,child,owned,*,revision):
        side='base' if child['evaluation_id'].startswith('diff-base-') else 'head'
        assert self.reserve_capacity(child,RESERVATION_BYTES) is True
        self.calls.append((side,deepcopy(child),deepcopy(owned),revision))
        if self.fail_side==side: raise ArtifactError('FAKE_PREPARATION_FAILED')
        node=target()[side]
        lease=Mock()
        lease.target=node; lease.postverify.return_value=deepcopy(node);lease.cleanup.return_value=True
        self.owned[child['evaluation_id']]=lease
        return deepcopy(node)


class DiffLeaseTests(unittest.TestCase):
    def setUp(self):
        stack=ExitStack();self.addCleanup(stack.close)
        stack.enter_context(patch('uas.diff_target.ArtifactTargets',FakeTrees))
        stack.enter_context(patch('uas.diff_target._open_dir',return_value=91))
        stack.enter_context(patch('uas.diff_target.os.close'))
        stack.enter_context(patch('uas.diff_target.os.fstat',return_value=SimpleNamespace(st_dev=1,st_ino=2)))
        stack.enter_context(patch('uas.diff_target.os.fstatvfs',return_value=SimpleNamespace(f_frsize=4096,f_bsize=4096,f_bavail=100000)))
        stack.enter_context(patch('uas.diff_target.os.path.lexists',return_value=False))
        self.names=stack.enter_context(patch('uas.diff_target._names',return_value=[]))
        self.reserve=Mock(return_value=True)
        self.resolver=DiffSourceResolver(FakeOwnedResolver())
        self.owner=DiffTargets('/scratch','/journal',self.resolver,reserve_capacity=self.reserve)

    def test_atomic_double_capacity_and_two_exact_sha_requests_before_launch(self):
        result=self.owner.prepare(scope(),source())
        self.assertEqual(result,target())
        self.reserve.assert_called_once_with(scope(),DIFF_RESERVATION_BYTES)
        self.assertEqual(DIFF_RESERVATION_BYTES,2*RESERVATION_BYTES)
        calls=self.owner._trees.calls
        self.assertEqual([item[3] for item in calls],['a'*40,'b'*40])
        self.assertEqual(calls[0][2]['head_sha'],'b'*40) # ownership is NOT forged to base
        self.assertNotEqual(calls[0][1]['evaluation_id'],calls[1][1]['evaluation_id'])
        self.assertIsNone(self.owner._admission)
        self.assertFalse(self.owner._reserved_child(calls[0][1],RESERVATION_BYTES))

    def test_capacity_denial_precedes_every_materialization(self):
        self.reserve.return_value=False
        with self.assertRaises(ArtifactError):self.owner.prepare(scope(),source())
        self.assertEqual(self.owner._trees.calls,[])

    def test_two_lifetime_journal_slots_required_before_capacity_or_effect(self):
        self.names.return_value=['x']*15
        with self.assertRaises(ArtifactError):self.owner.prepare(scope(),source())
        self.reserve.assert_not_called();self.assertEqual(self.owner._trees.calls,[])

    def test_partial_second_target_failure_is_owned_and_reconciled_without_retry(self):
        self.owner._trees.fail_side='head'
        with self.assertRaises(ArtifactError):self.owner.prepare(scope(),source())
        self.assertIsNone(self.owner._admission)
        with self.assertRaises(ArtifactError):self.owner.prepare(scope(),source())
        self.assertTrue(self.owner.reconcile(scope()['evaluation_id'])['cleanup'])
        self.assertEqual(len(self.owner._trees.calls),2)

    def test_postproof_checks_both_targets_and_unchanged_document(self):
        pair=self.owner.prepare(scope(),source());lease=self.owner.lease(pair)
        self.assertEqual(lease.postverify(),pair)
        head=lease._leases()[1];head.postverify.return_value={**pair['head'],'tree_sha':'f'*40}
        with self.assertRaises(ArtifactError):lease.postverify()

    def test_launch_and_exit_apply_to_both_leases_no_recovery_adoption(self):
        pair=self.owner.prepare(scope(),source());lease=self.owner.lease(pair)
        lease.mark_launch_possible();lease.mark_exit_confirmed()
        for child in lease._leases():
            child.mark_launch_possible.assert_called_once();child.mark_exit_confirmed.assert_called_once()
        with self.assertRaises(ArtifactError):lease.mark_launch_possible()
        self.assertFalse(self.owner.reconcile(scope()['evaluation_id'])['cleanup'])
        self.assertFalse(self.owner.reconcile('unknown-evaluation')['cleanup'])

    def test_cleanup_failure_never_skips_the_second_owned_target(self):
        pair=self.owner.prepare(scope(),source());lease=self.owner.lease(pair)
        left,right=lease._leases();left.cleanup.side_effect=ArtifactError('FIRST_CLEANUP_FAILED')
        with self.assertRaises(ArtifactError):lease.cleanup()
        right.cleanup.assert_called_once()
        self.assertFalse(self.owner.reconcile(scope()['evaluation_id'])['cleanup'])

    def test_unknown_pair_and_mutated_source_are_never_owned(self):
        with self.assertRaises(ArtifactError):self.owner.lease(target())
        self.resolver.resolver.value['head_sha']='f'*40
        with self.assertRaises(ArtifactError):self.owner.prepare(scope(),source())
        self.reserve.assert_not_called()
