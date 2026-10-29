"""Finite native Gate owner/transport checks; OS boundaries are inert."""
import copy
import time
import unittest
from unittest.mock import Mock, patch
from contextlib import ExitStack, contextmanager

import test_artifact_helper as fixture
from uas import artifact_helper as helper, kernel_origin
from uas.artifact_protocol import ArtifactError
from uas.native_gate_control import NativeGateControl
from uas.native_review_host import NativeReviewHost, NativeReviewSources, NativeReviewAcceptance
from uas.diff_target import DiffSourceResolver


def launch():
    value = object.__new__(helper.GateHelperLaunch)
    value.workstation = fixture.workstation()
    value.scope, value.target = copy.deepcopy(fixture.SCOPE), copy.deepcopy(fixture.TARGET)
    value.origin, value.channel = fixture.origin(), Mock()
    value.transport = None
    value._inspect = Mock(); value.endpoint = Mock()
    value.state = 'bound'; value.journal = Mock(); value.binding = None
    value.exec_id = 'e' * 64; value.incarnation = 'i' * 32
    value.deadline = time.monotonic() + 5
    return value


def facade(profile=helper.PROFILE_ID):
    host = object.__new__(NativeReviewHost)
    host.identity = Mock(); host.sources = NativeReviewSources(host.identity)
    host.diff_sources = DiffSourceResolver(host.sources)
    host.identity.binding.room_id = fixture.SCOPE['room_id']
    host.identity.binding.room_instance = fixture.SCOPE['room_instance']
    active = object.__new__(NativeReviewAcceptance)
    active.host, active.identity = host, host.identity
    active.envelope = dict(run_id=fixture.SCOPE['run_id'], generation=fixture.SCOPE['generation'])
    active.phase, active.capability = 'observing', None
    active.in_fence = False; active.cuts = 0
    @contextmanager
    def commit():
        active.cuts += 1; active.in_fence = True
        try: yield
        finally: active.in_fence = False
    active.commit = commit
    host.identity.active = active
    service = helper.GateSupervisorService(host.diff_sources if profile == helper.DIFF_PROFILE else host.sources,
        Mock(), launch_factory=Mock(), listener=Mock(), profile=profile)
    return NativeGateControl(host, service, profile=profile)


class NativeGateControlTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.dup = self.stack.enter_context(patch.object(helper.os, 'dup', return_value=41))
        self.closefd = self.stack.enter_context(patch.object(helper.os, 'close'))
        self.stack.enter_context(patch.object(kernel_origin, '_identity', return_value=(3, 4)))
        self.stack.enter_context(patch.object(kernel_origin, 'alive', return_value=True))

    def offer(self, value):
        return value.local_offer(fixture.PATHS, exchange_id='1' * 32, controller='2' * 32)

    def test_same_channel_moves_once_original_origin_retained_and_observer_exact(self):
        value = launch(); original, channel = value.origin, value.channel
        offer = self.offer(value)
        self.assertIs(value.origin, original); self.assertIsNone(value.channel)
        self.assertIs(offer.channel, channel); self.assertIsNot(offer.origin, original)
        self.assertEqual(offer.origin.identity, original.identity)
        self.assertEqual(offer.origin.credentials, original.credentials)
        self.assertEqual(value.state, 'running'); self.assertEqual(offer.deadline, value.deadline)
        self.assertEqual(offer._document, value.binding)
        with self.assertRaises(ArtifactError): self.offer(value)
        self.dup.assert_called_once_with(40); channel.close.assert_not_called()
        self.closefd.assert_not_called()

    def test_invalid_request_owner_and_identity_drift_refuse(self):
        for change in ('revoked', 'unbound', 'nochannel', 'identity'):
            with self.subTest(change=change):
                value = launch(); channel = value.channel
                if change == 'revoked': value.origin.revoked = True
                elif change == 'unbound': value.state = 'running'
                elif change == 'nochannel': value.channel = None
                else: value.origin.identity = (9, 9)
                with self.assertRaises(ArtifactError): self.offer(value)
                channel.close.assert_not_called()
        value = launch()
        with self.assertRaises(ArtifactError): value.local_offer(['../escape'],exchange_id='1'*32,controller='2'*32)
        self.assertEqual(value.state,'bound')

    def test_dup_failure_preserves_original_custody_and_blocks_retry(self):
        value = launch(); channel = value.channel
        self.dup.side_effect = OSError('dup')
        with self.assertRaises(OSError): self.offer(value)
        self.assertEqual(value.state,'quarantined'); self.assertIs(value.channel,channel)
        self.closefd.assert_not_called(); channel.close.assert_not_called()
        with self.assertRaises(ArtifactError): self.offer(value)
        self.dup.assert_called_once()

    def test_offer_construction_failure_closes_only_observer(self):
        value = launch(); channel = value.channel
        with patch.object(helper,'GateOffer',side_effect=ArtifactError('INVALID')):
            with self.assertRaises(ArtifactError): self.offer(value)
        self.closefd.assert_called_once_with(41)
        self.assertIs(value.channel,channel); self.assertEqual(value.state,'quarantined')
        channel.close.assert_not_called()

    def test_running_journal_failure_does_not_transfer_channel_or_allow_replay(self):
        value=launch(); channel=value.channel
        value.journal.append.side_effect=[None,OSError('journal'),None]
        with self.assertRaises(OSError): self.offer(value)
        self.assertEqual(value.state,'quarantined'); self.assertIs(value.channel,channel)
        self.closefd.assert_called_once_with(41); channel.close.assert_not_called()
        with self.assertRaises(ArtifactError): self.offer(value)

    def test_binding_journal_failure_never_duplicates_or_moves(self):
        value=launch(); channel=value.channel; value.journal.append.side_effect=OSError('journal')
        with self.assertRaises(OSError): self.offer(value)
        self.dup.assert_not_called(); self.assertIs(value.channel,channel)
        with self.assertRaises(ArtifactError): self.offer(value)

    def test_actual_service_prepare_start_finish_registry_and_no_second_launch(self):
        owner=facade(); value=launch()
        owner.service.targets.prepare.return_value=copy.deepcopy(fixture.TARGET)
        owner.service.launch_factory.return_value=value
        value.start=Mock(return_value=value); value.finish=Mock(return_value={'cleanup':True})
        target=owner.prepare(fixture.SCOPE,{'source':'controlled'})
        offer=owner.start(fixture.SCOPE,target,fixture.PATHS)
        self.assertIs(owner._offers[fixture.SCOPE['evaluation_id']],offer)
        with self.assertRaises(ArtifactError): owner.finish(target,offer)
        offer.state='exited'; self.assertEqual(owner.finish(target,offer),{'cleanup':True})
        with self.assertRaises(ArtifactError): owner.start(fixture.SCOPE,target,fixture.PATHS)
        owner.service.launch_factory.assert_called_once(); value.start.assert_called_once()
        self.assertEqual(value.finish.call_count,1)

    def test_uncertain_start_never_retries_and_reconciles_original_service(self):
        owner=facade();owner.service.targets.prepare.return_value=copy.deepcopy(fixture.TARGET)
        owner.prepare(fixture.SCOPE,{})
        owner.service.launch_factory.side_effect=OSError('unknown')
        with self.assertRaises(OSError):owner.start(fixture.SCOPE,fixture.TARGET,fixture.PATHS)
        with self.assertRaises(ArtifactError):owner.start(fixture.SCOPE,fixture.TARGET,fixture.PATHS)
        self.assertFalse(owner.reconcile(fixture.SCOPE['evaluation_id'])['cleanup'])
        owner.service.launch_factory.assert_called_once()

    def test_source_owner_drift_and_foreign_offer_refuse(self):
        owner=facade();foreign=helper.GateOffer(fixture.bound_document(),Mock(),fixture.origin(),fixture.PATHS)
        foreign.state='exited'
        with self.assertRaises(ArtifactError):owner.finish(fixture.TARGET,foreign)
        with self.assertRaises(ArtifactError):owner.abort(fixture.SCOPE['evaluation_id'],offer=foreign)
        owner.host.sources=Mock()
        with self.assertRaises(ArtifactError):owner.current({})
        owner=facade();owner.service.resolver=Mock()
        with self.assertRaises(ArtifactError):NativeGateControl(owner.host,owner.service)

    def test_profile_resolve_uses_existing_exact_resolver_and_rejects_subject_drift(self):
        for profile in helper.BOOTSTRAPS:
            owner=facade(profile);owner.sources.resolve=Mock(return_value={'source':'resolved'})
            result=owner.resolve('run','participant','instance',subject='head' if profile==helper.DIFF_PROFILE else None)
            self.assertEqual(result,{'source':'resolved'})
            expected={'run_id':'run','participant_id':'participant','room_instance':'instance'}
            if profile==helper.DIFF_PROFILE:expected['subject']='head'
            owner.sources.resolve.assert_called_once_with(**expected)
        with self.assertRaises(ArtifactError):facade().resolve('r','p','i',subject='head')

    def test_effect_requires_exact_active_scope_and_releases_fence_before_service(self):
        owner=facade(); active=owner.host.identity.active
        def prepared(*args):
            self.assertFalse(active.in_fence)
            self.assertEqual(active.cuts,1)
            return copy.deepcopy(fixture.TARGET)
        owner.service.targets.prepare.side_effect=prepared
        owner.prepare(fixture.SCOPE,{})
        self.assertEqual(active.cuts,1)
        for change in ('absent','consuming','held','other-run','other-generation','other-room'):
            owner=facade(); active=owner.host.identity.active; scope=copy.deepcopy(fixture.SCOPE)
            if change=='absent':owner.host.identity.active=None
            elif change=='consuming':active.phase='consuming'
            elif change=='held':active.capability=object()
            elif change=='other-run':scope['run_id']='other'
            elif change=='other-generation':scope['generation']=2
            else:scope['room_id']='other'
            with self.subTest(change=change),self.assertRaises(ArtifactError):owner.prepare(scope,{})
            owner.service.targets.prepare.assert_not_called()

    def test_revocation_before_second_effect_denies_launch_but_cleanup_still_owned(self):
        owner=facade();owner.service.targets.prepare.return_value=copy.deepcopy(fixture.TARGET)
        owner.prepare(fixture.SCOPE,{})
        owner.host.identity.active=None
        with self.assertRaises(ArtifactError):owner.start(fixture.SCOPE,fixture.TARGET,fixture.PATHS)
        owner.service.launch_factory.assert_not_called()
        owner.service.targets.reconcile.return_value=True
        self.assertTrue(owner.abort(fixture.SCOPE['evaluation_id'])['cleanup'])

    def test_held_observer_constructor_failure_closes_raw_duplicate_once(self):
        value=launch(); channel=value.channel
        with patch.object(kernel_origin,'_identity',side_effect=kernel_origin.OriginUnavailable('unavailable')):
            with self.assertRaises(kernel_origin.OriginUnavailable):self.offer(value)
        self.dup.assert_called_once_with(40);self.closefd.assert_called_once_with(41)
        self.assertIs(value.channel,channel);channel.close.assert_not_called()
        self.assertEqual(value.state,'quarantined')
        with self.assertRaises(ArtifactError):self.offer(value)
