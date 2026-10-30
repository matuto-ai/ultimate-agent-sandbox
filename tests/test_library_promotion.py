"""T46 synthetic handoff: existing capture and archive, never release authority.

Scenario decisions are invented data. This test does not implement or validate
human approval and sends no package to a recipient. Git targets are disposable.
"""
import unittest
from unittest.mock import patch

import test_library_archive as archive_fixture
from uas import library_bundle


class PromotionRehearsalTests(unittest.TestCase):
    def test_synthetic_outcome_capture_failure_and_archived_freeze(self):
        fx = archive_fixture.ArchiveTests(
            'test_archive_restore_canonical_commits_same_identity_and_retained_drafts')
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        source = fx.source
        source_version = source.head()
        self.assertEqual(fx.state(), 'active')
        original_root = source.contents('index.md')
        body = (
            'SYNTHETIC REHEARSAL ONLY; no human approval or external handoff occurred.\n'
            'Source version: ' + source_version + '\n'
            'Package: synthetic-guide-v1. Audience: fictional guidance maintainers.\n'
            'Simulated disclosure decision: scenario-D1, exact v1 text only; '
            'no attachments, links, metadata, identities or private evidence released.\n'
            'Simulated destination decision: scenario-A1, accepted upstream in scenario.\n'
            'Destination evidence: fictional review scenario-A1, no real commit.\n'
            'Additional evidence denied; independently reproducible toy example used.\n'
            'Adoption unknown. Actual human approval and destination evidence: none.\n'
        )
        value = dict(type='decision', title='Synthetic handoff outcome', body=body, sources=[])
        before = source.head()
        with patch.object(source.publisher, 'publish', side_effect=OSError('synthetic outage')):
            failed = source.enqueue('promotion-failure', 'promotion-outcome', value)
        self.assertEqual(failed.outcome, 'NOT_DURABLE', failed)
        self.assertEqual(source.head(), before)  # known before-write fault, not a general promise
        result = source.enqueue('promotion-retry', 'promotion-outcome', value)
        self.assertEqual(result.outcome, 'DURABLY_QUEUED', result)
        draft = source.contents(result.path)
        self.assertIn(body, draft)
        self.assertIn('Submission Actor: actor-alpha', draft)
        self.assertEqual(library_bundle.frontmatter(draft, result.path)[0]['status'], 'draft')
        archived = fx.send(fx.value('archive', 'promotion-archive'))
        self.assertEqual(archived['outcome'], 'COMMITTED', archived)
        frozen = source.head()
        self.assertEqual(fx.state(), 'archived')
        self.assertEqual(source.contents(result.path), draft)
        denied = source.enqueue('promotion-after-archive', 'promotion-later-outcome', value)
        self.assertEqual((denied.outcome, denied.reason), ('REJECTED', 'PROJECT_ARCHIVING'))
        self.assertEqual(source.head(), frozen)
        self.assertEqual(source.contents(result.path), draft)
        self.assertEqual(source.contents('index.md', source_version), original_root)
        self.assertIn('Library state: archived', source.contents('index.md'))
