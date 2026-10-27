"""Pure raw-object/SQLite attribution tests: no Git, shell, sockets or process I/O."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from uas.git_policy import GitIdentity
from uas.git_provenance import GitProvenance, MAX_COMMIT, parse_commit
from uas.ledger import LedgerError, Origin


TREE = '1' * 40
PARENT = '2' * 40
ALICE = GitIdentity('alice', 'Alice Canonical', 'alice@example.invalid')
BOB = GitIdentity('bob', 'Bob Canonical', 'bob@example.invalid')
SOURCE_AUTHOR = 'Original Author <original@example.invalid> 1234567890 +0230'


def origin(actor='alice', incarnation='first'):
    return Origin(actor, 'participant-' + actor, incarnation, 'epoch-1', ('git-read', 'git-push'))


def raw_commit(*, author=None, committer=None, identity=ALICE, parent=None, message=b'private message\n', extra=b''):
    author = author or f'{identity.name} <{identity.email}> 1760000000 +0000'
    committer = committer or f'{identity.name} <{identity.email}> 1760000001 +0000'
    return (f'tree {TREE}\n'.encode() + (b'' if parent is None else f'parent {parent}\n'.encode())
        + f'author {author}\ncommitter {committer}\n'.encode() + extra + b'\n' + message)


class CommitParserTests(unittest.TestCase):
    def invalid(self, raw):
        with self.assertRaises(LedgerError) as raised:
            parse_commit(raw)
        self.assertEqual('INVALID_GIT_COMMIT', raised.exception.code)

    def test_actual_object_id_uses_commit_header_and_exact_raw_bytes(self):
        raw = raw_commit(parent=PARENT)
        result = parse_commit(raw)
        self.assertEqual(hashlib.sha1(b'commit ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), result.oid)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result.raw_digest)
        self.assertEqual((PARENT,), result.parents)
        self.assertEqual(TREE, result.tree)
        self.assertEqual(b'private message\n', result.message)

    def test_source_exact_author_timezone_and_date_are_preserved(self):
        self.assertEqual(SOURCE_AUTHOR, parse_commit(raw_commit(author=SOURCE_AUTHOR)).author)

    def test_signed_source_extension_continuation_is_not_identity(self):
        result = parse_commit(raw_commit(extra=b'gpgsig -----BEGIN PGP SIGNATURE-----\n author forged <fake@example.invalid> 1 +0000\n -----END PGP SIGNATURE-----\n'))
        self.assertTrue(result.author.startswith('Alice Canonical '))

    def test_duplicate_missing_or_continued_core_header_fails(self):
        raw = raw_commit()
        for malformed in (raw.replace(b'author ', b'unknown ', 1),
                          raw.replace(b'\n\n', b'\nauthor Another <a@b> 1 +0000\n\n'),
                          raw.replace(b'committer ', b' author ', 1),
                          raw.replace(b'tree ', b'parent ', 1),
                          raw.replace(b'tree ' + TREE.encode(), b'tree ' + b'1' * 64)):
            with self.subTest(raw=malformed):
                self.invalid(malformed)

    def test_invalid_identities_and_timestamps_fail(self):
        for identity in ('A\nOther <a@b> 1 +0000', 'A\rOther <a@b> 1 +0000', 'A <a b> 1 +0000',
                         ' A <a@b> 1 +0000', 'A <a@b> nope +0000', 'A <a@b> 1 +2400',
                         'A <a@b> 1 +0060', 'A <a@b> 01 +0000', 'A <a@b> 1 +0000 forged',
                         'A\u200d <a@b> 1 +0000', 'A\u2028 <a@b> 1 +0000',
                         'A' * 257 + ' <a@b> 1 +0000', 'A <a@b> 9999999999999999999 +0000'):
            with self.subTest(identity=identity):
                self.invalid(raw_commit(author=identity))

    def test_bounds_binary_controls_and_nonbytes_fail(self):
        for raw in ('not bytes', None, b'', b'a' * (MAX_COMMIT + 1), raw_commit(message=b'bad\0message'),
                    raw_commit().replace(b'\n\n', b'\r\n\r\n'), raw_commit().replace(b'Alice', b'\xfflice')):
            with self.subTest(kind=type(raw)):
                self.invalid(raw)

    def test_empty_message_and_negative_old_source_time_are_valid(self):
        parsed = parse_commit(raw_commit(author='Historic <old@example.invalid> -123 +0000', message=b''))
        self.assertEqual(b'', parsed.message)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'provenance.db'
        self.store = GitProvenance(self.path, 'room', 'project')
        self.addCleanup(lambda: self.store.close())
        self.alice = origin()

    def error(self, code, function, *args, **kwargs):
        with self.assertRaises(LedgerError) as raised:
            function(*args, **kwargs)
        self.assertEqual(code, raised.exception.code)

    def prepare(self, operation='op', who=None, identity=ALICE, **kwargs):
        kwargs.setdefault('request_digest', 'a' * 64)
        kwargs.setdefault('checkout_id', 'checkout-' + operation)
        return self.store.prepare(operation, who or self.alice, identity, authorize=lambda: True, **kwargs)

    def anchor(self, *, contributors=('source-actor',), author=SOURCE_AUTHOR):
        raw = raw_commit(author=author, message=b'never persist source message\n')
        oid = parse_commit(raw).oid
        self.store.anchor_source('owner/source', oid, raw, contributors=contributors)
        return oid

    def cherry(self, oid, *, identity=ALICE, author=SOURCE_AUTHOR, message=None):
        return raw_commit(identity=identity, author=author, parent=PARENT,
            message=message if message is not None else b'private cherry message\n\n(cherry picked from commit ' + oid.encode() + b')\n')

    def prepare_cherry(self, *, contributors=('source-actor',)):
        oid = self.anchor(contributors=contributors)
        result = self.prepare(kind='cherry-pick', source_repository='owner/source', source_oid=oid, parent_oid=PARENT)
        return oid, result

    def test_prepare_finish_and_exact_retry_are_durable_and_never_reexecute(self):
        self.assertTrue(self.prepare()['execute'])
        self.assertFalse(self.prepare()['execute'])
        raw = raw_commit()
        finished = self.store.finish('op', self.alice, raw, authorize=lambda: True)
        self.assertEqual('COMMITTED', finished['status'])
        self.assertEqual(['alice'], finished['contributors'])
        self.assertEqual(finished, self.store.finish('op', self.alice, raw, authorize=lambda: True))
        self.assertFalse(self.prepare()['execute'])
        self.store.close()
        self.store = GitProvenance(self.path, 'room', 'project')
        self.assertEqual(finished, self.store.status('op', self.alice, authorize=lambda: True))
        self.assertEqual(['alice'], self.store.contributors(finished['commit_oid']))

    def test_every_duplicate_or_result_disclosure_reauthenticates(self):
        self.prepare()
        self.error('FORBIDDEN', self.store.prepare, 'op', self.alice, ALICE, authorize=lambda: False, request_digest='a' * 64, checkout_id='checkout-op')
        self.error('FORBIDDEN', self.store.status, 'op', self.alice, authorize=lambda: False)
        self.error('FORBIDDEN', self.store.finish, 'op', self.alice, raw_commit(), authorize=lambda: False)

    def test_operation_and_origin_binding_cannot_be_selected_by_retry(self):
        self.prepare()
        self.error('ID_CONFLICT', self.store.prepare, 'op', origin('bob'), BOB, authorize=lambda: True, request_digest='a' * 64, checkout_id='checkout-op')
        self.error('ID_CONFLICT', self.store.prepare, 'op', self.alice, ALICE, parent_oid=PARENT, authorize=lambda: True, request_digest='a' * 64, checkout_id='checkout-op')
        self.error('GIT_ORIGIN_MISMATCH', self.store.status, 'op', origin(incarnation='replacement'), authorize=lambda: True)
        self.error('GIT_ACTOR_MISMATCH', self.store.prepare, 'new', self.alice, BOB, authorize=lambda: True, request_digest='a' * 64, checkout_id='checkout-new')

    def test_controller_native_request_digest_is_bound_without_raw_arguments(self):
        self.assertTrue(self.prepare(request_digest='a' * 64)['execute'])
        self.assertFalse(self.prepare(request_digest='a' * 64)['execute'])
        self.error('ID_CONFLICT', self.store.prepare, 'op', self.alice, ALICE,
                   request_digest='b' * 64, authorize=lambda: True, checkout_id='checkout-op')
        for digest in ([], '', 'a' * 40, 'a' * 63, 'g' * 64):
            self.error('INVALID_GIT_REQUEST_DIGEST', self.store.prepare, 'other', self.alice, ALICE,
                       request_digest=digest, authorize=lambda: True, checkout_id='checkout-other')

    def test_ordinary_author_and_committer_must_both_be_canonical(self):
        self.prepare()
        self.error('GIT_AUTHOR_MISMATCH', self.store.finish, 'op', self.alice,
                   raw_commit(author=SOURCE_AUTHOR), authorize=lambda: True)
        self.error('GIT_COMMITTER_MISMATCH', self.store.finish, 'op', self.alice,
                   raw_commit(committer=SOURCE_AUTHOR), authorize=lambda: True)
        self.assertEqual('PREPARED', self.store.status('op', self.alice, authorize=lambda: True)['status'])

    def test_parent_is_bound_and_unborn_cannot_smuggle_a_parent(self):
        self.prepare()
        self.error('GIT_PARENT_MISMATCH', self.store.finish, 'op', self.alice, raw_commit(parent=PARENT), authorize=lambda: True)
        self.prepare('other', parent_oid=PARENT)
        self.error('GIT_PARENT_MISMATCH', self.store.finish, 'other', self.alice, raw_commit(), authorize=lambda: True)
        self.assertEqual('COMMITTED', self.store.finish('other', self.alice, raw_commit(parent=PARENT), authorize=lambda: True)['status'])

    def test_unanchored_or_wrong_source_sha_never_prepares(self):
        self.error('GIT_SOURCE_UNANCHORED', self.store.prepare, 'op', self.alice, ALICE,
                   kind='cherry-pick', source_repository='owner/source', source_oid='3' * 40, authorize=lambda: True, request_digest='a' * 64, checkout_id='checkout-op')
        self.error('GIT_SOURCE_MISMATCH', self.store.anchor_source, 'owner/source', '3' * 40, raw_commit())
        self.assertEqual([], self.store.actor_contributions('alice'))

    def test_same_sha_in_other_repository_is_not_an_anchor_grant(self):
        oid = self.anchor()
        self.error('GIT_SOURCE_UNANCHORED', self.store.prepare, 'op', self.alice, ALICE,
                   kind='cherry-pick', source_repository='other/source', source_oid=oid, authorize=lambda: True, request_digest='a' * 64, checkout_id='checkout-op')

    def test_source_lookup_survives_restart_without_untrusted_git_metadata(self):
        oid = self.anchor()
        expected = self.store.source_anchor('owner/source', oid)
        self.assertEqual(SOURCE_AUTHOR, expected['author'])
        self.store.close()
        self.store = GitProvenance(self.path, 'room', 'project')
        self.assertEqual(expected, self.store.source_anchor('owner/source', oid))
        self.error('GIT_SOURCE_UNANCHORED', self.store.source_anchor, 'owner/other', oid)

    def test_advertisements_are_durable_exact_repository_object_facts(self):
        first, second = 'a' * 40, 'b' * 40
        self.assertFalse(self.store.was_advertised('owner/source', first))
        result = self.store.record_advertisements('owner/source', [second, first, first])
        self.assertEqual(2, result['count'])
        self.assertEqual(2, result['new_count'])
        self.assertEqual(0, self.store.record_advertisements('owner/source', [first])['new_count'])
        self.assertTrue(self.store.was_advertised('owner/source', first))
        self.assertFalse(self.store.was_advertised('other/source', first))
        self.store.close()
        self.store = GitProvenance(self.path, 'room', 'project')
        self.assertTrue(self.store.was_advertised('owner/source', second))
        self.assertFalse(self.store.was_advertised('owner/source', 'c' * 40))

    def test_advertisement_bounds_and_null_oid_cannot_be_source_evidence(self):
        for value in ('a' * 40, None, ['a' * 40] * 4097, ['0' * 40]):
            self.error('INVALID_GIT_ADVERTISEMENT', self.store.record_advertisements, 'owner/source', value)
        self.error('INVALID_GIT_OBJECT', self.store.record_advertisements, 'owner/source', ['a' * 64])
        self.assertEqual(0, self.store.record_advertisements('owner/empty', [])['count'])

    def test_advertisement_storage_failure_does_not_publish_source_fact(self):
        with patch.object(self.store, '_commit', side_effect=sqlite3.OperationalError('disk detail')):
            self.error('GIT_PROVENANCE_UNAVAILABLE', self.store.record_advertisements, 'owner/source', ['a' * 40])
        self.store.close()
        self.store = GitProvenance(self.path, 'room', 'project')
        self.assertFalse(self.store.was_advertised('owner/source', 'a' * 40))

    def test_one_prepared_mutation_per_checkout_and_other_checkout_remains_usable(self):
        self.assertIsNone(self.store.pending_checkout('primary'))
        self.prepare(checkout_id='primary')
        self.error('GIT_CHECKOUT_BUSY', self.prepare, 'another', checkout_id='primary')
        self.assertTrue(self.prepare('parallel', checkout_id='concurrent')['execute'])
        pending = self.store.pending_checkout('primary')
        self.assertEqual('op', pending['operation_id'])
        self.assertEqual('primary', pending['checkout_id'])
        self.assertFalse(pending['execute'])

    def test_checkout_is_part_of_exact_operation_identity(self):
        self.prepare(checkout_id='primary')
        self.error('ID_CONFLICT', self.prepare, checkout_id='different')
        self.assertIsNone(self.store.pending_checkout('different'))

    def test_finish_and_abort_release_checkout_without_clearing_actor_history(self):
        self.prepare(checkout_id='primary')
        self.store.finish('op', self.alice, raw_commit(), authorize=lambda: True)
        self.assertIsNone(self.store.pending_checkout('primary'))
        self.prepare('second', checkout_id='primary')
        self.store.abort('second', self.alice, authorize=lambda: True)
        self.assertIsNone(self.store.pending_checkout('primary'))
        self.assertEqual(2, len(self.store.actor_contributions('alice')))

    def test_unknown_retains_and_fences_checkout_across_reopen(self):
        self.prepare(checkout_id='primary')
        self.store.mark_unknown('op', self.alice, authorize=lambda: True)
        self.error('GIT_CHECKOUT_FENCED', self.prepare, 'another', checkout_id='primary')
        self.store.close()
        self.store = GitProvenance(self.path, 'room', 'project')
        self.assertEqual('UNKNOWN', self.store.pending_checkout('primary')['status'])
        self.assertEqual('UNKNOWN', self.store.reconcile_unknown('op')['status'])
        self.error('GIT_CHECKOUT_FENCED', self.prepare, 'another', checkout_id='primary')

    def test_positive_fenced_recovery_keeps_checkout_reserved(self):
        self.prepare(checkout_id='primary')
        self.store.recover_pending(is_fenced=lambda _: True)
        self.assertEqual('UNKNOWN', self.store.pending_checkout('primary')['status'])
        self.error('GIT_CHECKOUT_FENCED', self.prepare, 'another', checkout_id='primary')

    def test_trusted_reconciliation_of_exact_commit_releases_but_never_reexecutes(self):
        self.prepare(checkout_id='primary')
        self.store.mark_unknown('op', self.alice, authorize=lambda: True)
        self.error('GIT_AUTHOR_MISMATCH', self.store.reconcile_unknown, 'op', raw=raw_commit(author=SOURCE_AUTHOR))
        self.assertEqual('UNKNOWN', self.store.pending_checkout('primary')['status'])
        receipt = self.store.reconcile_unknown('op', raw=raw_commit())
        self.assertEqual('COMMITTED', receipt['status'])
        self.assertEqual(receipt, self.store.reconcile_unknown('op', raw=raw_commit()))
        self.assertIsNone(self.store.pending_checkout('primary'))
        self.assertFalse(self.prepare(checkout_id='primary')['execute'])

    def test_trusted_unchanged_reconciliation_releases_but_retains_aborted_taint(self):
        self.prepare(checkout_id='primary')
        self.store.mark_unknown('op', self.alice, authorize=lambda: True)
        receipt = self.store.reconcile_unknown('op', confirmed_unchanged=True)
        self.assertEqual('ABORTED', receipt['status'])
        self.assertEqual(receipt, self.store.reconcile_unknown('op', confirmed_unchanged=True))
        self.assertIsNone(self.store.pending_checkout('primary'))
        self.assertFalse(self.prepare(checkout_id='primary')['execute'])
        self.assertEqual(['alice'], self.store.actor_contributions('alice')[0]['contributors'])

    def test_reconciliation_rejects_unproven_state_or_conflicting_observations(self):
        self.prepare(checkout_id='primary')
        self.error('GIT_OPERATION_STATE', self.store.reconcile_unknown, 'op', confirmed_unchanged=True)
        self.store.mark_unknown('op', self.alice, authorize=lambda: True)
        self.error('INVALID_GIT_RECONCILIATION', self.store.reconcile_unknown, 'op', raw=raw_commit(), confirmed_unchanged=True)
        self.error('INVALID_GIT_RECONCILIATION', self.store.reconcile_unknown, 'op', confirmed_unchanged=1)

    def test_separate_owner_connection_cannot_reserve_busy_checkout(self):
        with GitProvenance(self.path, 'room', 'project') as other:
            self.prepare(checkout_id='primary')
            self.error('GIT_CHECKOUT_BUSY', other.prepare, 'second', origin('bob'), BOB,
                       checkout_id='primary', request_digest='b' * 64, authorize=lambda: True)
            self.assertEqual('op', other.pending_checkout('primary')['operation_id'])

    def test_cherry_preserves_full_author_current_committer_source_sha_and_taint(self):
        oid, started = self.prepare_cherry()
        self.assertEqual(['alice', 'source-actor'], started['contributors'])
        final = self.store.finish('op', self.alice, self.cherry(oid), authorize=lambda: True)
        self.assertEqual(oid, final['source_oid'])
        self.assertEqual(['alice', 'source-actor'], self.store.contributors(final['commit_oid']))
        self.assertEqual(SOURCE_AUTHOR, parse_commit(self.cherry(oid)).author)

    def test_cherry_author_date_and_source_trailer_are_not_caller_selected(self):
        oid, _ = self.prepare_cherry()
        self.error('GIT_SOURCE_AUTHOR_MISMATCH', self.store.finish, 'op', self.alice,
                   self.cherry(oid, author=SOURCE_AUTHOR.replace('+0230', '+0000')), authorize=lambda: True)
        for message in (b'no trailer\n', b'prose (cherry picked from commit ' + oid.encode() + b')\n',
                        b'message\n(cherry picked from commit ' + b'4' * 40 + b')\n',
                        b'message\n(cherry picked from commit ' + oid.encode() + b')\nmore text\n'):
            self.error('GIT_SOURCE_TRAILER_MISMATCH', self.store.finish, 'op', self.alice,
                       self.cherry(oid, message=message), authorize=lambda: True)

    def test_empty_source_message_can_have_a_standalone_final_trailer(self):
        oid, _ = self.prepare_cherry()
        self.store.finish('op', self.alice, self.cherry(oid,
            message=b'(cherry picked from commit ' + oid.encode() + b')\n'), authorize=lambda: True)

    def test_source_email_does_not_invent_an_actor_or_clear_known_source_taint(self):
        oid, _ = self.prepare_cherry(contributors=())
        final = self.store.finish('op', self.alice, self.cherry(oid), authorize=lambda: True)
        self.assertEqual(['alice'], final['contributors'])
        self.assertEqual([], self.store.actor_contributions('original'))
        raw = raw_commit(author=SOURCE_AUTHOR, message=b'never persist source message\n')
        self.store.anchor_source('owner/source', oid, raw, contributors=('known-source',))
        self.store.anchor_source('owner/source', oid, raw, contributors=())
        self.assertEqual(['alice', 'known-source'], self.store.contributors(final['commit_oid']))
        self.assertEqual(['alice', 'known-source'], self.store.status('op', self.alice, authorize=lambda: True)['contributors'])

    def test_chained_cherry_picks_keep_transitive_and_later_known_source_taint(self):
        first_source, _ = self.prepare_cherry()
        first_raw = self.cherry(first_source)
        first = self.store.finish('op', self.alice, first_raw, authorize=lambda: True)
        self.store.anchor_source('owner/another', first['commit_oid'], first_raw)
        bob = origin('bob')
        self.store.prepare('second', bob, BOB, kind='cherry-pick', source_repository='owner/another',
                           source_oid=first['commit_oid'], parent_oid=PARENT, authorize=lambda: True, request_digest='a' * 64, checkout_id='checkout-second')
        second = self.store.finish('second', bob, self.cherry(first['commit_oid'], identity=BOB), authorize=lambda: True)
        self.assertEqual(['alice', 'bob', 'source-actor'], self.store.contributors(second['commit_oid']))
        self.anchor(contributors=('late-known-source',))
        self.assertEqual(['alice', 'bob', 'late-known-source', 'source-actor'], self.store.contributors(second['commit_oid']))
        self.assertEqual(2, len(self.store.actor_contributions('late-known-source')))

    def test_conflict_replacement_uses_new_committer_and_retains_old_taint(self):
        oid, _ = self.prepare_cherry()
        self.store.mark_conflict('op', self.alice, authorize=lambda: True)
        bob = origin('bob', 'resolver')
        continuation = self.store.continue_conflict('op', bob, BOB, authorize=lambda: True)
        self.assertTrue(continuation['execute'])
        self.assertEqual(['alice', 'bob', 'source-actor'], continuation['contributors'])
        self.error('GIT_ORIGIN_MISMATCH', self.store.prepare, 'op', self.alice, ALICE,
            kind='cherry-pick', source_repository='owner/source', source_oid=oid,
            parent_oid=PARENT, authorize=lambda: True, request_digest='a' * 64, checkout_id='checkout-op')
        self.error('GIT_ORIGIN_MISMATCH', self.store.finish, 'op', self.alice, self.cherry(oid), authorize=lambda: True)
        self.error('GIT_COMMITTER_MISMATCH', self.store.finish, 'op', bob, self.cherry(oid), authorize=lambda: True)
        final = self.store.finish('op', bob, self.cherry(oid, identity=BOB), authorize=lambda: True)
        self.assertEqual(['alice', 'bob', 'source-actor'], final['contributors'])
        self.assertEqual('COMMITTED', self.store.actor_contributions('alice')[0]['status'])

    def test_continuation_is_one_shot_and_only_after_a_recorded_conflict(self):
        self.prepare_cherry()
        self.error('GIT_OPERATION_STATE', self.store.continue_conflict, 'op', self.alice, ALICE, authorize=lambda: True)
        self.store.mark_conflict('op', self.alice, authorize=lambda: True)
        self.assertTrue(self.store.continue_conflict('op', self.alice, ALICE, authorize=lambda: True)['execute'])
        self.error('GIT_OPERATION_STATE', self.store.continue_conflict, 'op', self.alice, ALICE, authorize=lambda: True)

    def test_abort_is_terminal_and_cannot_clear_contribution_or_replay(self):
        self.prepare_cherry()
        self.store.mark_conflict('op', self.alice, authorize=lambda: True)
        aborted = self.store.abort('op', self.alice, authorize=lambda: True)
        self.assertEqual('ABORTED', aborted['status'])
        self.assertFalse(aborted['execute'])
        self.assertEqual(['alice', 'source-actor'], aborted['contributors'])
        self.assertEqual(aborted, self.store.abort('op', self.alice, authorize=lambda: True))
        self.error('GIT_OPERATION_STATE', self.store.continue_conflict, 'op', self.alice, ALICE, authorize=lambda: True)
        self.assertEqual('ABORTED', self.store.actor_contributions('alice')[0]['status'])

    def test_unknown_is_not_success_or_permission_to_retry(self):
        self.prepare()
        self.assertEqual('UNKNOWN', self.store.mark_unknown('op', self.alice, authorize=lambda: True)['status'])
        duplicate = self.prepare()
        self.assertFalse(duplicate['execute'])
        self.assertEqual('UNKNOWN', duplicate['status'])
        self.error('GIT_OPERATION_STATE', self.store.finish, 'op', self.alice, raw_commit(), authorize=lambda: True)

    def test_recovery_requires_positive_fencing_and_preserves_taint(self):
        self.prepare()
        self.assertEqual([], self.store.recover_pending(is_fenced=lambda _: False))
        self.store.close()
        self.store = GitProvenance(self.path, 'room', 'project')
        seen = []
        self.assertEqual(['op'], self.store.recover_pending(is_fenced=lambda who: seen.append(who) is None))
        self.assertEqual([self.alice.canonical()], [who.canonical() for who in seen])
        self.assertEqual('UNKNOWN', self.store.actor_contributions('alice')[0]['status'])
        self.assertFalse(self.prepare()['execute'])

    def test_unknown_operation_has_no_implicit_creation_or_reexecution(self):
        self.error('GIT_OPERATION_UNKNOWN', self.store.status, 'missing', self.alice, authorize=lambda: True)
        self.error('GIT_OPERATION_UNKNOWN', self.store.finish, 'missing', self.alice, raw_commit(), authorize=lambda: True)

    def test_invalid_kind_origin_or_source_shape_fails_before_permission(self):
        for kind in (None, [], 'am', 'merge'):
            self.error('UNSUPPORTED_GIT_OPERATION', self.store.prepare, 'op', self.alice, ALICE,
                       kind=kind, authorize=lambda: True, request_digest='a' * 64, checkout_id='checkout-op')
        self.error('FORBIDDEN', self.store.prepare, 'op', None, ALICE, authorize=lambda: True, request_digest='a' * 64, checkout_id='checkout-op')
        self.error('FORBIDDEN', self.store.continue_conflict, 'op', None, ALICE, authorize=lambda: True)
        self.error('INVALID_GIT_SOURCE', self.store.prepare, 'op', self.alice, ALICE,
                   source_oid='4' * 40, authorize=lambda: True, request_digest='a' * 64, checkout_id='checkout-op')
        self.assertEqual([], self.store.actor_contributions('alice'))

    def test_source_contributor_capacity_rolls_back_without_erasing_prior_taint(self):
        raw = raw_commit(author=SOURCE_AUTHOR, message=b'never persist source message\n')
        oid = parse_commit(raw).oid
        known = ['actor-' + str(n) for n in range(256)]
        self.store.anchor_source('owner/source', oid, raw, contributors=known)
        self.error('GIT_PROVENANCE_CAPACITY', self.store.anchor_source, 'owner/source', oid, raw,
                   contributors=('another-actor',))
        self.assertEqual(sorted(known), self.store.contributors(oid))
        self.error('GIT_PROVENANCE_CAPACITY', self.store.prepare, 'op', self.alice, ALICE,
                   kind='cherry-pick', source_repository='owner/source', source_oid=oid, authorize=lambda: True, request_digest='a' * 64, checkout_id='checkout-op')
        self.assertEqual([], self.store.actor_contributions('alice'))

    def test_metadata_storage_excludes_messages_and_patch_contents(self):
        oid, _ = self.prepare_cherry()
        raw = self.cherry(oid)
        self.store.finish('op', self.alice, raw, authorize=lambda: True)
        dump = '\n'.join(self.store._connection().iterdump())
        self.assertNotIn('never persist source message', dump)
        self.assertNotIn('private cherry message', dump)
        audit = json.dumps(self.store.audit_events())
        self.assertNotIn('Original Author', audit)
        self.assertNotIn('alice@example.invalid', audit)
        self.assertIn(hashlib.sha256(raw).hexdigest(), audit)

    def test_precommit_storage_failure_latches_owner_and_rolls_back_permission(self):
        with patch.object(self.store, '_commit', side_effect=sqlite3.OperationalError('private disk detail')):
            self.error('GIT_PROVENANCE_UNAVAILABLE', self.prepare, request_digest='a' * 64)
        self.assertTrue(self.store.failed)
        self.error('GIT_PROVENANCE_UNAVAILABLE', self.prepare, request_digest='a' * 64)
        self.store.close()
        self.store = GitProvenance(self.path, 'room', 'project')
        self.assertTrue(self.prepare()['execute'])

    def test_postcommit_unknown_latches_owner_and_reopen_never_grants_replay(self):
        commit = self.store._commit
        def uncertain():
            commit()
            raise sqlite3.OperationalError('lost commit acknowledgement')
        with patch.object(self.store, '_commit', side_effect=uncertain):
            self.error('GIT_PROVENANCE_UNAVAILABLE', self.prepare, request_digest='a' * 64)
        self.store.close()
        self.store = GitProvenance(self.path, 'room', 'project')
        self.assertFalse(self.prepare()['execute'])
        self.assertEqual(['op'], self.store.recover_pending(is_fenced=lambda _: True))

    def test_final_commit_uncertainty_retains_committed_receipt_after_reopen(self):
        self.prepare()
        commit = self.store._commit
        def uncertain():
            commit()
            raise sqlite3.OperationalError('lost terminal acknowledgement')
        with patch.object(self.store, '_commit', side_effect=uncertain):
            self.error('GIT_PROVENANCE_UNAVAILABLE', self.store.finish, 'op', self.alice, raw_commit(), authorize=lambda: True)
        self.store.close()
        self.store = GitProvenance(self.path, 'room', 'project')
        self.assertEqual('COMMITTED', self.store.status('op', self.alice, authorize=lambda: True)['status'])
        self.assertEqual([], self.store.recover_pending(is_fenced=lambda _: True))

    def test_store_scope_schema_and_private_modes_are_mandatory(self):
        self.error('PROJECT_MISMATCH', GitProvenance, self.path, 'another-room', 'project')
        self.error('PROJECT_MISMATCH', GitProvenance, self.path, 'room', 'another-project')
        self.assertEqual(0o600, self.path.stat().st_mode & 0o777)
        self.store.close()
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE unrelated(value TEXT)')
        self.error('INVALID_STORE', GitProvenance, self.path, 'room', 'project')

    def test_unprivate_parent_and_symlink_store_fail_closed(self):
        public = Path(self.temp.name) / 'public'
        public.mkdir(mode=0o755)
        self.error('INVALID_STORE', GitProvenance, public / 'db', 'room', 'project')
        link = Path(self.temp.name) / 'link'
        link.symlink_to(self.path)
        self.error('INVALID_STORE', GitProvenance, link, 'room', 'project')


if __name__ == '__main__':
    unittest.main()

    def test_worker_reservation_requires_positive_exact_cleanup_and_no_replay(self):
        self.store.reserve_worker('w', 'checkout', self.alice, 'a' * 64, authorize=lambda: True)
        self.assertEqual(self.store.pending_worker('checkout'), 'w')
        self.error('GIT_WORKER_QUIESCENCE_UNKNOWN', self.store.finish_worker, 'w',
                   {'worker_identity': [1, 2], 'quiescent': True, 'exited': False})
        self.error('GIT_WORKER_QUIESCENCE_UNKNOWN', self.store.reserve_worker, 'other', 'checkout',
                   self.alice, 'b' * 64, authorize=lambda: True)
        evidence = {'worker_identity': [1, 2], 'quiescent': True, 'exited': True}
        self.store.finish_worker('w', evidence)
        self.store.finish_worker('w', evidence)
        self.assertIsNone(self.store.pending_worker('checkout'))
        self.error('GIT_COMMAND_ALREADY_CONSUMED', self.store.reserve_worker, 'w', 'checkout',
                   self.alice, 'a' * 64, authorize=lambda: True)
        self.store.reserve_worker('other', 'checkout', self.alice, 'b' * 64, authorize=lambda: True)

    def test_amend_preserves_transitive_source_taint_after_run_transition(self):
        source = self.anchor(contributors=('source-actor',))
        self.prepare('cherry', kind='cherry-pick', source_repository='owner/source', source_oid=source,
                     parent_oid=PARENT, run_scope={'run_id': 'one', 'generation': 1})
        raw = self.cherry(source)
        original = self.store.finish('cherry', self.alice, raw, authorize=lambda: True)['commit_oid']
        self.prepare('amend', origin('bob'), BOB, parent_oid=PARENT, replaced_oid=original,
                     run_scope={'run_id': 'two', 'generation': 1})
        result = self.store.finish('amend', origin('bob'), raw_commit(identity=BOB, parent=PARENT), authorize=lambda: True)
        self.assertEqual(result['contributors'], ['alice', 'bob', 'source-actor'])
        self.assertEqual(self.store.contributors(result['commit_oid']), ['alice', 'bob', 'source-actor'])
