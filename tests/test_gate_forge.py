"""Pure Forge Gate, Broker/audit and private-client tests; no native I/O."""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from test_github_surface import (API, R, SHA, HEAD, pull, check, status, run, job, response)
from uas.config import ConfigError
from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_read import ExternalReadBroker
from uas.forge_read_provider import BrokerReadProvider
from uas.forge_read_service import GateForgeBrokerClient, ReadBrokerClient
from uas.gate_forge import (BrokerForgeState, ExternalGateForgeBroker, compile_forge_config,
    validate_forge_observation, validate_target_observation, adjudicate_forge_state,
    gate_forge_origin, _canonical, _digest)
from uas.github_executor import _PATH
from uas.github_read import GitHubProject
from uas.ledger import LedgerError, Origin


TARGET = {'repository': R, 'pull_number': 42, 'pull_id': 2042,
          'head_sha': HEAD, 'base_sha': SHA, 'base_ref': 'main'}


def item(identifier='suite', kind='check-run', producer=4, context='unit',
         coverage='head', purpose='complete-suite'):
    return {'id': identifier, 'kind': kind, 'producer_id': producer, 'context': context,
            'coverage': coverage, 'purpose': purpose}


def config(*items):
    return {'ci': list(items or [item()])}


class Fixture:
    def __init__(self):
        self.calls = []
        self.pull = pull()
        self.branch = {'name': 'main', 'protected': False, 'commit': {'sha': SHA}}
        self.protection = {'url': API + '/branches/main/protection',
                           'required_status_checks': {'strict': False, 'contexts': [], 'checks': []}}
        self.rules = []
        self.checks = {HEAD: [check()], 'c'*40: [check(2, 'c'*40)]}
        self.statuses = {HEAD: [status()], 'c'*40: []}
        self.runs = {HEAD: [{**run(), 'run_number': 7}], 'c'*40: []}
        self.jobs = [job()]
        self.parents = [SHA, HEAD]
        self.ancestor = SHA
        self.before = None

    def __call__(self, path):
        self.calls.append(path)
        if self.before is not None:
            value = self.before(path)
            if value is not None: return value
        base = 'repos/' + R
        clean = path.partition('?')[0]
        if clean == base + '/pulls/42': value = self.pull
        elif clean == base + '/branches/main': value = self.branch
        elif clean == base + '/branches/main/protection': value = self.protection
        elif clean == base + '/rules/branches/main': value = self.rules
        elif clean.startswith(base + '/compare/'):
            value = {'base_commit': {'sha': SHA}, 'merge_base_commit': {'sha': self.ancestor},
                     'status': 'ahead' if self.ancestor == SHA else 'diverged'}
        elif clean == base + '/commits/' + 'c'*40:
            value = {'sha': 'c'*40, 'url': API + '/commits/' + 'c'*40,
                     'parents': [{'sha': p} for p in self.parents]}
        elif '/commits/' in clean and clean.endswith('/check-runs'):
            values = self.checks.get(clean.split('/')[-2], [])
            value = {'check_runs': values, 'total_count': len(values)}
        elif '/commits/' in clean and clean.endswith('/statuses'):
            value = self.statuses.get(clean.split('/')[-2], [])
        elif clean == base + '/actions/runs':
            sha = path.split('head_sha=')[1].split('&')[0]
            values = self.runs.get(sha, [])
            value = {'workflow_runs': values, 'total_count': len(values)}
        elif clean == base + '/actions/runs/8': value = self.runs[HEAD][0]
        elif clean == base + '/actions/runs/8/attempts/2/jobs':
            value = {'jobs': self.jobs, 'total_count': len(self.jobs)}
        else: raise AssertionError('unexpected fixture path: ' + path)
        return response(deepcopy(value))


class ForgeGateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.provider = BrokerForgeState(GitHubProject(R), self.fixture)

    def observe(self, policy=None):
        return self.provider.observe(TARGET, policy or config())

    def reduce(self, policy=None):
        policy = policy or config()
        return adjudicate_forge_state(self.observe(policy), TARGET, policy)

    def test_config_canonical_source_purpose_and_rejections(self):
        policy = config(item('z'), item('a', 'commit-status', 7, 'build', purpose='focused'))
        self.assertEqual(['a', 'z'], [r['id'] for r in compile_forge_config(policy)['ci']])
        for bad in ({}, {'ci': []}, {'ci': [item(purpose='focused')]}, config(item(), item()),
                    config({**item(), 'producer_id': True}), config({**item(), 'kind': 'findings-clear'}),
                    config({**item(), 'coverage': 'any-revision'}), config({**item(), 'optional': True}),
                    config({**item(), 'context': 'unit\nspoof'}), config({**item(), 'context': 'é'*300})):
            with self.subTest(bad=bad), self.assertRaises(ConfigError): compile_forge_config(bad)

    def test_all_ci_sources_and_purposes_bind_exact_revisions_producers_attempts(self):
        policy = config(item(), item('status', 'commit-status', 7, 'build', purpose='focused'),
            item('workflow', 'actions-workflow', 5, 'pull_request', purpose='specialized'),
            item('job', 'actions-job', 5, 'unit', purpose='focused'))
        observed = self.observe(policy)
        self.assertEqual('OK', observed['status'])
        validate_forge_observation(observed, TARGET)
        result = adjudicate_forge_state(observed, TARGET, policy)
        self.assertEqual('passed', result['verdict'])
        self.assertEqual(4, len(result['dependencies']['ci']))
        job_fact = next(r['fact'] for r in result['dependencies']['ci'] if r['id'] == 'job')
        self.assertEqual((8, 2, 5), (job_fact['run_id'], job_fact['run_attempt'], job_fact['workflow_id']))
        self.assertNotIn('DO_NOT', json.dumps(observed))
        self.assertTrue(all(_PATH.fullmatch(path) for path in self.fixture.calls))

    def test_missing_producer_and_pending_never_fall_back_to_old_pass(self):
        self.fixture.checks[HEAD][0]['app']['id'] = 88
        self.assertEqual('failed', self.reduce()['verdict'])
        self.fixture.checks[HEAD] = [{**check(), 'status': 'in_progress', 'conclusion': None}]
        policy = config(item(coverage='head-or-test-merge'))
        result = self.reduce(policy)
        self.assertEqual('failed', result['verdict'])
        self.assertEqual('pending', result['checks'][1]['note'])
        self.assertEqual(HEAD, result['checks'][1]['item']['tested_sha'])

    def test_latest_status_per_creator_context_is_provider_order_not_largest_id(self):
        self.fixture.statuses[HEAD] = [{**status(1), 'state': 'pending'}, status(999)]
        result = self.reduce(config(item('suite', 'commit-status', 7, 'build')))
        self.assertEqual('failed', result['verdict'])
        self.assertEqual(1, result['dependencies']['ci'][0]['fact']['id'])

    def test_latest_run_number_and_attempt_pending_block_old_workflow_pass(self):
        newer = {**run(10, 3), 'run_number': 8, 'status': 'in_progress', 'conclusion': None}
        self.fixture.runs[HEAD].append(newer)
        def before(path):
            if path.endswith('/actions/runs/10'): return response(newer)
            if '/actions/runs/10/attempts/3/jobs' in path:
                return response({'jobs': [], 'total_count': 0})
        self.fixture.before = before
        result = self.reduce(config(item('suite', 'actions-workflow', 5, 'pull_request')))
        self.assertEqual('failed', result['verdict'])
        self.assertEqual(10, result['dependencies']['ci'][0]['fact']['id'])

    def test_passing_job_does_not_hide_pending_parent_attempt(self):
        self.fixture.runs[HEAD][0].update(status='in_progress', conclusion=None)
        result = self.reduce(config(item('suite', 'actions-job', 5, 'unit')))
        self.assertEqual('pending', result['checks'][1]['note'])
        self.assertEqual('failed', result['verdict'])

    def test_complete_suite_workflow_requires_nonempty_completed_non_skipped_jobs(self):
        policy = config(item('suite', 'actions-workflow', 5, 'pull_request'))
        self.assertEqual('passed', self.reduce(policy)['verdict'])
        self.fixture.jobs[0]['conclusion'] = 'skipped'
        self.assertEqual('incomplete-suite', self.reduce(policy)['checks'][1]['note'])
        self.fixture.jobs = []
        self.assertEqual('failed', self.reduce(policy)['verdict'])

    def test_exact_attempt_change_during_job_enumeration_errors(self):
        count = 0
        def before(path):
            nonlocal count
            if path.endswith('/actions/runs/8'):
                count += 1
                if count == 2: return response({**run(attempt=3), 'run_number': 7})
        self.fixture.before = before
        policy = config(item('suite', 'actions-workflow', 5, 'pull_request'))
        observed = self.observe(policy)
        self.assertEqual('GATE_FORGE_ATTEMPT_CHANGED', observed['status'])
        self.assertEqual('error', adjudicate_forge_state(observed, TARGET, policy)['verdict'])

    def test_test_merge_needs_explicit_coverage_and_exact_parent_association(self):
        self.fixture.checks[HEAD] = []
        self.assertEqual('failed', self.reduce()['verdict'])
        policy = config(item(coverage='head-or-test-merge'))
        result = self.reduce(policy)
        self.assertEqual('passed', result['verdict'])
        self.assertEqual('c'*40, result['dependencies']['ci'][0]['tested_sha'])
        self.fixture.parents.reverse()
        self.assertEqual('failed', self.reduce(policy)['verdict'])

    def test_required_checks_separate_from_configured_suite_and_producer_binding(self):
        self.fixture.branch['protected'] = True
        checks = self.fixture.protection['required_status_checks']
        checks.update(contexts=['unit'], checks=[{'context': 'unit', 'app_id': 4}])
        self.assertEqual('passed', self.reduce()['verdict'])
        checks['checks'][0]['app_id'] = 9
        self.assertEqual('failed', self.reduce()['verdict'])
        checks.update(contexts=['another'], checks=[{'context': 'another', 'app_id': None}])
        self.assertEqual('failed', self.reduce()['verdict'])

    def test_branch_any_producer_does_not_hide_unconfigured_same_name_status(self):
        self.fixture.branch['protected'] = True
        self.fixture.protection['required_status_checks'].update(contexts=['unit'],
            checks=[{'context': 'unit', 'app_id': None}])
        self.assertEqual('passed', self.reduce()['verdict'])
        self.fixture.statuses[HEAD].append({**status(3), 'context': 'unit', 'state': 'pending'})
        self.assertEqual('failed', self.reduce()['verdict'])

    def test_ruleset_check_and_strict_base_ancestry_fail_closed(self):
        self.fixture.rules = [{'type': 'required_status_checks', 'ruleset_id': 5,
            'ruleset_source_type': 'Repository', 'ruleset_source': R, 'parameters': {
                'strict_required_status_checks_policy': True,
                'required_status_checks': [{'context': 'unit', 'integration_id': 4}]}}]
        self.assertEqual('passed', self.reduce()['verdict'])
        self.fixture.ancestor = 'd'*40
        self.assertEqual('failed', self.reduce()['verdict'])
        self.fixture.checks[HEAD] = []
        self.assertEqual('passed', self.reduce(config(item(coverage='head-or-test-merge')))['verdict'])

    def test_unreadable_protection_rules_or_failed_page_are_not_absence(self):
        for endpoint in ('/rules/branches/main', '/branches/main/protection', '/check-runs'):
            self.fixture = Fixture(); self.fixture.branch['protected'] = True
            self.provider = BrokerForgeState(GitHubProject(R), self.fixture)
            self.fixture.before = lambda path, endpoint=endpoint: response({}, 403) if endpoint in path else None
            with self.subTest(endpoint=endpoint):
                observed = self.observe()
                self.assertEqual('unknown', observed['completeness'])
                self.assertEqual('error', adjudicate_forge_state(observed, TARGET, config())['verdict'])

    def test_unsupported_required_workflow_rules_are_explicit_errors(self):
        self.fixture.rules = [{'type': 'workflows', 'ruleset_id': 5,
            'ruleset_source_type': 'Organization', 'ruleset_source': 'owner', 'parameters': {}}]
        self.assertEqual('UNSUPPORTED_FORGE_REQUIRED_RULE', self.observe()['status'])

    def test_closing_target_and_requirements_changes_never_pass(self):
        calls = 0
        def before(path):
            nonlocal calls
            if path.endswith('/pulls/42'):
                calls += 1
                if calls == 2:
                    changed = pull(); changed['head']['sha'] = 'f'*40
                    return response(changed)
        self.fixture.before = before
        self.assertEqual('GATE_FORGE_TARGET_CHANGED', self.observe()['status'])
        self.fixture = Fixture(); self.provider = BrokerForgeState(GitHubProject(R), self.fixture)
        rules_calls = 0
        def rules(path):
            nonlocal rules_calls
            if '/rules/branches/main?' in path:
                rules_calls += 1
                if rules_calls == 2: return response([{'type': 'required_signatures', 'ruleset_id': 5,
                    'ruleset_source_type': 'Repository', 'ruleset_source': R}])
        self.fixture.before = rules
        self.assertEqual('GATE_FORGE_TARGET_CHANGED', self.observe()['status'])

    def test_each_fresh_call_rechecks_ancestry_and_does_not_cache(self):
        self.assertEqual('passed', self.reduce()['verdict'])
        count = len(self.fixture.calls)
        self.fixture.branch['commit']['sha'] = 'f'*40
        self.assertEqual('error', self.reduce()['verdict'])
        self.assertGreater(len(self.fixture.calls), count)

    def test_unrelated_ci_does_not_change_selected_dependency_token(self):
        first = self.reduce()['dependencies']['dependency_digest']
        self.fixture.checks[HEAD].append({**check(8), 'name': 'unrelated'})
        second = self.reduce()['dependencies']['dependency_digest']
        self.assertEqual(first, second)

    def test_malformed_or_fabricated_observations_cannot_pass(self):
        observed = self.observe()
        for mutate in (
            lambda v: v.update(verdict='passed'),
            lambda v: v['revisions'][0]['checks'][0].update(ok=True),
            lambda v: v['revisions'][0]['checks'][0].update(head_sha='f'*40),
            lambda v: v['revisions'][0]['checks'][0].update(conclusion='arbitrary'),
            lambda v: v['target'].update(base_sha='f'*40),
            lambda v: v['required'].update(extra=True),
        ):
            bad = deepcopy(observed); mutate(bad)
            bad['observation_digest'] = _digest({k:v for k,v in bad.items() if k != 'observation_digest'})
            with self.subTest(bad=bad):
                self.assertEqual('error', adjudicate_forge_state(bad, TARGET, config())['verdict'])

    def test_narrow_target_observation_needs_no_ci_policy_or_rules_permission(self):
        self.fixture.before = lambda path: response({}, 403) if '/rules/' in path else None
        observed = self.provider.observe_target(TARGET)
        self.assertEqual('OK', observed['status'])
        validate_target_observation(observed, TARGET)
        self.assertEqual(5, len(self.fixture.calls))
        self.assertTrue(all('/rules/' not in path and '/actions/' not in path and '/check-runs' not in path
                            for path in self.fixture.calls))
        self.assertEqual('error', self.reduce()['verdict'])

    def test_narrow_target_rejects_identity_change_and_malformed_correlated_evidence(self):
        observed = self.provider.observe_target(TARGET)
        bad = deepcopy(observed); bad['pull']['id'] += 1
        bad['observation_digest'] = _digest({k:v for k,v in bad.items() if k != 'observation_digest'})
        with self.assertRaisesRegex(LedgerError, 'INVALID_FORGE_OBSERVATION'):
            validate_target_observation(bad, TARGET)
        self.fixture.pull['base']['sha'] = 'f'*40
        self.assertEqual('GATE_FORGE_TARGET_CHANGED', self.provider.observe_target(TARGET)['status'])

    def test_closed_merged_draft_pull_and_non_success_conclusions_fail(self):
        for key, value in (('state', 'closed'), ('draft', True)):
            self.fixture.pull[key] = value
            self.assertEqual('failed', self.reduce()['verdict'])
            self.fixture.pull = pull()
        for conclusion in ('failure', 'skipped', 'neutral', 'cancelled', 'timed_out'):
            self.fixture.checks[HEAD][0]['conclusion'] = conclusion
            self.assertEqual('failed', self.reduce()['verdict'])

    def test_page_exhaustion_and_output_limit_cannot_create_pass(self):
        self.fixture.before = lambda path: response({'check_runs': [check()], 'total_count': 101}) if '/check-runs' in path else None
        self.assertEqual('unknown', self.observe()['completeness'])
        self.fixture.before = None
        self.provider = BrokerForgeState(GitHubProject(R), self.fixture, max_bytes=20)
        self.assertEqual('OUTPUT_LIMIT', self.observe()['status'])


class ForgeGateBrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.audit = ForgeAudit(Path(self.tmp.name) / 'audit.db', 'deployment')
        self.addCleanup(self.audit.close)
        self.fixture = Fixture()
        self.project = GitHubProject(R)
        self.binding = ForgeBinding('room', 'project', R)
        self.selected = []
        def providers(actor):
            self.selected.append(actor)
            return BrokerReadProvider(self.project, self.fixture, None)
        self.gates = ExternalGateForgeBroker(self.binding, 'instance', self.audit, 'fixed-actor', providers)
        self.broker = ExternalReadBroker(self.binding, 'instance', self.audit, providers,
            Path(self.tmp.name) / 'results', gates=self.gates)
        self.envelope = {'id': 'evaluation', 'kind': 'gate-forge', 'target': TARGET, 'config': config()}

    def call(self, envelope=None, origin=None, authorize=lambda: True):
        return self.broker.execute(envelope or self.envelope,
            origin=origin or gate_forge_origin('instance'), authorize=authorize)

    def test_audit_precedes_contact_pins_actor_and_no_participant_authority(self):
        def before(path):
            self.assertEqual(1, self.audit._db.execute("SELECT count(*) FROM read_starts").fetchone()[0])
        self.fixture.before = before
        result = self.call()
        self.assertEqual('OK', result['observation']['status'])
        self.assertEqual(['fixed-actor'], self.selected)
        self.assertTrue(result['audit_reference'].startswith('gate-forge-'))
        participant = Origin('fixed-actor', 'participant', 'inc', 'epoch', ('forge-read', 'forge-gate'))
        calls = len(self.fixture.calls)
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'): self.call(origin=participant)
        self.assertEqual(calls, len(self.fixture.calls))

    def test_repeat_never_recontacts_and_conflicting_id_fails(self):
        self.call(); count = len(self.fixture.calls)
        self.assertEqual('INTERRUPTED_OBSERVATION', self.call()['observation']['status'])
        self.assertEqual(count, len(self.fixture.calls))
        with self.assertRaisesRegex(LedgerError, 'ID_CONFLICT'):
            self.call({**self.envelope, 'config': config(item(context='other'))})
        self.assertEqual(count, len(self.fixture.calls))

    def test_revocation_during_pages_prevents_response_and_new_contacts(self):
        active = True
        def before(path):
            nonlocal active
            active = False
        self.fixture.before = before
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'): self.call(authorize=lambda: active)
        self.assertEqual(1, len(self.fixture.calls))
        self.assertIsNotNone(self.audit._db.execute('SELECT result FROM read_terminals').fetchone())

    def test_cross_project_extra_fields_and_caller_actor_are_denied_before_contact(self):
        for extra in ({'actor_id': 'chosen'}, {'source': 'external-forge-broker'}, {'argv': ['api']},
                      {'target': {**TARGET, 'repository': 'other/project'}}):
            with self.subTest(extra=extra), self.assertRaises((LedgerError, ConfigError)):
                self.call({**self.envelope, **extra})
        self.assertEqual([], self.fixture.calls)

    def test_private_client_only_wraps_prepared_guarded_existing_channel(self):
        client = object.__new__(ReadBrokerClient)
        client.binding = self.binding; client.room_instance = 'instance'; client.gate_enabled = True
        state = {'phase': 'running', 'instance_id': 'instance'}
        client.supervisor = SimpleNamespace(_read=lambda: state, _locked=nullcontext)
        captured = []
        def prepare(envelope, origin, *, authorize):
            captured.append((deepcopy(envelope), origin, authorize()))
            return envelope
        def perform(envelope):
            return {'admission': 'not-evaluated', **self.call(envelope)}
        client.prepare, client.perform = prepare, perform
        adapter = GateForgeBrokerClient(client)
        result = adapter.observe(TARGET, config(), 'evaluation', authorize=lambda: True)
        self.assertEqual('OK', result['observation']['status'])
        self.assertEqual(gate_forge_origin('instance'), captured[0][1])
        self.assertTrue(captured[0][2])
        state['instance_id'] = 'replaced'
        with self.assertRaisesRegex(LedgerError, 'FORBIDDEN'):
            adapter.observe(TARGET, config(), 'fresh', authorize=lambda: True)


if __name__ == '__main__':
    unittest.main()
