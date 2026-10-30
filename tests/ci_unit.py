"""Standard discovery, six complete/disjoint unit partitions, no test exclusions.

Measured modules share work between the parallel one-minute unit jobs. Every
other module (including future additions) belongs to the remainder. Discovery
errors fail every invocation; imported tests are never run merely to select IDs.
"""
import argparse
import hashlib
from pathlib import Path
import sys
import unittest


# Hosted 6c97 elapsed intervals: approximately 35.8 / 32.2 / 34.6 seconds.
# Hosted 46f2154 remainder moved 3.624 + 3.314 + 2.929 seconds to integration.
# Hosted 3678efe remainder overflow: move measured 17.581s / 11.223s into
# existing parallel jobs (19.815s / 27.673s), not new jobs or larger limits.
# Estimates become 37.396 / 38.896 / 43.763s; timings vary, not a guarantee.
# Keep module ownership stable; new modules default to remainder, never disappear.
# #168 dispatch real-process/Git suite measured9.4s locally; remainder timed
# out at61s. Existing slow lane43s hosted has headroom; no excluded tests.
SLOW_MODULES = frozenset({'test_library_dispatch', 'test_peer', 'test_checkouts', 'test_gate_evaluation',
                          'test_forge_mutations', 'test_artifact_manual_source',
                          'test_run_review', 'test_staged_source_closure',
                          'test_claude_permission_policy', 'test_artifact_native_source',
                          'test_workstation_control', 'test_peer_delivery_phases', 'test_participant_pi_launch', 'test_room_control_plane', 'test_workstation_peer', 'test_review_hosted'})
# #155 hosted remainder reached its one-minute job boundary despite passing
# tests (49s + setup/smoke). Move the ~7s registration module to the measured
# 24s integration partition; no exclusions, new jobs or enlarged timeouts.
# #164 run41001402968 passed380 tests52.26s but job cleanup hit60s.
# Move hosted5.70s Hub to45s slow job; Git payload3.03s to45s remainder.
# Preserve every test and timeout; new assembly stays integration.
# #162 kernel/Git route module measured ~3.5s locally; keep off tight remainder.
INTEGRATION_MODULES = frozenset({'test_library_assembly', 'test_context', 'test_library_registration',
    'test_native_pi_reset_adversarial', 'test_participant',
    'test_native_completed_reviewer_reset', 'test_native_reviewer_reset_adversarial',
    'test_command_native_source', 'test_forge_read_process', 'test_native_trust',
    'test_diff_native', 'test_gate_forge_hub', 'test_native_session_human_actions',
    'test_manager_action_host', 'test_forge_assignment',
    'test_native_reviewer_recruitment_adversarial', 'test_native_gate_completion', 'test_native_session_driver', 'test_ledger', 'test_run_admission', 'test_forge_projections'})
# Run 40958947508: remainder took 60.833s before its process smoke.
# Move ~23s of measured remainder work and ~7.5s from integration to a sibling.
# #155 final graph: remainder 48s plus setup reached 62s. These four
# modules measured 4.34s locally out of 24.05s remainder (~8.7s hosted).
# Existing additional lane measured 18s hosted; move rather than exclude.
# #158 real-Git projection module measured 3.9s locally. Keep it off the
# previously tight remainder; additional has ~26s hosted baseline headroom.
# #165 moved the measured enqueue module to this parallel lane.
# #168 follow-up: slow lane hit60s; move existing Hub (~5.7shosted)
# to additional lane (46s) without changing total inventory/limits.
ADDITIONAL_MODULES = frozenset({
    'test_library_hub',
    'test_library_enqueue',
    'test_local_native_terminal', 'test_local_native_stop', 'test_local_three_runs',
    'test_library_git', 'test_library_projection', 'test_native_combined_image_package',
    'test_native_claude_checks', 'test_native_git_operations',
    'test_forge_mutation_audit', 'test_manager_read_model', 'test_library_records',
    'test_gate_diff_hub', 'test_artifact_connected', 'test_native_broker_audit_source',
    'test_local_room_prepare', 'test_forge_reconciliation', 'test_room_cli_diagnostics',
    'test_exec_state', 'test_workstation_delivery', 'test_lifecycle', 'test_forge_capacity',
})
# #170 actual process interruption/recovery suite measured20s locally. Existing
# hosted lanes51-53s cannot absorb it; one parallel one-minute lane preserves
# all tests and the overall2-3min graph, with no timeout increase.
# #173 relocation suite measured 6s; synthesis has headroom after #170.
SYNTHESIS_MODULES = frozenset({'test_library_attempts', 'test_library_import', 'test_library_relocation'})
# #172 real-process scheduler suite measured 25s locally; existing lanes
# approach 50s hosted. Keep one-minute limits and full exhaustive discovery.
SCHEDULER_MODULES = frozenset({'test_library_scheduler'})
PARTITIONS = ('slow', 'integration', 'additional', 'synthesis', 'scheduler', 'remainder')
assert not SCHEDULER_MODULES & (SLOW_MODULES | INTEGRATION_MODULES | ADDITIONAL_MODULES | SYNTHESIS_MODULES)
assert not SYNTHESIS_MODULES & (SLOW_MODULES | INTEGRATION_MODULES | ADDITIONAL_MODULES)
assert not (SLOW_MODULES & INTEGRATION_MODULES or SLOW_MODULES & ADDITIONAL_MODULES
            or INTEGRATION_MODULES & ADDITIONAL_MODULES)


def partition_for(identifier):
    if type(identifier) is not str or not identifier:
        raise ValueError('invalid discovered test ID')
    module = identifier.split('.', 1)[0]
    if module in SCHEDULER_MODULES:
        return 'scheduler'
    if module in SYNTHESIS_MODULES:
        return 'synthesis'
    if module in SLOW_MODULES:
        return 'slow'
    if module in INTEGRATION_MODULES:
        return 'integration'
    return 'additional' if module in ADDITIONAL_MODULES else 'remainder'


def verify_partition_ids(all_ids, groups):
    """Reject duplicate, missing, extra or incorrectly assigned discovered IDs."""
    if set(groups) != set(PARTITIONS) or len(all_ids) != len(set(all_ids)):
        raise ValueError('invalid unit partition inventory')
    combined = []
    for group in PARTITIONS:
        ids = groups[group]
        if len(ids) != len(set(ids)) or any(partition_for(value) != group for value in ids):
            raise ValueError('duplicate or misplaced partition ID')
        combined.extend(ids)
    if len(combined) != len(all_ids) or set(combined) != set(all_ids):
        raise ValueError('omitted, extra or overlapping unit partition ID')


def leaves(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from leaves(item)
        elif isinstance(item, unittest.TestCase):
            yield item
        else:
            raise ValueError('unsupported discovered test object')


def partition_suite(suite):
    cases = list(leaves(suite))
    groups = {name: [] for name in PARTITIONS}
    for case in cases:
        groups[partition_for(case.id())].append(case)
    ids = [case.id() for case in cases]
    verify_partition_ids(ids, {name: [case.id() for case in selected]
                               for name, selected in groups.items()})
    return cases, groups


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('partition', nargs='?', default='all', choices=('all', *PARTITIONS))
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    loader = unittest.TestLoader()
    suite = loader.discover(str(root / 'tests'), pattern='test*.py')
    if loader.errors:
        for error in loader.errors:
            print(error, file=sys.stderr)
        return 1
    cases, groups = partition_suite(suite)
    if not cases or any(not groups[name] for name in PARTITIONS):
        raise ValueError('empty discovered unit partition')
    digest = hashlib.sha256('\n'.join(sorted(case.id() for case in cases)).encode()).hexdigest()
    selected = cases if args.partition == 'all' else groups[args.partition]
    print(f'Unit inventory: total={len(cases)} slow={len(groups["slow"])} '
          f'integration={len(groups["integration"])} additional={len(groups["additional"])} '
          f'scheduler={len(groups["scheduler"])} synthesis={len(groups["synthesis"])} remainder={len(groups["remainder"])} selected={args.partition}:{len(selected)} '
          f'ids_sha256={digest}', flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(selected))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
