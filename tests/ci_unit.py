"""Standard discovery, twelve complete/disjoint unit partitions, no test exclusions.

Measured modules share work between the parallel one-minute unit jobs. Every
other module (including future additions) belongs to the remainder. Discovery
errors fail every invocation; imported tests are never run merely to select IDs.
"""
import argparse
import hashlib
from pathlib import Path
import sys
import unittest


# #241: postmerge41047585809 passed311 integration tests60.074s and84
# synthesis tests52.524s, then hit unchanged60s jobs. Eight suites total351s;
# nine average39s before setup. Ten lanes target32–38s measured headroom.
# Full module timings and planning bounds: docs/testing/ci-partition-headroom.md.
# These are partitions, not exclusions. Every future module defaults to remainder.
SLOW_MODULES = frozenset({'test_artifact_manual_source',
 'test_artifact_native_source',
 'test_checkouts',
 'test_claude_permission_policy',
 'test_forge_mutations',
 'test_gate_evaluation',
 'test_library_dispatch',
 'test_library_import',
 'test_participant_pi_launch',
 'test_peer',
 'test_peer_delivery_phases',
 'test_review_hosted',
 'test_room_control_plane',
 'test_run_review',
 'test_workstation_control',
 'test_workstation_peer'})

INTEGRATION_MODULES = frozenset({'test_command_native_source',
 'test_diff_native',
 'test_forge_assignment',
 'test_forge_projections',
 'test_forge_read_process',
 'test_gate_forge_hub',
 'test_ledger',
 'test_library_enqueue',
 'test_library_registration',
 'test_manager_action_host',
 'test_native_completed_reviewer_reset',
 'test_native_gate_completion',
 'test_native_reviewer_recruitment_adversarial',
 'test_native_reviewer_reset_adversarial',
 'test_native_session_driver',
 'test_native_session_human_actions',
 'test_native_trust',
 'test_participant',
 'test_run_admission'})

ADDITIONAL_MODULES = frozenset({'test_artifact_connected',
 'test_exec_state',
 'test_forge_capacity',
 'test_forge_mutation_audit',
 'test_forge_reconciliation',
 'test_gate_diff_hub',
 'test_library_git',
 'test_library_observations',
 'test_library_projection',
 'test_library_settings',
 'test_lifecycle',
 'test_local_room_prepare',
 'test_local_three_runs',
 'test_manager_read_model',
 'test_native_broker_audit_source',
 'test_native_claude_checks',
 'test_native_combined_image_package',
 'test_native_git_operations',
 'test_room_cli_diagnostics',
 'test_workstation_delivery'})

SYNTHESIS_MODULES = frozenset({'test_context',
 'test_library_attempts',
 'test_native_pi_reset_adversarial',
 'test_staged_source_closure'})

SCHEDULER_MODULES = frozenset({'test_library_scheduler', 'test_library_assembly'})

OPERATOR_MODULES = frozenset({'test_library_controls', 'test_git_payload'})

# #182 measured repair+native+retention ~23s; keep setup/variance margin.
MAINTENANCE_MODULES = frozenset({'test_library_retention', 'test_library_repair', 'test_library_repair_native'})

INSPECTION_MODULES = frozenset({'test_library_hub', 'test_library_inspection', 'test_library_relocation'})

# #189 host/service/Git transport measured7.2s hosted; lifecycle24.8s
# leaves margin in the existing60s lane, without changing discovery or limits.
# #183 attention fixtures reuse the service/records Git composition here.
LIFECYCLE_MODULES = frozenset({'test_library_attention', 'test_library_records',
 'test_library_service', 'test_manager_library_transport'})

DISPOSITION_MODULES = frozenset({'test_library_adjudication',
 'test_library_adjudication_native',
 'test_library_adjudication_recovery',
 'test_library_disposition',
 'test_library_disposition_native',
 'test_library_disposition_recovery'})

ARCHIVE_MODULES = frozenset({'test_library_archive', 'test_library_archive_integration', 'test_library_archive_native'})

PARTITIONS = ('archive', 'maintenance', 'lifecycle', 'disposition', 'inspection', 'operator', 'slow',
              'integration', 'additional', 'synthesis', 'scheduler', 'remainder')
MODULE_GROUPS = (ARCHIVE_MODULES, MAINTENANCE_MODULES, LIFECYCLE_MODULES, DISPOSITION_MODULES, INSPECTION_MODULES,
                OPERATOR_MODULES, SLOW_MODULES, INTEGRATION_MODULES,
                ADDITIONAL_MODULES, SYNTHESIS_MODULES, SCHEDULER_MODULES)
assert sum(map(len, MODULE_GROUPS)) == len(set().union(*MODULE_GROUPS))


def partition_for(identifier):
    if type(identifier) is not str or not identifier:
        raise ValueError('invalid discovered test ID')
    module = identifier.split('.', 1)[0]
    if module in ARCHIVE_MODULES:
        return 'archive'
    if module in MAINTENANCE_MODULES:
        return 'maintenance'
    if module in LIFECYCLE_MODULES:
        return 'lifecycle'
    if module in DISPOSITION_MODULES:
        return 'disposition'
    if module in INSPECTION_MODULES:
        return 'inspection'
    if module in OPERATOR_MODULES:
        return 'operator'
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
    print(f'Unit inventory: total={len(cases)} maintenance={len(groups["maintenance"])} lifecycle={len(groups["lifecycle"])} disposition={len(groups["disposition"])} inspection={len(groups["inspection"])} slow={len(groups["slow"])} '
          f'integration={len(groups["integration"])} additional={len(groups["additional"])} '
          f'operator={len(groups["operator"])} scheduler={len(groups["scheduler"])} synthesis={len(groups["synthesis"])} remainder={len(groups["remainder"])} selected={args.partition}:{len(selected)} '
          f'ids_sha256={digest}', flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(selected))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
