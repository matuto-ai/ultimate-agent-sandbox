"""Standard discovery, two complete/disjoint unit partitions, no test exclusions.

Measured modules share work between the existing parallel unit jobs. Every
other module (including future additions) belongs to the remainder. Discovery
errors fail either invocation; imported tests are never run merely to select IDs.
"""
import argparse
import hashlib
from pathlib import Path
import sys
import unittest


SLOW_MODULES = frozenset({'test_peer', 'test_checkouts', 'test_forge_capacity',
                          'test_gate_evaluation', 'test_forge_mutations',
                          # Post-77 hosted log: approximately 16 seconds together.
                          'test_context', 'test_artifact_manual_source',
                          'test_run_review', 'test_staged_source_closure',
                          # Room hosted log: approximately 15 seconds together.
                          'test_participant', 'test_artifact_native_source',
                          'test_forge_mutation_audit', 'test_workstation_peer',
                          'test_forge_read_process', 'test_native_trust'})
PARTITIONS = ('slow', 'remainder')


def partition_for(identifier):
    if type(identifier) is not str or not identifier:
        raise ValueError('invalid discovered test ID')
    return 'slow' if identifier.split('.', 1)[0] in SLOW_MODULES else 'remainder'


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
          f'remainder={len(groups["remainder"])} selected={args.partition}:{len(selected)} '
          f'ids_sha256={digest}', flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(selected))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
