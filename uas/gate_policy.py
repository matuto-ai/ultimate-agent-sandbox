"""Pure bounded Gate-definition compilation; never execution or adjudication.

Only configured artifact-presence checks are supported in this first slice.
Other accepted evaluators/kinds need their own complete contracts before use.
"""
from copy import deepcopy
from pathlib import PurePosixPath


def compile_policy(value, field):
    # Imported at call time: config owns common serialization validation while
    # this module owns Gate semantics. No I/O, identity selection or effects.
    from .config import ConfigError, _object, _integer, _named, _strings, _reference, _array, _text, _id
    policy = deepcopy(value)
    _object(policy, field, ('id', 'version', 'gates', 'protected_operations',
                          'review_return_cap', 'queue_timeout_seconds', 'response_timeout_seconds'))
    _id(policy['id'], field + '.id')
    _integer(policy['version'], field + '.version')
    gates = _named(policy['gates'], field + '.gates')
    operations = _object(policy['protected_operations'], field + '.protected_operations',
                         ('submit-for-review', 'complete'))
    for operation, names in operations.items():
        fp = field + '.protected_operations.' + operation
        operations[operation] = _strings(names, fp, nonempty=True)
        for i, name in enumerate(names):
            _reference(name, f'{fp}[{i}]', gates)
    for gate, gp in gates.values():
        # Kind is checked before kind-specific fields for a precise refusal.
        _object(gate, gp, ('id', 'kind'), ('evaluator', 'config'))
        if gate['kind'] != 'mechanical':
            raise ConfigError(gp + '.kind', 'Gate kind has no supported complete compiler contract')
        _object(gate, gp, ('id', 'kind', 'evaluator', 'config'))
        if gate['evaluator'] != 'artifacts':
            raise ConfigError(gp + '.evaluator', 'evaluator has no supported complete compiler contract')
        config = _object(gate['config'], gp + '.config', ('items',))
        items = _array(config['items'], gp + '.config.items')
        if len(items) > 128:
            raise ConfigError(gp + '.config.items', 'artifact configuration exceeds 128 items')
        seen = set()
        for i, item in enumerate(items):
            ip = f'{gp}.config.items[{i}]'
            _object(item, ip, ('path', 'type', 'nonempty'))
            path = _text(item['path'], ip + '.path', 1024)
            parts = path.split('/')
            try:
                encoded = path.encode('utf-8', errors='strict')
                if (len(encoded) > 4095 or len(parts) > 32
                        or any(len(p.encode('utf-8')) > 255 for p in parts)):
                    raise ValueError()
            except (UnicodeError, ValueError) as error:
                raise ConfigError(ip + '.path', 'artifact path exceeds UTF-8 filesystem bounds') from error
            if (PurePosixPath(path).is_absolute() or any(p in ('', '.', '..') for p in parts)
                    or '\\' in path or any(c in path for c in '*?[]')
                    or any(p.lower() == '.git' for p in parts)):
                raise ConfigError(ip + '.path', 'expected literal target-relative artifact path')
            if path in seen:
                raise ConfigError(ip + '.path', 'duplicate artifact path')
            seen.add(path)
            if item['type'] not in ('file', 'directory'):
                raise ConfigError(ip + '.type', 'unsupported artifact type')
            if type(item['nonempty']) is not bool:
                raise ConfigError(ip + '.nonempty', 'expected boolean')
        config['items'] = sorted(items, key=lambda item: item['path'])
        # These are consequences of the accepted evaluator, not user-selected
        # claims of authority, wall-clock TTLs or a configurable workflow DAG.
        gate['source'] = 'supervisor-one-shot-helper'
        gate['scope'] = 'exact-head-tree'
        gate['freshness'] = 'dependency-changes'
        gate['dependencies'] = ['run-id', 'run-generation', 'policy-id', 'policy-version', 'repository', 'head-sha']
        gate['guarded_operations'] = sorted(op for op, ids in operations.items() if gate['id'] in ids)
        if not gate['guarded_operations']:
            raise ConfigError(gp + '.id', 'Gate must guard a configured operation')
    _integer(policy['review_return_cap'], field + '.review_return_cap', maximum=5)
    for key in ('queue_timeout_seconds', 'response_timeout_seconds'):
        _integer(policy[key], field + '.' + key)
    policy['gates'] = [gates[key][0] for key in sorted(gates)]
    return policy
