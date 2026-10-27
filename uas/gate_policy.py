"""Pure bounded Gate-definition compilation; never execution or adjudication.

Definitions are deployment-owned. Participant evidence never selects an evaluator,
command, source, identity relationship, scope, freshness rule or guarded operation.
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
        _object(gate, gp, ('id', 'kind'), ('evaluator', 'config'))
        if gate['kind'] not in ('mechanical', 'attestation', 'decision'):
            raise ConfigError(gp + '.kind', 'unsupported Gate kind')
        if gate['kind'] == 'mechanical':
            _object(gate, gp, ('id', 'kind', 'evaluator', 'config'))
            evaluator = gate['evaluator']
            if evaluator == 'artifacts':
                gate['config'] = _artifacts(gate['config'], gp)
            elif evaluator == 'forge-state':
                from .gate_forge import compile_forge_config
                gate['config'] = compile_forge_config(gate['config'], gp + '.config')
            elif evaluator in ('command', 'diff-claims'):
                from .gate_repository import compile_repository_config
                gate['config'] = compile_repository_config(evaluator, gate['config'], gp + '.config')
            else:
                raise ConfigError(gp + '.evaluator', 'unsupported mechanical evaluator')
            gate['source'] = 'broker' if evaluator == 'forge-state' else 'supervisor-one-shot-helper'
            gate['scope'] = ('exact-pr-head-base' if evaluator == 'forge-state' else
                             'exact-base-head' if evaluator == 'diff-claims' else 'exact-head-tree')
        else:
            _object(gate, gp, ('id', 'kind', 'config'))
            gate['config'] = _identity_config(gate['config'], gp + '.config', gate['kind'])
            gate['source'] = 'authenticated-identity'
            gate['scope'] = gate['config']['scope']
        # These are consequences of the accepted evaluator, not user-selected
        # claims of authority, wall-clock TTLs or a configurable workflow DAG.
        gate['freshness'] = 'dependency-changes'
        gate['dependencies'] = ['run-id', 'run-generation', 'policy-id', 'policy-version']
        if gate['scope'] != 'run':
            gate['dependencies'] += ['repository', 'head-sha']
        if gate['scope'] in ('exact-base-head', 'exact-pr-head-base'):
            gate['dependencies'].append('base-sha')
        if gate.get('evaluator') == 'forge-state':
            gate['dependencies'] += ['pull-id', 'forge-state-version', 'ci-attempts', 'required-checks']
        if gate['kind'] != 'mechanical' and gate['config']['continuing_authority']:
            gate['dependencies'] += ['actor-authority-epoch', 'eligibility']
        gate['guarded_operations'] = sorted(op for op, ids in operations.items() if gate['id'] in ids)
        if not gate['guarded_operations']:
            raise ConfigError(gp + '.id', 'Gate must guard a configured operation')
    _integer(policy['review_return_cap'], field + '.review_return_cap', maximum=5)
    for key in ('queue_timeout_seconds', 'response_timeout_seconds'):
        _integer(policy[key], field + '.' + key)
    policy['gates'] = [gates[key][0] for key in sorted(gates)]
    return policy


def _artifacts(config, gp):
    from .config import ConfigError, _object, _array, _text
    config = _object(config, gp + '.config', ('items',))
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
    return config


def _identity_config(config, field, kind):
    from .config import ConfigError, _object, _id, _strings
    config = _object(config, field, ('statement_id', 'scope', 'eligible_actors',
        'relationship', 'required_capability', 'allow_self', 'continuing_authority'))
    _id(config['statement_id'], field + '.statement_id')
    if config['scope'] not in ('run', 'head'):
        raise ConfigError(field + '.scope', 'expected run or head scope')
    config['eligible_actors'] = _strings(config['eligible_actors'], field + '.eligible_actors', nonempty=True)
    for actor in config['eligible_actors']:
        _id(actor, field + '.eligible_actors')
    if len(config['eligible_actors']) > 32:
        raise ConfigError(field + '.eligible_actors', 'at most 32 durable Actor identities')
    if config['relationship'] not in ('human', 'participant', 'implementer', 'independent-reviewer'):
        raise ConfigError(field + '.relationship', 'unsupported identity relationship')
    if config['required_capability'] not in (None, 'implement', 'review'):
        raise ConfigError(field + '.required_capability', 'unsupported Hub capability')
    for key in ('allow_self', 'continuing_authority'):
        if type(config[key]) is not bool:
            raise ConfigError(field + '.' + key, 'expected boolean')
    if config['relationship'] == 'independent-reviewer' and (
            config['scope'] != 'head' or config['required_capability'] != 'review'
            or config['allow_self'] or not config['continuing_authority']):
        raise ConfigError(field + '.relationship', 'independent review requires exact head and continuing review authority')
    if config['relationship'] == 'implementer' and not config['allow_self']:
        raise ConfigError(field + '.allow_self', 'implementer evidence must explicitly permit self assertion')
    return config
