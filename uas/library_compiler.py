"""Pure deterministic compilation of untrusted synthesis, never publication.

T19 supplies the authenticated scope, exact input snapshot/batch and service time.
The model receives opaque references from catalog(), not filesystem authority.
Only a complete T05-validated result is returned; inputs are never mutated.
"""
from dataclasses import dataclass
import hashlib
import json
import re
import unicodedata
from types import MappingProxyType

from . import library, library_bundle as bundle, library_gate as gate
from .library_registration import project_state


@dataclass(frozen=True)
class Compilation:
    tree: bundle.Tree
    validation: gate.Result
    outcomes: tuple
    paths: object
    proposal_sha256: str
    input_sha: str


def _fail(code, field):
    raise library.LibraryError(code, field)


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _ref(path):
    return 'concept-' + _hash(path.encode('utf-8'))


def _quote(value):
    return json.dumps(value, ensure_ascii=False)


def _label(value):
    return re.sub(r'([\\`*_{}\[\]()<>!#|])', r'\\\1', value)


def _document(data, path):
    return bundle.frontmatter(bundle._canonical(path, data, path), path)


def _inputs(scope, settings, current, selected):
    admitted = library.admit_settings_value(settings)
    prefix = bundle._prefix(scope)
    if type(current) is not bundle.Tree or not current.files:
        _fail('PROJECT_NOT_REGISTERED', 'current')
    # Validate the unchanged complete canonical tree as well as the final result.
    gate.validate(scope, admitted, proposed=current, current=current)
    if project_state(current, prefix) != 'active':
        _fail('PROJECT_ARCHIVED', 'current')
    bundle._selected(selected, admitted['limits'])
    if not selected or len(set(selected)) != len(selected):
        _fail('INVALID_BATCH', 'selected')
    drafts, concepts = {}, {}
    total = 0
    for queue in selected:
        relative = 'pending/' + queue + '.md'
        data = current.files.get(prefix + '/' + relative)
        if data is None:
            _fail('SELECTED_DRAFT_MISSING', 'selected')
        meta, body = _document(data, relative)
        if meta.get('status') != 'draft':
            _fail('NOT_A_PENDING_DRAFT', 'selected')
        drafts[queue] = (meta, body, data)
        total += len(data)
    if total > admitted['limits']['batch_bytes']:
        _fail('BATCH_TOO_LARGE', 'selected')
    for path, data in current.files.items():
        relative = path[len(prefix) + 1:]
        kind, directory, _ = bundle._classify(relative)
        if kind == 'concept' and directory in bundle.DIRECTORIES:
            meta, body = _document(data, relative)
            concepts[_ref(relative)] = (relative, meta, body, data)
    return admitted, prefix, drafts, concepts


def catalog(scope, settings, *, current, selected):
    """Bounded caller-facing references; returned data is not write authority.

    Existing bodies are complete Markdown, including prior service notices and
    provenance. An update with identical body/title/description/sources/status
    preserves the exact original bytes and current verification.
    """
    _, _, drafts, concepts = _inputs(scope, settings, current, selected)
    return {'drafts': list(drafts), 'concepts': {
        ref: {'type': meta.get('type'), 'title': meta.get('title'),
              'description': meta.get('description', ''), 'body': body,
              'status': meta.get('status')}
        for ref, (_, meta, body, _) in sorted(concepts.items())}}


def _text(value, field, limit, *, multiline=False):
    value = library._text(value, field, limit, multiline=multiline)
    bundle._text_check(value, field)
    return value


def _admit(value, *, drain_id, attempt, selected, concepts, limits):
    library._object(value, 'proposal', ('version', 'drain_id', 'attempt', 'operations', 'outcomes'))
    if type(value['version']) is not int or value['version'] != 1:
        _fail('UNSUPPORTED_CONTRACT_VERSION', 'proposal.version')
    if value['drain_id'] != drain_id or type(value['drain_id']) is not str:
        _fail('PROPOSAL_BATCH_MISMATCH', 'proposal.drain_id')
    if type(value['attempt']) is not int or value['attempt'] != attempt:
        _fail('PROPOSAL_BATCH_MISMATCH', 'proposal.attempt')
    if library._size(value) > limits['payload_bytes']:
        _fail('PROPOSAL_TOO_LARGE', 'proposal')
    operations = library._array(value['operations'], 'operations', library.MAX_PROPOSAL_OPERATIONS)
    result, targets = {}, set()
    for index, operation in enumerate(operations):
        field = 'operations[%d]' % index
        if type(operation) is not dict:
            _fail('INVALID_CONTRACT', field)
        op = operation.get('op')
        common = ('id', 'op', 'drafts')
        if type(op) is not str:
            _fail('UNSAFE_PROPOSAL_OPERATION', field)
        if op == 'create':
            fields = common + ('type', 'title', 'description', 'body')
        elif op == 'update':
            fields = common + ('target', 'title', 'description', 'body')
        elif op == 'deprecate':
            fields = common + ('target', 'reason')
        else:
            _fail('UNSAFE_PROPOSAL_OPERATION', field)
        library._object(operation, field, fields)
        identifier = library._identifier(operation['id'], field + '.id')
        if identifier in result:
            _fail('DUPLICATE_OPERATION', field + '.id')
        queues = library._array(operation['drafts'], field + '.drafts', limits['batch_drafts'], nonempty=True)
        if any(type(q) is not str or q not in selected for q in queues) or len(set(queues)) != len(queues):
            _fail('UNCERTAIN_ATTRIBUTION', field + '.drafts')
        item = dict(operation, drafts=tuple(sorted(queues)))
        if op != 'create':
            target = operation['target']
            if type(target) is not str or target not in concepts:
                _fail('UNKNOWN_CONCEPT_REFERENCE', field + '.target')
            if target in targets:
                _fail('DUPLICATE_TARGET', field + '.target')
            targets.add(target)
            if concepts[target][1].get('type') not in library.CAPTURE_TYPES:
                _fail('UNSUPPORTED_TYPE', field + '.target')
        elif type(operation['type']) is not str or operation['type'] not in library.CAPTURE_TYPES:
            _fail('UNSUPPORTED_TYPE', field + '.type')
        if op == 'deprecate':
            library._token(operation['reason'], field + '.reason')
        else:
            _text(operation['title'], field + '.title', limits['title_chars'])
            # Empty descriptions are supported, but never multiline/control data.
            if operation['description'] != '':
                _text(operation['description'], field + '.description', limits['title_chars'])
            elif type(operation['description']) is not str:
                _fail('INVALID_TEXT', field + '.description')
            _text(operation['body'], field + '.body', limits['body_bytes'], multiline=True)
            if not operation['body'].strip() or len(operation['body'].encode('utf-8')) > limits['body_bytes']:
                _fail('INVALID_BODY', field + '.body')
        result[identifier] = item
    outcomes = {}
    for index, outcome in enumerate(library._array(value['outcomes'], 'outcomes', limits['batch_drafts'], nonempty=True)):
        field = 'outcomes[%d]' % index
        if type(outcome) is not dict:
            _fail('INVALID_CONTRACT', field)
        kind = outcome.get('kind')
        if type(kind) is not str or kind not in ('integrated', 'merged', 'parked'):
            _fail('INVALID_DRAFT_OUTCOME', field)
        library._object(outcome, field, ('queue_id', 'kind', 'reason') if kind == 'parked'
                        else ('queue_id', 'kind', 'targets'))
        queue = outcome['queue_id']
        if type(queue) is not str or queue not in selected or queue in outcomes:
            _fail('UNCERTAIN_ATTRIBUTION', field + '.queue_id')
        if kind == 'parked':
            library._token(outcome['reason'], field + '.reason')
            if any(queue in operation['drafts'] for operation in result.values()):
                _fail('UNCERTAIN_ATTRIBUTION', field)
            outcomes[queue] = dict(outcome)
            continue
        refs = library._array(outcome['targets'], field + '.targets', library.MAX_PROPOSAL_OPERATIONS, nonempty=True)
        if any(type(ref) is not str or ref not in result for ref in refs) or len(set(refs)) != len(refs):
            _fail('UNKNOWN_OPERATION_REFERENCE', field)
        expected = {ref for ref, op in result.items() if queue in op['drafts']}
        if set(refs) != expected:
            _fail('UNCERTAIN_ATTRIBUTION', field)
        if kind == 'merged' and any(result[ref]['op'] == 'create' for ref in refs):
            _fail('INVALID_DRAFT_OUTCOME', field)
        outcomes[queue] = dict(outcome, targets=tuple(sorted(refs)))
    if set(outcomes) != set(selected):
        _fail('UNCERTAIN_ATTRIBUTION', 'outcomes')
    return result, outcomes


def _slug(title):
    ascii_title = unicodedata.normalize('NFKD', title).encode('ascii', 'ignore').decode('ascii').lower()
    return re.sub(r'[^a-z0-9]+', '-', ascii_title).strip('-')[:80].rstrip('-') or 'concept'


def _allocate(operation, used):
    directory = {'context': 'context', 'decision': 'decisions', 'research': 'research'}[operation['type']]
    stem = _slug(operation['title'])
    path = directory + '/' + stem + '.md'
    if path.casefold() in used or stem == 'index':
        # Full queue-derived hash avoids a short-prefix collision fallback counter.
        suffix = library._digest(list(operation['drafts']))
        path = directory + '/' + stem + '-' + suffix + '.md'
    if path.casefold() in used:
        _fail('SLUG_COLLISION', 'operations')
    used.add(path.casefold())
    return path


def _blocks(data):
    """Keep unknown existing YAML blocks byte-for-byte, including reader kinds."""
    if data is None:
        return {}
    lines = data.decode('utf-8').split('\n')
    end = lines.index('---', 1)
    result, key = {}, None
    for line in lines[1:end]:
        match = re.match(r'^([A-Za-z0-9_.-]+):', line)
        if match:
            key = match.group(1)
            result[key] = []
        if key is not None:
            result[key].append(line)
    return {key: '\n'.join(lines) for key, lines in result.items()}


def _sources(drafts, queues, before):
    # The model supplies no source records. Preserve existing provenance and
    # every supplied declaration from the operation's attributed input drafts.
    entries = list(before.get('sources') or [])
    for queue in queues:
        entries.extend(drafts[queue][0].get('sources') or [])
    result = []
    for entry in entries:
        if not any(bundle._same(entry, other) for other in result):
            result.append(entry)
    return result


def _yaml(value):
    # Existing source entries may contain tolerated reader keys. Emit supported
    # scalar/collection syntax without converting an implicit reader kind.
    if isinstance(value, bundle.Implicit):
        return str(value)
    if type(value) is str:
        return _quote(value)
    if type(value) is list:
        return '[' + ', '.join(_yaml(item) for item in value) + ']'
    if type(value) is dict:
        return '{' + ', '.join(key + ': ' + _yaml(item) for key, item in value.items()) + '}'
    _fail('INVALID_SOURCE', 'sources')


def _render(operation, before, body_before, raw_before, sources, *, at, drain_id,
            input_sha, drafts):
    blocks = _blocks(raw_before)
    kind = operation['op']
    desired = dict(before)
    if kind == 'create':
        desired['type'] = operation['type']
    desired['status'] = 'deprecated' if kind == 'deprecate' else 'stable'
    if kind != 'deprecate':
        desired.update(title=operation['title'], description=operation['description'])
        body = operation['body']
    else:
        body = body_before
    if sources:
        desired['sources'] = sources
    # Unchanged semantic input retains exact bytes and existing verification.
    equal = (raw_before is not None and body == body_before
             and all(bundle._same(desired.get(key), before.get(key))
                     for key in ('type', 'title', 'status', 'sources'))
             and desired.get('description', '') == before.get('description', ''))
    if equal:
        return raw_before
    desired['generated'] = bundle.Implicit('true')
    desired['verified'] = bundle.Implicit('false')
    for key in ('type', 'title', 'description', 'status', 'generated', 'verified'):
        if key in desired:
            blocks[key] = key + ': ' + _yaml(desired[key])
    if sources:
        blocks['sources'] = 'sources:\n' + '\n'.join('  - ' + _yaml(entry) for entry in sources)
    if gate.notice_missing(body):
        body = gate.NOTICE + '\n\n' + body
    provenance = ['\n\n## Synthesis provenance', '', 'Service time: ' + at,
                  'Drain identity: ' + drain_id, 'Input commit: ' + input_sha]
    if kind == 'deprecate':
        provenance.append('Deprecation reason: ' + operation['reason'])
    for queue in operation['drafts']:
        provenance.append('Source draft: ' + queue + '; SHA256: ' + _hash(drafts[queue][2]))
    return ('---\n' + '\n'.join(blocks.values()) + '\n---\n' + body
            + '\n'.join(provenance) + '\n').encode('utf-8')


def _index(data, directory, changed, files, prefix, parked):
    """Replace only recognizable single-entry lines; preserve other authored data.

    A nonstandard authored entry to an affected concept is ambiguous: fail the
    whole compile rather than silently rewrite prose or leave a stale index.
    """
    text = data.decode('utf-8')
    protected = set()
    for token in gate.MarkdownIt('commonmark').parse(text):
        if token.type in ('fence', 'code_block') and token.map:
            protected.update(range(*token.map))
    lines = []
    for number, line in enumerate(text.splitlines()):
        if number in protected:
            lines.append(line)
            continue
        links = [(label, bundle._target(target, directory + '/index.md'))
                 for label, target in bundle._scan(line)]
        if any(path in changed for _, path in links):
            if (len(links) != 1 or not re.match(r'^\s*[-*+] \[.*\]\([^)]*\)(?:\s*-.*)?\s*$', line)):
                _fail('INDEX_ENTRY_NOT_REPRODUCIBLE', directory + '/index.md')
            continue
        lines.append(line)
    if gate.notice_missing('\n'.join(lines)):
        lines.extend(['', gate.NOTICE])
    for relative in sorted(changed):
        if not relative.startswith(directory + '/') or prefix + '/' + relative not in files:
            continue
        meta, _ = _document(files[prefix + '/' + relative], relative)
        name = relative.split('/')[1]
        status = ('DRAFT PARKED: ' + parked[name[:-3]] if name[:-3] in parked
                  else meta.get('status', 'unknown'))
        lines.append('* [' + _label(meta['title']) + '](' + name + ') - '
                     + _label(meta['type']) + '; ' + status + '; '
                     + _label(meta.get('description', '')))
    return ('\n'.join(lines).rstrip('\n') + '\n').encode('utf-8')


def compile_proposal(scope, settings, *, current, selected, input_sha, drain_id,
                     attempt, at, proposal):
    """Compile one exact fixed-batch proposal, with no I/O or partial result.

    All kwargs except proposal are service-owned snapshot/batch context. This
    seam neither grants verification nor evaluates semantic truth; T19 owns
    fresh authority, input-change reconciliation and atomic publication.
    """
    admitted, prefix, drafts, concepts = _inputs(scope, settings, current, selected)
    library._commit(input_sha, 'input_sha')
    library._token(drain_id, 'drain_id')
    library._integer(attempt, 'attempt')
    library._timestamp(at, 'at')
    operations, outcomes = _admit(proposal, drain_id=drain_id, attempt=attempt,
                                   selected=selected, concepts=concepts, limits=admitted['limits'])
    files = dict(current.files)
    used = {path[len(prefix) + 1:].casefold() for path in files}
    paths, changed = {}, set()
    # Deterministic order independent of model array ordering.
    for identifier, operation in sorted(operations.items()):
        if operation['op'] == 'create':
            path = _allocate(operation, used)
            before, body_before, raw_before = {}, '', None
        else:
            path, before, body_before, raw_before = concepts[operation['target']]
        paths[identifier] = path
        sources = _sources(drafts, operation['drafts'], before)
        files[prefix + '/' + path] = _render(operation, before, body_before, raw_before,
            sources, at=at, drain_id=drain_id, input_sha=input_sha, drafts=drafts)
        if files[prefix + '/' + path] != raw_before:
            changed.add(path)
    parked = {}
    for queue, outcome in outcomes.items():
        relative = 'pending/' + queue + '.md'
        changed.add(relative)
        if outcome['kind'] == 'parked':
            parked[queue] = outcome['reason']
        else:
            del files[prefix + '/' + relative]
    for directory in bundle.DIRECTORIES + ('pending',):
        if any(path.startswith(directory + '/') for path in changed):
            index = prefix + '/' + directory + '/index.md'
            files[index] = _index(files[index], directory, changed, files, prefix, parked)
    # The root notice is deterministic, but other reader text is not replaced.
    root = prefix + '/index.md'
    if gate.notice_missing(_document(files[root], 'index.md')[1]):
        files[root] += ('\n' + gate.NOTICE + '\n').encode('utf-8')
    log = ['\n## ' + at[:10], '* **Synthesis**: ' + drain_id + '; input ' + input_sha + '.']
    for queue, outcome in sorted(outcomes.items()):
        detail = outcome.get('reason') or ', '.join(paths[ref] for ref in outcome['targets'])
        log.append('* ' + queue + ': ' + outcome['kind'].upper() + '; ' + detail + '.')
    files[prefix + '/log.md'] += ('\n'.join(log) + '\n').encode('utf-8')
    proposed = bundle.Tree(files)
    validated = gate.validate(scope, admitted, proposed=proposed, current=current, selected=selected)
    return Compilation(proposed, validated,
        tuple(MappingProxyType(dict(outcomes[q])) for q in sorted(outcomes)),
        MappingProxyType(paths), library._digest(proposal), input_sha)
