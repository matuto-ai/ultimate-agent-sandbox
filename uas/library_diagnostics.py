"""T36 bounded, read-only diagnostics over one immutable Project snapshot.

Reports contain only codes and hashed locations/content. They are observations,
never publication gates, semantic verdicts, repairs or verification renewals.
"""
from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import threading
import time
import uuid

from . import library, library_bundle as bundle, library_gate as gate
from .library_sources import Resolver

RULE_VERSION = 'library-diagnostics-1'
MAX_UNITS = 20000
MAX_SECONDS = 60
MAX_FINDINGS = 4096


def digest(value):
    if type(value) is not bytes:
        value = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(value).hexdigest()


def _date(value):
    if not isinstance(value, str):
        raise ValueError('date')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        if len(value) != 10:
            raise ValueError('date')
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class _Stop(Exception):
    pass


class Scanner:
    """Trusted service seam, not a caller-selected source or filesystem route.

    Source resolvers must be T14 Resolver instances already selected by trusted
    Project configuration. A missing registry entry means not checked; failures
    reading configured pinned material mean unavailable, never guessed mismatch.
    Each external-source read remains local-only and bounded by T14.
    """
    def __init__(self, scope, settings, *, current_scope, sources=None,
                 clock=lambda: datetime.now(timezone.utc).isoformat(),
                 monotonic=time.monotonic, max_units=MAX_UNITS, seconds=30):
        bundle._prefix(scope)
        self.scope = scope
        self.settings = library.admit_settings_value(settings)
        self.current_scope = current_scope
        self.sources = dict(sources or {})
        if any(type(k) is not str or type(v) is not Resolver for k, v in self.sources.items()):
            raise library.LibraryError('INVALID_SOURCE_BINDING', 'diagnostics')
        if (type(max_units) is not int or not 1 <= max_units <= MAX_UNITS
                or type(seconds) not in (int, float) or not 0 < seconds <= MAX_SECONDS):
            raise library.LibraryError('INVALID_SCAN_BOUND', 'diagnostics')
        self.clock, self.monotonic = clock, monotonic
        self.max_units, self.seconds = max_units, seconds
        self.config_hash = digest(self.settings)

    def current(self):
        fresh = self.current_scope()
        if type(fresh) is not library.LibraryScope or fresh.canonical() != self.scope.canonical():
            raise library.LibraryError('AUTHORITY_REVOKED', 'diagnostics')

    def scan(self, input_sha, tree, *, cancelled=lambda: False):
        """One bounded report. Unchecked areas never clear previous findings.

        Consumers retain reports by scan_id/input_sha. No active-finding deletion
        or global clean flag exists; no_findings is None for partial coverage.
        """
        self.current()
        if input_sha is not None:
            library._commit(input_sha, 'input_sha')
        if type(tree) is not bundle.Tree:
            raise library.LibraryError('INVALID_CONTRACT', 'diagnostics')
        at = self.clock()
        now = _date(at)
        report = {'version': 1, 'scan_id': uuid.uuid4().hex,
                  'project_id': self.scope.project_id,
                  'project_identity': self.scope.project_identity,
                  'input_sha': input_sha, 'observed_at': at,
                  'rule_version': RULE_VERSION, 'configuration_sha256': self.config_hash,
                  'coverage': {'checked': [], 'unchecked': [], 'sources': []},
                  'findings': [], 'complete': False, 'no_findings': None,
                  'resulting_references': []}
        prefix = bundle._prefix(self.scope) + '/'
        files = dict(tree.files)
        if any(type(k) is not str or type(v) is not bytes for k, v in files.items()):
            raise library.LibraryError('INVALID_CONTRACT', 'diagnostics')
        deadline = self.monotonic() + self.seconds
        units = 0
        # Units and names are fixed before examining content. Locations are hashes,
        # not attacker-controlled filenames or exception strings.
        areas = ['tree', *(('document:' + p + ':' + phase) for p in sorted(files)
                            for phase in ('structure', 'links', 'sources')), 'relationships']
        completed = set()
        parsed, links, concepts = {}, {}, {}
        accepted = set()
        graph_complete = True

        def location(path):
            return digest(path)

        def tick():
            nonlocal units
            self.current()
            units += 1
            if cancelled() or units > self.max_units or self.monotonic() >= deadline:
                raise _Stop()

        def finding(category, code, path, raw=b'', detail=None):
            if len(report['findings']) >= MAX_FINDINGS:
                raise _Stop()
            item = {'category': category, 'code': code, 'location_sha256': location(path),
                    'content_sha256': digest(raw)}
            if detail is not None:
                item['detail_sha256'] = digest(detail)
            item['finding_id'] = digest([self.scope.project_identity, RULE_VERSION,
                                         self.config_hash, item])
            if item not in report['findings']:
                report['findings'].append(item)

        def check(path, raw, function):
            tick()
            try:
                return function()
            except library.LibraryError as error:
                finding('violation', error.code, path, raw)
                return None

        try:
            tick()
            if input_sha is None or not files:
                finding('unavailable', 'PROJECT_NOT_REGISTERED', 'tree')
                raise _Stop()
            # Crash bounds checked before decoding/parsing. Out-of-bound trees
            # remain partial; do not misrepresent omitted data as checked.
            limits = self.settings['limits']
            if (len(files) > limits['scan_documents']
                    or any(type(k) is not str or type(v) is not bytes for k, v in files.items())
                    or sum(len(v) for v in files.values()) > limits['projection_bytes']):
                finding('violation', 'SCAN_TREE_BOUND', 'tree')
                raise _Stop()
            folded = set()
            for path in tree.symlinks:
                tick()
                finding('violation', 'SYMLINK_NOT_ALLOWED', path)
            for required in bundle.REQUIRED:
                if prefix + required not in files:
                    finding('violation', 'MISSING_REQUIRED_FILE', required)
            completed.add('tree')
            for path, raw in sorted(files.items()):
                tick()
                area = 'document:' + path
                if not path.startswith(prefix):
                    finding('violation', 'FOREIGN_PROJECT', path, raw)
                    completed.add(area + ':structure')
                    continue
                relative = path[len(prefix):]
                if len(raw) > limits['document_bytes']:
                    graph_complete = False
                    finding('violation', 'DOCUMENT_TOO_LARGE', path, raw)
                    continue
                if path.casefold() in folded:
                    finding('violation', 'PATH_COLLISION', path, raw)
                folded.add(path.casefold())
                if check(path, raw, lambda: bundle._path(path, 'diagnostics')) is None:
                    graph_complete = False
                    completed.add(area + ':structure')
                    continue
                text = check(path, raw, lambda: bundle._canonical(path, raw, 'diagnostics'))
                if text is None:
                    graph_complete = False
                    completed.add(area + ':structure')
                    continue
                kind, directory, name = bundle._classify(relative)
                meta, body = {}, text
                if relative == 'index.md' or kind == 'concept':
                    value = check(path, raw, lambda: bundle.frontmatter(text, relative))
                    if value is None:
                        graph_complete = False
                        completed.add(area + ':structure')
                        continue
                    meta, body = value
                parsed[relative] = (meta, body, raw)
                if relative == 'index.md':
                    check(path, raw, lambda: bundle._root_index(text, self.scope))
                elif relative == 'log.md':
                    check(path, raw, lambda: bundle._log(text, text, False))
                elif kind == 'index':
                    check(path, raw, lambda: bundle._index(relative, text, False))
                elif kind == 'concept':
                    tick()
                    try:
                        bundle._concept(relative, directory, name, text, text, set(), limits, gate.SOURCE_FIELDS)
                    except library.LibraryError as error:
                        finding('violation', error.code, path, raw)
                    else:
                        if directory in bundle.DIRECTORIES:
                            accepted.add(relative)
                    concepts[relative] = meta
                    if not meta.get('sources') and meta.get('type') != 'research':
                        finding('observation', 'OPTIONAL_SOURCE_MISSING', path, raw)
                    if 'stale_after' in meta:
                        try:
                            if now >= _date(meta['stale_after']):
                                finding('observation', 'FRESHNESS_ELAPSED', path, raw)
                        except (ValueError, TypeError, OverflowError):
                            finding('observation', 'FRESHNESS_UNCHECKED', path, raw)
                    completed.add(area + ':structure')
                    self._sources(meta, relative, raw, tick, finding, report, files, prefix)
                completed.add(area + ':structure')
                completed.add(area + ':sources')
                # Unknown existing files/metadata stay tolerated reader data.
                targets = set()
                try:
                    for event, target in gate.scan(body, relative, include_definitions=False, include_image_children=False):
                        tick()
                        if event == 'link':
                            try:
                                resolved = gate.destination(relative, target)
                            except library.LibraryError:
                                continue  # old external links are tolerated reader data
                            if resolved:
                                targets.add(resolved)
                except library.LibraryError as error:
                    graph_complete = False
                    finding('violation', error.code, path, raw)
                else:
                    completed.add(area + ':links')
                links[relative] = targets
                completed.add(area + ':structure')
            tick()
            for relative, (meta, body, raw) in parsed.items():
                tick()
                for target in sorted(links.get(relative, ())):
                    tick()
                    if prefix + target not in files:
                        finding('observation', 'BROKEN_INTERNAL_LINK', prefix + relative, raw, target)
            for relative, meta in concepts.items():
                tick()
                directory = relative.split('/')[0]
                index = directory + '/index.md'
                if index in parsed:
                    entries = bundle._links(parsed[index][1], index)
                    if relative not in entries:
                        finding('violation', 'MISSING_INDEX_ENTRY', prefix + index,
                                parsed[index][2], relative)
                    elif meta.get('title') is not None and entries[relative] != meta['title']:
                        finding('violation', 'INDEX_TITLE_MISMATCH', prefix + index,
                                parsed[index][2], relative)
                if relative in accepted and graph_complete:
                    incoming = any(other != relative and relative in links.get(other, ())
                                   for other in accepted)
                    if not incoming:
                        finding('observation', 'ISOLATED_CONCEPT', prefix + relative, parsed[relative][2])
            if graph_complete:
                completed.add('relationships')
        except _Stop:
            pass
        report['coverage']['checked'] = [location(area) for area in areas if area in completed]
        report['coverage']['unchecked'] = [location(area) for area in areas if area not in completed]
        report['coverage']['unchecked'].extend(
            item['location_sha256'] for item in report['coverage']['sources']
            if item['state'] in ('not_checked', 'unavailable'))
        report['complete'] = not report['coverage']['unchecked']
        report['no_findings'] = not report['findings'] if report['complete'] else None
        self.current()
        return report

    def _sources(self, meta, relative, raw, tick, finding, report, files, prefix):
        values = meta.get('sources')
        if type(values) is not list:
            return
        if len(values) > self.settings['limits']['sources']:
            raise _Stop()
        for index, entry in enumerate(values):
            tick()
            where = prefix + relative + ':source:' + str(index)
            status = 'not_checked'
            if type(entry) is not dict:
                continue
            try:
                declared = gate._declaration(relative, entry, index)
            except library.LibraryError as error:
                finding('violation', error.code, where, raw)
                status = 'invalid'
            else:
                resource = entry['resource']
                if declared['pinned'] and 'sha256' in entry:
                    declaration = {k:entry[k] for k in ('resource', 'range', 'sha256')}
                    if declared['kind'] == 'concept':
                        content = files.get(prefix + resource)
                        if content is not None:
                            first, last = map(int, entry['range'].split('-'))
                            lines = content.splitlines(keepends=True)
                            status = 'checked'
                            if last > len(lines) or digest(b''.join(lines[first-1:last])) != entry['sha256']:
                                status = 'mismatch'
                    elif resource in self.sources:
                        try:
                            self.sources[resource].resolve(self.scope, self.settings, declaration)
                            status = 'checked'
                        except library.LibraryError as error:
                            status = ('mismatch' if error.code in ('SOURCE_HASH_MISMATCH', 'SOURCE_RANGE_UNAVAILABLE')
                                      else 'unavailable')
                    if status == 'mismatch':
                        finding('mismatch', 'SOURCE_PROVENANCE_MISMATCH', where, raw, declaration)
                if status == 'not_checked':
                    finding('unchecked', 'SOURCE_NOT_CHECKED', where, raw, resource)
                elif status == 'unavailable':
                    finding('unavailable', 'SOURCE_UNAVAILABLE', where, raw, resource)
            report['coverage']['sources'].append({'location_sha256': digest(where), 'state': status})


class Diagnostics:
    """Event-driven service composition; failures never enter the write path.

    The owner may persist reports via sink. The bounded in-memory history is an
    observation window, not an active findings database. Partial reports cannot
    remove earlier reports or turn historical SHAs into current assessments.
    """
    def __init__(self, publisher, scanner, *, sink=None, history_limit=32):
        if not 1 <= history_limit <= 256:
            raise library.LibraryError('INVALID_SCAN_BOUND', 'diagnostics')
        self.publisher, self.scanner, self.sink = publisher, scanner, sink
        self._history = deque(maxlen=history_limit)
        self._condition = threading.Condition()
        self._stop = threading.Event()
        self._subscription = None
        self._thread = None
        self._processed = 0
        self.last_error = None

    @property
    def reports(self):
        with self._condition:
            return json.loads(json.dumps(list(self._history)))

    def start(self):
        if self._subscription is not None:
            raise library.LibraryError('ALREADY_STARTED', 'diagnostics')
        self._subscription = self.publisher.subscribe(self.scanner.scope)
        self._thread = threading.Thread(target=self._run, name='library-diagnostics', daemon=True)
        self._thread.start()
        return self

    def request(self):
        """Explicit trusted service request; adapters authenticate human scan actions."""
        self.scanner.current()
        if self._subscription is None:
            raise library.LibraryError('NOT_READY', 'diagnostics')
        self._subscription.signal()

    def _run(self):
        after = 0
        while True:
            version, _, closed = self._subscription.wait(after)
            if closed:
                return
            try:
                sha, tree = self.publisher.projection_snapshot(self.scanner.scope, self.scanner.settings,
                                                               current=self.scanner.current)
                result = self.scanner.scan(sha, tree, cancelled=self._stop.is_set)
                # A failing sink is reported, not thrown into canonical writes.
                if self.sink is not None:
                    self.sink(json.loads(json.dumps(result)))
                with self._condition:
                    self._history.append(result)
                self.last_error = None
            except Exception:
                # No raw exception, source/transport output, or text leaks.
                self.last_error = 'SCAN_UNAVAILABLE'
            after = version
            with self._condition:
                self._processed = version
                self._condition.notify_all()

    def wait_idle(self, timeout=5):
        if self._subscription is None:
            raise library.LibraryError('NOT_READY', 'diagnostics')
        version, _, _ = self._subscription.wait(-1, 0)
        with self._condition:
            return self._condition.wait_for(lambda: self._processed >= version, timeout)

    def close(self):
        self._stop.set()
        if self._subscription is not None:
            self.publisher.unsubscribe(self._subscription)
        if self._thread is not None:
            self._thread.join()
