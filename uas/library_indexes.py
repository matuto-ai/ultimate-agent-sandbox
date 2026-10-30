"""Conservative reconstruction: recognized service indexes, never authored text.

No I/O, model, concept mutation or history synthesis. An uncertain index is
retained byte-for-byte and reported; names alone do not prove ownership.
"""
import re
from . import library, library_bundle as bundle, library_gate as gate, library_deadline
from .library_compiler import _document, _label


def reconstruct(scope, tree):
    prefix = bundle._prefix(scope)
    files = dict(tree.files)
    reports = []
    root = prefix+'/index.md'
    if root in files:
        from .library_registration import skeleton
        canonical = skeleton(scope, '2000-01-01T00:00:00+00:00').files[root]
        try:
            lines = files[root].decode('utf-8').splitlines()
            expected = canonical.decode('utf-8').splitlines()
            required = {'---', 'okf_version: "0.2"', '# Project Library', gate.NOTICE,
                        'Source coordinates: '+scope.project_path, 'Source identity: '+scope.project_identity}
            allowed = set(expected) | {'Library state: active'}
            if (required.issubset(lines) and all(line in allowed for line in lines)
                    and lines.count('---') == 2 and lines.count('Library state: active') <= 1):
                files[root] = canonical + (b'\nLibrary state: active\n' if 'Library state: active' in lines else b'')
            else:
                reports.append({'path':'index.md','reason':'AUTHORED_OR_UNCERTAIN_INDEX'})
        except UnicodeError:
            reports.append({'path':'index.md','reason':'MALFORMED_INDEX'})
    for directory in bundle.DIRECTORIES + ('pending',):
        library_deadline.remaining(30)
        path = prefix + '/' + directory + '/index.md'
        if path not in files:
            reports.append({'path':directory+'/index.md', 'reason':'MISSING_INDEX_OWNERSHIP'})
            continue
        try: text = files[path].decode('utf-8')
        except UnicodeError:
            reports.append({'path':directory+'/index.md','reason':'MALFORMED_INDEX'})
            continue
        header = '# ' + directory.title()
        accepted = {header, gate.NOTICE, ''}
        generated = {}
        parked = {}
        uncertain = False
        for full, data in sorted(files.items()):
            relative = full[len(prefix)+1:]
            kind, owner, _ = bundle._classify(relative)
            if kind != 'concept' or owner != directory: continue
            library_deadline.remaining(30)
            try:
                meta, _ = _document(data, relative)
                if any(type(meta.get(key)) is not str for key in ('title','type')):
                    raise ValueError('not reproducible')
                if any(type(meta[key]) is not str for key in ('status','description') if key in meta):
                    raise ValueError('not reproducible')
            except (library.LibraryError, UnicodeError, ValueError, KeyError, TypeError):
                uncertain = True
                break
            name = relative.split('/')[1]
            line = '* ['+_label(meta['title'])+']('+name+') - '+_label(meta['type'])+'; '+meta.get('status','unknown')+'; '+_label(meta.get('description',''))
            generated[name] = line
            accepted.add(line)
            if directory == 'pending':
                accepted.add('* ['+_label(meta['title'])+']('+name+') - DRAFT.')
                pattern = (r'\* \['+re.escape(_label(meta['title']))+r'\]\('+re.escape(name)+r'\) - '+re.escape(_label(meta['type']))+r'; DRAFT PARKED: [A-Za-z0-9][A-Za-z0-9._:/-]{0,127}; '+re.escape(_label(meta.get('description',''))))
                for old in text.splitlines():
                    if re.fullmatch(pattern, old):
                        if name in parked and parked[name] != old: uncertain = True
                        parked[name] = old
                        accepted.add(old)
        lines = text.splitlines()
        if uncertain or header not in lines or gate.NOTICE not in lines or any(line not in accepted for line in lines):
            reports.append({'path':directory+'/index.md','reason':'AUTHORED_OR_UNCERTAIN_INDEX'})
            continue
        # Queue eligibility is not derivable from absence of a log marker:
        # history itself may be damaged. Never invent a missing pending entry.
        if directory == 'pending':
            for name, line in generated.items():
                variants = [old for old in lines if old in accepted
                            and (']('+name+') - ') in old]
                if len(set(variants)) != 1:
                    uncertain = True
                elif name in parked and variants[0] != parked[name]:
                    uncertain = True
                else:
                    generated[name] = variants[0]
            if uncertain:
                reports.append({'path':directory+'/index.md','reason':'UNCERTAIN_QUEUE_HISTORY'})
                continue
        content = header+'\n\n'+gate.NOTICE+'\n'
        if generated: content += '\n'+'\n'.join(parked.get(name,line) for name,line in sorted(generated.items()))+'\n'
        files[path] = content.encode('utf-8')
    return bundle.Tree(files), tuple(reports)
