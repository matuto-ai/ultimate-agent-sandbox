"""Faithful human decision formatting, with no model or verification authority.

One new decision per pending identity, never a general editor. Existing concepts
(and their verification evidence) are untouched. Caller supplies no path, title,
source, trust flag or provenance. The shared transaction owns complete validation.
"""
import hashlib

from . import library, library_bundle as bundle, library_gate as gate
from .library_compiler import _document, _index, _quote, _yaml


def render(files, current, operation, settings, input_sha):
    prefix = bundle._prefix(operation.scope)
    queue = operation.payload['queue_id']
    path = 'decisions/adjudication-' + queue + '.md'
    if prefix+'/'+path in files:
        raise library.LibraryError('ADJUDICATION_TARGET_EXISTS', 'disposition')
    original = current.files[prefix+'/pending/'+queue+'.md']
    meta, _ = _document(original, 'pending/'+queue+'.md')
    # Independently validate both unescaped authored sections before adding any
    # generated delimiters: neither fences nor JSON escaping may hide a secret.
    for key in ('conclusion', 'rationale'):
        gate._policy('log.md', operation.payload[key], settings['filters'], [])
    headers = ['type: "decision"', 'title: '+_quote(meta['title']),
               'description: "Human adjudication"', 'status: "stable"',
               'generated: false', 'verified: false']
    if meta.get('sources'):
        headers.append('sources:\n'+'\n'.join('  - '+_yaml(item) for item in meta['sources']))
    body = (gate.NOTICE+'\n\n## Human conclusion\n\n'+operation.payload['conclusion']
        +'\n\n## Human rationale\n\n'+operation.payload['rationale']
        +'\n\n## Human adjudication provenance\n\n'
        +'Human identity: '+operation.scope.human_id+'\n'
        +'Actor identity: '+operation.scope.actor_id+'\n'
        +'Request identity: '+operation.request_id+'\n'
        +'Service time: '+operation.at+'\n'
        +'Input commit: '+input_sha+'\n'
        +'Source draft: '+queue+'; SHA256: '+hashlib.sha256(original).hexdigest()+'\n'
        +'Verification: not conferred by human adjudication.\n')
    files[prefix+'/'+path] = ('---\n'+'\n'.join(headers)+'\n---\n'+body).encode('utf-8')
    index=prefix+'/decisions/index.md'
    files[index]=_index(current.files[index], 'decisions', {path}, files, prefix, {}, current.files)
