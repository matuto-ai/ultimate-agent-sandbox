"""Inert durable checkout writer-scope shape shared by ownership consumers.

This metadata is not live process authority or a quiescence receipt. Importing
it cannot load a Docker backend, inspect a process or invoke Project Git.
"""
from datetime import datetime
import re


def valid_timestamp(value):
    try:
        return (type(value) is str and len(value) <= 64 and
                datetime.fromisoformat(value).year > 1 and
                datetime.fromisoformat(value).tzinfo is not None)
    except (ValueError, TypeError):
        return False


def valid_writer_scope(scope, instance):
    return (type(scope) is dict and set(scope) == {'kind', 'instance', 'container', 'started_at'}
            and scope.get('kind') == 'docker-workstation' and scope.get('instance') == instance
            and type(scope.get('container')) is str
            and re.fullmatch(r'[0-9a-f]{64}', scope['container']) is not None
            and valid_timestamp(scope.get('started_at')))
