"""Thread-local bounded Library operation budget, never a global timeout edit."""
from contextlib import contextmanager
from contextvars import ContextVar
import time
from .library import LibraryError

_deadline = ContextVar('library_deadline', default=None)


def remaining(maximum):
    deadline = _deadline.get()
    if deadline is None: return maximum
    left = min(maximum, deadline - time.monotonic())
    if left <= 0: raise LibraryError('ATTEMPT_TIMEOUT', 'deadline')
    return left


@contextmanager
def bounded(seconds):
    previous = _deadline.get()
    deadline = time.monotonic() + seconds
    token = _deadline.set(min(previous, deadline) if previous is not None else deadline)
    try: yield
    finally: _deadline.reset(token)
