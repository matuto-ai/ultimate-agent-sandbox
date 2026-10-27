"""Shared Gate-only no-follow directory acquisition; no filesystem effects.

Held O_PATH ancestors need search permission, not directory-listing permission.
The returned leaf is always readable for existing fstat/scandir/fsync/*at users.
Ownership and identity checks remain the caller's responsibility.
"""
import os
from pathlib import Path

from .artifact_protocol import ArtifactError


READABLE_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def open_directory(path, *, invalid_code, unsupported_code):
    """Open an absolute non-root directory through held no-follow ancestors.

    Error codes are fixed internal caller vocabulary, never caller authority.
    O_PATH is mandatory. Every acquisition uses DIRECTORY/NOFOLLOW/CLOEXEC;
    no fallback, path resolution, permission mutation or close retry occurs.
    """
    path = Path(path)
    parts = path.parts[1:]
    if not path.is_absolute() or '..' in path.parts or not parts:
        raise ArtifactError(invalid_code)
    search = getattr(os, 'O_PATH', None)
    if type(search) is not int or search <= 0:
        raise ArtifactError(unsupported_code)
    search |= os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = None
    try:
        fd = os.open('/', search)
        for index, part in enumerate(parts):
            child = os.open(part, READABLE_DIRECTORY_FLAGS if index == len(parts) - 1 else search,
                            dir_fd=fd)
            previous, fd = fd, child
            # Transfer first: a failed close still releases the new child.
            # Linux may have released previous even if close reports an error;
            # retrying its number could close another thread's reused descriptor.
            os.close(previous)
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)
