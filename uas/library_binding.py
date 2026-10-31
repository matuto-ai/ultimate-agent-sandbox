"""Lightweight shared Library Project binding; no ledger, service or model effects.

The full Library contract reexports these exact validators and error type. Keep
one definition so persistent Hub startup validates the same authority binding
without compiling unrelated capture/model/human-operation contracts.
"""
import posixpath
import re

TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")

IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")

REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}\Z")

class LibraryError(ValueError):
    """Stable code plus safe field path; never echoes input values or secrets.

    ``evidence`` carries optional rule/location/hash facts about the refusal
    (for example a credential rule name, its document line and a digest of the
    matched bytes) so a record can correlate refusals without the secret.
    """

    def __init__(self, code: str, field: str = "$", evidence=None):
        self.code, self.field = code, field
        self.evidence = evidence
        super().__init__(f"{code}: {field}")

def _fail(code, field="$"):
    raise LibraryError(code, field)

def _token(value, field, limit=128):
    if type(value) is not str or len(value) > limit or not TOKEN.fullmatch(value):
        _fail("INVALID_IDENTIFIER", field)
    return value

def _identifier(value, field):
    if type(value) is not str or not IDENTIFIER.fullmatch(value):
        _fail("INVALID_IDENTIFIER", field)
    return value

def _absolute(value):
    return (type(value) is str and value.startswith("/") and value != "/"
            and ".." not in value.split("/") and posixpath.normpath(value) == value)

def project_binding(project, *, source_identity):
    """Derive the Library binding from the trusted configured Room Project.

    Registration identity is the source Forge host plus the immutable source
    repository identity, so a rename or transfer keeps project identity, queue
    identity and deduplication stable. Current ``repository`` coordinates only
    establish the human-readable bundle path. The main product is GitHub-first,
    so the source host is fixed; Library hosting stays independent of it.
    """
    if type(project) is not dict:
        _fail("INVALID_BINDING", "project")
    project_id = _identifier(project.get("id"), "project.id")
    repository = project.get("repository")
    if type(repository) is not str or not REPOSITORY.fullmatch(repository):
        _fail("INVALID_BINDING", "project.repository")
    roots = project.get("roots")
    if type(roots) is not dict or not _absolute(roots.get("reference")):
        _fail("INVALID_BINDING", "project.roots.reference")
    reference = roots["reference"].rstrip("/") or "/"
    if reference == "/":
        _fail("INVALID_BINDING", "project.roots.reference")
    identity = _token(source_identity, "source_identity", 128)
    return {"project_id": project_id,
            "project_identity": "github.com/" + identity,
            "project_path": "github.com/" + repository,
            "reference_root": reference + "/library",
            "snapshot_path": reference + "/library.snapshot.json"}
