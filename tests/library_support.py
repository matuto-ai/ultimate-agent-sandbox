"""Shared Library fixtures; imported by tests and the restart worker only."""
import io
import json

from uas import library
from uas.ledger import Origin
from uas.manager_actions import HumanSession

AT = "2026-10-28T22:00:00+00:00"
ORIGIN = Origin("actor-alpha", "seat-a", "inc-1", "epoch-1", ("implement", "library:enqueue"))
OTHER = Origin("actor-beta", "seat-b", "inc-2", "epoch-2", ("implement", "library:enqueue"))
HUMAN_ORIGIN = Origin("human-seat", "human-seat", "inc-human", "human-epoch", ("human-control-run",))


def document():
    return {
        "version": 1,
        "repository": {"target": "ssh://git@git.example.com/library.git",
                       "branch": "library/canonical", "credential_ref": "target-cred",
                       "qualification_ref": "target-qualification"},
        "model": {"profile_ref": "synth-local", "placement": "local",
                  "qualification_ref": "synth-qualification"},
        "filters": dict(library.INITIAL_FILTERS),
        "limits": dict(library.INITIAL_LIMITS),
    }


def settings(value=None, egress=()):
    return library.admit_settings(io.StringIO(json.dumps(document() if value is None else value)),
                                  egress_approvals=egress)


def binding(project_id="alpha", repository="acme/alpha", source="1001"):
    return library.project_binding({"id": project_id, "repository": repository,
                                    "roots": {"reference": "/srv/" + project_id + "/reference"}},
                                   source_identity=source)


def session(allowed=("library-drain",), connected=True):
    return HumanSession("deployment", "room", "instance", "manager", HUMAN_ORIGIN,
                        lambda _session, action: action in allowed, lambda: connected)


def value(title="Pick SQLite", body="We picked SQLite.\n"):
    return {"type": "decision", "title": title, "body": body,
            "sources": [{"resource": "decisions/pick-sqlite.md"}]}


def capture(*, origin=ORIGIN, target=None, operation_id="op-1", request_id="request-1",
            payload=None):
    return library.capture(library.participant_scope(origin, binding=target or binding()),
                           settings(), operation_id=operation_id, request_id=request_id,
                           value=payload or value(), at=AT)


def operation():
    """The single identity the restart worker records."""
    return capture()
